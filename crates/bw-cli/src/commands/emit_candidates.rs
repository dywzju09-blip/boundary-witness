use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use bw_model::{
    StaticFact, StaticFactEnvelope, V3_2_BOUNDARY_INDEX_SCHEMA_V1, V32BoundaryEvidenceKind,
    V32BoundaryEvidenceRef, V32BoundaryIndexRecord, V32BoundaryKind, V32CandidateRecord,
    candidate_from_boundary, validate_v3_2_boundary_index, validate_v3_2_candidates,
};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl, write_records},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct EmitCandidatesArgs {
    #[arg(long = "boundary-index")]
    boundary_index: PathBuf,
    #[arg(long = "static-facts")]
    static_facts: Option<PathBuf>,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long = "records-per-part", default_value_t = 1000)]
    records_per_part: usize,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

#[derive(Serialize)]
struct EmitCandidatesOutput {
    kind: &'static str,
    run_id: String,
    input_boundary_count: u64,
    input_negative_count: u64,
    candidate_count: u64,
    static_lifecycle_candidate_count: u64,
    skipped_negative_count: u64,
    part_count: u64,
    output_dir: String,
    checksums_path: String,
}

#[derive(Serialize)]
struct PartitionManifest {
    schema_version: &'static str,
    run_id: String,
    records_per_part: usize,
    candidate_count: u64,
    part_count: u64,
    parts: Vec<PartitionPart>,
}

#[derive(Clone, Serialize)]
struct PartitionPart {
    part_id: String,
    path: String,
    record_count: u64,
    sha256: String,
}

#[derive(Clone, Debug)]
struct BoundarySourceSpan {
    crate_id: String,
    path: String,
    line_start: u64,
    line_end: u64,
}

pub fn run(args: EmitCandidatesArgs) -> Result<CommandStatus, CliError> {
    if args.records_per_part == 0 {
        return Err(CliError::input(
            "BW-CANDIDATE-PART-SIZE",
            "records-per-part 必须大于 0",
        ));
    }
    if args.run_id.trim().is_empty() {
        return Err(CliError::input("BW-CANDIDATE-RUN-ID", "run_id 不能为空"));
    }

    let boundary_records =
        read_jsonl::<V32BoundaryIndexRecord>(&args.boundary_index, args.max_line_bytes)?;
    let boundary_summary = validate_v3_2_boundary_index(boundary_records.clone())?;

    let mut candidates = Vec::<V32CandidateRecord>::new();
    let mut skipped_negative_count = 0_u64;
    for located in &boundary_records {
        match candidate_from_boundary(&located.value, &args.run_id) {
            Some(candidate) => candidates.push(candidate),
            None => skipped_negative_count += 1,
        }
    }
    let existing_boundary_spans = covered_source_spans_from_boundaries(&boundary_records);
    let static_lifecycle_candidate_count = if let Some(static_facts) = &args.static_facts {
        let static_facts = read_jsonl::<StaticFactEnvelope>(static_facts, args.max_line_bytes)?;
        let static_candidates = candidates_from_static_lifecycle_facts(
            &static_facts,
            &args.run_id,
            &existing_boundary_spans,
        );
        let count = static_candidates.len() as u64;
        candidates.extend(static_candidates);
        count
    } else {
        0
    };

    validate_v3_2_candidates(
        candidates
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, value)| bw_model::Located {
                path: args.output_dir.join("candidates"),
                line: index + 1,
                value,
            }),
    )?;

    fs::create_dir_all(args.output_dir.join("candidates"))?;
    let mut parts = Vec::<PartitionPart>::new();
    if candidates.is_empty() {
        let part_path = args.output_dir.join("candidates/part-00000.jsonl.zst");
        // 空分片仍要写出：下游按 parts 清单读，缺文件与"零候选"是两种不同的结论。
        write_records::<V32CandidateRecord>(&part_path, &[])?;
        parts.push(PartitionPart {
            part_id: "part-00000".to_owned(),
            path: "candidates/part-00000.jsonl.zst".to_owned(),
            record_count: 0,
            sha256: sha256_file(&part_path)?,
        });
    } else {
        for (part_index, chunk) in candidates.chunks(args.records_per_part).enumerate() {
            let part_id = format!("part-{part_index:05}");
            let relative = format!("candidates/{part_id}.jsonl.zst");
            let part_path = args.output_dir.join(&relative);
            write_records(&part_path, chunk)?;
            parts.push(PartitionPart {
                part_id,
                path: relative,
                record_count: chunk.len() as u64,
                sha256: sha256_file(&part_path)?,
            });
        }
    }

    let partition_manifest = PartitionManifest {
        schema_version: "v3.2.candidate_partition.1",
        run_id: args.run_id.clone(),
        records_per_part: args.records_per_part,
        candidate_count: candidates.len() as u64,
        part_count: parts.len() as u64,
        parts: parts.clone(),
    };
    let manifest_path = args.output_dir.join("partition-manifest.json");
    write_json_file(&manifest_path, &partition_manifest)?;

    let confidence_counts = count_confidence(&candidates);
    let pattern_counts = count_patterns(&candidates);
    let stats = serde_json::json!({
        "schema_version": "v3.2.candidate_stats.1",
        "run_id": args.run_id,
        "input_boundary_count": boundary_summary.boundary_count,
        "input_negative_count": boundary_summary.negative_count,
        "candidate_count": candidates.len(),
        "static_lifecycle_candidate_count": static_lifecycle_candidate_count,
        "skipped_negative_count": skipped_negative_count,
        "part_count": parts.len(),
        "confidence_counts": confidence_counts,
        "pattern_family_counts": pattern_counts,
    });
    write_json_file(&args.output_dir.join("stats.json"), &stats)?;

    let checksums_path = args.output_dir.join("checksums.sha256");
    write_checksums(&args.output_dir, &parts, &manifest_path, &checksums_path)?;

    let summary = EmitCandidatesOutput {
        kind: "v3-2-candidate-partition",
        run_id: args.run_id,
        input_boundary_count: boundary_summary.boundary_count,
        input_negative_count: boundary_summary.negative_count,
        candidate_count: candidates.len() as u64,
        static_lifecycle_candidate_count,
        skipped_negative_count,
        part_count: parts.len() as u64,
        output_dir: args.output_dir.display().to_string(),
        checksums_path: checksums_path.display().to_string(),
    };
    crate::commands::write_json_stdout(&summary)?;
    Ok(CommandStatus::Success)
}

fn count_confidence(records: &[V32CandidateRecord]) -> BTreeMap<&'static str, u64> {
    let mut counts = BTreeMap::new();
    for record in records {
        let key = match record.confidence {
            bw_model::V32CandidateConfidence::NeedsDynamicValidation => "needs_dynamic_validation",
            bw_model::V32CandidateConfidence::StaticOnly => "static_only",
            bw_model::V32CandidateConfidence::LowPriority => "low_priority",
        };
        *counts.entry(key).or_default() += 1;
    }
    counts
}

fn count_patterns(records: &[V32CandidateRecord]) -> BTreeMap<&'static str, u64> {
    let mut counts = BTreeMap::new();
    for record in records {
        let key = match record.pattern_family {
            bw_model::V32PatternFamily::RetainedBorrowedCallback => "retained_borrowed_callback",
            bw_model::V32PatternFamily::CallbackLifecycleRelease => "callback_lifecycle_release",
            bw_model::V32PatternFamily::ForeignRetainedPointer => "foreign_retained_pointer",
            bw_model::V32PatternFamily::OpaqueHandleTransfer => "opaque_handle_transfer",
            bw_model::V32PatternFamily::NativeLibraryBoundary => "native_library_boundary",
            bw_model::V32PatternFamily::ReturnedBorrowView => "returned_borrow_view",
            bw_model::V32PatternFamily::ExternalBufferView => "external_buffer_view",
        };
        *counts.entry(key).or_default() += 1;
    }
    counts
}

fn candidates_from_static_lifecycle_facts(
    static_facts: &[bw_model::Located<StaticFactEnvelope>],
    run_id: &str,
    existing_boundary_spans: &[BoundarySourceSpan],
) -> Vec<V32CandidateRecord> {
    let context = StaticLifecycleFactContext::from_facts(static_facts);
    let mut boundaries_by_key = BTreeMap::<String, (u8, V32BoundaryIndexRecord)>::new();
    for located in static_facts {
        let envelope = &located.value;
        if !envelope.is_authoritative_lifecycle_binding() {
            continue;
        }
        if static_fact_is_covered_by_existing_boundary(envelope, existing_boundary_spans) {
            continue;
        }
        let Some(boundary) = boundary_from_static_lifecycle_fact(envelope, run_id, &context) else {
            continue;
        };
        let key = static_lifecycle_dedup_key(&boundary);
        let priority = static_lifecycle_boundary_priority(envelope);
        match boundaries_by_key.get(&key) {
            Some((existing_priority, _)) if *existing_priority >= priority => {}
            _ => {
                boundaries_by_key.insert(key, (priority, boundary));
            }
        }
    }
    let boundaries = boundaries_by_key
        .into_values()
        .map(|(_, boundary)| boundary)
        .collect::<Vec<_>>();
    boundaries
        .iter()
        .filter_map(|boundary| candidate_from_boundary(boundary, run_id))
        .collect()
}

fn static_lifecycle_boundary_priority(envelope: &StaticFactEnvelope) -> u8 {
    match envelope.payload {
        StaticFact::DropPrevention(_) => 40,
        StaticFact::ReturnedBorrowInvalidationOrder(_) => 35,
        StaticFact::PersistedReturnedBorrow(_) | StaticFact::ExternalBufferBinding(_) => 30,
        StaticFact::RawPointerTransfer(_) | StaticFact::RegistrationSite(_) => 25,
        StaticFact::ReturnedBorrowRelation(_) => 20,
        StaticFact::AtomicOrdering(_) => 18,
        StaticFact::DropSite(_) => 10,
        StaticFact::CallbackUserDataReconstruction(_) => 5,
        _ => 0,
    }
}

fn static_lifecycle_dedup_key(boundary: &V32BoundaryIndexRecord) -> String {
    format!(
        "{}:{}:{}",
        boundary.crate_id,
        static_lifecycle_boundary_slug(boundary.boundary_kind),
        boundary
            .api_path
            .as_deref()
            .unwrap_or(&boundary.boundary_id)
    )
}

#[derive(Clone, Debug, Default)]
struct StaticLifecycleFactContext {
    object_type_by_site: BTreeMap<(String, String), String>,
}

impl StaticLifecycleFactContext {
    fn from_facts(static_facts: &[bw_model::Located<StaticFactEnvelope>]) -> Self {
        let mut context = Self::default();
        for located in static_facts {
            let envelope = &located.value;
            if !envelope.is_authoritative_lifecycle_binding() {
                continue;
            }
            if let StaticFact::ObjectSite(fact) = &envelope.payload {
                context.object_type_by_site.insert(
                    (envelope.build_id.to_string(), fact.site_id.to_string()),
                    fact.type_name.clone(),
                );
            }
        }
        context
    }

    fn object_type_for_site<'a>(
        &'a self,
        envelope: &StaticFactEnvelope,
        site_id: &str,
    ) -> Option<&'a str> {
        self.object_type_by_site
            .get(&(envelope.build_id.to_string(), site_id.to_owned()))
            .map(String::as_str)
    }
}

fn covered_source_spans_from_boundaries(
    boundary_records: &[bw_model::Located<V32BoundaryIndexRecord>],
) -> Vec<BoundarySourceSpan> {
    boundary_records
        .iter()
        .filter(|record| record.value.boundary_kind != V32BoundaryKind::NegativeSummary)
        .flat_map(|record| {
            record.value.evidence_refs.iter().filter_map(|evidence| {
                let line_start = evidence.line_start?;
                let line_end = evidence.line_end.unwrap_or(line_start);
                (evidence.kind == V32BoundaryEvidenceKind::SourceSpan
                    && !evidence.path.trim().is_empty())
                .then(|| BoundarySourceSpan {
                    crate_id: record.value.crate_id.clone(),
                    path: evidence.path.clone(),
                    line_start,
                    line_end,
                })
            })
        })
        .collect()
}

fn static_fact_is_covered_by_existing_boundary(
    envelope: &StaticFactEnvelope,
    existing_boundary_spans: &[BoundarySourceSpan],
) -> bool {
    let Some(artifact) = envelope.artifact.as_ref() else {
        return false;
    };
    let Some(source_ref) = envelope.source_ref.as_ref() else {
        return false;
    };
    let line_start = source_ref.line_start;
    let line_end = source_ref.line_end;
    existing_boundary_spans.iter().any(|span| {
        span.crate_id == artifact.crate_id
            && span.path == source_ref.path
            && ranges_overlap(line_start, line_end, span.line_start, span.line_end)
    })
}

fn ranges_overlap(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> bool {
    left_start <= right_end && right_start <= left_end
}

fn boundary_from_static_lifecycle_fact(
    envelope: &StaticFactEnvelope,
    run_id: &str,
    context: &StaticLifecycleFactContext,
) -> Option<V32BoundaryIndexRecord> {
    let artifact = envelope.artifact.as_ref()?;
    let source_ref = envelope.source_ref.as_ref()?;
    let (boundary_kind, api_id) = match &envelope.payload {
        StaticFact::ReturnedBorrowRelation(fact) => {
            if !static_lifecycle_candidate_is_worthy(
                V32BoundaryKind::ReturnedBorrow,
                &fact.api_id,
                source_ref.symbol_path.as_deref(),
            ) {
                return None;
            }
            (V32BoundaryKind::ReturnedBorrow, fact.api_id.clone())
        }
        StaticFact::ExternalBufferBinding(fact) => {
            if !static_lifecycle_candidate_is_worthy(
                V32BoundaryKind::ExternalBuffer,
                &fact.api_id,
                source_ref.symbol_path.as_deref(),
            ) {
                return None;
            }
            (V32BoundaryKind::ExternalBuffer, fact.api_id.clone())
        }
        StaticFact::PersistedReturnedBorrow(fact) => {
            if !persisted_returned_borrow_candidate_is_worthy(
                &fact.api_id,
                source_ref.symbol_path.as_deref(),
            ) {
                return None;
            }
            (V32BoundaryKind::ReturnedBorrow, fact.api_id.clone())
        }
        StaticFact::DropPrevention(fact) => {
            if !manual_drop_prevention_candidate_is_worthy(envelope, fact, context) {
                return None;
            }
            (
                V32BoundaryKind::ForeignRetainedPointer,
                source_ref
                    .symbol_path
                    .clone()
                    .unwrap_or_else(|| "manual_drop_prevention".to_owned()),
            )
        }
        StaticFact::DropSite(fact) => {
            let api_id = source_ref.symbol_path.clone()?;
            if wrapper_destructure_drop_candidate_is_worthy(envelope, fact, context) {
                (V32BoundaryKind::ForeignRetainedPointer, api_id)
            } else if container_lifecycle_drop_candidate_is_worthy(envelope, fact, context) {
                (V32BoundaryKind::ReturnedBorrow, api_id)
            } else {
                return None;
            }
        }
        StaticFact::RegistrationSite(fact) => {
            if fact.role != bw_model::RegistrationRole::Register
                || fact.user_data_site_id.is_none()
                || !static_lifecycle_candidate_is_worthy(
                    V32BoundaryKind::ForeignRetainedPointer,
                    &fact.api_id,
                    source_ref.symbol_path.as_deref(),
                )
            {
                return None;
            }
            (V32BoundaryKind::ForeignRetainedPointer, fact.api_id.clone())
        }
        StaticFact::RawPointerTransfer(fact)
            if fact.transfer_kind == bw_model::RawPointerTransferKind::FromRawParts =>
        {
            let api_id = source_ref
                .symbol_path
                .as_deref()
                .map(|symbol| format!("{symbol}::Vec::from_raw_parts"))
                .unwrap_or_else(|| "alloc::vec::Vec::from_raw_parts".to_owned());
            if !static_lifecycle_candidate_is_worthy(
                V32BoundaryKind::ForeignRetainedPointer,
                &api_id,
                source_ref.symbol_path.as_deref(),
            ) {
                return None;
            }
            (V32BoundaryKind::ForeignRetainedPointer, api_id)
        }
        StaticFact::CallbackUserDataReconstruction(_) => {
            let api_id = source_ref
                .symbol_path
                .clone()
                .unwrap_or_else(|| "callback_user_data_reconstruction".to_owned());
            (V32BoundaryKind::CallbackRegistration, api_id)
        }
        StaticFact::AtomicOrdering(fact) => {
            if !atomic_ordering_lifecycle_candidate_is_worthy(
                fact,
                source_ref.symbol_path.as_deref(),
            ) {
                return None;
            }
            (V32BoundaryKind::ReturnedBorrow, fact.api_id.clone())
        }
        _ => return None,
    };
    if public_api_path_contains_forbidden_token(&api_id) {
        return None;
    }

    Some(V32BoundaryIndexRecord {
        schema_version: V3_2_BOUNDARY_INDEX_SCHEMA_V1.to_owned(),
        run_id: run_id.to_owned(),
        crate_id: artifact.crate_id.clone(),
        boundary_id: static_lifecycle_boundary_id(
            &artifact.crate_id,
            boundary_kind,
            &source_ref.path,
            source_ref.line_start,
            &api_id,
        ),
        boundary_kind,
        api_path: Some(api_id),
        evidence_refs: vec![V32BoundaryEvidenceRef {
            kind: V32BoundaryEvidenceKind::SourceSpan,
            path: source_ref.path.clone(),
            line_start: Some(source_ref.line_start),
            line_end: Some(source_ref.line_end),
        }],
        confidence: "medium".to_owned(),
        notes: vec!["candidate emitted from authoritative lifecycle static fact".to_owned()],
    })
}

fn manual_drop_prevention_candidate_is_worthy(
    envelope: &StaticFactEnvelope,
    fact: &bw_model::DropPreventionFact,
    context: &StaticLifecycleFactContext,
) -> bool {
    if fact.prevention_kind != bw_model::DropPreventionKind::MemForget {
        return false;
    }
    let Some(source_ref) = envelope.source_ref.as_ref() else {
        return false;
    };
    let Some(symbol_path) = source_ref.symbol_path.as_deref() else {
        return false;
    };
    let object_type = context
        .object_type_for_site(envelope, fact.object_site_id.as_str())
        .unwrap_or_default();
    let identity = lifecycle_identity(symbol_path, Some(object_type));
    if ordinary_ephemeral_type(object_type) {
        return false;
    }
    [
        "into_inner",
        "into_raw",
        "from_raw",
        "manuallydrop",
        "mem::forget",
        "forget",
        "destructure",
        "take",
    ]
    .iter()
    .any(|token| identity.contains(token))
}

fn wrapper_destructure_drop_candidate_is_worthy(
    envelope: &StaticFactEnvelope,
    fact: &bw_model::DropSiteFact,
    context: &StaticLifecycleFactContext,
) -> bool {
    let Some(source_ref) = envelope.source_ref.as_ref() else {
        return false;
    };
    let Some(symbol_path) = source_ref.symbol_path.as_deref() else {
        return false;
    };
    let Some(method) = api_tail_method(symbol_path) else {
        return false;
    };
    if !matches!(
        method.as_str(),
        "into_inner" | "into_parts" | "into_raw_parts" | "take_inner"
    ) {
        return false;
    }
    let object_type = context
        .object_type_for_site(envelope, fact.object_site_id.as_str())
        .unwrap_or_default();
    if ordinary_ephemeral_type(object_type) {
        return false;
    }
    let identity = lifecycle_identity(symbol_path, Some(object_type));
    [
        "wrapper",
        "instrumented",
        "guard",
        "owner",
        "handle",
        "span",
        "inner",
    ]
    .iter()
    .any(|token| identity.contains(token))
}

fn container_lifecycle_drop_candidate_is_worthy(
    envelope: &StaticFactEnvelope,
    fact: &bw_model::DropSiteFact,
    context: &StaticLifecycleFactContext,
) -> bool {
    let Some(source_ref) = envelope.source_ref.as_ref() else {
        return false;
    };
    let Some(symbol_path) = source_ref.symbol_path.as_deref() else {
        return false;
    };
    let object_type = context
        .object_type_for_site(envelope, fact.object_site_id.as_str())
        .unwrap_or_default();
    let identity = lifecycle_identity(symbol_path, Some(object_type));
    let container_signal = [
        "lru",
        "cache",
        "entry",
        "node",
        "bucket",
        "slot",
        "threadlocal",
        "thread_local",
    ]
    .iter()
    .any(|token| identity.contains(token));
    if !container_signal || ordinary_unchecked_adapter(symbol_path) {
        return false;
    }
    let method_signal = [
        "::pop",
        "::pop_",
        "::remove",
        "::clear",
        "::resize",
        "::insert",
        "::put",
        "::swap_remove",
        "::drain",
        "::retain",
        "::into_iter",
    ]
    .iter()
    .any(|token| identity.contains(token));
    method_signal && (!ordinary_ephemeral_type(object_type) || container_signal)
}

fn lifecycle_identity(symbol_path: &str, object_type: Option<&str>) -> String {
    let mut identity = symbol_path.to_ascii_lowercase();
    if let Some(object_type) = object_type
        && !object_type.trim().is_empty()
    {
        identity.push(' ');
        identity.push_str(&object_type.to_ascii_lowercase());
    }
    identity
}

fn ordinary_ephemeral_type(type_name: &str) -> bool {
    let lower = type_name.trim().to_ascii_lowercase();
    lower.starts_with("core::option::option<")
        || lower.starts_with("std::option::option<")
        || lower.starts_with("core::result::result<")
        || lower.starts_with("std::result::result<")
        || lower == "()"
}

fn ordinary_unchecked_adapter(symbol_path: &str) -> bool {
    let lower = symbol_path.to_ascii_lowercase();
    lower.contains("unchecked_unwrap")
        || lower.contains("unwrap_unchecked")
        || lower.contains("expect")
}

fn static_lifecycle_candidate_is_worthy(
    kind: V32BoundaryKind,
    api_id: &str,
    symbol_path: Option<&str>,
) -> bool {
    let mut identity = api_id.to_ascii_lowercase();
    if let Some(symbol_path) = symbol_path {
        identity.push(' ');
        identity.push_str(&symbol_path.to_ascii_lowercase());
    }
    let sqlite_statement_field_name_signal = kind == V32BoundaryKind::ReturnedBorrow
        && identity.contains("sqlite::connection::stmt::statement::field_name");
    let returned_borrow_accessor_signal = kind == V32BoundaryKind::ReturnedBorrow
        && api_tail_method(api_id)
            .or_else(|| symbol_path.and_then(api_tail_method))
            .is_some_and(|method| {
                matches!(
                    method.as_str(),
                    "inner"
                        | "inner_mut"
                        | "span"
                        | "span_mut"
                        | "get_or"
                        | "get_or_try"
                        | "get_or_default"
                        | "get_mut"
                )
            });
    let returned_borrow_view_method_signal = kind == V32BoundaryKind::ReturnedBorrow
        && api_tail_method(api_id)
            .or_else(|| symbol_path.and_then(api_tail_method))
            .is_some_and(|method| {
                matches!(
                    method.as_str(),
                    "as_bytes"
                        | "as_mut"
                        | "as_ref"
                        | "as_slice"
                        | "as_str"
                        | "back"
                        | "borrow"
                        | "borrow_mut"
                        | "entry"
                        | "first"
                        | "front"
                        | "get"
                        | "get_key_value"
                        | "get_mut"
                        | "iter"
                        | "iter_mut"
                        | "keys"
                        | "last"
                        | "peek"
                        | "peek_lru"
                        | "peek_mut"
                        | "value"
                        | "values"
                        | "view"
                )
            });
    let arena_into_iter_lifecycle_signal = kind == V32BoundaryKind::ReturnedBorrow
        && api_tail_method(api_id)
            .or_else(|| symbol_path.and_then(api_tail_method))
            .is_some_and(|method| method == "into_iter")
        && (identity.contains("arena") || identity.contains("bump"))
        && identity.contains("intoiterator");
    let external_buffer_selector_signal = kind == V32BoundaryKind::ExternalBuffer
        && identity.contains("select")
        && (identity.contains("proto") || identity.contains("negotiat"));
    let strong_signal = match kind {
        V32BoundaryKind::ReturnedBorrow => [
            "borrow", "view", "slice", "buffer", "buf", "raw", "ptr", "pointer", "ffi", "native",
            "external", "owner", "handle", "column",
        ]
        .iter()
        .any(|token| identity.contains(token)),
        V32BoundaryKind::ExternalBuffer => [
            "buffer", "buf", "slice", "raw", "ptr", "pointer", "ffi", "native", "external",
            "as_ptr",
        ]
        .iter()
        .any(|token| identity.contains(token)),
        V32BoundaryKind::ForeignRetainedPointer => [
            "user_data",
            "ex_data",
            "callback",
            "hook",
            "register",
            "raw",
            "ptr",
            "pointer",
            "ffi",
            "native",
            "foreign",
            "retained",
        ]
        .iter()
        .any(|token| identity.contains(token)),
        _ => false,
    };
    if !strong_signal
        && !sqlite_statement_field_name_signal
        && !returned_borrow_accessor_signal
        && !returned_borrow_view_method_signal
        && !arena_into_iter_lifecycle_signal
        && !external_buffer_selector_signal
    {
        return false;
    }
    let ordinary_builder_signal = [
        "builder", "build_", "name", "version", "label", "kind", "capacity", "len",
    ]
    .iter()
    .any(|token| identity.contains(token));
    if ordinary_builder_signal {
        if sqlite_statement_field_name_signal {
            return true;
        }
        return [
            "ffi",
            "native",
            "external",
            "raw",
            "ptr",
            "pointer",
            "buffer",
            "buf",
            "slice",
            "ex_data",
            "user_data",
        ]
        .iter()
        .any(|token| identity.contains(token));
    }
    true
}

fn api_tail_method(api_id: &str) -> Option<String> {
    api_id
        .split("::")
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(str::trim)
        .find(|segment| !segment.is_empty() && !segment.starts_with("{closure"))
        .and_then(|segment| {
            let raw = segment.split('<').next().unwrap_or(segment);
            let method = raw
                .chars()
                .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                .collect::<String>();
            (!method.is_empty()).then(|| method.to_ascii_lowercase())
        })
}

fn persisted_returned_borrow_candidate_is_worthy(api_id: &str, symbol_path: Option<&str>) -> bool {
    let mut identity = api_id.to_ascii_lowercase();
    if let Some(symbol_path) = symbol_path {
        identity.push(' ');
        identity.push_str(&symbol_path.to_ascii_lowercase());
    }
    if identity.split_whitespace().any(|part| {
        part.starts_with("std::") || part.starts_with("core::") || part.starts_with("alloc::")
    }) {
        return false;
    }
    [
        "borrow", "view", "slice", "buffer", "buf", "raw", "ptr", "pointer", "ffi", "native",
        "external", "owner", "handle", "field", "column",
    ]
    .iter()
    .any(|token| identity.contains(token))
}

fn atomic_ordering_lifecycle_candidate_is_worthy(
    fact: &bw_model::AtomicOrderingFact,
    symbol_path: Option<&str>,
) -> bool {
    if fact.operation != bw_model::AtomicOperationKind::Load {
        return false;
    }
    if !matches!(
        fact.ordering,
        bw_model::AtomicOrderingKind::Relaxed | bw_model::AtomicOrderingKind::Acquire
    ) {
        return false;
    }
    if !atomic_target_is_pointer_like(&fact.target_type_name) {
        return false;
    }

    let mut identity = fact.api_id.to_ascii_lowercase();
    if let Some(symbol_path) = symbol_path {
        identity.push(' ');
        identity.push_str(&symbol_path.to_ascii_lowercase());
    }
    let Some(method) =
        api_tail_method(&fact.api_id).or_else(|| symbol_path.and_then(api_tail_method))
    else {
        return false;
    };
    let lifecycle_method = matches!(
        method.as_str(),
        "next"
            | "next_back"
            | "get"
            | "get_or"
            | "get_or_try"
            | "iter"
            | "iter_mut"
            | "into_iter"
            | "peek"
            | "peek_lru"
    );
    let iterator_or_container_owner = [
        "iter",
        "iterator",
        "intoiterator",
        "into_iterator",
        "rawiter",
        "raw_iter",
        "threadlocal",
        "thread_local",
        "container",
        "cache",
        "arena",
        "bump",
        "slot",
        "entry",
    ]
    .iter()
    .any(|token| identity.contains(token));

    lifecycle_method && iterator_or_container_owner
}

fn atomic_target_is_pointer_like(target_type_name: &str) -> bool {
    let target = target_type_name.to_ascii_lowercase();
    target.contains("atomicptr")
        || target.contains("atomic_ptr")
        || target.contains("atomic<*")
        || target.contains("*mut ")
        || target.contains("*const ")
}

fn public_api_path_contains_forbidden_token(api_id: &str) -> bool {
    const PUBLIC_FORBIDDEN_TOKENS: [&str; 9] = [
        "vulnerable",
        "fixed",
        "cve",
        "ghsa",
        "expected",
        "patch",
        "advisory",
        "poc",
        "exploit",
    ];
    let lower = api_id.to_ascii_lowercase();
    PUBLIC_FORBIDDEN_TOKENS
        .iter()
        .any(|token| lower.contains(token))
}

fn static_lifecycle_boundary_id(
    crate_id: &str,
    boundary_kind: V32BoundaryKind,
    path: &str,
    line_start: u64,
    api_id: &str,
) -> String {
    let identity = format!("{crate_id}:{path}:{line_start}:{api_id}");
    let digest = Sha256::digest(identity.as_bytes());
    let suffix = hex_digest(digest);
    format!(
        "boundary:{}:{}:{}",
        sanitize_id(crate_id),
        static_lifecycle_boundary_slug(boundary_kind),
        &suffix[..16]
    )
}

fn static_lifecycle_boundary_slug(boundary_kind: V32BoundaryKind) -> &'static str {
    match boundary_kind {
        V32BoundaryKind::CallbackRegistration => "callback-registration",
        V32BoundaryKind::ReturnedBorrow => "returned-borrow",
        V32BoundaryKind::ExternalBuffer => "external-buffer",
        V32BoundaryKind::ForeignRetainedPointer => "foreign-retained-pointer",
        _ => "static-lifecycle",
    }
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn write_json_file(path: &Path, value: &impl Serialize) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, value)
        .map_err(|error| CliError::internal(error.to_string()))?;
    file.write_all(b"\n")?;
    Ok(())
}

fn write_checksums(
    output_dir: &Path,
    parts: &[PartitionPart],
    manifest_path: &Path,
    checksums_path: &Path,
) -> Result<(), CliError> {
    let mut lines = Vec::<String>::new();
    lines.push(format!(
        "{}  {}",
        sha256_file(manifest_path)?,
        "partition-manifest.json"
    ));
    lines.push(format!(
        "{}  {}",
        sha256_file(&output_dir.join("stats.json"))?,
        "stats.json"
    ));
    for part in parts {
        lines.push(format!("{}  {}", part.sha256, part.path));
    }
    lines.sort();
    let mut file = File::create(checksums_path)?;
    for line in lines {
        writeln!(file, "{line}")?;
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, CliError> {
    let bytes = fs::read(path)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {}", path.display(), error)))?;
    Ok(hex_digest(Sha256::digest(bytes)))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
