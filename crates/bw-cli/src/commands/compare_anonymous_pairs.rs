use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use bw_model::{
    V3_2_7_PAIR_DELTA_SCHEMA_V1, V32BoundaryEvidenceKind, V32CandidateRecord, V32PatternFamily,
    V326AnonymousPairRecord, V326CoverageGapReason, V326Distinguishability,
    V326LifecycleCoverageRecord, V326LifecycleFeatureRecord, V326PairDeltaRecord,
    compare_v3_2_6_pair, validate_v3_2_6_anonymous_pairs, validate_v3_2_6_lifecycle_coverage,
    validate_v3_2_6_lifecycle_features, validate_v3_2_7_pair_deltas, validate_v3_2_candidates,
};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, load_candidates, read_jsonl, write_records},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct CompareAnonymousPairsArgs {
    #[arg(long)]
    features: PathBuf,
    #[arg(long)]
    candidates: PathBuf,
    #[arg(long)]
    coverage: Option<PathBuf>,
    #[arg(long = "pair-manifest")]
    pair_manifest: PathBuf,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

#[derive(Serialize)]
struct CompareOutput {
    kind: &'static str,
    run_id: String,
    pair_count: u64,
    comparison_count: u64,
    separable_static_count: u64,
    indistinguishable_static_only_count: u64,
    insufficient_evidence_count: u64,
    unpaired_count: u64,
    output_dir: String,
    deltas_path: String,
    checksums_path: String,
}

pub fn run(args: CompareAnonymousPairsArgs) -> Result<CommandStatus, CliError> {
    if args.run_id.trim().is_empty() {
        return Err(CliError::input("BW-V326-RUN-ID", "run_id 不能为空"));
    }

    let pair_records =
        read_jsonl::<V326AnonymousPairRecord>(&args.pair_manifest, args.max_line_bytes)?;
    validate_v3_2_6_anonymous_pairs(pair_records.clone())?;
    let pair_count = pair_records.len() as u64;

    let candidates = load_candidates(&args.candidates, args.max_line_bytes)?;
    validate_v3_2_candidates(
        candidates
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, value)| bw_model::Located {
                path: args.candidates.clone(),
                line: index + 1,
                value,
            }),
    )?;
    let candidate_run_id = candidates.first().map(|candidate| candidate.run_id.clone());
    let candidates_by_id = candidates
        .into_iter()
        .map(|candidate| (candidate.candidate_id.clone(), candidate))
        .collect::<BTreeMap<_, _>>();

    let feature_records =
        read_jsonl::<V326LifecycleFeatureRecord>(&args.features, args.max_line_bytes)?;
    validate_v3_2_6_lifecycle_features(feature_records.clone())?;
    if let (Some(candidate_run_id), Some(feature)) = (candidate_run_id, feature_records.first()) {
        if candidate_run_id != feature.value.run_id {
            return Err(CliError::input(
                "BW-V326-PAIR-RUN-MISMATCH",
                format!(
                    "candidate run_id {} 与 lifecycle feature run_id {} 不一致",
                    candidate_run_id, feature.value.run_id
                ),
            ));
        }
    }

    let mut features_by_crate = BTreeMap::<String, Vec<V326LifecycleFeatureRecord>>::new();
    for located in feature_records {
        features_by_crate
            .entry(located.value.crate_id.clone())
            .or_default()
            .push(located.value);
    }
    let coverage_by_candidate = load_coverage_by_candidate(&args.coverage, args.max_line_bytes)?;

    let mut deltas = Vec::<V326PairDeltaRecord>::new();
    for located in pair_records {
        let mut pair = located.value;
        let pair_manifest_run_id = pair.run_id.clone();
        pair.run_id = args.run_id.clone();
        let left = features_by_crate
            .get(&pair.left_crate_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let right = features_by_crate
            .get(&pair.right_crate_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut pair_deltas = compare_pair_candidates(
            &pair,
            left,
            right,
            &candidates_by_id,
            &coverage_by_candidate,
        )?;
        for delta in &mut pair_deltas {
            delta.pair_manifest_run_id = pair_manifest_run_id.clone();
        }
        deltas.extend(pair_deltas);
    }

    let summary =
        validate_v3_2_7_pair_deltas(deltas.iter().cloned().enumerate().map(|(index, value)| {
            bw_model::Located {
                path: args.output_dir.join("pair-deltas.jsonl.zst"),
                line: index + 1,
                value,
            }
        }))?;

    fs::create_dir_all(&args.output_dir)?;
    let deltas_path = args.output_dir.join("pair-deltas.jsonl.zst");
    write_records(&deltas_path, &deltas)?;

    let distinguishability_summary = serde_json::json!({
        "schema_version": "v3.2.7.distinguishability_summary.1",
        "run_id": args.run_id,
        "pair_count": pair_count,
        "comparison_count": summary.record_count,
        "separable_static_count": summary.separable_static_count,
        "indistinguishable_static_only_count": summary.indistinguishable_static_only_count,
        "insufficient_evidence_count": summary.insufficient_evidence_count,
        "unpaired_count": summary.unpaired_count,
        "notes": [
            "anonymous left/right comparison only; not a defect conclusion"
        ]
    });
    write_json_file(
        &args.output_dir.join("distinguishability-summary.json"),
        &distinguishability_summary,
    )?;

    let checksums_path = args.output_dir.join("checksums.txt");
    write_checksums(&args.output_dir, &checksums_path)?;

    let output = CompareOutput {
        kind: "v3-2-7-pair-delta",
        run_id: args.run_id,
        pair_count,
        comparison_count: summary.record_count,
        separable_static_count: summary.separable_static_count,
        indistinguishable_static_only_count: summary.indistinguishable_static_only_count,
        insufficient_evidence_count: summary.insufficient_evidence_count,
        unpaired_count: summary.unpaired_count,
        output_dir: args.output_dir.display().to_string(),
        deltas_path: deltas_path.display().to_string(),
        checksums_path: checksums_path.display().to_string(),
    };
    crate::commands::write_json_stdout(&output)?;
    Ok(CommandStatus::Success)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CandidateAlignmentKey {
    pattern_family: V32PatternFamily,
    api_path: String,
    api_identity_is_specific: bool,
}

fn compare_pair_candidates(
    pair: &V326AnonymousPairRecord,
    left_features: &[V326LifecycleFeatureRecord],
    right_features: &[V326LifecycleFeatureRecord],
    candidates_by_id: &BTreeMap<String, V32CandidateRecord>,
    coverage_by_candidate: &BTreeMap<String, V326LifecycleCoverageRecord>,
) -> Result<Vec<V326PairDeltaRecord>, CliError> {
    let left_candidates = align_candidates(&pair.left_crate_id, candidates_by_id)?;
    let right_candidates = align_candidates(&pair.right_crate_id, candidates_by_id)?;
    let left = align_features(&pair.left_crate_id, left_features, candidates_by_id)?;
    let right = align_features(&pair.right_crate_id, right_features, candidates_by_id)?;
    let mut alignment_keys = left_candidates.keys().cloned().collect::<BTreeSet<_>>();
    alignment_keys.extend(right_candidates.keys().cloned());

    let mut deltas = Vec::new();
    for alignment_key in alignment_keys {
        let left_candidate_ids = left_candidates
            .get(&alignment_key)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let right_candidate_ids = right_candidates
            .get(&alignment_key)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let left_records = left
            .get(&alignment_key)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let right_records = right
            .get(&alignment_key)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut delta = if !alignment_key.api_identity_is_specific {
            let mut delta = insufficient_alignment_delta(pair, left_records, right_records);
            delta
                .notes
                .push("candidate API identity is not source-bound and specific".to_owned());
            delta
        } else if left_candidate_ids.len() > 1
            || right_candidate_ids.len() > 1
            || left_records.len() > 1
            || right_records.len() > 1
        {
            insufficient_alignment_delta(pair, left_records, right_records)
        } else {
            match (
                left_candidate_ids,
                right_candidate_ids,
                left_records,
                right_records,
            ) {
                ([..], [..], [left], [right])
                    if left_candidate_ids.len() == 1 && right_candidate_ids.len() == 1 =>
                {
                    compare_v3_2_6_pair(pair, left, right)?
                }
                ([], _, _, _) | (_, [], _, _) => unpaired_delta(pair, left_records, right_records),
                _ => {
                    let mut delta = insufficient_alignment_delta(pair, left_records, right_records);
                    delta
                        .notes
                        .push("lifecycle feature is missing for an aligned candidate".to_owned());
                    delta
                }
            }
        };
        augment_pair_delta_notes(
            &mut delta,
            left_records,
            right_records,
            coverage_by_candidate,
        );
        delta.schema_version = V3_2_7_PAIR_DELTA_SCHEMA_V1.to_owned();
        delta.comparison_key = comparison_key(pair, &alignment_key);
        deltas.push(delta);
    }

    if deltas.is_empty() {
        let mut delta = insufficient_alignment_delta(pair, left_features, right_features);
        delta.comparison_key = comparison_key(
            pair,
            &CandidateAlignmentKey {
                pattern_family: V32PatternFamily::NativeLibraryBoundary,
                api_path: "no_active_lifecycle_feature".to_owned(),
                api_identity_is_specific: false,
            },
        );
        delta
            .notes
            .push("no aligned candidate pair has active lifecycle evidence".to_owned());
        augment_pair_delta_notes(
            &mut delta,
            left_features,
            right_features,
            coverage_by_candidate,
        );
        deltas.push(delta);
    }

    Ok(deltas)
}

fn load_coverage_by_candidate(
    path: &Option<PathBuf>,
    max_line_bytes: usize,
) -> Result<BTreeMap<String, V326LifecycleCoverageRecord>, CliError> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let coverage_records = read_jsonl::<V326LifecycleCoverageRecord>(path, max_line_bytes)?;
    validate_v3_2_6_lifecycle_coverage(coverage_records.clone())?;
    let mut by_candidate = BTreeMap::<String, V326LifecycleCoverageRecord>::new();
    for located in coverage_records {
        by_candidate.insert(located.value.candidate_id.clone(), located.value);
    }
    Ok(by_candidate)
}

fn align_candidates(
    crate_id: &str,
    candidates_by_id: &BTreeMap<String, V32CandidateRecord>,
) -> Result<BTreeMap<CandidateAlignmentKey, Vec<String>>, CliError> {
    let mut aligned = BTreeMap::<CandidateAlignmentKey, Vec<String>>::new();
    for candidate in candidates_by_id
        .values()
        .filter(|candidate| candidate.crate_id == crate_id)
    {
        let key = candidate_alignment_key(candidate)?;
        aligned
            .entry(key)
            .or_default()
            .push(candidate.candidate_id.clone());
    }
    Ok(aligned)
}

fn align_features(
    crate_id: &str,
    features: &[V326LifecycleFeatureRecord],
    candidates_by_id: &BTreeMap<String, V32CandidateRecord>,
) -> Result<BTreeMap<CandidateAlignmentKey, Vec<V326LifecycleFeatureRecord>>, CliError> {
    let mut aligned = BTreeMap::<CandidateAlignmentKey, Vec<V326LifecycleFeatureRecord>>::new();
    for feature in features {
        let candidate = candidates_by_id.get(&feature.candidate_id).ok_or_else(|| {
            CliError::input(
                "BW-V326-PAIR-CANDIDATE-MISSING",
                format!(
                    "candidate {} 缺少用于匿名 pair 对齐的 candidate record",
                    feature.candidate_id
                ),
            )
        })?;
        if candidate.crate_id != crate_id
            || candidate.crate_id != feature.crate_id
            || candidate.pattern_family != feature.pattern_family
        {
            return Err(CliError::input(
                "BW-V326-PAIR-CANDIDATE-MISMATCH",
                format!(
                    "candidate {} 与 lifecycle feature 的 crate_id 或 pattern_family 不一致",
                    feature.candidate_id
                ),
            ));
        }
        let key = candidate_alignment_key(candidate)?;
        aligned.entry(key).or_default().push(feature.clone());
    }
    Ok(aligned)
}

fn candidate_alignment_key(
    candidate: &V32CandidateRecord,
) -> Result<CandidateAlignmentKey, CliError> {
    let api_path = candidate.api_path.clone().ok_or_else(|| {
        CliError::input(
            "BW-V326-PAIR-CANDIDATE-API",
            format!("candidate {} 缺少 api_path", candidate.candidate_id),
        )
    })?;
    Ok(CandidateAlignmentKey {
        pattern_family: candidate.pattern_family,
        api_identity_is_specific: api_path_is_specific(candidate, &api_path),
        api_path,
    })
}

fn api_path_is_specific(candidate: &V32CandidateRecord, api_path: &str) -> bool {
    let is_fallback = matches!(
        (candidate.pattern_family, api_path),
        (V32PatternFamily::NativeLibraryBoundary, "extern")
            | (
                V32PatternFamily::RetainedBorrowedCallback,
                "callback_registration"
            )
            | (
                V32PatternFamily::CallbackLifecycleRelease,
                "callback_unregistration"
            )
            | (
                V32PatternFamily::ForeignRetainedPointer,
                "foreign_retained_pointer"
            )
            | (V32PatternFamily::OpaqueHandleTransfer, "opaque_handle")
            | (V32PatternFamily::ReturnedBorrowView, "returned_borrow")
            | (V32PatternFamily::ExternalBufferView, "external_buffer")
    );
    let has_source_span = candidate.evidence_refs.iter().any(|evidence| {
        evidence.kind == V32BoundaryEvidenceKind::SourceSpan
            && !evidence.path.trim().is_empty()
            && evidence.line_start.is_some()
            && evidence.line_end.is_some()
    });
    !is_fallback
        && has_source_span
        && (rust_api_path_is_specific(api_path) || contract_api_id_is_specific(api_path))
}

fn rust_api_path_is_specific(api_path: &str) -> bool {
    api_path
        .split("::")
        .all(|segment| !segment.trim().is_empty())
        && api_path.contains("::")
}

fn contract_api_id_is_specific(api_path: &str) -> bool {
    let mut parts = api_path.split(':');
    let Some(prefix) = parts.next() else {
        return false;
    };
    let Some(component) = parts.next() else {
        return false;
    };
    let Some(name) = parts.next() else {
        return false;
    };
    let Some(role) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && prefix == "api"
        && [prefix, component, name, role]
            .iter()
            .all(|segment| !segment.trim().is_empty())
        && matches!(role, "register" | "unregister" | "replace" | "release")
}

fn active_features(records: &[V326LifecycleFeatureRecord]) -> Vec<String> {
    records
        .iter()
        .flat_map(|record| bw_model::active_feature_names(&record.features))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn unpaired_delta(
    pair: &V326AnonymousPairRecord,
    left: &[V326LifecycleFeatureRecord],
    right: &[V326LifecycleFeatureRecord],
) -> V326PairDeltaRecord {
    V326PairDeltaRecord {
        schema_version: V3_2_7_PAIR_DELTA_SCHEMA_V1.to_owned(),
        run_id: pair.run_id.clone(),
        pair_id: pair.pair_id.clone(),
        comparison_key: String::new(),
        pair_manifest_run_id: String::new(),
        left_crate_id: pair.left_crate_id.clone(),
        right_crate_id: pair.right_crate_id.clone(),
        left_top_features: active_features(left),
        right_top_features: active_features(right),
        semantic_delta: Vec::new(),
        distinguishability: V326Distinguishability::Unpaired,
        notes: vec![
            "pair roles are anonymous; this is not a defect conclusion".to_owned(),
            "candidate API and pattern alignment is missing on at least one side".to_owned(),
        ],
    }
}

fn insufficient_alignment_delta(
    pair: &V326AnonymousPairRecord,
    left: &[V326LifecycleFeatureRecord],
    right: &[V326LifecycleFeatureRecord],
) -> V326PairDeltaRecord {
    V326PairDeltaRecord {
        schema_version: V3_2_7_PAIR_DELTA_SCHEMA_V1.to_owned(),
        run_id: pair.run_id.clone(),
        pair_id: pair.pair_id.clone(),
        comparison_key: String::new(),
        pair_manifest_run_id: String::new(),
        left_crate_id: pair.left_crate_id.clone(),
        right_crate_id: pair.right_crate_id.clone(),
        left_top_features: active_features(left),
        right_top_features: active_features(right),
        semantic_delta: Vec::new(),
        distinguishability: V326Distinguishability::InsufficientEvidence,
        notes: vec![
            "pair roles are anonymous; this is not a defect conclusion".to_owned(),
            "candidate alignment is ambiguous or lifecycle evidence is insufficient".to_owned(),
        ],
    }
}

fn augment_pair_delta_notes(
    delta: &mut V326PairDeltaRecord,
    left: &[V326LifecycleFeatureRecord],
    right: &[V326LifecycleFeatureRecord],
    coverage_by_candidate: &BTreeMap<String, V326LifecycleCoverageRecord>,
) {
    if matches!(
        delta.distinguishability,
        V326Distinguishability::SeparableStatic
    ) {
        return;
    }
    let mut notes = BTreeSet::<String>::new();
    for feature in left.iter().chain(right.iter()) {
        if bw_model::active_feature_names(&feature.features).is_empty() {
            notes.insert("aligned candidate has no active lifecycle feature".to_owned());
        }
        let release_is_proven = feature.features.release_covers_callback;
        for missing in &feature.missing_evidence {
            notes.extend(pair_gap_notes_from_missing_evidence(
                missing,
                release_is_proven,
            ));
        }
        if let Some(coverage) = coverage_by_candidate.get(&feature.candidate_id) {
            for gap in &coverage.unavailable_paths {
                notes.extend(pair_gap_notes_from_coverage_reason(
                    gap.reason,
                    release_is_proven,
                ));
            }
            if coverage.fact_refs.is_empty() {
                notes.insert("aligned candidate has no lifecycle fact refs".to_owned());
            }
        }
    }
    for note in notes {
        if !delta.notes.iter().any(|existing| existing == &note) {
            delta.notes.push(note);
        }
    }
}

fn pair_gap_notes_from_missing_evidence(missing: &str, release_is_proven: bool) -> Vec<String> {
    let mut notes = Vec::new();
    if missing.contains("foreign_contract_missing") {
        notes.push("foreign contract coverage is missing for aligned candidate".to_owned());
    }
    if missing.contains("mir_hir_fact_missing") || missing.contains("static_facts_missing") {
        notes.push("MIR/HIR static fact coverage is missing for aligned candidate".to_owned());
    }
    if missing.contains("object_binding_unproven")
        || missing.contains("callback_object_identity_unavailable")
    {
        notes.push(
            "cross-function object binding proof is unavailable for aligned candidate".to_owned(),
        );
    }
    if !release_is_proven
        && (missing.contains("release_coverage")
            || missing.contains("release_order_unknown")
            || missing.contains("release_endpoint_missing")
            || missing.contains("no unregister"))
    {
        notes.push(
            "release coverage or ordering proof is unavailable for aligned candidate".to_owned(),
        );
    }
    if missing.contains("source_only") {
        notes.push("source-only scope gap remains for aligned candidate".to_owned());
    }
    if missing.contains("raw_pointer") {
        notes.push("raw-pointer binding proof is incomplete for aligned candidate".to_owned());
    }
    notes
}

fn pair_gap_notes_from_coverage_reason(
    reason: V326CoverageGapReason,
    release_is_proven: bool,
) -> Vec<String> {
    match reason {
        V326CoverageGapReason::StaticFactsMissing => {
            vec!["MIR/HIR static fact coverage is missing for aligned candidate".to_owned()]
        }
        V326CoverageGapReason::SourceOnlyFallback | V326CoverageGapReason::InsufficientSpan => {
            vec!["source-only scope gap remains for aligned candidate".to_owned()]
        }
        V326CoverageGapReason::DropImplUnavailable if !release_is_proven => {
            vec![
                "release coverage or ordering proof is unavailable for aligned candidate"
                    .to_owned(),
            ]
        }
        V326CoverageGapReason::DropImplUnavailable => Vec::new(),
        V326CoverageGapReason::MacroExpansion
        | V326CoverageGapReason::MissingDependency
        | V326CoverageGapReason::CompileCfg => Vec::new(),
    }
}

fn comparison_key(pair: &V326AnonymousPairRecord, alignment: &CandidateAlignmentKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"boundary-witness:v3-2-7:anonymous-pair-alignment");
    hasher.update([0]);
    hasher.update(pair.pair_id.as_bytes());
    hasher.update([0]);
    hasher.update(format!("{:?}", alignment.pattern_family).as_bytes());
    hasher.update([0]);
    hasher.update(alignment.api_path.as_bytes());
    hasher.update([0]);
    hasher.update([u8::from(alignment.api_identity_is_specific)]);
    format!("comparison:{:x}", hasher.finalize())
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

fn write_checksums(output_dir: &Path, checksums_path: &Path) -> Result<(), CliError> {
    let mut lines = vec![
        format!(
            "{}  {}",
            sha256_file(&output_dir.join("pair-deltas.jsonl.zst"))?,
            "pair-deltas.jsonl.zst"
        ),
        format!(
            "{}  {}",
            sha256_file(&output_dir.join("distinguishability-summary.json"))?,
            "distinguishability-summary.json"
        ),
    ];
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
