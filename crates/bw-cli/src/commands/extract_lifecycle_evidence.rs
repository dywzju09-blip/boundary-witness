use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use bw_model::{
    StaticFactEnvelope, V32BoundaryEvidenceKind, V32BoundaryIndexRecord, V32BoundaryKind,
    V32CandidateRecord, V32CorpusManifestRecord, V32CorpusSourceKind, V326CoverageGap,
    V326CoverageGapReason, V326EvidenceConfidence, V326EvidenceKind, V326LifecycleCoverageRecord,
    V326LifecycleEvidenceRecord, V326LifecycleFactKind, V326LifecycleFactProvenance,
    V326LifecycleFactRecord, V326SourceRef, lifecycle_fact_from_static_fact,
    validate_v3_2_6_lifecycle_coverage, validate_v3_2_6_lifecycle_evidence,
    validate_v3_2_6_lifecycle_facts, validate_v3_2_boundary_index, validate_v3_2_candidates,
    validate_v3_2_corpus_manifest, verify_v3_2_6_lifecycle_fact_static_provenance,
};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    commands::{
        DEFAULT_MAX_LINE_BYTES, hex_digest, load_candidates, read_jsonl, strip_rust_comments,
        write_json_file, write_records,
    },
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct ExtractLifecycleEvidenceArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long = "boundary-index")]
    boundary_index: PathBuf,
    #[arg(long)]
    candidates: PathBuf,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long = "static-facts")]
    static_facts: Option<PathBuf>,
    #[arg(long = "mir-coverage")]
    mir_coverage: Option<PathBuf>,
    #[arg(long)]
    run_id: String,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

#[derive(Serialize)]
struct ExtractOutput {
    kind: &'static str,
    run_id: String,
    evidence_count: u64,
    fact_count: u64,
    coverage_count: u64,
    output_dir: String,
    evidence_path: String,
    facts_path: String,
    coverage_path: String,
    checksums_path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MirCoverageReport {
    schema_version: String,
    expected_packages: Vec<MirCoveragePackage>,
    seen_packages: Vec<MirCoveragePackage>,
    seen_targets: Vec<MirCoverageTarget>,
    seen_bodies: Vec<MirCoverageBody>,
    skipped: Vec<MirCoverageSkippedBody>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MirCoveragePackage {
    name: String,
    version: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MirCoverageTarget {
    package: String,
    version: String,
    target: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MirCoverageBody {
    package: String,
    version: String,
    target: String,
    def_path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MirCoverageSkippedBody {
    package: String,
    version: String,
    target: String,
    def_path: String,
    reason: String,
}

#[derive(Clone, Debug)]
struct SourceLine {
    path: String,
    line_number: u64,
    text: String,
    scan_text: String,
}

#[derive(Clone, Debug)]
struct SourceCatalog {
    lines: Vec<SourceLine>,
    path_line_indexes: BTreeMap<String, Vec<usize>>,
}

#[derive(Clone, Debug)]
struct SourceSpan {
    path: String,
    line_start: u64,
    line_end: u64,
}

#[derive(Clone, Debug)]
struct CandidateScope {
    spans: Vec<SourceSpan>,
    api_paths: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct StaticFactSelection {
    fact_indexes: Vec<usize>,
    anchor_record_ids: Vec<String>,
}

pub fn run(args: ExtractLifecycleEvidenceArgs) -> Result<CommandStatus, CliError> {
    if args.run_id.trim().is_empty() {
        return Err(CliError::input("BW-V326-RUN-ID", "run_id 不能为空"));
    }

    let manifest_records =
        read_jsonl::<V32CorpusManifestRecord>(&args.manifest, args.max_line_bytes)?;
    validate_v3_2_corpus_manifest(manifest_records.clone())?;

    let boundary_records =
        read_jsonl::<V32BoundaryIndexRecord>(&args.boundary_index, args.max_line_bytes)?;
    validate_v3_2_boundary_index(boundary_records.clone())?;

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
    let candidates_by_id = candidates
        .iter()
        .map(|candidate| (candidate.candidate_id.clone(), candidate))
        .collect::<BTreeMap<_, _>>();

    let static_facts = match &args.static_facts {
        Some(path) => read_jsonl::<StaticFactEnvelope>(path, args.max_line_bytes)?,
        None => Vec::new(),
    };
    let static_fact_envelopes = static_facts
        .iter()
        .map(|located| located.value.clone())
        .collect::<Vec<_>>();
    let mir_coverage = match &args.mir_coverage {
        Some(path) => Some(read_mir_coverage(path)?),
        None => None,
    };

    let boundary_by_id = boundary_records
        .into_iter()
        .map(|located| (located.value.boundary_id.clone(), located.value))
        .collect::<BTreeMap<_, _>>();
    let manifest_dir = args.manifest.parent().unwrap_or_else(|| Path::new("."));
    let manifest_by_crate = manifest_records
        .into_iter()
        .map(|located| (located.value.crate_id.clone(), located.value))
        .collect::<BTreeMap<_, _>>();
    let mut candidate_scopes_by_crate = BTreeMap::<String, Vec<(String, CandidateScope)>>::new();
    for candidate in &candidates {
        candidate_scopes_by_crate
            .entry(candidate.crate_id.clone())
            .or_default()
            .push((
                candidate.candidate_id.clone(),
                CandidateScope::from_candidate(
                    candidate,
                    boundary_by_id.get(&candidate.boundary_id),
                ),
            ));
    }

    let mut evidence = Vec::<V326LifecycleEvidenceRecord>::new();
    let mut source_cache = BTreeMap::<String, SourceCatalog>::new();
    for candidate in &candidates {
        let boundary = boundary_by_id.get(&candidate.boundary_id);
        let crate_scopes = candidate_scopes_by_crate
            .get(&candidate.crate_id)
            .expect("candidate scope is populated for candidate crate");
        let scope = crate_scopes
            .iter()
            .find(|(candidate_id, _)| candidate_id == &candidate.candidate_id)
            .map(|(_, scope)| scope)
            .expect("candidate scope is populated for candidate");
        if scope.spans.is_empty() {
            continue;
        }
        let Some(manifest) = manifest_by_crate.get(&candidate.crate_id) else {
            return Err(CliError::input(
                "BW-V326-MANIFEST-MISSING",
                format!(
                    "candidate crate_id {} 在 corpus manifest 中不存在",
                    candidate.crate_id
                ),
            ));
        };
        if !source_cache.contains_key(&candidate.crate_id) {
            let source_root = resolve_local_source(manifest_dir, manifest)?;
            source_cache.insert(
                candidate.crate_id.clone(),
                collect_source_lines(&source_root)?,
            );
        }
        let source_catalog = source_cache
            .get(&candidate.crate_id)
            .expect("source cache is populated for candidate crate");
        let source_indexes =
            scope.source_line_indexes(source_catalog, &candidate.candidate_id, crate_scopes);
        let mut ordinal = 0_u32;
        for index in source_indexes {
            let line = &source_catalog.lines[index];
            let mut classified = classify_line(line);
            if boundary_has_exact_source_anchor(
                boundary,
                V32BoundaryKind::CallbackRegistration,
                line,
            ) {
                classified.push((
                    V326EvidenceKind::ForeignRegister,
                    boundary_evidence_confidence(boundary),
                    serde_json::json!({"signal":"callback registration boundary anchor"}),
                ));
            }
            if boundary_has_exact_source_anchor(
                boundary,
                V32BoundaryKind::CallbackUnregistration,
                line,
            ) {
                let confidence = boundary_evidence_confidence(boundary);
                classified.push((
                    V326EvidenceKind::ForeignUnregister,
                    confidence,
                    serde_json::json!({"signal":"callback unregistration boundary anchor"}),
                ));
                classified.push((
                    V326EvidenceKind::ReleaseSite,
                    confidence,
                    serde_json::json!({"signal":"callback unregistration boundary anchor"}),
                ));
            }
            for (kind, confidence, details) in classified {
                ordinal += 1;
                evidence.push(V326LifecycleEvidenceRecord {
                    schema_version: bw_model::V3_2_6_LIFECYCLE_EVIDENCE_SCHEMA_V1.to_owned(),
                    run_id: args.run_id.clone(),
                    record_id: format!(
                        "evidence:{}:{}:{:04}",
                        sanitize_id(&candidate.crate_id),
                        sanitize_id(&candidate.candidate_id),
                        ordinal
                    ),
                    crate_id: candidate.crate_id.clone(),
                    candidate_id: candidate.candidate_id.clone(),
                    evidence_kind: kind,
                    source_ref: V326SourceRef {
                        path: line.path.clone(),
                        line_start: Some(line.line_number),
                        line_end: Some(line.line_number),
                        symbol_path: candidate.api_path.clone(),
                        text_sha256: Some(hex_digest(Sha256::digest(line.text.as_bytes()))),
                    },
                    confidence,
                    details,
                    notes: vec!["neutral lifecycle evidence; not a defect conclusion".to_owned()],
                });
            }
        }
    }

    evidence.sort_by(|left, right| {
        left.candidate_id
            .cmp(&right.candidate_id)
            .then_with(|| left.record_id.cmp(&right.record_id))
    });

    let mut static_selections_by_candidate = candidates
        .iter()
        .map(|candidate| {
            let boundary = boundary_by_id.get(&candidate.boundary_id);
            let manifest = manifest_by_crate
                .get(&candidate.crate_id)
                .expect("candidate crate is present in the corpus manifest");
            let scope = CandidateScope::from_candidate(candidate, boundary);
            let crate_scopes = candidate_scopes_by_crate
                .get(&candidate.crate_id)
                .map(Vec::as_slice)
                .unwrap_or_default();
            (
                candidate.candidate_id.clone(),
                scoped_static_facts_for_candidate(
                    &static_facts,
                    &scope,
                    &candidate.candidate_id,
                    crate_scopes,
                    manifest,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    expand_returned_borrow_chain_static_selections(
        &mut static_selections_by_candidate,
        &static_facts,
        &candidates_by_id,
        &manifest_by_crate,
    );
    // 借用捕获只能来自编译器事实，不能来自源码文本。
    //
    // `classify_line` 的 BorrowEdge 规则要求同一行里同时出现 `&local` 和裸指针转换
    // ——那是手写 FFI 的形态。安全封装侧的 `move |..| { borrowed.record(1) }` 永远
    // 命中不了，于是 `has_borrowed_capture` 恒为假，而它恰好是这类漏洞唯一的判别
    // 特征：排名于是只能靠"检测到多少保护"区分候选，保护检测得越少反而排得越高。
    //
    // 归属沿用 `scoped_static_facts_for_candidate` 的选择结果，不另造一套。按源码
    // 行邻近归属是行不通的：注册在调用那一行，捕获在闭包体内，两者相隔十行以上。
    // 真正把它们连起来的是共享的 `callback_site_id`，而那正是该函数的 site 跳转
    // 已经在做的事。
    for (candidate_id, selection) in &static_selections_by_candidate {
        let Some(candidate) = candidates_by_id.get(candidate_id) else {
            continue;
        };
        let mut ordinal = 0_u32;
        for index in &selection.fact_indexes {
            let envelope = &static_facts[*index].value;
            let bw_model::StaticFact::CallbackCapture(fact) = &envelope.payload else {
                continue;
            };
            if fact.capture_mode != bw_model::CaptureMode::Borrowed {
                continue;
            }
            let Some(source_ref) = &envelope.source_ref else {
                continue;
            };
            ordinal += 1;
            evidence.push(V326LifecycleEvidenceRecord {
                schema_version: bw_model::V3_2_6_LIFECYCLE_EVIDENCE_SCHEMA_V1.to_owned(),
                run_id: args.run_id.clone(),
                record_id: format!(
                    "evidence:{}:{}:borrow-edge:{:04}",
                    sanitize_id(&candidate.crate_id),
                    sanitize_id(candidate_id),
                    ordinal
                ),
                crate_id: candidate.crate_id.clone(),
                candidate_id: candidate_id.clone(),
                evidence_kind: V326EvidenceKind::BorrowEdge,
                source_ref: V326SourceRef {
                    path: source_ref.path.clone(),
                    line_start: Some(source_ref.line_start),
                    line_end: Some(source_ref.line_end),
                    symbol_path: source_ref.symbol_path.clone(),
                    // 事实侧不带行文本，摘要留空而不是补一个算不出来的值。
                    text_sha256: None,
                },
                // 编译器事实，不是文本猜测。
                confidence: V326EvidenceConfidence::High,
                details: serde_json::json!({
                    "signal": "compiler callback capture with borrowed capture mode",
                    "capture_ordinal": fact.capture_ordinal,
                }),
                notes: vec!["neutral lifecycle evidence; not a defect conclusion".to_owned()],
            });
        }
    }
    evidence.sort_by(|left, right| {
        left.candidate_id
            .cmp(&right.candidate_id)
            .then_with(|| left.record_id.cmp(&right.record_id))
    });

    let mut static_fact_claimants = BTreeMap::<String, BTreeSet<String>>::new();
    for (candidate_id, selection) in &static_selections_by_candidate {
        for index in &selection.fact_indexes {
            static_fact_claimants
                .entry(static_fact_identity_key(&static_facts[*index].value))
                .or_default()
                .insert(candidate_id.clone());
        }
    }
    let mut canonical_static_fact_claimants = canonical_returned_borrow_static_fact_claimants(
        &static_fact_claimants,
        &static_selections_by_candidate,
        &static_facts,
        &candidates_by_id,
    );
    canonical_static_fact_claimants.extend(canonical_registration_static_fact_claimants(
        &static_fact_claimants,
        &static_facts,
        &candidates_by_id,
    ));
    canonical_static_fact_claimants.extend(canonical_callback_user_data_static_fact_claimants(
        &static_fact_claimants,
        &static_facts,
        &candidates_by_id,
    ));
    canonical_static_fact_claimants.extend(
        canonical_callback_user_data_object_flow_static_fact_claimants(
            &static_fact_claimants,
            &static_facts,
            &candidates_by_id,
        ),
    );
    append_signature_lifetime_bound_evidence(
        &mut evidence,
        &args.run_id,
        &candidates,
        &static_selections_by_candidate,
        &static_facts,
        &static_fact_claimants,
        &manifest_by_crate,
        manifest_dir,
        &mut source_cache,
    )?;
    append_sibling_unregistration_evidence(
        &mut evidence,
        &args.run_id,
        &candidates,
        &boundary_by_id,
        &candidate_scopes_by_crate,
        &static_facts,
        &manifest_by_crate,
    );
    evidence.sort_by(|left, right| {
        left.candidate_id
            .cmp(&right.candidate_id)
            .then_with(|| left.record_id.cmp(&right.record_id))
    });

    let mut facts = Vec::<V326LifecycleFactRecord>::new();
    let mut coverage = Vec::<V326LifecycleCoverageRecord>::new();
    for candidate in &candidates {
        let selection = static_selections_by_candidate
            .get(&candidate.candidate_id)
            .expect("static fact selection must exist for every candidate");
        let mut candidate_facts = Vec::<V326LifecycleFactRecord>::new();
        let mut exclusive_static_count = 0_u64;
        for index in &selection.fact_indexes {
            let located = &static_facts[*index];
            let identity = static_fact_identity_key(&located.value);
            let unique_claimant = static_fact_claimants
                .get(&identity)
                .is_some_and(|claimants| claimants.len() == 1);
            let canonical_claimant = canonical_static_fact_claimants
                .get(&identity)
                .is_some_and(|claimant| claimant == &candidate.candidate_id);
            if !unique_claimant && !canonical_claimant {
                continue;
            }
            let source_ref = source_ref_from_static_fact(&located.value);
            let evidence_refs =
                evidence_refs_near_source(&evidence, &candidate.candidate_id, &source_ref);
            if let Some(mut fact) = lifecycle_fact_from_static_fact(
                &args.run_id,
                candidate,
                &located.value,
                source_ref,
                evidence_refs,
            ) {
                fact.provenance.static_anchor_record_ids = selection.anchor_record_ids.clone();
                if verify_v3_2_6_lifecycle_fact_static_provenance(
                    &mut fact,
                    candidate,
                    &static_fact_envelopes,
                ) {
                    candidate_facts.push(fact);
                    exclusive_static_count += 1;
                }
            }
        }
        // Source-derived facts are non-authoritative observations. Emit them when this
        // candidate has no exclusive static facts, even if a global --static-facts file
        // exists for other candidates. They must never alone prove object identity,
        // release coverage, ordering, or raw-pointer binding.
        if exclusive_static_count == 0 {
            let source_facts = derive_source_facts_for_candidate(
                &args.run_id,
                candidate,
                &evidence
                    .iter()
                    .filter(|item| item.candidate_id == candidate.candidate_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            candidate_facts.extend(source_facts);
        }
        let coverage_record = coverage_for_candidate(
            &args.run_id,
            candidate,
            &candidate_facts,
            exclusive_static_count == 0,
            mir_coverage.as_ref(),
        );
        facts.extend(candidate_facts);
        coverage.push(coverage_record);
    }
    facts.sort_by(|left, right| {
        left.candidate_id
            .cmp(&right.candidate_id)
            .then_with(|| left.fact_id.cmp(&right.fact_id))
    });
    coverage.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));

    validate_v3_2_6_lifecycle_evidence(evidence.iter().cloned().enumerate().map(
        |(index, value)| bw_model::Located {
            path: args.output_dir.join("lifecycle-evidence.jsonl.zst"),
            line: index + 1,
            value,
        },
    ))?;
    validate_v3_2_6_lifecycle_facts(facts.iter().cloned().enumerate().map(|(index, value)| {
        bw_model::Located {
            path: args.output_dir.join("lifecycle-facts.jsonl.zst"),
            line: index + 1,
            value,
        }
    }))?;
    validate_v3_2_6_lifecycle_coverage(coverage.iter().cloned().enumerate().map(
        |(index, value)| bw_model::Located {
            path: args.output_dir.join("lifecycle-coverage.jsonl.zst"),
            line: index + 1,
            value,
        },
    ))?;

    fs::create_dir_all(&args.output_dir)?;
    let evidence_path = args.output_dir.join("lifecycle-evidence.jsonl.zst");
    write_records(&evidence_path, &evidence)?;
    let facts_path = args.output_dir.join("lifecycle-facts.jsonl.zst");
    write_records(&facts_path, &facts)?;
    let coverage_path = args.output_dir.join("lifecycle-coverage.jsonl.zst");
    write_records(&coverage_path, &coverage)?;

    let stats = serde_json::json!({
        "schema_version": "v3.2.6.lifecycle_evidence_stats.1",
        "run_id": args.run_id,
        "evidence_count": evidence.len(),
        "fact_count": facts.len(),
        "coverage_count": coverage.len(),
        "candidate_count": candidates.len(),
        "kind_counts": kind_counts(&evidence),
    });
    write_json_file(&args.output_dir.join("evidence-stats.json"), &stats)?;

    let checksums_path = args.output_dir.join("checksums.txt");
    write_checksums(&args.output_dir, &checksums_path)?;

    let output = ExtractOutput {
        kind: "v3-2-6-lifecycle-evidence",
        run_id: args.run_id,
        evidence_count: evidence.len() as u64,
        fact_count: facts.len() as u64,
        coverage_count: coverage.len() as u64,
        output_dir: args.output_dir.display().to_string(),
        evidence_path: evidence_path.display().to_string(),
        facts_path: facts_path.display().to_string(),
        coverage_path: coverage_path.display().to_string(),
        checksums_path: checksums_path.display().to_string(),
    };
    crate::commands::write_json_stdout(&output)?;
    Ok(CommandStatus::Success)
}

impl CandidateScope {
    const CONTEXT_RADIUS: u64 = 3;

    fn from_candidate(
        candidate: &V32CandidateRecord,
        boundary: Option<&V32BoundaryIndexRecord>,
    ) -> Self {
        let mut spans = candidate_source_spans(candidate);
        if let Some(boundary) = boundary {
            spans.extend(boundary_source_spans(boundary));
        }
        spans.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.line_start.cmp(&right.line_start))
                .then_with(|| left.line_end.cmp(&right.line_end))
        });
        spans.dedup_by(|left, right| {
            left.path == right.path
                && left.line_start == right.line_start
                && left.line_end == right.line_end
        });

        let mut api_paths = Vec::new();
        if let Some(api_path) = &candidate.api_path {
            api_paths.push(normalize_api_path(api_path));
        }
        if let Some(boundary) = boundary.and_then(|record| record.api_path.as_ref()) {
            api_paths.push(normalize_api_path(boundary));
        }
        api_paths.sort();
        api_paths.dedup();

        Self { spans, api_paths }
    }

    fn source_line_indexes(
        &self,
        catalog: &SourceCatalog,
        candidate_id: &str,
        crate_scopes: &[(String, CandidateScope)],
    ) -> Vec<usize> {
        if self.spans.is_empty() {
            return Vec::new();
        }

        let mut indexes = Vec::new();
        for span in &self.spans {
            let Some(path_indexes) = catalog.path_line_indexes.get(&span.path) else {
                continue;
            };
            indexes.extend(path_indexes.iter().copied().filter(|index| {
                let line = &catalog.lines[*index];
                span.contains(line) && self.owns_source_line(line, candidate_id, crate_scopes)
            }));
        }
        indexes.sort_unstable();
        indexes.dedup();
        indexes
    }

    fn owns_source_line(
        &self,
        line: &SourceLine,
        candidate_id: &str,
        crate_scopes: &[(String, CandidateScope)],
    ) -> bool {
        let Some(self_distance) = self.distance_to_source_line(line) else {
            return false;
        };
        let owner_distances = crate_scopes
            .iter()
            .filter_map(|(other_id, scope)| {
                scope
                    .distance_to_source_line(line)
                    .map(|distance| (other_id.as_str(), distance))
            })
            .collect::<Vec<_>>();
        unique_nearest_candidate_owner(&owner_distances).is_some_and(
            |(owner_id, owner_distance)| {
                owner_id == candidate_id && owner_distance == self_distance
            },
        )
    }

    fn owns_source_ref(
        &self,
        source_ref: &V326SourceRef,
        candidate_id: &str,
        crate_scopes: &[(String, CandidateScope)],
    ) -> bool {
        let Some(self_distance) = self.distance_to_source_ref(source_ref) else {
            return false;
        };
        let owner_distances = crate_scopes
            .iter()
            .filter_map(|(other_id, scope)| {
                scope
                    .distance_to_source_ref(source_ref)
                    .map(|distance| (other_id.as_str(), distance))
            })
            .collect::<Vec<_>>();
        unique_nearest_candidate_owner(&owner_distances).is_some_and(
            |(owner_id, owner_distance)| {
                owner_id == candidate_id && owner_distance == self_distance
            },
        )
    }

    fn distance_to_source_line(&self, line: &SourceLine) -> Option<u64> {
        self.spans
            .iter()
            .filter_map(|span| span.distance_to_line(line))
            .min()
    }

    fn distance_to_source_ref(&self, source_ref: &V326SourceRef) -> Option<u64> {
        let Some(line_start) = source_ref.line_start else {
            return None;
        };
        let line_end = source_ref.line_end.unwrap_or(line_start);
        let path = normalize_source_path(&source_ref.path);
        self.spans
            .iter()
            .filter(|span| span.path == path)
            .filter_map(|span| span.distance_to_range(line_start, line_end))
            .min()
    }

    fn contains_source_ref(&self, source_ref: &V326SourceRef) -> bool {
        self.distance_to_source_ref(source_ref).is_some()
    }
}

fn unique_nearest_candidate_owner<'a>(distances: &'a [(&'a str, u64)]) -> Option<(&'a str, u64)> {
    let min_distance = distances.iter().map(|(_, distance)| *distance).min()?;
    let nearest = distances
        .iter()
        .filter(|(_, distance)| *distance == min_distance)
        .copied()
        .collect::<Vec<_>>();
    if nearest.len() == 1 {
        nearest.first().copied()
    } else {
        None
    }
}

impl SourceCatalog {
    fn new(lines: Vec<SourceLine>) -> Self {
        let mut path_line_indexes = BTreeMap::<String, Vec<usize>>::new();
        for (index, line) in lines.iter().enumerate() {
            path_line_indexes
                .entry(line.path.clone())
                .or_default()
                .push(index);
        }
        Self {
            lines,
            path_line_indexes,
        }
    }
}

impl SourceSpan {
    fn contains(&self, line: &SourceLine) -> bool {
        if self.path != normalize_source_path(&line.path) {
            return false;
        }
        let expanded_start = self
            .line_start
            .saturating_sub(CandidateScope::CONTEXT_RADIUS);
        let expanded_end = self.line_end.saturating_add(CandidateScope::CONTEXT_RADIUS);
        line.line_number >= expanded_start && line.line_number <= expanded_end
    }

    fn distance_to_line(&self, line: &SourceLine) -> Option<u64> {
        if self.path != normalize_source_path(&line.path) {
            return None;
        }
        self.distance_to_range(line.line_number, line.line_number)
    }

    fn distance_to_range(&self, line_start: u64, line_end: u64) -> Option<u64> {
        let range_start = line_start.min(line_end);
        let range_end = line_start.max(line_end);
        let distance = if range_end < self.line_start {
            self.line_start.saturating_sub(range_end)
        } else if range_start > self.line_end {
            range_start.saturating_sub(self.line_end)
        } else {
            0
        };
        (distance <= CandidateScope::CONTEXT_RADIUS).then_some(distance)
    }
}

fn candidate_source_spans(candidate: &V32CandidateRecord) -> Vec<SourceSpan> {
    candidate
        .evidence_refs
        .iter()
        .filter(|evidence| evidence.kind == V32BoundaryEvidenceKind::SourceSpan)
        .filter_map(|evidence| {
            let line_start = evidence.line_start?;
            let line_end = evidence.line_end?;
            Some(SourceSpan {
                path: normalize_source_path(&evidence.path),
                line_start,
                line_end,
            })
        })
        .collect()
}

fn boundary_source_spans(boundary: &V32BoundaryIndexRecord) -> Vec<SourceSpan> {
    boundary
        .evidence_refs
        .iter()
        .filter(|evidence| evidence.kind == V32BoundaryEvidenceKind::SourceSpan)
        .filter_map(|evidence| {
            let line_start = evidence.line_start?;
            let line_end = evidence.line_end?;
            Some(SourceSpan {
                path: normalize_source_path(&evidence.path),
                line_start,
                line_end,
            })
        })
        .collect()
}

fn normalize_api_path(api_path: &str) -> String {
    api_path.trim().to_ascii_lowercase()
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReturnedBorrowApiKey {
    module_prefix: String,
    method: String,
}

fn returned_borrow_api_key(api_path: &str) -> Option<ReturnedBorrowApiKey> {
    if is_source_api_alias(api_path) {
        return None;
    }
    let symbols = normalize_api_path(api_path)
        .split("::")
        .filter_map(source_api_symbol_from_segment)
        .collect::<Vec<_>>();
    if symbols.len() < 3 {
        return None;
    }
    let method = symbols.last()?.clone();
    let module_prefix = symbols[..symbols.len() - 2].join("::");
    (!module_prefix.is_empty()).then_some(ReturnedBorrowApiKey {
        module_prefix,
        method,
    })
}

fn normalize_source_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn classify_line(
    line: &SourceLine,
) -> Vec<(V326EvidenceKind, V326EvidenceConfidence, serde_json::Value)> {
    let lower = line.scan_text.to_ascii_lowercase();
    let mut hits = Vec::new();

    if lower.contains("box::into_raw") {
        hits.push((
            V326EvidenceKind::OwnedAnchor,
            V326EvidenceConfidence::High,
            serde_json::json!({"signal":"box into raw"}),
        ));
    }
    if lower.contains("box::from_raw") {
        hits.push((
            V326EvidenceKind::ReleaseSite,
            V326EvidenceConfidence::High,
            serde_json::json!({"signal":"box from raw"}),
        ));
    }
    if lower.contains("arc::") || lower.contains("std::sync::arc") {
        hits.push((
            V326EvidenceKind::OwnedAnchor,
            V326EvidenceConfidence::High,
            serde_json::json!({"signal":"arc anchor"}),
        ));
    }
    if lower.contains(" as *mut ") || lower.contains(" as *const ") {
        hits.push((
            V326EvidenceKind::RawPointerEscape,
            V326EvidenceConfidence::Medium,
            serde_json::json!({"signal":"raw pointer cast"}),
        ));
    }
    if lower.contains("impl drop") {
        hits.push((
            V326EvidenceKind::DropGuard,
            V326EvidenceConfidence::High,
            serde_json::json!({"signal":"drop impl"}),
        ));
    }
    if (lower.contains("&local") || lower.contains("&mut local") || lower.contains("&local "))
        && (lower.contains(" as *mut ") || lower.contains(" as *const "))
    {
        hits.push((
            V326EvidenceKind::BorrowEdge,
            V326EvidenceConfidence::Medium,
            serde_json::json!({"signal":"local borrow into raw pointer"}),
        ));
    }
    if lower.contains("'static") {
        hits.push((
            V326EvidenceKind::LifetimeBound,
            V326EvidenceConfidence::High,
            serde_json::json!({"signal":"static lifetime bound"}),
        ));
    }

    hits
}

fn derive_source_facts_for_candidate(
    run_id: &str,
    candidate: &V32CandidateRecord,
    evidence: &[V326LifecycleEvidenceRecord],
) -> Vec<V326LifecycleFactRecord> {
    evidence
        .iter()
        .filter_map(|item| source_fact_kind(item.evidence_kind).map(|kind| (item, kind)))
        .map(|(item, fact_kind)| {
            let suffix = source_fact_suffix(fact_kind);
            V326LifecycleFactRecord {
                schema_version: bw_model::V3_2_6_LIFECYCLE_FACT_SCHEMA_V1.to_owned(),
                run_id: run_id.to_owned(),
                candidate_id: candidate.candidate_id.clone(),
                crate_id: candidate.crate_id.clone(),
                fact_id: source_fact_id(candidate, item, suffix),
                fact_kind,
                source_ref: item.source_ref.clone(),
                symbol_path: item
                    .source_ref
                    .symbol_path
                    .clone()
                    .or_else(|| candidate.api_path.clone()),
                confidence: item.confidence,
                coverage_state: bw_model::V326CoverageState::Covered,
                provenance: V326LifecycleFactProvenance::source_observation(),
                object_ids: source_fact_object_ids(item),
                evidence_refs: vec![item.record_id.clone()],
                notes: vec![
                    "source-derived candidate-scoped lifecycle fact; not a defect conclusion"
                        .to_owned(),
                ],
            }
        })
        .collect()
}

fn source_fact_kind(kind: V326EvidenceKind) -> Option<V326LifecycleFactKind> {
    match kind {
        V326EvidenceKind::ForeignRegister => Some(V326LifecycleFactKind::RegisterCall),
        V326EvidenceKind::ForeignUnregister => Some(V326LifecycleFactKind::UnregisterCall),
        V326EvidenceKind::ForeignReplace => Some(V326LifecycleFactKind::ReplaceCall),
        V326EvidenceKind::ReleaseSite => Some(V326LifecycleFactKind::ReleaseCall),
        V326EvidenceKind::BorrowEdge => Some(V326LifecycleFactKind::BorrowedCapture),
        V326EvidenceKind::MoveEdge | V326EvidenceKind::OwnedAnchor => {
            Some(V326LifecycleFactKind::OwnedMoveCapture)
        }
        V326EvidenceKind::RawPointerEscape => Some(V326LifecycleFactKind::RawPointerEscape),
        V326EvidenceKind::DropGuard | V326EvidenceKind::DropSite => {
            Some(V326LifecycleFactKind::DropSite)
        }
        V326EvidenceKind::CallbackCandidate
        | V326EvidenceKind::ObjectCandidate
        | V326EvidenceKind::CaptureEdge
        | V326EvidenceKind::ForeignRetentionHint
        | V326EvidenceKind::LifetimeBound
        | V326EvidenceKind::OpaqueHandleTransfer => None,
    }
}

fn source_fact_suffix(kind: V326LifecycleFactKind) -> &'static str {
    match kind {
        V326LifecycleFactKind::CallbackDefinition => "callback",
        V326LifecycleFactKind::BorrowedCapture => "borrowed_capture",
        V326LifecycleFactKind::OwnedMoveCapture => "owned_capture",
        V326LifecycleFactKind::DropImpl => "drop_impl",
        V326LifecycleFactKind::DropSite => "drop_site",
        V326LifecycleFactKind::DropPrevention => "drop_prevention",
        V326LifecycleFactKind::RawPointerEscape => "raw_pointer_escape",
        V326LifecycleFactKind::UnsafeCast => "unsafe_cast",
        V326LifecycleFactKind::RegisterCall => "register_call",
        V326LifecycleFactKind::UnregisterCall => "unregister_call",
        V326LifecycleFactKind::ReplaceCall => "replace_call",
        V326LifecycleFactKind::ReleaseCall => "release_call",
        V326LifecycleFactKind::ReleasePathProof => "release_path_proof",
        V326LifecycleFactKind::CallbackReleaseUseOrder => "callback_release_use_order",
        V326LifecycleFactKind::CallbackLifetimeBound => "callback_lifetime_bound",
        V326LifecycleFactKind::TraitImpl => "trait_impl",
        V326LifecycleFactKind::ContractRetention => "contract_retention",
        V326LifecycleFactKind::ReturnedBorrowRelation => "returned_borrow_relation",
        V326LifecycleFactKind::PersistedReturnedBorrow => "persisted_returned_borrow",
        V326LifecycleFactKind::ReturnedBorrowInvalidationOrder => {
            "returned_borrow_invalidation_order"
        }
        V326LifecycleFactKind::ExternalBufferBinding => "external_buffer_binding",
        V326LifecycleFactKind::CallbackUserDataReconstruction => {
            "callback_user_data_reconstruction"
        }
        V326LifecycleFactKind::AtomicOrdering => "atomic_ordering",
        V326LifecycleFactKind::ObjectBindingGap => "object_binding_gap",
        V326LifecycleFactKind::ObjectFlow => "object_flow",
    }
}

fn source_fact_object_ids(item: &V326LifecycleEvidenceRecord) -> Vec<String> {
    vec![format!("source_evidence:{}", sanitize_id(&item.record_id))]
}

fn source_fact_id(
    candidate: &V32CandidateRecord,
    item: &V326LifecycleEvidenceRecord,
    suffix: &str,
) -> String {
    format!(
        "fact:source:{}:{}:{}",
        sanitize_id(&candidate.candidate_id),
        sanitize_id(&item.record_id),
        suffix
    )
}

fn source_ref_from_static_fact(envelope: &StaticFactEnvelope) -> V326SourceRef {
    let source_ref = envelope
        .source_ref
        .as_ref()
        .expect("selected static facts always carry a v0.2 source_ref");
    V326SourceRef {
        path: normalize_source_path(&source_ref.path),
        line_start: Some(source_ref.line_start),
        line_end: Some(source_ref.line_end),
        symbol_path: source_ref
            .symbol_path
            .clone()
            .or_else(|| static_fact_symbol_path(envelope)),
        text_sha256: None,
    }
}

fn static_fact_symbol_path(envelope: &StaticFactEnvelope) -> Option<String> {
    match &envelope.payload {
        bw_model::StaticFact::ObjectSite(fact) => Some(fact.type_name.clone()),
        bw_model::StaticFact::CallbackSite(fact) => Some(fact.def_path.clone()),
        bw_model::StaticFact::RegistrationSite(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::ExternalCallSite(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::ReturnedBorrowRelation(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::PersistedReturnedBorrow(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::ReturnedBorrowInvalidationOrder(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::ExternalBufferBinding(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::AtomicOrdering(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::ObjectBindingGap(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::ObjectFlow(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::CallbackReleaseUseOrder(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::CallbackLifetimeBound(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::RegistrationGuard(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::AllocationOwnership(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::SafeEntryLineage(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::ForeignSymbolBinding(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::CallbackCapture(_)
        | bw_model::StaticFact::DropSite(_)
        | bw_model::StaticFact::DropPrevention(_)
        | bw_model::StaticFact::CallbackUserDataReconstruction(_)
        | bw_model::StaticFact::RawPointerTransfer(_)
        | bw_model::StaticFact::ReleasePathProof(_) => None,
    }
}

fn static_fact_matches_source_api_alias(
    envelope: &StaticFactEnvelope,
    scope: &CandidateScope,
) -> bool {
    if scope.api_paths.is_empty() {
        return false;
    }
    static_fact_source_api_aliases(envelope)
        .iter()
        .any(|alias| {
            scope
                .api_paths
                .iter()
                .filter(|api_path| is_source_api_alias(api_path))
                .any(|api_path| api_path == alias)
        })
}

fn static_fact_matches_exact_api_or_symbol(
    envelope: &StaticFactEnvelope,
    scope: &CandidateScope,
) -> bool {
    if scope.api_paths.is_empty() {
        return false;
    }
    static_fact_api_or_symbol(envelope)
        .as_ref()
        .is_some_and(|fact_api| scope.api_paths.iter().any(|api_path| api_path == fact_api))
}

fn is_source_api_alias(api_path: &str) -> bool {
    api_path.trim().starts_with("source_api::")
}

fn scoped_static_facts_for_candidate(
    static_facts: &[bw_model::Located<StaticFactEnvelope>],
    scope: &CandidateScope,
    candidate_id: &str,
    crate_scopes: &[(String, CandidateScope)],
    manifest: &V32CorpusManifestRecord,
) -> StaticFactSelection {
    const MAX_STATIC_SITE_HOPS: usize = 2;
    let mut selected = vec![false; static_facts.len()];
    let mut linked_sites = BTreeSet::<(String, String)>::new();
    let mut anchor_record_ids = BTreeSet::<String>::new();

    for (index, located) in static_facts.iter().enumerate() {
        if !static_fact_matches_manifest(&located.value, manifest) {
            continue;
        }
        let source_ref = source_ref_from_static_fact(&located.value);
        let callback_user_data_anchor =
            static_fact_matches_callback_user_data_symbol(&located.value, scope)
                && (scope.spans.is_empty() || scope.contains_source_ref(&source_ref));
        let source_anchor = scope.contains_source_ref(&source_ref)
            && scope.owns_source_ref(&source_ref, candidate_id, crate_scopes)
            && !static_fact_is_standard_returned_borrow_adapter(&located.value)
            && !matches!(
                located.value.payload,
                bw_model::StaticFact::CallbackUserDataReconstruction(_)
            );
        let source_api_anchor = static_fact_matches_source_api_alias(&located.value, scope);
        let api_anchor = static_fact_matches_exact_api_or_symbol(&located.value, scope)
            && (scope.spans.is_empty() || source_anchor);
        if source_anchor || callback_user_data_anchor || source_api_anchor || api_anchor {
            selected[index] = true;
            linked_sites.extend(static_fact_site_ids(&located.value));
            anchor_record_ids.insert(located.value.record_id.to_string());
        }
    }

    for _ in 0..MAX_STATIC_SITE_HOPS {
        let hop_sites = linked_sites.clone();
        let mut changed = false;
        for (index, located) in static_facts.iter().enumerate() {
            if selected[index] || !static_fact_matches_manifest(&located.value, manifest) {
                continue;
            }
            let site_ids = static_fact_site_ids(&located.value);
            if site_ids.iter().any(|site_id| hop_sites.contains(site_id)) {
                selected[index] = true;
                linked_sites.extend(site_ids);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    StaticFactSelection {
        fact_indexes: selected
            .into_iter()
            .enumerate()
            .filter_map(|(index, selected)| selected.then_some(index))
            .collect(),
        anchor_record_ids: anchor_record_ids.into_iter().collect(),
    }
}

fn canonical_returned_borrow_static_fact_claimants(
    static_fact_claimants: &BTreeMap<String, BTreeSet<String>>,
    static_selections_by_candidate: &BTreeMap<String, StaticFactSelection>,
    static_facts: &[bw_model::Located<StaticFactEnvelope>],
    candidates_by_id: &BTreeMap<String, &V32CandidateRecord>,
) -> BTreeMap<String, String> {
    let mut canonical = BTreeMap::new();
    for (identity, claimants) in static_fact_claimants {
        if claimants.len() <= 1 {
            continue;
        }
        let Some(located) = static_facts
            .iter()
            .find(|located| static_fact_identity_key(&located.value) == *identity)
        else {
            continue;
        };
        let Some(target_key) = returned_borrow_chain_api_key(&located.value) else {
            continue;
        };
        let target_is_relation = matches!(
            located.value.payload,
            bw_model::StaticFact::ReturnedBorrowRelation(_)
        );
        let exact_anchor_claimants = claimants
            .iter()
            .filter(|candidate_id| {
                let Some(candidate) = candidates_by_id.get(candidate_id.as_str()) else {
                    return false;
                };
                candidate
                    .api_path
                    .as_deref()
                    .and_then(returned_borrow_api_key)
                    .as_ref()
                    == Some(&target_key)
            })
            .filter(|candidate_id| {
                static_selections_by_candidate
                    .get(candidate_id.as_str())
                    .is_some_and(|selection| {
                        if target_is_relation {
                            selection
                                .anchor_record_ids
                                .iter()
                                .any(|record_id| record_id == located.value.record_id.as_str())
                        } else {
                            selection_has_returned_borrow_relation_anchor_for_key(
                                selection,
                                static_facts,
                                &target_key,
                            )
                        }
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        if exact_anchor_claimants.len() == 1 {
            canonical.insert(identity.clone(), exact_anchor_claimants[0].clone());
        }
    }
    canonical
}

fn expand_returned_borrow_chain_static_selections(
    selections_by_candidate: &mut BTreeMap<String, StaticFactSelection>,
    static_facts: &[bw_model::Located<StaticFactEnvelope>],
    candidates_by_id: &BTreeMap<String, &V32CandidateRecord>,
    manifest_by_crate: &BTreeMap<String, V32CorpusManifestRecord>,
) {
    let fact_index_by_record_id = static_facts
        .iter()
        .enumerate()
        .map(|(index, located)| (located.value.record_id.to_string(), index))
        .collect::<BTreeMap<_, _>>();
    for (candidate_id, selection) in selections_by_candidate.iter_mut() {
        let Some(candidate) = candidates_by_id.get(candidate_id.as_str()) else {
            continue;
        };
        let Some(manifest) = manifest_by_crate.get(&candidate.crate_id) else {
            continue;
        };
        let anchored_keys = selection
            .anchor_record_ids
            .iter()
            .filter_map(|record_id| fact_index_by_record_id.get(record_id))
            .filter_map(|index| {
                let envelope = &static_facts[*index].value;
                matches!(
                    envelope.payload,
                    bw_model::StaticFact::ReturnedBorrowRelation(_)
                )
                .then(|| returned_borrow_chain_api_key(envelope))
                .flatten()
            })
            .collect::<BTreeSet<_>>();
        if anchored_keys.is_empty() {
            continue;
        }
        let mut selected = selection
            .fact_indexes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        for (index, located) in static_facts.iter().enumerate() {
            if selected.contains(&index) || !static_fact_matches_manifest(&located.value, manifest)
            {
                continue;
            }
            if !matches!(
                located.value.payload,
                bw_model::StaticFact::PersistedReturnedBorrow(_)
                    | bw_model::StaticFact::ReturnedBorrowInvalidationOrder(_)
            ) {
                continue;
            }
            if returned_borrow_chain_api_key(&located.value)
                .as_ref()
                .is_some_and(|key| anchored_keys.contains(key))
            {
                selected.insert(index);
            }
        }
        selection.fact_indexes = selected.into_iter().collect();
    }
}

/// 注册类静态事实的归属仲裁。
///
/// 带 callback / user_data site id 的注册事实"连接度高"：两跳扩散让很多候选都碰得到它，
/// 唯一性门于是把它整条丢掉。实测 rusqlite 0.26.1：`InnerConnection::update_hook` 的
/// register 事实（源码 546-550，带 callback + user_data site）有 **8 个 claimant**，被
/// 全部丢弃；同一个函数里只带自身 site id 的 unregister 事实（553-553，1 个 claimant）
/// 却留了下来。**事实越完整越容易被丢弃，正好反了**，而且丢的是唯一能给 witness plan
/// 绑定 api_id 的那一类，表现出来只是所有 plan 都"没有 target"。
///
/// 仲裁规则：注册事实归**边界正落在这个调用点上**的候选，即 span 与事实源码范围直接重叠
/// （距离 0）的那个。靠两跳蹭到的候选是邻居，不是所有者。仍然不唯一就不猜，保持丢弃。
fn canonical_registration_static_fact_claimants(
    static_fact_claimants: &BTreeMap<String, BTreeSet<String>>,
    static_facts: &[bw_model::Located<StaticFactEnvelope>],
    candidates_by_id: &BTreeMap<String, &V32CandidateRecord>,
) -> BTreeMap<String, String> {
    let mut canonical = BTreeMap::new();
    for (identity, claimants) in static_fact_claimants {
        if claimants.len() <= 1 {
            continue;
        }
        let Some(located) = static_facts
            .iter()
            .find(|located| static_fact_identity_key(&located.value) == *identity)
        else {
            continue;
        };
        if !matches!(
            located.value.payload,
            bw_model::StaticFact::RegistrationSite(_)
        ) {
            continue;
        }
        let source_ref = source_ref_from_static_fact(&located.value);
        let Some(line_start) = source_ref.line_start else {
            continue;
        };
        let line_end = source_ref.line_end.unwrap_or(line_start);
        let path = normalize_source_path(&source_ref.path);
        let owners = claimants
            .iter()
            .filter(|candidate_id| {
                candidates_by_id
                    .get(candidate_id.as_str())
                    .is_some_and(|candidate| {
                        candidate_source_spans(candidate).iter().any(|span| {
                            span.path == path
                                && span.distance_to_range(line_start, line_end) == Some(0)
                        })
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        if owners.len() == 1 {
            canonical.insert(identity.clone(), owners[0].clone());
        }
    }
    canonical
}

fn canonical_callback_user_data_static_fact_claimants(
    static_fact_claimants: &BTreeMap<String, BTreeSet<String>>,
    static_facts: &[bw_model::Located<StaticFactEnvelope>],
    candidates_by_id: &BTreeMap<String, &V32CandidateRecord>,
) -> BTreeMap<String, String> {
    let mut canonical = BTreeMap::new();
    for (identity, claimants) in static_fact_claimants {
        if claimants.len() <= 1 {
            continue;
        }
        let Some(located) = static_facts
            .iter()
            .find(|located| static_fact_identity_key(&located.value) == *identity)
        else {
            continue;
        };
        if !matches!(
            located.value.payload,
            bw_model::StaticFact::CallbackUserDataReconstruction(_)
        ) {
            continue;
        }

        let expected_static_boundary_id =
            callback_user_data_static_lifecycle_boundary_id(&located.value);
        let source_ref = source_ref_from_static_fact(&located.value);
        let fact_symbol = source_ref.symbol_path.as_deref().map(normalize_api_path);
        let exact_boundary_claimants = claimants
            .iter()
            .filter(|candidate_id| {
                let Some(candidate) = candidates_by_id.get(candidate_id.as_str()) else {
                    return false;
                };
                expected_static_boundary_id
                    .as_ref()
                    .is_some_and(|boundary_id| candidate.boundary_id == *boundary_id)
            })
            .cloned()
            .collect::<Vec<_>>();
        if exact_boundary_claimants.len() == 1 {
            canonical.insert(identity.clone(), exact_boundary_claimants[0].clone());
            continue;
        }
        let exact_api_claimants = claimants
            .iter()
            .filter(|candidate_id| {
                let Some(candidate) = candidates_by_id.get(candidate_id.as_str()) else {
                    return false;
                };
                fact_symbol.as_ref().is_some_and(|symbol| {
                    candidate
                        .api_path
                        .as_deref()
                        .map(normalize_api_path)
                        .as_ref()
                        == Some(symbol)
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        if exact_api_claimants.len() == 1 {
            canonical.insert(identity.clone(), exact_api_claimants[0].clone());
        }
    }
    canonical
}

fn canonical_callback_user_data_object_flow_static_fact_claimants(
    static_fact_claimants: &BTreeMap<String, BTreeSet<String>>,
    static_facts: &[bw_model::Located<StaticFactEnvelope>],
    candidates_by_id: &BTreeMap<String, &V32CandidateRecord>,
) -> BTreeMap<String, String> {
    let mut canonical = BTreeMap::new();
    for (identity, claimants) in static_fact_claimants {
        if claimants.len() <= 1 {
            continue;
        }
        let Some(located) = static_facts
            .iter()
            .find(|located| static_fact_identity_key(&located.value) == *identity)
        else {
            continue;
        };
        let bw_model::StaticFact::ObjectFlow(object_flow) = &located.value.payload else {
            continue;
        };
        if !callback_user_data_object_flow_is_exact_binding(object_flow) {
            continue;
        }
        let Some(fact_api) = static_fact_api_or_symbol(&located.value) else {
            continue;
        };
        let exact_api_claimants = claimants
            .iter()
            .filter(|candidate_id| {
                candidates_by_id
                    .get(candidate_id.as_str())
                    .and_then(|candidate| candidate.api_path.as_deref())
                    .map(normalize_api_path)
                    .as_ref()
                    == Some(&fact_api)
            })
            .cloned()
            .collect::<Vec<_>>();
        if exact_api_claimants.len() == 1 {
            canonical.insert(identity.clone(), exact_api_claimants[0].clone());
        }
    }
    canonical
}

fn callback_user_data_object_flow_is_exact_binding(fact: &bw_model::ObjectFlowFact) -> bool {
    matches!(
        fact.flow_kind,
        bw_model::ObjectFlowKind::FieldStore | bw_model::ObjectFlowKind::FieldLoad
    ) && matches!(
        (fact.from_object_kind, fact.to_object_kind),
        (
            bw_model::ObjectFlowObjectKind::UserData,
            bw_model::ObjectFlowObjectKind::OpaqueHandle
        ) | (
            bw_model::ObjectFlowObjectKind::OpaqueHandle,
            bw_model::ObjectFlowObjectKind::UserData
        )
    ) && fact
        .field_path
        .as_deref()
        .is_some_and(|field_path| field_path.starts_with("callback_user_data:"))
}

fn callback_user_data_static_lifecycle_boundary_id(
    envelope: &StaticFactEnvelope,
) -> Option<String> {
    let artifact = envelope.artifact.as_ref()?;
    let source_ref = envelope.source_ref.as_ref()?;
    let api_id = source_ref.symbol_path.as_ref()?;
    let identity = format!(
        "{}:{}:{}:{}",
        artifact.crate_id, source_ref.path, source_ref.line_start, api_id
    );
    let suffix = hex_digest(Sha256::digest(identity.as_bytes()));
    Some(format!(
        "boundary:{}:callback-registration:{}",
        sanitize_static_lifecycle_id(&artifact.crate_id),
        &suffix[..16]
    ))
}

fn sanitize_static_lifecycle_id(value: &str) -> String {
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

fn selection_has_returned_borrow_relation_anchor_for_key(
    selection: &StaticFactSelection,
    static_facts: &[bw_model::Located<StaticFactEnvelope>],
    target_key: &ReturnedBorrowApiKey,
) -> bool {
    selection.anchor_record_ids.iter().any(|record_id| {
        static_facts.iter().any(|located| {
            located.value.record_id.as_str() == record_id
                && matches!(
                    located.value.payload,
                    bw_model::StaticFact::ReturnedBorrowRelation(_)
                )
                && returned_borrow_chain_api_key(&located.value).as_ref() == Some(target_key)
        })
    })
}

fn returned_borrow_chain_api_key(envelope: &StaticFactEnvelope) -> Option<ReturnedBorrowApiKey> {
    let api_id = match &envelope.payload {
        bw_model::StaticFact::ReturnedBorrowRelation(fact) => &fact.api_id,
        bw_model::StaticFact::PersistedReturnedBorrow(fact) => &fact.api_id,
        bw_model::StaticFact::ReturnedBorrowInvalidationOrder(fact) => &fact.api_id,
        _ => return None,
    };
    returned_borrow_api_key(api_id)
}

fn static_fact_is_standard_returned_borrow_adapter(envelope: &StaticFactEnvelope) -> bool {
    let api_id = match &envelope.payload {
        bw_model::StaticFact::PersistedReturnedBorrow(fact) => &fact.api_id,
        bw_model::StaticFact::ReturnedBorrowInvalidationOrder(fact) => &fact.api_id,
        _ => return false,
    };
    let normalized = normalize_api_path(api_id);
    normalized.starts_with("std::")
        || normalized.starts_with("core::")
        || normalized.starts_with("alloc::")
}

fn static_fact_matches_manifest(
    envelope: &StaticFactEnvelope,
    manifest: &V32CorpusManifestRecord,
) -> bool {
    envelope.is_authoritative_lifecycle_binding()
        && envelope.artifact.as_ref().is_some_and(|artifact| {
            artifact.crate_id == manifest.crate_id
                && artifact.package_name == manifest.crate_name
                && artifact.package_version == manifest.version
        })
}

fn static_fact_matches_callback_user_data_symbol(
    envelope: &StaticFactEnvelope,
    scope: &CandidateScope,
) -> bool {
    if !matches!(
        envelope.payload,
        bw_model::StaticFact::CallbackUserDataReconstruction(_)
    ) {
        return false;
    }
    let Some(source_ref) = envelope.source_ref.as_ref() else {
        return false;
    };
    let Some(symbol_path) = source_ref.symbol_path.as_ref() else {
        return false;
    };
    let symbol_path = normalize_api_path(symbol_path);
    scope
        .api_paths
        .iter()
        .any(|api_path| api_path == &symbol_path)
}

fn static_fact_identity_key(envelope: &StaticFactEnvelope) -> String {
    let artifact_key = envelope
        .artifact
        .as_ref()
        .map(|artifact| {
            format!(
                "{}:{}:{}:{}",
                artifact.crate_id, artifact.package_name, artifact.package_version, artifact.target
            )
        })
        .unwrap_or_else(|| "artifact:none".to_owned());
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        envelope.producer, envelope.build_id, artifact_key, envelope.record_id
    )
}

fn static_fact_site_ids(envelope: &StaticFactEnvelope) -> Vec<(String, String)> {
    let build_id = envelope.build_id.to_string();
    let site_ids = match &envelope.payload {
        bw_model::StaticFact::ObjectSite(fact) => vec![fact.site_id.to_string()],
        bw_model::StaticFact::CallbackSite(fact) => vec![fact.site_id.to_string()],
        bw_model::StaticFact::CallbackCapture(fact) => vec![
            fact.site_id.to_string(),
            fact.callback_site_id.to_string(),
            fact.object_site_id.to_string(),
        ],
        bw_model::StaticFact::DropSite(fact) => {
            vec![fact.site_id.to_string(), fact.object_site_id.to_string()]
        }
        bw_model::StaticFact::DropPrevention(fact) => {
            vec![fact.site_id.to_string(), fact.object_site_id.to_string()]
        }
        bw_model::StaticFact::CallbackUserDataReconstruction(fact) => vec![
            fact.site_id.to_string(),
            fact.callback_site_id.to_string(),
            fact.user_data_site_id.to_string(),
            fact.object_site_id.to_string(),
        ],
        bw_model::StaticFact::RegistrationSite(fact) => fact
            .callback_site_id
            .iter()
            .map(ToString::to_string)
            .chain(fact.user_data_site_id.iter().map(ToString::to_string))
            .chain(std::iter::once(fact.site_id.to_string()))
            .collect(),
        bw_model::StaticFact::RawPointerTransfer(fact) => {
            vec![fact.site_id.to_string(), fact.user_data_site_id.to_string()]
        }
        bw_model::StaticFact::ReleasePathProof(fact) => vec![
            fact.site_id.to_string(),
            fact.registration_site_id.to_string(),
            fact.release_site_id.to_string(),
            fact.object_site_id.to_string(),
        ],
        bw_model::StaticFact::CallbackReleaseUseOrder(fact) => vec![
            fact.site_id.to_string(),
            fact.registration_site_id.to_string(),
            fact.release_site_id.to_string(),
            fact.use_site_id.to_string(),
            fact.object_site_id.to_string(),
        ],
        bw_model::StaticFact::ExternalCallSite(fact) => fact
            .callback_site_id
            .iter()
            .map(ToString::to_string)
            .chain(std::iter::once(fact.site_id.to_string()))
            .collect(),
        bw_model::StaticFact::ReturnedBorrowRelation(fact) => vec![
            fact.site_id.to_string(),
            fact.source_site_id.to_string(),
            fact.returned_site_id.to_string(),
        ],
        bw_model::StaticFact::PersistedReturnedBorrow(fact) => vec![
            fact.site_id.to_string(),
            fact.source_site_id.to_string(),
            fact.returned_site_id.to_string(),
            fact.storage_site_id.to_string(),
        ],
        bw_model::StaticFact::ReturnedBorrowInvalidationOrder(fact) => vec![
            fact.site_id.to_string(),
            fact.persisted_site_id.to_string(),
            fact.invalidation_site_id.to_string(),
            fact.use_site_id.to_string(),
        ],
        bw_model::StaticFact::ExternalBufferBinding(fact) => vec![
            fact.site_id.to_string(),
            fact.source_site_id.to_string(),
            fact.buffer_site_id.to_string(),
        ],
        bw_model::StaticFact::AtomicOrdering(fact) => vec![fact.site_id.to_string()],
        bw_model::StaticFact::CallbackLifetimeBound(fact) => vec![fact.site_id.to_string()],
        bw_model::StaticFact::RegistrationGuard(fact) => vec![fact.site_id.to_string()],
        bw_model::StaticFact::AllocationOwnership(fact) => vec![fact.site_id.to_string()],
        bw_model::StaticFact::SafeEntryLineage(fact) => vec![fact.site_id.to_string()],
        bw_model::StaticFact::ForeignSymbolBinding(fact) => vec![fact.site_id.to_string()],
        bw_model::StaticFact::ObjectBindingGap(fact) => vec![fact.site_id.to_string()],
        bw_model::StaticFact::ObjectFlow(fact) => vec![
            fact.site_id.to_string(),
            fact.from_site_id.to_string(),
            fact.to_site_id.to_string(),
        ],
    };
    site_ids
        .into_iter()
        .map(|site_id| (build_id.clone(), site_id))
        .collect()
}

fn static_fact_api_or_symbol(envelope: &StaticFactEnvelope) -> Option<String> {
    match &envelope.payload {
        bw_model::StaticFact::ObjectSite(fact) => Some(fact.type_name.clone()),
        bw_model::StaticFact::CallbackSite(fact) => Some(fact.def_path.clone()),
        bw_model::StaticFact::RegistrationSite(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::ExternalCallSite(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::ReturnedBorrowRelation(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::PersistedReturnedBorrow(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::ReturnedBorrowInvalidationOrder(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::ExternalBufferBinding(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::AtomicOrdering(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::ObjectBindingGap(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::ObjectFlow(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::CallbackReleaseUseOrder(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::CallbackLifetimeBound(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::RegistrationGuard(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::AllocationOwnership(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::SafeEntryLineage(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::ForeignSymbolBinding(fact) => Some(fact.api_id.clone()),
        bw_model::StaticFact::CallbackCapture(_)
        | bw_model::StaticFact::DropSite(_)
        | bw_model::StaticFact::DropPrevention(_)
        | bw_model::StaticFact::CallbackUserDataReconstruction(_)
        | bw_model::StaticFact::RawPointerTransfer(_)
        | bw_model::StaticFact::ReleasePathProof(_) => None,
    }
    .map(|value| normalize_api_path(&value))
}

fn static_fact_source_api_aliases(envelope: &StaticFactEnvelope) -> BTreeSet<String> {
    let Some(source_ref) = envelope.source_ref.as_ref() else {
        return BTreeSet::new();
    };
    let Some(source_scope) = source_api_scope_from_path(&source_ref.path) else {
        return BTreeSet::new();
    };
    source_ref
        .symbol_path
        .iter()
        .chain(static_fact_api_or_symbol(envelope).iter())
        .flat_map(|symbol_path| source_api_symbol_tails(symbol_path))
        .map(|symbol| source_api_alias(&source_scope, &symbol))
        .collect()
}

fn source_api_scope_from_path(path: &str) -> Option<String> {
    let normalized = normalize_source_path(path);
    let scoped_path = normalized.strip_prefix("./").unwrap_or(normalized.as_str());
    let scoped_path = scoped_path
        .find("/src/")
        .map(|index| &scoped_path[index + 1..])
        .unwrap_or(scoped_path);
    let source_scope = scoped_path
        .trim_end_matches(".rs")
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect::<Vec<_>>()
        .join("::");
    (!source_scope.is_empty()).then_some(source_scope)
}

fn source_api_symbol_tails(symbol_path: &str) -> BTreeSet<String> {
    let mut tails = BTreeSet::new();
    let segments = symbol_path
        .split("::")
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    for segment in segments.iter().rev() {
        if segment.starts_with("{closure") {
            continue;
        }
        if let Some(symbol) = source_api_symbol_from_segment(segment) {
            tails.insert(symbol);
            break;
        }
    }
    tails
}

fn source_api_symbol_from_segment(segment: &str) -> Option<String> {
    let raw_symbol = segment.split('<').next().unwrap_or(segment).trim();
    let symbol = raw_symbol
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
        .collect::<String>();
    if symbol.is_empty() || symbol.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        None
    } else {
        Some(symbol)
    }
}

fn source_api_alias(source_scope: &str, symbol: &str) -> String {
    let source_identity = format!("{source_scope}::{symbol}");
    format!(
        "source_api::{:x}",
        Sha256::digest(source_identity.as_bytes())
    )
}

#[derive(Clone, Debug)]
struct SiblingUnregistrationAnchor {
    sibling_candidate_id: String,
    source_api_path: String,
    source_ref: V326SourceRef,
    static_fact_record_id: String,
}

fn append_sibling_unregistration_evidence(
    evidence: &mut Vec<V326LifecycleEvidenceRecord>,
    run_id: &str,
    candidates: &[V32CandidateRecord],
    boundary_by_id: &BTreeMap<String, V32BoundaryIndexRecord>,
    candidate_scopes_by_crate: &BTreeMap<String, Vec<(String, CandidateScope)>>,
    static_facts: &[bw_model::Located<StaticFactEnvelope>],
    manifest_by_crate: &BTreeMap<String, V32CorpusManifestRecord>,
) {
    let mut unregisters_by_owner =
        BTreeMap::<(String, String), Vec<SiblingUnregistrationAnchor>>::new();

    for sibling in candidates {
        if candidate_boundary_kind(sibling, boundary_by_id)
            != Some(V32BoundaryKind::CallbackUnregistration)
        {
            continue;
        }
        let Some(source_api_path) = candidate_source_api_path(sibling, boundary_by_id) else {
            continue;
        };
        let Some(manifest) = manifest_by_crate.get(&sibling.crate_id) else {
            continue;
        };
        let Some(crate_scopes) = candidate_scopes_by_crate.get(&sibling.crate_id) else {
            continue;
        };
        let Some(scope) = crate_scopes
            .iter()
            .find(|(candidate_id, _)| candidate_id == &sibling.candidate_id)
            .map(|(_, scope)| scope)
        else {
            continue;
        };

        for located in static_facts {
            if !static_fact_matches_manifest(&located.value, manifest)
                || !static_fact_is_unregister_call(&located.value)
            {
                continue;
            }
            let source_ref = source_ref_from_static_fact(&located.value);
            if !scope.contains_source_ref(&source_ref)
                || !scope.owns_source_ref(&source_ref, &sibling.candidate_id, crate_scopes)
            {
                continue;
            }
            unregisters_by_owner
                .entry((sibling.crate_id.clone(), source_api_path.clone()))
                .or_default()
                .push(SiblingUnregistrationAnchor {
                    sibling_candidate_id: sibling.candidate_id.clone(),
                    source_api_path: source_api_path.clone(),
                    source_ref,
                    static_fact_record_id: located.value.record_id.to_string(),
                });
        }
    }

    let mut emitted = evidence
        .iter()
        .filter(|item| item.evidence_kind == V326EvidenceKind::ForeignUnregister)
        .filter_map(|item| {
            Some((
                item.candidate_id.clone(),
                item.details
                    .get("sibling_candidate_id")?
                    .as_str()?
                    .to_owned(),
                item.details
                    .get("static_fact_record_id")?
                    .as_str()?
                    .to_owned(),
            ))
        })
        .collect::<BTreeSet<_>>();

    for candidate in candidates {
        if candidate_boundary_kind(candidate, boundary_by_id)
            != Some(V32BoundaryKind::CallbackRegistration)
        {
            continue;
        }
        let Some(source_api_path) = candidate_source_api_path(candidate, boundary_by_id) else {
            continue;
        };
        let Some(siblings) =
            unregisters_by_owner.get(&(candidate.crate_id.clone(), source_api_path))
        else {
            continue;
        };

        for sibling in siblings {
            if sibling.sibling_candidate_id == candidate.candidate_id {
                continue;
            }
            let emitted_key = (
                candidate.candidate_id.clone(),
                sibling.sibling_candidate_id.clone(),
                sibling.static_fact_record_id.clone(),
            );
            if !emitted.insert(emitted_key) {
                continue;
            }
            let ordinal = evidence
                .iter()
                .filter(|item| item.candidate_id == candidate.candidate_id)
                .count()
                + 1;
            evidence.push(V326LifecycleEvidenceRecord {
                schema_version: bw_model::V3_2_6_LIFECYCLE_EVIDENCE_SCHEMA_V1.to_owned(),
                run_id: run_id.to_owned(),
                record_id: format!(
                    "evidence:{}:{}:sibling_unregister:{:04}",
                    sanitize_id(&candidate.crate_id),
                    sanitize_id(&candidate.candidate_id),
                    ordinal
                ),
                crate_id: candidate.crate_id.clone(),
                candidate_id: candidate.candidate_id.clone(),
                evidence_kind: V326EvidenceKind::ForeignUnregister,
                source_ref: V326SourceRef {
                    symbol_path: sibling
                        .source_ref
                        .symbol_path
                        .clone()
                        .or_else(|| Some(sibling.source_api_path.clone())),
                    ..sibling.source_ref.clone()
                },
                confidence: V326EvidenceConfidence::Medium,
                details: serde_json::json!({
                    "signal": "sibling_candidate_unregistration",
                    "relation": "same_source_api_owner",
                    "sibling_candidate_id": sibling.sibling_candidate_id,
                    "static_fact_record_id": sibling.static_fact_record_id
                }),
                notes: vec![
                    "neutral same-owner sibling unregistration evidence; not a release ordering proof or defect conclusion"
                        .to_owned(),
                ],
            });
        }
    }
}

fn candidate_boundary_kind(
    candidate: &V32CandidateRecord,
    boundary_by_id: &BTreeMap<String, V32BoundaryIndexRecord>,
) -> Option<V32BoundaryKind> {
    boundary_by_id
        .get(&candidate.boundary_id)
        .map(|boundary| boundary.boundary_kind)
}

fn candidate_source_api_path(
    candidate: &V32CandidateRecord,
    boundary_by_id: &BTreeMap<String, V32BoundaryIndexRecord>,
) -> Option<String> {
    let mut api_paths = Vec::new();
    if let Some(api_path) = candidate.api_path.as_ref() {
        api_paths.push(api_path.as_str());
    }
    if let Some(api_path) = boundary_by_id
        .get(&candidate.boundary_id)
        .and_then(|boundary| boundary.api_path.as_ref())
    {
        api_paths.push(api_path.as_str());
    }
    api_paths
        .into_iter()
        .map(normalize_api_path)
        .find(|api_path| is_source_api_alias(api_path))
}

fn static_fact_is_unregister_call(envelope: &StaticFactEnvelope) -> bool {
    matches!(
        &envelope.payload,
        bw_model::StaticFact::RegistrationSite(fact)
            if fact.role == bw_model::RegistrationRole::Unregister
    )
}

fn append_signature_lifetime_bound_evidence(
    evidence: &mut Vec<V326LifecycleEvidenceRecord>,
    run_id: &str,
    candidates: &[V32CandidateRecord],
    selections: &BTreeMap<String, StaticFactSelection>,
    static_facts: &[bw_model::Located<StaticFactEnvelope>],
    static_fact_claimants: &BTreeMap<String, BTreeSet<String>>,
    manifest_by_crate: &BTreeMap<String, V32CorpusManifestRecord>,
    manifest_dir: &Path,
    source_cache: &mut BTreeMap<String, SourceCatalog>,
) -> Result<(), CliError> {
    let mut emitted = evidence
        .iter()
        .filter(|item| item.evidence_kind == V326EvidenceKind::LifetimeBound)
        .filter_map(|item| {
            Some((
                item.candidate_id.clone(),
                item.source_ref.path.clone(),
                item.source_ref.line_start?,
            ))
        })
        .collect::<BTreeSet<_>>();

    for candidate in candidates {
        let Some(selection) = selections.get(&candidate.candidate_id) else {
            continue;
        };
        let has_signature_anchor = selection.fact_indexes.iter().any(|index| {
            let located = &static_facts[*index];
            static_fact_can_anchor_signature_lifetime_bound(&located.value)
                && static_fact_claimants
                    .get(&static_fact_identity_key(&located.value))
                    .is_some_and(|claimants| claimants.len() == 1)
        });
        if !has_signature_anchor {
            continue;
        }
        let Some(manifest) = manifest_by_crate.get(&candidate.crate_id) else {
            return Err(CliError::input(
                "BW-V326-MANIFEST-MISSING",
                format!(
                    "candidate crate_id {} 在 corpus manifest 中不存在",
                    candidate.crate_id
                ),
            ));
        };
        if !source_cache.contains_key(&candidate.crate_id) {
            let source_root = resolve_local_source(manifest_dir, manifest)?;
            source_cache.insert(
                candidate.crate_id.clone(),
                collect_source_lines(&source_root)?,
            );
        }
        let source_catalog = source_cache
            .get(&candidate.crate_id)
            .expect("source cache is populated for candidate crate");

        for index in &selection.fact_indexes {
            let located = &static_facts[*index];
            if !static_fact_can_anchor_signature_lifetime_bound(&located.value)
                || static_fact_claimants
                    .get(&static_fact_identity_key(&located.value))
                    .is_none_or(|claimants| claimants.len() != 1)
            {
                continue;
            }
            let anchor_source_ref = source_ref_from_static_fact(&located.value);
            let mut signature_bounds = Vec::<(&SourceLine, &'static str)>::new();
            if let Some(line) = signature_lifetime_bound_line(source_catalog, &anchor_source_ref) {
                signature_bounds.push((
                    line,
                    "static lifetime bound in selected registration signature",
                ));
            }
            if matches!(
                located.value.payload,
                bw_model::StaticFact::ExternalBufferBinding(_)
            ) && let Some(line) = signature_external_buffer_return_lifetime_bound_line(
                source_catalog,
                &anchor_source_ref,
            ) {
                signature_bounds.push((
                    line,
                    bw_model::V3_2_6_EXTERNAL_BUFFER_RETURN_LIFETIME_SIGNAL,
                ));
            }
            for (line, signal) in signature_bounds {
                let key = (
                    candidate.candidate_id.clone(),
                    line.path.clone(),
                    line.line_number,
                );
                if !emitted.insert(key) {
                    continue;
                }
                let ordinal = evidence
                    .iter()
                    .filter(|item| item.candidate_id == candidate.candidate_id)
                    .count()
                    + 1;
                evidence.push(V326LifecycleEvidenceRecord {
                    schema_version: bw_model::V3_2_6_LIFECYCLE_EVIDENCE_SCHEMA_V1.to_owned(),
                    run_id: run_id.to_owned(),
                    record_id: format!(
                        "evidence:{}:{}:signature_bound:{:04}",
                        sanitize_id(&candidate.crate_id),
                        sanitize_id(&candidate.candidate_id),
                        ordinal
                    ),
                    crate_id: candidate.crate_id.clone(),
                    candidate_id: candidate.candidate_id.clone(),
                    evidence_kind: V326EvidenceKind::LifetimeBound,
                    source_ref: V326SourceRef {
                        path: line.path.clone(),
                        line_start: Some(line.line_number),
                        line_end: Some(line.line_number),
                        symbol_path: anchor_source_ref
                            .symbol_path
                            .clone()
                            .or_else(|| candidate.api_path.clone()),
                        text_sha256: Some(hex_digest(Sha256::digest(line.text.as_bytes()))),
                    },
                    confidence: V326EvidenceConfidence::High,
                    details: serde_json::json!({
                        "signal": signal,
                        "static_fact_record_id": located.value.record_id.to_string()
                    }),
                    notes: vec![
                        "neutral lifecycle evidence from selected static fact signature; not a defect conclusion"
                            .to_owned(),
                    ],
                });
            }
        }
    }

    Ok(())
}

fn static_fact_can_anchor_signature_lifetime_bound(envelope: &StaticFactEnvelope) -> bool {
    matches!(
        &envelope.payload,
        bw_model::StaticFact::RegistrationSite(fact)
            if matches!(
                fact.role,
                bw_model::RegistrationRole::Register | bw_model::RegistrationRole::Replace
            )
    ) || matches!(
        &envelope.payload,
        bw_model::StaticFact::PersistedReturnedBorrow(_)
            | bw_model::StaticFact::ReturnedBorrowInvalidationOrder(_)
            | bw_model::StaticFact::ExternalBufferBinding(_)
    )
}

fn signature_lifetime_bound_line<'a>(
    catalog: &'a SourceCatalog,
    source_ref: &V326SourceRef,
) -> Option<&'a SourceLine> {
    signature_lines(catalog, source_ref)?
        .into_iter()
        .find(|line| line.scan_text.to_ascii_lowercase().contains("'static"))
}

fn signature_external_buffer_return_lifetime_bound_line<'a>(
    catalog: &'a SourceCatalog,
    source_ref: &V326SourceRef,
) -> Option<&'a SourceLine> {
    let signature_lines = signature_lines(catalog, source_ref)?;
    let signature = signature_lines
        .iter()
        .map(|line| line.scan_text.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let return_lifetime = return_reference_lifetime(&signature)?;
    let params = buffer_reference_params(&signature);
    if params.is_empty()
        || params
            .iter()
            .any(|param| reference_lifetime(param).as_deref() != Some(return_lifetime.as_str()))
    {
        return None;
    }
    signature_lines
        .iter()
        .copied()
        .find(|line| line.scan_text.contains("->"))
        .or_else(|| signature_lines.last().copied())
}

fn signature_lines<'a>(
    catalog: &'a SourceCatalog,
    source_ref: &V326SourceRef,
) -> Option<Vec<&'a SourceLine>> {
    const SIGNATURE_BACKSCAN_LIMIT: usize = 80;
    let line_number = source_ref.line_start?;
    let path = normalize_source_path(&source_ref.path);
    let path_indexes = catalog.path_line_indexes.get(&path)?;
    let position = path_indexes
        .iter()
        .position(|index| catalog.lines[*index].line_number == line_number)?;
    let lower_bound = position.saturating_sub(SIGNATURE_BACKSCAN_LIMIT);
    let fn_position = (lower_bound..=position).rev().find(|candidate_position| {
        let line = &catalog.lines[path_indexes[*candidate_position]];
        is_rust_function_signature_start(&line.scan_text)
    })?;
    let signature_end = (fn_position..=position)
        .find(|candidate_position| {
            catalog.lines[path_indexes[*candidate_position]]
                .scan_text
                .contains('{')
        })
        .unwrap_or(position);
    Some(
        (fn_position..=signature_end)
            .map(|candidate_position| &catalog.lines[path_indexes[candidate_position]])
            .collect(),
    )
}

fn return_reference_lifetime(signature: &str) -> Option<String> {
    let (_, return_ty) = signature.split_once("->")?;
    reference_lifetime(return_ty)
}

fn buffer_reference_params(signature: &str) -> Vec<&str> {
    let params_start = signature.find('(').map(|index| index + 1).unwrap_or(0);
    let params_end = signature[params_start..]
        .find(')')
        .map(|index| params_start + index)
        .unwrap_or(params_start);
    signature[params_start..params_end]
        .split(',')
        .map(str::trim)
        .filter(|param| param_contains_buffer_reference(param))
        .collect()
}

fn param_contains_buffer_reference(param: &str) -> bool {
    let lower = param.to_ascii_lowercase();
    lower.contains('&')
        && (lower.contains("[u8]")
            || lower.contains("[std::ffi::c_uchar]")
            || lower.contains("[c_uchar]")
            || lower.contains("[libc::c_uchar]")
            || lower.contains("str"))
}

fn reference_lifetime(text: &str) -> Option<String> {
    let after_ref = text.split_once('&')?.1.trim_start();
    let lifetime = after_ref.strip_prefix('\'')?;
    let token = lifetime
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>();
    (!token.is_empty()).then_some(format!("'{token}"))
}

fn is_rust_function_signature_start(scan_text: &str) -> bool {
    let lower = scan_text.trim_start().to_ascii_lowercase();
    lower.starts_with("fn ")
        || lower.starts_with("pub fn ")
        || lower.starts_with("pub(crate) fn ")
        || lower.starts_with("pub(super) fn ")
        || lower.starts_with("pub(in ")
        || lower.starts_with("unsafe fn ")
        || lower.starts_with("pub unsafe fn ")
        || lower.starts_with("pub(crate) unsafe fn ")
        || lower.starts_with("pub(super) unsafe fn ")
        || lower.starts_with("async fn ")
        || lower.starts_with("pub async fn ")
        || lower.starts_with("pub(crate) async fn ")
        || lower.starts_with("pub(super) async fn ")
}

fn evidence_refs_near_source(
    evidence: &[V326LifecycleEvidenceRecord],
    candidate_id: &str,
    source_ref: &V326SourceRef,
) -> Vec<String> {
    let refs = evidence
        .iter()
        .filter(|item| item.candidate_id == candidate_id)
        .filter(|item| {
            item.source_ref.path == source_ref.path
                && item.source_ref.line_start == source_ref.line_start
        })
        .map(|item| item.record_id.clone())
        .collect::<Vec<_>>();
    if refs.is_empty() {
        vec![format!(
            "static-fact:{}:{}",
            sanitize_id(candidate_id),
            source_ref.line_start.unwrap_or(0)
        )]
    } else {
        refs
    }
}

fn coverage_for_candidate(
    run_id: &str,
    candidate: &V32CandidateRecord,
    facts: &[V326LifecycleFactRecord],
    static_facts_missing: bool,
    mir_coverage: Option<&MirCoverageReport>,
) -> V326LifecycleCoverageRecord {
    let mut covered_function_bodies = facts
        .iter()
        .filter_map(|fact| match fact.fact_kind {
            V326LifecycleFactKind::CallbackDefinition
            | V326LifecycleFactKind::RegisterCall
            | V326LifecycleFactKind::UnregisterCall
            | V326LifecycleFactKind::ReplaceCall
            | V326LifecycleFactKind::ReleaseCall
            | V326LifecycleFactKind::ReturnedBorrowRelation
            | V326LifecycleFactKind::ExternalBufferBinding => fact.symbol_path.clone(),
            _ => None,
        })
        .collect::<Vec<_>>();
    covered_function_bodies.sort();
    covered_function_bodies.dedup();

    let mut covered_drop_impls = facts
        .iter()
        .filter(|fact| {
            matches!(
                fact.fact_kind,
                V326LifecycleFactKind::DropImpl | V326LifecycleFactKind::DropSite
            )
        })
        .filter_map(|fact| {
            fact.symbol_path
                .clone()
                .or_else(|| Some(fact.fact_id.clone()))
        })
        .collect::<Vec<_>>();
    covered_drop_impls.sort();
    covered_drop_impls.dedup();

    let mut covered_trait_impls = facts
        .iter()
        .filter(|fact| fact.fact_kind == V326LifecycleFactKind::TraitImpl)
        .filter_map(|fact| fact.symbol_path.clone())
        .collect::<Vec<_>>();
    covered_trait_impls.sort();
    covered_trait_impls.dedup();

    let mut unavailable_paths = Vec::new();
    if let Some(report) = mir_coverage {
        let (mir_functions, mir_gaps) = mir_coverage_for_candidate(candidate, report);
        covered_function_bodies.extend(mir_functions);
        covered_function_bodies.sort();
        covered_function_bodies.dedup();
        unavailable_paths.extend(mir_gaps);
    }
    if static_facts_missing {
        unavailable_paths.push(V326CoverageGap {
            path: candidate.candidate_id.clone(),
            reason: V326CoverageGapReason::StaticFactsMissing,
            notes: vec!["static facts were not provided for this candidate".to_owned()],
        });
    }
    if mir_coverage.is_none() {
        unavailable_paths.push(V326CoverageGap {
            path: candidate.candidate_id.clone(),
            reason: V326CoverageGapReason::SourceOnlyFallback,
            notes: vec!["MIR coverage input was not provided for this candidate".to_owned()],
        });
    }
    if facts.iter().all(|fact| {
        !matches!(
            fact.fact_kind,
            V326LifecycleFactKind::DropImpl | V326LifecycleFactKind::DropSite
        )
    }) {
        unavailable_paths.push(V326CoverageGap {
            path: format!("{}::drop", candidate.candidate_id),
            reason: V326CoverageGapReason::DropImplUnavailable,
            notes: vec!["Drop impl was not covered by the static fact bridge".to_owned()],
        });
    }

    V326LifecycleCoverageRecord {
        schema_version: bw_model::V3_2_6_LIFECYCLE_COVERAGE_SCHEMA_V1.to_owned(),
        run_id: run_id.to_owned(),
        candidate_id: candidate.candidate_id.clone(),
        crate_id: candidate.crate_id.clone(),
        covered_function_bodies,
        covered_trait_impls,
        covered_drop_impls,
        unavailable_paths,
        fact_refs: facts.iter().map(|fact| fact.fact_id.clone()).collect(),
        notes: vec!["coverage manifest is candidate-scoped".to_owned()],
    }
}

fn read_mir_coverage(path: &Path) -> Result<MirCoverageReport, CliError> {
    let text = fs::read_to_string(path).map_err(|error| {
        CliError::input(
            "BW-V326-MIR-COVERAGE",
            format!("{}: {}", path.display(), error),
        )
    })?;
    let report: MirCoverageReport = serde_json::from_str(&text).map_err(|error| {
        CliError::input(
            "BW-V326-MIR-COVERAGE",
            format!("{}: {}", path.display(), error),
        )
    })?;
    if report.schema_version != "bw.mir-coverage/0.1" {
        return Err(CliError::input(
            "BW-V326-MIR-COVERAGE-SCHEMA",
            format!(
                "{}: expected bw.mir-coverage/0.1, found {}",
                path.display(),
                report.schema_version
            ),
        ));
    }
    validate_mir_coverage_shape(path, &report)?;
    Ok(report)
}

fn validate_mir_coverage_shape(path: &Path, report: &MirCoverageReport) -> Result<(), CliError> {
    for package in report
        .expected_packages
        .iter()
        .chain(report.seen_packages.iter())
    {
        if package.name.trim().is_empty() || package.version.trim().is_empty() {
            return Err(CliError::input(
                "BW-V326-MIR-COVERAGE-EMPTY",
                format!("{}: package name/version 不能为空", path.display()),
            ));
        }
    }
    for target in &report.seen_targets {
        if target.package.trim().is_empty()
            || target.version.trim().is_empty()
            || target.target.trim().is_empty()
        {
            return Err(CliError::input(
                "BW-V326-MIR-COVERAGE-EMPTY",
                format!("{}: seen target 字段不能为空", path.display()),
            ));
        }
    }
    for body in &report.seen_bodies {
        if body.package.trim().is_empty()
            || body.version.trim().is_empty()
            || body.target.trim().is_empty()
            || body.def_path.trim().is_empty()
        {
            return Err(CliError::input(
                "BW-V326-MIR-COVERAGE-EMPTY",
                format!("{}: seen body 字段不能为空", path.display()),
            ));
        }
    }
    for body in &report.skipped {
        if body.package.trim().is_empty()
            || body.version.trim().is_empty()
            || body.target.trim().is_empty()
            || body.def_path.trim().is_empty()
            || body.reason.trim().is_empty()
        {
            return Err(CliError::input(
                "BW-V326-MIR-COVERAGE-EMPTY",
                format!("{}: skipped body 字段不能为空", path.display()),
            ));
        }
    }
    Ok(())
}

fn mir_coverage_for_candidate(
    candidate: &V32CandidateRecord,
    report: &MirCoverageReport,
) -> (Vec<String>, Vec<V326CoverageGap>) {
    let mut covered = report
        .seen_bodies
        .iter()
        .filter(|body| mir_def_path_matches_candidate(candidate, &body.def_path))
        .map(|body| body.def_path.clone())
        .collect::<Vec<_>>();
    covered.sort();
    covered.dedup();

    let mut gaps = report
        .skipped
        .iter()
        .filter(|body| mir_def_path_matches_candidate(candidate, &body.def_path))
        .map(|body| V326CoverageGap {
            path: body.def_path.clone(),
            reason: coverage_gap_reason_from_mir(&body.reason),
            notes: vec![format!("MIR coverage skipped body reason: {}", body.reason)],
        })
        .collect::<Vec<_>>();
    gaps.sort_by(|left, right| left.path.cmp(&right.path));
    gaps.dedup_by(|left, right| left.path == right.path && left.reason == right.reason);
    (covered, gaps)
}

fn mir_def_path_matches_candidate(candidate: &V32CandidateRecord, def_path: &str) -> bool {
    let Some(api_path) = candidate.api_path.as_deref() else {
        return false;
    };
    let api_path = normalize_api_path(api_path);
    let def_path = normalize_api_path(def_path);
    !api_path.is_empty() && api_path == def_path
}

fn coverage_gap_reason_from_mir(reason: &str) -> V326CoverageGapReason {
    match reason
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .as_str()
    {
        "macro_expansion" | "macro" => V326CoverageGapReason::MacroExpansion,
        "missing_dependency" | "dependency" => V326CoverageGapReason::MissingDependency,
        "compile_cfg" | "cfg" => V326CoverageGapReason::CompileCfg,
        "insufficient_span" | "span" => V326CoverageGapReason::InsufficientSpan,
        "drop_impl_unavailable" | "drop_unavailable" => V326CoverageGapReason::DropImplUnavailable,
        "static_facts_missing" => V326CoverageGapReason::StaticFactsMissing,
        _ => V326CoverageGapReason::SourceOnlyFallback,
    }
}

fn resolve_local_source(
    manifest_dir: &Path,
    record: &V32CorpusManifestRecord,
) -> Result<PathBuf, CliError> {
    match record.source_kind {
        V32CorpusSourceKind::LocalArchive | V32CorpusSourceKind::RegistrySnapshot => {
            let path = PathBuf::from(&record.source_ref);
            if path.is_absolute() {
                Ok(path)
            } else {
                Ok(manifest_dir.join(path))
            }
        }
        other => Err(CliError::input(
            "BW-V326-SOURCE-KIND",
            format!(
                "V3.2.6 evidence extractor 仅支持 local_archive/registry_snapshot，收到 {other:?}"
            ),
        )),
    }
}

fn collect_source_lines(source_root: &Path) -> Result<SourceCatalog, CliError> {
    let src_dir = if source_root.join("src").is_dir() {
        source_root.join("src")
    } else {
        source_root.to_path_buf()
    };
    if !src_dir.exists() {
        return Err(CliError::input(
            "BW-V326-SOURCE-MISSING",
            format!("源码目录不存在: {}", src_dir.display()),
        ));
    }

    let mut files = Vec::<PathBuf>::new();
    collect_rs_files(&src_dir, &mut files)?;
    files.sort();

    let mut lines = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file)
            .map_err(|error| CliError::input("BW-IO", format!("{}: {}", file.display(), error)))?;
        let relative = file
            .strip_prefix(source_root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let mut block_comment_depth = 0;
        for (index, line) in text.lines().enumerate() {
            lines.push(SourceLine {
                path: relative.clone(),
                line_number: (index as u64) + 1,
                text: line.to_owned(),
                scan_text: strip_rust_comments(line, &mut block_comment_depth),
            });
        }
    }
    Ok(SourceCatalog::new(lines))
}

fn boundary_has_exact_source_anchor(
    boundary: Option<&V32BoundaryIndexRecord>,
    kind: V32BoundaryKind,
    line: &SourceLine,
) -> bool {
    boundary.is_some_and(|boundary| {
        boundary.boundary_kind == kind
            && boundary.evidence_refs.iter().any(|reference| {
                reference.kind == V32BoundaryEvidenceKind::SourceSpan
                    && normalize_source_path(&reference.path) == normalize_source_path(&line.path)
                    && reference.line_start == Some(line.line_number)
                    && reference.line_end == Some(line.line_number)
            })
    })
}

fn boundary_evidence_confidence(
    boundary: Option<&V32BoundaryIndexRecord>,
) -> V326EvidenceConfidence {
    match boundary.map(|item| item.confidence.as_str()) {
        Some("high") => V326EvidenceConfidence::High,
        Some("low") => V326EvidenceConfidence::Low,
        _ => V326EvidenceConfidence::Medium,
    }
}

fn collect_rs_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), CliError> {
    let entries = fs::read_dir(dir)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {}", dir.display(), error)))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| CliError::input("BW-IO", format!("{}: {}", dir.display(), error)))?;
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, files)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn write_checksums(output_dir: &Path, checksums_path: &Path) -> Result<(), CliError> {
    let mut lines = vec![
        format!(
            "{}  {}",
            sha256_file(&output_dir.join("lifecycle-evidence.jsonl.zst"))?,
            "lifecycle-evidence.jsonl.zst"
        ),
        format!(
            "{}  {}",
            sha256_file(&output_dir.join("lifecycle-facts.jsonl.zst"))?,
            "lifecycle-facts.jsonl.zst"
        ),
        format!(
            "{}  {}",
            sha256_file(&output_dir.join("lifecycle-coverage.jsonl.zst"))?,
            "lifecycle-coverage.jsonl.zst"
        ),
        format!(
            "{}  {}",
            sha256_file(&output_dir.join("evidence-stats.json"))?,
            "evidence-stats.json"
        ),
    ];
    lines.sort();
    let mut file = File::create(checksums_path)?;
    for line in lines {
        writeln!(file, "{line}")?;
    }
    Ok(())
}

fn kind_counts(evidence: &[V326LifecycleEvidenceRecord]) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for item in evidence {
        let key = format!("{:?}", item.evidence_kind);
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn sha256_file(path: &Path) -> Result<String, CliError> {
    let bytes = fs::read(path)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {}", path.display(), error)))?;
    Ok(hex_digest(Sha256::digest(bytes)))
}

#[cfg(test)]
mod registration_claimant_tests {
    use super::*;

    fn candidate_with_span(candidate_id: &str, line: u64) -> V32CandidateRecord {
        V32CandidateRecord {
            schema_version: bw_model::V3_2_CANDIDATE_SCHEMA_V1.to_owned(),
            run_id: "run:v326".to_owned(),
            candidate_id: candidate_id.to_owned(),
            crate_id: "crate:rusqlite:0.26.1".to_owned(),
            boundary_id: format!("boundary:{candidate_id}"),
            pattern_family: bw_model::V32PatternFamily::RetainedBorrowedCallback,
            confidence: bw_model::V32CandidateConfidence::NeedsDynamicValidation,
            evidence_refs: vec![bw_model::V32BoundaryEvidenceRef {
                kind: V32BoundaryEvidenceKind::SourceSpan,
                path: "src/hooks.rs".to_owned(),
                line_start: Some(line),
                line_end: Some(line),
            }],
            api_path: Some("source_api::c993ec".to_owned()),
            recommended_next_step: bw_model::V32RecommendedNextStep::GenerateLifecycleSubgraph,
            notes: Vec::new(),
        }
    }

    /// 一条跨多行的注册事实，形如 rusqlite 0.26.1 `InnerConnection::update_hook` 里那次
    /// `ffi::sqlite3_update_hook(..)` 调用（源码 546-550）。
    fn multiline_registration_fact() -> StaticFactEnvelope {
        StaticFactEnvelope {
            schema_version: bw_model::STATIC_SCHEMA_V02.to_owned(),
            record_id: bw_model::RecordId("fact:registration:update-hook".to_owned()),
            producer: "fixture".to_owned(),
            build_id: bw_model::BuildId("build:rusqlite".to_owned()),
            artifact: Some(bw_model::StaticArtifactIdentity {
                crate_id: "crate:rusqlite:0.26.1".to_owned(),
                package_name: "rusqlite".to_owned(),
                package_version: "0.26.1".to_owned(),
                target: "lib".to_owned(),
            }),
            source_ref: Some(bw_model::StaticSourceRef {
                path: "src/hooks.rs".to_owned(),
                line_start: 546,
                line_end: 550,
                symbol_path: Some(
                    "hooks::<impl inner_connection::InnerConnection>::update_hook".to_owned(),
                ),
            }),
            payload: bw_model::StaticFact::RegistrationSite(bw_model::RegistrationSiteFact {
                site_id: bw_model::SiteId("site:registration:update-hook".to_owned()),
                semantic_site_key: bw_model::SemanticSiteKey("semantic:update-hook".to_owned()),
                callback_site_id: Some(bw_model::SiteId("site:callback:update-hook".to_owned())),
                user_data_site_id: Some(bw_model::SiteId("site:user-data:update-hook".to_owned())),
                api_id: "api:rusqlite:update_hook:register".to_owned(),
                role: bw_model::RegistrationRole::Register,
            }),
        }
    }

    /// 注册事实归"边界正落在这个调用点上"的候选，不归靠两跳蹭到的邻居。
    ///
    /// 没有这条仲裁，多 claimant 的注册事实会被唯一性门整条丢掉，witness plan 于是拿不到
    /// api_id，全部退化成"没有 target"——一个看起来正常、实际什么都绑不上的结果。
    #[test]
    fn a_multi_claimant_registration_fact_goes_to_the_candidate_whose_span_covers_the_call() {
        let located = bw_model::Located {
            path: PathBuf::from("static-facts.jsonl"),
            line: 1,
            value: multiline_registration_fact(),
        };
        let identity = static_fact_identity_key(&located.value);
        // 546 与事实的 546-550 直接重叠；515 和 567 只是邻居。
        let owner = candidate_with_span("candidate:owner", 546);
        let before = candidate_with_span("candidate:before", 515);
        let after = candidate_with_span("candidate:after", 567);
        let candidates_by_id = BTreeMap::from([
            (owner.candidate_id.clone(), &owner),
            (before.candidate_id.clone(), &before),
            (after.candidate_id.clone(), &after),
        ]);
        let claimants = BTreeMap::from([(
            identity.clone(),
            BTreeSet::from([
                owner.candidate_id.clone(),
                before.candidate_id.clone(),
                after.candidate_id.clone(),
            ]),
        )]);

        let canonical = canonical_registration_static_fact_claimants(
            &claimants,
            std::slice::from_ref(&located),
            &candidates_by_id,
        );

        assert_eq!(
            canonical.get(&identity).map(String::as_str),
            Some("candidate:owner"),
            "the candidate whose boundary is the registration call owns the fact"
        );
    }

    /// 两个候选都直接覆盖同一个调用点时不猜，保持丢弃。
    #[test]
    fn two_overlapping_candidates_leave_the_registration_fact_unclaimed() {
        let located = bw_model::Located {
            path: PathBuf::from("static-facts.jsonl"),
            line: 1,
            value: multiline_registration_fact(),
        };
        let identity = static_fact_identity_key(&located.value);
        let first = candidate_with_span("candidate:first", 546);
        let second = candidate_with_span("candidate:second", 548);
        let candidates_by_id = BTreeMap::from([
            (first.candidate_id.clone(), &first),
            (second.candidate_id.clone(), &second),
        ]);
        let claimants = BTreeMap::from([(
            identity.clone(),
            BTreeSet::from([first.candidate_id.clone(), second.candidate_id.clone()]),
        )]);

        let canonical = canonical_registration_static_fact_claimants(
            &claimants,
            std::slice::from_ref(&located),
            &candidates_by_id,
        );

        assert!(
            canonical.get(&identity).is_none(),
            "an ambiguous owner must stay unclaimed rather than be guessed"
        );
    }
}
