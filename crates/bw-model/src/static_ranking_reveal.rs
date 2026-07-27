use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    Located, ModelError, V32BoundaryIndexRecord, V32BuildabilityRecord, V32BuildabilityStatus,
    V32PatternFamily, V32RankedCandidateRecord,
};

pub const V3_2_5_PRIVATE_GROUND_TRUTH_SCHEMA_V1: &str = "v3.2.5.private_ground_truth.1";
pub const V3_2_5_STATIC_RANKING_REVEAL_SCHEMA_V1: &str = "v3.2.5.static_ranking_reveal.1";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct V325PrivateGroundTruthRecord {
    #[serde(deserialize_with = "crate::schema::deserialize_v3_2_5_private_ground_truth_schema")]
    pub schema_version: String,
    pub suite_id: String,
    pub sample_id: String,
    pub public_crate_id: String,
    pub role: V325SampleRole,
    #[serde(default)]
    pub paired_with: Vec<String>,
    #[serde(default)]
    pub expected_pattern_families: Vec<V325ExpectedPatternFamily>,
    #[serde(default)]
    pub expected_api_substrings: Vec<String>,
    #[serde(default)]
    pub expected_path_substrings: Vec<String>,
    pub root_cause_key: String,
    #[serde(default)]
    pub vulnerability_identity: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V325SampleRole {
    Vulnerable,
    FixedControl,
    SafeControl,
    Distractor,
    Negative,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V325ExpectedPatternFamily {
    RetainedBorrowedCallback,
    CallbackLifecycleRelease,
    ForeignRetainedPointer,
    OpaqueHandleTransfer,
    NativeLibraryBoundary,
    ReturnedBorrowView,
    ExternalBufferView,
    IteratorStaleReference,
    ContainerEntryLifecycle,
    WrapperDestructurePointerLifecycle,
    ManualDropWindow,
    ArenaIteratorLifetime,
    AllocatorBackedCollection,
    ConcurrentIteratorVisibility,
    AtomicLoadLifecycle,
    MutableSliceViewConversion,
    CheckedViewInvariant,
}

impl V325ExpectedPatternFamily {
    pub fn from_public_pattern(pattern: V32PatternFamily) -> Self {
        match pattern {
            V32PatternFamily::RetainedBorrowedCallback => Self::RetainedBorrowedCallback,
            V32PatternFamily::CallbackLifecycleRelease => Self::CallbackLifecycleRelease,
            V32PatternFamily::ForeignRetainedPointer => Self::ForeignRetainedPointer,
            V32PatternFamily::OpaqueHandleTransfer => Self::OpaqueHandleTransfer,
            V32PatternFamily::NativeLibraryBoundary => Self::NativeLibraryBoundary,
            V32PatternFamily::ReturnedBorrowView => Self::ReturnedBorrowView,
            V32PatternFamily::ExternalBufferView => Self::ExternalBufferView,
        }
    }

    fn compatible_public_patterns(self) -> &'static [V32PatternFamily] {
        match self {
            Self::RetainedBorrowedCallback => &[V32PatternFamily::RetainedBorrowedCallback],
            Self::CallbackLifecycleRelease => &[V32PatternFamily::CallbackLifecycleRelease],
            Self::ForeignRetainedPointer => &[V32PatternFamily::ForeignRetainedPointer],
            Self::OpaqueHandleTransfer => &[V32PatternFamily::OpaqueHandleTransfer],
            Self::NativeLibraryBoundary => &[V32PatternFamily::NativeLibraryBoundary],
            Self::ReturnedBorrowView
            | Self::IteratorStaleReference
            | Self::ContainerEntryLifecycle
            | Self::ArenaIteratorLifetime
            | Self::AllocatorBackedCollection
            | Self::ConcurrentIteratorVisibility
            | Self::AtomicLoadLifecycle => &[V32PatternFamily::ReturnedBorrowView],
            Self::ExternalBufferView
            | Self::MutableSliceViewConversion
            | Self::CheckedViewInvariant => &[
                V32PatternFamily::ReturnedBorrowView,
                V32PatternFamily::ExternalBufferView,
            ],
            Self::WrapperDestructurePointerLifecycle | Self::ManualDropWindow => {
                &[V32PatternFamily::ForeignRetainedPointer]
            }
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V325PrivateGroundTruthSummary {
    pub record_count: u64,
    pub vulnerable_count: u64,
    pub control_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct V325StaticRankingRevealSummary {
    pub schema_version: String,
    pub run_id: String,
    pub suite_id: String,
    pub ranked_candidates_sha256: String,
    pub ground_truth_sha256: String,
    pub top_k_values: Vec<u32>,
    pub metrics: V325RevealMetrics,
    pub miss_class_counts: BTreeMap<String, u64>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct V325RevealMetrics {
    pub vulnerable_sample_count: u64,
    pub control_sample_count: u64,
    pub buildable_vulnerable_count: u64,
    pub nday_candidate_hit_count: u64,
    pub top1_hit_count: u64,
    pub top5_hit_count: u64,
    pub top10_hit_count: u64,
    pub ranking_miss_count: u64,
    pub boundary_miss_count: u64,
    pub build_failure_count: u64,
    pub false_positive_control_count: u64,
    pub paired_control_clean_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V325MissClass {
    HitTopK,
    BuildFailure,
    BoundaryMiss,
    CandidateMiss,
    RankingMiss,
    AdapterBlocked,
    GroundTruthMismatch,
}

impl V325MissClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HitTopK => "hit_top_k",
            Self::BuildFailure => "build_failure",
            Self::BoundaryMiss => "boundary_miss",
            Self::CandidateMiss => "candidate_miss",
            Self::RankingMiss => "ranking_miss",
            Self::AdapterBlocked => "adapter_blocked",
            Self::GroundTruthMismatch => "ground_truth_mismatch",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct V325PrivateMatchDetail {
    pub sample_id: String,
    pub public_crate_id: String,
    pub role: V325SampleRole,
    pub miss_class: V325MissClass,
    pub best_rank: Option<u32>,
    pub best_score: Option<u32>,
    pub matched_pattern_family: Option<V32PatternFamily>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct RevealStaticRankingInput<'a> {
    pub run_id: &'a str,
    pub ranked_candidates_sha256: &'a str,
    pub ground_truth_sha256: &'a str,
    pub top_k_values: &'a [u32],
    pub control_false_positive_min_score: u32,
    pub ground_truth: &'a [V325PrivateGroundTruthRecord],
    pub ranked: &'a [V32RankedCandidateRecord],
    pub buildability: &'a [V32BuildabilityRecord],
    pub boundary_index: &'a [V32BoundaryIndexRecord],
}

pub fn validate_v3_2_5_private_ground_truth<I>(
    records: I,
) -> Result<V325PrivateGroundTruthSummary, ModelError>
where
    I: IntoIterator<Item = Located<V325PrivateGroundTruthRecord>>,
{
    let mut summary = V325PrivateGroundTruthSummary::default();
    let mut suite_id: Option<String> = None;
    let mut sample_ids = BTreeSet::<String>::new();
    let mut public_crate_ids = BTreeSet::<String>::new();
    let mut located_records = Vec::new();

    for located in records {
        let record = &located.value;
        validate_non_empty(&located, "suite_id", &record.suite_id)?;
        validate_non_empty(&located, "sample_id", &record.sample_id)?;
        validate_non_empty(&located, "public_crate_id", &record.public_crate_id)?;
        validate_non_empty(&located, "root_cause_key", &record.root_cause_key)?;

        if let Some(expected) = &suite_id {
            if expected != &record.suite_id {
                return Err(at(
                    &located,
                    "BW-V325-SUITE-MISMATCH",
                    format!("同一文件出现 suite_id {expected} 和 {}", record.suite_id),
                ));
            }
        } else {
            suite_id = Some(record.suite_id.clone());
        }
        if !sample_ids.insert(record.sample_id.clone()) {
            return Err(at(
                &located,
                "BW-V325-SAMPLE-DUP",
                format!("sample_id {} 重复", record.sample_id),
            ));
        }
        if !public_crate_ids.insert(record.public_crate_id.clone()) {
            return Err(at(
                &located,
                "BW-V325-CRATE-DUP",
                format!("public_crate_id {} 重复", record.public_crate_id),
            ));
        }
        if record.role == V325SampleRole::Vulnerable && record.expected_pattern_families.is_empty()
        {
            return Err(at(
                &located,
                "BW-V325-VULN-PATTERN-EMPTY",
                "vulnerable 样本必须声明 expected_pattern_families",
            ));
        }

        summary.record_count += 1;
        match record.role {
            V325SampleRole::Vulnerable => summary.vulnerable_count += 1,
            V325SampleRole::FixedControl | V325SampleRole::SafeControl => {
                summary.control_count += 1
            }
            V325SampleRole::Distractor | V325SampleRole::Negative => {}
        }
        located_records.push(located);
    }

    for located in &located_records {
        for paired in &located.value.paired_with {
            if !sample_ids.contains(paired) {
                return Err(at(
                    located,
                    "BW-V325-PAIR-MISSING",
                    format!(
                        "sample {} 的 paired_with 引用不存在的 sample_id {paired}",
                        located.value.sample_id
                    ),
                ));
            }
        }
    }

    Ok(summary)
}

pub fn validate_v3_2_5_static_ranking_reveal(
    summary: &V325StaticRankingRevealSummary,
) -> Result<(), ModelError> {
    if summary.schema_version != V3_2_5_STATIC_RANKING_REVEAL_SCHEMA_V1 {
        return Err(ModelError::validation(
            "BW-V325-REVEAL-SCHEMA",
            format!(
                "schema_version 必须是 {V3_2_5_STATIC_RANKING_REVEAL_SCHEMA_V1}，实际为 {}",
                summary.schema_version
            ),
        ));
    }
    validate_hex64(
        "ranked_candidates_sha256",
        &summary.ranked_candidates_sha256,
    )?;
    validate_hex64("ground_truth_sha256", &summary.ground_truth_sha256)?;
    if summary.run_id.trim().is_empty() || summary.suite_id.trim().is_empty() {
        return Err(ModelError::validation(
            "BW-V325-REVEAL-EMPTY",
            "run_id 与 suite_id 不能为空",
        ));
    }
    if summary.top_k_values.is_empty() {
        return Err(ModelError::validation(
            "BW-V325-REVEAL-TOPK",
            "top_k_values 不能为空",
        ));
    }
    // Public reveal must not carry private identity tokens in notes.
    for note in &summary.notes {
        reject_public_identity_tokens("notes", note)?;
    }
    Ok(())
}

pub fn reveal_static_ranking(
    input: RevealStaticRankingInput<'_>,
) -> Result<(V325StaticRankingRevealSummary, Vec<V325PrivateMatchDetail>), ModelError> {
    if input.run_id.trim().is_empty() {
        return Err(ModelError::validation("BW-V325-RUN-ID", "run_id 不能为空"));
    }
    validate_hex64("ranked_candidates_sha256", input.ranked_candidates_sha256)?;
    validate_hex64("ground_truth_sha256", input.ground_truth_sha256)?;

    let gt_summary =
        validate_v3_2_5_private_ground_truth(input.ground_truth.iter().cloned().enumerate().map(
            |(index, value)| Located {
                path: "ground-truth.jsonl".into(),
                line: index + 1,
                value,
            },
        ))?;

    let suite_id = input
        .ground_truth
        .first()
        .map(|record| record.suite_id.clone())
        .unwrap_or_default();

    let buildable = input
        .buildability
        .iter()
        .filter(|record| record.status == V32BuildabilityStatus::Buildable)
        .map(|record| record.crate_id.clone())
        .collect::<BTreeSet<_>>();
    let build_known = !input.buildability.is_empty();
    let boundary_crates = input
        .boundary_index
        .iter()
        .map(|record| record.crate_id.clone())
        .collect::<BTreeSet<_>>();

    let ranked_by_crate = {
        let mut map = BTreeMap::<String, Vec<&V32RankedCandidateRecord>>::new();
        for ranked in input.ranked {
            map.entry(ranked.crate_id.clone()).or_default().push(ranked);
        }
        for list in map.values_mut() {
            list.sort_by_key(|item| item.rank);
        }
        map
    };

    let mut metrics = V325RevealMetrics {
        vulnerable_sample_count: gt_summary.vulnerable_count,
        control_sample_count: gt_summary.control_count,
        ..V325RevealMetrics::default()
    };
    let mut miss_class_counts = BTreeMap::<String, u64>::new();
    let mut details = Vec::new();
    let top_k = if input.top_k_values.is_empty() {
        vec![1, 5, 10]
    } else {
        input.top_k_values.to_vec()
    };
    let max_top = *top_k.iter().max().unwrap_or(&10);

    for sample in input.ground_truth {
        match sample.role {
            V325SampleRole::Vulnerable => {
                let (miss, best_rank, best_score, pattern, notes) = evaluate_vulnerable(
                    sample,
                    &buildable,
                    build_known,
                    &boundary_crates,
                    ranked_by_crate
                        .get(&sample.public_crate_id)
                        .map(Vec::as_slice),
                    max_top,
                );
                bump(&mut miss_class_counts, miss.as_str());
                if miss != V325MissClass::BuildFailure {
                    metrics.buildable_vulnerable_count += 1;
                }
                match miss {
                    V325MissClass::HitTopK => {
                        metrics.nday_candidate_hit_count += 1;
                        if let Some(rank) = best_rank {
                            if rank <= 1 {
                                metrics.top1_hit_count += 1;
                            }
                            if rank <= 5 {
                                metrics.top5_hit_count += 1;
                            }
                            if rank <= 10 {
                                metrics.top10_hit_count += 1;
                            }
                        }
                    }
                    V325MissClass::BuildFailure => {
                        metrics.build_failure_count += 1;
                    }
                    V325MissClass::BoundaryMiss => {
                        metrics.boundary_miss_count += 1;
                    }
                    V325MissClass::CandidateMiss => {
                        metrics.boundary_miss_count += 1;
                    }
                    V325MissClass::RankingMiss => {
                        metrics.nday_candidate_hit_count += 1;
                        metrics.ranking_miss_count += 1;
                        if let Some(rank) = best_rank {
                            if rank <= 1 {
                                metrics.top1_hit_count += 1;
                            }
                            if rank <= 5 {
                                metrics.top5_hit_count += 1;
                            }
                            if rank <= 10 {
                                metrics.top10_hit_count += 1;
                            }
                        }
                    }
                    V325MissClass::AdapterBlocked | V325MissClass::GroundTruthMismatch => {}
                }
                details.push(V325PrivateMatchDetail {
                    sample_id: sample.sample_id.clone(),
                    public_crate_id: sample.public_crate_id.clone(),
                    role: sample.role,
                    miss_class: miss,
                    best_rank,
                    best_score,
                    matched_pattern_family: pattern,
                    notes,
                });
            }
            V325SampleRole::FixedControl | V325SampleRole::SafeControl => {
                let ranked = ranked_by_crate
                    .get(&sample.public_crate_id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                let expected = accepted_pattern_families(sample);
                let fp = ranked.iter().any(|item| {
                    expected.contains(&item.pattern_family)
                        && item.score >= input.control_false_positive_min_score
                });
                if fp {
                    metrics.false_positive_control_count += 1;
                    details.push(V325PrivateMatchDetail {
                        sample_id: sample.sample_id.clone(),
                        public_crate_id: sample.public_crate_id.clone(),
                        role: sample.role,
                        miss_class: V325MissClass::GroundTruthMismatch,
                        best_rank: ranked.first().map(|item| item.rank),
                        best_score: ranked.first().map(|item| item.score),
                        matched_pattern_family: ranked.first().map(|item| item.pattern_family),
                        notes: vec![
                            "control has same-family high-score candidate".to_owned(),
                            "not a vulnerability conclusion".to_owned(),
                        ],
                    });
                } else {
                    metrics.paired_control_clean_count += 1;
                    details.push(V325PrivateMatchDetail {
                        sample_id: sample.sample_id.clone(),
                        public_crate_id: sample.public_crate_id.clone(),
                        role: sample.role,
                        miss_class: V325MissClass::HitTopK,
                        best_rank: None,
                        best_score: None,
                        matched_pattern_family: None,
                        notes: vec!["control clean for expected families".to_owned()],
                    });
                }
            }
            V325SampleRole::Distractor | V325SampleRole::Negative => {
                details.push(V325PrivateMatchDetail {
                    sample_id: sample.sample_id.clone(),
                    public_crate_id: sample.public_crate_id.clone(),
                    role: sample.role,
                    miss_class: V325MissClass::HitTopK,
                    best_rank: None,
                    best_score: None,
                    matched_pattern_family: None,
                    notes: vec!["background sample; not counted in vulnerable metrics".to_owned()],
                });
            }
        }
    }

    let summary = V325StaticRankingRevealSummary {
        schema_version: V3_2_5_STATIC_RANKING_REVEAL_SCHEMA_V1.to_owned(),
        run_id: input.run_id.to_owned(),
        suite_id,
        ranked_candidates_sha256: input.ranked_candidates_sha256.to_owned(),
        ground_truth_sha256: input.ground_truth_sha256.to_owned(),
        top_k_values: top_k,
        metrics,
        miss_class_counts,
        notes: vec![
            "static ranking blind smoke".to_owned(),
            "candidate/ranking is not a vulnerability conclusion".to_owned(),
            "no 0day claim".to_owned(),
        ],
    };
    validate_v3_2_5_static_ranking_reveal(&summary)?;
    Ok((summary, details))
}

fn evaluate_vulnerable(
    sample: &V325PrivateGroundTruthRecord,
    buildable: &BTreeSet<String>,
    build_known: bool,
    boundary_crates: &BTreeSet<String>,
    ranked: Option<&[&V32RankedCandidateRecord]>,
    max_top: u32,
) -> (
    V325MissClass,
    Option<u32>,
    Option<u32>,
    Option<V32PatternFamily>,
    Vec<String>,
) {
    if build_known && !buildable.contains(&sample.public_crate_id) {
        return (
            V325MissClass::BuildFailure,
            None,
            None,
            None,
            vec!["crate not buildable; not a no-vulnerability conclusion".to_owned()],
        );
    }

    let expected = accepted_pattern_families(sample);
    if expected.is_empty() {
        return (
            V325MissClass::GroundTruthMismatch,
            None,
            None,
            None,
            vec!["vulnerable sample missing expected_pattern_families".to_owned()],
        );
    }

    let ranked = ranked.unwrap_or(&[]);
    if ranked.is_empty() {
        if build_known && !boundary_crates.contains(&sample.public_crate_id) {
            return (
                V325MissClass::BoundaryMiss,
                None,
                None,
                None,
                vec!["no ranked candidate and no boundary for crate".to_owned()],
            );
        }
        return (
            V325MissClass::CandidateMiss,
            None,
            None,
            None,
            vec!["no ranked candidate matching crate".to_owned()],
        );
    }

    let mut best: Option<&V32RankedCandidateRecord> = None;
    for item in ranked {
        if expected.contains(&item.pattern_family) {
            best = Some(item);
            break;
        }
    }

    match best {
        None => (
            V325MissClass::CandidateMiss,
            None,
            None,
            None,
            vec!["ranked candidates exist but expected pattern family missing".to_owned()],
        ),
        Some(item) if item.rank <= max_top => (
            V325MissClass::HitTopK,
            Some(item.rank),
            Some(item.score),
            Some(item.pattern_family),
            vec![format!(
                "matched pattern {:?} at rank {} score {}",
                item.pattern_family, item.rank, item.score
            )],
        ),
        Some(item) => (
            V325MissClass::RankingMiss,
            Some(item.rank),
            Some(item.score),
            Some(item.pattern_family),
            vec![format!(
                "matched pattern {:?} but rank {} exceeds top-{}",
                item.pattern_family, item.rank, max_top
            )],
        ),
    }
}

fn accepted_pattern_families(sample: &V325PrivateGroundTruthRecord) -> BTreeSet<V32PatternFamily> {
    let mut expected = sample
        .expected_pattern_families
        .iter()
        .flat_map(|pattern| pattern.compatible_public_patterns().iter().copied())
        .collect::<BTreeSet<_>>();
    if returned_borrow_lifetime_root_cause(&sample.root_cause_key) {
        expected.insert(V32PatternFamily::ReturnedBorrowView);
        expected.insert(V32PatternFamily::ExternalBufferView);
    }
    expected
}

fn returned_borrow_lifetime_root_cause(root_cause_key: &str) -> bool {
    let key = root_cause_key.to_ascii_lowercase();
    (key.contains("returned-borrow") || key.contains("returned_borrow"))
        && (key.contains("lifetime") || key.contains("borrowed"))
}

fn bump(map: &mut BTreeMap<String, u64>, key: &str) {
    *map.entry(key.to_owned()).or_default() += 1;
}

fn validate_non_empty(
    located: &Located<V325PrivateGroundTruthRecord>,
    field: &str,
    value: &str,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(at(
            located,
            "BW-V325-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn validate_hex64(field: &str, value: &str) -> Result<(), ModelError> {
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ModelError::validation(
            "BW-V325-SHA256",
            format!("{field} 必须是 64 位十六进制"),
        ));
    }
    Ok(())
}

fn reject_public_identity_tokens(field: &str, value: &str) -> Result<(), ModelError> {
    let lower = value.to_ascii_lowercase();
    let forbidden = [
        "cve-",
        "ghsa-",
        "poc",
        "proof-of-concept",
        "patch_url",
        "advisory",
        "vulnerability_id",
        "expected_location",
        "/private/",
    ];
    if let Some(token) = forbidden.iter().find(|token| lower.contains(*token)) {
        return Err(ModelError::validation(
            "BW-V325-PUBLIC-TOKEN",
            format!("public reveal {field} 禁止包含 token `{token}`"),
        ));
    }
    Ok(())
}

fn at(
    located: &Located<V325PrivateGroundTruthRecord>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, message).at_line(located.path.clone(), located.line)
}
