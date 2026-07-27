use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use bw_model::{
    RevealStaticRankingInput, V3_2_RANKED_CANDIDATE_SCHEMA_V1, V32BoundaryIndexRecord,
    V32BuildabilityRecord, V32RankedCandidateRecord, V32RiskFeatures, V32ScoreBreakdown,
    V325PrivateGroundTruthRecord, V326RankedCandidateRecord, reveal_static_ranking,
    validate_v3_2_5_private_ground_truth, validate_v3_2_5_static_ranking_reveal,
    validate_v3_2_6_ranked_candidates, validate_v3_2_boundary_index, validate_v3_2_buildability,
    validate_v3_2_ranked_candidates,
};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl, write_json_stdout},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct RevealStaticRankingArgs {
    /// Ranked candidates file or directory containing ranked-candidates.jsonl.zst.
    #[arg(long = "ranked-candidates")]
    ranked_candidates: PathBuf,
    /// Private ground-truth JSONL (Git 外路径；不得提交).
    #[arg(long = "ground-truth")]
    ground_truth: PathBuf,
    #[arg(long)]
    buildability: Option<PathBuf>,
    #[arg(long = "boundary-index")]
    boundary_index: Option<PathBuf>,
    /// Must match scanner-freeze ranked SHA-256.
    #[arg(long = "expected-ranked-sha256")]
    expected_ranked_sha256: String,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long = "top-k", value_delimiter = ',', default_value = "1,5,10")]
    top_k: Vec<u32>,
    #[arg(long = "control-false-positive-min-score", default_value_t = 20)]
    control_false_positive_min_score: u32,
    /// Optional private match-detail path (must stay outside Git).
    #[arg(long = "private-match-detail")]
    private_match_detail: Option<PathBuf>,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

#[derive(Serialize)]
struct RevealCliOutput {
    kind: &'static str,
    run_id: String,
    suite_id: String,
    ranked_candidates_sha256: String,
    ground_truth_sha256: String,
    metrics: bw_model::V325RevealMetrics,
    output_dir: String,
    reveal_summary_path: String,
}

pub fn run(args: RevealStaticRankingArgs) -> Result<CommandStatus, CliError> {
    if args.run_id.trim().is_empty() {
        return Err(CliError::input("BW-V325-RUN-ID", "run_id 不能为空"));
    }
    if args.expected_ranked_sha256.len() != 64 {
        return Err(CliError::input(
            "BW-V325-FREEZE-SHA",
            "expected-ranked-sha256 必须是 64 位十六进制",
        ));
    }

    let ranked_path = resolve_ranked_path(&args.ranked_candidates)?;
    let ranked_bytes = fs::read(&ranked_path).map_err(|error| {
        CliError::input("BW-IO", format!("{}: {}", ranked_path.display(), error))
    })?;
    let ranked_sha = sha256_hex(&ranked_bytes);
    if ranked_sha != args.expected_ranked_sha256.to_ascii_lowercase() {
        return Err(CliError::input(
            "BW-V325-FREEZE-MISMATCH",
            format!(
                "ranked-candidates SHA-256 与 freeze 不一致: actual={ranked_sha} expected={}",
                args.expected_ranked_sha256
            ),
        ));
    }

    let ground_bytes = fs::read(&args.ground_truth).map_err(|error| {
        CliError::input(
            "BW-IO",
            format!("{}: {}", args.ground_truth.display(), error),
        )
    })?;
    let ground_sha = sha256_hex(&ground_bytes);

    let ranked_values = load_ranked_for_reveal(&ranked_path, args.max_line_bytes)?;

    let ground =
        read_jsonl::<V325PrivateGroundTruthRecord>(&args.ground_truth, args.max_line_bytes)?;
    validate_v3_2_5_private_ground_truth(ground.clone())?;
    let ground_values = ground
        .into_iter()
        .map(|located| located.value)
        .collect::<Vec<_>>();

    let buildability_values = if let Some(path) = &args.buildability {
        let records = read_jsonl::<V32BuildabilityRecord>(path, args.max_line_bytes)?;
        validate_v3_2_buildability(records.clone())?;
        records
            .into_iter()
            .map(|located| located.value)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let boundary_values = if let Some(path) = &args.boundary_index {
        let records = read_jsonl::<V32BoundaryIndexRecord>(path, args.max_line_bytes)?;
        validate_v3_2_boundary_index(records.clone())?;
        records
            .into_iter()
            .map(|located| located.value)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let (summary, details) = reveal_static_ranking(RevealStaticRankingInput {
        run_id: &args.run_id,
        ranked_candidates_sha256: &ranked_sha,
        ground_truth_sha256: &ground_sha,
        top_k_values: &args.top_k,
        control_false_positive_min_score: args.control_false_positive_min_score,
        ground_truth: &ground_values,
        ranked: &ranked_values,
        buildability: &buildability_values,
        boundary_index: &boundary_values,
    })
    .map_err(CliError::from)?;
    validate_v3_2_5_static_ranking_reveal(&summary).map_err(CliError::from)?;

    fs::create_dir_all(&args.output_dir)?;
    let summary_path = args.output_dir.join("reveal-summary.json");
    write_json_file(&summary_path, &summary)?;

    if let Some(detail_path) = &args.private_match_detail {
        if let Some(parent) = detail_path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_jsonl_file(detail_path, &details)?;
    }

    let mut checksums = File::create(args.output_dir.join("checksums.sha256"))
        .map_err(|error| CliError::internal(error.to_string()))?;
    writeln!(checksums, "{ranked_sha}  ranked-candidates (input freeze)")
        .map_err(|error| CliError::internal(error.to_string()))?;
    writeln!(checksums, "{ground_sha}  ground-truth (private input)")
        .map_err(|error| CliError::internal(error.to_string()))?;
    let summary_sha = sha256_file(&summary_path)?;
    writeln!(checksums, "{summary_sha}  reveal-summary.json")
        .map_err(|error| CliError::internal(error.to_string()))?;

    write_json_stdout(&RevealCliOutput {
        kind: "v3-2-5-static-ranking-reveal",
        run_id: args.run_id,
        suite_id: summary.suite_id.clone(),
        ranked_candidates_sha256: ranked_sha,
        ground_truth_sha256: ground_sha,
        metrics: summary.metrics,
        output_dir: args.output_dir.display().to_string(),
        reveal_summary_path: summary_path.display().to_string(),
    })?;
    Ok(CommandStatus::Success)
}

fn resolve_ranked_path(path: &Path) -> Result<PathBuf, CliError> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }
    let candidate = path.join("ranked-candidates.jsonl.zst");
    if candidate.is_file() {
        return Ok(candidate);
    }
    Err(CliError::input(
        "BW-IO",
        format!("找不到 ranked-candidates.jsonl.zst: {}", path.display()),
    ))
}

fn load_ranked_for_reveal(
    path: &Path,
    max_line_bytes: usize,
) -> Result<Vec<V32RankedCandidateRecord>, CliError> {
    match read_jsonl::<V32RankedCandidateRecord>(path, max_line_bytes) {
        Ok(records) => {
            validate_v3_2_ranked_candidates(records.clone())?;
            Ok(records.into_iter().map(|located| located.value).collect())
        }
        Err(v32_error) => {
            let records = read_jsonl::<V326RankedCandidateRecord>(path, max_line_bytes)
                .map_err(|_| v32_error)?;
            validate_v3_2_6_ranked_candidates(records.clone())?;
            Ok(records
                .into_iter()
                .map(|located| ranked_v3_2_6_to_v3_2(located.value))
                .collect())
        }
    }
}

fn ranked_v3_2_6_to_v3_2(record: V326RankedCandidateRecord) -> V32RankedCandidateRecord {
    V32RankedCandidateRecord {
        schema_version: V3_2_RANKED_CANDIDATE_SCHEMA_V1.to_owned(),
        run_id: record.run_id,
        rank: record.rank,
        candidate_id: record.candidate_id,
        crate_id: record.crate_id,
        pattern_family: record.pattern_family,
        score: record.score,
        score_breakdown: V32ScoreBreakdown {
            foreign_retention_without_owned_anchor: positive_score(
                record.score_breakdown.foreign_may_retain_callback,
            ),
            missing_unregister_before_drop: positive_score(
                record.score_breakdown.missing_unregister_before_drop,
            ),
            cross_language_alias: positive_score(record.score_breakdown.has_borrowed_capture)
                + positive_score(record.score_breakdown.has_raw_pointer_escape),
            opaque_handle_without_owner: positive_score(
                record.score_breakdown.opaque_handle_without_owner,
            ),
            callback_retained_across_drop: positive_score(
                record
                    .score_breakdown
                    .rust_object_may_drop_before_foreign_release,
            ),
            confidence_bonus: positive_score(record.score_breakdown.needs_dynamic_witness),
        },
        risk_features: V32RiskFeatures {
            foreign_retention_without_owned_anchor: record
                .risk_features
                .iter()
                .any(|feature| feature == "foreign_may_retain_callback")
                && !record
                    .protective_features
                    .iter()
                    .any(|feature| feature == "has_owned_anchor"),
            missing_unregister_before_drop: record
                .risk_features
                .iter()
                .any(|feature| feature == "missing_unregister_before_drop"),
            cross_language_alias: record.risk_features.iter().any(|feature| {
                feature == "has_borrowed_capture" || feature == "has_raw_pointer_escape"
            }),
            opaque_handle_without_owner: record
                .risk_features
                .iter()
                .any(|feature| feature == "opaque_handle_without_owner"),
            callback_retained_across_drop: record
                .risk_features
                .iter()
                .any(|feature| feature == "rust_object_may_drop_before_foreign_release"),
        },
        lifecycle_graph_path: record.lifecycle_graph_path,
        ranking_reason: record.ranking_reason,
        notes: record.notes,
    }
}

fn positive_score(value: i32) -> u32 {
    u32::try_from(value).unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn sha256_file(path: &Path) -> Result<String, CliError> {
    let mut file = File::open(path)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {}", path.display(), error)))?;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|error| CliError::input("BW-IO", error.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    let mut file = File::create(path).map_err(|error| CliError::internal(error.to_string()))?;
    serde_json::to_writer_pretty(&mut file, value)
        .map_err(|error| CliError::internal(error.to_string()))?;
    file.write_all(b"\n")
        .map_err(|error| CliError::internal(error.to_string()))?;
    Ok(())
}

fn write_jsonl_file<T: Serialize>(path: &Path, values: &[T]) -> Result<(), CliError> {
    let mut file = File::create(path).map_err(|error| CliError::internal(error.to_string()))?;
    for value in values {
        serde_json::to_writer(&mut file, value)
            .map_err(|error| CliError::internal(error.to_string()))?;
        file.write_all(b"\n")
            .map_err(|error| CliError::internal(error.to_string()))?;
    }
    Ok(())
}
