use std::{
    fs::{self, File},
    io::{Cursor, Write},
    path::{Path, PathBuf},
};

use bw_model::{
    V32CandidateRecord, V32LifecycleGraph, V32RankedCandidateRecord,
    lifecycle_graph_from_candidate, ranking_reason, score_lifecycle_graph,
    validate_v3_2_candidates, validate_v3_2_lifecycle_graphs, validate_v3_2_ranked_candidates,
};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct RankLifecycleArgs {
    /// Candidate partition file (.jsonl/.jsonl.zst) or directory containing candidates/*.jsonl.zst.
    #[arg(long = "candidates")]
    candidates: PathBuf,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

#[derive(Serialize)]
struct RankLifecycleOutput {
    kind: &'static str,
    run_id: String,
    candidate_count: u64,
    graph_count: u64,
    ranked_count: u64,
    max_score: u32,
    output_dir: String,
    ranked_path: String,
    checksums_path: String,
}

pub fn run(args: RankLifecycleArgs) -> Result<CommandStatus, CliError> {
    if args.run_id.trim().is_empty() {
        return Err(CliError::input("BW-LIFECYCLE-RUN-ID", "run_id 不能为空"));
    }

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

    fs::create_dir_all(args.output_dir.join("lifecycle-graphs"))?;

    let mut graphs = Vec::<V32LifecycleGraph>::new();
    let mut ranked_inputs = Vec::<(
        V32CandidateRecord,
        V32LifecycleGraph,
        u32,
        bw_model::V32ScoreBreakdown,
        String,
    )>::new();

    for candidate in &candidates {
        let graph = lifecycle_graph_from_candidate(candidate, &args.run_id);
        let (score, breakdown) = score_lifecycle_graph(&graph, candidate.confidence);
        let graph_path = lifecycle_graph_relative_path(&candidate.candidate_id);
        let absolute_graph_path = args.output_dir.join(&graph_path);
        write_json_file(&absolute_graph_path, &graph)?;
        graphs.push(graph.clone());
        ranked_inputs.push((candidate.clone(), graph, score, breakdown, graph_path));
    }

    validate_v3_2_lifecycle_graphs(graphs.iter().cloned().enumerate().map(|(index, value)| {
        bw_model::Located {
            path: args.output_dir.join("lifecycle-graphs"),
            line: index + 1,
            value,
        }
    }))?;

    ranked_inputs.sort_by(|left, right| {
        right
            .2
            .cmp(&left.2)
            .then_with(|| left.0.candidate_id.cmp(&right.0.candidate_id))
    });

    let mut ranked = Vec::<V32RankedCandidateRecord>::with_capacity(ranked_inputs.len());
    for (rank_index, (candidate, graph, score, breakdown, graph_path)) in
        ranked_inputs.into_iter().enumerate()
    {
        ranked.push(V32RankedCandidateRecord {
            schema_version: bw_model::V3_2_RANKED_CANDIDATE_SCHEMA_V1.to_owned(),
            run_id: args.run_id.clone(),
            rank: (rank_index as u32) + 1,
            candidate_id: candidate.candidate_id,
            crate_id: candidate.crate_id,
            pattern_family: candidate.pattern_family,
            score,
            score_breakdown: breakdown.clone(),
            risk_features: graph.risk_features.clone(),
            lifecycle_graph_path: graph_path,
            ranking_reason: ranking_reason(score, &graph.risk_features, breakdown.confidence_bonus),
            notes: vec![
                "ranking is not a vulnerability conclusion".to_owned(),
                "higher score only means higher priority for later validation".to_owned(),
            ],
        });
    }

    let summary = validate_v3_2_ranked_candidates(ranked.iter().cloned().enumerate().map(
        |(index, value)| bw_model::Located {
            path: args.output_dir.join("ranked-candidates.jsonl.zst"),
            line: index + 1,
            value,
        },
    ))?;

    let ranked_path = args.output_dir.join("ranked-candidates.jsonl.zst");
    write_records(&ranked_path, &ranked)?;

    let stats = serde_json::json!({
        "schema_version": "v3.2.lifecycle_stats.1",
        "run_id": args.run_id,
        "candidate_count": candidates.len(),
        "graph_count": summary.graph_count,
        "ranked_count": summary.ranked_count,
        "max_score": summary.max_score,
        "top_candidate_id": ranked.first().map(|record| record.candidate_id.clone()),
        "top_score": ranked.first().map(|record| record.score),
    });
    write_json_file(&args.output_dir.join("stats.json"), &stats)?;

    let checksums_path = args.output_dir.join("checksums.sha256");
    write_checksums(&args.output_dir, &ranked, &checksums_path)?;

    let output = RankLifecycleOutput {
        kind: "v3-2-lifecycle-ranking",
        run_id: args.run_id,
        candidate_count: candidates.len() as u64,
        graph_count: summary.graph_count,
        ranked_count: summary.ranked_count,
        max_score: summary.max_score,
        output_dir: args.output_dir.display().to_string(),
        ranked_path: ranked_path.display().to_string(),
        checksums_path: checksums_path.display().to_string(),
    };
    crate::commands::write_json_stdout(&output)?;
    Ok(CommandStatus::Success)
}

fn load_candidates(
    path: &Path,
    max_line_bytes: usize,
) -> Result<Vec<V32CandidateRecord>, CliError> {
    if path.is_file() {
        return Ok(read_jsonl::<V32CandidateRecord>(path, max_line_bytes)?
            .into_iter()
            .map(|located| located.value)
            .collect());
    }
    if path.is_dir() {
        let candidates_dir = if path.join("candidates").is_dir() {
            path.join("candidates")
        } else {
            path.to_path_buf()
        };
        let mut files = fs::read_dir(&candidates_dir)
            .map_err(|error| {
                CliError::input("BW-IO", format!("{}: {}", candidates_dir.display(), error))
            })?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        (name.starts_with("part-") && name.ends_with(".jsonl.zst"))
                            || name.ends_with(".jsonl")
                    })
            })
            .collect::<Vec<_>>();
        files.sort();
        if files.is_empty() {
            return Err(CliError::input(
                "BW-LIFECYCLE-CANDIDATES-EMPTY",
                format!(
                    "目录 {} 中没有找到 candidates/part-*.jsonl.zst",
                    candidates_dir.display()
                ),
            ));
        }
        let mut records = Vec::new();
        for file in files {
            records.extend(
                read_jsonl::<V32CandidateRecord>(&file, max_line_bytes)?
                    .into_iter()
                    .map(|located| located.value),
            );
        }
        return Ok(records);
    }
    Err(CliError::input(
        "BW-IO",
        format!("candidates 路径不存在: {}", path.display()),
    ))
}

fn lifecycle_graph_relative_path(candidate_id: &str) -> String {
    let sanitized = candidate_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("lifecycle-graphs/{sanitized}.json")
}

fn write_records(path: &Path, records: &[V32RankedCandidateRecord]) -> Result<(), CliError> {
    let mut bytes = Vec::<u8>::new();
    for record in records {
        serde_json::to_writer(&mut bytes, record)
            .map_err(|error| CliError::internal(error.to_string()))?;
        bytes.push(b'\n');
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(path)?;
    if path.extension().is_some_and(|extension| extension == "zst") {
        zstd::stream::copy_encode(Cursor::new(bytes), file, 0)
            .map_err(|error| CliError::input("BW-IO", error.to_string()))?;
    } else {
        let mut file = file;
        file.write_all(&bytes)?;
    }
    Ok(())
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
    ranked: &[V32RankedCandidateRecord],
    checksums_path: &Path,
) -> Result<(), CliError> {
    let mut lines = Vec::<String>::new();
    lines.push(format!(
        "{}  {}",
        sha256_file(&output_dir.join("ranked-candidates.jsonl.zst"))?,
        "ranked-candidates.jsonl.zst"
    ));
    lines.push(format!(
        "{}  {}",
        sha256_file(&output_dir.join("stats.json"))?,
        "stats.json"
    ));
    for record in ranked {
        lines.push(format!(
            "{}  {}",
            sha256_file(&output_dir.join(&record.lifecycle_graph_path))?,
            record.lifecycle_graph_path
        ));
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
