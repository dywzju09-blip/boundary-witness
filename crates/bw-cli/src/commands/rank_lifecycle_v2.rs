use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use bw_model::{
    V326LifecycleFeatureRecord, V326LifecycleGraphV3Record, V326RankedCandidateRecord,
    rank_v3_2_6_features, summarize_v3_2_6_ranked_object_chains,
    validate_v3_2_6_lifecycle_features, validate_v3_2_6_lifecycle_graph_v3,
    validate_v3_2_6_ranked_candidates,
};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl, write_records},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct RankLifecycleV2Args {
    #[arg(long)]
    features: PathBuf,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long = "graph-dir", default_value = "graphs")]
    graph_dir: String,
    #[arg(long)]
    run_id: String,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

#[derive(Serialize)]
struct RankOutput {
    kind: &'static str,
    run_id: String,
    ranked_count: u64,
    max_score: u32,
    output_dir: String,
    ranked_path: String,
    checksums_path: String,
}

pub fn run(args: RankLifecycleV2Args) -> Result<CommandStatus, CliError> {
    if args.run_id.trim().is_empty() {
        return Err(CliError::input("BW-V326-RUN-ID", "run_id 不能为空"));
    }

    let feature_records =
        read_jsonl::<V326LifecycleFeatureRecord>(&args.features, args.max_line_bytes)?;
    validate_v3_2_6_lifecycle_features(feature_records.clone())?;
    let features = feature_records
        .into_iter()
        .map(|located| located.value)
        .collect::<Vec<_>>();

    let graph_dir = validate_relative_graph_dir(&args.graph_dir)?;
    let mut ranked = rank_v3_2_6_features(&args.run_id, features)?;
    for record in &mut ranked {
        record.lifecycle_graph_path =
            format!("{}/{}.json", graph_dir, sanitize_id(&record.candidate_id));
        if let Some(graph) = read_graph_summary_for_rank(&args.output_dir, record)? {
            record.chain_summary = summarize_v3_2_6_ranked_object_chains(record, &graph);
        }
    }
    let summary = validate_v3_2_6_ranked_candidates(ranked.iter().cloned().enumerate().map(
        |(index, value)| bw_model::Located {
            path: args.output_dir.join("ranked-candidates.jsonl.zst"),
            line: index + 1,
            value,
        },
    ))?;

    fs::create_dir_all(&args.output_dir)?;
    let ranked_path = args.output_dir.join("ranked-candidates.jsonl.zst");
    write_records(&ranked_path, &ranked)?;

    let stats = serde_json::json!({
        "schema_version": "v3.2.6.ranking_stats.1",
        "run_id": args.run_id,
        "ranked_count": summary.ranked_count,
        "max_score": summary.max_score,
        "top_candidate_id": ranked.first().map(|record| record.candidate_id.clone()),
        "top_score": ranked.first().map(|record| record.score),
    });
    write_json_file(&args.output_dir.join("ranking-stats.json"), &stats)?;

    let checksums_path = args.output_dir.join("checksums.txt");
    write_checksums(&args.output_dir, &checksums_path)?;

    let output = RankOutput {
        kind: "v3-2-6-ranked-candidate",
        run_id: args.run_id,
        ranked_count: summary.ranked_count,
        max_score: summary.max_score,
        output_dir: args.output_dir.display().to_string(),
        ranked_path: ranked_path.display().to_string(),
        checksums_path: checksums_path.display().to_string(),
    };
    crate::commands::write_json_stdout(&output)?;
    Ok(CommandStatus::Success)
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

fn read_graph_summary_for_rank(
    output_dir: &Path,
    record: &V326RankedCandidateRecord,
) -> Result<Option<V326LifecycleGraphV3Record>, CliError> {
    let graph_path = Path::new(&record.lifecycle_graph_path);
    if graph_path.is_absolute()
        || graph_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(CliError::input(
            "BW-V326-RANK-GRAPH-PATH",
            "lifecycle_graph_path 必须是相对路径，不能是绝对路径或包含 ..",
        ));
    }
    let full_path = output_dir.join(graph_path);
    if !full_path.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(&full_path)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {}", full_path.display(), error)))?;
    let graph: V326LifecycleGraphV3Record = serde_json::from_str(&text).map_err(|error| {
        CliError::input("BW-JSON", format!("{}: {}", full_path.display(), error))
    })?;
    validate_v3_2_6_lifecycle_graph_v3([bw_model::Located {
        path: full_path.clone(),
        line: 1,
        value: graph.clone(),
    }])?;
    if graph.candidate_id != record.candidate_id || graph.crate_id != record.crate_id {
        return Err(CliError::input(
            "BW-V326-RANK-GRAPH-MISMATCH",
            format!(
                "{} 与 ranked candidate {} / {} 不一致",
                full_path.display(),
                record.candidate_id,
                record.crate_id
            ),
        ));
    }
    Ok(Some(graph))
}

fn write_checksums(output_dir: &Path, checksums_path: &Path) -> Result<(), CliError> {
    let mut lines = vec![
        format!(
            "{}  {}",
            sha256_file(&output_dir.join("ranked-candidates.jsonl.zst"))?,
            "ranked-candidates.jsonl.zst"
        ),
        format!(
            "{}  {}",
            sha256_file(&output_dir.join("ranking-stats.json"))?,
            "ranking-stats.json"
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

fn validate_relative_graph_dir(value: &str) -> Result<String, CliError> {
    let value = value.trim().trim_matches('/');
    if value.is_empty() {
        return Err(CliError::input(
            "BW-V326-RANK-GRAPH-DIR",
            "graph-dir 不能为空",
        ));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(CliError::input(
            "BW-V326-RANK-GRAPH-DIR",
            "graph-dir 必须是相对目录，不能是绝对路径或包含 ..",
        ));
    }
    Ok(value.replace('\\', "/"))
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
