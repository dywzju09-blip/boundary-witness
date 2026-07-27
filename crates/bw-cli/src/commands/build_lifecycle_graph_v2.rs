use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Cursor, Write},
    path::{Path, PathBuf},
};

use bw_model::{
    V32CandidateRecord, V326LifecycleEvidenceRecord, V326LifecycleFeatureRecord,
    V326LifecycleGraphRecord, build_v3_2_6_lifecycle_graph, derive_v3_2_6_lifecycle_features,
    validate_v3_2_6_lifecycle_evidence, validate_v3_2_6_lifecycle_features,
    validate_v3_2_6_lifecycle_graphs, validate_v3_2_candidates,
};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct BuildLifecycleGraphV2Args {
    #[arg(long)]
    candidates: PathBuf,
    #[arg(long)]
    evidence: PathBuf,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

#[derive(Serialize)]
struct BuildOutput {
    kind: &'static str,
    run_id: String,
    candidate_count: u64,
    graph_count: u64,
    feature_count: u64,
    output_dir: String,
    features_path: String,
    checksums_path: String,
}

pub fn run(args: BuildLifecycleGraphV2Args) -> Result<CommandStatus, CliError> {
    if args.run_id.trim().is_empty() {
        return Err(CliError::input("BW-V326-RUN-ID", "run_id 不能为空"));
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

    let evidence_records =
        read_jsonl::<V326LifecycleEvidenceRecord>(&args.evidence, args.max_line_bytes)?;
    validate_v3_2_6_lifecycle_evidence(evidence_records.clone())?;

    let mut evidence_by_candidate = BTreeMap::<String, Vec<V326LifecycleEvidenceRecord>>::new();
    for located in evidence_records {
        evidence_by_candidate
            .entry(located.value.candidate_id.clone())
            .or_default()
            .push(located.value);
    }

    fs::create_dir_all(args.output_dir.join("graphs"))?;

    let mut graphs = Vec::<V326LifecycleGraphRecord>::new();
    let mut features = Vec::<V326LifecycleFeatureRecord>::new();
    let mut graph_paths = Vec::<String>::new();

    for candidate in &candidates {
        let evidence = evidence_by_candidate
            .get(&candidate.candidate_id)
            .cloned()
            .unwrap_or_default();
        let mut graph = build_v3_2_6_lifecycle_graph(candidate, &evidence);
        graph.run_id = args.run_id.clone();
        let mut feature = derive_v3_2_6_lifecycle_features(candidate, &graph, &evidence);
        feature.run_id = args.run_id.clone();

        let relative = format!("graphs/{}.json", sanitize_id(&candidate.candidate_id));
        write_json_file(&args.output_dir.join(&relative), &graph)?;
        graph_paths.push(relative);
        graphs.push(graph);
        features.push(feature);
    }

    validate_v3_2_6_lifecycle_graphs(graphs.iter().cloned().enumerate().map(|(index, value)| {
        bw_model::Located {
            path: args.output_dir.join("graphs"),
            line: index + 1,
            value,
        }
    }))?;
    validate_v3_2_6_lifecycle_features(features.iter().cloned().enumerate().map(
        |(index, value)| bw_model::Located {
            path: args.output_dir.join("lifecycle-features.jsonl.zst"),
            line: index + 1,
            value,
        },
    ))?;

    let features_path = args.output_dir.join("lifecycle-features.jsonl.zst");
    write_feature_records(&features_path, &features)?;

    let stats = serde_json::json!({
        "schema_version": "v3.2.6.lifecycle_graph_stats.1",
        "run_id": args.run_id,
        "candidate_count": candidates.len(),
        "graph_count": graphs.len(),
        "feature_count": features.len(),
        "incomplete_graph_count": graphs.iter().filter(|graph| !graph.incomplete_evidence.is_empty()).count(),
    });
    write_json_file(&args.output_dir.join("graph-stats.json"), &stats)?;

    let checksums_path = args.output_dir.join("checksums.txt");
    write_checksums(&args.output_dir, &graph_paths, &checksums_path)?;

    let output = BuildOutput {
        kind: "v3-2-6-lifecycle-graph-v2",
        run_id: args.run_id,
        candidate_count: candidates.len() as u64,
        graph_count: graphs.len() as u64,
        feature_count: features.len() as u64,
        output_dir: args.output_dir.display().to_string(),
        features_path: features_path.display().to_string(),
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
                        name.ends_with(".jsonl")
                            || name.ends_with(".jsonl.zst")
                            || (name.starts_with("part-")
                                && (name.ends_with(".jsonl") || name.ends_with(".jsonl.zst")))
                    })
            })
            .collect::<Vec<_>>();
        files.sort();
        if files.is_empty() {
            return Err(CliError::input(
                "BW-V326-CANDIDATES-EMPTY",
                format!(
                    "目录 {} 中没有找到 candidate JSONL 分片",
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

fn write_feature_records(
    path: &Path,
    records: &[V326LifecycleFeatureRecord],
) -> Result<(), CliError> {
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
    graph_paths: &[String],
    checksums_path: &Path,
) -> Result<(), CliError> {
    let mut lines = vec![
        format!(
            "{}  {}",
            sha256_file(&output_dir.join("lifecycle-features.jsonl.zst"))?,
            "lifecycle-features.jsonl.zst"
        ),
        format!(
            "{}  {}",
            sha256_file(&output_dir.join("graph-stats.json"))?,
            "graph-stats.json"
        ),
    ];
    for relative in graph_paths {
        lines.push(format!(
            "{}  {}",
            sha256_file(&output_dir.join(relative))?,
            relative
        ));
    }
    lines.sort();
    let mut file = File::create(checksums_path)?;
    for line in lines {
        writeln!(file, "{line}")?;
    }
    Ok(())
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
