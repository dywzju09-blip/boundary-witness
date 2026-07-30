use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use bw_model::{
    V326LifecycleEvidenceRecord, V326LifecycleFeatureRecord, V326LifecycleGraphRecord,
    build_v3_2_6_lifecycle_graph, derive_v3_2_6_lifecycle_features,
    validate_v3_2_6_lifecycle_evidence, validate_v3_2_6_lifecycle_features,
    validate_v3_2_6_lifecycle_graphs, validate_v3_2_candidates,
};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, load_candidates, read_jsonl, write_records},
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
    write_records(&features_path, &features)?;

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
