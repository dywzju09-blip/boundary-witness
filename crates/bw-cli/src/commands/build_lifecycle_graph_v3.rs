use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Cursor, Write},
    path::{Path, PathBuf},
};

use bw_model::{
    StaticFactEnvelope, V32CandidateRecord, V326LifecycleContractRecord,
    V326LifecycleEvidenceRecord, V326LifecycleFactOrigin, V326LifecycleFactRecord,
    V326LifecycleFeatureRecord, V326LifecycleGraphV3Record, build_v3_2_6_lifecycle_graph,
    build_v3_2_6_lifecycle_graph_v3, derive_v3_2_6_lifecycle_features_with_context,
    validate_v3_2_6_lifecycle_contracts, validate_v3_2_6_lifecycle_evidence,
    validate_v3_2_6_lifecycle_facts, validate_v3_2_6_lifecycle_features,
    validate_v3_2_6_lifecycle_graph_v3, validate_v3_2_candidates,
    verify_v3_2_6_lifecycle_fact_static_provenance,
};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl},
    exit::{CliError, CommandStatus},
};

use super::audit_lifecycle_contracts::audit_registry_source_for_contracts;

#[derive(Args)]
pub struct BuildLifecycleGraphV3Args {
    #[arg(long)]
    candidates: PathBuf,
    #[arg(long)]
    evidence: PathBuf,
    #[arg(long)]
    facts: Option<PathBuf>,
    #[arg(long = "static-facts")]
    static_facts: Option<PathBuf>,
    #[arg(long)]
    contracts: Option<PathBuf>,
    #[arg(long = "registry-manifest")]
    registry_manifest: Option<PathBuf>,
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
    contract_source_audit_state: &'static str,
    contracts_sha256: Option<String>,
    contract_input_checksum_verified_count: u64,
    contract_input_checksum_missing_path_count: u64,
    output_dir: String,
    features_path: String,
    checksums_path: String,
}

pub fn run(args: BuildLifecycleGraphV3Args) -> Result<CommandStatus, CliError> {
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
    let candidates_by_id = candidates
        .iter()
        .map(|candidate| (candidate.candidate_id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();

    let evidence_records =
        read_jsonl::<V326LifecycleEvidenceRecord>(&args.evidence, args.max_line_bytes)?;
    validate_v3_2_6_lifecycle_evidence(evidence_records.clone())?;
    let mut evidence_by_candidate = BTreeMap::<String, Vec<V326LifecycleEvidenceRecord>>::new();
    for located in evidence_records {
        let evidence = located.value;
        let Some(candidate) = candidates_by_id.get(evidence.candidate_id.as_str()) else {
            return Err(CliError::input(
                "BW-V326-EVIDENCE-CANDIDATE",
                format!(
                    "evidence {} 引用了不存在的 candidate_id",
                    evidence.record_id
                ),
            ));
        };
        if evidence.crate_id != candidate.crate_id {
            return Err(CliError::input(
                "BW-V326-EVIDENCE-CANDIDATE-CRATE",
                format!(
                    "evidence {} 的 crate_id 与 candidate {} 不一致",
                    evidence.record_id, evidence.candidate_id
                ),
            ));
        }
        evidence_by_candidate
            .entry(evidence.candidate_id.clone())
            .or_default()
            .push(evidence);
    }

    let mut fact_records = match &args.facts {
        Some(path) => {
            let records = read_jsonl::<V326LifecycleFactRecord>(path, args.max_line_bytes)?;
            validate_v3_2_6_lifecycle_facts(records.clone())?;
            records.into_iter().map(|located| located.value).collect()
        }
        None => Vec::new(),
    };
    let declared_static_fact_count = fact_records
        .iter()
        .filter(|fact| fact.provenance.origin == V326LifecycleFactOrigin::StaticArtifact)
        .count();
    let static_fact_records = match &args.static_facts {
        Some(path) => read_jsonl::<StaticFactEnvelope>(path, args.max_line_bytes)?
            .into_iter()
            .map(|located| located.value)
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };
    if declared_static_fact_count > 0 && args.static_facts.is_none() {
        return Err(CliError::input(
            "BW-V326-FACT-PROVENANCE",
            "lifecycle facts 声明 static_artifact provenance 时必须提供 --static-facts 以回查来源",
        ));
    }
    for fact in &mut fact_records {
        let Some(candidate) = candidates_by_id.get(fact.candidate_id.as_str()) else {
            return Err(CliError::input(
                "BW-V326-FACT-CANDIDATE",
                format!("fact {} 引用了不存在的 candidate_id", fact.fact_id),
            ));
        };
        if fact.crate_id != candidate.crate_id {
            return Err(CliError::input(
                "BW-V326-FACT-CANDIDATE-CRATE",
                format!(
                    "fact {} 的 crate_id 与 candidate {} 不一致",
                    fact.fact_id, fact.candidate_id
                ),
            ));
        }
        if fact.provenance.origin == V326LifecycleFactOrigin::StaticArtifact
            && !verify_v3_2_6_lifecycle_fact_static_provenance(
                fact,
                candidate,
                &static_fact_records,
            )
        {
            return Err(CliError::input(
                "BW-V326-FACT-PROVENANCE",
                format!(
                    "fact {} 无法在 --static-facts 中回查 provenance",
                    fact.fact_id
                ),
            ));
        }
    }
    let mut facts_by_candidate = BTreeMap::<String, Vec<V326LifecycleFactRecord>>::new();
    for fact in fact_records {
        facts_by_candidate
            .entry(fact.candidate_id.clone())
            .or_default()
            .push(fact);
    }

    if args.contracts.is_none() && args.registry_manifest.is_some() {
        return Err(CliError::input(
            "BW-CONTRACT-AUDIT-SOURCE",
            "--registry-manifest 只能与 --contracts 一起使用",
        ));
    }
    let mut contract_source_audit_state = "not_requested";
    let mut contracts_sha256 = None;
    let mut contract_input_checksum_verified_count = 0_u64;
    let mut contract_input_checksum_missing_path_count = 0_u64;
    let contract_records = match &args.contracts {
        Some(path) => {
            let records = read_jsonl::<V326LifecycleContractRecord>(path, args.max_line_bytes)?;
            validate_v3_2_6_lifecycle_contracts(records.clone())?;
            let contracts = records
                .into_iter()
                .map(|located| located.value)
                .collect::<Vec<_>>();
            let (sha256, source_audit) = audit_registry_source_for_contracts(
                &contracts,
                path,
                args.registry_manifest.as_deref(),
            )?;
            contract_source_audit_state = source_audit.state;
            contracts_sha256 = Some(sha256);
            contract_input_checksum_verified_count = source_audit.input_checksum_verified_count;
            contract_input_checksum_missing_path_count =
                source_audit.input_checksum_missing_path_count;
            contracts
        }
        None => Vec::new(),
    };

    fs::create_dir_all(args.output_dir.join("graphs-v3"))?;

    let mut graphs = Vec::<V326LifecycleGraphV3Record>::new();
    let mut features = Vec::<V326LifecycleFeatureRecord>::new();
    let mut graph_paths = Vec::<String>::new();

    for candidate in &candidates {
        let evidence = evidence_by_candidate
            .get(&candidate.candidate_id)
            .cloned()
            .unwrap_or_default();
        let facts = facts_by_candidate
            .get(&candidate.candidate_id)
            .cloned()
            .unwrap_or_default();
        let mut graph_v3 =
            build_v3_2_6_lifecycle_graph_v3(candidate, &evidence, &facts, &contract_records);
        graph_v3.run_id = args.run_id.clone();
        let graph_v2 = build_v3_2_6_lifecycle_graph(candidate, &evidence);
        let mut feature = derive_v3_2_6_lifecycle_features_with_context(
            candidate,
            &graph_v2,
            &evidence,
            &facts,
            &contract_records,
        );
        feature.run_id = args.run_id.clone();

        let relative = format!("graphs-v3/{}.json", sanitize_id(&candidate.candidate_id));
        write_json_file(&args.output_dir.join(&relative), &graph_v3)?;
        graph_paths.push(relative);
        graphs.push(graph_v3);
        features.push(feature);
    }

    validate_v3_2_6_lifecycle_graph_v3(graphs.iter().cloned().enumerate().map(
        |(index, value)| bw_model::Located {
            path: args.output_dir.join("graphs-v3"),
            line: index + 1,
            value,
        },
    ))?;
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
        "schema_version": "v3.2.6.lifecycle_graph_v3_stats.1",
        "run_id": args.run_id,
        "candidate_count": candidates.len(),
        "graph_count": graphs.len(),
        "feature_count": features.len(),
        "incomplete_graph_count": graphs.iter().filter(|graph| !graph.incomplete_reasons.is_empty()).count(),
    });
    write_json_file(&args.output_dir.join("graph-v3-stats.json"), &stats)?;

    let checksums_path = args.output_dir.join("checksums.txt");
    write_checksums(&args.output_dir, &graph_paths, &checksums_path)?;

    let output = BuildOutput {
        kind: "v3-2-6-lifecycle-graph-v3",
        run_id: args.run_id,
        candidate_count: candidates.len() as u64,
        graph_count: graphs.len() as u64,
        feature_count: features.len() as u64,
        contract_source_audit_state,
        contracts_sha256,
        contract_input_checksum_verified_count,
        contract_input_checksum_missing_path_count,
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
            .filter_map(Result::ok)
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

fn write_records<T: Serialize>(path: &Path, records: &[T]) -> Result<(), CliError> {
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
            sha256_file(&output_dir.join("graph-v3-stats.json"))?,
            "graph-v3-stats.json"
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

fn sha256_file(path: &Path) -> Result<String, CliError> {
    let bytes = fs::read(path)?;
    Ok(hex_digest(Sha256::digest(bytes)))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
