use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use bw_model::{
    V32AdapterEffortRecord, V32BoundaryIndexRecord, V32BuildabilityRecord,
    V32FailureTaxonomyRecord, build_failure_taxonomy, validate_v3_2_adapter_effort,
    validate_v3_2_boundary_index, validate_v3_2_buildability, validate_v3_2_failure_taxonomy,
};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, hex_digest, read_jsonl, write_json_file, write_records},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct BuildFailureTaxonomyArgs {
    #[arg(long)]
    buildability: PathBuf,
    #[arg(long = "boundary-index")]
    boundary_index: PathBuf,
    #[arg(long = "adapter-effort")]
    adapter_effort: PathBuf,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

#[derive(Serialize)]
struct BuildFailureTaxonomyOutput {
    kind: &'static str,
    run_id: String,
    record_count: u64,
    infrastructure_failure_count: u64,
    build_failure_count: u64,
    no_boundary_count: u64,
    deferred_count: u64,
    output_dir: String,
    taxonomy_path: String,
    checksums_path: String,
}

pub fn run(args: BuildFailureTaxonomyArgs) -> Result<CommandStatus, CliError> {
    if args.run_id.trim().is_empty() {
        return Err(CliError::input("BW-TAXONOMY-RUN-ID", "run_id 不能为空"));
    }

    let buildability =
        read_jsonl::<V32BuildabilityRecord>(&args.buildability, args.max_line_bytes)?;
    let buildability_summary = validate_v3_2_buildability(buildability.clone())?;
    let boundary = read_jsonl::<V32BoundaryIndexRecord>(&args.boundary_index, args.max_line_bytes)?;
    let boundary_summary = validate_v3_2_boundary_index(boundary.clone())?;
    let adapter = read_jsonl::<V32AdapterEffortRecord>(&args.adapter_effort, args.max_line_bytes)?;
    let adapter_summary = validate_v3_2_adapter_effort(adapter.clone())?;

    let build_values = buildability
        .into_iter()
        .map(|located| located.value)
        .collect::<Vec<_>>();
    let boundary_values = boundary
        .into_iter()
        .map(|located| located.value)
        .collect::<Vec<_>>();
    let adapter_values = adapter
        .into_iter()
        .map(|located| located.value)
        .collect::<Vec<_>>();

    let records = build_failure_taxonomy(
        &args.run_id,
        &build_values,
        &boundary_values,
        &adapter_values,
    );
    let summary = validate_v3_2_failure_taxonomy(records.iter().cloned().enumerate().map(
        |(index, value)| bw_model::Located {
            path: args.output_dir.join("failure-taxonomy.jsonl.zst"),
            line: index + 1,
            value,
        },
    ))?;

    fs::create_dir_all(&args.output_dir)?;
    let taxonomy_path = args.output_dir.join("failure-taxonomy.jsonl.zst");
    write_records(&taxonomy_path, &records)?;

    let funnel = serde_json::json!({
        "schema_version": "v3.2.pilot_funnel.1",
        "run_id": args.run_id,
        "buildability_record_count": buildability_summary.record_count,
        "buildable_count": buildability_summary.buildable_count,
        "build_failed_count": buildability_summary.failed_count,
        "boundary_record_count": boundary_summary.record_count,
        "boundary_count": boundary_summary.boundary_count,
        "negative_count": boundary_summary.negative_count,
        "candidate_count": boundary_summary.boundary_count,
        "adapter_record_count": adapter_summary.record_count,
        "dynamic_ready_count": adapter_summary.adapter_needed_count,
        "deferred_count": adapter_summary.deferred_count,
        "taxonomy_record_count": summary.record_count,
        "infrastructure_failure_count": summary.infrastructure_failure_count,
        "no_boundary_count": summary.no_boundary_count,
        "taxonomy_deferred_count": summary.deferred_count,
        "method_negative_count": summary.method_negative_count,
    });
    write_json_file(&args.output_dir.join("pilot-funnel.json"), &funnel)?;

    let stats = serde_json::json!({
        "schema_version": "v3.2.failure_taxonomy_stats.1",
        "run_id": args.run_id,
        "record_count": summary.record_count,
        "infrastructure_failure_count": summary.infrastructure_failure_count,
        "build_failure_count": summary.build_failure_count,
        "no_boundary_count": summary.no_boundary_count,
        "deferred_count": summary.deferred_count,
        "method_negative_count": summary.method_negative_count,
        "failure_class_counts": count_failure_classes(&records),
        "stage_counts": count_stages(&records),
    });
    write_json_file(&args.output_dir.join("stats.json"), &stats)?;

    let checksums_path = args.output_dir.join("checksums.sha256");
    write_checksums(
        &[
            ("failure-taxonomy.jsonl.zst", &taxonomy_path),
            ("stats.json", &args.output_dir.join("stats.json")),
            (
                "pilot-funnel.json",
                &args.output_dir.join("pilot-funnel.json"),
            ),
        ],
        &checksums_path,
    )?;

    let output = BuildFailureTaxonomyOutput {
        kind: "v3-2-failure-taxonomy",
        run_id: args.run_id,
        record_count: summary.record_count,
        infrastructure_failure_count: summary.infrastructure_failure_count,
        build_failure_count: summary.build_failure_count,
        no_boundary_count: summary.no_boundary_count,
        deferred_count: summary.deferred_count,
        output_dir: args.output_dir.display().to_string(),
        taxonomy_path: taxonomy_path.display().to_string(),
        checksums_path: checksums_path.display().to_string(),
    };
    crate::commands::write_json_stdout(&output)?;
    Ok(CommandStatus::Success)
}

fn count_failure_classes(
    records: &[V32FailureTaxonomyRecord],
) -> std::collections::BTreeMap<&'static str, u64> {
    let mut counts = std::collections::BTreeMap::new();
    for record in records {
        let key = match record.failure_class {
            bw_model::V32FailureClass::RequiresSystemDependency => "requires_system_dependency",
            bw_model::V32FailureClass::CargoCheckFailed => "cargo_check_failed",
            bw_model::V32FailureClass::NotBuildable => "not_buildable",
            bw_model::V32FailureClass::UnsupportedTarget => "unsupported_target",
            bw_model::V32FailureClass::Timeout => "timeout",
            bw_model::V32FailureClass::ToolError => "tool_error",
            bw_model::V32FailureClass::NoSupportedBoundaryPattern => {
                "no_supported_boundary_pattern"
            }
            bw_model::V32FailureClass::DeferredStaticOnly => "deferred_static_only",
            bw_model::V32FailureClass::AnalyzerUnsupported => "analyzer_unsupported",
            bw_model::V32FailureClass::InsufficientEvidence => "insufficient_evidence",
            bw_model::V32FailureClass::IntegrityFailure => "integrity_failure",
        };
        *counts.entry(key).or_default() += 1;
    }
    counts
}

fn count_stages(
    records: &[V32FailureTaxonomyRecord],
) -> std::collections::BTreeMap<&'static str, u64> {
    let mut counts = std::collections::BTreeMap::new();
    for record in records {
        let key = match record.stage {
            bw_model::V32TaxonomyStage::BuildPrecheck => "build_precheck",
            bw_model::V32TaxonomyStage::BoundaryIndex => "boundary_index",
            bw_model::V32TaxonomyStage::CandidatePartition => "candidate_partition",
            bw_model::V32TaxonomyStage::LifecycleRanking => "lifecycle_ranking",
            bw_model::V32TaxonomyStage::DynamicPrep => "dynamic_prep",
        };
        *counts.entry(key).or_default() += 1;
    }
    counts
}

fn write_checksums(files: &[(&str, &Path)], checksums_path: &Path) -> Result<(), CliError> {
    let mut lines = Vec::<String>::new();
    for (relative, path) in files {
        lines.push(format!("{}  {relative}", sha256_file(path)?));
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
