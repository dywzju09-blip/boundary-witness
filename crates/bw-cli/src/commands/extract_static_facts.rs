use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsStr,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use bw_model::{
    StaticFactEnvelope, V32CorpusIntakeStatus, V32CorpusManifestRecord, V32CorpusSourceKind,
    validate_v3_2_corpus_manifest,
};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl, write_json_stdout},
    exit::{CliError, CommandStatus},
};

const STATIC_EXTRACTION_STATUS_SCHEMA_V1: &str = "v3.2.static_fact_extraction_status.1";
const STATIC_FEATURE_PROFILE_SCHEMA_V1: &str = "v3.2.static_feature_profile.1";
const PUBLIC_FORBIDDEN_TOKENS: [&str; 9] = [
    "vulnerable",
    "fixed",
    "cve",
    "ghsa",
    "expected",
    "patch",
    "advisory",
    "poc",
    "exploit",
];
const STATIC_EXTRACTION_COMPAT_RUSTFLAGS: &str =
    "-A useless_deprecated -A dangerous_implicit_autorefs -A bindings_with_variant_name";

#[derive(Args)]
pub struct ExtractStaticFactsArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long = "logs-root")]
    logs_root: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long = "rustc-wrapper")]
    rustc_wrapper: PathBuf,
    #[arg(long)]
    rustc: Option<PathBuf>,
    #[arg(long)]
    python: Option<PathBuf>,
    #[arg(long, default_value = "cargo")]
    cargo: PathBuf,
    #[arg(long)]
    locked: bool,
    #[arg(long = "feature-profile")]
    feature_profile: Option<PathBuf>,
    #[arg(long = "all-features")]
    all_features: bool,
    #[arg(long = "no-default-features")]
    no_default_features: bool,
    #[arg(long, value_delimiter = ',')]
    features: Vec<String>,
    #[arg(long)]
    timeout_seconds: Option<u64>,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

#[derive(Serialize)]
struct ExtractStaticFactsOutput {
    kind: &'static str,
    run_id: String,
    record_count: u64,
    analyzed_count: u64,
    skipped_count: u64,
    failed_count: u64,
    fact_count: u64,
    output_dir: String,
    static_facts_path: String,
    mir_coverage_path: String,
    status_path: String,
    stats_path: String,
    checksums_path: String,
}

#[derive(Clone, Serialize)]
struct StaticExtractionStatusRecord {
    schema_version: &'static str,
    run_id: String,
    crate_id: String,
    crate_name: String,
    version: String,
    status: StaticExtractionStatus,
    target_count: u64,
    elapsed_ms: u64,
    log_ref: String,
    failure_class: Option<String>,
    notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StaticExtractionStatus {
    Analyzed,
    Skipped,
    NotBuildable,
    ToolError,
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    manifest_path: PathBuf,
    #[serde(default)]
    targets: Vec<CargoTarget>,
}

#[derive(Deserialize)]
struct CargoTarget {
    name: String,
    #[serde(default)]
    kind: Vec<String>,
    #[serde(default)]
    src_path: PathBuf,
}

#[derive(Clone, Debug, Default)]
struct CargoFeatureSelection {
    all_features: bool,
    no_default_features: bool,
    features: Vec<String>,
}

impl CargoFeatureSelection {
    fn is_default(&self) -> bool {
        !self.all_features && !self.no_default_features && self.features.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticFeatureProfileRecord {
    schema_version: String,
    crate_id: String,
    crate_name: String,
    version: String,
    #[serde(default)]
    all_features: bool,
    #[serde(default)]
    no_default_features: bool,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    source_refs: Vec<String>,
    #[serde(default)]
    notes: Vec<String>,
}

#[derive(Serialize)]
struct RustcWrapperConfig<'a> {
    output_dir: &'a Path,
    metadata_path: &'a Path,
    allowlist: Vec<RustcAllowlistEntry>,
}

#[derive(Clone, Serialize)]
struct RustcAllowlistEntry {
    crate_name: String,
    crate_id: String,
    package_name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
struct CoveragePackage {
    name: String,
    version: String,
}

#[derive(Serialize)]
struct EmptyMirCoverage {
    schema_version: &'static str,
    expected_packages: Vec<CoveragePackage>,
    seen_packages: Vec<CoveragePackage>,
    seen_targets: Vec<serde_json::Value>,
    seen_bodies: Vec<serde_json::Value>,
    skipped: Vec<serde_json::Value>,
}

pub fn run(args: ExtractStaticFactsArgs) -> Result<CommandStatus, CliError> {
    if args.run_id.trim().is_empty() {
        return Err(CliError::input(
            "BW-V32-STATIC-FACT-RUN-ID",
            "run_id 不能为空",
        ));
    }
    validate_feature_args(&args)?;
    if !args.rustc_wrapper.is_file() {
        return Err(CliError::input(
            "BW-V32-STATIC-FACT-WRAPPER",
            format!("rustc-wrapper 不存在: {}", args.rustc_wrapper.display()),
        ));
    }
    if let Some(python) = &args.python
        && !python.is_file()
    {
        return Err(CliError::input(
            "BW-V32-STATIC-FACT-PYTHON",
            format!("python 不存在: {}", python.display()),
        ));
    }

    let manifest_records =
        read_jsonl::<V32CorpusManifestRecord>(&args.manifest, args.max_line_bytes)?;
    validate_v3_2_corpus_manifest(manifest_records.clone())?;
    let feature_profiles = load_feature_profiles(&args, &manifest_records)?;

    fs::create_dir_all(&args.output_dir)?;
    fs::create_dir_all(&args.logs_root)?;
    fs::create_dir_all(args.output_dir.join("metadata"))?;
    fs::create_dir_all(args.output_dir.join("rustc-configs"))?;
    let rustc_private_lib_dirs = rustc_private_library_dirs(&args);
    preflight_rustc_wrapper(&args, &rustc_private_lib_dirs)?;

    let manifest_dir = args.manifest.parent().unwrap_or_else(|| Path::new("."));
    let mut status_records = Vec::<StaticExtractionStatusRecord>::new();
    let mut expected_packages = BTreeSet::<CoveragePackage>::new();

    for located in manifest_records {
        let status = extract_one(
            &args,
            manifest_dir,
            &located.value,
            &feature_profiles,
            &mut expected_packages,
            &rustc_private_lib_dirs,
        )?;
        status_records.push(status);
    }

    let static_facts_path = args.output_dir.join("static-facts.jsonl");
    let static_manifest_path = args.output_dir.join("static-facts.manifest.json");
    let mir_coverage_path = args.output_dir.join("mir-coverage.json");
    ensure_static_outputs(
        &static_facts_path,
        &static_manifest_path,
        &mir_coverage_path,
        expected_packages.into_iter().collect(),
    )?;

    let static_facts = read_jsonl::<StaticFactEnvelope>(&static_facts_path, args.max_line_bytes)?;

    let status_path = args.output_dir.join("static-extraction-status.jsonl");
    write_jsonl_records(&status_path, &status_records)?;

    let analyzed_count = status_records
        .iter()
        .filter(|record| record.status == StaticExtractionStatus::Analyzed)
        .count() as u64;
    let skipped_count = status_records
        .iter()
        .filter(|record| record.status == StaticExtractionStatus::Skipped)
        .count() as u64;
    let failed_count = status_records
        .iter()
        .filter(|record| {
            matches!(
                record.status,
                StaticExtractionStatus::NotBuildable | StaticExtractionStatus::ToolError
            )
        })
        .count() as u64;

    let stats_path = args.output_dir.join("static-extraction-stats.json");
    let stats = serde_json::json!({
        "schema_version": "v3.2.static_fact_extraction_stats.1",
        "run_id": args.run_id,
        "record_count": status_records.len(),
        "analyzed_count": analyzed_count,
        "skipped_count": skipped_count,
        "failed_count": failed_count,
        "fact_count": static_facts.len(),
        "notes": [
            "static facts are compiler observations, not vulnerability conclusions",
            "candidate risk decisions must be derived in later lifecycle stages"
        ],
    });
    write_json_file(&stats_path, &stats)?;

    let checksums_path = args.output_dir.join("checksums.sha256");
    write_checksums(
        &args.output_dir,
        &[
            "static-facts.jsonl",
            "static-facts.manifest.json",
            "mir-coverage.json",
            "static-extraction-status.jsonl",
            "static-extraction-stats.json",
        ],
        &checksums_path,
    )?;

    let summary = ExtractStaticFactsOutput {
        kind: "v3-2-static-fact-extraction",
        run_id: args.run_id,
        record_count: status_records.len() as u64,
        analyzed_count,
        skipped_count,
        failed_count,
        fact_count: static_facts.len() as u64,
        output_dir: args.output_dir.display().to_string(),
        static_facts_path: static_facts_path.display().to_string(),
        mir_coverage_path: mir_coverage_path.display().to_string(),
        status_path: status_path.display().to_string(),
        stats_path: stats_path.display().to_string(),
        checksums_path: checksums_path.display().to_string(),
    };
    write_json_stdout(&summary)?;
    Ok(CommandStatus::Success)
}

fn extract_one(
    args: &ExtractStaticFactsArgs,
    manifest_dir: &Path,
    record: &V32CorpusManifestRecord,
    feature_profiles: &BTreeMap<String, CargoFeatureSelection>,
    expected_packages: &mut BTreeSet<CoveragePackage>,
    rustc_private_lib_dirs: &[PathBuf],
) -> Result<StaticExtractionStatusRecord, CliError> {
    let log_ref = format!("static-facts/{}.log", sanitize_file_stem(&record.crate_id));
    let log_path = args.logs_root.join(&log_ref);
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }

    if record.intake_status == V32CorpusIntakeStatus::Excluded {
        write_log(
            &log_path,
            "skipped by corpus intake",
            "",
            &record.intake_notes.join("\n"),
        )?;
        return Ok(status_record(
            args,
            record,
            StaticExtractionOutcome {
                status: StaticExtractionStatus::Skipped,
                target_count: 0,
                elapsed_ms: 0,
                log_ref,
                failure_class: Some("excluded_by_intake"),
                notes: record.intake_notes.clone(),
            },
        ));
    }

    let source_path = match resolve_local_source(manifest_dir, record) {
        Ok(path) => path,
        Err(failure_class) => {
            write_log(&log_path, "source resolution failed", "", failure_class)?;
            return Ok(status_record(
                args,
                record,
                StaticExtractionOutcome {
                    status: StaticExtractionStatus::Skipped,
                    target_count: 0,
                    elapsed_ms: 0,
                    log_ref,
                    failure_class: Some(failure_class),
                    notes: vec!["source was not materialized locally".to_owned()],
                },
            ));
        }
    };

    let cargo_toml = source_path.join("Cargo.toml");
    if !cargo_toml.is_file() {
        write_log(
            &log_path,
            "Cargo.toml missing",
            "",
            &cargo_toml.display().to_string(),
        )?;
        return Ok(status_record(
            args,
            record,
            StaticExtractionOutcome {
                status: StaticExtractionStatus::ToolError,
                target_count: 0,
                elapsed_ms: 0,
                log_ref,
                failure_class: Some("manifest_missing"),
                notes: vec!["local source did not contain Cargo.toml".to_owned()],
            },
        ));
    }

    let metadata_path = args
        .output_dir
        .join("metadata")
        .join(format!("{}.json", sanitize_file_stem(&record.crate_id)));
    let feature_selection = feature_profiles
        .get(&record.crate_id)
        .cloned()
        .unwrap_or_else(|| global_feature_selection(args));
    let metadata_command = cargo_metadata_command(args, &cargo_toml, &feature_selection);
    let metadata_command_for_log = format!("{metadata_command:?}");
    let metadata_result = run_process(metadata_command, args.timeout_seconds)?;
    let (metadata_stdout, mut log_output, metadata_elapsed_ms) = match metadata_result {
        ProcessResult::Completed {
            status,
            stdout,
            stderr,
            elapsed_ms,
        } => {
            if !status.success() {
                write_log(&log_path, &metadata_command_for_log, &stdout, &stderr)?;
                return Ok(status_record(
                    args,
                    record,
                    StaticExtractionOutcome {
                        status: StaticExtractionStatus::ToolError,
                        target_count: 0,
                        elapsed_ms,
                        log_ref,
                        failure_class: Some("cargo_metadata_failed"),
                        notes: vec!["cargo metadata did not complete successfully".to_owned()],
                    },
                ));
            }
            (
                stdout,
                format!(
                    "metadata command: {metadata_command_for_log}\n\nmetadata stderr:\n{stderr}\n"
                ),
                elapsed_ms,
            )
        }
        ProcessResult::TimedOut {
            stdout,
            stderr,
            elapsed_ms,
        } => {
            write_log(&log_path, &metadata_command_for_log, &stdout, &stderr)?;
            return Ok(status_record(
                args,
                record,
                StaticExtractionOutcome {
                    status: StaticExtractionStatus::ToolError,
                    target_count: 0,
                    elapsed_ms,
                    log_ref,
                    failure_class: Some("cargo_metadata_timeout"),
                    notes: vec!["cargo metadata exceeded timeout_seconds".to_owned()],
                },
            ));
        }
    };
    fs::write(&metadata_path, metadata_stdout.as_bytes())?;
    let metadata: CargoMetadata = serde_json::from_str(&metadata_stdout).map_err(|error| {
        CliError::input(
            "BW-V32-STATIC-FACT-METADATA",
            format!("{}: {}", metadata_path.display(), error),
        )
    })?;
    let Some(package) = select_manifest_package(&metadata, record, &cargo_toml) else {
        write_log(
            &log_path,
            &metadata_command_for_log,
            &metadata_stdout,
            "manifest package was not found in cargo metadata",
        )?;
        return Ok(status_record(
            args,
            record,
            StaticExtractionOutcome {
                status: StaticExtractionStatus::ToolError,
                target_count: 0,
                elapsed_ms: metadata_elapsed_ms,
                log_ref,
                failure_class: Some("metadata_package_missing"),
                notes: vec!["cargo metadata did not include the manifest package".to_owned()],
            },
        ));
    };

    expected_packages.insert(CoveragePackage {
        name: package.name.clone(),
        version: package.version.clone(),
    });

    let allowlist = allowlist_for_package(record, package);
    if allowlist.is_empty() {
        write_log(
            &log_path,
            &metadata_command_for_log,
            &metadata_stdout,
            "no lib/bin targets were selected for static fact extraction",
        )?;
        return Ok(status_record(
            args,
            record,
            StaticExtractionOutcome {
                status: StaticExtractionStatus::Skipped,
                target_count: 0,
                elapsed_ms: metadata_elapsed_ms,
                log_ref,
                failure_class: Some("no_extractable_targets"),
                notes: vec!["no root lib/bin target was available for wrapper analysis".to_owned()],
            },
        ));
    }

    let config_path = args
        .output_dir
        .join("rustc-configs")
        .join(format!("{}.json", sanitize_file_stem(&record.crate_id)));
    let config = RustcWrapperConfig {
        output_dir: &args.output_dir,
        metadata_path: &metadata_path,
        allowlist: allowlist.clone(),
    };
    write_json_file(&config_path, &config)?;

    let mut check_command = Command::new(&args.cargo);
    check_command
        .arg("check")
        .arg("--manifest-path")
        .arg(&cargo_toml)
        .arg("--quiet")
        .env("RUSTC_WRAPPER", &args.rustc_wrapper)
        .env("BW_RUSTC_CONFIG", &config_path)
        .env("BW_STATIC_EXTRACT_OUTPUT_DIR", &args.output_dir)
        .env(
            "CARGO_TARGET_DIR",
            args.output_dir
                .join("targets")
                .join(sanitize_file_stem(&record.crate_id)),
        )
        .env("CARGO_INCREMENTAL", "0");
    apply_cargo_feature_args(&mut check_command, &feature_selection);
    if let Some(rustc) = &args.rustc {
        check_command.env("RUSTC", rustc);
    }
    if let Some(python) = &args.python {
        check_command
            .env("PYTHON", python)
            .env("npm_config_python", python);
    }
    apply_static_extraction_rustflags(&mut check_command);
    apply_dynamic_library_path_env(&mut check_command, rustc_private_lib_dirs);
    if args.locked {
        check_command.arg("--locked");
    }
    let check_command_for_log = format!("{check_command:?}");
    let check_result = run_process(check_command, args.timeout_seconds)?;
    match check_result {
        ProcessResult::Completed {
            status,
            stdout,
            stderr,
            elapsed_ms,
        } => {
            log_output.push_str(&format!(
                "\ncheck command: {check_command_for_log}\n\ncheck stdout:\n{stdout}\n\ncheck stderr:\n{stderr}\n"
            ));
            write_log(&log_path, "extract-static-facts", &log_output, "")?;
            if status.success() {
                Ok(status_record(
                    args,
                    record,
                    StaticExtractionOutcome {
                        status: StaticExtractionStatus::Analyzed,
                        target_count: allowlist.len() as u64,
                        elapsed_ms: metadata_elapsed_ms + elapsed_ms,
                        log_ref,
                        failure_class: None,
                        notes: vec![static_extraction_note(&feature_selection)],
                    },
                ))
            } else {
                Ok(status_record(
                    args,
                    record,
                    StaticExtractionOutcome {
                        status: StaticExtractionStatus::NotBuildable,
                        target_count: allowlist.len() as u64,
                        elapsed_ms: metadata_elapsed_ms + elapsed_ms,
                        log_ref,
                        failure_class: Some(classify_cargo_failure(&stderr)),
                        notes: vec!["cargo check failed under static fact extraction".to_owned()],
                    },
                ))
            }
        }
        ProcessResult::TimedOut {
            stdout,
            stderr,
            elapsed_ms,
        } => {
            log_output.push_str(&format!(
                "\ncheck command: {check_command_for_log}\n\ncheck stdout:\n{stdout}\n\ncheck stderr:\n{stderr}\n"
            ));
            write_log(&log_path, "extract-static-facts timeout", &log_output, "")?;
            Ok(status_record(
                args,
                record,
                StaticExtractionOutcome {
                    status: StaticExtractionStatus::ToolError,
                    target_count: allowlist.len() as u64,
                    elapsed_ms: metadata_elapsed_ms + elapsed_ms,
                    log_ref,
                    failure_class: Some("cargo_check_timeout"),
                    notes: vec!["cargo check exceeded timeout_seconds".to_owned()],
                },
            ))
        }
    }
}

fn cargo_metadata_command(
    args: &ExtractStaticFactsArgs,
    cargo_toml: &Path,
    feature_selection: &CargoFeatureSelection,
) -> Command {
    let mut command = Command::new(&args.cargo);
    command
        .arg("metadata")
        .arg("--format-version=1")
        .arg("--no-deps")
        .arg("--manifest-path")
        .arg(cargo_toml);
    apply_cargo_feature_args(&mut command, feature_selection);
    if args.locked {
        command.arg("--locked");
    }
    command
}

fn validate_feature_args(args: &ExtractStaticFactsArgs) -> Result<(), CliError> {
    if args.feature_profile.is_some()
        && (args.all_features || args.no_default_features || !args.features.is_empty())
    {
        return Err(CliError::input(
            "BW-V32-STATIC-FACT-FEATURES",
            "--feature-profile 不能与全局 --all-features、--no-default-features 或 --features 同时使用",
        ));
    }
    if args.all_features && !args.features.is_empty() {
        return Err(CliError::input(
            "BW-V32-STATIC-FACT-FEATURES",
            "--all-features 不能与 --features 同时使用",
        ));
    }
    if let Some(feature) = args
        .features
        .iter()
        .find(|feature| feature.trim().is_empty())
    {
        return Err(CliError::input(
            "BW-V32-STATIC-FACT-FEATURES",
            format!("feature 名称不能为空: {feature:?}"),
        ));
    }
    Ok(())
}

fn global_feature_selection(args: &ExtractStaticFactsArgs) -> CargoFeatureSelection {
    CargoFeatureSelection {
        all_features: args.all_features,
        no_default_features: args.no_default_features,
        features: args.features.clone(),
    }
}

fn apply_cargo_feature_args(command: &mut Command, selection: &CargoFeatureSelection) {
    if selection.all_features {
        command.arg("--all-features");
    }
    if selection.no_default_features {
        command.arg("--no-default-features");
    }
    if !selection.features.is_empty() {
        command.arg("--features").arg(selection.features.join(","));
    }
}

fn load_feature_profiles(
    args: &ExtractStaticFactsArgs,
    manifest_records: &[bw_model::Located<V32CorpusManifestRecord>],
) -> Result<BTreeMap<String, CargoFeatureSelection>, CliError> {
    let Some(path) = &args.feature_profile else {
        return Ok(BTreeMap::new());
    };

    let manifest_index = manifest_records
        .iter()
        .map(|located| {
            (
                located.value.crate_id.clone(),
                (
                    located.value.crate_name.clone(),
                    located.value.version.clone(),
                    located.value.intake_status,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let records = read_jsonl::<StaticFeatureProfileRecord>(path, args.max_line_bytes)?;
    let mut profiles = BTreeMap::<String, CargoFeatureSelection>::new();

    for located in records {
        validate_feature_profile_record(&located.value, &manifest_index, located.line)?;
        let selection = CargoFeatureSelection {
            all_features: located.value.all_features,
            no_default_features: located.value.no_default_features,
            features: located.value.features.clone(),
        };
        if profiles
            .insert(located.value.crate_id.clone(), selection)
            .is_some()
        {
            return Err(feature_profile_error(
                located.line,
                format!(
                    "crate_id {} 在 feature profile 中重复",
                    located.value.crate_id
                ),
            ));
        }
    }

    Ok(profiles)
}

fn validate_feature_profile_record(
    record: &StaticFeatureProfileRecord,
    manifest_index: &BTreeMap<String, (String, String, V32CorpusIntakeStatus)>,
    line: usize,
) -> Result<(), CliError> {
    if record.schema_version != STATIC_FEATURE_PROFILE_SCHEMA_V1 {
        return Err(feature_profile_error(
            line,
            format!(
                "schema_version 必须是 {STATIC_FEATURE_PROFILE_SCHEMA_V1}，实际为 {}",
                record.schema_version
            ),
        ));
    }
    validate_feature_profile_text(line, "crate_id", &record.crate_id)?;
    validate_feature_profile_text(line, "crate_name", &record.crate_name)?;
    validate_feature_profile_text(line, "version", &record.version)?;
    if record.all_features && !record.features.is_empty() {
        return Err(feature_profile_error(
            line,
            "--all-features 语义不能与显式 features 同时出现在同一 profile 记录",
        ));
    }
    let mut seen_features = BTreeSet::<&str>::new();
    for feature in &record.features {
        validate_feature_profile_text(line, "features", feature)?;
        if feature.trim() != feature {
            return Err(feature_profile_error(
                line,
                format!("feature 名称不能包含首尾空白: {feature:?}"),
            ));
        }
        if !seen_features.insert(feature.as_str()) {
            return Err(feature_profile_error(
                line,
                format!("feature 名称 {feature:?} 重复"),
            ));
        }
    }
    if record.source_refs.is_empty() {
        return Err(feature_profile_error(
            line,
            "feature profile 记录必须提供 source_refs 说明配置来源",
        ));
    }
    for source_ref in &record.source_refs {
        validate_feature_profile_text(line, "source_refs", source_ref)?;
    }
    for note in &record.notes {
        validate_feature_profile_text(line, "notes", note)?;
    }

    let Some((crate_name, version, intake_status)) = manifest_index.get(&record.crate_id) else {
        return Err(feature_profile_error(
            line,
            format!(
                "feature profile 引用了 corpus manifest 中不存在的 crate_id {}",
                record.crate_id
            ),
        ));
    };
    if crate_name != &record.crate_name || version != &record.version {
        return Err(feature_profile_error(
            line,
            format!(
                "feature profile identity 与 corpus manifest 不一致: {} {} vs {} {}",
                record.crate_name, record.version, crate_name, version
            ),
        ));
    }
    if *intake_status == V32CorpusIntakeStatus::Excluded {
        return Err(feature_profile_error(
            line,
            format!(
                "excluded crate {} 不应配置 static feature profile",
                record.crate_id
            ),
        ));
    }

    Ok(())
}

fn validate_feature_profile_text(
    line: usize,
    field: &'static str,
    value: &str,
) -> Result<(), CliError> {
    if value.trim().is_empty() {
        return Err(feature_profile_error(line, format!("{field} 不能为空")));
    }
    reject_public_forbidden_token(field, value)
        .map_err(|message| feature_profile_error(line, message))
}

fn reject_public_forbidden_token(field: &'static str, value: &str) -> Result<(), String> {
    let lower = value.to_ascii_lowercase();
    if let Some(token) = PUBLIC_FORBIDDEN_TOKENS
        .iter()
        .find(|token| lower.contains(*token))
    {
        return Err(format!(
            "{field} 包含 V3.2 public artifact 禁止公开携带的身份线索 token `{token}`"
        ));
    }
    Ok(())
}

fn feature_profile_error(line: usize, message: impl Into<String>) -> CliError {
    CliError::input(
        "BW-V32-STATIC-FACT-FEATURE-PROFILE",
        format!("feature profile 第 {line} 行: {}", message.into()),
    )
}

fn static_extraction_note(selection: &CargoFeatureSelection) -> String {
    if selection.is_default() {
        "compiler wrapper finished; facts are static evidence only".to_owned()
    } else {
        "compiler wrapper finished with crate-scoped feature profile; facts are static evidence only"
            .to_owned()
    }
}

fn preflight_rustc_wrapper(
    args: &ExtractStaticFactsArgs,
    rustc_private_lib_dirs: &[PathBuf],
) -> Result<(), CliError> {
    let rustc = selected_rustc(args);
    let mut command = Command::new(&args.rustc_wrapper);
    command
        .arg(rustc)
        .arg("-vV")
        .env("BW_STATIC_EXTRACT_OUTPUT_DIR", &args.output_dir);
    apply_dynamic_library_path_env(&mut command, rustc_private_lib_dirs);
    let output = command.output().map_err(|error| {
        CliError::input(
            "BW-V32-STATIC-FACT-WRAPPER-PROBE",
            format!("rustc-wrapper 预检无法启动: {error}"),
        )
    })?;
    if output.status.success() {
        return Ok(());
    }

    Err(CliError::input(
        "BW-V32-STATIC-FACT-WRAPPER-PROBE",
        format!(
            "rustc-wrapper 预检失败: status={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ),
    ))
}

fn rustc_private_library_dirs(args: &ExtractStaticFactsArgs) -> Vec<PathBuf> {
    let rustc = selected_rustc(args);
    let mut dirs = BTreeSet::<PathBuf>::new();
    if let Some(sysroot) = rustc_print(&rustc, "sysroot") {
        dirs.insert(PathBuf::from(sysroot).join("lib"));
    }
    if let Some(target_libdir) = rustc_print(&rustc, "target-libdir") {
        dirs.insert(PathBuf::from(target_libdir));
    }
    dirs.into_iter().filter(|path| path.is_dir()).collect()
}

fn selected_rustc(args: &ExtractStaticFactsArgs) -> std::ffi::OsString {
    args.rustc
        .as_ref()
        .map(|path| path.as_os_str().to_owned())
        .or_else(|| env::var_os("RUSTC"))
        .unwrap_or_else(|| "rustc".into())
}

fn rustc_print(rustc: &OsStr, name: &str) -> Option<String> {
    let output = Command::new(rustc).arg("--print").arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn apply_dynamic_library_path_env(command: &mut Command, extra_dirs: &[PathBuf]) {
    if extra_dirs.is_empty() {
        return;
    }
    for key in [
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "LD_LIBRARY_PATH",
    ] {
        let mut paths = extra_dirs.to_vec();
        if let Some(existing) = env::var_os(key) {
            paths.extend(env::split_paths(&existing));
        }
        if let Ok(joined) = env::join_paths(paths) {
            command.env(key, joined);
        }
    }
}

fn apply_static_extraction_rustflags(command: &mut Command) {
    let existing = env::var("RUSTFLAGS").unwrap_or_default();
    let trimmed = existing.trim();
    let rustflags = if trimmed.is_empty() {
        STATIC_EXTRACTION_COMPAT_RUSTFLAGS.to_owned()
    } else if trimmed.contains(STATIC_EXTRACTION_COMPAT_RUSTFLAGS) {
        trimmed.to_owned()
    } else {
        format!("{trimmed} {STATIC_EXTRACTION_COMPAT_RUSTFLAGS}")
    };
    command.env("RUSTFLAGS", rustflags);
}

fn select_manifest_package<'a>(
    metadata: &'a CargoMetadata,
    record: &V32CorpusManifestRecord,
    cargo_toml: &Path,
) -> Option<&'a CargoPackage> {
    metadata
        .packages
        .iter()
        .find(|package| package.name == record.crate_name && package.version == record.version)
        .or_else(|| {
            metadata
                .packages
                .iter()
                .find(|package| same_path(&package.manifest_path, cargo_toml))
        })
}

fn allowlist_for_package(
    record: &V32CorpusManifestRecord,
    package: &CargoPackage,
) -> Vec<RustcAllowlistEntry> {
    let mut crate_names = BTreeSet::<String>::new();
    for target in &package.targets {
        if target.src_path.as_os_str().is_empty() {
            continue;
        }
        if target
            .kind
            .iter()
            .any(|kind| matches!(kind.as_str(), "lib" | "bin"))
        {
            crate_names.insert(rust_crate_name(&target.name));
        }
    }
    crate_names
        .into_iter()
        .map(|crate_name| RustcAllowlistEntry {
            crate_name,
            crate_id: record.crate_id.clone(),
            package_name: package.name.clone(),
            version: package.version.clone(),
            target: None,
        })
        .collect()
}

fn same_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn rust_crate_name(value: &str) -> String {
    value.replace('-', "_")
}

fn ensure_static_outputs(
    static_facts_path: &Path,
    static_manifest_path: &Path,
    mir_coverage_path: &Path,
    expected_packages: Vec<CoveragePackage>,
) -> Result<(), CliError> {
    if !static_facts_path.exists() {
        fs::write(static_facts_path, "")?;
    }
    if !static_manifest_path.exists() {
        write_json_file(
            static_manifest_path,
            &serde_json::json!({
                "schema_version": "bw.static-facts.manifest/0.1",
                "shards": [],
            }),
        )?;
    }
    if !mir_coverage_path.exists() {
        let coverage = EmptyMirCoverage {
            schema_version: "bw.mir-coverage/0.1",
            expected_packages,
            seen_packages: Vec::new(),
            seen_targets: Vec::new(),
            seen_bodies: Vec::new(),
            skipped: Vec::new(),
        };
        write_json_file(mir_coverage_path, &coverage)?;
    }
    Ok(())
}

struct StaticExtractionOutcome {
    status: StaticExtractionStatus,
    target_count: u64,
    elapsed_ms: u64,
    log_ref: String,
    failure_class: Option<&'static str>,
    notes: Vec<String>,
}

fn status_record(
    args: &ExtractStaticFactsArgs,
    record: &V32CorpusManifestRecord,
    outcome: StaticExtractionOutcome,
) -> StaticExtractionStatusRecord {
    StaticExtractionStatusRecord {
        schema_version: STATIC_EXTRACTION_STATUS_SCHEMA_V1,
        run_id: args.run_id.clone(),
        crate_id: record.crate_id.clone(),
        crate_name: record.crate_name.clone(),
        version: record.version.clone(),
        status: outcome.status,
        target_count: outcome.target_count,
        elapsed_ms: outcome.elapsed_ms,
        log_ref: outcome.log_ref,
        failure_class: outcome.failure_class.map(str::to_owned),
        notes: outcome.notes,
    }
}

fn resolve_local_source(
    manifest_dir: &Path,
    record: &V32CorpusManifestRecord,
) -> Result<PathBuf, &'static str> {
    match record.source_kind {
        V32CorpusSourceKind::LocalArchive | V32CorpusSourceKind::RegistrySnapshot => {
            let path = PathBuf::from(&record.source_ref);
            if path.is_absolute() {
                Ok(path)
            } else {
                Ok(manifest_dir.join(path))
            }
        }
        V32CorpusSourceKind::CratesIo | V32CorpusSourceKind::GitArchive => {
            Err("source_not_materialized")
        }
    }
}

enum ProcessResult {
    Completed {
        status: ExitStatus,
        stdout: String,
        stderr: String,
        elapsed_ms: u64,
    },
    TimedOut {
        stdout: String,
        stderr: String,
        elapsed_ms: u64,
    },
}

fn run_process(
    mut command: Command,
    timeout_seconds: Option<u64>,
) -> Result<ProcessResult, std::io::Error> {
    let start = Instant::now();
    let timeout = timeout_seconds
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs);
    let Some(timeout) = timeout else {
        let output = command.output()?;
        return Ok(ProcessResult::Completed {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            elapsed_ms: start.elapsed().as_millis() as u64,
        });
    };

    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().map(read_child_pipe_in_thread);
    let stderr = child.stderr.take().map(read_child_pipe_in_thread);
    loop {
        if let Some(status) = child.try_wait()? {
            let stdout = join_child_pipe(stdout)?;
            let stderr = join_child_pipe(stderr)?;
            return Ok(ProcessResult::Completed {
                status,
                stdout,
                stderr,
                elapsed_ms: start.elapsed().as_millis() as u64,
            });
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let stdout = join_child_pipe(stdout)?;
            let stderr = join_child_pipe(stderr)?;
            return Ok(ProcessResult::TimedOut {
                stdout,
                stderr,
                elapsed_ms: start.elapsed().as_millis() as u64,
            });
        }

        thread::sleep(Duration::from_millis(50));
    }
}

fn read_child_pipe_in_thread<T>(mut pipe: T) -> JoinHandle<Result<String, std::io::Error>>
where
    T: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut output = Vec::new();
        pipe.read_to_end(&mut output)?;
        Ok(String::from_utf8_lossy(&output).into_owned())
    })
}

fn join_child_pipe(
    handle: Option<JoinHandle<Result<String, std::io::Error>>>,
) -> Result<String, std::io::Error> {
    let Some(handle) = handle else {
        return Ok(String::new());
    };
    handle
        .join()
        .map_err(|_| std::io::Error::other("cargo output reader thread panicked"))?
}

fn classify_cargo_failure(stderr: &str) -> &'static str {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("could not find system library")
        || lower.contains("pkg-config")
        || lower.contains("system dependency")
        || lower.contains("linker")
    {
        "requires_system_dependency"
    } else if lower.contains("could not find specification for target")
        || lower.contains("target may not be installed")
    {
        "unsupported_target"
    } else {
        "cargo_check_failed"
    }
}

fn write_jsonl_records<T>(path: &Path, records: &[T]) -> Result<(), CliError>
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    for record in records {
        serde_json::to_writer(&mut file, record)
            .map_err(|error| CliError::internal(error.to_string()))?;
        file.write_all(b"\n")?;
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

fn write_log(path: &Path, command: &str, stdout: &str, stderr: &str) -> Result<(), CliError> {
    let mut file = File::create(path)?;
    writeln!(file, "command: {command}")?;
    writeln!(file, "\nstdout:\n{stdout}")?;
    writeln!(file, "\nstderr:\n{stderr}")?;
    Ok(())
}

fn write_checksums(
    output_dir: &Path,
    relatives: &[&str],
    checksums_path: &Path,
) -> Result<(), CliError> {
    let mut lines = Vec::<String>::new();
    for relative in relatives {
        lines.push(format!(
            "{}  {relative}",
            sha256_file(&output_dir.join(relative))?
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

fn sanitize_file_stem(value: &str) -> String {
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
