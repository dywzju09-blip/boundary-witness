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
    commands::{
        DEFAULT_MAX_LINE_BYTES, hex_digest, read_jsonl, write_json_file, write_json_stdout,
    },
    exit::{CliError, CommandStatus},
};

const STATIC_EXTRACTION_STATUS_SCHEMA_V1: &str = "v3.2.static_fact_extraction_status.1";
const STATIC_FEATURE_PROFILE_SCHEMA_V1: &str = "v3.2.static_feature_profile.1";
const RESOLVED_DEPENDENCIES_SCHEMA_V1: &str = "v3.2.resolved_dependencies.1";
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

/// 跨 crate 摘要的前提。
///
/// rustc 默认只为泛型和 `#[inline]` 函数把 MIR 编码进 rlib，普通的 `pub fn` 不编码。
/// 而注册往往包在依赖 crate 的一层薄封装里（`fn install(cb, data) { conn.update_hook(..) }`），
/// 拿不到那层的函数体就看不穿它，整条注册链在这里断掉。代价是 rlib 变大、构建变慢，
/// 只在静态抽取这一步施加，且只在 nightly 上——见 [`cross_crate_mir_available`]。
const CROSS_CRATE_MIR_RUSTFLAG: &str = "-Zalways-encode-mir";

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
    resolved_dependencies_path: String,
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
    /// 锁文件所在目录。metadata 用 `--no-deps` 跑，因此依赖解析结果只能从锁文件读。
    #[serde(default)]
    workspace_root: PathBuf,
}

/// 一个被扫 crate 解析到的依赖版本。
///
/// witness plan 要知道注册 API 由哪个 crate 的哪个版本提供，才能生成能编译的 harness。
/// 被扫 crate 自己的版本回答不了这个问题：扫任意 crate 找第三方 API 误用时，提供方
/// 是另一个 crate。这里只记录解析结果，不判断哪个依赖跟合约有关——那是 plan 阶段
/// 拿 API map 去比对的事。
#[derive(Serialize)]
struct ResolvedDependenciesRecord {
    schema_version: &'static str,
    run_id: String,
    crate_id: String,
    packages: Vec<CoveragePackage>,
    notes: Vec<String>,
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
    let cross_crate_mir = cross_crate_mir_available(&args);

    let manifest_dir = args.manifest.parent().unwrap_or_else(|| Path::new("."));
    let mut status_records = Vec::<StaticExtractionStatusRecord>::new();
    let mut expected_packages = BTreeSet::<CoveragePackage>::new();
    let mut resolved_dependencies = Vec::<ResolvedDependenciesRecord>::new();

    for located in manifest_records {
        let status = extract_one(
            &args,
            manifest_dir,
            &located.value,
            &feature_profiles,
            &mut expected_packages,
            &mut resolved_dependencies,
            &rustc_private_lib_dirs,
            cross_crate_mir,
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

    let resolved_dependencies_path = args.output_dir.join("resolved-dependencies.jsonl");
    write_jsonl_records(&resolved_dependencies_path, &resolved_dependencies)?;

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
        // 跨 crate MIR 的有无直接决定覆盖面，必须留在产物里：没有它时分析照跑，
        // 但看不穿依赖里的注册封装，"没扫到"里混着"没看见"。两种运行不可比较。
        "cross_crate_mir": cross_crate_mir,
        "notes": [
            "static facts are compiler observations, not vulnerability conclusions",
            "candidate risk decisions must be derived in later lifecycle stages",
            if cross_crate_mir {
                "dependencies were compiled with MIR, so registrations wrapped in a dependency are visible"
            } else {
                "dependencies carry no MIR on this toolchain: registrations wrapped in a dependency are invisible to this run"
            }
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
            "resolved-dependencies.jsonl",
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
        resolved_dependencies_path: resolved_dependencies_path.display().to_string(),
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
    resolved_dependencies: &mut Vec<ResolvedDependenciesRecord>,
    rustc_private_lib_dirs: &[PathBuf],
    cross_crate_mir: bool,
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
    apply_static_extraction_rustflags(&mut check_command, cross_crate_mir);
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
                // cargo check 成功后锁文件一定已写出，此时读到的是本次实际编译的版本。
                resolved_dependencies.push(read_resolved_dependencies(
                    &args.run_id,
                    &record.crate_id,
                    &metadata.workspace_root,
                )?);
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

/// 从 `Cargo.lock` 读被扫 crate 这次实际解析到的依赖版本。
///
/// 读锁文件而不是再跑一次带依赖的 `cargo metadata`：`cargo check` 刚跑完，锁文件就是
/// 本次编译的解析结果，且不额外起进程。锁文件缺失或解析不了不是错误——记成空集合
/// 加一条 note，让下游知道"这条 crate 的提供方版本不可知"，而不是让它以为没有依赖。
fn read_resolved_dependencies(
    run_id: &str,
    crate_id: &str,
    workspace_root: &Path,
) -> Result<ResolvedDependenciesRecord, CliError> {
    let mut notes = Vec::new();
    let packages = if workspace_root.as_os_str().is_empty() {
        notes.push("cargo metadata did not report a workspace_root".to_owned());
        Vec::new()
    } else {
        let lock_path = workspace_root.join("Cargo.lock");
        match fs::read_to_string(&lock_path) {
            Ok(text) => match parse_lockfile_packages(&text) {
                Some(packages) => packages,
                None => {
                    notes.push("Cargo.lock did not parse as a package list".to_owned());
                    Vec::new()
                }
            },
            Err(_) => {
                notes.push("Cargo.lock was not readable after cargo check".to_owned());
                Vec::new()
            }
        }
    };
    if packages.is_empty() && notes.is_empty() {
        notes.push("Cargo.lock listed no packages".to_owned());
    }
    Ok(ResolvedDependenciesRecord {
        schema_version: RESOLVED_DEPENDENCIES_SCHEMA_V1,
        run_id: run_id.to_owned(),
        crate_id: crate_id.to_owned(),
        packages,
        notes,
    })
}

/// `Cargo.lock` 的 `[[package]]` 表。同一个 crate 可能有多个版本共存，全部保留。
fn parse_lockfile_packages(text: &str) -> Option<Vec<CoveragePackage>> {
    #[derive(Deserialize)]
    struct Lockfile {
        #[serde(default)]
        package: Vec<LockedPackage>,
    }
    #[derive(Deserialize)]
    struct LockedPackage {
        name: String,
        version: String,
    }

    let lockfile = toml::from_str::<Lockfile>(text).ok()?;
    let mut packages = lockfile
        .package
        .into_iter()
        .map(|package| CoveragePackage {
            name: package.name,
            version: package.version,
        })
        .collect::<Vec<_>>();
    packages.sort();
    packages.dedup();
    Some(packages)
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

fn apply_static_extraction_rustflags(command: &mut Command, cross_crate_mir: bool) {
    let mut flags = STATIC_EXTRACTION_COMPAT_RUSTFLAGS.to_owned();
    if cross_crate_mir {
        flags.push(' ');
        flags.push_str(CROSS_CRATE_MIR_RUSTFLAG);
    }
    let existing = env::var("RUSTFLAGS").unwrap_or_default();
    let trimmed = existing.trim();
    let rustflags = if trimmed.is_empty() {
        flags
    } else if trimmed.contains(&flags) {
        trimmed.to_owned()
    } else {
        format!("{trimmed} {flags}")
    };
    command.env("RUSTFLAGS", rustflags);
}

/// 本次抽取能否让依赖带上 MIR。
///
/// `-Zalways-encode-mir` 只有 nightly 接受，而它决定了分析能不能看穿依赖里的注册
/// 封装。wrapper 本身链接 `rustc_private`，真实流水线永远跑 nightly；但这个命令也
/// 可能被 stable 调起，那时硬塞 `-Z` 会让每个 crate 直接编译失败。
///
/// 探测而非假设，且探测结果写进产物：拿不到跨 crate MIR 时分析照跑，只是覆盖面变窄，
/// 这必须是记录在案的限制，而不是悄悄退化成"没扫到问题"。
fn cross_crate_mir_available(args: &ExtractStaticFactsArgs) -> bool {
    let rustc = args
        .rustc
        .clone()
        .unwrap_or_else(|| PathBuf::from(env::var_os("RUSTC").unwrap_or_else(|| "rustc".into())));
    Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| version_output_is_nightly(&String::from_utf8_lossy(&output.stdout)))
}

/// `rustc --version` 是否报告 nightly（含 dev 构建）。
fn version_output_is_nightly(version_output: &str) -> bool {
    version_output.contains("nightly") || version_output.contains("-dev")
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

#[cfg(test)]
mod cross_crate_mir_tests {
    use super::{
        CROSS_CRATE_MIR_RUSTFLAG, STATIC_EXTRACTION_COMPAT_RUSTFLAGS,
        apply_static_extraction_rustflags, version_output_is_nightly,
    };
    use std::process::Command;

    fn rustflags_of(command: &Command) -> String {
        command
            .get_envs()
            .find(|(key, _)| *key == "RUSTFLAGS")
            .and_then(|(_, value)| value)
            .map(|value| value.to_string_lossy().into_owned())
            .expect("the stage must always set RUSTFLAGS")
    }

    #[test]
    fn cross_crate_mir_flag_is_emitted_only_when_enabled() {
        let mut enabled = Command::new("cargo");
        apply_static_extraction_rustflags(&mut enabled, true);
        assert!(
            rustflags_of(&enabled).contains(CROSS_CRATE_MIR_RUSTFLAG),
            "without the flag the analysis cannot see through a dependency's registration wrapper"
        );

        let mut disabled = Command::new("cargo");
        apply_static_extraction_rustflags(&mut disabled, false);
        assert!(
            !rustflags_of(&disabled).contains(CROSS_CRATE_MIR_RUSTFLAG),
            "-Z is nightly-only: emitting it on stable fails every crate outright"
        );
    }

    #[test]
    fn compatibility_flags_survive_either_way() {
        for cross_crate_mir in [true, false] {
            let mut command = Command::new("cargo");
            apply_static_extraction_rustflags(&mut command, cross_crate_mir);
            let flags = rustflags_of(&command);
            for expected in STATIC_EXTRACTION_COMPAT_RUSTFLAGS.split_whitespace() {
                assert!(
                    flags.contains(expected),
                    "{expected} must survive with cross_crate_mir={cross_crate_mir}: {flags}"
                );
            }
        }
    }

    #[test]
    fn nightly_is_detected_from_the_version_line() {
        assert!(version_output_is_nightly(
            "rustc 1.99.0-nightly (abcdef012 2026-07-08)"
        ));
        assert!(version_output_is_nightly("rustc 1.99.0-dev"));
        assert!(
            !version_output_is_nightly("rustc 1.97.0 (2d8144b78 2026-07-07)"),
            "a stable toolchain must not be offered the -Z flag"
        );
        assert!(!version_output_is_nightly("rustc 1.97.0-beta.3"));
    }
}
