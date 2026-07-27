use std::{
    env,
    fs::{self, File},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use bw_model::{
    V3_2_BUILDABILITY_SCHEMA_V1, V32BuildabilityRecord, V32BuildabilityStatus,
    V32CorpusIntakeStatus, V32CorpusManifestRecord, V32CorpusSourceKind,
    validate_v3_2_corpus_manifest,
};
use clap::Args;
use serde::Serialize;

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl, write_json_stdout},
    exit::{CliError, CommandStatus},
};

const BUILD_PRECHECK_COMPAT_ALLOW_FLAGS: [&str; 3] = [
    "-A useless_deprecated",
    "-A dangerous_implicit_autorefs",
    "-A bindings_with_variant_name",
];
const BUILD_PRECHECK_COMPAT_LINTS: [&str; 3] = [
    "useless_deprecated",
    "dangerous_implicit_autorefs",
    "bindings_with_variant_name",
];

#[derive(Args)]
pub struct BuildPrecheckArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    logs_root: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long)]
    target: Option<String>,
    #[arg(long, default_value = "cargo")]
    cargo: PathBuf,
    #[arg(long)]
    locked: bool,
    #[arg(long)]
    timeout_seconds: Option<u64>,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

#[derive(Serialize)]
struct BuildPrecheckOutput {
    kind: &'static str,
    record_count: u64,
    buildable_count: u64,
    failed_count: u64,
    fallback_attempt_count: u64,
    fallback_buildable_count: u64,
    output: String,
}

pub fn run(args: BuildPrecheckArgs) -> Result<CommandStatus, CliError> {
    let manifest_records =
        read_jsonl::<V32CorpusManifestRecord>(&args.manifest, args.max_line_bytes)?;
    validate_v3_2_corpus_manifest(manifest_records.clone())?;

    fs::create_dir_all(&args.logs_root)?;
    let target = args.target.clone().unwrap_or_else(host_target);
    let toolchain = toolchain_summary(&args.cargo);
    let manifest_dir = args.manifest.parent().unwrap_or_else(|| Path::new("."));
    let mut records = Vec::<V32BuildabilityRecord>::new();

    for located in manifest_records {
        records.push(precheck_one(
            &args,
            manifest_dir,
            &target,
            &toolchain,
            &located.value,
        )?);
    }

    write_records(&args.output, &records)?;
    let buildable_count = records
        .iter()
        .filter(|record| record.status == V32BuildabilityStatus::Buildable)
        .count() as u64;
    let summary = BuildPrecheckOutput {
        kind: "v3-2-buildability-precheck",
        record_count: records.len() as u64,
        buildable_count,
        failed_count: records.len() as u64 - buildable_count,
        fallback_attempt_count: records
            .iter()
            .filter(|record| record.fallback_status.is_some())
            .count() as u64,
        fallback_buildable_count: records
            .iter()
            .filter(|record| record.fallback_status == Some(V32BuildabilityStatus::Buildable))
            .count() as u64,
        output: args.output.display().to_string(),
    };
    write_json_stdout(&summary)?;
    Ok(CommandStatus::Success)
}

fn precheck_one(
    args: &BuildPrecheckArgs,
    manifest_dir: &Path,
    target: &str,
    toolchain: &str,
    record: &V32CorpusManifestRecord,
) -> Result<V32BuildabilityRecord, CliError> {
    let log_ref = format!("build/{}.log", sanitize_file_stem(&record.crate_id));
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
        return Ok(buildability_record(
            args,
            record,
            BuildabilityOutcome {
                target,
                toolchain,
                status: V32BuildabilityStatus::NotBuildable,
                log_ref,
                elapsed_ms: 0,
                failure_class: Some("excluded_by_intake"),
            },
        ));
    }

    let source_path = match resolve_local_source(manifest_dir, record) {
        Ok(path) => path,
        Err(failure_class) => {
            write_log(&log_path, "source resolution failed", "", failure_class)?;
            return Ok(buildability_record(
                args,
                record,
                BuildabilityOutcome {
                    target,
                    toolchain,
                    status: V32BuildabilityStatus::ToolError,
                    log_ref,
                    elapsed_ms: 0,
                    failure_class: Some(failure_class),
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
        return Ok(buildability_record(
            args,
            record,
            BuildabilityOutcome {
                target,
                toolchain,
                status: V32BuildabilityStatus::NotBuildable,
                log_ref,
                elapsed_ms: 0,
                failure_class: Some("manifest_missing"),
            },
        ));
    }

    let command = cargo_check_command(args, &cargo_toml, target);

    let command_for_log = format!("{command:?}");
    match run_cargo_check(command, args.timeout_seconds) {
        Ok(CargoCheckResult::Completed {
            status,
            stdout,
            stderr,
            elapsed_ms,
        }) => {
            write_log(&log_path, &command_for_log, &stdout, &stderr)?;
            if status.success() {
                return Ok(with_original_attempt(
                    buildability_record(
                        args,
                        record,
                        BuildabilityOutcome {
                            target,
                            toolchain,
                            status: V32BuildabilityStatus::Buildable,
                            log_ref,
                            elapsed_ms,
                            failure_class: None,
                        },
                    ),
                    V32BuildabilityStatus::Buildable,
                    None,
                ));
            }
            if should_retry_with_compat_rustflags(&stderr) {
                let original_status = classify_cargo_failure(&stderr);
                let original_failure_class = Some("legacy_lint_requires_compat_rustflags");
                let compat_rustflags = build_precheck_compat_rustflags();
                let mut fallback_command = cargo_check_command(args, &cargo_toml, target);
                fallback_command.env("RUSTFLAGS", &compat_rustflags);
                let fallback_command_for_log = format!("{fallback_command:?}");
                return match run_cargo_check(fallback_command, args.timeout_seconds) {
                    Ok(CargoCheckResult::Completed {
                        status: fallback_status,
                        stdout: fallback_stdout,
                        stderr: fallback_stderr,
                        elapsed_ms: fallback_elapsed_ms,
                    }) => {
                        let outcome = if fallback_status.success() {
                            "compat rustflags fallback succeeded"
                        } else {
                            "compat rustflags fallback failed"
                        };
                        write_compat_fallback_log(
                            &log_path,
                            CompatFallbackLog {
                                initial_command: &command_for_log,
                                initial_stdout: &stdout,
                                initial_stderr: &stderr,
                                fallback_command: &fallback_command_for_log,
                                compat_rustflags: &compat_rustflags,
                                fallback_stdout: &fallback_stdout,
                                fallback_stderr: &fallback_stderr,
                                outcome,
                            },
                        )?;
                        if fallback_status.success() {
                            Ok(with_fallback_attempt(
                                buildability_record(
                                    args,
                                    record,
                                    BuildabilityOutcome {
                                        target,
                                        toolchain,
                                        status: V32BuildabilityStatus::Buildable,
                                        log_ref,
                                        elapsed_ms: elapsed_ms + fallback_elapsed_ms,
                                        failure_class: None,
                                    },
                                ),
                                original_status,
                                original_failure_class,
                                V32BuildabilityStatus::Buildable,
                                None,
                                &compat_rustflags,
                            ))
                        } else {
                            let status = classify_cargo_failure(&fallback_stderr);
                            let failure_class = match status {
                                V32BuildabilityStatus::RequiresSystemDependency => {
                                    "requires_system_dependency"
                                }
                                V32BuildabilityStatus::UnsupportedTarget => "unsupported_target",
                                _ => "compat_rustflags_fallback_failed",
                            };
                            Ok(with_fallback_attempt(
                                buildability_record(
                                    args,
                                    record,
                                    BuildabilityOutcome {
                                        target,
                                        toolchain,
                                        status,
                                        log_ref,
                                        elapsed_ms: elapsed_ms + fallback_elapsed_ms,
                                        failure_class: Some(failure_class),
                                    },
                                ),
                                original_status,
                                original_failure_class,
                                status,
                                Some(failure_class),
                                &compat_rustflags,
                            ))
                        }
                    }
                    Ok(CargoCheckResult::TimedOut {
                        stdout: fallback_stdout,
                        stderr: mut fallback_stderr,
                        elapsed_ms: fallback_elapsed_ms,
                    }) => {
                        if !fallback_stderr.is_empty() && !fallback_stderr.ends_with('\n') {
                            fallback_stderr.push('\n');
                        }
                        fallback_stderr.push_str(
                            "bw build-precheck timeout: compat rustflags fallback cargo check exceeded timeout_seconds\n",
                        );
                        write_compat_fallback_log(
                            &log_path,
                            CompatFallbackLog {
                                initial_command: &command_for_log,
                                initial_stdout: &stdout,
                                initial_stderr: &stderr,
                                fallback_command: &fallback_command_for_log,
                                compat_rustflags: &compat_rustflags,
                                fallback_stdout: &fallback_stdout,
                                fallback_stderr: &fallback_stderr,
                                outcome: "compat rustflags fallback timed out",
                            },
                        )?;
                        Ok(with_fallback_attempt(
                            buildability_record(
                                args,
                                record,
                                BuildabilityOutcome {
                                    target,
                                    toolchain,
                                    status: V32BuildabilityStatus::Timeout,
                                    log_ref,
                                    elapsed_ms: elapsed_ms + fallback_elapsed_ms,
                                    failure_class: Some("compat_rustflags_fallback_timeout"),
                                },
                            ),
                            original_status,
                            original_failure_class,
                            V32BuildabilityStatus::Timeout,
                            Some("compat_rustflags_fallback_timeout"),
                            &compat_rustflags,
                        ))
                    }
                    Err(error) => {
                        write_compat_fallback_log(
                            &log_path,
                            CompatFallbackLog {
                                initial_command: &command_for_log,
                                initial_stdout: &stdout,
                                initial_stderr: &stderr,
                                fallback_command: &fallback_command_for_log,
                                compat_rustflags: &compat_rustflags,
                                fallback_stdout: "",
                                fallback_stderr: &error.to_string(),
                                outcome: "compat rustflags fallback spawn failed",
                            },
                        )?;
                        Ok(with_fallback_attempt(
                            buildability_record(
                                args,
                                record,
                                BuildabilityOutcome {
                                    target,
                                    toolchain,
                                    status: V32BuildabilityStatus::ToolError,
                                    log_ref,
                                    elapsed_ms,
                                    failure_class: Some("compat_rustflags_fallback_spawn_failed"),
                                },
                            ),
                            original_status,
                            original_failure_class,
                            V32BuildabilityStatus::ToolError,
                            Some("compat_rustflags_fallback_spawn_failed"),
                            &compat_rustflags,
                        ))
                    }
                };
            }

            let status = classify_cargo_failure(&stderr);
            let failure_class = match status {
                V32BuildabilityStatus::RequiresSystemDependency => "requires_system_dependency",
                V32BuildabilityStatus::UnsupportedTarget => "unsupported_target",
                _ => "cargo_check_failed",
            };
            return Ok(with_original_attempt(
                buildability_record(
                    args,
                    record,
                    BuildabilityOutcome {
                        target,
                        toolchain,
                        status,
                        log_ref,
                        elapsed_ms,
                        failure_class: Some(failure_class),
                    },
                ),
                status,
                Some(failure_class),
            ));
        }
        Ok(CargoCheckResult::TimedOut {
            stdout,
            mut stderr,
            elapsed_ms,
        }) => {
            if !stderr.is_empty() && !stderr.ends_with('\n') {
                stderr.push('\n');
            }
            stderr.push_str("bw build-precheck timeout: cargo check exceeded timeout_seconds\n");
            write_log(&log_path, &command_for_log, &stdout, &stderr)?;
            return Ok(with_original_attempt(
                buildability_record(
                    args,
                    record,
                    BuildabilityOutcome {
                        target,
                        toolchain,
                        status: V32BuildabilityStatus::Timeout,
                        log_ref,
                        elapsed_ms,
                        failure_class: Some("timeout"),
                    },
                ),
                V32BuildabilityStatus::Timeout,
                Some("timeout"),
            ));
        }
        Err(error) => {
            write_log(&log_path, &command_for_log, "", &error.to_string())?;
            Ok(with_original_attempt(
                buildability_record(
                    args,
                    record,
                    BuildabilityOutcome {
                        target,
                        toolchain,
                        status: V32BuildabilityStatus::ToolError,
                        log_ref,
                        elapsed_ms: 0,
                        failure_class: Some("cargo_spawn_failed"),
                    },
                ),
                V32BuildabilityStatus::ToolError,
                Some("cargo_spawn_failed"),
            ))
        }
    }
}

fn cargo_check_command(args: &BuildPrecheckArgs, cargo_toml: &Path, target: &str) -> Command {
    let mut command = Command::new(&args.cargo);
    command
        .arg("check")
        .arg("--manifest-path")
        .arg(cargo_toml)
        .arg("--quiet");
    if args.locked {
        command.arg("--locked");
    }
    if args.target.is_some() {
        command.arg("--target").arg(target);
    }
    command
}

fn should_retry_with_compat_rustflags(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    BUILD_PRECHECK_COMPAT_LINTS
        .iter()
        .any(|lint| lower.contains(lint))
}

fn build_precheck_compat_rustflags() -> String {
    let mut rustflags = env::var("RUSTFLAGS").unwrap_or_default().trim().to_owned();
    for allow_flag in BUILD_PRECHECK_COMPAT_ALLOW_FLAGS {
        if !rustflags.contains(allow_flag) {
            if !rustflags.is_empty() {
                rustflags.push(' ');
            }
            rustflags.push_str(allow_flag);
        }
    }
    rustflags
}

enum CargoCheckResult {
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

fn run_cargo_check(
    mut command: Command,
    timeout_seconds: Option<u64>,
) -> Result<CargoCheckResult, std::io::Error> {
    let start = Instant::now();
    let timeout = timeout_seconds
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs);
    let Some(timeout) = timeout else {
        let output = command.output()?;
        return Ok(CargoCheckResult::Completed {
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
            return Ok(CargoCheckResult::Completed {
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
            return Ok(CargoCheckResult::TimedOut {
                stdout,
                stderr,
                elapsed_ms: start.elapsed().as_millis() as u64,
            });
        }

        std::thread::sleep(Duration::from_millis(50));
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

fn classify_cargo_failure(stderr: &str) -> V32BuildabilityStatus {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("could not find system library")
        || lower.contains("pkg-config")
        || lower.contains("system dependency")
        || lower.contains("linker")
    {
        V32BuildabilityStatus::RequiresSystemDependency
    } else if lower.contains("could not find specification for target")
        || lower.contains("target may not be installed")
    {
        V32BuildabilityStatus::UnsupportedTarget
    } else {
        V32BuildabilityStatus::NotBuildable
    }
}

struct BuildabilityOutcome<'a> {
    target: &'a str,
    toolchain: &'a str,
    status: V32BuildabilityStatus,
    log_ref: String,
    elapsed_ms: u64,
    failure_class: Option<&'a str>,
}

fn buildability_record(
    args: &BuildPrecheckArgs,
    record: &V32CorpusManifestRecord,
    outcome: BuildabilityOutcome<'_>,
) -> V32BuildabilityRecord {
    V32BuildabilityRecord {
        schema_version: V3_2_BUILDABILITY_SCHEMA_V1.to_owned(),
        run_id: args.run_id.clone(),
        crate_id: record.crate_id.clone(),
        status: outcome.status,
        toolchain: outcome.toolchain.to_owned(),
        target: outcome.target.to_owned(),
        native_dependencies: Vec::new(),
        elapsed_ms: outcome.elapsed_ms,
        log_ref: outcome.log_ref,
        failure_class: outcome.failure_class.map(str::to_owned),
        original_status: None,
        original_failure_class: None,
        fallback_status: None,
        fallback_failure_class: None,
        fallback_rustflags: None,
    }
}

fn with_original_attempt(
    mut record: V32BuildabilityRecord,
    status: V32BuildabilityStatus,
    failure_class: Option<&str>,
) -> V32BuildabilityRecord {
    record.original_status = Some(status);
    record.original_failure_class = failure_class.map(str::to_owned);
    record
}

fn with_fallback_attempt(
    record: V32BuildabilityRecord,
    original_status: V32BuildabilityStatus,
    original_failure_class: Option<&str>,
    fallback_status: V32BuildabilityStatus,
    fallback_failure_class: Option<&str>,
    fallback_rustflags: &str,
) -> V32BuildabilityRecord {
    let mut record = with_original_attempt(record, original_status, original_failure_class);
    record.fallback_status = Some(fallback_status);
    record.fallback_failure_class = fallback_failure_class.map(str::to_owned);
    record.fallback_rustflags = Some(fallback_rustflags.to_owned());
    record
}

fn write_records(path: &Path, records: &[V32BuildabilityRecord]) -> Result<(), CliError> {
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

fn write_log(path: &Path, command: &str, stdout: &str, stderr: &str) -> Result<(), CliError> {
    let mut file = File::create(path)?;
    writeln!(file, "command: {command}")?;
    writeln!(file, "\nstdout:\n{stdout}")?;
    writeln!(file, "\nstderr:\n{stderr}")?;
    Ok(())
}

struct CompatFallbackLog<'a> {
    initial_command: &'a str,
    initial_stdout: &'a str,
    initial_stderr: &'a str,
    fallback_command: &'a str,
    compat_rustflags: &'a str,
    fallback_stdout: &'a str,
    fallback_stderr: &'a str,
    outcome: &'a str,
}

fn write_compat_fallback_log(path: &Path, log: CompatFallbackLog<'_>) -> Result<(), CliError> {
    let command = format!(
        "{}\n\ncompat fallback: enabled for build-precheck legacy lint compatibility\ncompat rustflags: {}\ncompat fallback command: {}",
        log.initial_command, log.compat_rustflags, log.fallback_command
    );
    let stdout = format!(
        "initial cargo check stdout:\n{}\n\ncompat fallback stdout:\n{}",
        log.initial_stdout, log.fallback_stdout
    );
    let stderr = format!(
        "initial cargo check stderr:\n{}\n\ncompat fallback stderr:\n{}\n\ncompat fallback outcome: {}\n",
        log.initial_stderr, log.fallback_stderr, log.outcome
    );
    write_log(path, &command, &stdout, &stderr)
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

fn host_target() -> String {
    let output = Command::new("rustc").arg("-vV").output();
    let Ok(output) = output else {
        return "host".to_owned();
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap_or("host")
        .to_owned()
}

fn toolchain_summary(cargo: &Path) -> String {
    let cargo_version = Command::new(cargo)
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "cargo unknown".to_owned());
    let rustc_version = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "rustc unknown".to_owned());
    format!("{cargo_version}; {rustc_version}")
}
