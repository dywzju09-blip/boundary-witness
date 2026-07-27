use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use bw_model::{
    CallbackRetentionContract, Finding, FindingClassification, RuntimeEvent, RuntimeEventEnvelope,
    StaticFactEnvelope, validate_runtime_path,
};
use bw_oracle::{Oracle, OracleEngine, StaticFactIndex, normalize_finding};
use bw_runtime::TraceIndex;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    CaseOperation, ChildRunner, ChildSpec, ChildStatus, D0CaseMatrix, ExperimentError,
    ExperimentSummary, FinalizeRun, FinalizedRun, OutcomeFacts, ReplayRecord, Result, RunDirectory,
    RunMetadata, case_matrix::CallbackApi, classify_outcome, summarize_replays,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum D0RunMode {
    Preflight,
    Formal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D0WorkPlan {
    pub mode: D0RunMode,
    pub items: Vec<D0WorkItem>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D0WorkItem {
    pub case_id: String,
    pub api: CallbackApi,
    pub replay_id: String,
    pub iteration: Option<u32>,
    pub kind: D0WorkKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum D0WorkKind {
    Replay {
        static_facts: PathBuf,
        executable: PathBuf,
    },
    CompileCheck {
        source: PathBuf,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct D0ReplayAnalysis {
    pub api: CallbackApi,
    pub case_id: String,
    pub replay_id: String,
    pub build_id: String,
    pub static_facts: PathBuf,
    pub contract: PathBuf,
    pub trace: PathBuf,
    pub findings_output: PathBuf,
}

#[derive(Clone, Debug)]
pub struct D0RunOptions {
    pub matrix: D0CaseMatrix,
    pub repo_root: PathBuf,
    pub runs_root: PathBuf,
    pub contract: PathBuf,
    pub mode: D0RunMode,
    pub metadata: RunMetadata,
}

#[derive(Clone, Debug)]
pub struct D0RunReport {
    pub final_run: FinalizedRun,
    pub summary: ExperimentSummary,
    pub compile_check_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D0CompileCheckRecord {
    pub case_id: String,
    pub api: CallbackApi,
    pub replay_id: String,
    pub status: ChildStatus,
    pub timed_out: bool,
    pub stdout_log: String,
    pub stderr_log: String,
}

struct D0ExecutionState<'a> {
    run: &'a RunDirectory,
    child_runner: &'a ChildRunner,
    required_trace_files: &'a mut Vec<String>,
    required_log_files: &'a mut Vec<String>,
}

pub fn plan_d0_work(
    matrix: &D0CaseMatrix,
    mode: D0RunMode,
    repo_root: &Path,
) -> Result<D0WorkPlan> {
    let repetitions = match mode {
        D0RunMode::Preflight => 1,
        D0RunMode::Formal => matrix.repetitions,
    };
    let mut items = Vec::new();
    for case in &matrix.cases {
        match case.operation {
            CaseOperation::Run => {
                let static_facts = required_path(case.static_facts.as_ref(), &case.case_id)?;
                let executable = required_path(case.executable.as_ref(), &case.case_id)?;
                for iteration in 1..=repetitions {
                    items.push(D0WorkItem {
                        case_id: case.case_id.clone(),
                        api: case.api,
                        replay_id: format!("{}-r{iteration:03}", case.case_id),
                        iteration: Some(iteration),
                        kind: D0WorkKind::Replay {
                            static_facts: repo_root.join(static_facts),
                            executable: repo_root.join(executable),
                        },
                    });
                }
            }
            CaseOperation::CompileCheck => {
                let source = required_path(case.source.as_ref(), &case.case_id)?;
                items.push(D0WorkItem {
                    case_id: case.case_id.clone(),
                    api: case.api,
                    replay_id: format!("{}-compile-check", case.case_id),
                    iteration: None,
                    kind: D0WorkKind::CompileCheck {
                        source: repo_root.join(source),
                    },
                });
            }
        }
    }
    Ok(D0WorkPlan { mode, items })
}

fn required_path<'a>(path: Option<&'a PathBuf>, case_id: &str) -> Result<&'a PathBuf> {
    path.ok_or_else(|| {
        ExperimentError::InvalidInput(format!("case {case_id} is missing required artifact path"))
    })
}

pub fn run_d0(options: D0RunOptions) -> Result<D0RunReport> {
    let plan = plan_d0_work(&options.matrix, options.mode, &options.repo_root)?;
    let run_id = crate::generate_run_id(&options.metadata.git_commit)?;
    let run = RunDirectory::create(&options.runs_root, run_id, options.metadata.clone())?;
    copy_input_file(&options.contract, &run.input_dir().join("contract.toml"))?;

    let child_runner = ChildRunner::new(run.logs_dir().join("children"));
    let mut replay_records = Vec::new();
    let mut compile_records = Vec::new();
    let mut required_trace_files = Vec::new();
    let mut required_log_files = Vec::new();
    let replay_records_path = run.artifacts_dir().join("replay-records.jsonl");
    let compile_records_path = run.artifacts_dir().join("compile-checks.jsonl");

    for item in &plan.items {
        match &item.kind {
            D0WorkKind::Replay {
                static_facts,
                executable,
            } => {
                let mut state = D0ExecutionState {
                    run: &run,
                    child_runner: &child_runner,
                    required_trace_files: &mut required_trace_files,
                    required_log_files: &mut required_log_files,
                };
                let record = execute_replay(&options, &mut state, item, static_facts, executable)?;
                append_jsonl(&replay_records_path, &record)?;
                replay_records.push(record);
            }
            D0WorkKind::CompileCheck { source } => {
                let mut state = D0ExecutionState {
                    run: &run,
                    child_runner: &child_runner,
                    required_trace_files: &mut required_trace_files,
                    required_log_files: &mut required_log_files,
                };
                let record = execute_compile_check(&options, &mut state, item, source)?;
                append_jsonl(&compile_records_path, &record)?;
                compile_records.push(record);
            }
        }
    }

    let summary = summarize_replays(&replay_records)?;
    let compile_check_count = compile_records.len();
    let final_run = run.finalize(FinalizeRun {
        summary: json!({
            "schema_version": "boundary-witness.d0-run/0.1",
            "suite_id": &options.matrix.suite_id,
            "mode": options.mode,
            "work_items": plan.items.len(),
            "replay_count": replay_records.len(),
            "compile_check_count": compile_check_count,
            "experiment_summary": &summary,
            "compile_checks": &compile_records,
        }),
        execution: None,
        required_trace_files,
        required_log_files,
    })?;

    Ok(D0RunReport {
        final_run,
        summary,
        compile_check_count,
    })
}

pub fn analyze_d0_replay(input: &D0ReplayAnalysis) -> Result<ReplayRecord> {
    validate_runtime_path(&input.trace, 1024 * 1024).map_err(|error| {
        ExperimentError::InvalidInput(format!("invalid trace {}: {error}", input.trace.display()))
    })?;
    let static_facts = read_jsonl::<StaticFactEnvelope>(&input.static_facts)?;
    let static_index = StaticFactIndex::from_envelopes(static_facts).map_err(|error| {
        ExperimentError::InvalidInput(format!(
            "invalid static facts {}: {error}",
            input.static_facts.display()
        ))
    })?;
    let contract = CallbackRetentionContract::from_toml_str(
        &fs::read_to_string(&input.contract)
            .map_err(|error| ExperimentError::io(&input.contract, error))?,
    )
    .map_err(|error| {
        ExperimentError::InvalidInput(format!(
            "invalid contract {}: {error}",
            input.contract.display()
        ))
    })?;
    let events = read_jsonl::<RuntimeEventEnvelope>(&input.trace)?;

    let mut oracle = Oracle::new(static_index, contract);
    for event in &events {
        oracle.observe(event).map_err(|error| {
            ExperimentError::InvalidInput(format!("oracle failed for {}: {error}", input.replay_id))
        })?;
    }
    let summary = oracle.finish().map_err(|error| {
        ExperimentError::InvalidInput(format!(
            "oracle finish failed for {}: {error}",
            input.replay_id
        ))
    })?;
    let findings = summary.findings();
    write_findings_jsonl(&input.findings_output, findings)?;

    let signature_findings = signature_relevant_findings(findings);
    let mut signatures = signature_findings
        .map(normalize_finding)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            ExperimentError::InvalidInput(format!(
                "normalize finding failed for {}: {error}",
                input.replay_id
            ))
        })?
        .into_iter()
        .map(|finding| finding.signature)
        .collect::<Vec<_>>();
    signatures.sort();
    signatures.dedup();

    let facts = OutcomeFacts {
        has_contract_finding: !findings.is_empty(),
        ..OutcomeFacts::default()
    };
    let execution = classify_outcome(&facts);
    Ok(ReplayRecord {
        api: input.api,
        case_id: input.case_id.clone(),
        build_id: input.build_id.clone(),
        replay_id: input.replay_id.clone(),
        primary_outcome: execution.primary_outcome,
        finding_signature: if signatures.is_empty() {
            None
        } else {
            Some(signatures.join("+"))
        },
        evidence: execution.evidence,
    })
}

fn execute_replay(
    options: &D0RunOptions,
    state: &mut D0ExecutionState<'_>,
    item: &D0WorkItem,
    static_facts: &Path,
    executable: &Path,
) -> Result<ReplayRecord> {
    let build_id =
        static_build_id(static_facts)?.unwrap_or_else(|| options.metadata.build_id.clone());
    let trace_segments_dir = state
        .run
        .traces_dir()
        .join(format!("{}-segments", item.replay_id));
    fs::create_dir_all(&trace_segments_dir)
        .map_err(|error| ExperimentError::io(&trace_segments_dir, error))?;

    let child = state.child_runner.run(
        inherit_tool_environment(ChildSpec::new(executable))
            .env(
                "BW_RUN_ID",
                format!("{}:{}", options.matrix.suite_id, item.replay_id),
            )
            .env("BW_TRACE_ID", format!("{}:trace", item.replay_id))
            .env("BW_TRACE_DIR", trace_segments_dir.display().to_string())
            .env("BW_TRACE_COMPRESS", "0")
            .env("BW_BUILD_ID", build_id.clone())
            .timeout(Duration::from_millis(options.matrix.timeout_ms)),
    )?;
    state
        .required_log_files
        .push(relative_to(&state.run.logs_dir(), &child.stdout_path)?);
    state
        .required_log_files
        .push(relative_to(&state.run.logs_dir(), &child.stderr_path)?);

    if child.status != ChildStatus::Exited(0) {
        return child_failure_record(
            item,
            build_id,
            &child.status,
            child.timed_out,
            &child.stderr_path,
        );
    }

    let trace_path = state
        .run
        .traces_dir()
        .join(format!("{}.jsonl", item.replay_id));
    flatten_trace(&trace_segments_dir, &trace_path)?;
    state
        .required_trace_files
        .push(relative_to(&state.run.traces_dir(), &trace_path)?);

    let findings_output = state
        .run
        .artifacts_dir()
        .join("findings")
        .join(format!("{}.jsonl", item.replay_id));
    let record = analyze_d0_replay(&D0ReplayAnalysis {
        api: item.api,
        case_id: item.case_id.clone(),
        replay_id: item.replay_id.clone(),
        build_id,
        static_facts: static_facts.to_path_buf(),
        contract: options.contract.clone(),
        trace: trace_path,
        findings_output: findings_output.clone(),
    })?;
    append_file(&state.run.findings_path(), &findings_output)?;
    Ok(record)
}

fn execute_compile_check(
    options: &D0RunOptions,
    state: &mut D0ExecutionState<'_>,
    item: &D0WorkItem,
    source: &Path,
) -> Result<D0CompileCheckRecord> {
    let manifest = source.join("Cargo.toml");
    let child = state.child_runner.run(
        inherit_tool_environment(ChildSpec::new(PathBuf::from("cargo")))
            .args([
                "check".to_owned(),
                "--locked".to_owned(),
                "--manifest-path".to_owned(),
                manifest.display().to_string(),
            ])
            .timeout(Duration::from_millis(options.matrix.compile_timeout_ms)),
    )?;
    let stdout_log = relative_to(&state.run.logs_dir(), &child.stdout_path)?;
    let stderr_log = relative_to(&state.run.logs_dir(), &child.stderr_path)?;
    state.required_log_files.push(stdout_log.clone());
    state.required_log_files.push(stderr_log.clone());
    Ok(D0CompileCheckRecord {
        case_id: item.case_id.clone(),
        api: item.api,
        replay_id: item.replay_id.clone(),
        status: child.status,
        timed_out: child.timed_out,
        stdout_log,
        stderr_log,
    })
}

fn inherit_tool_environment(mut spec: ChildSpec) -> ChildSpec {
    for key in [
        "PATH",
        "HOME",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "RUSTC",
        "RUSTDOC",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
    ] {
        spec = spec.inherit_env(key);
    }
    spec
}

fn child_failure_record(
    item: &D0WorkItem,
    build_id: String,
    status: &ChildStatus,
    timed_out: bool,
    stderr_path: &Path,
) -> Result<ReplayRecord> {
    let stderr = fs::read_to_string(stderr_path).unwrap_or_default();
    let facts = OutcomeFacts {
        has_timeout: timed_out,
        has_panic: matches!(status, ChildStatus::Exited(_)) && stderr.contains("panicked at"),
        has_native_crash: !timed_out
            && !matches!(status, ChildStatus::Exited(0))
            && !stderr.contains("panicked at"),
        ..OutcomeFacts::default()
    };
    let execution = classify_outcome(&facts);
    Ok(ReplayRecord {
        api: item.api,
        case_id: item.case_id.clone(),
        build_id,
        replay_id: item.replay_id.clone(),
        primary_outcome: execution.primary_outcome,
        finding_signature: None,
        evidence: execution.evidence,
    })
}

fn copy_input_file(source: &Path, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| ExperimentError::io(parent, error))?;
    }
    fs::copy(source, destination).map_err(|error| ExperimentError::io(source, error))?;
    Ok(())
}

fn append_jsonl<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| ExperimentError::io(parent, error))?;
    }
    let mut output = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| ExperimentError::io(path, error))?;
    serde_json::to_writer(&mut output, value)?;
    output
        .write_all(b"\n")
        .map_err(|error| ExperimentError::io(path, error))
}

fn append_file(destination: &Path, source: &Path) -> Result<()> {
    let content = fs::read(source).map_err(|error| ExperimentError::io(source, error))?;
    if content.is_empty() {
        return Ok(());
    }
    let mut output = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(destination)
        .map_err(|error| ExperimentError::io(destination, error))?;
    output
        .write_all(&content)
        .map_err(|error| ExperimentError::io(destination, error))
}

fn relative_to(root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        ExperimentError::InvalidInput(format!(
            "{} is not under {}",
            path.display(),
            root.display()
        ))
    })?;
    Ok(relative.display().to_string())
}

fn static_build_id(path: &Path) -> Result<Option<String>> {
    let file = File::open(path).map_err(|error| ExperimentError::io(path, error))?;
    for (line_number, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|error| ExperimentError::io(path, error))?;
        if line.trim().is_empty() {
            continue;
        }
        let fact = StaticFactEnvelope::from_json_str(&line).map_err(|error| {
            ExperimentError::InvalidInput(format!(
                "invalid static fact {}:{}: {error}",
                path.display(),
                line_number + 1
            ))
        })?;
        return Ok(Some(fact.build_id.to_string()));
    }
    Ok(None)
}

fn flatten_trace(trace_dir: &Path, output_path: &Path) -> Result<()> {
    let index_path = trace_dir.join("trace-index.json");
    let index = TraceIndex::from_path(&index_path).map_err(|error| {
        ExperimentError::InvalidInput(format!(
            "invalid trace index {}: {error}",
            index_path.display()
        ))
    })?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|error| ExperimentError::io(parent, error))?;
    }
    let mut output =
        File::create(output_path).map_err(|error| ExperimentError::io(output_path, error))?;
    let mut events = Vec::new();
    for segment in index.segments {
        if segment.compressed {
            return Err(ExperimentError::InvalidInput(format!(
                "compressed D0 trace segment is not supported: {}",
                segment.path
            )));
        }
        let segment_path = trace_dir.join(segment.path);
        let input =
            File::open(&segment_path).map_err(|error| ExperimentError::io(&segment_path, error))?;
        for (line_number, line) in BufReader::new(input).lines().enumerate() {
            let line = line.map_err(|error| ExperimentError::io(&segment_path, error))?;
            if line.trim().is_empty() {
                continue;
            }
            let event = RuntimeEventEnvelope::from_json_str(&line).map_err(|error| {
                ExperimentError::InvalidInput(format!(
                    "invalid trace segment {}:{}: {error}",
                    segment_path.display(),
                    line_number + 1
                ))
            })?;
            events.push(event);
        }
    }

    let event_count = events.len() as u64;
    for (seq, event) in events.iter_mut().enumerate() {
        event.seq = seq as u64;
        if let RuntimeEvent::TraceEnd(ended) = &mut event.payload {
            ended.event_count = event_count;
        }
        serde_json::to_writer(&mut output, event)?;
        output
            .write_all(b"\n")
            .map_err(|error| ExperimentError::io(output_path, error))?;
    }
    Ok(())
}

fn signature_relevant_findings(findings: &[Finding]) -> Box<dyn Iterator<Item = &Finding> + '_> {
    let has_callback_lifetime = findings
        .iter()
        .any(|finding| finding.rule_id == "BW-LIFE-002");
    if has_callback_lifetime {
        return Box::new(
            findings
                .iter()
                .filter(|finding| finding.rule_id == "BW-LIFE-002"),
        );
    }

    let has_confirmed = findings
        .iter()
        .any(|finding| finding.classification == FindingClassification::ConfirmedViolation);
    if has_confirmed {
        Box::new(
            findings.iter().filter(|finding| {
                finding.classification == FindingClassification::ConfirmedViolation
            }),
        )
    } else {
        Box::new(findings.iter())
    }
}

fn read_jsonl<T>(path: &Path) -> Result<Vec<T>>
where
    T: serde::de::DeserializeOwned,
{
    let file = File::open(path).map_err(|error| ExperimentError::io(path, error))?;
    let reader = BufReader::new(file);
    let mut values = Vec::new();
    for (line_number, line) in reader.lines().enumerate() {
        let line = line.map_err(|error| ExperimentError::io(path, error))?;
        if line.trim().is_empty() {
            continue;
        }
        values.push(serde_json::from_str(&line).map_err(|error| {
            ExperimentError::InvalidInput(format!(
                "invalid jsonl {}:{}: {error}",
                path.display(),
                line_number + 1
            ))
        })?);
    }
    Ok(values)
}

fn write_findings_jsonl(path: &Path, findings: &[Finding]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| ExperimentError::io(parent, error))?;
    }
    let mut output = File::create(path).map_err(|error| ExperimentError::io(path, error))?;
    for finding in findings {
        serde_json::to_writer(&mut output, finding)?;
        output
            .write_all(b"\n")
            .map_err(|error| ExperimentError::io(path, error))?;
    }
    Ok(())
}
