use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use bw_model::{
    Finding, FindingClassification, RuntimeEvent, RuntimeEventEnvelope, StaticFactEnvelope,
};
use bw_runtime::TraceIndex;
use serde::{Deserialize, Serialize};

pub const RUNNER_SCHEMA_V01: &str = "bw.rusqlite-runner/0.1";
pub const GROUND_TRUTH_SCHEMA_V01: &str = "bw.rusqlite-ground-truth/0.1";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindRunnerConfig {
    pub schema_version: String,
    pub suite_id: String,
    pub build_id: String,
    pub contract: PathBuf,
    pub bw_binary: PathBuf,
    pub output_dir: PathBuf,
    #[serde(default)]
    pub cases: Vec<BlindCaseConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindCaseConfig {
    pub static_facts: PathBuf,
    pub executable: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub working_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedCase {
    pub case_id: String,
    pub static_facts: PathBuf,
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub working_dir: Option<PathBuf>,
    pub case_dir: PathBuf,
    pub trace_dir: PathBuf,
    pub trace_path: PathBuf,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
    pub analyze_stdout_log: PathBuf,
    pub analyze_stderr_log: PathBuf,
    pub findings_path: PathBuf,
    pub result_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedOutcome {
    Clean,
    ExposureOnly,
    ConfirmedViolation,
    ChildFailure,
    AnalysisFailure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedCaseResult {
    pub case_id: String,
    pub outcome: ObservedOutcome,
    pub finding_rule_ids: Vec<String>,
    pub child_exit_code: Option<i32>,
    pub analyze_exit_code: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroundTruthFile {
    pub schema_version: String,
    pub suite_id: String,
    #[serde(default)]
    pub cases: Vec<GroundTruthCase>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroundTruthSet {
    pub cases: Vec<GroundTruthCase>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroundTruthCase {
    pub case_id: String,
    pub expectation: ExpectedOutcome,
    pub family: String,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    Clean,
    ExposureOnly,
    ConfirmedViolation,
    CompileReject,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReport {
    pub total_cases: usize,
    pub matched_cases: usize,
    pub mismatches: Vec<VerificationMismatch>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationMismatch {
    pub case_id: String,
    pub expected: String,
    pub observed: String,
    pub reason: String,
}

#[derive(Debug)]
pub enum BlindRunnerError {
    Config(String),
    Io {
        action: &'static str,
        source: std::io::Error,
    },
    Json(serde_json::Error),
    MissingTraceIndex(PathBuf),
    UnsupportedCompressedTrace(PathBuf),
    UnknownCase(String),
    DuplicateCase(String),
}

impl BlindRunnerError {
    fn io(action: &'static str, source: std::io::Error) -> Self {
        Self::Io { action, source }
    }
}

impl fmt::Display for BlindRunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => formatter.write_str(message),
            Self::Io { action, source } => write!(formatter, "{action}: {source}"),
            Self::Json(error) => write!(formatter, "json error: {error}"),
            Self::MissingTraceIndex(path) => {
                write!(formatter, "missing trace index at {}", path.display())
            }
            Self::UnsupportedCompressedTrace(path) => write!(
                formatter,
                "compressed trace segment is not supported by the blind runner flattener: {}",
                path.display()
            ),
            Self::UnknownCase(case_id) => write!(formatter, "no ground truth for {case_id}"),
            Self::DuplicateCase(case_id) => write!(formatter, "duplicate case id {case_id}"),
        }
    }
}

impl Error for BlindRunnerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for BlindRunnerError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub fn parse_runner_config(input: &str) -> Result<BlindRunnerConfig, BlindRunnerError> {
    let config = toml::from_str::<BlindRunnerConfig>(input)
        .map_err(|error| BlindRunnerError::Config(error.to_string()))?;
    if config.schema_version != RUNNER_SCHEMA_V01 {
        return Err(BlindRunnerError::Config(format!(
            "unsupported runner schema {}",
            config.schema_version
        )));
    }
    Ok(config)
}

pub fn parse_ground_truth(input: &str) -> Result<GroundTruthFile, BlindRunnerError> {
    let ground_truth = toml::from_str::<GroundTruthFile>(input)
        .map_err(|error| BlindRunnerError::Config(error.to_string()))?;
    if ground_truth.schema_version != GROUND_TRUTH_SCHEMA_V01 {
        return Err(BlindRunnerError::Config(format!(
            "unsupported ground truth schema {}",
            ground_truth.schema_version
        )));
    }
    Ok(ground_truth)
}

pub fn plan_cases(config: &BlindRunnerConfig) -> Result<Vec<PlannedCase>, BlindRunnerError> {
    Ok(config
        .cases
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let case_id = format!("case-{:04}", index + 1);
            let case_dir = config.output_dir.join(&case_id);
            PlannedCase {
                case_id,
                static_facts: case.static_facts.clone(),
                executable: case.executable.clone(),
                args: case.args.clone(),
                env: case.env.clone(),
                working_dir: case.working_dir.clone(),
                trace_dir: case_dir.join("trace"),
                trace_path: case_dir.join("trace.jsonl"),
                stdout_log: case_dir.join("stdout.log"),
                stderr_log: case_dir.join("stderr.log"),
                analyze_stdout_log: case_dir.join("analyze.stdout.log"),
                analyze_stderr_log: case_dir.join("analyze.stderr.log"),
                findings_path: case_dir.join("findings.jsonl"),
                result_path: case_dir.join("result.json"),
                case_dir,
            }
        })
        .collect())
}

pub fn run_config(config: &BlindRunnerConfig) -> Result<Vec<ObservedCaseResult>, BlindRunnerError> {
    let mut results = Vec::new();
    for case in plan_cases(config)? {
        results.push(execute_case(config, &case)?);
    }
    Ok(results)
}

pub fn execute_case(
    config: &BlindRunnerConfig,
    case: &PlannedCase,
) -> Result<ObservedCaseResult, BlindRunnerError> {
    fs::create_dir_all(&case.trace_dir)
        .map_err(|error| BlindRunnerError::io("create trace directory", error))?;

    let child_output = run_child(config, case)?;
    fs::write(&case.stdout_log, &child_output.stdout)
        .map_err(|error| BlindRunnerError::io("write child stdout", error))?;
    fs::write(&case.stderr_log, &child_output.stderr)
        .map_err(|error| BlindRunnerError::io("write child stderr", error))?;

    if !child_output.status.success() {
        let result = ObservedCaseResult {
            case_id: case.case_id.clone(),
            outcome: ObservedOutcome::ChildFailure,
            finding_rule_ids: Vec::new(),
            child_exit_code: exit_code(child_output.status),
            analyze_exit_code: None,
        };
        write_result(case, &result)?;
        return Ok(result);
    }

    flatten_trace(&case.trace_dir, &case.trace_path)?;
    let analyze_output = Command::new(&config.bw_binary)
        .arg("analyze")
        .arg("--static")
        .arg(&case.static_facts)
        .arg("--contract")
        .arg(&config.contract)
        .arg("--trace")
        .arg(&case.trace_path)
        .arg("--output")
        .arg(&case.findings_path)
        .output()
        .map_err(|error| BlindRunnerError::io("run bw analyze", error))?;

    fs::write(&case.analyze_stdout_log, &analyze_output.stdout)
        .map_err(|error| BlindRunnerError::io("write analyze stdout", error))?;
    fs::write(&case.analyze_stderr_log, &analyze_output.stderr)
        .map_err(|error| BlindRunnerError::io("write analyze stderr", error))?;

    let analyze_exit_code = exit_code(analyze_output.status);
    if !matches!(analyze_exit_code, Some(0 | 1)) {
        let result = ObservedCaseResult {
            case_id: case.case_id.clone(),
            outcome: ObservedOutcome::AnalysisFailure,
            finding_rule_ids: Vec::new(),
            child_exit_code: exit_code(child_output.status),
            analyze_exit_code,
        };
        write_result(case, &result)?;
        return Ok(result);
    }

    let findings = read_findings(&case.findings_path)?;
    let finding_rule_ids = findings
        .iter()
        .map(|finding| finding.rule_id.clone())
        .collect::<Vec<_>>();
    let outcome = observed_outcome(&findings);
    let result = ObservedCaseResult {
        case_id: case.case_id.clone(),
        outcome,
        finding_rule_ids,
        child_exit_code: exit_code(child_output.status),
        analyze_exit_code,
    };
    write_result(case, &result)?;
    Ok(result)
}

pub fn verify_against_ground_truth(
    observed: &[ObservedCaseResult],
    ground_truth: &GroundTruthSet,
) -> Result<VerificationReport, BlindRunnerError> {
    let mut expected_by_id = BTreeMap::new();
    for expected in &ground_truth.cases {
        if expected_by_id
            .insert(expected.case_id.clone(), expected)
            .is_some()
        {
            return Err(BlindRunnerError::DuplicateCase(expected.case_id.clone()));
        }
    }

    let mut seen = BTreeSet::new();
    let mut mismatches = Vec::new();
    for result in observed {
        let expected = expected_by_id
            .get(&result.case_id)
            .ok_or_else(|| BlindRunnerError::UnknownCase(result.case_id.clone()))?;
        seen.insert(result.case_id.clone());
        if !expected.matches(&result.outcome) {
            mismatches.push(VerificationMismatch {
                case_id: result.case_id.clone(),
                expected: expected.expectation.as_str().to_owned(),
                observed: result.outcome.as_str().to_owned(),
                reason: format!(
                    "{} expected {}",
                    expected.family,
                    expected.expectation.as_str()
                ),
            });
        }
    }

    for case_id in expected_by_id.keys() {
        if !seen.contains(case_id) {
            mismatches.push(VerificationMismatch {
                case_id: case_id.clone(),
                expected: expected_by_id[case_id].expectation.as_str().to_owned(),
                observed: "missing".to_owned(),
                reason: "ground truth case has no observed result".to_owned(),
            });
        }
    }

    Ok(VerificationReport {
        total_cases: ground_truth.cases.len(),
        matched_cases: ground_truth.cases.len().saturating_sub(mismatches.len()),
        mismatches,
    })
}

pub fn read_observed_results(path: &Path) -> Result<Vec<ObservedCaseResult>, BlindRunnerError> {
    let file =
        File::open(path).map_err(|error| BlindRunnerError::io("open observed results", error))?;
    let reader = BufReader::new(file);
    let mut results = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|error| BlindRunnerError::io("read observed results", error))?;
        if line.trim().is_empty() {
            continue;
        }
        results.push(serde_json::from_str::<ObservedCaseResult>(&line)?);
    }
    Ok(results)
}

pub fn write_observed_results(
    path: &Path,
    results: &[ObservedCaseResult],
) -> Result<(), BlindRunnerError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| BlindRunnerError::io("create observed result directory", error))?;
    }
    let mut file = File::create(path)
        .map_err(|error| BlindRunnerError::io("create observed result file", error))?;
    for result in results {
        serde_json::to_writer(&mut file, result)?;
        file.write_all(b"\n")
            .map_err(|error| BlindRunnerError::io("write observed result", error))?;
    }
    Ok(())
}

fn run_child(
    config: &BlindRunnerConfig,
    case: &PlannedCase,
) -> Result<std::process::Output, BlindRunnerError> {
    let build_id = case_build_id(config, case)?;
    let mut command = Command::new(&case.executable);
    command.args(&case.args);
    if let Some(working_dir) = &case.working_dir {
        command.current_dir(working_dir);
    }
    command
        .env("BW_RUN_ID", format!("{}:{}", config.suite_id, case.case_id))
        .env("BW_TRACE_ID", format!("{}:trace", case.case_id))
        .env("BW_TRACE_DIR", &case.trace_dir)
        .env("BW_TRACE_COMPRESS", "0")
        .env("BW_BUILD_ID", build_id)
        .envs(&case.env);
    command
        .output()
        .map_err(|error| BlindRunnerError::io("run blind case child", error))
}

fn case_build_id(
    config: &BlindRunnerConfig,
    case: &PlannedCase,
) -> Result<String, BlindRunnerError> {
    static_build_id(&case.static_facts).map(|build_id| build_id.unwrap_or(config.build_id.clone()))
}

fn static_build_id(path: &Path) -> Result<Option<String>, BlindRunnerError> {
    let file =
        File::open(path).map_err(|error| BlindRunnerError::io("open static facts", error))?;
    for (line_number, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|error| BlindRunnerError::io("read static facts", error))?;
        if line.trim().is_empty() {
            continue;
        }
        let fact = StaticFactEnvelope::from_json_str(&line).map_err(|error| {
            BlindRunnerError::Config(format!(
                "invalid static fact {}:{}: {error}",
                path.display(),
                line_number + 1
            ))
        })?;
        return Ok(Some(fact.build_id.to_string()));
    }
    Ok(None)
}

fn flatten_trace(trace_dir: &Path, output_path: &Path) -> Result<(), BlindRunnerError> {
    let index_path = trace_dir.join("trace-index.json");
    if !index_path.exists() {
        return Err(BlindRunnerError::MissingTraceIndex(index_path));
    }
    let index = TraceIndex::from_path(&index_path)
        .map_err(|error| BlindRunnerError::Config(error.to_string()))?;
    let mut output =
        File::create(output_path).map_err(|error| BlindRunnerError::io("create trace", error))?;
    let mut events = Vec::new();
    for segment in index.segments {
        let segment_path = trace_dir.join(segment.path);
        if segment.compressed {
            return Err(BlindRunnerError::UnsupportedCompressedTrace(segment_path));
        }
        let input = File::open(&segment_path)
            .map_err(|error| BlindRunnerError::io("open trace segment", error))?;
        for (line_number, line) in BufReader::new(input).lines().enumerate() {
            let line = line.map_err(|error| BlindRunnerError::io("read trace segment", error))?;
            if line.trim().is_empty() {
                continue;
            }
            let event = RuntimeEventEnvelope::from_json_str(&line).map_err(|error| {
                BlindRunnerError::Config(format!(
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
            .map_err(|error| BlindRunnerError::io("write normalized trace", error))?;
    }
    Ok(())
}

fn read_findings(path: &Path) -> Result<Vec<Finding>, BlindRunnerError> {
    let file = File::open(path).map_err(|error| BlindRunnerError::io("open findings", error))?;
    let reader = BufReader::new(file);
    let mut findings = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|error| BlindRunnerError::io("read findings", error))?;
        if line.trim().is_empty() {
            continue;
        }
        findings.push(Finding::from_json_str(&line).map_err(|error| {
            BlindRunnerError::Config(format!("invalid finding {}: {}", path.display(), error))
        })?);
    }
    Ok(findings)
}

fn observed_outcome(findings: &[Finding]) -> ObservedOutcome {
    if findings
        .iter()
        .any(|finding| finding.classification == FindingClassification::ConfirmedViolation)
    {
        ObservedOutcome::ConfirmedViolation
    } else if findings.is_empty() {
        ObservedOutcome::Clean
    } else {
        ObservedOutcome::ExposureOnly
    }
}

fn write_result(case: &PlannedCase, result: &ObservedCaseResult) -> Result<(), BlindRunnerError> {
    let json = serde_json::to_vec_pretty(result)?;
    fs::write(&case.result_path, json)
        .map_err(|error| BlindRunnerError::io("write case result", error))
}

fn exit_code(status: ExitStatus) -> Option<i32> {
    status.code()
}

impl GroundTruthCase {
    fn matches(&self, observed: &ObservedOutcome) -> bool {
        matches!(
            (&self.expectation, observed),
            (ExpectedOutcome::Clean, ObservedOutcome::Clean)
                | (ExpectedOutcome::ExposureOnly, ObservedOutcome::ExposureOnly)
                | (
                    ExpectedOutcome::ConfirmedViolation,
                    ObservedOutcome::ConfirmedViolation
                )
                | (
                    ExpectedOutcome::CompileReject,
                    ObservedOutcome::ChildFailure
                )
        )
    }
}

impl ExpectedOutcome {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::ExposureOnly => "exposure_only",
            Self::ConfirmedViolation => "confirmed_violation",
            Self::CompileReject => "compile_reject",
        }
    }
}

impl ObservedOutcome {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::ExposureOnly => "exposure_only",
            Self::ConfirmedViolation => "confirmed_violation",
            Self::ChildFailure => "child_failure",
            Self::AnalysisFailure => "analysis_failure",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use bw_model::{
        validate_runtime_path, BuildId, CheckpointEvent, CheckpointKind, RecordId, RunId,
        RuntimeEvent, RuntimeEventEnvelope, TraceEndEvent, TraceId, TraceStartEvent,
        TRACE_SCHEMA_V01,
    };

    use super::{flatten_trace, static_build_id};

    #[test]
    fn flatten_trace_normalizes_runtime_sequence_for_model_validation() {
        let temp = temp_dir("flatten-seq");
        let trace_dir = temp.join("trace");
        fs::create_dir_all(&trace_dir).expect("trace dir should be created");
        let segment_path = trace_dir.join("trace-segment-000001.jsonl");
        write_jsonl(
            &segment_path,
            &[
                event(
                    1,
                    RuntimeEvent::TraceStart(TraceStartEvent {
                        build_id: BuildId::from("build:test"),
                    }),
                ),
                event(
                    2,
                    RuntimeEvent::Checkpoint(CheckpointEvent {
                        checkpoint: CheckpointKind::Registered,
                    }),
                ),
                event(3, RuntimeEvent::TraceEnd(TraceEndEvent { event_count: 2 })),
            ],
        );
        fs::write(
            trace_dir.join("trace-index.json"),
            format!(
                r#"{{
  "schema_version": "bw.trace-index/0.1",
  "segments": [
    {{
      "path": "trace-segment-000001.jsonl",
      "event_start": 1,
      "event_end": 3,
      "event_count": 3,
      "sha256": "{}",
      "compressed": false
    }}
  ]
}}"#,
                "0".repeat(64)
            ),
        )
        .expect("trace index should be written");

        let output_path = temp.join("trace.jsonl");
        flatten_trace(&trace_dir, &output_path).expect("trace should flatten");

        let output = fs::read_to_string(&output_path).expect("trace should be readable");
        let events = output
            .lines()
            .map(|line| RuntimeEventEnvelope::from_json_str(line).expect("event should parse"))
            .collect::<Vec<_>>();
        assert_eq!(
            events.iter().map(|event| event.seq).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert!(matches!(
            &events[2].payload,
            RuntimeEvent::TraceEnd(TraceEndEvent { event_count: 3 })
        ));
        validate_runtime_path(&output_path, 1024 * 1024).expect("normalized trace should validate");

        fs::remove_dir_all(temp).expect("temp dir should be removed");
    }

    #[test]
    fn static_build_id_uses_first_static_fact_for_case_runtime_identity() {
        let temp = temp_dir("static-build-id");
        fs::create_dir_all(&temp).expect("temp dir should be created");
        let static_facts = temp.join("static.jsonl");
        fs::write(
            &static_facts,
            r#"{"schema_version":"bw.static/0.1","record_id":"fact:callback","producer":"test","build_id":"build:case-0001:bin","payload":{"kind":"callback_site","site_id":"site:callback","semantic_site_key":"semantic:callback","def_path":"main::{closure#0}"}}
"#,
        )
        .expect("static facts should be written");

        assert_eq!(
            static_build_id(&static_facts).expect("build id should parse"),
            Some("build:case-0001:bin".to_owned())
        );

        fs::remove_dir_all(temp).expect("temp dir should be removed");
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bw-rusqlite-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn write_jsonl(path: &Path, events: &[RuntimeEventEnvelope]) {
        let mut output = Vec::new();
        for event in events {
            serde_json::to_writer(&mut output, event).expect("event should serialize");
            output.push(b'\n');
        }
        fs::write(path, output).expect("segment should be written");
    }

    fn event(seq: u64, payload: RuntimeEvent) -> RuntimeEventEnvelope {
        RuntimeEventEnvelope {
            schema_version: TRACE_SCHEMA_V01.to_owned(),
            record_id: RecordId::from(format!("record:{seq}")),
            run_id: RunId::from("run:test"),
            trace_id: TraceId::from("trace:test"),
            seq,
            thread_id: "main".to_owned(),
            source: "test".to_owned(),
            payload,
        }
    }
}
