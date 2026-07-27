use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs::{self, File},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow};
use bw_blind_model::{
    BLIND_OBSERVED_SCHEMA_V01, BlindCaseId, BlindCaseObservation, BlindCaseStatus,
    BlindObservedFinding, BlindSplit, BlindWitnessEvidence,
};
use bw_model::{
    Finding, FindingClassification, RuntimeEvent, RuntimeEventEnvelope, StaticFactEnvelope,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const DEFAULT_CASE_ROOT: &str = "/case";
const ATTEMPT_COUNT: u32 = 20;

pub struct ObservationInput {
    pub suite_id: String,
    pub split: BlindSplit,
    pub case_id: BlindCaseId,
    pub method_commit: String,
    pub public_manifest_sha256: String,
    pub findings: Vec<(String, FindingClassification, String, bool)>,
    pub witness_path: Option<String>,
    pub witness_sha256: Option<String>,
    pub replay_attempts: u32,
    pub replay_successes: u32,
}

pub fn observation_from_findings(input: ObservationInput) -> Result<BlindCaseObservation> {
    let has_confirmed = input.findings.iter().any(|(_, classification, _, _)| {
        *classification == FindingClassification::ConfirmedViolation
    });
    let witness = if has_confirmed {
        Some(BlindWitnessEvidence {
            artifact_path: input
                .witness_path
                .ok_or_else(|| anyhow!("confirmed finding missing witness_path"))?,
            artifact_sha256: input
                .witness_sha256
                .ok_or_else(|| anyhow!("confirmed finding missing witness_sha256"))?,
            replay_attempts: input.replay_attempts,
            replay_successes: input.replay_successes,
        })
    } else {
        None
    };
    let observation = BlindCaseObservation {
        schema_version: BLIND_OBSERVED_SCHEMA_V01.to_owned(),
        suite_id: input.suite_id,
        split: input.split,
        case_id: input.case_id,
        method_commit: input.method_commit,
        public_manifest_sha256: input.public_manifest_sha256,
        status: BlindCaseStatus::Completed,
        findings: input
            .findings
            .into_iter()
            .map(
                |(rule_id, classification, normalized_signature, evidence_complete)| {
                    let normalized_signature =
                        public_normalized_signature(&rule_id, &normalized_signature);
                    BlindObservedFinding {
                        rule_id,
                        classification,
                        normalized_signature,
                        evidence_complete,
                    }
                },
            )
            .collect(),
        witness,
    };
    observation.validate(0)?;
    Ok(observation)
}

fn public_normalized_signature(rule_id: &str, analyzer_signature: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"bw-rusqlite-v3-adapter.public-signature/0.1\0");
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(analyzer_signature.as_bytes());
    hex_digest(hasher.finalize())
}

pub struct AdapterRunOptions {
    pub case_root: PathBuf,
    pub work_root: PathBuf,
    pub suite_id: String,
    pub split: BlindSplit,
    pub case_id: BlindCaseId,
    pub method_commit: String,
    pub public_manifest_sha256: String,
}

pub struct AttemptResult {
    pub attempt: u32,
    pub attempt_dir: PathBuf,
    pub findings: Vec<Finding>,
}

#[derive(serde::Deserialize)]
struct TraceIndex {
    schema_version: String,
    segments: Vec<TraceSegment>,
}

#[derive(serde::Deserialize)]
struct TraceSegment {
    path: String,
    compressed: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WitnessDocument {
    schema_version: String,
    case_id: String,
    replay_attempts: u32,
    replay_successes: u32,
    confirmed_signatures: Vec<String>,
    attempt_dirs: Vec<String>,
}

pub fn run_from_env() -> Result<()> {
    let case_root = std::env::var("BW_RUSQLITE_V3_CASE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CASE_ROOT));
    let work_root = PathBuf::from(required_env("BW_CHILD_WORK_DIR")?);
    let options = AdapterRunOptions {
        case_root,
        work_root,
        suite_id: required_env("BW_BLIND_SUITE_ID")?,
        split: parse_split(&required_env("BW_BLIND_SPLIT")?)?,
        case_id: BlindCaseId::parse(&required_env("BW_BLIND_CASE_ID")?)?,
        method_commit: required_env("BW_BLIND_METHOD_COMMIT")?,
        public_manifest_sha256: required_env("BW_BLIND_MANIFEST_SHA256")?,
    };
    run_adapter(options)
}

pub fn run_adapter(options: AdapterRunOptions) -> Result<()> {
    let payload = PayloadPaths::new(&options.case_root);
    payload.ensure_files()?;
    fs::create_dir_all(&options.work_root).with_context(|| {
        format!(
            "create adapter work directory {}",
            options.work_root.display()
        )
    })?;
    let build_id = read_static_build_id(&payload.static_facts)?;
    let first = run_once(&payload, &options.work_root, &options, &build_id, 0)?;
    let confirmed = confirmed_signatures(&first.findings);
    let (witness_path, witness_sha256, replay_attempts, replay_successes) = if confirmed.is_empty()
    {
        (None, None, 0, 0)
    } else {
        let mut attempt_dirs = vec![relative_attempt_dir(0)];
        for attempt in 1..ATTEMPT_COUNT {
            let replay = run_once(&payload, &options.work_root, &options, &build_id, attempt)?;
            let replay_signatures = confirmed_signatures(&replay.findings);
            if replay_signatures != confirmed {
                anyhow::bail!(
                    "replay {attempt} confirmed signature mismatch: expected {:?}, got {:?}",
                    confirmed,
                    replay_signatures
                );
            }
            attempt_dirs.push(relative_attempt_dir(attempt));
        }
        let witness_dir = options.work_root.join("witness");
        fs::create_dir_all(&witness_dir)
            .with_context(|| format!("create witness directory {}", witness_dir.display()))?;
        let witness_path = witness_dir.join("witness.json");
        let witness = WitnessDocument {
            schema_version: "bw.rusqlite-v3-witness/0.1".to_owned(),
            case_id: options.case_id.as_str().to_owned(),
            replay_attempts: ATTEMPT_COUNT,
            replay_successes: ATTEMPT_COUNT,
            confirmed_signatures: confirmed.iter().cloned().collect(),
            attempt_dirs,
        };
        fs::write(&witness_path, serde_json::to_vec_pretty(&witness)?)
            .with_context(|| format!("write witness {}", witness_path.display()))?;
        (
            Some("witness/witness.json".to_owned()),
            Some(sha256_file(&witness_path)?),
            ATTEMPT_COUNT,
            ATTEMPT_COUNT,
        )
    };
    let observation = observation_from_findings(ObservationInput {
        suite_id: options.suite_id,
        split: options.split,
        case_id: options.case_id,
        method_commit: options.method_commit,
        public_manifest_sha256: options.public_manifest_sha256,
        findings: first
            .findings
            .into_iter()
            .map(|finding| {
                (
                    finding.rule_id,
                    finding.classification,
                    finding.normalized_signature,
                    !finding.evidence.is_empty(),
                )
            })
            .collect(),
        witness_path,
        witness_sha256,
        replay_attempts,
        replay_successes,
    })?;
    let observation_path = options.work_root.join("observation.json");
    fs::write(&observation_path, serde_json::to_vec_pretty(&observation)?)
        .with_context(|| format!("write observation {}", observation_path.display()))?;
    Ok(())
}

fn required_env(key: &str) -> Result<String> {
    let value = std::env::var(key).with_context(|| format!("read required env {key}"))?;
    if value.trim().is_empty() {
        anyhow::bail!("{key} must be non-empty");
    }
    Ok(value)
}

fn parse_split(value: &str) -> Result<BlindSplit> {
    match value {
        "gate" => Ok(BlindSplit::Gate),
        "evaluation" => Ok(BlindSplit::Evaluation),
        _ => Err(anyhow!("BW_BLIND_SPLIT must be gate or evaluation")),
    }
}

pub struct PayloadPaths {
    case_executable: PathBuf,
    bw_binary: PathBuf,
    static_facts: PathBuf,
    contract: PathBuf,
}

impl PayloadPaths {
    fn new(case_root: &Path) -> Self {
        let payload = case_root.join("payload");
        Self {
            case_executable: payload.join("bin/case"),
            bw_binary: payload.join("bin/bw"),
            static_facts: payload.join("static-facts.jsonl"),
            contract: payload.join("contract.toml"),
        }
    }

    fn ensure_files(&self) -> Result<()> {
        for path in [
            &self.case_executable,
            &self.bw_binary,
            &self.static_facts,
            &self.contract,
        ] {
            if !path.is_file() {
                anyhow::bail!("missing payload file {}", path.display());
            }
        }
        Ok(())
    }
}

pub fn run_once(
    payload: &PayloadPaths,
    work_root: &Path,
    options: &AdapterRunOptions,
    build_id: &str,
    attempt: u32,
) -> Result<AttemptResult> {
    let attempt_dir = work_root.join("attempts").join(attempt.to_string());
    let trace_dir = attempt_dir.join("trace");
    fs::create_dir_all(&trace_dir)
        .with_context(|| format!("create trace directory {}", trace_dir.display()))?;
    let child_output = Command::new(&payload.case_executable)
        .env(
            "BW_RUN_ID",
            format!("{}:{}:attempt-{attempt}", options.suite_id, options.case_id),
        )
        .env(
            "BW_TRACE_ID",
            format!("{}:trace:{attempt}", options.case_id),
        )
        .env("BW_TRACE_DIR", &trace_dir)
        .env("BW_TRACE_COMPRESS", "0")
        .env("BW_BUILD_ID", build_id)
        .output()
        .with_context(|| format!("run payload case {}", payload.case_executable.display()))?;
    fs::write(attempt_dir.join("stdout.log"), &child_output.stdout)
        .with_context(|| format!("write attempt stdout {}", attempt_dir.display()))?;
    fs::write(attempt_dir.join("stderr.log"), &child_output.stderr)
        .with_context(|| format!("write attempt stderr {}", attempt_dir.display()))?;
    if !child_output.status.success() {
        anyhow::bail!("payload case exited with {}", child_output.status);
    }

    let trace_path = attempt_dir.join("trace.jsonl");
    flatten_trace(&trace_dir, &trace_path)?;
    let findings_path = attempt_dir.join("findings.jsonl");
    let analyze_output = Command::new(&payload.bw_binary)
        .arg("analyze")
        .arg("--static")
        .arg(&payload.static_facts)
        .arg("--contract")
        .arg(&payload.contract)
        .arg("--trace")
        .arg(&trace_path)
        .arg("--output")
        .arg(&findings_path)
        .output()
        .with_context(|| format!("run analyzer {}", payload.bw_binary.display()))?;
    fs::write(
        attempt_dir.join("analyze.stdout.log"),
        &analyze_output.stdout,
    )
    .with_context(|| format!("write analyze stdout {}", attempt_dir.display()))?;
    fs::write(
        attempt_dir.join("analyze.stderr.log"),
        &analyze_output.stderr,
    )
    .with_context(|| format!("write analyze stderr {}", attempt_dir.display()))?;
    if !matches!(analyze_output.status.code(), Some(0 | 1)) {
        anyhow::bail!("bw analyze exited with {}", analyze_output.status);
    }
    let findings = read_findings(&findings_path)?;
    Ok(AttemptResult {
        attempt,
        attempt_dir,
        findings,
    })
}

fn read_static_build_id(path: &Path) -> Result<String> {
    let input =
        File::open(path).with_context(|| format!("open static facts {}", path.display()))?;
    for (line_number, line) in BufReader::new(input).lines().enumerate() {
        let line = line.with_context(|| format!("read static facts {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let fact = StaticFactEnvelope::from_json_str(&line)
            .with_context(|| format!("parse static fact {}:{}", path.display(), line_number + 1))?;
        return Ok(fact.build_id.to_string());
    }
    Err(anyhow!(
        "static facts {} did not contain a build_id",
        path.display()
    ))
}

fn flatten_trace(trace_dir: &Path, output_path: &Path) -> Result<()> {
    let index_path = trace_dir.join("trace-index.json");
    let index_text = fs::read_to_string(&index_path)
        .with_context(|| format!("read trace index {}", index_path.display()))?;
    let index: TraceIndex = serde_json::from_str(&index_text)
        .with_context(|| format!("parse trace index {}", index_path.display()))?;
    if index.schema_version != "bw.trace-index/0.1" {
        anyhow::bail!("unsupported trace index schema {}", index.schema_version);
    }
    let mut events = Vec::new();
    for segment in index.segments {
        if segment.compressed {
            anyhow::bail!("compressed trace segment is unsupported: {}", segment.path);
        }
        let segment_path = trace_dir.join(&segment.path);
        let input = File::open(&segment_path)
            .with_context(|| format!("open trace segment {}", segment_path.display()))?;
        for (line_number, line) in BufReader::new(input).lines().enumerate() {
            let line =
                line.with_context(|| format!("read trace segment {}", segment_path.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            let event = RuntimeEventEnvelope::from_json_str(&line).with_context(|| {
                format!(
                    "parse trace segment {}:{}",
                    segment_path.display(),
                    line_number + 1
                )
            })?;
            events.push(event);
        }
    }
    let event_count = events.len() as u64;
    let mut output = String::new();
    for (seq, event) in events.iter_mut().enumerate() {
        event.seq = seq as u64;
        if let RuntimeEvent::TraceEnd(ended) = &mut event.payload {
            ended.event_count = event_count;
        }
        output.push_str(&serde_json::to_string(event)?);
        output.push('\n');
    }
    fs::write(output_path, output)
        .with_context(|| format!("write flattened trace {}", output_path.display()))
}

fn read_findings(path: &Path) -> Result<Vec<Finding>> {
    let input = File::open(path).with_context(|| format!("open findings {}", path.display()))?;
    let mut findings = Vec::new();
    for (line_number, line) in BufReader::new(input).lines().enumerate() {
        let line = line.with_context(|| format!("read findings {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        findings
            .push(Finding::from_json_str(&line).with_context(|| {
                format!("parse finding {}:{}", path.display(), line_number + 1)
            })?);
    }
    Ok(findings)
}

fn confirmed_signatures(findings: &[Finding]) -> BTreeSet<String> {
    findings
        .iter()
        .filter(|finding| finding.classification == FindingClassification::ConfirmedViolation)
        .map(|finding| finding.normalized_signature.clone())
        .collect()
}

fn relative_attempt_dir(attempt: u32) -> String {
    format!("attempts/{attempt}")
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(hex_digest(Sha256::digest(bytes)))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
