use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use bw_blind_model::{
    BLIND_OBSERVED_SCHEMA_V01, BlindCaseId, BlindCaseObservation, BlindCaseStatus,
    BlindObservedFinding, BlindPolicy, BlindPublicManifest, BlindSplit, BlindWitnessEvidence,
    FormalIsolationBackend, InstallReceipt, RunnerReceipt, TestReceiptKey,
};
use bw_model::RunManifest;
use sha2::{Digest, Sha256};

use crate::{
    BLIND_GROUND_TRUTH_SCHEMA_V01, BlindGroundTruth, CuratorError, Result, TruthRole,
    run_snapshot::VerifiedRunSnapshot,
};

pub const BLIND_REVEAL_SCHEMA_V01: &str = "boundary-witness.blind-reveal/0.1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevealOptions {
    pub public_manifest: PathBuf,
    pub policy: PathBuf,
    pub run_directory: PathBuf,
    pub ground_truth: PathBuf,
    pub install_receipt: PathBuf,
    pub runner_receipt: PathBuf,
    pub receipt_key: TestReceiptKey,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct RevealReport {
    schema_version: String,
    suite_id: String,
    split: BlindSplit,
    method_commit: String,
    public_manifest_sha256: String,
    policy_sha256: String,
    ground_truth_sha256: String,
    run_id: String,
    deployment_sha256: String,
    run_checksums_sha256: String,
    observations_sha256: String,
    total_cases: usize,
    cases: Vec<RevealedCase>,
    integrity_errors: Vec<String>,
    #[serde(skip)]
    verified_policy: BlindPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct RevealedCase {
    case_id: BlindCaseId,
    curator_key: String,
    role: TruthRole,
    component: String,
    api: String,
    root_cause_key: String,
    paired_case_ids: Vec<BlindCaseId>,
    source_revision: String,
    status: BlindCaseStatus,
    findings: Vec<BlindObservedFinding>,
    witness: Option<BlindWitnessEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct GateDecision {
    pub schema_version: String,
    pub suite_id: String,
    pub split: BlindSplit,
    pub method_commit: String,
    pub public_manifest_sha256: String,
    pub deployment_sha256: String,
    pub run_id: String,
    pub run_checksums_sha256: String,
    pub observations_sha256: String,
    pub reveal_report_sha256: String,
    pub gate_passed: bool,
    pub minimum_confirmed_cases: u32,
    pub passed_violation_cases: u32,
    pub confirmed_root_causes: Vec<String>,
    pub control_failures: Vec<String>,
    pub incomplete_cases: Vec<String>,
}

pub fn reveal(options: RevealOptions) -> Result<RevealReport> {
    let manifest_bytes = read(&options.public_manifest)?;
    let manifest = BlindPublicManifest::parse_json(utf8(
        &manifest_bytes,
        "public manifest must be valid UTF-8",
    )?)?;
    let public_manifest_sha256 = sha256_hex(&manifest_bytes);

    let policy_bytes = read(&options.policy)?;
    let policy_sha256 = sha256_hex(&policy_bytes);
    let policy = BlindPolicy::parse_toml(utf8(&policy_bytes, "policy must be valid UTF-8")?)?;
    let ground_truth_bytes = read(&options.ground_truth)?;
    let ground_truth_sha256 = sha256_hex(&ground_truth_bytes);
    let ground_truth: BlindGroundTruth = serde_json::from_slice(&ground_truth_bytes)?;
    let run_evidence = VerifiedRunSnapshot::capture(&options.run_directory)?;
    let run_manifest = RunManifest::from_json_str(utf8(
        &run_evidence.manifest_bytes,
        "run manifest must be valid UTF-8",
    )?)?;
    let run_summary: serde_json::Value = serde_json::from_slice(&run_evidence.summary_bytes)?;
    if run_manifest.completed_at_utc.is_none() {
        return Err(validation("reveal requires a finalized run manifest"));
    }
    let observations = read_observations_bytes(&run_evidence.observations_bytes)?;
    verify_receipts(
        &options,
        &run_evidence,
        &run_manifest,
        &manifest,
        &observations,
        &public_manifest_sha256,
        &policy_sha256,
    )?;

    let mut integrity_errors = Vec::new();
    if manifest.policy_sha256 != policy_sha256 {
        integrity_errors.push("policy digest mismatch".to_owned());
    }
    validate_run_identity(
        &run_manifest,
        &run_summary,
        &manifest,
        &public_manifest_sha256,
        &run_evidence,
        observations.len(),
        &mut integrity_errors,
    );
    validate_ground_truth_identity(
        &ground_truth,
        &manifest,
        &public_manifest_sha256,
        &mut integrity_errors,
    );
    validate_observation_identities(
        &observations,
        &manifest,
        &public_manifest_sha256,
        &mut integrity_errors,
    );
    validate_observation_evidence(&observations, &policy, &run_evidence, &mut integrity_errors);

    let manifest_ids = manifest
        .cases
        .iter()
        .map(|case| case.case_id.clone())
        .collect::<BTreeSet<_>>();
    let truth_by_id = collect_truth_cases(&ground_truth, &mut integrity_errors);
    let observations_by_id = collect_observations(observations, &mut integrity_errors);
    validate_one_to_one_ids(
        &manifest_ids,
        &truth_by_id,
        &observations_by_id,
        &mut integrity_errors,
    );
    validate_truth_pairs(&truth_by_id, &mut integrity_errors);

    if !integrity_errors.is_empty() {
        return Err(validation(integrity_errors.join("; ")));
    }

    let mut cases = Vec::with_capacity(manifest_ids.len());
    for case_id in manifest_ids {
        let truth = truth_by_id
            .get(&case_id)
            .expect("case identity was checked before reveal");
        let observation = observations_by_id
            .get(&case_id)
            .expect("case identity was checked before reveal");
        cases.push(RevealedCase {
            case_id,
            curator_key: truth.curator_key.clone(),
            role: truth.role.clone(),
            component: truth.component.clone(),
            api: truth.api.clone(),
            root_cause_key: truth.root_cause_key.clone(),
            paired_case_ids: truth.paired_case_ids.clone(),
            source_revision: truth.source_revision.clone(),
            status: observation.status,
            findings: observation.findings.clone(),
            witness: observation.witness.clone(),
        });
    }

    Ok(RevealReport {
        schema_version: BLIND_REVEAL_SCHEMA_V01.to_owned(),
        suite_id: manifest.suite_id,
        split: manifest.split,
        method_commit: manifest.method_commit,
        public_manifest_sha256,
        policy_sha256,
        ground_truth_sha256,
        run_id: run_manifest.run_id.0,
        deployment_sha256: run_manifest.deployment_sha256,
        run_checksums_sha256: run_evidence.checksums_sha256,
        observations_sha256: sha256_hex(&run_evidence.observations_bytes),
        total_cases: cases.len(),
        cases,
        integrity_errors: Vec::new(),
        verified_policy: policy,
    })
}

impl RevealReport {
    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    #[must_use]
    pub fn suite_id(&self) -> &str {
        &self.suite_id
    }

    #[must_use]
    pub const fn split(&self) -> BlindSplit {
        self.split
    }

    #[must_use]
    pub fn method_commit(&self) -> &str {
        &self.method_commit
    }

    #[must_use]
    pub fn public_manifest_sha256(&self) -> &str {
        &self.public_manifest_sha256
    }

    #[must_use]
    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    #[must_use]
    pub fn ground_truth_sha256(&self) -> &str {
        &self.ground_truth_sha256
    }

    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    #[must_use]
    pub fn deployment_sha256(&self) -> &str {
        &self.deployment_sha256
    }

    #[must_use]
    pub fn run_checksums_sha256(&self) -> &str {
        &self.run_checksums_sha256
    }

    #[must_use]
    pub fn observations_sha256(&self) -> &str {
        &self.observations_sha256
    }

    #[must_use]
    pub const fn total_cases(&self) -> usize {
        self.total_cases
    }

    #[must_use]
    pub fn cases(&self) -> &[RevealedCase] {
        &self.cases
    }
}

impl RevealedCase {
    #[must_use]
    pub const fn case_id(&self) -> &BlindCaseId {
        &self.case_id
    }

    #[must_use]
    pub fn curator_key(&self) -> &str {
        &self.curator_key
    }

    #[must_use]
    pub const fn role(&self) -> &TruthRole {
        &self.role
    }

    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    #[must_use]
    pub fn api(&self) -> &str {
        &self.api
    }

    #[must_use]
    pub fn root_cause_key(&self) -> &str {
        &self.root_cause_key
    }

    #[must_use]
    pub fn paired_case_ids(&self) -> &[BlindCaseId] {
        &self.paired_case_ids
    }

    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    #[must_use]
    pub const fn status(&self) -> BlindCaseStatus {
        self.status
    }

    #[must_use]
    pub fn findings(&self) -> &[BlindObservedFinding] {
        &self.findings
    }

    #[must_use]
    pub const fn witness(&self) -> Option<&BlindWitnessEvidence> {
        self.witness.as_ref()
    }
}

impl GateDecision {
    pub fn from_reveal(report: &RevealReport, policy: &BlindPolicy) -> Result<Self> {
        policy.validate()?;
        if policy != &report.verified_policy {
            return Err(validation(
                "policy does not match policy verified during reveal",
            ));
        }
        if report.split != BlindSplit::Gate {
            return Err(validation("gate decision requires gate split"));
        }
        if !report.integrity_errors.is_empty() {
            return Err(validation(format!(
                "gate decision requires an integrity-clean reveal: {}",
                report.integrity_errors.join("; ")
            )));
        }

        let cases_by_id = report
            .cases
            .iter()
            .map(|case| (&case.case_id, case))
            .collect::<BTreeMap<_, _>>();
        let mut passed_violation_cases = 0;
        let mut confirmed_root_causes = BTreeSet::new();
        let mut incomplete_cases = Vec::new();

        for case in report
            .cases
            .iter()
            .filter(|case| case.role == TruthRole::Violation)
        {
            if violation_passes(case, policy) {
                passed_violation_cases += 1;
                confirmed_root_causes.insert(case.root_cause_key.clone());
            } else {
                incomplete_cases.push(case.case_id.to_string());
            }
        }

        let mut control_failures = Vec::new();
        for control in report
            .cases
            .iter()
            .filter(|case| matches!(case.role, TruthRole::SafeControl | TruthRole::FixedControl))
        {
            if control.status != BlindCaseStatus::Completed {
                let case_id = control.case_id.to_string();
                control_failures.push(case_id.clone());
                incomplete_cases.push(case_id);
                continue;
            }
            let paired_violation_rule_ids = control
                .paired_case_ids
                .iter()
                .filter_map(|case_id| cases_by_id.get(case_id))
                .filter(|case| case.role == TruthRole::Violation)
                .flat_map(|case| confirmed_rule_ids(case))
                .collect::<BTreeSet<_>>();
            if confirmed_rule_ids(control)
                .any(|rule_id| paired_violation_rule_ids.contains(rule_id))
            {
                control_failures.push(control.case_id.to_string());
            }
        }

        incomplete_cases.sort();
        incomplete_cases.dedup();

        let gate_passed = passed_violation_cases >= policy.gate_minimum_confirmed_cases
            && control_failures.is_empty();
        Ok(Self {
            schema_version: BLIND_REVEAL_SCHEMA_V01.to_owned(),
            suite_id: report.suite_id.clone(),
            split: report.split,
            method_commit: report.method_commit.clone(),
            public_manifest_sha256: report.public_manifest_sha256.clone(),
            deployment_sha256: report.deployment_sha256.clone(),
            run_id: report.run_id.clone(),
            run_checksums_sha256: report.run_checksums_sha256.clone(),
            observations_sha256: report.observations_sha256.clone(),
            reveal_report_sha256: reveal_report_sha256(report)?,
            gate_passed,
            minimum_confirmed_cases: policy.gate_minimum_confirmed_cases,
            passed_violation_cases,
            confirmed_root_causes: confirmed_root_causes.into_iter().collect(),
            control_failures,
            incomplete_cases,
        })
    }
}

fn verify_receipts(
    options: &RevealOptions,
    snapshot: &VerifiedRunSnapshot,
    run: &RunManifest,
    manifest: &BlindPublicManifest,
    observations: &[BlindCaseObservation],
    public_manifest_sha256: &str,
    policy_sha256: &str,
) -> Result<()> {
    let install_bytes =
        read(&options.install_receipt).map_err(|_| validation("install receipt is required"))?;
    let install: InstallReceipt = serde_json::from_slice(&install_bytes)?;
    install.verify(&options.receipt_key)?;

    let external_runner_bytes =
        read(&options.runner_receipt).map_err(|_| validation("runner receipt is required"))?;
    if external_runner_bytes != snapshot.runner_receipt_bytes {
        return Err(validation(
            "runner receipt does not match finalized run receipt",
        ));
    }
    let runner: RunnerReceipt = serde_json::from_slice(&snapshot.runner_receipt_bytes)?;
    if runner.isolation_backend == FormalIsolationBackend::NativeUntrustedSmoke {
        return Err(validation("formal reveal requires trusted isolation"));
    }
    runner.verify(&options.receipt_key)?;

    let install_sha256 = sha256_hex(&install_bytes);
    let observations_sha256 = sha256_hex(&snapshot.observations_bytes);
    let manifest_case_count = u64::try_from(manifest.cases.len())
        .map_err(|_| validation("public manifest case_count exceeds u64"))?;
    let observation_count = u64::try_from(observations.len())
        .map_err(|_| validation("consumed observation count exceeds u64"))?;
    if runner.case_count != manifest_case_count {
        return Err(validation(
            "runner receipt case_count mismatch with public manifest",
        ));
    }
    if runner.case_count != observation_count {
        return Err(validation(
            "runner receipt case_count mismatch with consumed observations",
        ));
    }
    let expected_execution_snapshot_digest =
        case_execution_snapshot_digest(manifest, public_manifest_sha256);
    let expected = [
        (
            "install receipt method_commit mismatch",
            install.method_commit.as_str(),
            run.git_commit.as_str(),
        ),
        (
            "install receipt public_manifest_sha256 mismatch",
            install.public_manifest_sha256.as_str(),
            public_manifest_sha256,
        ),
        (
            "install receipt policy_sha256 mismatch",
            install.policy_sha256.as_str(),
            policy_sha256,
        ),
        (
            "install receipt archive_sha256 mismatch",
            install.archive_sha256.as_str(),
            run.deployment_sha256.as_str(),
        ),
        (
            "runner receipt run_id mismatch",
            runner.run_id.as_str(),
            snapshot.run_id.as_str(),
        ),
        (
            "runner receipt suite_id mismatch",
            runner.suite_id.as_str(),
            manifest.suite_id.as_str(),
        ),
        (
            "runner receipt split mismatch",
            runner.split.as_str(),
            split_name(manifest.split),
        ),
        (
            "runner receipt method_commit mismatch",
            runner.method_commit.as_str(),
            run.git_commit.as_str(),
        ),
        (
            "runner receipt public_manifest_sha256 mismatch",
            runner.public_manifest_sha256.as_str(),
            public_manifest_sha256,
        ),
        (
            "runner receipt policy_sha256 mismatch",
            runner.policy_sha256.as_str(),
            policy_sha256,
        ),
        (
            "runner receipt case_execution_snapshot_digest mismatch",
            runner.case_execution_snapshot_digest.as_str(),
            expected_execution_snapshot_digest.as_str(),
        ),
        (
            "runner receipt archive_sha256 mismatch",
            runner.archive_sha256.as_str(),
            run.deployment_sha256.as_str(),
        ),
        (
            "runner receipt observations_sha256 mismatch",
            runner.observations_sha256.as_str(),
            observations_sha256.as_str(),
        ),
        (
            "runner receipt run evidence checksum mismatch",
            runner.run_checksums_sha256.as_str(),
            snapshot.checksums_sha256.as_str(),
        ),
        (
            "runner receipt install receipt checksum mismatch",
            runner.install_receipt_sha256.as_str(),
            install_sha256.as_str(),
        ),
    ];
    for (message, actual, expected) in expected {
        if actual != expected {
            return Err(validation(message));
        }
    }
    Ok(())
}

fn case_execution_snapshot_digest(
    manifest: &BlindPublicManifest,
    public_manifest_sha256: &str,
) -> String {
    let mut cases = manifest.cases.iter().collect::<Vec<_>>();
    cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));

    let mut hasher = Sha256::new();
    hasher.update(public_manifest_sha256.as_bytes());
    hasher.update([0]);
    for case in cases {
        hasher.update(case.case_id.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(case.case_sha256.as_bytes());
        hasher.update([0]);
    }
    sha256_hex(&hasher.finalize())
}

fn validate_run_identity(
    run: &RunManifest,
    summary: &serde_json::Value,
    manifest: &BlindPublicManifest,
    manifest_sha256: &str,
    snapshot: &VerifiedRunSnapshot,
    observation_count: usize,
    errors: &mut Vec<String>,
) {
    if run.git_commit != manifest.method_commit {
        errors.push("run method commit mismatch".to_owned());
    }
    if run.config_digest != manifest_sha256 {
        errors.push("run public manifest digest mismatch".to_owned());
    }
    if !is_sha256(&run.deployment_sha256) {
        errors.push("run deployment digest is invalid".to_owned());
    }
    if snapshot.run_id != run.run_id.0 {
        errors.push("run directory name does not match run manifest run_id".to_owned());
    }
    let user_summary = &summary["user_summary"];
    if summary["schema_version"] != "boundary-witness.run-integrity/0.1"
        || summary["status"] != "finalized"
        || summary["run_id"] != run.run_id.0
        || user_summary["schema_version"] != "boundary-witness.blind-run/0.1"
        || user_summary["suite_id"] != manifest.suite_id
        || user_summary["split"] != split_name(manifest.split)
        || user_summary["case_count"] != observation_count
        || user_summary["method_commit"] != manifest.method_commit
        || user_summary["public_manifest_sha256"] != manifest_sha256
        || user_summary["deployment_sha256"] != run.deployment_sha256
    {
        errors.push("run summary is not bound to blind run identity".to_owned());
    }
}

fn validate_observation_evidence(
    observations: &[BlindCaseObservation],
    policy: &BlindPolicy,
    snapshot: &VerifiedRunSnapshot,
    errors: &mut Vec<String>,
) {
    for observation in observations {
        if let Err(error) = observation.validate(policy.minimum_replay_attempts) {
            errors.push(format!(
                "observation {} failed validation: {error}",
                observation.case_id
            ));
            continue;
        }
        let Some(witness) = &observation.witness else {
            continue;
        };
        let path = format!("artifacts/{}", witness.artifact_path);
        match snapshot.file(&path) {
            Some(bytes) if sha256_hex(bytes) == witness.artifact_sha256 => {}
            Some(_) => errors.push(format!(
                "observation {} witness artifact digest mismatch",
                observation.case_id
            )),
            None => {
                errors.push(format!(
                    "observation {} witness is not a checksummed run artifact",
                    observation.case_id
                ));
            }
        }
    }
}

const fn split_name(split: BlindSplit) -> &'static str {
    match split {
        BlindSplit::Gate => "gate",
        BlindSplit::Evaluation => "evaluation",
    }
}

fn reveal_report_sha256(report: &RevealReport) -> Result<String> {
    let mut bytes = serde_json::to_vec_pretty(report)?;
    bytes.push(b'\n');
    Ok(sha256_hex(&bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn violation_passes(case: &RevealedCase, policy: &BlindPolicy) -> bool {
    case.status == BlindCaseStatus::Completed
        && case.findings.iter().any(|finding| {
            finding.classification == bw_model::FindingClassification::ConfirmedViolation
                && finding.evidence_complete
        })
        && case.witness.as_ref().is_some_and(|witness| {
            witness.replay_attempts >= policy.minimum_replay_attempts
                && witness.replay_successes == witness.replay_attempts
        })
}

fn confirmed_rule_ids(case: &RevealedCase) -> impl Iterator<Item = &str> {
    case.findings.iter().filter_map(|finding| {
        (finding.classification == bw_model::FindingClassification::ConfirmedViolation)
            .then_some(finding.rule_id.as_str())
    })
}

fn validate_ground_truth_identity(
    ground_truth: &BlindGroundTruth,
    manifest: &BlindPublicManifest,
    manifest_sha256: &str,
    errors: &mut Vec<String>,
) {
    if ground_truth.schema_version != BLIND_GROUND_TRUTH_SCHEMA_V01 {
        errors.push("unsupported blind ground-truth schema_version".to_owned());
    }
    if ground_truth.suite_id != manifest.suite_id {
        errors.push("ground truth suite ID mismatch".to_owned());
    }
    if ground_truth.split != manifest.split {
        errors.push("ground truth split mismatch".to_owned());
    }
    if ground_truth.public_manifest_sha256 != manifest_sha256 {
        errors.push("ground truth public manifest digest mismatch".to_owned());
    }
}

fn validate_observation_identities(
    observations: &[BlindCaseObservation],
    manifest: &BlindPublicManifest,
    manifest_sha256: &str,
    errors: &mut Vec<String>,
) {
    for observation in observations {
        let case_id = &observation.case_id;
        if observation.schema_version != BLIND_OBSERVED_SCHEMA_V01 {
            errors.push(format!(
                "observation {case_id} has unsupported schema_version"
            ));
        }
        if observation.suite_id != manifest.suite_id {
            errors.push(format!("observation {case_id} suite ID mismatch"));
        }
        if observation.split != manifest.split {
            errors.push(format!("observation {case_id} split mismatch"));
        }
        if observation.method_commit != manifest.method_commit {
            errors.push(format!("observation {case_id} method commit mismatch"));
        }
        if observation.public_manifest_sha256 != manifest_sha256 {
            errors.push(format!(
                "observation {case_id} public manifest digest mismatch"
            ));
        }
    }
}

fn collect_truth_cases<'a>(
    truth: &'a BlindGroundTruth,
    errors: &mut Vec<String>,
) -> BTreeMap<BlindCaseId, &'a crate::BlindTruthCase> {
    let mut by_id = BTreeMap::new();
    for case in &truth.cases {
        if by_id.insert(case.case_id.clone(), case).is_some() {
            errors.push(format!("duplicate ground-truth case: {}", case.case_id));
        }
    }
    by_id
}

fn collect_observations(
    observations: Vec<BlindCaseObservation>,
    errors: &mut Vec<String>,
) -> BTreeMap<BlindCaseId, BlindCaseObservation> {
    let mut by_id = BTreeMap::new();
    for observation in observations {
        let case_id = observation.case_id.clone();
        if by_id.insert(case_id.clone(), observation).is_some() {
            errors.push(format!("duplicate observation case: {case_id}"));
        }
    }
    by_id
}

fn validate_one_to_one_ids(
    manifest_ids: &BTreeSet<BlindCaseId>,
    truth_by_id: &BTreeMap<BlindCaseId, &crate::BlindTruthCase>,
    observations_by_id: &BTreeMap<BlindCaseId, BlindCaseObservation>,
    errors: &mut Vec<String>,
) {
    let truth_ids = truth_by_id.keys().cloned().collect::<BTreeSet<_>>();
    let observation_ids = observations_by_id.keys().cloned().collect::<BTreeSet<_>>();
    for case_id in manifest_ids.difference(&truth_ids) {
        errors.push(format!("missing ground-truth case: {case_id}"));
    }
    for case_id in truth_ids.difference(manifest_ids) {
        errors.push(format!("extra ground-truth case: {case_id}"));
    }
    for case_id in manifest_ids.difference(&observation_ids) {
        errors.push(format!("missing observation case: {case_id}"));
    }
    for case_id in observation_ids.difference(manifest_ids) {
        errors.push(format!("extra observation case: {case_id}"));
    }
}

fn validate_truth_pairs(
    truth_by_id: &BTreeMap<BlindCaseId, &crate::BlindTruthCase>,
    errors: &mut Vec<String>,
) {
    for case in truth_by_id.values() {
        let mut paired_ids = BTreeSet::new();
        for paired_id in &case.paired_case_ids {
            if !paired_ids.insert(paired_id) {
                errors.push(format!(
                    "ground-truth case {} has duplicate paired case: {paired_id}",
                    case.case_id
                ));
            }
            let Some(paired) = truth_by_id.get(paired_id) else {
                errors.push(format!(
                    "ground-truth case {} references missing paired case: {paired_id}",
                    case.case_id
                ));
                continue;
            };
            if !paired.paired_case_ids.contains(&case.case_id) {
                errors.push(format!(
                    "ground-truth pairing is not reciprocal: {} -> {paired_id}",
                    case.case_id
                ));
            }
        }
    }
}

fn read_observations_bytes(input: &[u8]) -> Result<Vec<BlindCaseObservation>> {
    let text = utf8(input, "observations JSONL must be valid UTF-8")?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(CuratorError::from))
        .collect()
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| CuratorError::Read {
        path: path.to_owned(),
        source,
    })
}

fn utf8<'a>(bytes: &'a [u8], message: &str) -> Result<&'a str> {
    std::str::from_utf8(bytes).map_err(|_| validation(message))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validation(message: impl Into<String>) -> CuratorError {
    CuratorError::Validation(message.into())
}
