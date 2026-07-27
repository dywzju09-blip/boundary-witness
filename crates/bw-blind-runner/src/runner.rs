use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use bw_blind_model::{
    BLIND_OBSERVED_SCHEMA_V01, BlindCaseObservation, BlindCaseStatus, BlindPolicy, BlindPublicCase,
    BlindPublicManifest, BlindSplit, FormalIsolationBackend, TestReceiptKey,
};
use bw_experiment::{
    ChildRunner, ChildSpec, ChildStatus, FinalizeRun, FinalizedRun, RunDirectory, RunMetadata,
    generate_run_id, verify_run_integrity,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    AuditError, Result,
    audit::ensure_pack_root_path_is_safe,
    audit_public_pack,
    execution_snapshot::ExecutionPackSnapshot,
    isolation::IsolationExecutor,
    output_scan::{scan_child_output, scan_finalized_candidate, scan_summary_value},
    provenance::{
        RunnerReceiptOptions, bind_runner_provenance_to_audit, build_runner_receipt,
        runner_evidence_digest, sha256_file, sha256_tree, verify_install_receipt,
        verify_pre_audit_runner_provenance,
    },
};

pub struct RunOptions {
    pub public_pack_root: PathBuf,
    pub runs_root: PathBuf,
    pub metadata: RunMetadata,
    pub install_receipt: PathBuf,
    pub receipt_key: TestReceiptKey,
    pub isolation_backend: FormalIsolationBackend,
    /// Commit of the runner binary/source, distinct from the public method commit.
    pub runner_commit: String,
    /// Stable identity of the machine or service running the runner binary.
    pub runner_host_id: String,
}

pub struct BlindRunReport {
    pub final_run: FinalizedRun,
    pub suite_id: String,
    pub split: BlindSplit,
    pub case_count: usize,
    pub completed_count: usize,
    pub failed_count: usize,
    pub runner_receipt_path: PathBuf,
    pub runner_receipt_sha256: String,
}

pub fn run_public_pack(options: RunOptions) -> Result<BlindRunReport> {
    let verified_install_receipt =
        verify_install_receipt(&options.install_receipt, &options.receipt_key)?;
    ensure_pack_root_path_is_safe(&options.public_pack_root)?;
    validate_sha256("deployment digest", &options.metadata.deployment_sha256)?;
    let deployment_sha256 = options.metadata.deployment_sha256.clone();
    let public_pack_root =
        fs::canonicalize(&options.public_pack_root).map_err(|source| AuditError::Read {
            path: options.public_pack_root.clone(),
            source,
        })?;
    if public_pack_root.file_name().and_then(|name| name.to_str())
        != Some(deployment_sha256.as_str())
    {
        return Err(AuditError::Validation(
            "installed public pack directory name must match deployment digest".to_owned(),
        ));
    }
    let provenance = verify_pre_audit_runner_provenance(
        verified_install_receipt,
        &public_pack_root,
        &options.metadata,
    )?;
    let isolation = IsolationExecutor::from_formal_backend(
        options.isolation_backend.clone(),
        &options.metadata.image_digest,
    )?;
    isolation.preflight()?;
    let audit = audit_public_pack(&options.public_pack_root)?;
    bind_runner_provenance_to_audit(&provenance, &audit)?;
    if options.metadata.git_commit != audit.method_commit {
        return Err(AuditError::Validation(format!(
            "run metadata git commit does not match audited public manifest: expected {}, got {}",
            audit.method_commit, options.metadata.git_commit
        )));
    }
    if options.metadata.config_digest != audit.manifest_sha256 {
        return Err(AuditError::Validation(format!(
            "run metadata config digest does not match audited public manifest: expected {}, got {}",
            audit.manifest_sha256, options.metadata.config_digest
        )));
    }
    ensure_no_output_overlap(&public_pack_root, &options.runs_root)?;
    let execution_snapshot = ExecutionPackSnapshot::capture(&public_pack_root, &audit)?;
    let manifest = &execution_snapshot.manifest;
    let policy = &execution_snapshot.policy;
    fs::create_dir_all(&options.runs_root).map_err(|source| AuditError::Write {
        path: options.runs_root.clone(),
        source,
    })?;
    let runs_root = fs::canonicalize(&options.runs_root).map_err(|source| AuditError::Read {
        path: options.runs_root.clone(),
        source,
    })?;
    let run_id = generate_run_id(&options.metadata.git_commit)?;
    let run = RunDirectory::create(&runs_root, run_id, options.metadata)?;
    let child_work_root = run.logs_dir().join("children");
    let child_runner = ChildRunner::new(&child_work_root);
    let execution_root = run.logs_dir().join("execution-source");
    fs::create_dir(&execution_root).map_err(|source| AuditError::Write {
        path: execution_root.clone(),
        source,
    })?;
    let run_artifacts_root = run.artifacts_dir();
    let mut observations = Vec::with_capacity(manifest.cases.len());

    for case in &manifest.cases {
        let case_execution_root = execution_snapshot.materialize_case(&execution_root, case)?;
        let case_context = CaseRunContext {
            case_execution_root: &case_execution_root,
            run_artifacts_root: &run_artifacts_root,
            child_work_root: &child_work_root,
            child_runner: &child_runner,
            isolation: &isolation,
            manifest,
            manifest_sha256: &audit.manifest_sha256,
            minimum_replays: policy.minimum_replay_attempts,
            policy,
        };
        let case_result = run_case(&case_context, case);
        let cleanup_result = ExecutionPackSnapshot::remove_materialized_case(&case_execution_root);

        match (case_result, cleanup_result) {
            (Ok(observation), Ok(())) => observations.push(observation),
            (Ok(_), Err(cleanup_error)) => return Err(cleanup_error),
            (Err(run_error), Ok(())) => {
                fs::remove_dir(&execution_root).map_err(|source| AuditError::Write {
                    path: execution_root.clone(),
                    source,
                })?;
                return Err(run_error);
            }
            (Err(run_error), Err(cleanup_error)) => {
                return Err(AuditError::Validation(format!(
                    "case execution failed: {run_error}; additionally failed to remove materialized execution snapshot: {cleanup_error}"
                )));
            }
        }
    }
    fs::remove_dir(&execution_root).map_err(|source| AuditError::Write {
        path: execution_root,
        source,
    })?;

    let observations_path = run.artifacts_dir().join("observations.jsonl");
    write_observations(&observations_path, &observations)?;
    let completed_count = observations
        .iter()
        .filter(|observation| observation.status == BlindCaseStatus::Completed)
        .count();
    let case_count = observations.len();
    let failed_count = case_count - completed_count;
    let runner_receipt_path = run.artifacts_dir().join("blind-runner-receipt.json");
    let runner_receipt = build_runner_receipt(
        &provenance,
        RunnerReceiptOptions {
            runner_version: format!("bw-blind-runner/{}", env!("CARGO_PKG_VERSION")),
            runner_commit: options.runner_commit,
            run_id: run.run_id().to_owned(),
            suite_id: audit.suite_id.clone(),
            split: split_name(audit.split).to_owned(),
            case_count: case_count as u64,
            isolation_backend: options.isolation_backend,
            case_execution_snapshot_digest: execution_snapshot_digest(&audit),
            observations_sha256: sha256_file(&observations_path)?,
            stdout_stderr_digest: digest_tree_or_empty(&run.logs_dir().join("children"))?,
            witness_tree_sha256: digest_tree_or_empty(&run.artifacts_dir().join("witnesses"))?,
            run_checksums_sha256: runner_evidence_digest(run.partial_path())?,
            created_at_utc: bw_experiment::manifest::now_utc_string(),
            host_id: options.runner_host_id,
        },
        &options.receipt_key,
    )?;
    let runner_receipt_bytes = serde_json::to_vec(&runner_receipt)?;
    fs::write(&runner_receipt_path, &runner_receipt_bytes).map_err(|source| AuditError::Write {
        path: runner_receipt_path.clone(),
        source,
    })?;
    let runner_receipt_sha256 = sha256_hex(&runner_receipt_bytes);
    let summary = json!({
        "schema_version": "boundary-witness.blind-run/0.1",
        "suite_id": &audit.suite_id,
        "split": audit.split,
        "case_count": case_count,
        "completed_count": completed_count,
        "failed_count": failed_count,
        "method_commit": &audit.method_commit,
        "public_manifest_sha256": &audit.manifest_sha256,
        "deployment_sha256": &deployment_sha256,
    });
    let finalize_input = FinalizeRun {
        summary,
        execution: None,
        required_trace_files: Vec::new(),
        required_log_files: Vec::new(),
    };
    let completed_at_utc = bw_experiment::manifest::now_utc_string();
    let summary_document = run.summary_document(&finalize_input, &completed_at_utc)?;
    scan_summary_value(&summary_document, policy)?;
    scan_finalized_candidate(run.partial_path(), policy)?;
    let final_run = run.finalize_at(finalize_input, completed_at_utc)?;
    verify_run_integrity(final_run.path())?;
    let runner_receipt_path = final_run.path().join("artifacts/blind-runner-receipt.json");

    Ok(BlindRunReport {
        final_run,
        suite_id: audit.suite_id,
        split: audit.split,
        case_count,
        completed_count,
        failed_count,
        runner_receipt_path,
        runner_receipt_sha256,
    })
}

fn digest_tree_or_empty(path: &Path) -> Result<String> {
    if path.exists() {
        sha256_tree(path)
    } else {
        Ok(sha256_hex(&[]))
    }
}

fn execution_snapshot_digest(audit: &crate::PublicPackAudit) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audit.manifest_sha256.as_bytes());
    hasher.update([0]);
    for (case_id, digest) in &audit.case_digests {
        hasher.update(case_id.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(digest.as_bytes());
        hasher.update([0]);
    }
    sha256_hex(&hasher.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn validate_sha256(label: &str, value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(AuditError::Validation(format!(
            "{label} must be 64 lowercase hexadecimal characters"
        )))
    }
}

fn ensure_no_output_overlap(public_pack_root: &Path, runs_root: &Path) -> Result<()> {
    let runs_destination = physical_destination(runs_root)?;
    if public_pack_root == runs_destination
        || public_pack_root.starts_with(&runs_destination)
        || runs_destination.starts_with(public_pack_root)
    {
        return Err(AuditError::Validation(
            "public pack and runs root must not overlap".to_owned(),
        ));
    }
    Ok(())
}

fn physical_destination(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|source| AuditError::Read {
                path: PathBuf::from("."),
                source,
            })?
            .join(path)
    };
    let mut ancestor = absolute;
    let mut missing = Vec::new();
    loop {
        match fs::canonicalize(&ancestor) {
            Ok(mut destination) => {
                for component in missing.iter().rev() {
                    destination.push(component);
                }
                return Ok(destination);
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                let component = ancestor.file_name().ok_or_else(|| {
                    AuditError::Validation(format!(
                        "runs root has no existing ancestor: {}",
                        path.display()
                    ))
                })?;
                missing.push(component.to_os_string());
                ancestor.pop();
            }
            Err(source) => {
                return Err(AuditError::Read {
                    path: ancestor,
                    source,
                });
            }
        }
    }
}

struct CaseRunContext<'a> {
    case_execution_root: &'a Path,
    run_artifacts_root: &'a Path,
    child_work_root: &'a Path,
    child_runner: &'a ChildRunner,
    isolation: &'a IsolationExecutor,
    manifest: &'a BlindPublicManifest,
    manifest_sha256: &'a str,
    minimum_replays: u32,
    policy: &'a BlindPolicy,
}

fn run_case(context: &CaseRunContext<'_>, case: &BlindPublicCase) -> Result<BlindCaseObservation> {
    match execute_case(context, case)? {
        Ok(observation) => Ok(observation),
        Err(status) => Ok(failed_observation(
            context.manifest,
            context.manifest_sha256,
            case,
            status,
        )),
    }
}

fn execute_case(
    context: &CaseRunContext<'_>,
    case: &BlindPublicCase,
) -> Result<std::result::Result<BlindCaseObservation, BlindCaseStatus>> {
    let mut environment = std::collections::BTreeMap::new();
    for (key, value) in &case.command.env {
        environment.insert(key.clone(), value.clone());
    }
    environment.insert(
        "BW_BLIND_CASE_ID".to_owned(),
        case.case_id.as_str().to_owned(),
    );
    environment.insert(
        "BW_BLIND_SUITE_ID".to_owned(),
        context.manifest.suite_id.clone(),
    );
    environment.insert(
        "BW_BLIND_SPLIT".to_owned(),
        split_name(context.manifest.split).to_owned(),
    );
    environment.insert(
        "BW_BLIND_METHOD_COMMIT".to_owned(),
        context.manifest.method_commit.clone(),
    );
    environment.insert(
        "BW_BLIND_MANIFEST_SHA256".to_owned(),
        context.manifest_sha256.to_owned(),
    );
    let timeout = Duration::from_secs(case.timeout_seconds);
    let result = match context.isolation {
        IsolationExecutor::NativeUntrustedSmoke => {
            let mut spec = ChildSpec::new(context.case_execution_root.join(&case.command.program))
                .args(case.command.args.clone());
            for (key, value) in &environment {
                spec = spec.env(key, value);
            }
            context
                .child_runner
                .run(spec.work_dir_env("BW_CHILD_WORK_DIR").timeout(timeout))
                .map_err(|_| ())
        }
        IsolationExecutor::Container(container) => {
            environment.insert("BW_CHILD_WORK_DIR".to_owned(), "/work".to_owned());
            Ok(container.run_case(
                context.child_work_root,
                context.case_execution_root,
                &case.command.program,
                &case.command.args,
                &environment,
                timeout,
            )?)
        }
    };
    let result = match result {
        Ok(result) => result,
        Err(_) => return Ok(Err(BlindCaseStatus::ToolError)),
    };
    scan_child_output(&result.work_dir, context.policy)?;

    let observation = (|| -> std::result::Result<BlindCaseObservation, BlindCaseStatus> {
        match result.status {
            ChildStatus::Exited(0) => {}
            ChildStatus::TimedOut => return Err(BlindCaseStatus::TimedOut),
            ChildStatus::Exited(_) | ChildStatus::Signaled(_) => {
                return Err(BlindCaseStatus::ToolError);
            }
        }

        let observation_path = result.work_dir.join("observation.json");
        ensure_regular_file_under(&result.work_dir, Path::new("observation.json"))?;
        let mut observation = BlindCaseObservation::from_path(observation_path)
            .map_err(|_| BlindCaseStatus::ToolError)?;
        observation
            .validate(context.minimum_replays)
            .map_err(|_| BlindCaseStatus::ToolError)?;
        validate_observation_identity(
            &observation,
            context.manifest,
            context.manifest_sha256,
            case,
        )?;
        if let Some(witness) = &observation.witness {
            ensure_regular_file_under(&result.work_dir, Path::new(&witness.artifact_path))?;
            let source = result.work_dir.join(&witness.artifact_path);
            let actual = sha256_path(&source)?;
            if actual != witness.artifact_sha256 {
                return Err(BlindCaseStatus::ToolError);
            }
            let artifact_relative = PathBuf::from("witnesses")
                .join(case.case_id.as_str())
                .join(&witness.artifact_path);
            let destination = context.run_artifacts_root.join(&artifact_relative);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|_| BlindCaseStatus::ToolError)?;
            }
            fs::copy(&source, &destination).map_err(|_| BlindCaseStatus::ToolError)?;
            observation
                .witness
                .as_mut()
                .expect("witness was present")
                .artifact_path = artifact_relative.to_string_lossy().replace('\\', "/");
        }
        Ok(observation)
    })();
    Ok(observation)
}

fn validate_observation_identity(
    observation: &BlindCaseObservation,
    manifest: &BlindPublicManifest,
    manifest_sha256: &str,
    case: &BlindPublicCase,
) -> std::result::Result<(), BlindCaseStatus> {
    if observation.suite_id != manifest.suite_id
        || observation.split != manifest.split
        || observation.case_id != case.case_id
        || observation.method_commit != manifest.method_commit
        || observation.public_manifest_sha256 != manifest_sha256
    {
        return Err(BlindCaseStatus::ToolError);
    }
    Ok(())
}

fn failed_observation(
    manifest: &BlindPublicManifest,
    manifest_sha256: &str,
    case: &BlindPublicCase,
    status: BlindCaseStatus,
) -> BlindCaseObservation {
    BlindCaseObservation {
        schema_version: BLIND_OBSERVED_SCHEMA_V01.to_owned(),
        suite_id: manifest.suite_id.clone(),
        split: manifest.split,
        case_id: case.case_id.clone(),
        method_commit: manifest.method_commit.clone(),
        public_manifest_sha256: manifest_sha256.to_owned(),
        status,
        findings: Vec::new(),
        witness: None,
    }
}

fn ensure_regular_file_under(
    root: &Path,
    relative: &Path,
) -> std::result::Result<(), BlindCaseStatus> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(BlindCaseStatus::ToolError);
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|_| BlindCaseStatus::ToolError)?;
        if metadata.file_type().is_symlink() {
            return Err(BlindCaseStatus::ToolError);
        }
    }
    if !current.is_file() {
        return Err(BlindCaseStatus::ToolError);
    }
    Ok(())
}

fn sha256_path(path: &Path) -> std::result::Result<String, BlindCaseStatus> {
    let bytes = fs::read(path).map_err(|_| BlindCaseStatus::ToolError)?;
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
}

fn write_observations(path: &Path, observations: &[BlindCaseObservation]) -> Result<()> {
    let mut output = String::new();
    for observation in observations {
        writeln!(&mut output, "{}", serde_json::to_string(observation)?).expect("String write");
    }
    fs::write(path, output).map_err(|source| AuditError::Write {
        path: path.to_owned(),
        source,
    })
}

const fn split_name(split: BlindSplit) -> &'static str {
    match split {
        BlindSplit::Gate => "gate",
        BlindSplit::Evaluation => "evaluation",
    }
}
