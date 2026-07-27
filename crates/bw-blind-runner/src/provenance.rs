use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use bw_blind_model::{
    BLIND_RUNNER_RECEIPT_SCHEMA_V01, FormalIsolationBackend, InstallReceipt, RunnerReceipt,
    TestReceiptKey,
};
use sha2::{Digest, Sha256};

use crate::{AuditError, PublicPackAudit, Result};

pub struct VerifiedInstallReceipt {
    pub receipt: InstallReceipt,
    pub receipt_sha256: String,
}

pub struct RunnerProvenance {
    pub install_receipt_sha256: String,
    pub archive_sha256: String,
    pub deployment_json_sha256: String,
    pub public_manifest_sha256: String,
    pub policy_sha256: String,
    pub method_commit: String,
}

pub struct RunnerReceiptOptions {
    pub runner_version: String,
    pub runner_commit: String,
    pub run_id: String,
    pub suite_id: String,
    pub split: String,
    pub case_count: u64,
    pub isolation_backend: FormalIsolationBackend,
    pub case_execution_snapshot_digest: String,
    pub observations_sha256: String,
    pub stdout_stderr_digest: String,
    pub witness_tree_sha256: String,
    pub run_checksums_sha256: String,
    pub created_at_utc: String,
    pub host_id: String,
}

pub fn verify_install_receipt(path: &Path, key: &TestReceiptKey) -> Result<VerifiedInstallReceipt> {
    let bytes = fs::read(path).map_err(|source| {
        AuditError::Validation(format!(
            "failed to read install receipt {}: {source}",
            path.display()
        ))
    })?;
    let receipt: InstallReceipt = serde_json::from_slice(&bytes)?;
    receipt.verify(key)?;
    Ok(VerifiedInstallReceipt {
        receipt,
        receipt_sha256: sha256_hex(&bytes),
    })
}

/// Verifies receipt bindings that do not require parsing the public manifest.
///
/// Keep this before the public-pack audit so a bad install receipt cannot cause the
/// runner to process untrusted pack semantics.
pub(crate) fn verify_pre_audit_runner_provenance(
    verified: VerifiedInstallReceipt,
    public_pack_root: &Path,
    metadata: &bw_experiment::RunMetadata,
) -> Result<RunnerProvenance> {
    let receipt = verified.receipt;
    if receipt.archive_sha256 != metadata.deployment_sha256 {
        return Err(AuditError::Validation(format!(
            "install receipt archive_sha256 mismatch: expected {}, got {}",
            metadata.deployment_sha256, receipt.archive_sha256
        )));
    }
    let actual_manifest_sha256 = sha256_file(&public_pack_root.join("manifest.json"))?;
    if receipt.public_manifest_sha256 != actual_manifest_sha256 {
        return Err(AuditError::Validation(format!(
            "install receipt public_manifest_sha256 mismatch: expected {}, got {}",
            receipt.public_manifest_sha256, actual_manifest_sha256
        )));
    }
    let raw_method_commit = raw_manifest_method_commit(&public_pack_root.join("manifest.json"))?;
    if receipt.method_commit != raw_method_commit {
        return Err(AuditError::Validation(format!(
            "install receipt method_commit mismatch: expected {}, got {}",
            raw_method_commit, receipt.method_commit
        )));
    }
    if metadata.git_commit != raw_method_commit {
        return Err(AuditError::Validation(format!(
            "run metadata git commit does not match raw public manifest method_commit: expected {}, got {}",
            raw_method_commit, metadata.git_commit
        )));
    }

    let installed_path =
        fs::canonicalize(&receipt.installed_path).map_err(|source| AuditError::Read {
            path: PathBuf::from(&receipt.installed_path),
            source,
        })?;
    if installed_path != public_pack_root {
        return Err(AuditError::Validation(format!(
            "install receipt installed_path mismatch: expected {}, got {}",
            public_pack_root.display(),
            installed_path.display()
        )));
    }

    let actual_tree_sha256 = installed_pack_tree_sha256(public_pack_root)?;
    if receipt.installed_pack_tree_sha256 != actual_tree_sha256 {
        return Err(AuditError::Validation(format!(
            "install receipt installed_pack_tree_sha256 mismatch: expected {}, got {}",
            receipt.installed_pack_tree_sha256, actual_tree_sha256
        )));
    }
    let actual_policy_sha256 = sha256_file(&public_pack_root.join("policy.toml"))?;
    if receipt.policy_sha256 != actual_policy_sha256 {
        return Err(AuditError::Validation(format!(
            "install receipt policy_sha256 mismatch: expected {}, got {}",
            receipt.policy_sha256, actual_policy_sha256
        )));
    }

    Ok(RunnerProvenance {
        install_receipt_sha256: verified.receipt_sha256,
        archive_sha256: receipt.archive_sha256,
        deployment_json_sha256: receipt.deployment_json_sha256,
        public_manifest_sha256: receipt.public_manifest_sha256,
        policy_sha256: receipt.policy_sha256,
        method_commit: receipt.method_commit,
    })
}

fn raw_manifest_method_commit(path: &Path) -> Result<String> {
    let bytes = fs::read(path).map_err(|source| AuditError::Read {
        path: path.to_owned(),
        source,
    })?;
    let manifest: serde_json::Value = serde_json::from_slice(&bytes)?;
    let method_commit = manifest
        .get("method_commit")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            AuditError::Validation("raw public manifest method_commit must be a string".to_owned())
        })?;
    if method_commit.len() != 40
        || !method_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AuditError::Validation(
            "raw public manifest method_commit must be 40 lowercase hexadecimal characters"
                .to_owned(),
        ));
    }
    Ok(method_commit.to_owned())
}

/// Binds the already-authenticated receipt to the semantic public-pack audit.
pub(crate) fn bind_runner_provenance_to_audit(
    provenance: &RunnerProvenance,
    audit: &PublicPackAudit,
) -> Result<()> {
    if provenance.public_manifest_sha256 != audit.manifest_sha256 {
        return Err(AuditError::Validation(format!(
            "install receipt public_manifest_sha256 mismatch: expected {}, got {}",
            audit.manifest_sha256, provenance.public_manifest_sha256
        )));
    }
    if provenance.method_commit != audit.method_commit {
        return Err(AuditError::Validation(format!(
            "install receipt method_commit mismatch: expected {}, got {}",
            audit.method_commit, provenance.method_commit
        )));
    }
    Ok(())
}

pub(crate) fn build_runner_receipt(
    provenance: &RunnerProvenance,
    options: RunnerReceiptOptions,
    key: &TestReceiptKey,
) -> Result<RunnerReceipt> {
    let mut receipt = RunnerReceipt {
        schema_version: BLIND_RUNNER_RECEIPT_SCHEMA_V01.to_owned(),
        runner_version: options.runner_version,
        runner_commit: options.runner_commit,
        run_id: options.run_id,
        suite_id: options.suite_id,
        split: options.split,
        method_commit: provenance.method_commit.clone(),
        archive_sha256: provenance.archive_sha256.clone(),
        deployment_json_sha256: provenance.deployment_json_sha256.clone(),
        install_receipt_sha256: provenance.install_receipt_sha256.clone(),
        public_manifest_sha256: provenance.public_manifest_sha256.clone(),
        policy_sha256: provenance.policy_sha256.clone(),
        case_count: options.case_count,
        isolation_backend: options.isolation_backend,
        case_execution_snapshot_digest: options.case_execution_snapshot_digest,
        observations_sha256: options.observations_sha256,
        stdout_stderr_digest: options.stdout_stderr_digest,
        witness_tree_sha256: options.witness_tree_sha256,
        run_checksums_sha256: options.run_checksums_sha256,
        created_at_utc: options.created_at_utc,
        host_id: options.host_id,
        trust: bw_blind_model::ReceiptTrust {
            key_id: String::new(),
            signature_sha256: String::new(),
        },
    };
    key.sign_runner(&mut receipt)?;
    Ok(receipt)
}

pub(crate) fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).map_err(|source| AuditError::Read {
        path: path.to_owned(),
        source,
    })?;
    Ok(sha256_hex(&bytes))
}

pub(crate) fn sha256_tree(root: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    hash_tree_entries(root, root, &mut hasher)?;
    Ok(hex_lower(&hasher.finalize()))
}

/// Hashes the runner-produced evidence that remains stable across finalization.
///
/// This deliberately excludes the receipt, manifest, summary, completion marker, and checksum
/// manifest. The final checksum manifest separately protects the complete finalized run,
/// including the runner receipt, without creating a self-referential digest.
pub(crate) fn runner_evidence_digest(run_root: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"boundary-witness.runner-evidence-digest/0.1\0");
    hash_evidence_file(&mut hasher, run_root, "findings.jsonl")?;
    hash_evidence_file(&mut hasher, run_root, "artifacts/observations.jsonl")?;
    for relative in ["artifacts/witnesses", "logs/children", "traces"] {
        hash_evidence_tree(&mut hasher, run_root, relative)?;
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn installed_pack_tree_sha256(root: &Path) -> Result<String> {
    let root_metadata = fs::symlink_metadata(root).map_err(|source| AuditError::Read {
        path: root.to_owned(),
        source,
    })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(AuditError::Validation(format!(
            "installed public pack is not a regular directory: {}",
            root.display()
        )));
    }

    let mut hasher = Sha256::new();
    hash_installed_directory(&mut hasher, b".", file_mode(&root_metadata));
    hash_installed_entries(root, root, &mut hasher)?;
    Ok(hex_lower(&hasher.finalize()))
}

fn hash_installed_entries(root: &Path, directory: &Path, hasher: &mut Sha256) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| AuditError::Read {
            path: directory.to_owned(),
            source,
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source| AuditError::Read {
            path: directory.to_owned(),
            source,
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| AuditError::Read {
            path: path.clone(),
            source,
        })?;
        let relative = path
            .strip_prefix(root)
            .expect("installed entry is below installed root")
            .to_string_lossy()
            .replace('\\', "/");
        if metadata.is_dir() {
            hash_installed_directory(hasher, relative.as_bytes(), file_mode(&metadata));
            hash_installed_entries(root, &path, hasher)?;
        } else if metadata.is_file() {
            let bytes = fs::read(&path).map_err(|source| AuditError::Read {
                path: path.clone(),
                source,
            })?;
            hasher.update(b"F");
            hasher.update((relative.len() as u64).to_be_bytes());
            hasher.update(relative.as_bytes());
            hasher.update(file_mode(&metadata).to_be_bytes());
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(Sha256::digest(&bytes));
        } else {
            return Err(AuditError::Validation(format!(
                "installed public pack contains an unsupported entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn hash_installed_directory(hasher: &mut Sha256, path: &[u8], mode: u32) {
    hasher.update(b"D");
    hasher.update((path.len() as u64).to_be_bytes());
    hasher.update(path);
    hasher.update(mode.to_be_bytes());
}

fn hash_tree_entries(root: &Path, directory: &Path, hasher: &mut Sha256) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| AuditError::Read {
            path: directory.to_owned(),
            source,
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source| AuditError::Read {
            path: directory.to_owned(),
            source,
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| AuditError::Read {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(AuditError::Validation(format!(
                "tree digest contains a symlink: {}",
                path.display()
            )));
        }
        let relative = path
            .strip_prefix(root)
            .expect("tree entry is below root")
            .to_string_lossy()
            .replace('\\', "/");
        if metadata.is_dir() {
            hasher.update(b"D");
            hasher.update(relative.as_bytes());
            hasher.update([0]);
            hash_tree_entries(root, &path, hasher)?;
        } else if metadata.is_file() {
            hasher.update(b"F");
            hasher.update(relative.as_bytes());
            hasher.update([0]);
            hasher.update(Sha256::digest(fs::read(&path).map_err(|source| {
                AuditError::Read {
                    path: path.clone(),
                    source,
                }
            })?));
        } else {
            return Err(AuditError::Validation(format!(
                "tree digest contains an unsupported entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn hash_evidence_file(hasher: &mut Sha256, run_root: &Path, relative: &str) -> Result<()> {
    let path = run_root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|source| AuditError::Read {
        path: path.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AuditError::Validation(format!(
            "runner evidence file is not a regular file: {}",
            path.display()
        )));
    }
    let bytes = fs::read(&path).map_err(|source| AuditError::Read {
        path: path.clone(),
        source,
    })?;
    hasher.update(b"F");
    hasher.update(relative.as_bytes());
    hasher.update([0]);
    hasher.update(Sha256::digest(bytes));
    Ok(())
}

fn hash_evidence_tree(hasher: &mut Sha256, run_root: &Path, relative: &str) -> Result<()> {
    let root = run_root.join(relative);
    hasher.update(b"T");
    hasher.update(relative.as_bytes());
    hasher.update([0]);
    let metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            hasher.update(b"absent");
            return Ok(());
        }
        Err(source) => {
            return Err(AuditError::Read { path: root, source });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AuditError::Validation(format!(
            "runner evidence tree is not a regular directory: {}",
            root.display()
        )));
    }
    hasher.update(b"present");
    hash_evidence_tree_entries(hasher, run_root, &root)
}

fn hash_evidence_tree_entries(
    hasher: &mut Sha256,
    run_root: &Path,
    directory: &Path,
) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| AuditError::Read {
            path: directory.to_owned(),
            source,
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source| AuditError::Read {
            path: directory.to_owned(),
            source,
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| AuditError::Read {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(AuditError::Validation(format!(
                "runner evidence tree contains a symlink: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            hash_evidence_tree_entries(hasher, run_root, &path)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(run_root)
                .expect("runner evidence entry is below run root")
                .to_string_lossy()
                .replace('\\', "/");
            hash_evidence_file(hasher, run_root, &relative)?;
        } else {
            return Err(AuditError::Validation(format!(
                "runner evidence tree contains an unsupported entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn file_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
