use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use bw_blind_model::{BlindPolicy, BlindPublicCase, BlindPublicManifest};
use sha2::{Digest, Sha256};

use crate::{AuditError, PublicPackAudit, Result};

pub(crate) struct ExecutionPackSnapshot {
    pub(crate) manifest: BlindPublicManifest,
    pub(crate) policy: BlindPolicy,
    cases: BTreeMap<bw_blind_model::BlindCaseId, CaseExecutionSnapshot>,
}

struct CaseExecutionSnapshot {
    files: Vec<SnapshotFile>,
}

struct SnapshotFile {
    relative: PathBuf,
    bytes: Vec<u8>,
    executable: bool,
}

impl ExecutionPackSnapshot {
    pub(crate) fn capture(public_pack_root: &Path, audit: &PublicPackAudit) -> Result<Self> {
        let manifest_bytes = read_stable_file(&public_pack_root.join("manifest.json"))?.0;
        let actual_manifest_sha256 = sha256_bytes(&manifest_bytes);
        if actual_manifest_sha256 != audit.manifest_sha256 {
            return Err(AuditError::Validation(
                "public manifest changed between audit and execution snapshot".to_owned(),
            ));
        }
        let manifest = BlindPublicManifest::parse_json(
            std::str::from_utf8(&manifest_bytes)
                .map_err(|_| AuditError::Validation("manifest.json is not UTF-8".to_owned()))?,
        )?;
        if manifest.suite_id != audit.suite_id
            || manifest.split != audit.split
            || manifest.method_commit != audit.method_commit
            || manifest.cases.len() != audit.case_count
        {
            return Err(AuditError::Validation(
                "public manifest identity changed between audit and execution snapshot".to_owned(),
            ));
        }

        let policy_bytes = read_stable_file(&public_pack_root.join("policy.toml"))?.0;
        if sha256_bytes(&policy_bytes) != manifest.policy_sha256 {
            return Err(AuditError::Validation(
                "policy changed between audit and execution snapshot".to_owned(),
            ));
        }
        let policy = BlindPolicy::parse_toml(
            std::str::from_utf8(&policy_bytes)
                .map_err(|_| AuditError::Validation("policy.toml is not UTF-8".to_owned()))?,
        )?;

        let mut cases = BTreeMap::new();
        for case in &manifest.cases {
            let snapshot =
                CaseExecutionSnapshot::capture(&public_pack_root.join(&case.case_root), case)?;
            let expected = audit.case_digests.get(&case.case_id).ok_or_else(|| {
                AuditError::Validation(format!(
                    "audited case digest is missing for {}",
                    case.case_id
                ))
            })?;
            if snapshot.tree_digest() != *expected {
                return Err(AuditError::Validation(format!(
                    "case {} changed between audit and execution snapshot",
                    case.case_id
                )));
            }
            cases.insert(case.case_id.clone(), snapshot);
        }
        if cases.len() != audit.case_digests.len() {
            return Err(AuditError::Validation(
                "audited case set changed before execution snapshot".to_owned(),
            ));
        }

        Ok(Self {
            manifest,
            policy,
            cases,
        })
    }

    pub(crate) fn materialize_case(
        &self,
        execution_root: &Path,
        case: &BlindPublicCase,
    ) -> Result<PathBuf> {
        fs::create_dir_all(execution_root).map_err(|source| AuditError::Write {
            path: execution_root.to_owned(),
            source,
        })?;
        let destination = execution_root.join(case.case_id.as_str());
        if fs::symlink_metadata(&destination).is_ok() {
            return Err(AuditError::Validation(format!(
                "execution snapshot destination already exists: {}",
                destination.display()
            )));
        }
        fs::create_dir(&destination).map_err(|source| AuditError::Write {
            path: destination.clone(),
            source,
        })?;
        let materialize = || -> Result<()> {
            let snapshot = self.cases.get(&case.case_id).ok_or_else(|| {
                AuditError::Validation(format!("execution snapshot missing case {}", case.case_id))
            })?;
            for file in &snapshot.files {
                let path = destination.join(&file.relative);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|source| AuditError::Write {
                        path: parent.to_owned(),
                        source,
                    })?;
                }
                fs::write(&path, &file.bytes).map_err(|source| AuditError::Write {
                    path: path.clone(),
                    source,
                })?;
                set_snapshot_permissions(&path, file.executable)?;
            }
            set_snapshot_directory_permissions(&destination)
        };
        match materialize() {
            Ok(()) => Ok(destination),
            Err(materialize_error) => match Self::remove_materialized_case(&destination) {
                Ok(()) => Err(materialize_error),
                Err(cleanup_error) => Err(AuditError::Validation(format!(
                    "failed to materialize execution snapshot: {materialize_error}; additionally failed to remove partial execution snapshot {}: {cleanup_error}",
                    destination.display()
                ))),
            },
        }
    }

    pub(crate) fn remove_materialized_case(path: &Path) -> Result<()> {
        make_snapshot_directories_removable(path)?;
        fs::remove_dir_all(path).map_err(|source| AuditError::Write {
            path: path.to_owned(),
            source,
        })
    }
}

impl CaseExecutionSnapshot {
    fn capture(case_root: &Path, case: &BlindPublicCase) -> Result<Self> {
        let metadata = fs::symlink_metadata(case_root).map_err(|source| AuditError::Read {
            path: case_root.to_owned(),
            source,
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AuditError::Validation(format!(
                "case root changed before execution snapshot: {}",
                case.case_root
            )));
        }
        let mut files = Vec::new();
        capture_snapshot_files(case_root, case_root, &mut files)?;
        files.sort_by(|left, right| left.relative.cmp(&right.relative));
        let command = Path::new(&case.command.program);
        if !files.iter().any(|file| file.relative == command) {
            return Err(AuditError::Validation(format!(
                "execution snapshot missing command for {}",
                case.case_id
            )));
        }
        let snapshot = Self { files };
        if snapshot.tree_digest() != case.case_sha256 {
            return Err(AuditError::Validation(format!(
                "case {} changed before execution snapshot",
                case.case_id
            )));
        }
        Ok(snapshot)
    }

    fn tree_digest(&self) -> String {
        let mut hasher = Sha256::new();
        for file in &self.files {
            hasher.update(
                file.relative
                    .to_string_lossy()
                    .replace('\\', "/")
                    .as_bytes(),
            );
            hasher.update([0]);
            hasher.update(sha256_bytes(&file.bytes).as_bytes());
        }
        hex_lower(&hasher.finalize())
    }
}

fn capture_snapshot_files(
    root: &Path,
    directory: &Path,
    output: &mut Vec<SnapshotFile>,
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
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| AuditError::Read {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(AuditError::Validation(format!(
                "case entry changed to symlink before execution snapshot: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            capture_snapshot_files(root, &path, output)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .expect("snapshot paths originate under case root")
                .to_path_buf();
            let (bytes, executable) = read_stable_file(&path)?;
            output.push(SnapshotFile {
                relative,
                bytes,
                executable,
            });
        } else {
            return Err(AuditError::Validation(format!(
                "case entry is not a regular file before execution snapshot: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn read_stable_file(path: &Path) -> Result<(Vec<u8>, bool)> {
    let mut file = File::open(path).map_err(|source| AuditError::Read {
        path: path.to_owned(),
        source,
    })?;
    let before = file.metadata().map_err(|source| AuditError::Read {
        path: path.to_owned(),
        source,
    })?;
    if !before.is_file() {
        return Err(AuditError::Validation(format!(
            "execution snapshot source is not a regular file: {}",
            path.display()
        )));
    }
    let executable = is_executable(&before);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| AuditError::Read {
            path: path.to_owned(),
            source,
        })?;
    let after = file.metadata().map_err(|source| AuditError::Read {
        path: path.to_owned(),
        source,
    })?;
    if !same_file_identity(&before, &after) || before.len() != bytes.len() as u64 {
        return Err(AuditError::Validation(format!(
            "execution snapshot source changed while reading: {}",
            path.display()
        )));
    }
    Ok((bytes, executable))
}

#[cfg(unix)]
fn same_file_identity(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_identity(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
        && before.created().ok() == after.created().ok()
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn set_snapshot_permissions(path: &Path, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = if executable { 0o555 } else { 0o444 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
        AuditError::Write {
            path: path.to_owned(),
            source,
        }
    })
}

#[cfg(unix)]
fn set_snapshot_directory_permissions(directory: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let entries = fs::read_dir(directory)
        .map_err(|source| AuditError::Write {
            path: directory.to_owned(),
            source,
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source| AuditError::Write {
            path: directory.to_owned(),
            source,
        })?;
    for entry in entries {
        let path = entry.path();
        if fs::symlink_metadata(&path)
            .map_err(|source| AuditError::Write {
                path: path.clone(),
                source,
            })?
            .is_dir()
        {
            set_snapshot_directory_permissions(&path)?;
        }
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o555)).map_err(|source| {
        AuditError::Write {
            path: directory.to_owned(),
            source,
        }
    })
}

#[cfg(unix)]
fn make_snapshot_directories_removable(directory: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(|source| {
        AuditError::Write {
            path: directory.to_owned(),
            source,
        }
    })?;
    for entry in fs::read_dir(directory)
        .map_err(|source| AuditError::Write {
            path: directory.to_owned(),
            source,
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source| AuditError::Write {
            path: directory.to_owned(),
            source,
        })?
    {
        let path = entry.path();
        if fs::symlink_metadata(&path)
            .map_err(|source| AuditError::Write {
                path: path.clone(),
                source,
            })?
            .is_dir()
        {
            make_snapshot_directories_removable(&path)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_snapshot_directory_permissions(directory: &Path) -> Result<()> {
    let mut permissions = fs::metadata(directory)
        .map_err(|source| AuditError::Read {
            path: directory.to_owned(),
            source,
        })?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(directory, permissions).map_err(|source| AuditError::Write {
        path: directory.to_owned(),
        source,
    })
}

#[cfg(not(unix))]
fn make_snapshot_directories_removable(_directory: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn set_snapshot_permissions(path: &Path, _executable: bool) -> Result<()> {
    let mut permissions = fs::metadata(path)
        .map_err(|source| AuditError::Read {
            path: path.to_owned(),
            source,
        })?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).map_err(|source| AuditError::Write {
        path: path.to_owned(),
        source,
    })
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};

    use bw_blind_model::{
        BLIND_POLICY_SCHEMA_V01, BLIND_PUBLIC_SCHEMA_V01, BlindCaseId, BlindCommandSpec,
        BlindPolicy, BlindPublicCase, BlindPublicManifest, BlindSplit,
    };

    use super::{CaseExecutionSnapshot, ExecutionPackSnapshot, SnapshotFile};

    #[test]
    fn materialized_case_is_readable_and_traversable_by_container_user() {
        let case_id = BlindCaseId::parse("blind-8f34a923d01c77ab").unwrap();
        let case = BlindPublicCase {
            case_id: case_id.clone(),
            case_root: format!("cases/{case_id}"),
            case_sha256: "a".repeat(64),
            command: BlindCommandSpec {
                program: "adapter/bin/driver".to_owned(),
                args: Vec::new(),
                env: BTreeMap::new(),
            },
            timeout_seconds: 10,
        };
        let snapshot = ExecutionPackSnapshot {
            manifest: BlindPublicManifest {
                schema_version: BLIND_PUBLIC_SCHEMA_V01.to_owned(),
                suite_id: "snapshot-permissions".to_owned(),
                split: BlindSplit::Gate,
                method_commit: "0123456789012345678901234567890123456789".to_owned(),
                policy_sha256: "b".repeat(64),
                cases: vec![case.clone()],
            },
            policy: BlindPolicy {
                schema_version: BLIND_POLICY_SCHEMA_V01.to_owned(),
                minimum_replay_attempts: 1,
                gate_minimum_confirmed_cases: 1,
                forbidden_public_filename_tokens: Vec::new(),
            },
            cases: BTreeMap::from([(
                case_id,
                CaseExecutionSnapshot {
                    files: vec![
                        SnapshotFile {
                            relative: PathBuf::from("adapter/bin/driver"),
                            bytes: b"#!/bin/sh\nexit 0\n".to_vec(),
                            executable: true,
                        },
                        SnapshotFile {
                            relative: PathBuf::from("COMPLETE"),
                            bytes: b"complete\n".to_vec(),
                            executable: false,
                        },
                    ],
                },
            )]),
        };
        let temp = tempfile::tempdir().unwrap();
        let materialized = snapshot.materialize_case(temp.path(), &case).unwrap();

        assert_eq!(mode(&materialized), 0o555);
        assert_eq!(mode(&materialized.join("adapter")), 0o555);
        assert_eq!(mode(&materialized.join("adapter/bin")), 0o555);
        assert_eq!(mode(&materialized.join("adapter/bin/driver")), 0o555);
        assert_eq!(mode(&materialized.join("COMPLETE")), 0o444);

        ExecutionPackSnapshot::remove_materialized_case(&materialized).unwrap();
        assert!(!materialized.exists());
    }

    #[test]
    fn materialization_failure_removes_partial_case_snapshot() {
        let case_id = BlindCaseId::parse("blind-8f34a923d01c77ab").unwrap();
        let case = BlindPublicCase {
            case_id: case_id.clone(),
            case_root: format!("cases/{case_id}"),
            case_sha256: "a".repeat(64),
            command: BlindCommandSpec {
                program: "collide".to_owned(),
                args: Vec::new(),
                env: BTreeMap::new(),
            },
            timeout_seconds: 10,
        };
        let snapshot = ExecutionPackSnapshot {
            manifest: BlindPublicManifest {
                schema_version: BLIND_PUBLIC_SCHEMA_V01.to_owned(),
                suite_id: "snapshot-cleanup".to_owned(),
                split: BlindSplit::Gate,
                method_commit: "0123456789012345678901234567890123456789".to_owned(),
                policy_sha256: "b".repeat(64),
                cases: vec![case.clone()],
            },
            policy: BlindPolicy {
                schema_version: BLIND_POLICY_SCHEMA_V01.to_owned(),
                minimum_replay_attempts: 1,
                gate_minimum_confirmed_cases: 1,
                forbidden_public_filename_tokens: Vec::new(),
            },
            cases: BTreeMap::from([(
                case_id,
                CaseExecutionSnapshot {
                    files: vec![
                        SnapshotFile {
                            relative: PathBuf::from("collide"),
                            bytes: b"file blocks child directory\n".to_vec(),
                            executable: false,
                        },
                        SnapshotFile {
                            relative: PathBuf::from("collide/child"),
                            bytes: b"unreachable\n".to_vec(),
                            executable: false,
                        },
                    ],
                },
            )]),
        };
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join(case.case_id.as_str());

        let error = snapshot.materialize_case(temp.path(), &case).unwrap_err();

        assert!(error.to_string().contains("collide"));
        assert!(
            !destination.exists(),
            "failed materialization must remove its partial destination"
        );
    }

    fn mode(path: &std::path::Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }
}
