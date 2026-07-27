use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    BlindModelError, Result, error::validation, policy::MANDATORY_FORBIDDEN_PUBLIC_TOKENS,
    public::is_lower_hex,
};

pub const BLIND_INSTALL_RECEIPT_SCHEMA_V01: &str = "boundary-witness.blind-install-receipt/0.1";
pub const BLIND_RUNNER_RECEIPT_SCHEMA_V01: &str = "boundary-witness.blind-runner-receipt/0.1";

const TEST_SIGNATURE_DOMAIN: &[u8] = b"boundary-witness.receipt-test-signature/0.1\0";

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FormalIsolationBackend {
    Container,
    CgroupPidNamespace,
    NativeUntrustedSmoke,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptTrust {
    pub key_id: String,
    pub signature_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallReceipt {
    pub schema_version: String,
    pub installer_version: String,
    pub installer_commit: String,
    pub method_commit: String,
    pub archive_sha256: String,
    pub deployment_json_sha256: String,
    pub public_manifest_sha256: String,
    pub policy_sha256: String,
    pub installed_pack_tree_sha256: String,
    pub installed_path: String,
    pub created_at_utc: String,
    pub host_id: String,
    pub trust: ReceiptTrust,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerReceipt {
    pub schema_version: String,
    pub runner_version: String,
    pub runner_commit: String,
    pub run_id: String,
    pub suite_id: String,
    pub split: String,
    pub method_commit: String,
    pub archive_sha256: String,
    pub deployment_json_sha256: String,
    pub install_receipt_sha256: String,
    pub public_manifest_sha256: String,
    pub policy_sha256: String,
    pub case_count: u64,
    pub isolation_backend: FormalIsolationBackend,
    pub case_execution_snapshot_digest: String,
    pub observations_sha256: String,
    pub stdout_stderr_digest: String,
    pub witness_tree_sha256: String,
    /// Digest of stable runner evidence; this is not the final `checksums.sha256` file digest.
    pub run_checksums_sha256: String,
    pub created_at_utc: String,
    pub host_id: String,
    pub trust: ReceiptTrust,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TestReceiptKey {
    key_id: String,
    secret_key_bytes: Vec<u8>,
}

impl fmt::Debug for TestReceiptKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestReceiptKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl TestReceiptKey {
    pub fn from_hex(key_id: impl Into<String>, hex: &str) -> Result<Self> {
        let key_id = key_id.into();
        validate_nonempty("test receipt key_id", &key_id)?;
        reject_forbidden_public_tokens([("test receipt key_id", key_id.as_str())])?;
        if hex.is_empty()
            || !hex.len().is_multiple_of(2)
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(validation(
                "test receipt key must be non-empty even-length lowercase hexadecimal",
            ));
        }

        let secret_key_bytes = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = hex_nibble(pair[0]).expect("validated lowercase hexadecimal input");
                let low = hex_nibble(pair[1]).expect("validated lowercase hexadecimal input");
                (high << 4) | low
            })
            .collect();
        Ok(Self {
            key_id,
            secret_key_bytes,
        })
    }

    pub fn sign_install(&self, receipt: &mut InstallReceipt) -> Result<()> {
        receipt.validate_fields()?;
        receipt.trust = ReceiptTrust {
            key_id: self.key_id.clone(),
            signature_sha256: self.signature_for(&receipt.payload())?,
        };
        Ok(())
    }

    pub fn sign_runner(&self, receipt: &mut RunnerReceipt) -> Result<()> {
        receipt.validate_signable_fields()?;
        receipt.trust = ReceiptTrust {
            key_id: self.key_id.clone(),
            signature_sha256: self.signature_for(&receipt.payload())?,
        };
        Ok(())
    }

    fn signature_for<T: Serialize>(&self, payload: &T) -> Result<String> {
        let canonical_payload = canonical_receipt_json(payload)?;
        let mut hasher = Sha256::new();
        hasher.update(TEST_SIGNATURE_DOMAIN);
        hasher.update(self.key_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(canonical_payload);
        hasher.update(b"\0");
        hasher.update(&self.secret_key_bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }
}

impl InstallReceipt {
    pub fn verify(&self, key: &TestReceiptKey) -> Result<()> {
        self.validate_fields()?;
        verify_trust(&self.trust, key, &self.payload())
    }

    fn validate_fields(&self) -> Result<()> {
        if self.schema_version != BLIND_INSTALL_RECEIPT_SCHEMA_V01 {
            return Err(validation(
                "unsupported blind install receipt schema_version",
            ));
        }
        validate_nonempty_fields([
            ("installer_version", self.installer_version.as_str()),
            ("installed_path", self.installed_path.as_str()),
            ("created_at_utc", self.created_at_utc.as_str()),
            ("host_id", self.host_id.as_str()),
        ])?;
        validate_commit("installer_commit", &self.installer_commit)?;
        validate_commit("method_commit", &self.method_commit)?;
        validate_sha256_fields([
            ("archive_sha256", self.archive_sha256.as_str()),
            (
                "deployment_json_sha256",
                self.deployment_json_sha256.as_str(),
            ),
            (
                "public_manifest_sha256",
                self.public_manifest_sha256.as_str(),
            ),
            ("policy_sha256", self.policy_sha256.as_str()),
            (
                "installed_pack_tree_sha256",
                self.installed_pack_tree_sha256.as_str(),
            ),
        ])?;
        reject_forbidden_public_tokens(self.public_fields())
    }

    fn public_fields(&self) -> [(&str, &str); 12] {
        [
            ("schema_version", &self.schema_version),
            ("installer_version", &self.installer_version),
            ("installer_commit", &self.installer_commit),
            ("method_commit", &self.method_commit),
            ("installed_path", &self.installed_path),
            ("created_at_utc", &self.created_at_utc),
            ("host_id", &self.host_id),
            ("trust.key_id", &self.trust.key_id),
            ("archive_sha256", &self.archive_sha256),
            ("deployment_json_sha256", &self.deployment_json_sha256),
            ("public_manifest_sha256", &self.public_manifest_sha256),
            ("policy_sha256", &self.policy_sha256),
        ]
    }

    fn payload(&self) -> InstallReceiptPayload<'_> {
        InstallReceiptPayload {
            schema_version: &self.schema_version,
            installer_version: &self.installer_version,
            installer_commit: &self.installer_commit,
            method_commit: &self.method_commit,
            archive_sha256: &self.archive_sha256,
            deployment_json_sha256: &self.deployment_json_sha256,
            public_manifest_sha256: &self.public_manifest_sha256,
            policy_sha256: &self.policy_sha256,
            installed_pack_tree_sha256: &self.installed_pack_tree_sha256,
            installed_path: &self.installed_path,
            created_at_utc: &self.created_at_utc,
            host_id: &self.host_id,
        }
    }
}

impl RunnerReceipt {
    pub fn verify(&self, key: &TestReceiptKey) -> Result<()> {
        self.validate_fields()?;
        verify_trust(&self.trust, key, &self.payload())
    }

    fn validate_fields(&self) -> Result<()> {
        self.validate_signable_fields()?;
        if self.isolation_backend == FormalIsolationBackend::NativeUntrustedSmoke {
            return Err(validation(
                "formal runner receipt requires trusted isolation",
            ));
        }
        Ok(())
    }

    fn validate_signable_fields(&self) -> Result<()> {
        if self.schema_version != BLIND_RUNNER_RECEIPT_SCHEMA_V01 {
            return Err(validation(
                "unsupported blind runner receipt schema_version",
            ));
        }
        if self.case_count == 0 {
            return Err(validation("runner receipt case_count must be non-zero"));
        }
        validate_nonempty_fields([
            ("runner_version", self.runner_version.as_str()),
            ("run_id", self.run_id.as_str()),
            ("suite_id", self.suite_id.as_str()),
            ("split", self.split.as_str()),
            ("created_at_utc", self.created_at_utc.as_str()),
            ("host_id", self.host_id.as_str()),
        ])?;
        if !matches!(self.split.as_str(), "gate" | "evaluation") {
            return Err(validation(
                "runner receipt split must be gate or evaluation",
            ));
        }
        validate_commit("runner_commit", &self.runner_commit)?;
        validate_commit("method_commit", &self.method_commit)?;
        validate_sha256_fields([
            ("archive_sha256", self.archive_sha256.as_str()),
            (
                "deployment_json_sha256",
                self.deployment_json_sha256.as_str(),
            ),
            (
                "install_receipt_sha256",
                self.install_receipt_sha256.as_str(),
            ),
            (
                "public_manifest_sha256",
                self.public_manifest_sha256.as_str(),
            ),
            ("policy_sha256", self.policy_sha256.as_str()),
            (
                "case_execution_snapshot_digest",
                self.case_execution_snapshot_digest.as_str(),
            ),
            ("observations_sha256", self.observations_sha256.as_str()),
            ("stdout_stderr_digest", self.stdout_stderr_digest.as_str()),
            ("witness_tree_sha256", self.witness_tree_sha256.as_str()),
            ("run_checksums_sha256", self.run_checksums_sha256.as_str()),
        ])?;
        reject_forbidden_public_tokens(self.public_fields())
    }

    fn public_fields(&self) -> [(&str, &str); 18] {
        [
            ("schema_version", &self.schema_version),
            ("runner_version", &self.runner_version),
            ("runner_commit", &self.runner_commit),
            ("run_id", &self.run_id),
            ("suite_id", &self.suite_id),
            ("split", &self.split),
            ("method_commit", &self.method_commit),
            ("created_at_utc", &self.created_at_utc),
            ("host_id", &self.host_id),
            ("trust.key_id", &self.trust.key_id),
            ("archive_sha256", &self.archive_sha256),
            ("deployment_json_sha256", &self.deployment_json_sha256),
            ("install_receipt_sha256", &self.install_receipt_sha256),
            ("public_manifest_sha256", &self.public_manifest_sha256),
            ("policy_sha256", &self.policy_sha256),
            (
                "case_execution_snapshot_digest",
                &self.case_execution_snapshot_digest,
            ),
            ("observations_sha256", &self.observations_sha256),
            ("stdout_stderr_digest", &self.stdout_stderr_digest),
        ]
    }

    fn payload(&self) -> RunnerReceiptPayload<'_> {
        RunnerReceiptPayload {
            schema_version: &self.schema_version,
            runner_version: &self.runner_version,
            runner_commit: &self.runner_commit,
            run_id: &self.run_id,
            suite_id: &self.suite_id,
            split: &self.split,
            method_commit: &self.method_commit,
            archive_sha256: &self.archive_sha256,
            deployment_json_sha256: &self.deployment_json_sha256,
            install_receipt_sha256: &self.install_receipt_sha256,
            public_manifest_sha256: &self.public_manifest_sha256,
            policy_sha256: &self.policy_sha256,
            case_count: self.case_count,
            isolation_backend: &self.isolation_backend,
            case_execution_snapshot_digest: &self.case_execution_snapshot_digest,
            observations_sha256: &self.observations_sha256,
            stdout_stderr_digest: &self.stdout_stderr_digest,
            witness_tree_sha256: &self.witness_tree_sha256,
            run_checksums_sha256: &self.run_checksums_sha256,
            created_at_utc: &self.created_at_utc,
            host_id: &self.host_id,
        }
    }
}

pub fn canonical_receipt_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    serde_json::to_vec(&canonicalize_json(value)).map_err(BlindModelError::from)
}

fn verify_trust<T: Serialize>(
    trust: &ReceiptTrust,
    key: &TestReceiptKey,
    payload: &T,
) -> Result<()> {
    if trust.key_id != key.key_id {
        return Err(validation(
            "receipt trust key_id does not match verification key",
        ));
    }
    if !is_lower_hex(&trust.signature_sha256, 64) {
        return Err(validation(
            "receipt signature_sha256 must be 64 lowercase hexadecimal characters",
        ));
    }
    if trust.signature_sha256 != key.signature_for(payload)? {
        return Err(validation("receipt signature mismatch"));
    }
    Ok(())
}

fn validate_nonempty_fields<const N: usize>(fields: [(&str, &str); N]) -> Result<()> {
    for (name, value) in fields {
        validate_nonempty(name, value)?;
    }
    Ok(())
}

fn validate_nonempty(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(validation(format!("receipt {name} must be non-empty")));
    }
    Ok(())
}

fn validate_commit(name: &str, value: &str) -> Result<()> {
    if !is_lower_hex(value, 40) {
        return Err(validation(format!(
            "receipt {name} must be 40 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_sha256_fields<const N: usize>(fields: [(&str, &str); N]) -> Result<()> {
    for (name, value) in fields {
        if !is_lower_hex(value, 64) {
            return Err(validation(format!(
                "receipt {name} must be 64 lowercase hexadecimal characters"
            )));
        }
    }
    Ok(())
}

fn reject_forbidden_public_tokens<const N: usize>(fields: [(&str, &str); N]) -> Result<()> {
    for (name, value) in fields {
        let lowercase = value.to_lowercase();
        if let Some(token) = MANDATORY_FORBIDDEN_PUBLIC_TOKENS
            .iter()
            .find(|token| lowercase.contains(**token))
        {
            return Err(validation(format!(
                "forbidden public token in receipt {name}: {token}"
            )));
        }
    }
    Ok(())
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn canonicalize_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(canonicalize_json).collect())
        }
        serde_json::Value::Object(values) => {
            let values = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect::<BTreeMap<_, _>>();
            serde_json::Value::Object(values.into_iter().collect())
        }
        value => value,
    }
}

#[derive(Serialize)]
struct InstallReceiptPayload<'a> {
    schema_version: &'a str,
    installer_version: &'a str,
    installer_commit: &'a str,
    method_commit: &'a str,
    archive_sha256: &'a str,
    deployment_json_sha256: &'a str,
    public_manifest_sha256: &'a str,
    policy_sha256: &'a str,
    installed_pack_tree_sha256: &'a str,
    installed_path: &'a str,
    created_at_utc: &'a str,
    host_id: &'a str,
}

#[derive(Serialize)]
struct RunnerReceiptPayload<'a> {
    schema_version: &'a str,
    runner_version: &'a str,
    runner_commit: &'a str,
    run_id: &'a str,
    suite_id: &'a str,
    split: &'a str,
    method_commit: &'a str,
    archive_sha256: &'a str,
    deployment_json_sha256: &'a str,
    install_receipt_sha256: &'a str,
    public_manifest_sha256: &'a str,
    policy_sha256: &'a str,
    case_count: u64,
    isolation_backend: &'a FormalIsolationBackend,
    case_execution_snapshot_digest: &'a str,
    observations_sha256: &'a str,
    stdout_stderr_digest: &'a str,
    witness_tree_sha256: &'a str,
    run_checksums_sha256: &'a str,
    created_at_utc: &'a str,
    host_id: &'a str,
}
