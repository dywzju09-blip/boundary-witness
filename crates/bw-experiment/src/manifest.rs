use std::{
    fmt::Write as _,
    time::{SystemTime, UNIX_EPOCH},
};

use bw_model::{BuildId, ExecutionResult, RUN_SCHEMA_V01, RunId, RunManifest, ToolchainVersions};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{ExperimentError, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunMetadata {
    pub git_commit: String,
    pub deployment_sha256: String,
    pub image_digest: String,
    pub config_digest: String,
    pub build_id: String,
    pub host: String,
    pub cpu_limit: Option<u32>,
    pub seed: Option<u64>,
    pub toolchains: ToolchainVersions,
}

pub(crate) fn build_manifest(
    run_id: &str,
    metadata: &RunMetadata,
    started_at_utc: &str,
    completed_at_utc: Option<String>,
    execution: Option<ExecutionResult>,
) -> RunManifest {
    RunManifest {
        schema_version: RUN_SCHEMA_V01.to_owned(),
        run_id: RunId(run_id.to_owned()),
        build_id: BuildId(metadata.build_id.clone()),
        git_commit: metadata.git_commit.clone(),
        deployment_sha256: metadata.deployment_sha256.clone(),
        image_digest: metadata.image_digest.clone(),
        config_digest: metadata.config_digest.clone(),
        host: metadata.host.clone(),
        cpu_limit: metadata.cpu_limit,
        seed: metadata.seed,
        toolchains: metadata.toolchains.clone(),
        started_at_utc: started_at_utc.to_owned(),
        completed_at_utc,
        execution,
    }
}

pub(crate) fn write_json_file<T: Serialize>(path: &std::path::Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    std::fs::write(path, bytes).map_err(|error| ExperimentError::io(path, error))
}

#[must_use]
pub fn now_utc_string() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "unix:{}.{:09}Z",
        duration.as_secs(),
        duration.subsec_nanos()
    )
}

pub fn generate_run_id(commit: &str) -> Result<String> {
    let short = commit.get(0..7).ok_or_else(|| {
        ExperimentError::InvalidInput("git commit must have at least 7 characters".to_owned())
    })?;
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nonce_input = format!(
        "{}:{}:{}",
        duration.as_secs(),
        duration.subsec_nanos(),
        std::process::id()
    );
    let digest = Sha256::digest(nonce_input.as_bytes());
    let mut nonce = String::with_capacity(8);
    for byte in &digest[..4] {
        write!(&mut nonce, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(format!("unix{}-{}-{}", duration.as_secs(), short, nonce))
}
