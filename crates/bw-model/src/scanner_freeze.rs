use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ModelError;

pub const V3_3_SCANNER_FREEZE_SCHEMA_V1: &str = "v3.3.scanner_freeze.1";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V33ScannerFreezeRecord {
    pub schema_version: String,
    pub run_id: String,
    pub frozen_at_utc: String,
    pub method: V33ScannerFreezeMethod,
    pub inputs: V33ScannerFreezeInputs,
    pub toolchain: V33ScannerFreezeToolchain,
    pub source_identity_scan: V33ScannerFreezeSourceIdentityScan,
    pub outputs: V33ScannerFreezeOutputs,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V33ScannerFreezeMethod {
    pub commit: String,
    pub branch: String,
    pub worktree_required_clean: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V33ScannerFreezeInputs {
    pub corpus_manifest_sha256: String,
    pub anonymous_pairs_sha256: String,
    pub feature_profile_sha256: String,
    pub source_checksums_sha256: String,
    pub contract_toml_sha256: String,
    #[serde(default)]
    pub api_map_sha256: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V33ScannerFreezeToolchain {
    pub cargo_build_locked_for_method: bool,
    pub scanner_build_precheck_locked: bool,
    pub static_facts_rustup_toolchain: String,
    pub static_facts_dyld_library_path: String,
    pub stable_rustc: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V33ScannerFreezeSourceIdentityScan {
    pub scanner_metadata_forbidden_tokens: String,
    pub source_tree_strong_identity_tokens_zero: bool,
    #[serde(default)]
    pub generic_source_token_counts: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V33ScannerFreezeOutputs {
    pub buildability_sha256: String,
    pub boundary_index_sha256: String,
    pub static_facts_sha256: String,
    pub mir_coverage_sha256: String,
    pub candidates_sha256: String,
    pub contracts_sha256: String,
    pub lifecycle_evidence_sha256: String,
    pub lifecycle_facts_sha256: String,
    pub lifecycle_coverage_sha256: String,
    pub lifecycle_features_sha256: String,
    pub ranked_candidates_sha256: String,
}

pub fn validate_v3_3_scanner_freeze(record: &V33ScannerFreezeRecord) -> Result<(), ModelError> {
    if record.schema_version != V3_3_SCANNER_FREEZE_SCHEMA_V1 {
        return Err(ModelError::validation(
            "BW-V33-FREEZE-SCHEMA",
            format!(
                "scanner freeze schema 必须是 {V3_3_SCANNER_FREEZE_SCHEMA_V1}，实际为 {}",
                record.schema_version
            ),
        ));
    }
    validate_required("run_id", &record.run_id)?;
    validate_required("frozen_at_utc", &record.frozen_at_utc)?;
    validate_required("method.branch", &record.method.branch)?;
    validate_commit("method.commit", &record.method.commit)?;
    if !record.method.worktree_required_clean {
        return Err(ModelError::validation(
            "BW-V33-FREEZE-WORKTREE",
            "scanner freeze 必须要求 clean worktree",
        ));
    }
    if !record.toolchain.cargo_build_locked_for_method {
        return Err(ModelError::validation(
            "BW-V33-FREEZE-LOCKED",
            "method build 必须记录为 cargo --locked",
        ));
    }
    validate_required(
        "toolchain.static_facts_rustup_toolchain",
        &record.toolchain.static_facts_rustup_toolchain,
    )?;
    validate_required(
        "toolchain.static_facts_dyld_library_path",
        &record.toolchain.static_facts_dyld_library_path,
    )?;
    validate_required("toolchain.stable_rustc", &record.toolchain.stable_rustc)?;
    if record
        .source_identity_scan
        .scanner_metadata_forbidden_tokens
        != "pass"
    {
        return Err(ModelError::validation(
            "BW-V33-FREEZE-TOKEN-SCAN",
            "scanner metadata forbidden-token scan 必须为 pass",
        ));
    }
    if !record
        .source_identity_scan
        .source_tree_strong_identity_tokens_zero
    {
        return Err(ModelError::validation(
            "BW-V33-FREEZE-SOURCE-IDENTITY",
            "source tree strong identity token scan 必须为 0",
        ));
    }

    validate_hash(
        "inputs.corpus_manifest_sha256",
        &record.inputs.corpus_manifest_sha256,
    )?;
    validate_hash(
        "inputs.anonymous_pairs_sha256",
        &record.inputs.anonymous_pairs_sha256,
    )?;
    validate_hash(
        "inputs.feature_profile_sha256",
        &record.inputs.feature_profile_sha256,
    )?;
    validate_hash(
        "inputs.source_checksums_sha256",
        &record.inputs.source_checksums_sha256,
    )?;
    validate_hash(
        "inputs.contract_toml_sha256",
        &record.inputs.contract_toml_sha256,
    )?;
    if record.inputs.api_map_sha256.is_empty() {
        return Err(ModelError::validation(
            "BW-V33-FREEZE-API-MAP",
            "api_map_sha256 不能为空",
        ));
    }
    for (name, hash) in &record.inputs.api_map_sha256 {
        validate_required("inputs.api_map_sha256 key", name)?;
        validate_hash("inputs.api_map_sha256 value", hash)?;
    }

    validate_hash(
        "outputs.buildability_sha256",
        &record.outputs.buildability_sha256,
    )?;
    validate_hash(
        "outputs.boundary_index_sha256",
        &record.outputs.boundary_index_sha256,
    )?;
    validate_hash(
        "outputs.static_facts_sha256",
        &record.outputs.static_facts_sha256,
    )?;
    validate_hash(
        "outputs.mir_coverage_sha256",
        &record.outputs.mir_coverage_sha256,
    )?;
    validate_hash(
        "outputs.candidates_sha256",
        &record.outputs.candidates_sha256,
    )?;
    validate_hash("outputs.contracts_sha256", &record.outputs.contracts_sha256)?;
    validate_hash(
        "outputs.lifecycle_evidence_sha256",
        &record.outputs.lifecycle_evidence_sha256,
    )?;
    validate_hash(
        "outputs.lifecycle_facts_sha256",
        &record.outputs.lifecycle_facts_sha256,
    )?;
    validate_hash(
        "outputs.lifecycle_coverage_sha256",
        &record.outputs.lifecycle_coverage_sha256,
    )?;
    validate_hash(
        "outputs.lifecycle_features_sha256",
        &record.outputs.lifecycle_features_sha256,
    )?;
    validate_hash(
        "outputs.ranked_candidates_sha256",
        &record.outputs.ranked_candidates_sha256,
    )?;
    Ok(())
}

fn validate_required(field: &'static str, value: &str) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(ModelError::validation(
            "BW-V33-FREEZE-REQUIRED",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn validate_commit(field: &'static str, value: &str) -> Result<(), ModelError> {
    validate_required(field, value)?;
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ModelError::validation(
            "BW-V33-FREEZE-COMMIT",
            format!("{field} 必须是 40 位 git commit SHA"),
        ));
    }
    Ok(())
}

fn validate_hash(field: &'static str, value: &str) -> Result<(), ModelError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ModelError::validation(
            "BW-V33-FREEZE-SHA256",
            format!("{field} 必须是 64 位小写 SHA-256"),
        ));
    }
    Ok(())
}
