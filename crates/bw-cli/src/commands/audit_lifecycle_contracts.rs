use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    path::{Path, PathBuf},
};

use bw_model::{
    V326ContractRelease, V326ContractReplacement, V326ContractRetention, V326ForeignOwnerSemantics,
    V326LifecycleContractRecord, validate_v3_2_6_lifecycle_contracts,
};
use clap::Args;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct AuditLifecycleContractsArgs {
    #[arg(long)]
    contracts: PathBuf,
    #[arg(long = "registry-manifest")]
    registry_manifest: Option<PathBuf>,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
struct ContractAuditSummary {
    schema_version: &'static str,
    run_id: String,
    contract_count: u64,
    contracts_sha256: String,
    exact_api_count: u64,
    retention_may_retain_count: u64,
    retention_known_count: u64,
    replacement_known_count: u64,
    release_coverage_count: u64,
    owner_semantics_known_count: u64,
    unknown_semantics_count: u64,
    missing_evidence_refs_count: u64,
    source_counts: BTreeMap<String, u64>,
    registry_source_audit: RegistrySourceAuditSummary,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RegistrySourceAuditSummary {
    pub(crate) state: &'static str,
    registry_id: Option<String>,
    component_id: Option<String>,
    registry_run_id: Option<String>,
    registry_manifest_path: Option<String>,
    registry_manifest_sha256: Option<String>,
    lifecycle_contracts_sha256_matches: Option<bool>,
    pub(crate) materialized_api_count: u64,
    pub(crate) registry_source_contract_count: u64,
    registry_evidence_ref_count: u64,
    matched_registry_evidence_ref_count: u64,
    unmatched_registry_evidence_ref_count: u64,
    pub(crate) input_checksum_verified_count: u64,
    pub(crate) input_checksum_missing_path_count: u64,
}

#[derive(Serialize)]
struct AuditOutput {
    kind: &'static str,
    run_id: String,
    contract_count: u64,
    contracts_sha256: String,
    exact_api_count: u64,
    release_coverage_count: u64,
    source_audit_state: &'static str,
    registry_source_contract_count: u64,
    materialized_api_count: u64,
    matched_registry_evidence_ref_count: u64,
    unmatched_registry_evidence_ref_count: u64,
    input_checksum_verified_count: u64,
    input_checksum_missing_path_count: u64,
    output_dir: String,
    audit_path: String,
    checksums_path: String,
}

#[derive(Clone, Debug)]
struct ExpectedRegistryContract {
    api_id: String,
    component_id: String,
    evidence_ref: String,
}

#[derive(Clone, Copy, Debug, Default)]
struct RegistryInputChecksumAudit {
    verified_count: u64,
    missing_path_count: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryManifestInput {
    schema_version: String,
    registry_id: String,
    run_id: String,
    component_id: String,
    contract: Option<RegistryInputManifest>,
    api_map: Option<RegistryInputManifest>,
    #[serde(default)]
    api_maps: Vec<RegistryInputManifest>,
    #[serde(default)]
    materialized_apis: Vec<MaterializedApiManifest>,
    #[serde(default)]
    skipped_api_entries: Vec<SkippedApiManifest>,
    lifecycle_contracts_path: Option<String>,
    lifecycle_contracts_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryInputManifest {
    schema_version: String,
    id: String,
    sha256: String,
    #[serde(default)]
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterializedApiManifest {
    api_map_id: Option<String>,
    map_api_id: String,
    rust_path: String,
    contract_api_id: String,
    lifecycle_contract_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkippedApiManifest {
    #[serde(default)]
    api_map_id: Option<String>,
    map_api_id: String,
    reason: String,
}

pub fn run(args: AuditLifecycleContractsArgs) -> Result<CommandStatus, CliError> {
    if args.run_id.trim().is_empty() {
        return Err(CliError::input("BW-V327-RUN-ID", "run_id 不能为空"));
    }

    let records = read_jsonl::<V326LifecycleContractRecord>(&args.contracts, args.max_line_bytes)?;
    validate_v3_2_6_lifecycle_contracts(records.clone())?;
    let contracts = records
        .into_iter()
        .map(|located| located.value)
        .collect::<Vec<_>>();
    let contracts_sha256 = sha256_file(&args.contracts)?;
    let registry_source_audit = audit_registry_source(
        &contracts,
        contracts_sha256.as_str(),
        args.registry_manifest.as_deref(),
    )?;
    let summary = summarize_contracts(
        &args.run_id,
        &contracts,
        contracts_sha256,
        registry_source_audit,
    );

    fs::create_dir_all(&args.output_dir)?;
    let audit_path = args.output_dir.join("contract-audit.json");
    write_json_file(&audit_path, &summary)?;
    let checksums_path = args.output_dir.join("checksums.txt");
    write_checksums(&args.output_dir, &checksums_path)?;

    let output = AuditOutput {
        kind: "v3-2-7-contract-audit",
        run_id: args.run_id,
        contract_count: summary.contract_count,
        contracts_sha256: summary.contracts_sha256.clone(),
        exact_api_count: summary.exact_api_count,
        release_coverage_count: summary.release_coverage_count,
        source_audit_state: summary.registry_source_audit.state,
        registry_source_contract_count: summary
            .registry_source_audit
            .registry_source_contract_count,
        materialized_api_count: summary.registry_source_audit.materialized_api_count,
        matched_registry_evidence_ref_count: summary
            .registry_source_audit
            .matched_registry_evidence_ref_count,
        unmatched_registry_evidence_ref_count: summary
            .registry_source_audit
            .unmatched_registry_evidence_ref_count,
        input_checksum_verified_count: summary.registry_source_audit.input_checksum_verified_count,
        input_checksum_missing_path_count: summary
            .registry_source_audit
            .input_checksum_missing_path_count,
        output_dir: args.output_dir.display().to_string(),
        audit_path: audit_path.display().to_string(),
        checksums_path: checksums_path.display().to_string(),
    };
    crate::commands::write_json_stdout(&output)?;
    Ok(CommandStatus::Success)
}

pub(crate) fn audit_registry_source_for_contracts(
    contracts: &[V326LifecycleContractRecord],
    contracts_path: &Path,
    registry_manifest_path: Option<&Path>,
) -> Result<(String, RegistrySourceAuditSummary), CliError> {
    let contracts_sha256 = sha256_file(contracts_path)?;
    let source_audit =
        audit_registry_source(contracts, contracts_sha256.as_str(), registry_manifest_path)?;
    Ok((contracts_sha256, source_audit))
}

fn summarize_contracts(
    run_id: &str,
    contracts: &[V326LifecycleContractRecord],
    contracts_sha256: String,
    registry_source_audit: RegistrySourceAuditSummary,
) -> ContractAuditSummary {
    let mut source_counts = BTreeMap::<String, u64>::new();
    for contract in contracts {
        *source_counts.entry(contract.source.clone()).or_default() += 1;
    }

    ContractAuditSummary {
        schema_version: "v3.2.7.contract_audit.1",
        run_id: run_id.to_owned(),
        contract_count: contracts.len() as u64,
        contracts_sha256,
        exact_api_count: contracts
            .iter()
            .filter(|contract| is_exact_api_id(&contract.api_id))
            .count() as u64,
        retention_may_retain_count: contracts
            .iter()
            .filter(|contract| contract.retention == V326ContractRetention::MayRetainCallback)
            .count() as u64,
        retention_known_count: contracts
            .iter()
            .filter(|contract| contract.retention != V326ContractRetention::Unknown)
            .count() as u64,
        replacement_known_count: contracts
            .iter()
            .filter(|contract| contract.replacement != V326ContractReplacement::Unknown)
            .count() as u64,
        release_coverage_count: contracts
            .iter()
            .filter(|contract| contract.release != V326ContractRelease::Unknown)
            .count() as u64,
        owner_semantics_known_count: contracts
            .iter()
            .filter(|contract| contract.owner_semantics != V326ForeignOwnerSemantics::Unknown)
            .count() as u64,
        unknown_semantics_count: contracts
            .iter()
            .filter(|contract| {
                contract.retention == V326ContractRetention::Unknown
                    || contract.replacement == V326ContractReplacement::Unknown
                    || contract.release == V326ContractRelease::Unknown
                    || contract.owner_semantics == V326ForeignOwnerSemantics::Unknown
            })
            .count() as u64,
        missing_evidence_refs_count: contracts
            .iter()
            .filter(|contract| contract.evidence_refs.is_empty())
            .count() as u64,
        source_counts,
        registry_source_audit,
    }
}

fn audit_registry_source(
    contracts: &[V326LifecycleContractRecord],
    contracts_sha256: &str,
    registry_manifest_path: Option<&Path>,
) -> Result<RegistrySourceAuditSummary, CliError> {
    let registry_source_contract_count = contracts
        .iter()
        .filter(|contract| registry_source_contract(contract))
        .count() as u64;
    let Some(registry_manifest_path) = registry_manifest_path else {
        if registry_source_contract_count > 0 {
            return Err(CliError::input(
                "BW-CONTRACT-AUDIT-SOURCE",
                "registry source contract 需要 --registry-manifest 才能审计来源",
            ));
        }
        return Ok(RegistrySourceAuditSummary {
            state: "not_requested",
            registry_id: None,
            component_id: None,
            registry_run_id: None,
            registry_manifest_path: None,
            registry_manifest_sha256: None,
            lifecycle_contracts_sha256_matches: None,
            materialized_api_count: 0,
            registry_source_contract_count,
            registry_evidence_ref_count: 0,
            matched_registry_evidence_ref_count: 0,
            unmatched_registry_evidence_ref_count: 0,
            input_checksum_verified_count: 0,
            input_checksum_missing_path_count: 0,
        });
    };

    let manifest_bytes = fs::read(registry_manifest_path).map_err(|error| {
        CliError::input(
            "BW-CONTRACT-AUDIT-MANIFEST",
            format!("{}: {}", registry_manifest_path.display(), error),
        )
    })?;
    let manifest: RegistryManifestInput =
        serde_json::from_slice(&manifest_bytes).map_err(|error| {
            CliError::input(
                "BW-CONTRACT-AUDIT-MANIFEST",
                format!("{}: {}", registry_manifest_path.display(), error),
            )
        })?;
    if manifest.schema_version != "v3.2.6.callback_retention_registry.1" {
        return Err(CliError::input(
            "BW-CONTRACT-AUDIT-MANIFEST",
            format!(
                "registry manifest schema {} 不受支持",
                manifest.schema_version
            ),
        ));
    }
    validate_registry_manifest_shape(&manifest)?;
    let input_checksum_audit = audit_registry_input_checksums(&manifest, registry_manifest_path)?;
    let contracts_sha_matches = manifest.lifecycle_contracts_sha256 == contracts_sha256;
    if !contracts_sha_matches {
        return Err(CliError::input(
            "BW-CONTRACT-AUDIT-CHECKSUM",
            "registry manifest lifecycle_contracts_sha256 与 contracts 文件不一致",
        ));
    }

    let fallback_api_map_ids = registry_manifest_api_map_ids(&manifest);
    let mut expected_by_ref = BTreeMap::<String, String>::new();
    let mut expected_by_contract = BTreeMap::<String, ExpectedRegistryContract>::new();
    let mut seen_materialized_api_keys = BTreeSet::<String>::new();
    for api in &manifest.materialized_apis {
        let api_map_ids = materialized_api_map_ids(api, &fallback_api_map_ids)?;
        for api_map_id in api_map_ids {
            let materialized_key = format!("{api_map_id}:{}", api.map_api_id);
            if !seen_materialized_api_keys.insert(materialized_key.clone()) {
                return Err(CliError::input(
                    "BW-CONTRACT-AUDIT-MANIFEST",
                    format!("registry manifest materialized api 重复: {materialized_key}"),
                ));
            }
            let evidence_ref = format!("registry:{api_map_id}:{}", api.map_api_id);
            if expected_by_ref
                .insert(evidence_ref.clone(), api.lifecycle_contract_id.clone())
                .is_some()
            {
                return Err(CliError::input(
                    "BW-CONTRACT-AUDIT-MANIFEST",
                    format!("registry manifest evidence ref 重复: {evidence_ref}"),
                ));
            }
            if expected_by_contract
                .insert(
                    api.lifecycle_contract_id.clone(),
                    ExpectedRegistryContract {
                        api_id: api.map_api_id.clone(),
                        component_id: manifest.component_id.clone(),
                        evidence_ref,
                    },
                )
                .is_some()
            {
                return Err(CliError::input(
                    "BW-CONTRACT-AUDIT-MANIFEST",
                    format!(
                        "registry manifest lifecycle contract id 重复: {}",
                        api.lifecycle_contract_id
                    ),
                ));
            }
        }
    }

    let contracts_by_id = contracts
        .iter()
        .map(|contract| (contract.contract_id.as_str(), contract))
        .collect::<BTreeMap<_, _>>();
    let mut missing_manifest_contracts = Vec::<String>::new();
    let mut mismatched_manifest_contracts = Vec::<String>::new();
    for (contract_id, expected) in &expected_by_contract {
        let Some(contract) = contracts_by_id.get(contract_id.as_str()) else {
            missing_manifest_contracts.push(contract_id.clone());
            continue;
        };
        if contract.api_id != expected.api_id
            || contract.component_id != expected.component_id
            || contract.scope != "callback_retention_registry"
            || contract.source != "callback_retention_contract_registry"
            || !contract
                .evidence_refs
                .iter()
                .any(|reference| reference == &expected.evidence_ref)
        {
            mismatched_manifest_contracts.push(format!(
                "{} expected api={} component={} evidence={}",
                contract.contract_id, expected.api_id, expected.component_id, expected.evidence_ref
            ));
        }
    }

    let mut registry_source_without_evidence = Vec::<String>::new();
    let mut extra_registry_source_contracts = Vec::<String>::new();
    let mut registry_evidence_ref_count = 0_u64;
    let mut matched_registry_evidence_ref_count = 0_u64;
    let mut unmatched_registry_evidence_ref_count = 0_u64;
    let mut unmatched = Vec::<String>::new();
    for contract in contracts {
        if registry_source_contract(contract) {
            if contract
                .evidence_refs
                .iter()
                .all(|reference| !reference.starts_with("registry:"))
            {
                registry_source_without_evidence.push(contract.contract_id.clone());
            }
            if !expected_by_contract.contains_key(&contract.contract_id) {
                extra_registry_source_contracts.push(contract.contract_id.clone());
            }
        }
        for evidence_ref in contract
            .evidence_refs
            .iter()
            .filter(|reference| reference.starts_with("registry:"))
        {
            registry_evidence_ref_count += 1;
            if expected_by_ref
                .get(evidence_ref)
                .is_some_and(|contract_id| contract_id == &contract.contract_id)
            {
                matched_registry_evidence_ref_count += 1;
            } else {
                unmatched_registry_evidence_ref_count += 1;
                unmatched.push(format!("{} -> {}", contract.contract_id, evidence_ref));
            }
        }
    }
    if !missing_manifest_contracts.is_empty()
        || !extra_registry_source_contracts.is_empty()
        || unmatched_registry_evidence_ref_count > 0
    {
        let mut details = Vec::new();
        if !missing_manifest_contracts.is_empty() {
            details.push(format!(
                "manifest materialized api 缺少 contract record: {}",
                missing_manifest_contracts.join(", ")
            ));
        }
        if !extra_registry_source_contracts.is_empty() {
            details.push(format!(
                "contracts 中存在 manifest 未列出的 registry source record: {}",
                extra_registry_source_contracts.join(", ")
            ));
        }
        if !unmatched.is_empty() {
            details.push(format!(
                "registry evidence_refs 无法由 registry manifest 回查: {}",
                unmatched.join(", ")
            ));
        }
        return Err(CliError::input(
            "BW-CONTRACT-AUDIT-EVIDENCE",
            details.join("; "),
        ));
    }
    if !mismatched_manifest_contracts.is_empty() || !registry_source_without_evidence.is_empty() {
        let mut details = Vec::new();
        if !mismatched_manifest_contracts.is_empty() {
            details.push(format!(
                "registry source record 与 manifest 字段不一致: {}",
                mismatched_manifest_contracts.join(", ")
            ));
        }
        if !registry_source_without_evidence.is_empty() {
            details.push(format!(
                "registry source record 缺少 registry evidence_ref: {}",
                registry_source_without_evidence.join(", ")
            ));
        }
        return Err(CliError::input(
            "BW-CONTRACT-AUDIT-SOURCE",
            details.join("; "),
        ));
    }

    Ok(RegistrySourceAuditSummary {
        state: "registry_manifest_verified",
        registry_id: Some(manifest.registry_id),
        component_id: Some(manifest.component_id),
        registry_run_id: Some(manifest.run_id),
        registry_manifest_path: Some(registry_manifest_path.display().to_string()),
        registry_manifest_sha256: Some(hex_digest(Sha256::digest(&manifest_bytes))),
        lifecycle_contracts_sha256_matches: Some(contracts_sha_matches),
        materialized_api_count: manifest.materialized_apis.len() as u64,
        registry_source_contract_count,
        registry_evidence_ref_count,
        matched_registry_evidence_ref_count,
        unmatched_registry_evidence_ref_count,
        input_checksum_verified_count: input_checksum_audit.verified_count,
        input_checksum_missing_path_count: input_checksum_audit.missing_path_count,
    })
}

fn registry_source_contract(contract: &V326LifecycleContractRecord) -> bool {
    contract.source == "callback_retention_contract_registry"
        || contract
            .evidence_refs
            .iter()
            .any(|reference| reference.starts_with("registry:"))
}

fn audit_registry_input_checksums(
    manifest: &RegistryManifestInput,
    registry_manifest_path: &Path,
) -> Result<RegistryInputChecksumAudit, CliError> {
    let mut audit = RegistryInputChecksumAudit::default();
    let mut seen_inputs = BTreeSet::<(String, String, String)>::new();
    if let Some(contract) = &manifest.contract {
        audit_registry_input_checksum(
            "contract",
            contract,
            registry_manifest_path,
            &mut seen_inputs,
            &mut audit,
        )?;
    }
    if let Some(api_map) = &manifest.api_map {
        audit_registry_input_checksum(
            "api_map",
            api_map,
            registry_manifest_path,
            &mut seen_inputs,
            &mut audit,
        )?;
    }
    for api_map in &manifest.api_maps {
        audit_registry_input_checksum(
            "api_maps",
            api_map,
            registry_manifest_path,
            &mut seen_inputs,
            &mut audit,
        )?;
    }
    Ok(audit)
}

fn audit_registry_input_checksum(
    field: &str,
    input: &RegistryInputManifest,
    registry_manifest_path: &Path,
    seen_inputs: &mut BTreeSet<(String, String, String)>,
    audit: &mut RegistryInputChecksumAudit,
) -> Result<(), CliError> {
    let Some(path) = input.path.as_deref() else {
        audit.missing_path_count += 1;
        return Ok(());
    };
    let input_key = (input.id.clone(), input.sha256.clone(), path.to_owned());
    if !seen_inputs.insert(input_key) {
        return Ok(());
    }
    let input_path = resolve_manifest_input_path(registry_manifest_path, path);
    let actual = sha256_file(&input_path)?;
    if actual != input.sha256 {
        return Err(CliError::input(
            "BW-CONTRACT-AUDIT-CHECKSUM",
            format!(
                "registry manifest {field} {} sha256 不匹配: manifest={} actual={} path={}",
                input.id,
                input.sha256,
                actual,
                input_path.display()
            ),
        ));
    }
    audit.verified_count += 1;
    Ok(())
}

fn resolve_manifest_input_path(registry_manifest_path: &Path, input_path: &str) -> PathBuf {
    let path = PathBuf::from(input_path);
    if path.is_absolute() {
        return path;
    }
    registry_manifest_path
        .parent()
        .map(|parent| parent.join(path.clone()))
        .unwrap_or(path)
}

fn validate_registry_manifest_shape(manifest: &RegistryManifestInput) -> Result<(), CliError> {
    let Some(contract) = &manifest.contract else {
        return Err(CliError::input(
            "BW-CONTRACT-AUDIT-MANIFEST",
            "registry manifest 缺少 contract 输入摘要",
        ));
    };
    validate_registry_input_manifest("contract", contract)?;
    if let Some(api_map) = &manifest.api_map {
        validate_registry_input_manifest("api_map", api_map)?;
    }
    for api_map in &manifest.api_maps {
        validate_registry_input_manifest("api_maps", api_map)?;
    }
    let api_map_ids = registry_manifest_api_map_ids(manifest);
    if api_map_ids.is_empty() {
        return Err(CliError::input(
            "BW-CONTRACT-AUDIT-MANIFEST",
            "registry manifest 缺少 api_map/api_maps 输入摘要",
        ));
    }
    let mut unique_api_map_ids = BTreeSet::new();
    for api_map_id in &api_map_ids {
        if !unique_api_map_ids.insert(api_map_id.clone()) {
            return Err(CliError::input(
                "BW-CONTRACT-AUDIT-MANIFEST",
                format!("registry manifest api_map id 重复: {api_map_id}"),
            ));
        }
    }
    if manifest
        .lifecycle_contracts_path
        .as_deref()
        .is_some_and(|path| path.trim().is_empty())
    {
        return Err(CliError::input(
            "BW-CONTRACT-AUDIT-MANIFEST",
            "registry manifest lifecycle_contracts_path 不能为空",
        ));
    }
    let mut materialized_keys = BTreeSet::new();
    for api in &manifest.materialized_apis {
        require_manifest_text("materialized_apis.map_api_id", &api.map_api_id)?;
        require_manifest_text("materialized_apis.rust_path", &api.rust_path)?;
        require_manifest_text("materialized_apis.contract_api_id", &api.contract_api_id)?;
        require_manifest_text(
            "materialized_apis.lifecycle_contract_id",
            &api.lifecycle_contract_id,
        )?;
        if let Some(api_map_id) = &api.api_map_id
            && !unique_api_map_ids.contains(api_map_id)
        {
            return Err(CliError::input(
                "BW-CONTRACT-AUDIT-MANIFEST",
                format!("materialized api 引用未知 api_map_id: {api_map_id}"),
            ));
        }
        for api_map_id in materialized_api_map_ids(api, &api_map_ids)? {
            let key = format!("{api_map_id}:{}", api.map_api_id);
            if !materialized_keys.insert(key.clone()) {
                return Err(CliError::input(
                    "BW-CONTRACT-AUDIT-MANIFEST",
                    format!("registry manifest materialized api 重复: {key}"),
                ));
            }
        }
    }
    let mut skipped_keys = BTreeSet::new();
    for skipped in &manifest.skipped_api_entries {
        require_manifest_text("skipped_api_entries.map_api_id", &skipped.map_api_id)?;
        require_manifest_text("skipped_api_entries.reason", &skipped.reason)?;
        if let Some(api_map_id) = &skipped.api_map_id
            && !unique_api_map_ids.contains(api_map_id)
        {
            return Err(CliError::input(
                "BW-CONTRACT-AUDIT-MANIFEST",
                format!("skipped api 引用未知 api_map_id: {api_map_id}"),
            ));
        }
        for api_map_id in skipped_api_map_ids(skipped, &api_map_ids)? {
            let key = format!("{api_map_id}:{}", skipped.map_api_id);
            if !skipped_keys.insert(key.clone()) {
                return Err(CliError::input(
                    "BW-CONTRACT-AUDIT-MANIFEST",
                    format!("registry manifest skipped api 重复: {key}"),
                ));
            }
            if materialized_keys.contains(&key) {
                return Err(CliError::input(
                    "BW-CONTRACT-AUDIT-MANIFEST",
                    format!("registry manifest api 同时出现在 materialized 和 skipped: {key}"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_registry_input_manifest(
    field: &str,
    input: &RegistryInputManifest,
) -> Result<(), CliError> {
    require_manifest_text(&format!("{field}.schema_version"), &input.schema_version)?;
    require_manifest_text(&format!("{field}.id"), &input.id)?;
    if !is_hex_sha256(&input.sha256) {
        return Err(CliError::input(
            "BW-CONTRACT-AUDIT-MANIFEST",
            format!("{field}.sha256 不是 sha256 hex"),
        ));
    }
    if input
        .path
        .as_deref()
        .is_some_and(|path| path.trim().is_empty())
    {
        return Err(CliError::input(
            "BW-CONTRACT-AUDIT-MANIFEST",
            format!("{field}.path 不能为空"),
        ));
    }
    Ok(())
}

fn require_manifest_text(field: &str, value: &str) -> Result<(), CliError> {
    if value.trim().is_empty() {
        return Err(CliError::input(
            "BW-CONTRACT-AUDIT-MANIFEST",
            format!("registry manifest {field} 不能为空"),
        ));
    }
    Ok(())
}

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn registry_manifest_api_map_ids(manifest: &RegistryManifestInput) -> Vec<String> {
    if !manifest.api_maps.is_empty() {
        return manifest
            .api_maps
            .iter()
            .map(|api_map| api_map.id.clone())
            .collect();
    }
    manifest
        .api_map
        .as_ref()
        .map(|api_map| vec![api_map.id.clone()])
        .unwrap_or_default()
}

fn materialized_api_map_ids(
    api: &MaterializedApiManifest,
    fallback_api_map_ids: &[String],
) -> Result<Vec<String>, CliError> {
    manifest_entry_api_map_ids(
        "materialized api",
        &api.map_api_id,
        api.api_map_id.as_ref(),
        fallback_api_map_ids,
    )
}

fn skipped_api_map_ids(
    skipped: &SkippedApiManifest,
    fallback_api_map_ids: &[String],
) -> Result<Vec<String>, CliError> {
    manifest_entry_api_map_ids(
        "skipped api",
        &skipped.map_api_id,
        skipped.api_map_id.as_ref(),
        fallback_api_map_ids,
    )
}

fn manifest_entry_api_map_ids(
    field: &str,
    map_api_id: &str,
    api_map_id: Option<&String>,
    fallback_api_map_ids: &[String],
) -> Result<Vec<String>, CliError> {
    if let Some(api_map_id) = api_map_id {
        return Ok(vec![api_map_id.clone()]);
    }
    match fallback_api_map_ids {
        [single] => Ok(vec![single.clone()]),
        [] => Err(CliError::input(
            "BW-CONTRACT-AUDIT-MANIFEST",
            format!(
                "registry manifest {field} {map_api_id} 缺少 api_map_id 且没有 api_map fallback"
            ),
        )),
        _ => Err(CliError::input(
            "BW-CONTRACT-AUDIT-MANIFEST",
            format!(
                "registry manifest {field} {map_api_id} 缺少 api_map_id，multi-map 场景不可去歧义"
            ),
        )),
    }
}

fn is_exact_api_id(value: &str) -> bool {
    let value = value.trim();
    let canonical_rust_path = value.contains("::");
    let canonical_api_map_id = value.strip_prefix("api:").is_some_and(|suffix| {
        suffix.split(':').count() >= 3 && !suffix.split(':').any(str::is_empty)
    });
    !value.is_empty()
        && (canonical_rust_path || canonical_api_map_id)
        && !value.contains('*')
        && !value.contains('?')
        && !value.contains("...")
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    let file = File::create(path)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {}", path.display(), error)))?;
    serde_json::to_writer_pretty(file, value).map_err(|error| CliError::internal(error.to_string()))
}

fn write_checksums(output_dir: &Path, checksums_path: &Path) -> Result<(), CliError> {
    let lines = [format!(
        "{}  contract-audit.json",
        sha256_file(&output_dir.join("contract-audit.json"))?
    )];
    fs::write(checksums_path, format!("{}\n", lines.join("\n"))).map_err(|error| {
        CliError::input("BW-IO", format!("{}: {}", checksums_path.display(), error))
    })
}

fn sha256_file(path: &Path) -> Result<String, CliError> {
    let bytes = fs::read(path)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {}", path.display(), error)))?;
    Ok(hex_digest(Sha256::digest(bytes)))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
