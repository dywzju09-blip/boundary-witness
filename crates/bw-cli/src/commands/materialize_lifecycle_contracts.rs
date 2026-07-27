use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use bw_model::{
    CallbackRetentionRegistry, ContractClauseKind, RegistrationRole, ReleaseBehavior,
    V3_2_6_LIFECYCLE_CONTRACT_SCHEMA_V1, V326ContractRelease, V326ContractReplacement,
    V326ContractRetention, V326ForeignOwnerSemantics, V326LifecycleContractRecord,
    validate_v3_2_6_lifecycle_contracts,
};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::exit::{CliError, CommandStatus};

const REGISTRY_MANIFEST_SCHEMA_V1: &str = "v3.2.6.callback_retention_registry.1";

#[derive(Args)]
pub struct MaterializeLifecycleContractsArgs {
    #[arg(long = "contract-toml")]
    contract_toml: PathBuf,
    #[arg(long = "api-map-toml", required = true)]
    api_map_tomls: Vec<PathBuf>,
    #[arg(long)]
    run_id: String,
    #[arg(long = "component-id")]
    component_id: String,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
}

#[derive(Clone, Serialize)]
struct RegistryInputManifest {
    schema_version: String,
    id: String,
    sha256: String,
    path: String,
}

#[derive(Serialize)]
struct MaterializedApiManifest {
    api_map_id: String,
    map_api_id: String,
    rust_path: String,
    contract_api_id: String,
    lifecycle_contract_id: String,
}

#[derive(Serialize)]
struct SkippedApiManifest {
    api_map_id: String,
    map_api_id: String,
    reason: &'static str,
}

#[derive(Serialize)]
struct RegistryManifest {
    schema_version: &'static str,
    registry_id: String,
    run_id: String,
    component_id: String,
    contract: RegistryInputManifest,
    // 兼容 v3.2.6 初始 manifest 消费方；多 map 场景取第一个输入。
    api_map: RegistryInputManifest,
    api_maps: Vec<RegistryInputManifest>,
    materialized_apis: Vec<MaterializedApiManifest>,
    skipped_api_entries: Vec<SkippedApiManifest>,
    lifecycle_contracts_path: &'static str,
    lifecycle_contracts_sha256: String,
}

#[derive(Serialize)]
struct MaterializeOutput {
    kind: &'static str,
    run_id: String,
    component_id: String,
    materialized_count: usize,
    skipped_count: usize,
    output_dir: String,
    contracts_path: String,
    registry_manifest_path: String,
    checksums_path: String,
}

pub fn run(args: MaterializeLifecycleContractsArgs) -> Result<CommandStatus, CliError> {
    require_cli_text("run_id", &args.run_id)?;
    require_cli_text("component_id", &args.component_id)?;

    let contract_toml = read_toml(&args.contract_toml)?;
    let registries = args
        .api_map_tomls
        .iter()
        .map(|path| {
            let api_map_toml = read_toml(path)?;
            let registry =
                CallbackRetentionRegistry::from_toml_strs(&contract_toml, &api_map_toml)?;
            Ok((registry, api_map_toml))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    validate_unique_api_map_ids(&registries)?;
    let (records, materialized_apis, skipped_api_entries) = materialize(&registries, &args);
    if records.is_empty() {
        return Err(CliError::input(
            "BW-CONTRACT-REGISTRY-EMPTY",
            "没有可按精确 role 与 clause materialize 的 lifecycle contract record",
        ));
    }
    validate_v3_2_6_lifecycle_contracts(records.iter().cloned().enumerate().map(
        |(index, value)| {
            bw_model::Located {
                path: args
                    .api_map_tomls
                    .first()
                    .cloned()
                    .unwrap_or_else(|| args.contract_toml.clone()),
                line: index + 1,
                value,
            }
        },
    ))?;

    fs::create_dir_all(&args.output_dir)?;
    let contracts_path = args.output_dir.join("lifecycle-contracts.jsonl");
    write_jsonl(&contracts_path, &records)?;
    let contracts_sha256 = sha256_file(&contracts_path)?;

    let registry_manifest_path = args.output_dir.join("registry-manifest.json");
    let api_maps = registries
        .iter()
        .zip(args.api_map_tomls.iter())
        .map(
            |((registry, api_map_toml), api_map_path)| RegistryInputManifest {
                schema_version: registry.api_map.schema_version.clone(),
                id: registry.api_map.map_id.clone(),
                sha256: hex_digest(Sha256::digest(api_map_toml.as_bytes())),
                path: api_map_path.display().to_string(),
            },
        )
        .collect::<Vec<_>>();
    let registry_id = registry_id(&registries);
    let manifest = RegistryManifest {
        schema_version: REGISTRY_MANIFEST_SCHEMA_V1,
        registry_id,
        run_id: args.run_id.clone(),
        component_id: args.component_id.clone(),
        contract: RegistryInputManifest {
            schema_version: registries[0].0.contract.schema_version.clone(),
            id: registries[0].0.contract.contract_id.clone(),
            sha256: hex_digest(Sha256::digest(contract_toml.as_bytes())),
            path: args.contract_toml.display().to_string(),
        },
        api_map: api_maps[0].clone(),
        api_maps,
        materialized_apis,
        skipped_api_entries,
        lifecycle_contracts_path: "lifecycle-contracts.jsonl",
        lifecycle_contracts_sha256: contracts_sha256,
    };
    write_json_file(&registry_manifest_path, &manifest)?;

    let checksums_path = args.output_dir.join("checksums.sha256");
    write_checksums(&contracts_path, &registry_manifest_path, &checksums_path)?;

    crate::commands::write_json_stdout(&MaterializeOutput {
        kind: "v3-2-6-lifecycle-contract-registry",
        run_id: args.run_id,
        component_id: args.component_id,
        materialized_count: records.len(),
        skipped_count: manifest.skipped_api_entries.len(),
        output_dir: args.output_dir.display().to_string(),
        contracts_path: contracts_path.display().to_string(),
        registry_manifest_path: registry_manifest_path.display().to_string(),
        checksums_path: checksums_path.display().to_string(),
    })?;
    Ok(CommandStatus::Success)
}

fn validate_unique_api_map_ids(
    registries: &[(CallbackRetentionRegistry, String)],
) -> Result<(), CliError> {
    let mut seen = BTreeSet::new();
    for (registry, _) in registries {
        if !seen.insert(registry.api_map.map_id.clone()) {
            return Err(CliError::input(
                "BW-CONTRACT-REGISTRY-MANIFEST",
                format!("api_map id 重复: {}", registry.api_map.map_id),
            ));
        }
    }
    Ok(())
}

fn materialize(
    registries: &[(CallbackRetentionRegistry, String)],
    args: &MaterializeLifecycleContractsArgs,
) -> (
    Vec<V326LifecycleContractRecord>,
    Vec<MaterializedApiManifest>,
    Vec<SkippedApiManifest>,
) {
    let mut records = Vec::new();
    let mut materialized_apis = Vec::new();
    let mut skipped_api_entries = Vec::new();

    for (registry, _) in registries {
        let clause_kinds = registry
            .contract
            .clauses
            .iter()
            .map(|clause| (clause.clause_id.as_str(), clause.kind))
            .collect::<BTreeMap<_, _>>();
        for api in &registry.api_map.apis {
            let matching_entries = registry
                .contract
                .api_entries
                .iter()
                .filter(|entry| entry.api_id == api.contract_api_id)
                .collect::<Vec<_>>();
            let materializable = matching_entries.into_iter().find(|entry| {
                matches!(
                    (
                        entry.registration_role,
                        clause_kinds.get(entry.clause_id.as_str())
                    ),
                    (
                        Some(RegistrationRole::Register),
                        Some(ContractClauseKind::RetainAfterRegister)
                    ) | (
                        Some(RegistrationRole::Unregister),
                        Some(ContractClauseKind::ReleaseOnUnregister)
                    )
                )
            });
            let Some(entry) = materializable else {
                skipped_api_entries.push(SkippedApiManifest {
                    api_map_id: registry.api_map.map_id.clone(),
                    map_api_id: api.api_id.clone(),
                    reason: "缺少精确的 registration role 与 lifecycle clause",
                });
                continue;
            };

            let contract_id = format!("{}#{}", registry.contract.contract_id, api.api_id);
            records.push(V326LifecycleContractRecord {
                schema_version: V3_2_6_LIFECYCLE_CONTRACT_SCHEMA_V1.to_owned(),
                run_id: args.run_id.clone(),
                contract_id: contract_id.clone(),
                component_id: args.component_id.clone(),
                // The compiler emits this API-map identity in authoritative static facts. The
                // human-readable Rust path remains independently pinned in the registry manifest.
                api_id: api.api_id.clone(),
                retention: match entry.registration_role {
                    Some(RegistrationRole::Register) => V326ContractRetention::MayRetainCallback,
                    _ => V326ContractRetention::Unknown,
                },
                replacement: match entry.release_behavior {
                    ReleaseBehavior::ReleaseAndReplace => {
                        V326ContractReplacement::ReplacesPriorRegistration
                    }
                    _ => V326ContractReplacement::Unknown,
                },
                release: match entry.release_behavior {
                    ReleaseBehavior::ReleaseCurrent | ReleaseBehavior::ReleaseAndReplace => {
                        V326ContractRelease::CallbackOnly
                    }
                    ReleaseBehavior::None | ReleaseBehavior::ReleaseOnOwnerDrop => {
                        V326ContractRelease::Unknown
                    }
                },
                owner_semantics: if entry.owner_kind == "external_owner" {
                    V326ForeignOwnerSemantics::ForeignOwned
                } else {
                    V326ForeignOwnerSemantics::Unknown
                },
                scope: "callback_retention_registry".to_owned(),
                source: "callback_retention_contract_registry".to_owned(),
                evidence_refs: vec![format!(
                    "registry:{}:{}",
                    registry.api_map.map_id, api.api_id
                )],
                notes: vec![format!(
                    "由 contract API {} materialize，callback family 为 {}",
                    api.contract_api_id, api.callback_family
                )],
            });
            materialized_apis.push(MaterializedApiManifest {
                api_map_id: registry.api_map.map_id.clone(),
                map_api_id: api.api_id.clone(),
                rust_path: api.rust_path.clone(),
                contract_api_id: api.contract_api_id.clone(),
                lifecycle_contract_id: contract_id,
            });
        }
    }
    (records, materialized_apis, skipped_api_entries)
}

fn registry_id(registries: &[(CallbackRetentionRegistry, String)]) -> String {
    let contract_id = &registries[0].0.contract.contract_id;
    let api_map_ids = registries
        .iter()
        .map(|(registry, _)| registry.api_map.map_id.as_str())
        .collect::<Vec<_>>();
    format!("registry:{contract_id}:{}", api_map_ids.join("+"))
}

fn require_cli_text(field: &str, value: &str) -> Result<(), CliError> {
    if value.trim().is_empty() {
        return Err(CliError::input(
            "BW-CONTRACT-REGISTRY-REQUIRED",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

fn read_toml(path: &Path) -> Result<String, CliError> {
    fs::read_to_string(path)
        .map_err(|error| CliError::input("BW-IO", format!("{}: {error}", path.display())))
}

fn write_jsonl<T: Serialize>(path: &Path, records: &[T]) -> Result<(), CliError> {
    let mut file = File::create(path)?;
    for record in records {
        serde_json::to_writer(&mut file, record)
            .map_err(|error| CliError::internal(error.to_string()))?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

fn write_json_file(path: &Path, value: &impl Serialize) -> Result<(), CliError> {
    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, value)
        .map_err(|error| CliError::internal(error.to_string()))?;
    file.write_all(b"\n")?;
    Ok(())
}

fn write_checksums(
    contracts_path: &Path,
    registry_manifest_path: &Path,
    checksums_path: &Path,
) -> Result<(), CliError> {
    let mut lines = vec![
        format!(
            "{}  lifecycle-contracts.jsonl",
            sha256_file(contracts_path)?
        ),
        format!(
            "{}  registry-manifest.json",
            sha256_file(registry_manifest_path)?
        ),
    ];
    lines.sort();
    fs::write(checksums_path, format!("{}\n", lines.join("\n")))?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, CliError> {
    let bytes = fs::read(path)?;
    Ok(hex_digest(Sha256::digest(bytes)))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
