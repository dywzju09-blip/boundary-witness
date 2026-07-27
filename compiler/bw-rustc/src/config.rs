use std::{
    env,
    ffi::OsString,
    fmt, fs,
    path::{Path, PathBuf},
    string::FromUtf8Error,
};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use bw_model::{CallbackRetentionApiMap, ModelError};

use crate::{
    args::WrapperInvocation,
    cargo_metadata::{CargoMetadata, MetadataError},
    coverage::ExpectedPackage,
};

const COLLECTION_LOOKUP_CONTRACT_REGISTRY_SCHEMA_V01: &str =
    "bw-rustc.collection_lookup_contract_registry.0.1";
const COLLECTION_LOOKUP_CONTRACT_REGISTRY_MANIFEST_SCHEMA_V01: &str =
    "bw-rustc.collection_lookup_contract_registry_manifest.0.1";
const CALLBACK_RETENTION_API_MAP_REGISTRY_MANIFEST_SCHEMA_V01: &str =
    "bw-rustc.callback_retention_api_map_registry_manifest.0.1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisRequest {
    pub crate_name: String,
    pub crate_id: String,
    pub package_name: String,
    pub package_version: String,
    pub target: String,
    pub output_dir: PathBuf,
    pub package_root: PathBuf,
    pub expected_packages: Vec<ExpectedPackage>,
    pub collection_lookup_contracts: Vec<CollectionLookupContract>,
    pub callback_retention_api_maps: Vec<CallbackRetentionApiMap>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerConfig {
    output_dir: PathBuf,
    metadata_path: Option<PathBuf>,
    allowlist: Vec<AllowlistEntry>,
    #[serde(default)]
    collection_lookup_contracts: Vec<CollectionLookupContract>,
    #[serde(default)]
    collection_lookup_contract_registries: Vec<CollectionLookupContractRegistryRef>,
    #[serde(default)]
    callback_retention_api_maps: Vec<CallbackRetentionApiMap>,
    #[serde(default)]
    callback_retention_api_map_registries: Vec<CallbackRetentionApiMapRegistryRef>,
    #[serde(skip)]
    metadata: Option<CargoMetadata>,
    #[serde(skip)]
    expected_packages: Vec<ExpectedPackage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CollectionLookupContract {
    pub callee: String,
    pub storage_arg_index: usize,
    pub key_arg_index: usize,
    pub returns_identity_preserving_borrow: bool,
    pub mutates_storage: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CollectionLookupContractRegistryRef {
    path: PathBuf,
    sha256: String,
    manifest_path: Option<PathBuf>,
    manifest_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CallbackRetentionApiMapRegistryRef {
    path: PathBuf,
    sha256: String,
    manifest_path: Option<PathBuf>,
    manifest_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CollectionLookupContractRegistry {
    schema: String,
    contracts: Vec<CollectionLookupContract>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CollectionLookupContractRegistryManifest {
    schema: String,
    registry_path: PathBuf,
    registry_sha256: String,
    source_evidence: Vec<CollectionLookupContractSourceEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CallbackRetentionApiMapRegistryManifest {
    schema: String,
    registry_path: PathBuf,
    registry_sha256: String,
    source_evidence: Vec<CollectionLookupContractSourceEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CollectionLookupContractSourceEvidence {
    path: PathBuf,
    sha256: String,
    description: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowlistEntry {
    crate_name: String,
    crate_id: Option<String>,
    package_name: Option<String>,
    version: Option<String>,
    target: Option<String>,
}

impl CompilerConfig {
    pub fn from_path(path: impl Into<OsString>) -> Result<Self, ConfigError> {
        let path = PathBuf::from(path.into());
        let input = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
            path: path.clone(),
            source,
        })?;
        let mut config: Self = if path
            .extension()
            .is_some_and(|extension| extension == "toml")
        {
            toml::from_str(&input).map_err(|source| ConfigError::TomlParse {
                path: path.clone(),
                source,
            })?
        } else {
            serde_json::from_str(&input).map_err(|source| ConfigError::JsonParse {
                path: path.clone(),
                source,
            })?
        };
        config.expand_env()?;
        config.load_collection_lookup_contract_registries(path.parent())?;
        config.load_callback_retention_api_map_registries(path.parent())?;
        config.validate_callback_retention_api_maps()?;
        if let Some(metadata_path) = &config.metadata_path {
            config.metadata = Some(CargoMetadata::from_path(metadata_path.clone())?);
        }
        config.expected_packages = config.resolve_expected_packages()?;
        Ok(config)
    }

    fn expand_env(&mut self) -> Result<(), ConfigError> {
        self.output_dir = expand_env_path(&self.output_dir)?;
        self.metadata_path = self
            .metadata_path
            .as_ref()
            .map(|path| expand_env_path(path.as_path()))
            .transpose()?;
        for entry in &mut self.allowlist {
            entry.crate_name = expand_env_string(&entry.crate_name)?;
            entry.crate_id = entry
                .crate_id
                .as_ref()
                .map(|value| expand_env_string(value))
                .transpose()?;
            entry.package_name = entry
                .package_name
                .as_ref()
                .map(|value| expand_env_string(value))
                .transpose()?;
            entry.version = entry
                .version
                .as_ref()
                .map(|value| expand_env_string(value))
                .transpose()?;
            entry.target = entry
                .target
                .as_ref()
                .map(|value| expand_env_string(value))
                .transpose()?;
        }
        for contract in &mut self.collection_lookup_contracts {
            contract.callee = expand_env_string(&contract.callee)?;
        }
        for registry in &mut self.collection_lookup_contract_registries {
            registry.path = expand_env_path(&registry.path)?;
            registry.sha256 = expand_env_string(&registry.sha256)?;
            registry.manifest_path = registry
                .manifest_path
                .as_ref()
                .map(|path| expand_env_path(path.as_path()))
                .transpose()?;
            registry.manifest_sha256 = registry
                .manifest_sha256
                .as_ref()
                .map(|value| expand_env_string(value))
                .transpose()?;
        }
        for api_map in &mut self.callback_retention_api_maps {
            api_map.map_id = expand_env_string(&api_map.map_id)?;
            api_map.producer = expand_env_string(&api_map.producer)?;
            api_map.contract_id = expand_env_string(&api_map.contract_id)?;
            for entry in &mut api_map.apis {
                entry.api_id = expand_env_string(&entry.api_id)?;
                entry.rust_path = expand_env_string(&entry.rust_path)?;
                entry.contract_api_id = expand_env_string(&entry.contract_api_id)?;
                entry.callback_family = expand_env_string(&entry.callback_family)?;
                entry.opaque_binding_api_id = entry
                    .opaque_binding_api_id
                    .as_ref()
                    .map(|value| expand_env_string(value))
                    .transpose()?;
            }
        }
        for registry in &mut self.callback_retention_api_map_registries {
            registry.path = expand_env_path(&registry.path)?;
            registry.sha256 = expand_env_string(&registry.sha256)?;
            registry.manifest_path = registry
                .manifest_path
                .as_ref()
                .map(|path| expand_env_path(path.as_path()))
                .transpose()?;
            registry.manifest_sha256 = registry
                .manifest_sha256
                .as_ref()
                .map(|value| expand_env_string(value))
                .transpose()?;
        }
        Ok(())
    }

    fn load_collection_lookup_contract_registries(
        &mut self,
        config_dir: Option<&Path>,
    ) -> Result<(), ConfigError> {
        let mut registry_contracts = Vec::new();
        for registry in &self.collection_lookup_contract_registries {
            validate_sha256_hex(&registry.sha256).map_err(|_| ConfigError::InvalidSha256 {
                path: registry.path.clone(),
                value: registry.sha256.clone(),
            })?;
            let registry_path = resolve_config_relative_path(config_dir, &registry.path);
            let bytes = fs::read(&registry_path).map_err(|source| ConfigError::RegistryRead {
                path: registry_path.clone(),
                source,
            })?;
            let actual = sha256_hex(&bytes);
            if actual != registry.sha256.to_ascii_lowercase() {
                return Err(ConfigError::RegistryChecksumMismatch {
                    path: registry_path,
                    expected: registry.sha256.to_ascii_lowercase(),
                    actual,
                });
            }
            if let (Some(manifest_path), Some(manifest_sha256)) =
                (&registry.manifest_path, &registry.manifest_sha256)
            {
                self.audit_collection_lookup_contract_registry_manifest(
                    config_dir,
                    manifest_path,
                    manifest_sha256,
                    &registry_path,
                    &registry.sha256,
                )?;
            } else if registry.manifest_path.is_some() || registry.manifest_sha256.is_some() {
                return Err(ConfigError::RegistryManifestIncomplete {
                    path: registry_path.clone(),
                });
            }
            let registry: CollectionLookupContractRegistry = serde_json::from_slice(&bytes)
                .map_err(|source| ConfigError::RegistryJsonParse {
                    path: registry_path.clone(),
                    source,
                })?;
            if registry.schema != COLLECTION_LOOKUP_CONTRACT_REGISTRY_SCHEMA_V01 {
                return Err(ConfigError::RegistrySchema {
                    path: registry_path,
                    schema: registry.schema,
                });
            }
            registry_contracts.extend(registry.contracts);
        }
        self.collection_lookup_contracts
            .extend(registry_contracts.into_iter());
        Ok(())
    }

    fn load_callback_retention_api_map_registries(
        &mut self,
        config_dir: Option<&Path>,
    ) -> Result<(), ConfigError> {
        let mut registry_api_maps = Vec::new();
        for registry in &self.callback_retention_api_map_registries {
            validate_sha256_hex(&registry.sha256).map_err(|_| ConfigError::InvalidSha256 {
                path: registry.path.clone(),
                value: registry.sha256.clone(),
            })?;
            let registry_path = resolve_config_relative_path(config_dir, &registry.path);
            let bytes = fs::read(&registry_path).map_err(|source| ConfigError::RegistryRead {
                path: registry_path.clone(),
                source,
            })?;
            let actual = sha256_hex(&bytes);
            if actual != registry.sha256.to_ascii_lowercase() {
                return Err(ConfigError::RegistryChecksumMismatch {
                    path: registry_path,
                    expected: registry.sha256.to_ascii_lowercase(),
                    actual,
                });
            }
            if let (Some(manifest_path), Some(manifest_sha256)) =
                (&registry.manifest_path, &registry.manifest_sha256)
            {
                self.audit_callback_retention_api_map_registry_manifest(
                    config_dir,
                    manifest_path,
                    manifest_sha256,
                    &registry_path,
                    &registry.sha256,
                )?;
            } else if registry.manifest_path.is_some() || registry.manifest_sha256.is_some() {
                return Err(ConfigError::RegistryManifestIncomplete {
                    path: registry_path.clone(),
                });
            }
            let input = String::from_utf8(bytes).map_err(|source| ConfigError::RegistryUtf8 {
                path: registry_path.clone(),
                source,
            })?;
            let api_map = CallbackRetentionApiMap::from_toml_str(&input).map_err(|source| {
                ConfigError::CallbackApiMap {
                    path: registry_path.clone(),
                    source,
                }
            })?;
            registry_api_maps.push(api_map);
        }
        self.callback_retention_api_maps.extend(registry_api_maps);
        Ok(())
    }

    fn validate_callback_retention_api_maps(&self) -> Result<(), ConfigError> {
        let mut map_ids = std::collections::BTreeSet::<String>::new();
        let mut api_ids = std::collections::BTreeSet::<String>::new();
        for api_map in &self.callback_retention_api_maps {
            api_map
                .validate()
                .map_err(|source| ConfigError::InlineCallbackApiMap { source })?;
            if !map_ids.insert(api_map.map_id.clone()) {
                return Err(ConfigError::DuplicateCallbackApiMapId {
                    map_id: api_map.map_id.clone(),
                });
            }
            for entry in &api_map.apis {
                if !api_ids.insert(entry.api_id.clone()) {
                    return Err(ConfigError::DuplicateCallbackApiId {
                        api_id: entry.api_id.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    fn audit_callback_retention_api_map_registry_manifest(
        &self,
        config_dir: Option<&Path>,
        manifest_path: &Path,
        manifest_sha256: &str,
        registry_path: &Path,
        registry_sha256: &str,
    ) -> Result<(), ConfigError> {
        validate_sha256_hex(manifest_sha256).map_err(|_| ConfigError::InvalidSha256 {
            path: manifest_path.to_path_buf(),
            value: manifest_sha256.to_owned(),
        })?;
        let manifest_path = resolve_config_relative_path(config_dir, manifest_path);
        let manifest_bytes =
            fs::read(&manifest_path).map_err(|source| ConfigError::RegistryManifestRead {
                path: manifest_path.clone(),
                source,
            })?;
        let actual_manifest_sha256 = sha256_hex(&manifest_bytes);
        if actual_manifest_sha256 != manifest_sha256.to_ascii_lowercase() {
            return Err(ConfigError::RegistryManifestChecksumMismatch {
                path: manifest_path,
                expected: manifest_sha256.to_ascii_lowercase(),
                actual: actual_manifest_sha256,
            });
        }
        let manifest: CallbackRetentionApiMapRegistryManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|source| {
                ConfigError::RegistryManifestJsonParse {
                    path: manifest_path.clone(),
                    source,
                }
            })?;
        if manifest.schema != CALLBACK_RETENTION_API_MAP_REGISTRY_MANIFEST_SCHEMA_V01 {
            return Err(ConfigError::RegistryManifestSchema {
                path: manifest_path,
                schema: manifest.schema,
            });
        }
        self.audit_registry_manifest_common(
            config_dir,
            &manifest_path,
            &manifest.registry_path,
            &manifest.registry_sha256,
            &manifest.source_evidence,
            registry_path,
            registry_sha256,
        )
    }

    fn audit_collection_lookup_contract_registry_manifest(
        &self,
        config_dir: Option<&Path>,
        manifest_path: &Path,
        manifest_sha256: &str,
        registry_path: &Path,
        registry_sha256: &str,
    ) -> Result<(), ConfigError> {
        validate_sha256_hex(manifest_sha256).map_err(|_| ConfigError::InvalidSha256 {
            path: manifest_path.to_path_buf(),
            value: manifest_sha256.to_owned(),
        })?;
        let manifest_path = resolve_config_relative_path(config_dir, manifest_path);
        let manifest_bytes =
            fs::read(&manifest_path).map_err(|source| ConfigError::RegistryManifestRead {
                path: manifest_path.clone(),
                source,
            })?;
        let actual_manifest_sha256 = sha256_hex(&manifest_bytes);
        if actual_manifest_sha256 != manifest_sha256.to_ascii_lowercase() {
            return Err(ConfigError::RegistryManifestChecksumMismatch {
                path: manifest_path,
                expected: manifest_sha256.to_ascii_lowercase(),
                actual: actual_manifest_sha256,
            });
        }
        let manifest: CollectionLookupContractRegistryManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|source| {
                ConfigError::RegistryManifestJsonParse {
                    path: manifest_path.clone(),
                    source,
                }
            })?;
        if manifest.schema != COLLECTION_LOOKUP_CONTRACT_REGISTRY_MANIFEST_SCHEMA_V01 {
            return Err(ConfigError::RegistryManifestSchema {
                path: manifest_path,
                schema: manifest.schema,
            });
        }
        self.audit_registry_manifest_common(
            config_dir,
            &manifest_path,
            &manifest.registry_path,
            &manifest.registry_sha256,
            &manifest.source_evidence,
            registry_path,
            registry_sha256,
        )
    }

    fn audit_registry_manifest_common(
        &self,
        _config_dir: Option<&Path>,
        manifest_path: &Path,
        manifest_registry_path: &Path,
        manifest_registry_sha256: &str,
        source_evidence: &[CollectionLookupContractSourceEvidence],
        registry_path: &Path,
        registry_sha256: &str,
    ) -> Result<(), ConfigError> {
        validate_sha256_hex(manifest_registry_sha256).map_err(|_| ConfigError::InvalidSha256 {
            path: manifest_path.to_path_buf(),
            value: manifest_registry_sha256.to_owned(),
        })?;
        if manifest_registry_sha256 != registry_sha256.to_ascii_lowercase() {
            return Err(ConfigError::RegistryManifestRegistryChecksumMismatch {
                path: manifest_path.to_path_buf(),
                expected: registry_sha256.to_ascii_lowercase(),
                actual: manifest_registry_sha256.to_owned(),
            });
        }
        let resolved_manifest_registry_path =
            resolve_manifest_relative_path(manifest_path, manifest_registry_path);
        let manifest_registry_bytes =
            fs::read(&resolved_manifest_registry_path).map_err(|source| {
                ConfigError::RegistryRead {
                    path: resolved_manifest_registry_path.clone(),
                    source,
                }
            })?;
        let actual_registry_sha256 = sha256_hex(&manifest_registry_bytes);
        if actual_registry_sha256 != registry_sha256.to_ascii_lowercase() {
            return Err(ConfigError::RegistryChecksumMismatch {
                path: resolved_manifest_registry_path,
                expected: registry_sha256.to_ascii_lowercase(),
                actual: actual_registry_sha256,
            });
        }
        if !same_existing_path(registry_path, &resolved_manifest_registry_path) {
            return Err(ConfigError::RegistryManifestRegistryPathMismatch {
                manifest_path: manifest_path.to_path_buf(),
                registry_path: registry_path.to_path_buf(),
                manifest_registry_path: resolved_manifest_registry_path,
            });
        }
        if source_evidence.is_empty() {
            return Err(ConfigError::RegistryManifestMissingSourceEvidence {
                path: manifest_path.to_path_buf(),
            });
        }
        for evidence in source_evidence {
            require_non_empty_text(
                &evidence.description,
                ConfigError::RegistryManifestEmptySourceEvidence {
                    path: manifest_path.to_path_buf(),
                },
            )?;
            validate_sha256_hex(&evidence.sha256).map_err(|_| ConfigError::InvalidSha256 {
                path: evidence.path.clone(),
                value: evidence.sha256.clone(),
            })?;
            let evidence_path = resolve_manifest_relative_path(&manifest_path, &evidence.path);
            let evidence_bytes =
                fs::read(&evidence_path).map_err(|source| ConfigError::RegistryManifestRead {
                    path: evidence_path.clone(),
                    source,
                })?;
            let actual_evidence_sha256 = sha256_hex(&evidence_bytes);
            if actual_evidence_sha256 != evidence.sha256 {
                return Err(ConfigError::RegistrySourceEvidenceChecksumMismatch {
                    path: evidence_path,
                    expected: evidence.sha256.clone(),
                    actual: actual_evidence_sha256,
                });
            }
        }
        Ok(())
    }

    pub fn analysis_request(&self, invocation: &WrapperInvocation) -> Option<AnalysisRequest> {
        let crate_name = invocation.crate_name.as_ref()?;
        let entry = self.allowlist.iter().find(|entry| {
            entry.crate_name == *crate_name
                && entry
                    .target
                    .as_ref()
                    .is_none_or(|target| target == &invocation.target)
        })?;
        let expected = self.expected_package_for(entry);
        Some(AnalysisRequest {
            crate_name: crate_name.clone(),
            crate_id: entry
                .crate_id
                .clone()
                .unwrap_or_else(|| format!("crate:{}:{}", expected.name, expected.version)),
            package_name: expected.name.clone(),
            package_version: expected.version.clone(),
            target: invocation.target.clone(),
            output_dir: self.output_dir.clone(),
            package_root: package_root(),
            expected_packages: self.expected_packages.clone(),
            collection_lookup_contracts: self.collection_lookup_contracts.clone(),
            callback_retention_api_maps: self.callback_retention_api_maps.clone(),
        })
    }

    fn resolve_expected_packages(&self) -> Result<Vec<ExpectedPackage>, ConfigError> {
        self.allowlist
            .iter()
            .map(|entry| {
                let package_name = entry
                    .package_name
                    .as_deref()
                    .unwrap_or(entry.crate_name.as_str());
                if let Some(metadata) = &self.metadata {
                    let package = metadata
                        .package(package_name, entry.version.as_deref())
                        .ok_or_else(|| ConfigError::MissingPackage {
                            name: package_name.to_owned(),
                            version: entry.version.clone(),
                        })?;
                    if let Some(target) = &entry.target
                        && !package.has_target(&entry.crate_name, target)
                    {
                        return Err(ConfigError::MissingTarget {
                            package: package_name.to_owned(),
                            crate_name: entry.crate_name.clone(),
                            target: target.clone(),
                        });
                    }
                    Ok(ExpectedPackage {
                        name: package.name.clone(),
                        version: package.version.clone(),
                    })
                } else {
                    Ok(ExpectedPackage {
                        name: package_name.to_owned(),
                        version: entry
                            .version
                            .clone()
                            .unwrap_or_else(|| "unknown".to_owned()),
                    })
                }
            })
            .collect()
    }

    fn expected_package_for(&self, entry: &AllowlistEntry) -> ExpectedPackage {
        let package_name = entry
            .package_name
            .as_deref()
            .unwrap_or(entry.crate_name.as_str());
        self.expected_packages
            .iter()
            .find(|package| {
                package.name == package_name
                    && entry
                        .version
                        .as_ref()
                        .is_none_or(|version| version == &package.version)
            })
            .cloned()
            .unwrap_or_else(|| ExpectedPackage {
                name: package_name.to_owned(),
                version: entry
                    .version
                    .clone()
                    .unwrap_or_else(|| "unknown".to_owned()),
            })
    }
}

fn package_root() -> PathBuf {
    env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .or_else(|| env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn expand_env_path(path: &Path) -> Result<PathBuf, ConfigError> {
    expand_env_string(&path.to_string_lossy()).map(PathBuf::from)
}

fn expand_env_string(value: &str) -> Result<String, ConfigError> {
    let Some(name) = env_name(value) else {
        return Ok(value.to_owned());
    };
    env::var(&name).map_err(|_| ConfigError::MissingEnv { name })
}

fn env_name(value: &str) -> Option<String> {
    if let Some(name) = value
        .strip_prefix("${")
        .and_then(|name| name.strip_suffix('}'))
        .filter(|name| valid_env_name(name))
    {
        return Some(name.to_owned());
    }
    value
        .strip_prefix('$')
        .filter(|name| valid_env_name(name))
        .map(ToOwned::to_owned)
}

fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn resolve_config_relative_path(config_dir: Option<&Path>, path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    config_dir
        .map(|dir| dir.join(path))
        .unwrap_or_else(|| path.to_path_buf())
}

fn resolve_manifest_relative_path(manifest_path: &Path, input_path: &Path) -> PathBuf {
    if input_path.is_absolute() {
        return input_path.to_path_buf();
    }
    manifest_path
        .parent()
        .map(|parent| parent.join(input_path))
        .unwrap_or_else(|| input_path.to_path_buf())
}

fn same_existing_path(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn require_non_empty_text(value: &str, error: ConfigError) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        Err(error)
    } else {
        Ok(())
    }
}

fn validate_sha256_hex(value: &str) -> Result<(), ()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    JsonParse {
        path: PathBuf,
        source: serde_json::Error,
    },
    TomlParse {
        path: PathBuf,
        source: toml::de::Error,
    },
    RegistryRead {
        path: PathBuf,
        source: std::io::Error,
    },
    RegistryJsonParse {
        path: PathBuf,
        source: serde_json::Error,
    },
    RegistryUtf8 {
        path: PathBuf,
        source: FromUtf8Error,
    },
    CallbackApiMap {
        path: PathBuf,
        source: ModelError,
    },
    InlineCallbackApiMap {
        source: ModelError,
    },
    DuplicateCallbackApiMapId {
        map_id: String,
    },
    DuplicateCallbackApiId {
        api_id: String,
    },
    RegistryManifestRead {
        path: PathBuf,
        source: std::io::Error,
    },
    RegistryManifestJsonParse {
        path: PathBuf,
        source: serde_json::Error,
    },
    RegistryChecksumMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    RegistryManifestChecksumMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    RegistrySchema {
        path: PathBuf,
        schema: String,
    },
    RegistryManifestSchema {
        path: PathBuf,
        schema: String,
    },
    RegistryManifestIncomplete {
        path: PathBuf,
    },
    RegistryManifestRegistryChecksumMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    RegistryManifestRegistryPathMismatch {
        manifest_path: PathBuf,
        registry_path: PathBuf,
        manifest_registry_path: PathBuf,
    },
    RegistryManifestMissingSourceEvidence {
        path: PathBuf,
    },
    RegistryManifestEmptySourceEvidence {
        path: PathBuf,
    },
    RegistrySourceEvidenceChecksumMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    InvalidSha256 {
        path: PathBuf,
        value: String,
    },
    Metadata(MetadataError),
    MissingEnv {
        name: String,
    },
    MissingPackage {
        name: String,
        version: Option<String>,
    },
    MissingTarget {
        package: String,
        crate_name: String,
        target: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(formatter, "{}: {}", path.display(), source),
            Self::JsonParse { path, source } => write!(formatter, "{}: {}", path.display(), source),
            Self::TomlParse { path, source } => write!(formatter, "{}: {}", path.display(), source),
            Self::RegistryRead { path, source } => {
                write!(formatter, "registry {}: {}", path.display(), source)
            }
            Self::RegistryJsonParse { path, source } => {
                write!(formatter, "registry {}: {}", path.display(), source)
            }
            Self::RegistryUtf8 { path, source } => {
                write!(
                    formatter,
                    "registry {} is not valid UTF-8: {}",
                    path.display(),
                    source
                )
            }
            Self::CallbackApiMap { path, source } => {
                write!(formatter, "callback API map {}: {}", path.display(), source)
            }
            Self::InlineCallbackApiMap { source } => {
                write!(formatter, "inline callback API map: {source}")
            }
            Self::DuplicateCallbackApiMapId { map_id } => {
                write!(formatter, "callback API map id {map_id} is duplicated")
            }
            Self::DuplicateCallbackApiId { api_id } => {
                write!(formatter, "callback API id {api_id} is duplicated")
            }
            Self::RegistryManifestRead { path, source } => {
                write!(
                    formatter,
                    "registry manifest {}: {}",
                    path.display(),
                    source
                )
            }
            Self::RegistryManifestJsonParse { path, source } => {
                write!(
                    formatter,
                    "registry manifest {}: {}",
                    path.display(),
                    source
                )
            }
            Self::RegistryChecksumMismatch {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "registry {} sha256 mismatch: expected {expected}, got {actual}",
                path.display()
            ),
            Self::RegistryManifestChecksumMismatch {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "registry manifest {} sha256 mismatch: expected {expected}, got {actual}",
                path.display()
            ),
            Self::RegistrySchema { path, schema } => write!(
                formatter,
                "registry {} has unsupported schema {schema}",
                path.display()
            ),
            Self::RegistryManifestSchema { path, schema } => write!(
                formatter,
                "registry manifest {} has unsupported schema {schema}",
                path.display()
            ),
            Self::RegistryManifestIncomplete { path } => write!(
                formatter,
                "registry {} must provide both manifest_path and manifest_sha256",
                path.display()
            ),
            Self::RegistryManifestRegistryChecksumMismatch {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "registry manifest {} registry_sha256 mismatch: expected {expected}, got {actual}",
                path.display()
            ),
            Self::RegistryManifestRegistryPathMismatch {
                manifest_path,
                registry_path,
                manifest_registry_path,
            } => write!(
                formatter,
                "registry manifest {} points at {}, but config points at {}",
                manifest_path.display(),
                manifest_registry_path.display(),
                registry_path.display()
            ),
            Self::RegistryManifestMissingSourceEvidence { path } => write!(
                formatter,
                "registry manifest {} must include at least one source_evidence entry",
                path.display()
            ),
            Self::RegistryManifestEmptySourceEvidence { path } => write!(
                formatter,
                "registry manifest {} source_evidence description must be non-empty",
                path.display()
            ),
            Self::RegistrySourceEvidenceChecksumMismatch {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "registry source evidence {} sha256 mismatch: expected {expected}, got {actual}",
                path.display()
            ),
            Self::InvalidSha256 { path, value } => write!(
                formatter,
                "registry {} sha256 must be 64 lowercase hex chars, got {value}",
                path.display()
            ),
            Self::Metadata(error) => write!(formatter, "{error}"),
            Self::MissingEnv { name } => {
                write!(formatter, "environment variable {name} is not set")
            }
            Self::MissingPackage { name, version } => match version {
                Some(version) => write!(formatter, "metadata missing package {name} {version}"),
                None => write!(formatter, "metadata missing package {name}"),
            },
            Self::MissingTarget {
                package,
                crate_name,
                target,
            } => write!(
                formatter,
                "metadata package {package} missing target {target} for crate {crate_name}"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<MetadataError> for ConfigError {
    fn from(value: MetadataError) -> Self {
        Self::Metadata(value)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn collection_lookup_contract_registry_loads_with_matching_checksum() {
        let temp = tempdir().expect("tempdir should be created");
        let config_dir = temp.path().join("configs");
        let registry_dir = temp.path().join("registries");
        fs::create_dir_all(&config_dir).expect("config dir should be created");
        fs::create_dir_all(&registry_dir).expect("registry dir should be created");
        let registry_path = registry_dir.join("collection-lookup.json");
        let registry_bytes = serde_json::to_vec(&serde_json::json!({
            "schema": COLLECTION_LOOKUP_CONTRACT_REGISTRY_SCHEMA_V01,
            "contracts": [
                {
                    "callee": "diesel_helper_lookup::lookup_borrowed",
                    "storage_arg_index": 0,
                    "key_arg_index": 1,
                    "returns_identity_preserving_borrow": true,
                    "mutates_storage": false
                }
            ]
        }))
        .expect("registry should serialize");
        fs::write(&registry_path, &registry_bytes).expect("registry should be written");
        let config_path = config_dir.join("bw-rustc-config.json");
        fs::write(
            &config_path,
            serde_json::json!({
                "output_dir": temp.path().join("analysis"),
                "allowlist": [
                    { "crate_name": "diesel", "target": "lib" }
                ],
                "collection_lookup_contract_registries": [
                    {
                        "path": "../registries/collection-lookup.json",
                        "sha256": sha256_hex(&registry_bytes)
                    }
                ]
            })
            .to_string(),
        )
        .expect("config should be written");

        let config = CompilerConfig::from_path(&config_path).expect("config should load");
        assert_eq!(config.collection_lookup_contracts.len(), 1);
        assert_eq!(
            config.collection_lookup_contracts[0].callee,
            "diesel_helper_lookup::lookup_borrowed"
        );
    }

    #[test]
    fn collection_lookup_contract_registry_rejects_checksum_mismatch() {
        let temp = tempdir().expect("tempdir should be created");
        let registry_path = temp.path().join("collection-lookup.json");
        fs::write(
            &registry_path,
            serde_json::json!({
                "schema": COLLECTION_LOOKUP_CONTRACT_REGISTRY_SCHEMA_V01,
                "contracts": []
            })
            .to_string(),
        )
        .expect("registry should be written");
        let config_path = temp.path().join("bw-rustc-config.json");
        fs::write(
            &config_path,
            serde_json::json!({
                "output_dir": temp.path().join("analysis"),
                "allowlist": [
                    { "crate_name": "diesel", "target": "lib" }
                ],
                "collection_lookup_contract_registries": [
                    {
                        "path": "collection-lookup.json",
                        "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
                    }
                ]
            })
            .to_string(),
        )
        .expect("config should be written");

        assert!(matches!(
            CompilerConfig::from_path(&config_path),
            Err(ConfigError::RegistryChecksumMismatch { .. })
        ));
    }

    #[test]
    fn collection_lookup_contract_registry_manifest_verifies_source_evidence() {
        let temp = tempdir().expect("tempdir should be created");
        let config_dir = temp.path().join("configs");
        let registry_dir = temp.path().join("registries");
        fs::create_dir_all(&config_dir).expect("config dir should be created");
        fs::create_dir_all(&registry_dir).expect("registry dir should be created");

        let registry_path = registry_dir.join("collection-lookup.json");
        let registry_bytes = serde_json::to_vec(&serde_json::json!({
            "schema": COLLECTION_LOOKUP_CONTRACT_REGISTRY_SCHEMA_V01,
            "contracts": [
                {
                    "callee": "diesel_helper_lookup::lookup_borrowed",
                    "storage_arg_index": 0,
                    "key_arg_index": 1,
                    "returns_identity_preserving_borrow": true,
                    "mutates_storage": false
                }
            ]
        }))
        .expect("registry should serialize");
        let registry_sha256 = sha256_hex(&registry_bytes);
        fs::write(&registry_path, &registry_bytes).expect("registry should be written");

        let source_path = registry_dir.join("source-evidence.txt");
        let source_bytes = b"audited helper source: map.get(key).copied(), no mutation\n";
        fs::write(&source_path, source_bytes).expect("source evidence should be written");

        let manifest_path = registry_dir.join("registry-manifest.json");
        let manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "schema": COLLECTION_LOOKUP_CONTRACT_REGISTRY_MANIFEST_SCHEMA_V01,
            "registry_path": "collection-lookup.json",
            "registry_sha256": registry_sha256.clone(),
            "source_evidence": [
                {
                    "path": "source-evidence.txt",
                    "sha256": sha256_hex(source_bytes),
                    "description": "local source audit for identity-preserving lookup helper"
                }
            ]
        }))
        .expect("manifest should serialize");
        let manifest_sha256 = sha256_hex(&manifest_bytes);
        fs::write(&manifest_path, &manifest_bytes).expect("manifest should be written");

        let config_path = config_dir.join("bw-rustc-config.json");
        fs::write(
            &config_path,
            serde_json::json!({
                "output_dir": temp.path().join("analysis"),
                "allowlist": [
                    { "crate_name": "diesel", "target": "lib" }
                ],
                "collection_lookup_contract_registries": [
                    {
                        "path": "../registries/collection-lookup.json",
                        "sha256": registry_sha256,
                        "manifest_path": "../registries/registry-manifest.json",
                        "manifest_sha256": manifest_sha256
                    }
                ]
            })
            .to_string(),
        )
        .expect("config should be written");

        let config = CompilerConfig::from_path(&config_path).expect("config should load");
        assert_eq!(config.collection_lookup_contracts.len(), 1);
    }

    #[test]
    fn collection_lookup_contract_registry_manifest_rejects_source_checksum_mismatch() {
        let temp = tempdir().expect("tempdir should be created");
        let registry_path = temp.path().join("collection-lookup.json");
        let registry_bytes = serde_json::to_vec(&serde_json::json!({
            "schema": COLLECTION_LOOKUP_CONTRACT_REGISTRY_SCHEMA_V01,
            "contracts": []
        }))
        .expect("registry should serialize");
        let registry_sha256 = sha256_hex(&registry_bytes);
        fs::write(&registry_path, &registry_bytes).expect("registry should be written");

        let source_path = temp.path().join("source-evidence.txt");
        fs::write(&source_path, b"changed source evidence\n")
            .expect("source evidence should be written");

        let manifest_path = temp.path().join("registry-manifest.json");
        let manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "schema": COLLECTION_LOOKUP_CONTRACT_REGISTRY_MANIFEST_SCHEMA_V01,
            "registry_path": "collection-lookup.json",
            "registry_sha256": registry_sha256.clone(),
            "source_evidence": [
                {
                    "path": "source-evidence.txt",
                    "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                    "description": "stale source audit digest"
                }
            ]
        }))
        .expect("manifest should serialize");
        let manifest_sha256 = sha256_hex(&manifest_bytes);
        fs::write(&manifest_path, &manifest_bytes).expect("manifest should be written");

        let config_path = temp.path().join("bw-rustc-config.json");
        fs::write(
            &config_path,
            serde_json::json!({
                "output_dir": temp.path().join("analysis"),
                "allowlist": [
                    { "crate_name": "diesel", "target": "lib" }
                ],
                "collection_lookup_contract_registries": [
                    {
                        "path": "collection-lookup.json",
                        "sha256": registry_sha256,
                        "manifest_path": "registry-manifest.json",
                        "manifest_sha256": manifest_sha256
                    }
                ]
            })
            .to_string(),
        )
        .expect("config should be written");

        assert!(matches!(
            CompilerConfig::from_path(&config_path),
            Err(ConfigError::RegistrySourceEvidenceChecksumMismatch { .. })
        ));
    }
}
