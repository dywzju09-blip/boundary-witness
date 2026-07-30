use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    CONTRACT_SCHEMA_V01, ModelError, RegistrationRole,
    schema::{deserialize_contract_schema, require_toml_schema_version},
};

pub const CALLBACK_RETENTION_API_MAP_SCHEMA_V01: &str = "bw.api-map/0.1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractClauseKind {
    RetainAfterRegister,
    ReleaseOnUnregister,
    ReleaseOnReplacement,
    ReleaseOnOwnerDrop,
    InvokeWhileRetained,
    BorrowMustOutliveRetention,
    NoUseAfterLifetimeEnd,
    FreeAtMostOnce,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractClause {
    pub clause_id: String,
    pub kind: ContractClauseKind,
    pub description: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseBehavior {
    None,
    ReleaseCurrent,
    ReleaseAndReplace,
    ReleaseOnOwnerDrop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvokeRole {
    Callback,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackApiEntry {
    pub clause_id: String,
    pub api_id: String,
    pub registration_role: Option<RegistrationRole>,
    pub release_behavior: ReleaseBehavior,
    pub owner_kind: String,
    pub invoke_role: Option<InvokeRole>,
}

/// 通用 retained-callback contract 及其无漏洞标签 API role 映射。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackRetentionContract {
    #[serde(deserialize_with = "deserialize_contract_schema")]
    pub schema_version: String,
    pub contract_id: String,
    pub producer: String,
    pub clauses: Vec<ContractClause>,
    pub api_entries: Vec<CallbackApiEntry>,
}

impl CallbackRetentionContract {
    /// 解析并精确校验 TOML 中的 `bw.contract/0.1`。
    pub fn from_toml_str(input: &str) -> Result<Self, ModelError> {
        require_toml_schema_version(input, CONTRACT_SCHEMA_V01)?;
        let contract = toml::from_str::<Self>(input)?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        for (field, value) in [
            ("contract_id", self.contract_id.as_str()),
            ("producer", self.producer.as_str()),
        ] {
            require_nonempty(field, value)?;
        }

        let mut clause_ids = BTreeSet::new();
        for clause in &self.clauses {
            require_nonempty("clauses.clause_id", &clause.clause_id)?;
            require_nonempty("clauses.description", &clause.description)?;
            if !clause_ids.insert(clause.clause_id.as_str()) {
                return Err(ModelError::validation(
                    "BW-CONTRACT-CLAUSE-ID-DUPLICATE",
                    format!("contract 中 clause_id {} 重复", clause.clause_id),
                ));
            }
        }

        for entry in &self.api_entries {
            for (field, value) in [
                ("api_entries.clause_id", entry.clause_id.as_str()),
                ("api_entries.api_id", entry.api_id.as_str()),
                ("api_entries.owner_kind", entry.owner_kind.as_str()),
            ] {
                require_nonempty(field, value)?;
            }
            if !clause_ids.contains(entry.clause_id.as_str()) {
                return Err(ModelError::validation(
                    "BW-CONTRACT-CLAUSE-REFERENCE",
                    format!("api entry 引用了不存在的 clause_id {}", entry.clause_id),
                ));
            }
        }
        Ok(())
    }
}

/// 具体 Rust API 到通用 retained-callback contract API 的可审计映射。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackRetentionApiMap {
    pub schema_version: String,
    pub map_id: String,
    pub producer: String,
    pub contract_id: String,
    pub apis: Vec<CallbackRetentionApiMapEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackRetentionApiMapEntry {
    pub api_id: String,
    pub rust_path: String,
    pub contract_api_id: String,
    pub callback_family: String,
    #[serde(default)]
    pub opaque_handle_role: Option<OpaqueHandleApiRole>,
    #[serde(default)]
    pub opaque_binding_api_id: Option<String>,
    #[serde(default)]
    pub opaque_handle_arg_index: Option<usize>,
    #[serde(default)]
    pub opaque_key_arg_index: Option<usize>,
    #[serde(default)]
    pub opaque_payload_arg_index: Option<usize>,
    #[serde(default)]
    pub opaque_generation_key: Vec<OpaqueHandleIdentityComponent>,
    #[serde(default)]
    pub callback_arg_indices: Vec<usize>,
    #[serde(default)]
    pub user_data_arg_indices: Vec<usize>,
    /// 该 API 的 callback bound 还**不是** `'static` 的最后一个声明方版本。
    ///
    /// 库把 bound 收紧到 `'static` 之后，borrowed capture 这一形状在该版本上根本不成立，
    /// 按它写的 harness 连编译都过不去。没有这个字段时，任何版本上的注册都会被当成
    /// "模板适用"，拒绝理由于是退化成"这个版本没 vendored"——那是错的引导：vendored 了
    /// 也生成不出来。缺省 `None` 表示没记录过这条边界，判定为不可判定而不是"处处适用"。
    #[serde(default)]
    pub non_static_callback_max_version: Option<String>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpaqueHandleApiRole {
    Set,
    Get,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpaqueHandleIdentityComponent {
    BindingApiId,
    HandleArg,
    KeyArg,
    PayloadArg,
}

impl CallbackRetentionApiMap {
    /// 解析并校验 `bw.api-map/0.1` 的 API 映射。
    pub fn from_toml_str(input: &str) -> Result<Self, ModelError> {
        require_toml_schema_version(input, CALLBACK_RETENTION_API_MAP_SCHEMA_V01)?;
        let api_map = toml::from_str::<Self>(input)?;
        api_map.validate()?;
        Ok(api_map)
    }

    /// 校验 API 映射的必填字段、opaque-handle 身份组成与 binding 引用完整性。
    ///
    /// `from_toml_str` 会自动调用；内联反序列化（例如编译器 config 中直接给出的
    /// `callback_retention_api_maps`）绕过了 `from_toml_str`，必须显式调用本方法。
    pub fn validate(&self) -> Result<(), ModelError> {
        for (field, value) in [
            ("map_id", self.map_id.as_str()),
            ("producer", self.producer.as_str()),
            ("contract_id", self.contract_id.as_str()),
        ] {
            require_nonempty(field, value)?;
        }

        let mut api_ids = BTreeSet::new();
        for entry in &self.apis {
            for (field, value) in [
                ("apis.api_id", entry.api_id.as_str()),
                ("apis.rust_path", entry.rust_path.as_str()),
                ("apis.contract_api_id", entry.contract_api_id.as_str()),
                ("apis.callback_family", entry.callback_family.as_str()),
            ] {
                require_nonempty(field, value)?;
            }
            if !api_ids.insert(entry.api_id.as_str()) {
                return Err(ModelError::validation(
                    "BW-CONTRACT-API-MAP-API-ID-DUPLICATE",
                    format!("api map 中 api_id {} 重复", entry.api_id),
                ));
            }
            // 写了却解析不出来的边界比没写更糟：下游会把它当成一条已知边界去比较，
            // 比不出来就静默退回"不可判定"，而 map 作者以为自己已经声明过了。
            if let Some(boundary) = &entry.non_static_callback_max_version
                && parse_plain_version(boundary).is_none()
            {
                return Err(ModelError::validation(
                    "BW-CONTRACT-API-MAP-NON-STATIC-CALLBACK-MAX-VERSION",
                    format!(
                        "API {} 的 non_static_callback_max_version 必须是纯三段数字版本，实际是 {boundary}",
                        entry.api_id
                    ),
                ));
            }
            let has_opaque_metadata = entry.opaque_handle_role.is_some()
                || entry.opaque_binding_api_id.is_some()
                || entry.opaque_handle_arg_index.is_some()
                || entry.opaque_key_arg_index.is_some()
                || entry.opaque_payload_arg_index.is_some()
                || !entry.opaque_generation_key.is_empty();
            if has_opaque_metadata && entry.opaque_handle_role.is_none() {
                return Err(ModelError::validation(
                    "BW-CONTRACT-API-MAP-OPAQUE-ROLE",
                    format!(
                        "opaque handle API {} 声明了 opaque metadata 但缺少 opaque_handle_role",
                        entry.api_id
                    ),
                ));
            }
            if let Some(role) = entry.opaque_handle_role {
                if entry
                    .opaque_binding_api_id
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(ModelError::validation(
                        "BW-CONTRACT-API-MAP-OPAQUE-BINDING-API-ID",
                        format!(
                            "opaque handle API {} 缺少 opaque_binding_api_id",
                            entry.api_id
                        ),
                    ));
                }
                if role == OpaqueHandleApiRole::Set
                    && entry.opaque_binding_api_id.as_deref() != Some(entry.api_id.as_str())
                {
                    return Err(ModelError::validation(
                        "BW-CONTRACT-API-MAP-OPAQUE-SET-BINDING-API-ID",
                        format!(
                            "opaque handle set API {} 必须以自身 api_id 作为 opaque_binding_api_id",
                            entry.api_id
                        ),
                    ));
                }
                if entry.opaque_handle_arg_index.is_none() || entry.opaque_key_arg_index.is_none() {
                    return Err(ModelError::validation(
                        "BW-CONTRACT-API-MAP-OPAQUE-ARG-INDEX",
                        format!(
                            "opaque handle API {} 必须声明 handle/key 参数 index",
                            entry.api_id
                        ),
                    ));
                }
                validate_opaque_generation_key(entry, role)?;
                match role {
                    OpaqueHandleApiRole::Set if entry.opaque_payload_arg_index.is_none() => {
                        return Err(ModelError::validation(
                            "BW-CONTRACT-API-MAP-OPAQUE-PAYLOAD-ARG-INDEX",
                            format!(
                                "opaque handle set API {} 缺少 payload 参数 index",
                                entry.api_id
                            ),
                        ));
                    }
                    OpaqueHandleApiRole::Get if entry.opaque_payload_arg_index.is_some() => {
                        return Err(ModelError::validation(
                            "BW-CONTRACT-API-MAP-OPAQUE-GET-PAYLOAD-ARG-INDEX",
                            format!(
                                "opaque handle get API {} 不应声明 payload 参数 index",
                                entry.api_id
                            ),
                        ));
                    }
                    _ => {}
                }
            }
        }
        for entry in &self.apis {
            let Some(binding_api_id) = entry.opaque_binding_api_id.as_deref() else {
                continue;
            };
            let Some(binding_entry) = self
                .apis
                .iter()
                .find(|candidate| candidate.api_id == binding_api_id)
            else {
                return Err(ModelError::validation(
                    "BW-CONTRACT-API-MAP-OPAQUE-BINDING-REFERENCE",
                    format!(
                        "opaque handle API {} 引用了不存在的 opaque_binding_api_id {}",
                        entry.api_id, binding_api_id
                    ),
                ));
            };
            if binding_entry.opaque_handle_role != Some(OpaqueHandleApiRole::Set) {
                return Err(ModelError::validation(
                    "BW-CONTRACT-API-MAP-OPAQUE-BINDING-ROLE",
                    format!(
                        "opaque handle API {} 的 opaque_binding_api_id {} 不是 set role",
                        entry.api_id, binding_api_id
                    ),
                ));
            }
            if binding_entry.callback_family != entry.callback_family {
                return Err(ModelError::validation(
                    "BW-CONTRACT-API-MAP-OPAQUE-BINDING-FAMILY",
                    format!(
                        "opaque handle API {} 与 binding API {} 的 callback_family 不一致",
                        entry.api_id, binding_api_id
                    ),
                ));
            }
            if !binding_entry
                .opaque_generation_key
                .contains(&OpaqueHandleIdentityComponent::PayloadArg)
            {
                return Err(ModelError::validation(
                    "BW-CONTRACT-API-MAP-OPAQUE-BINDING-GENERATION-KEY",
                    format!(
                        "opaque handle API {} 的 binding API {} 缺少 payload generation key",
                        entry.api_id, binding_api_id
                    ),
                ));
            }
        }
        Ok(())
    }
}

fn validate_opaque_generation_key(
    entry: &CallbackRetentionApiMapEntry,
    role: OpaqueHandleApiRole,
) -> Result<(), ModelError> {
    if entry.opaque_generation_key.is_empty() {
        return Err(ModelError::validation(
            "BW-CONTRACT-API-MAP-OPAQUE-GENERATION-KEY",
            format!(
                "opaque handle API {} 必须声明结构化 opaque_generation_key",
                entry.api_id
            ),
        ));
    }
    let components = entry
        .opaque_generation_key
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if components.len() != entry.opaque_generation_key.len() {
        return Err(ModelError::validation(
            "BW-CONTRACT-API-MAP-OPAQUE-GENERATION-KEY-DUPLICATE",
            format!(
                "opaque handle API {} 的 opaque_generation_key 包含重复 component",
                entry.api_id
            ),
        ));
    }
    for required in [
        OpaqueHandleIdentityComponent::BindingApiId,
        OpaqueHandleIdentityComponent::HandleArg,
        OpaqueHandleIdentityComponent::KeyArg,
    ] {
        if !components.contains(&required) {
            return Err(ModelError::validation(
                "BW-CONTRACT-API-MAP-OPAQUE-GENERATION-KEY-COMPONENT",
                format!(
                    "opaque handle API {} 的 opaque_generation_key 必须包含 binding_api_id、handle_arg、key_arg",
                    entry.api_id
                ),
            ));
        }
    }
    let has_payload = components.contains(&OpaqueHandleIdentityComponent::PayloadArg);
    match role {
        OpaqueHandleApiRole::Set if !has_payload => Err(ModelError::validation(
            "BW-CONTRACT-API-MAP-OPAQUE-GENERATION-KEY-PAYLOAD",
            format!(
                "opaque handle set API {} 的 opaque_generation_key 必须包含 payload_arg",
                entry.api_id
            ),
        )),
        OpaqueHandleApiRole::Get if has_payload => Err(ModelError::validation(
            "BW-CONTRACT-API-MAP-OPAQUE-GENERATION-KEY-GET-PAYLOAD",
            format!(
                "opaque handle get API {} 的 opaque_generation_key 不应包含 payload_arg",
                entry.api_id
            ),
        )),
        _ => Ok(()),
    }
}

/// 已校验的 callback retention contract 与 API map 组合。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackRetentionRegistry {
    pub contract: CallbackRetentionContract,
    pub api_map: CallbackRetentionApiMap,
}

impl CallbackRetentionRegistry {
    /// 仅在 contract 与 API map 指向同一 contract_id 时创建 registry。
    pub fn from_toml_strs(contract_toml: &str, api_map_toml: &str) -> Result<Self, ModelError> {
        let contract = CallbackRetentionContract::from_toml_str(contract_toml)?;
        let api_map = CallbackRetentionApiMap::from_toml_str(api_map_toml)?;
        if contract.contract_id != api_map.contract_id {
            return Err(ModelError::validation(
                "BW-CONTRACT-API-MAP-CONTRACT-ID",
                format!(
                    "contract_id 不一致: contract 为 {}，api map 为 {}",
                    contract.contract_id, api_map.contract_id
                ),
            ));
        }
        Ok(Self { contract, api_map })
    }
}

fn require_nonempty(field: &str, value: &str) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(ModelError::validation(
            "BW-CONTRACT-API-MAP-REQUIRED-EMPTY",
            format!("{field} 不能为空"),
        ));
    }
    Ok(())
}

/// 解析 `x.y.z` 形式的纯三段数字版本。
///
/// 只接受三段十进制数字。带 pre-release / build 后缀（`1.0.0-rc.1`、`1.0.0+deadbeef`）时
/// 返回 `None`：那些版本的排序规则不是逐段数字比较，猜一个顺序会让"在不在范围内"
/// 这种判定悄悄出错，宁可让调用方记成不可判定。
pub fn parse_plain_version(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let mut next = || -> Option<u64> {
        let part = parts.next()?;
        // `parse::<u64>` 会接受 `+7`；版本段不允许符号。
        part.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| part.parse::<u64>().ok())
            .flatten()
    };
    let major = next()?;
    let minor = next()?;
    let patch = next()?;
    parts.next().is_none().then_some((major, minor, patch))
}

/// `version` 是否落在 `max_version`（含）以内。任一侧解析不出来时返回 `None`。
pub fn plain_version_at_most(version: &str, max_version: &str) -> Option<bool> {
    Some(parse_plain_version(version)? <= parse_plain_version(max_version)?)
}
