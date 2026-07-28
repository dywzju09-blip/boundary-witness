use std::sync::OnceLock;

use bw_model::{
    CallbackRetentionApiMap, CallbackRetentionApiMapEntry, ExternalCallRole, OpaqueHandleApiRole,
    OpaqueHandleIdentityComponent, RegistrationRole,
};

const RUSQLITE_API_MAP: &str =
    include_str!("../../../contracts/callback-retention/rusqlite-api-map.toml");
const OPENSSL_API_MAP: &str =
    include_str!("../../../contracts/callback-retention/openssl-api-map.toml");
const PYO3_API_MAP: &str = include_str!("../../../contracts/callback-retention/pyo3-api-map.toml");
const DIESEL_API_MAP: &str =
    include_str!("../../../contracts/callback-retention/diesel-api-map.toml");

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallClassification {
    Registration {
        api_id: String,
        role: RegistrationRole,
    },
    ExternalCall {
        api_id: String,
        role: ExternalCallRole,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallContext<'a> {
    pub current_crate_name: &'a str,
    pub owner_def_path: Option<&'a str>,
}

/// 注册 API 的 callback 参数可观测状态。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationArgumentKind {
    CallbackPresent,
    ExplicitNone,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ApiMapEntry {
    api_id: String,
    rust_path: String,
    contract_api_id: String,
    callback_family: String,
    opaque_handle_role: Option<OpaqueHandleApiRole>,
    opaque_binding_api_id: Option<String>,
    opaque_handle_arg_index: Option<usize>,
    opaque_key_arg_index: Option<usize>,
    opaque_payload_arg_index: Option<usize>,
    opaque_generation_key: Vec<OpaqueHandleIdentityComponent>,
    callback_arg_indices: Vec<usize>,
    user_data_arg_indices: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpaqueHandleApiContract {
    pub role: OpaqueHandleApiRole,
    pub api_id: String,
    pub binding_api_id: String,
    pub family: String,
    pub handle_arg_index: usize,
    pub key_arg_index: usize,
    pub payload_arg_index: Option<usize>,
    pub generation_key: Vec<OpaqueHandleIdentityComponent>,
}

pub fn classify_call(
    def_path: &str,
    argument_kind: RegistrationArgumentKind,
    context: CallContext<'_>,
) -> Option<CallClassification> {
    classify_call_with_api_maps(def_path, argument_kind, context, &[])
}

pub fn classify_call_with_api_maps(
    def_path: &str,
    argument_kind: RegistrationArgumentKind,
    context: CallContext<'_>,
    extra_api_maps: &[CallbackRetentionApiMap],
) -> Option<CallClassification> {
    let canonical = canonical_def_path(def_path);
    let entries = all_api_entries(extra_api_maps);
    let matching = entries
        .iter()
        .filter(|entry| entry_matches(entry, &canonical, context))
        .collect::<Vec<_>>();
    let registration_roles = matching
        .iter()
        .filter_map(|entry| match entry_classification(entry) {
            Some(classification @ CallClassification::Registration { .. }) => Some(classification),
            _ => None,
        })
        .collect::<Vec<_>>();
    if !registration_roles.is_empty() {
        let preferred_role = match argument_kind {
            RegistrationArgumentKind::CallbackPresent => Some(RegistrationRole::Register),
            RegistrationArgumentKind::ExplicitNone => Some(RegistrationRole::Unregister),
            RegistrationArgumentKind::Unknown => None,
        };
        if let Some(preferred_role) = preferred_role {
            return registration_roles
                .iter()
                .find(|classification| {
                    matches!(
                        classification,
                        CallClassification::Registration { role, .. } if *role == preferred_role
                    )
                })
                .cloned();
        }
        let only_role =
            registration_roles
                .first()
                .and_then(|classification| match classification {
                    CallClassification::Registration { role, .. } => Some(*role),
                    CallClassification::ExternalCall { .. } => None,
                });
        return only_role
            .is_some_and(|role| {
                registration_roles.iter().all(|classification| {
                    matches!(classification, CallClassification::Registration { role: candidate, .. } if *candidate == role)
                })
            })
            .then(|| registration_roles.into_iter().next())
            .flatten();
    }
    matching.into_iter().find_map(entry_classification)
}

/// 本次分析实际生效的 callback API map 集合。
///
/// 一个 wrapper 进程只分析一个 crate，因此配置在分析开始时装载一次即可。没有它时，
/// registry 装载的 API map 无法到达 `classify_call` 等分类入口——`AnalysisRequest`
/// 的对应字段此前只写不读，checksum 与 manifest 审计因而不影响任何分类结果。
struct ConfiguredApiMaps {
    entries: Vec<ApiMapEntry>,
    include_embedded: bool,
}

static CONFIGURED_API_MAPS: OnceLock<ConfiguredApiMaps> = OnceLock::new();

/// 装载本次分析的 callback API map。只有首次调用生效。
///
/// `include_embedded` 为 false 时，编译进二进制的内置 API map 不参与分类，
/// 生效集合完全来自经过 checksum 校验的 registry。
pub fn configure_api_maps(api_maps: &[CallbackRetentionApiMap], include_embedded: bool) {
    let _ = CONFIGURED_API_MAPS.set(ConfiguredApiMaps {
        entries: api_maps.iter().flat_map(api_map_entries).collect(),
        include_embedded,
    });
}

fn all_api_entries(extra_api_maps: &[CallbackRetentionApiMap]) -> Vec<ApiMapEntry> {
    merge_api_entries(CONFIGURED_API_MAPS.get(), extra_api_maps)
}

/// [`all_api_entries`] 的纯逻辑，便于在不写进程级配置的前提下测试取舍。
fn merge_api_entries(
    configured: Option<&ConfiguredApiMaps>,
    extra_api_maps: &[CallbackRetentionApiMap],
) -> Vec<ApiMapEntry> {
    let include_embedded = configured.is_none_or(|configured| configured.include_embedded);

    let mut entries = if include_embedded {
        embedded_api_entries().to_vec()
    } else {
        Vec::new()
    };
    if let Some(configured) = configured {
        entries.extend(configured.entries.iter().cloned());
    }
    entries.extend(extra_api_maps.iter().flat_map(api_map_entries));
    entries
}

fn embedded_api_entries() -> &'static [ApiMapEntry] {
    static ENTRIES: OnceLock<Vec<ApiMapEntry>> = OnceLock::new();
    ENTRIES
        .get_or_init(|| {
            [
                RUSQLITE_API_MAP,
                OPENSSL_API_MAP,
                PYO3_API_MAP,
                DIESEL_API_MAP,
            ]
            .into_iter()
            .flat_map(|api_map_toml| {
                CallbackRetentionApiMap::from_toml_str(api_map_toml)
                    .expect("embedded callback API map must pass bw.api-map/0.1 validation")
                    .apis
                    .into_iter()
                    .map(api_entry_from_map_entry)
            })
            .collect()
        })
        .as_slice()
}

fn api_map_entries(api_map: &CallbackRetentionApiMap) -> Vec<ApiMapEntry> {
    api_map
        .apis
        .iter()
        .cloned()
        .map(api_entry_from_map_entry)
        .collect()
}

fn api_entry_from_map_entry(entry: CallbackRetentionApiMapEntry) -> ApiMapEntry {
    ApiMapEntry {
        api_id: entry.api_id,
        rust_path: entry.rust_path,
        contract_api_id: entry.contract_api_id,
        callback_family: entry.callback_family,
        opaque_handle_role: entry.opaque_handle_role,
        opaque_binding_api_id: entry.opaque_binding_api_id,
        opaque_handle_arg_index: entry.opaque_handle_arg_index,
        opaque_key_arg_index: entry.opaque_key_arg_index,
        opaque_payload_arg_index: entry.opaque_payload_arg_index,
        opaque_generation_key: entry.opaque_generation_key,
        callback_arg_indices: entry.callback_arg_indices,
        user_data_arg_indices: entry.user_data_arg_indices,
    }
}

pub fn opaque_handle_contract(
    def_path: &str,
    context: CallContext<'_>,
) -> Option<OpaqueHandleApiContract> {
    opaque_handle_contract_with_api_maps(def_path, context, &[])
}

pub fn opaque_handle_contract_with_api_maps(
    def_path: &str,
    context: CallContext<'_>,
    extra_api_maps: &[CallbackRetentionApiMap],
) -> Option<OpaqueHandleApiContract> {
    let canonical = canonical_def_path(def_path);
    let entries = all_api_entries(extra_api_maps);
    let mut matches = entries
        .iter()
        .filter(|entry| entry_matches(entry, &canonical, context))
        .filter_map(|entry| {
            Some(OpaqueHandleApiContract {
                role: entry.opaque_handle_role?,
                api_id: entry.api_id.clone(),
                binding_api_id: entry.opaque_binding_api_id.clone()?,
                family: entry.callback_family.clone(),
                handle_arg_index: entry.opaque_handle_arg_index?,
                key_arg_index: entry.opaque_key_arg_index?,
                payload_arg_index: entry.opaque_payload_arg_index,
                generation_key: entry.opaque_generation_key.clone(),
            })
        });
    let first = matches.next()?;
    matches.all(|candidate| candidate == first).then_some(first)
}

pub fn opaque_handle_contract_for_api_id(api_id: &str) -> Option<OpaqueHandleApiContract> {
    opaque_handle_contract_for_api_id_with_api_maps(api_id, &[])
}

pub fn opaque_handle_contract_for_api_id_with_api_maps(
    api_id: &str,
    extra_api_maps: &[CallbackRetentionApiMap],
) -> Option<OpaqueHandleApiContract> {
    let entries = all_api_entries(extra_api_maps);
    let mut matches = entries
        .iter()
        .filter(|entry| entry.api_id == api_id)
        .filter_map(|entry| {
            Some(OpaqueHandleApiContract {
                role: entry.opaque_handle_role?,
                api_id: entry.api_id.clone(),
                binding_api_id: entry.opaque_binding_api_id.clone()?,
                family: entry.callback_family.clone(),
                handle_arg_index: entry.opaque_handle_arg_index?,
                key_arg_index: entry.opaque_key_arg_index?,
                payload_arg_index: entry.opaque_payload_arg_index,
                generation_key: entry.opaque_generation_key.clone(),
            })
        });
    let first = matches.next()?;
    matches.all(|candidate| candidate == first).then_some(first)
}

pub fn callback_argument_indices(def_path: &str, context: CallContext<'_>) -> Vec<usize> {
    callback_argument_indices_with_api_maps(def_path, context, &[])
}

pub fn callback_argument_indices_with_api_maps(
    def_path: &str,
    context: CallContext<'_>,
    extra_api_maps: &[CallbackRetentionApiMap],
) -> Vec<usize> {
    let canonical = canonical_def_path(def_path);
    let entries = all_api_entries(extra_api_maps);
    if let Some(indices) = unique_mapped_callback_argument_indices(&entries, &canonical, context) {
        return indices;
    }
    if rusqlite_update_hook_call_path(&canonical, context)
        || rusqlite_commit_hook_call_path(&canonical, context)
        || rusqlite_rollback_hook_call_path(&canonical, context)
    {
        return vec![1];
    }
    if rusqlite_set_callback_with_user_data_call_path(&canonical, context) {
        return vec![1];
    }
    if rusqlite_create_scalar_function_call_path(&canonical, context) {
        return vec![2];
    }
    if rusqlite_sqlite3_update_hook_ffi_path(&canonical) {
        return vec![1];
    }
    if rusqlite_sqlite3_commit_hook_ffi_path(&canonical)
        || rusqlite_sqlite3_rollback_hook_ffi_path(&canonical)
    {
        return vec![1];
    }
    if rusqlite_sqlite3_create_function_v2_ffi_path(&canonical) {
        return vec![5, 6, 7];
    }
    if diesel_sqlite3_create_function_v2_ffi_path(&canonical, context) {
        return vec![5, 6, 7];
    }
    if pyo3_pycapsule_new_ffi_path(&canonical) {
        return vec![2];
    }
    Vec::new()
}

pub fn user_data_argument_indices(api_id: &str) -> Vec<usize> {
    user_data_argument_indices_with_api_maps(api_id, &[])
}

pub fn user_data_argument_indices_with_api_maps(
    api_id: &str,
    extra_api_maps: &[CallbackRetentionApiMap],
) -> Vec<usize> {
    let entries = all_api_entries(extra_api_maps);
    if let Some(indices) = unique_mapped_user_data_argument_indices(&entries, api_id) {
        return indices;
    }
    match api_id {
        "api:rusqlite:update_hook:register" => vec![2],
        "api:rusqlite:commit_hook:register" => vec![2],
        "api:rusqlite:rollback_hook:register" => vec![2],
        "api:rusqlite:create_scalar_function:register" => vec![4],
        "api:rusqlite:set_callback_with_user_data:register" => vec![2],
        "api:openssl:ssl_ctx_set_ex_data:register" => vec![2],
        "api:openssl:ssl_set_ex_data:register" => vec![2],
        "api:pyo3:pycapsule_new:register" => vec![0],
        "api:diesel:sqlite3_create_function_v2:register" => vec![4],
        _ => Vec::new(),
    }
}

fn unique_mapped_callback_argument_indices(
    entries: &[ApiMapEntry],
    canonical_def_path: &str,
    context: CallContext<'_>,
) -> Option<Vec<usize>> {
    let mut matches = entries
        .iter()
        .filter(|entry| entry_matches(entry, canonical_def_path, context))
        .filter(|entry| !entry.callback_arg_indices.is_empty())
        .map(|entry| entry.callback_arg_indices.clone());
    let first = matches.next()?;
    matches.all(|candidate| candidate == first).then_some(first)
}

fn unique_mapped_user_data_argument_indices(
    entries: &[ApiMapEntry],
    api_id: &str,
) -> Option<Vec<usize>> {
    let mut matches = entries
        .iter()
        .filter(|entry| entry.api_id == api_id)
        .filter(|entry| !entry.user_data_arg_indices.is_empty())
        .map(|entry| entry.user_data_arg_indices.clone());
    let first = matches.next()?;
    matches.all(|candidate| candidate == first).then_some(first)
}

fn entry_matches(entry: &ApiMapEntry, canonical_def_path: &str, context: CallContext<'_>) -> bool {
    if entry.rust_path == "SQLite callback trampoline" {
        return canonical_def_path.contains("callback_trampoline");
    }
    canonical_def_path == entry.rust_path
        || (context.current_crate_name == "rusqlite"
            && api_path_without_crate(&entry.rust_path)
                .is_some_and(|path| canonical_def_path == path))
        || rusqlite_cfg_module_impl_matches(entry, canonical_def_path, context)
        || cross_crate_inherent_impl_matches(entry, canonical_def_path)
        || rusqlite_ffi_call_matches(entry, canonical_def_path)
        || openssl_ffi_call_matches(entry, canonical_def_path)
        || pyo3_ffi_call_matches(entry, canonical_def_path)
        || diesel_ffi_call_matches(entry, canonical_def_path, context)
}

fn api_path_without_crate(api_rust_path: &str) -> Option<&str> {
    api_rust_path.split_once("::").map(|(_, path)| path)
}

/// 被分析的 crate 只是 API 的**使用者**，callee 定义在声明该 API 的 crate 里。
///
/// API map 写的是人类可读的 `<krate>::<Owner>::<method>`，但 rustc 对一个跨 crate
/// 的固有实现方法打印的是 `<krate>::<module>::<impl <SelfTy>>::<method>`：模块段和
/// `<impl …>` 段都在，因而既不等于 map 里的路径，也不是编译该 crate 自身时那种
/// 无 crate 前缀的形式（`<module>::<impl …>::<method>`，由
/// [`rusqlite_cfg_module_impl_matches`] 处理）。
///
/// 判定只看 callee 自己的 def path —— crate、self 类型、方法名。**不看当前被编译的
/// crate 是谁**：调用方是谁与"这个调用是不是注册"无关。这正是扫描任意 crate 找
/// 第三方 API 误用时走的路径。
fn cross_crate_inherent_impl_matches(entry: &ApiMapEntry, canonical_def_path: &str) -> bool {
    let Some((krate, owner, method)) = split_owner_api_rust_path(&entry.rust_path) else {
        return false;
    };
    let Some(rest) = canonical_def_path.strip_prefix(&format!("{krate}::")) else {
        return false;
    };
    let Some(rest) = rest.strip_suffix(&format!("::{method}")) else {
        return false;
    };
    let Some(self_ty) = inherent_impl_self_type(rest) else {
        return false;
    };
    self_ty == owner || self_ty.ends_with(&format!("::{owner}"))
}

/// 把 API map 的 `<krate>::<Owner>::<method>` 拆开。段数必须正好是 3：自由函数
/// （`openssl_sys::SSL_CTX_set_ex_data`）不是固有实现方法，不该走这条匹配。
fn split_owner_api_rust_path(api_rust_path: &str) -> Option<(&str, &str, &str)> {
    let mut segments = api_rust_path.split("::");
    let krate = segments.next()?;
    let owner = segments.next()?;
    let method = segments.next()?;
    segments.next().is_none().then_some((krate, owner, method))
}

/// 从 `<module>::<impl <SelfTy>>` 里取出 `SelfTy`，仅限固有实现。
///
/// trait 实现打印成 `<impl <Trait> for <SelfTy>>`，必须拒绝：否则
/// `<impl Drop for rusqlite::Connection>::drop` 这类路径会因为尾段同名而被误判成注册。
/// 带泛型参数的 self 类型（`<impl Foo<Bar>>`）这里会被保守地判不匹配，宁可漏也不错认。
fn inherent_impl_self_type(path: &str) -> Option<&str> {
    let inner = path.strip_suffix('>')?;
    let (module_prefix, self_ty) = inner.rsplit_once("<impl ")?;
    if !(module_prefix.is_empty() || module_prefix.ends_with("::")) {
        return None;
    }
    if self_ty.contains(" for ") || self_ty.contains('<') || self_ty.contains('>') {
        return None;
    }
    Some(self_ty)
}

fn rusqlite_cfg_module_impl_matches(
    entry: &ApiMapEntry,
    canonical_def_path: &str,
    context: CallContext<'_>,
) -> bool {
    if context.current_crate_name != "rusqlite" {
        return false;
    }
    let Some(api_path) = api_path_without_crate(&entry.rust_path) else {
        return false;
    };
    let Some((owner, method)) = api_path.rsplit_once("::") else {
        return false;
    };
    if owner != "Connection" {
        return false;
    }
    let expected_module = match method {
        "create_scalar_function" => "functions",
        "update_hook" | "commit_hook" | "rollback_hook" => "hooks",
        _ => return false,
    };
    if !canonical_def_path.ends_with(&format!("::{method}")) {
        return false;
    }
    if !canonical_def_path.starts_with(&format!("{expected_module}::<impl ")) {
        return false;
    }
    canonical_def_path.contains("Connection>")
        || canonical_def_path.contains("inner_connection::InnerConnection>")
}

fn rusqlite_ffi_call_matches(entry: &ApiMapEntry, canonical_def_path: &str) -> bool {
    if rusqlite_sqlite3_update_hook_ffi_path(canonical_def_path) {
        return entry.api_id == "api:rusqlite:update_hook:register"
            || entry.api_id == "api:rusqlite:update_hook:unregister";
    }
    if rusqlite_sqlite3_commit_hook_ffi_path(canonical_def_path) {
        return entry.api_id == "api:rusqlite:commit_hook:register"
            || entry.api_id == "api:rusqlite:commit_hook:unregister";
    }
    if rusqlite_sqlite3_rollback_hook_ffi_path(canonical_def_path) {
        return entry.api_id == "api:rusqlite:rollback_hook:register"
            || entry.api_id == "api:rusqlite:rollback_hook:unregister";
    }
    if rusqlite_sqlite3_create_function_v2_ffi_path(canonical_def_path) {
        return entry.api_id == "api:rusqlite:create_scalar_function:register";
    }
    false
}

fn openssl_ffi_call_matches(entry: &ApiMapEntry, canonical_def_path: &str) -> bool {
    if openssl_sys_api_path_matches(&entry.rust_path, canonical_def_path) {
        return true;
    }
    if openssl_ssl_ctx_set_ex_data_ffi_path(canonical_def_path) {
        return entry.api_id == "api:openssl:ssl_ctx_set_ex_data:register";
    }
    if openssl_ssl_set_ex_data_ffi_path(canonical_def_path) {
        return entry.api_id == "api:openssl:ssl_set_ex_data:register";
    }
    false
}

fn openssl_sys_api_path_matches(api_rust_path: &str, canonical_def_path: &str) -> bool {
    if !api_rust_path.starts_with("openssl_sys::")
        || !canonical_def_path.starts_with("openssl_sys::")
    {
        return false;
    }
    canonical_def_path == api_rust_path
        || api_rust_path
            .rsplit_once("::")
            .is_some_and(|(_, function)| canonical_def_path.ends_with(&format!("::{function}")))
}

fn pyo3_ffi_call_matches(entry: &ApiMapEntry, canonical_def_path: &str) -> bool {
    if pyo3_pycapsule_new_ffi_path(canonical_def_path) {
        return entry.api_id == "api:pyo3:pycapsule_new:register";
    }
    false
}

fn diesel_ffi_call_matches(
    entry: &ApiMapEntry,
    canonical_def_path: &str,
    context: CallContext<'_>,
) -> bool {
    if diesel_sqlite3_create_function_v2_ffi_path(canonical_def_path, context) {
        return entry.api_id == "api:diesel:sqlite3_create_function_v2:register";
    }
    false
}

fn rusqlite_update_hook_call_path(canonical_def_path: &str, context: CallContext<'_>) -> bool {
    context.current_crate_name == "rusqlite"
        && (canonical_def_path == "rusqlite::Connection::update_hook"
            || canonical_def_path == "Connection::update_hook"
            || canonical_def_path.ends_with("::Connection::update_hook")
            || (canonical_def_path.starts_with("hooks::<impl ")
                && canonical_def_path.ends_with("::update_hook")))
}

fn rusqlite_commit_hook_call_path(canonical_def_path: &str, context: CallContext<'_>) -> bool {
    context.current_crate_name == "rusqlite"
        && (canonical_def_path == "rusqlite::Connection::commit_hook"
            || canonical_def_path == "Connection::commit_hook"
            || canonical_def_path.ends_with("::Connection::commit_hook")
            || (canonical_def_path.starts_with("hooks::<impl ")
                && canonical_def_path.ends_with("::commit_hook")))
}

fn rusqlite_rollback_hook_call_path(canonical_def_path: &str, context: CallContext<'_>) -> bool {
    context.current_crate_name == "rusqlite"
        && (canonical_def_path == "rusqlite::Connection::rollback_hook"
            || canonical_def_path == "Connection::rollback_hook"
            || canonical_def_path.ends_with("::Connection::rollback_hook")
            || (canonical_def_path.starts_with("hooks::<impl ")
                && canonical_def_path.ends_with("::rollback_hook")))
}

fn rusqlite_create_scalar_function_call_path(
    canonical_def_path: &str,
    context: CallContext<'_>,
) -> bool {
    context.current_crate_name == "rusqlite"
        && (canonical_def_path == "rusqlite::Connection::create_scalar_function"
            || canonical_def_path == "Connection::create_scalar_function"
            || canonical_def_path.ends_with("::Connection::create_scalar_function")
            || (canonical_def_path.starts_with("functions::<impl ")
                && canonical_def_path.ends_with("::create_scalar_function")))
}

fn rusqlite_set_callback_with_user_data_call_path(
    canonical_def_path: &str,
    context: CallContext<'_>,
) -> bool {
    context.current_crate_name == "rusqlite"
        && (canonical_def_path == "rusqlite::Connection::set_callback_with_user_data"
            || canonical_def_path == "Connection::set_callback_with_user_data"
            || canonical_def_path.ends_with("::Connection::set_callback_with_user_data"))
}

fn rusqlite_sqlite3_update_hook_ffi_path(canonical_def_path: &str) -> bool {
    canonical_def_path.starts_with("libsqlite3_sys::")
        && canonical_def_path.ends_with("::sqlite3_update_hook")
}

fn rusqlite_sqlite3_commit_hook_ffi_path(canonical_def_path: &str) -> bool {
    canonical_def_path.starts_with("libsqlite3_sys::")
        && canonical_def_path.ends_with("::sqlite3_commit_hook")
}

fn rusqlite_sqlite3_rollback_hook_ffi_path(canonical_def_path: &str) -> bool {
    canonical_def_path.starts_with("libsqlite3_sys::")
        && canonical_def_path.ends_with("::sqlite3_rollback_hook")
}

fn rusqlite_sqlite3_create_function_v2_ffi_path(canonical_def_path: &str) -> bool {
    canonical_def_path.starts_with("libsqlite3_sys::")
        && canonical_def_path.ends_with("::sqlite3_create_function_v2")
}

fn diesel_sqlite3_create_function_v2_ffi_path(
    canonical_def_path: &str,
    context: CallContext<'_>,
) -> bool {
    context.current_crate_name == "diesel"
        && (canonical_def_path == "sqlite::connection::raw::ffi::sqlite3_create_function_v2"
            || ((canonical_def_path == "sqlite::connection::ffi::sqlite3_create_function_v2"
                || canonical_def_path == "sqlite3_create_function_v2")
                && context
                    .owner_def_path
                    .is_some_and(diesel_raw_register_owner_path)))
}

fn diesel_raw_register_owner_path(owner_def_path: &str) -> bool {
    let canonical = canonical_def_path(owner_def_path);
    canonical == "sqlite::connection::raw::RawConnection::register_sql_function"
        || canonical == "sqlite::connection::raw::register_sql_function"
}

fn openssl_ssl_ctx_set_ex_data_ffi_path(canonical_def_path: &str) -> bool {
    canonical_def_path.starts_with("openssl_sys::")
        && canonical_def_path.ends_with("::SSL_CTX_set_ex_data")
}

fn openssl_ssl_set_ex_data_ffi_path(canonical_def_path: &str) -> bool {
    canonical_def_path.starts_with("openssl_sys::")
        && canonical_def_path.ends_with("::SSL_set_ex_data")
}

fn pyo3_pycapsule_new_ffi_path(canonical_def_path: &str) -> bool {
    (canonical_def_path == "pyo3_ffi::PyCapsule_New"
        || canonical_def_path.starts_with("pyo3_ffi::"))
        && canonical_def_path.ends_with("::PyCapsule_New")
}

fn entry_classification(entry: &ApiMapEntry) -> Option<CallClassification> {
    match entry.contract_api_id.as_str() {
        "api:register" => Some(CallClassification::Registration {
            api_id: entry.api_id.clone(),
            role: RegistrationRole::Register,
        }),
        "api:unregister" => Some(CallClassification::Registration {
            api_id: entry.api_id.clone(),
            role: RegistrationRole::Unregister,
        }),
        "api:replace" => Some(CallClassification::Registration {
            api_id: entry.api_id.clone(),
            role: RegistrationRole::Replace,
        }),
        "api:invoke" => Some(CallClassification::ExternalCall {
            api_id: entry.api_id.clone(),
            role: ExternalCallRole::Invoke,
        }),
        "api:external_call" => Some(CallClassification::ExternalCall {
            api_id: entry.api_id.clone(),
            role: ExternalCallRole::ExternalCall,
        }),
        _ => None,
    }
}

fn canonical_def_path(def_path: &str) -> String {
    def_path
        .split("::")
        .filter(|segment| !(segment.starts_with("{impl#") && segment.ends_with('}')))
        .collect::<Vec<_>>()
        .join("::")
}

#[cfg(test)]
mod tests {
    use bw_model::OpaqueHandleIdentityComponent;
    use bw_model::{OpaqueHandleApiRole, RegistrationRole};

    use super::{
        CallClassification, CallContext, RegistrationArgumentKind, callback_argument_indices,
        classify_call, opaque_handle_contract, opaque_handle_contract_for_api_id,
        user_data_argument_indices,
    };

    fn rusqlite_context() -> CallContext<'static> {
        CallContext {
            current_crate_name: "rusqlite",
            owner_def_path: None,
        }
    }

    fn unrelated_context() -> CallContext<'static> {
        CallContext {
            current_crate_name: "unrelated",
            owner_def_path: None,
        }
    }

    fn openssl_context() -> CallContext<'static> {
        CallContext {
            current_crate_name: "openssl",
            owner_def_path: None,
        }
    }

    fn pyo3_context() -> CallContext<'static> {
        CallContext {
            current_crate_name: "pyo3",
            owner_def_path: None,
        }
    }

    fn diesel_context() -> CallContext<'static> {
        CallContext {
            current_crate_name: "diesel",
            owner_def_path: None,
        }
    }

    fn diesel_raw_register_context() -> CallContext<'static> {
        CallContext {
            current_crate_name: "diesel",
            owner_def_path: Some("sqlite::connection::raw::RawConnection::register_sql_function"),
        }
    }

    #[test]
    fn classifies_real_rusqlite_hooks_impl_update_hook() {
        let classification = classify_call(
            "hooks::<impl inner_connection::InnerConnection>::update_hook",
            RegistrationArgumentKind::CallbackPresent,
            rusqlite_context(),
        )
        .expect("real rusqlite hooks impl should classify as registration");

        assert!(matches!(
            classification,
            CallClassification::Registration {
                api_id,
                role: RegistrationRole::Register,
            } if api_id == "api:rusqlite:update_hook:register"
        ));
    }

    #[test]
    fn classifies_real_rusqlite_hooks_impl_commit_and_rollback_hooks() {
        for (method, register_api, unregister_api) in [
            (
                "commit_hook",
                "api:rusqlite:commit_hook:register",
                "api:rusqlite:commit_hook:unregister",
            ),
            (
                "rollback_hook",
                "api:rusqlite:rollback_hook:register",
                "api:rusqlite:rollback_hook:unregister",
            ),
        ] {
            let def_path = format!("hooks::<impl inner_connection::InnerConnection>::{method}");
            let register = classify_call(
                &def_path,
                RegistrationArgumentKind::CallbackPresent,
                rusqlite_context(),
            )
            .expect("real rusqlite hook impl should classify as registration");
            assert!(matches!(
                register,
                CallClassification::Registration {
                    api_id,
                    role: RegistrationRole::Register,
                } if api_id == register_api
            ));

            let unregister = classify_call(
                &def_path,
                RegistrationArgumentKind::ExplicitNone,
                rusqlite_context(),
            )
            .expect("real rusqlite hook impl explicit none should classify as unregister");
            assert!(matches!(
                unregister,
                CallClassification::Registration {
                    api_id,
                    role: RegistrationRole::Unregister,
                } if api_id == unregister_api
            ));

            assert_eq!(
                callback_argument_indices(&def_path, rusqlite_context()),
                &[1]
            );
            assert_eq!(user_data_argument_indices(register_api), &[2]);
        }
    }

    #[test]
    fn classifies_real_rusqlite_functions_impl_create_scalar_function() {
        let classification = classify_call(
            "functions::<impl inner_connection::InnerConnection>::create_scalar_function",
            RegistrationArgumentKind::CallbackPresent,
            rusqlite_context(),
        )
        .expect("real rusqlite functions impl should classify as registration");

        assert!(matches!(
            classification,
            CallClassification::Registration {
                api_id,
                role: RegistrationRole::Register,
            } if api_id == "api:rusqlite:create_scalar_function:register"
        ));
    }

    #[test]
    fn unrelated_update_hook_method_does_not_match_rusqlite_contract() {
        let classification = classify_call(
            "unrelated_component::Connection::update_hook",
            RegistrationArgumentKind::CallbackPresent,
            rusqlite_context(),
        );

        assert!(classification.is_none());
    }

    #[test]
    fn same_shape_non_rusqlite_impl_does_not_match_rusqlite_contract() {
        let hooks = classify_call(
            "hooks::<impl unrelated_component::Connection>::update_hook",
            RegistrationArgumentKind::CallbackPresent,
            unrelated_context(),
        );
        assert!(hooks.is_none());

        let functions = classify_call(
            "functions::<impl unrelated_component::Connection>::create_scalar_function",
            RegistrationArgumentKind::CallbackPresent,
            unrelated_context(),
        );
        assert!(functions.is_none());
    }

    #[test]
    fn local_sqlite3_same_name_does_not_match_ffi_contract() {
        let update_hook = classify_call(
            "rusqlite::sqlite3_update_hook",
            RegistrationArgumentKind::CallbackPresent,
            rusqlite_context(),
        );
        assert!(update_hook.is_none());

        let create_function = classify_call(
            "rusqlite::sqlite3_create_function_v2",
            RegistrationArgumentKind::CallbackPresent,
            rusqlite_context(),
        );
        assert!(create_function.is_none());

        let commit_hook = classify_call(
            "rusqlite::sqlite3_commit_hook",
            RegistrationArgumentKind::CallbackPresent,
            rusqlite_context(),
        );
        assert!(commit_hook.is_none());

        let rollback_hook = classify_call(
            "rusqlite::sqlite3_rollback_hook",
            RegistrationArgumentKind::CallbackPresent,
            rusqlite_context(),
        );
        assert!(rollback_hook.is_none());
    }

    #[test]
    fn classifies_rusqlite_update_hook_ffi_register_and_unregister() {
        let register = classify_call(
            "libsqlite3_sys::bindings::sqlite3_update_hook",
            RegistrationArgumentKind::CallbackPresent,
            rusqlite_context(),
        )
        .expect("sqlite3_update_hook callback argument should classify as register");
        assert!(matches!(
            register,
            CallClassification::Registration {
                api_id,
                role: RegistrationRole::Register,
            } if api_id == "api:rusqlite:update_hook:register"
        ));

        let unregister = classify_call(
            "libsqlite3_sys::bindings::sqlite3_update_hook",
            RegistrationArgumentKind::ExplicitNone,
            rusqlite_context(),
        )
        .expect("sqlite3_update_hook explicit none should classify as unregister");
        assert!(matches!(
            unregister,
            CallClassification::Registration {
                api_id,
                role: RegistrationRole::Unregister,
            } if api_id == "api:rusqlite:update_hook:unregister"
        ));
    }

    #[test]
    fn classifies_rusqlite_create_function_v2_ffi_register() {
        let classification = classify_call(
            "libsqlite3_sys::bindings::sqlite3_create_function_v2",
            RegistrationArgumentKind::CallbackPresent,
            rusqlite_context(),
        )
        .expect("sqlite3_create_function_v2 should classify as scalar registration");

        assert!(matches!(
            classification,
            CallClassification::Registration {
                api_id,
                role: RegistrationRole::Register,
            } if api_id == "api:rusqlite:create_scalar_function:register"
        ));
    }

    #[test]
    fn classifies_diesel_crate_local_sqlite3_create_function_v2_register() {
        let def_path = "sqlite::connection::raw::ffi::sqlite3_create_function_v2";
        let classification = classify_call(
            def_path,
            RegistrationArgumentKind::CallbackPresent,
            diesel_context(),
        )
        .expect("audited Diesel crate-local sqlite3_create_function_v2 should classify");

        assert!(matches!(
            classification,
            CallClassification::Registration {
                api_id,
                role: RegistrationRole::Register,
            } if api_id == "api:diesel:sqlite3_create_function_v2:register"
        ));
        assert_eq!(
            callback_argument_indices(def_path, diesel_context()),
            &[5, 6, 7]
        );
        assert_eq!(
            user_data_argument_indices("api:diesel:sqlite3_create_function_v2:register"),
            &[4]
        );
    }

    #[test]
    fn classifies_diesel_bare_foreign_item_only_inside_raw_register_owner() {
        let classification = classify_call(
            "sqlite3_create_function_v2",
            RegistrationArgumentKind::CallbackPresent,
            diesel_raw_register_context(),
        )
        .expect("Diesel raw register owner should classify bare foreign item callee");

        assert!(matches!(
            classification,
            CallClassification::Registration {
                api_id,
                role: RegistrationRole::Register,
            } if api_id == "api:diesel:sqlite3_create_function_v2:register"
        ));
        assert_eq!(
            callback_argument_indices("sqlite3_create_function_v2", diesel_raw_register_context()),
            &[5, 6, 7]
        );
    }

    #[test]
    fn classifies_diesel_connection_ffi_sqlite3_create_function_v2_inside_raw_register_owner() {
        let def_path = "sqlite::connection::ffi::sqlite3_create_function_v2";
        let classification = classify_call(
            def_path,
            RegistrationArgumentKind::CallbackPresent,
            diesel_raw_register_context(),
        )
        .expect("Diesel raw register owner should classify connection-level ffi alias");

        assert!(matches!(
            classification,
            CallClassification::Registration {
                api_id,
                role: RegistrationRole::Register,
            } if api_id == "api:diesel:sqlite3_create_function_v2:register"
        ));
        assert_eq!(
            callback_argument_indices(def_path, diesel_raw_register_context()),
            &[5, 6, 7]
        );
    }

    #[test]
    fn non_diesel_crate_local_sqlite3_create_function_v2_does_not_match_diesel_contract() {
        let classification = classify_call(
            "sqlite::connection::raw::ffi::sqlite3_create_function_v2",
            RegistrationArgumentKind::CallbackPresent,
            unrelated_context(),
        );
        assert!(classification.is_none());

        let root_same_name = classify_call(
            "diesel::sqlite3_create_function_v2",
            RegistrationArgumentKind::CallbackPresent,
            diesel_context(),
        );
        assert!(root_same_name.is_none());

        let bare_without_owner = classify_call(
            "sqlite3_create_function_v2",
            RegistrationArgumentKind::CallbackPresent,
            diesel_context(),
        );
        assert!(bare_without_owner.is_none());

        let connection_ffi_without_owner = classify_call(
            "sqlite::connection::ffi::sqlite3_create_function_v2",
            RegistrationArgumentKind::CallbackPresent,
            diesel_context(),
        );
        assert!(connection_ffi_without_owner.is_none());
    }

    #[test]
    fn classifies_rusqlite_commit_and_rollback_hook_ffi_register_and_unregister() {
        for (ffi_name, register_api, unregister_api) in [
            (
                "sqlite3_commit_hook",
                "api:rusqlite:commit_hook:register",
                "api:rusqlite:commit_hook:unregister",
            ),
            (
                "sqlite3_rollback_hook",
                "api:rusqlite:rollback_hook:register",
                "api:rusqlite:rollback_hook:unregister",
            ),
        ] {
            let def_path = format!("libsqlite3_sys::bindings::{ffi_name}");
            let register = classify_call(
                &def_path,
                RegistrationArgumentKind::CallbackPresent,
                rusqlite_context(),
            )
            .expect("sqlite hook callback argument should classify as register");
            assert!(matches!(
                register,
                CallClassification::Registration {
                    api_id,
                    role: RegistrationRole::Register,
                } if api_id == register_api
            ));

            let unregister = classify_call(
                &def_path,
                RegistrationArgumentKind::ExplicitNone,
                rusqlite_context(),
            )
            .expect("sqlite hook explicit none should classify as unregister");
            assert!(matches!(
                unregister,
                CallClassification::Registration {
                    api_id,
                    role: RegistrationRole::Unregister,
                } if api_id == unregister_api
            ));

            assert_eq!(
                callback_argument_indices(&def_path, rusqlite_context()),
                &[1]
            );
            assert_eq!(user_data_argument_indices(register_api), &[2]);
        }
    }

    #[test]
    fn classifies_openssl_ex_data_ffi_user_data_registers() {
        for (def_path, expected_api_id, expected_user_data_index) in [
            (
                "openssl_sys::handwritten::ssl::SSL_CTX_set_ex_data",
                "api:openssl:ssl_ctx_set_ex_data:register",
                2,
            ),
            (
                "openssl_sys::handwritten::ssl::SSL_set_ex_data",
                "api:openssl:ssl_set_ex_data:register",
                2,
            ),
        ] {
            let classification = classify_call(
                def_path,
                RegistrationArgumentKind::Unknown,
                openssl_context(),
            )
            .expect("audited OpenSSL ex_data setter should classify as retained user-data");

            assert!(matches!(
                classification,
                CallClassification::Registration {
                    api_id,
                    role: RegistrationRole::Register,
                } if api_id == expected_api_id
            ));
            assert!(callback_argument_indices(def_path, openssl_context()).is_empty());
            assert_eq!(
                user_data_argument_indices(expected_api_id),
                &[expected_user_data_index]
            );
        }
    }

    #[test]
    fn openssl_ex_data_opaque_handle_contract_comes_from_api_map() {
        let ssl_set = opaque_handle_contract(
            "openssl_sys::handwritten::ssl::SSL_set_ex_data",
            openssl_context(),
        )
        .expect("SSL_set_ex_data should have audited opaque set metadata");
        assert_eq!(ssl_set.role, OpaqueHandleApiRole::Set);
        assert_eq!(
            ssl_set.binding_api_id,
            "api:openssl:ssl_set_ex_data:register"
        );
        assert_eq!(ssl_set.handle_arg_index, 0);
        assert_eq!(ssl_set.key_arg_index, 1);
        assert_eq!(ssl_set.payload_arg_index, Some(2));
        assert_eq!(
            ssl_set.generation_key,
            vec![
                OpaqueHandleIdentityComponent::BindingApiId,
                OpaqueHandleIdentityComponent::HandleArg,
                OpaqueHandleIdentityComponent::KeyArg,
                OpaqueHandleIdentityComponent::PayloadArg,
            ]
        );

        let ssl_get = opaque_handle_contract(
            "openssl_sys::handwritten::ssl::SSL_get_ex_data",
            openssl_context(),
        )
        .expect("SSL_get_ex_data should have audited opaque get metadata");
        assert_eq!(ssl_get.role, OpaqueHandleApiRole::Get);
        assert_eq!(
            ssl_get.binding_api_id,
            "api:openssl:ssl_set_ex_data:register"
        );
        assert_eq!(ssl_get.handle_arg_index, 0);
        assert_eq!(ssl_get.key_arg_index, 1);
        assert_eq!(ssl_get.payload_arg_index, None);
        assert_eq!(
            ssl_get.generation_key,
            vec![
                OpaqueHandleIdentityComponent::BindingApiId,
                OpaqueHandleIdentityComponent::HandleArg,
                OpaqueHandleIdentityComponent::KeyArg,
            ]
        );

        let by_api = opaque_handle_contract_for_api_id("api:openssl:ssl_set_ex_data:register")
            .expect("set API id should resolve opaque set metadata");
        assert_eq!(by_api, ssl_set);

        assert!(
            opaque_handle_contract("openssl::ssl::SSL_get_ex_data", openssl_context()).is_none()
        );
    }

    #[test]
    fn classifies_pyo3_capsule_new_as_destructor_backed_user_data_register() {
        let classification = classify_call(
            "pyo3_ffi::cpython::capsule::PyCapsule_New",
            RegistrationArgumentKind::CallbackPresent,
            pyo3_context(),
        )
        .expect("audited CPython PyCapsule_New should classify as retained capsule user-data");

        assert!(matches!(
            classification,
            CallClassification::Registration {
                api_id,
                role: RegistrationRole::Register,
            } if api_id == "api:pyo3:pycapsule_new:register"
        ));
        assert_eq!(
            callback_argument_indices("pyo3_ffi::cpython::capsule::PyCapsule_New", pyo3_context()),
            &[2]
        );
        assert_eq!(
            user_data_argument_indices("api:pyo3:pycapsule_new:register"),
            &[0]
        );
    }

    #[test]
    fn local_pycapsule_new_same_name_does_not_match_pyo3_contract() {
        let classification = classify_call(
            "local_capsule::PyCapsule_New",
            RegistrationArgumentKind::CallbackPresent,
            pyo3_context(),
        );

        assert!(classification.is_none());
    }

    #[test]
    fn local_openssl_same_name_does_not_match_ex_data_contract() {
        for def_path in [
            "openssl::ssl::SSL_set_ex_data",
            "openssl::ssl::SSL_CTX_set_ex_data",
            "other_sys::handwritten::ssl::SSL_set_ex_data",
        ] {
            let classification = classify_call(
                def_path,
                RegistrationArgumentKind::Unknown,
                openssl_context(),
            );

            assert!(classification.is_none());
        }
    }

    /// 这是自动 0day 扫描实际走的路径：被扫的 crate 只是 rusqlite 的使用者。
    /// def path 取自真实编译产物 —— 见 `downstream_caller_registration_site` fixture。
    #[test]
    fn classifies_update_hook_called_from_a_downstream_crate() {
        let classification = classify_call(
            "rusqlite::hooks::<impl rusqlite::Connection>::update_hook",
            RegistrationArgumentKind::CallbackPresent,
            unrelated_context(),
        )
        .expect("a crate that merely depends on rusqlite must still register the call");

        assert!(matches!(
            classification,
            CallClassification::Registration {
                api_id,
                role: RegistrationRole::Register,
            } if api_id == "api:rusqlite:update_hook:register"
        ));
    }

    #[test]
    fn downstream_update_hook_with_explicit_none_is_an_unregister() {
        let classification = classify_call(
            "rusqlite::hooks::<impl rusqlite::Connection>::update_hook",
            RegistrationArgumentKind::ExplicitNone,
            unrelated_context(),
        )
        .expect("downstream unregistration must classify too");

        assert!(matches!(
            classification,
            CallClassification::Registration {
                role: RegistrationRole::Unregister,
                ..
            }
        ));
    }

    #[test]
    fn downstream_callback_argument_indices_are_resolved() {
        assert_eq!(
            callback_argument_indices(
                "rusqlite::hooks::<impl rusqlite::Connection>::update_hook",
                unrelated_context(),
            ),
            vec![1],
            "without the argument index the downstream call has no callback to bind"
        );
    }

    // 以下是放宽匹配的代价边界。跨 crate 匹配只依据 callee 的 def path，所以必须
    // 逐条钉死它不认什么，否则误判会一路传导到最终结论。

    /// trait 实现的方法名可能与注册 API 同名，尾段匹配会把它错认成注册。
    #[test]
    fn trait_impl_on_the_same_type_is_not_a_registration() {
        for def_path in [
            "rusqlite::hooks::<impl UpdateHook for rusqlite::Connection>::update_hook",
            "rusqlite::inner_connection::<impl Drop for rusqlite::Connection>::update_hook",
        ] {
            assert!(
                classify_call(
                    def_path,
                    RegistrationArgumentKind::CallbackPresent,
                    unrelated_context(),
                )
                .is_none(),
                "trait impl must not be mistaken for the inherent registration API: {def_path}"
            );
        }
    }

    /// 同名方法挂在别的类型上，不是合约声明的那个 owner。
    #[test]
    fn same_method_on_another_type_is_not_a_registration() {
        assert!(
            classify_call(
                "rusqlite::hooks::<impl rusqlite::Statement>::update_hook",
                RegistrationArgumentKind::CallbackPresent,
                unrelated_context(),
            )
            .is_none(),
            "the owner type in the API map is part of the identity, not decoration"
        );
    }

    /// 别的 crate 里刚好有个同名同签名的 `Connection::update_hook`。
    #[test]
    fn same_shape_in_another_crate_is_not_a_registration() {
        assert!(
            classify_call(
                "other_db::hooks::<impl other_db::Connection>::update_hook",
                RegistrationArgumentKind::CallbackPresent,
                unrelated_context(),
            )
            .is_none(),
            "the declaring crate is part of the identity"
        );
    }

    /// 使用者自己写的同名自由函数或方法，不在 rusqlite 里。
    #[test]
    fn caller_own_helper_named_like_the_api_is_not_a_registration() {
        for def_path in [
            "my_app::db::update_hook",
            "my_app::db::<impl my_app::db::Connection>::update_hook",
            "rusqlite_helpers::<impl rusqlite_helpers::Connection>::update_hook",
        ] {
            assert!(
                classify_call(
                    def_path,
                    RegistrationArgumentKind::CallbackPresent,
                    unrelated_context(),
                )
                .is_none(),
                "a lookalike outside the declaring crate must not classify: {def_path}"
            );
        }
    }

    /// `<impl …>` 段本身是识别固有实现的凭据，没有它就只是个模块内的自由函数。
    #[test]
    fn free_function_in_the_declaring_crate_is_not_a_registration() {
        assert!(
            classify_call(
                "rusqlite::hooks::update_hook",
                RegistrationArgumentKind::CallbackPresent,
                unrelated_context(),
            )
            .is_none(),
            "a free function in rusqlite::hooks is not Connection::update_hook"
        );
    }

    /// 老路径必须原样保留：编译 rusqlite 自身时 def path 没有 crate 前缀。
    #[test]
    fn in_crate_form_still_classifies_after_the_cross_crate_arm() {
        assert!(
            classify_call(
                "hooks::<impl rusqlite::Connection>::update_hook",
                RegistrationArgumentKind::CallbackPresent,
                rusqlite_context(),
            )
            .is_some(),
            "the cross-crate arm is additive; compiling rusqlite itself must be unaffected"
        );
    }
}

#[cfg(test)]
mod api_map_source_tests {
    use super::*;

    const REGISTRY_MAP: &str = r#"
schema_version = "bw.api-map/0.1"
map_id = "api-map:registry-only"
producer = "boundary-witness@test"
contract_id = "contract:callback-retention"

[[apis]]
api_id = "api:registry_only:register"
rust_path = "registry_only::Handle::set_callback"
contract_api_id = "api:register"
callback_family = "registry_only_callback"
callback_arg_indices = [1]
user_data_arg_indices = [2]
"#;

    fn registry_map() -> CallbackRetentionApiMap {
        CallbackRetentionApiMap::from_toml_str(REGISTRY_MAP).expect("test API map must parse")
    }

    fn configured(include_embedded: bool) -> ConfiguredApiMaps {
        ConfiguredApiMaps {
            entries: api_map_entries(&registry_map()),
            include_embedded,
        }
    }

    fn has_rust_path(entries: &[ApiMapEntry], rust_path: &str) -> bool {
        entries.iter().any(|entry| entry.rust_path == rust_path)
    }

    #[test]
    fn embedded_maps_are_used_when_nothing_is_configured() {
        let entries = merge_api_entries(None, &[]);
        assert!(
            has_rust_path(&entries, "rusqlite::Connection::update_hook"),
            "without a registry the embedded maps must stay in effect"
        );
    }

    #[test]
    fn configured_registry_maps_reach_classification() {
        let configured = configured(true);
        let entries = merge_api_entries(Some(&configured), &[]);
        assert!(
            has_rust_path(&entries, "registry_only::Handle::set_callback"),
            "a registry-loaded API map must reach the classifier; it was previously carried on \
             AnalysisRequest and never read"
        );
    }

    #[test]
    fn excluding_embedded_maps_leaves_only_the_audited_registry() {
        let configured = configured(false);
        let entries = merge_api_entries(Some(&configured), &[]);
        assert!(
            has_rust_path(&entries, "registry_only::Handle::set_callback"),
            "the audited registry must still be in effect"
        );
        assert!(
            !has_rust_path(&entries, "rusqlite::Connection::update_hook"),
            "embedded maps must not bypass the registry checksum audit once it is in force"
        );
        assert!(
            !has_rust_path(&entries, "openssl::ssl::SslRef::set_ex_data"),
            "no embedded map may survive an exclusive registry"
        );
    }

    #[test]
    fn extra_api_maps_are_appended_on_top_of_the_configured_set() {
        let configured = configured(false);
        let entries = merge_api_entries(Some(&configured), &[registry_map()]);
        let matches = entries
            .iter()
            .filter(|entry| entry.rust_path == "registry_only::Handle::set_callback")
            .count();
        assert_eq!(
            matches, 2,
            "per-call extra maps must add to, not replace, the configured set"
        );
    }
}
