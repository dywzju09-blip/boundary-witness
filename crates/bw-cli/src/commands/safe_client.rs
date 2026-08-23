//! safe-only 客户端的生成引擎（执行计划阶段 5.2，创新点 C1 的落点）。
//!
//! 输入是 [`WitnessPlan`](bw_model::WitnessPlan) 与一份**中性** adapter；输出是一个
//! 可编译的 `#![forbid(unsafe_code)]` 客户端 crate。
//!
//! # 三方职责边界（Gate B 判据）
//!
//! | 参与者 | 允许知道 | 禁止知道 |
//! | --- | --- | --- |
//! | adapter（冻结产物） | 公开 API 表面、合法调用方式、外部实现清单 | drop 时机、触发顺序、预期结果 |
//! | plan（判定推导） | 危险动作序列、形状 | 具体 API 名 |
//! | 本引擎 | 把前两者拼成可编译客户端 | 添加任何一方没有的动作 |
//!
//! 生成的每一条语句都对应 plan.steps 里的一步；引擎在产出后**断言步骤覆盖完整且
//! 顺序一致**。模板自带剧本而没有判定依据的客户端是伪造证据，这里用结构挡住它。
//!
//! # 控制组与 primary 共享同一模板
//!
//! 控制组只做两种机械改动：删掉触发步（no_trigger），或把触发步挪到任何失效动作
//! 之前（unregister_before_drop）。改动发生在步骤列表上而不是文本替换——语句与
//! 步骤的对应关系因此保持完整。

use std::path::{Path, PathBuf};

use bw_model::{DangerStep, HarnessShape, WitnessPlan, WitnessPlanRefusal};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::commands::hex_digest;

/// adapter 的协议版本。
pub(crate) const ADAPTER_SCHEMA: &str = "bw.adapter/0.1";

/// 客户端变体。primary 是计划本体；其余是机械导出的控制组。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) enum ClientVariant {
    Primary,
    NoTrigger,
    UnregisterBeforeDrop,
    OwnedCallback,
}

impl ClientVariant {
    pub(crate) fn dir_suffix(self) -> &'static str {
        match self {
            Self::Primary => "",
            Self::NoTrigger => "-no-trigger",
            Self::UnregisterBeforeDrop => "-unregister-first",
            Self::OwnedCallback => "-owned-callback",
        }
    }

    /// 控制矩阵引用用的稳定 token。
    pub(crate) fn token(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::NoTrigger => "no_trigger",
            Self::UnregisterBeforeDrop => "unregister_before_drop",
            Self::OwnedCallback => "owned_callback",
        }
    }

    pub(crate) fn from_token(token: &str) -> Option<Self> {
        match token {
            "primary" => Some(Self::Primary),
            "no_trigger" => Some(Self::NoTrigger),
            "unregister_before_drop" => Some(Self::UnregisterBeforeDrop),
            "owned_callback" => Some(Self::OwnedCallback),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// adapter 的严格解析。字段集与 adapters/*.toml 的冻结格式一致；
// deny_unknown_fields 让漂移在读取时爆掉而不是被静默忽略。
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Adapter {
    #[allow(dead_code)]
    pub(crate) schema_version: String,
    #[allow(dead_code)]
    pub(crate) adapter_id: String,
    /// 冻结元数据；生成产物只引用 adapter_id，冻结块保留以校验清单完整性。
    #[allow(dead_code)]
    #[serde(default)]
    pub(crate) freeze: Option<AdapterFreeze>,
    pub(crate) target: AdapterTarget,
    #[serde(default)]
    pub(crate) setup: Vec<AdapterStep>,
    #[serde(default)]
    pub(crate) registration_forms: Vec<AdapterRegistrationForm>,
    pub(crate) trigger: AdapterTrigger,
    #[serde(default, rename = "foreign_build")]
    pub(crate) foreign_builds: Vec<AdapterForeignBuild>,
    #[allow(dead_code)]
    #[serde(default)]
    pub(crate) teardown: Option<AdapterStep>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdapterFreeze {
    #[allow(dead_code)]
    pub(crate) frozen_at: String,
    #[allow(dead_code)]
    pub(crate) frozen_at_commit: String,
    #[allow(dead_code)]
    pub(crate) p3_verdict_available_at_freeze: bool,
    #[allow(dead_code)]
    pub(crate) authored_from: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdapterTarget {
    #[serde(rename = "crate")]
    pub(crate) crate_name: String,
    /// 记录进生成清单，供回执追溯组件版本。
    pub(crate) version: Option<String>,
    #[serde(default)]
    pub(crate) path_from_repo_root: Option<String>,
    #[serde(default)]
    pub(crate) edition: Option<String>,
    /// 组件依赖要开的 feature（公开 API 面，例如 rusqlite 的 bundled/hooks）。
    #[serde(default)]
    pub(crate) features: Option<Vec<String>>,
    /// 客户端是否需要把外部实现**直接链接进自己**。fixture 的 C stub 是：客户端
    /// 用 build.rs 编一份；rusqlite 这类组件自带外部库（bundled sqlite3），再链
    /// 一份符号冲突。默认 true 保持既有行为。
    #[serde(default = "default_true")]
    pub(crate) links_foreign_directly: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdapterStep {
    #[allow(dead_code)]
    pub(crate) step: String,
    pub(crate) rust: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdapterRegistrationForm {
    pub(crate) form: String,
    pub(crate) methods: Vec<String>,
    /// 公开签名形状（如 `FnMut(rusqlite::hooks::Action, &str, &str, i64)`）。
    /// 生成器只从中读**参数个数**来构造类型正确的闭包；类型本身由方法泛型推导。
    pub(crate) callback_signature: String,
    /// 中性事实：该表单的方法是否返回注册守卫。生成器用它交叉验证形状。
    pub(crate) returns_guard: bool,
    /// 公开签名的回调参数是不是 `Option<F>`（rusqlite 的注册入口都是）。默认
    /// false；true 时生成 `method(Some(callback))`。这只是调用形状，不含任何
    /// 行为语义。
    #[serde(default)]
    pub(crate) wraps_callback_in_option: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdapterTrigger {
    #[allow(dead_code)]
    pub(crate) step: String,
    pub(crate) rust: String,
    /// 触发最终落到的外部符号；与注册符号不同，属文档性元数据。
    #[allow(dead_code)]
    pub(crate) foreign_symbol: Option<String>,
    /// 组件必须提供安全触发入口才能生成反证；没有即覆盖缺口（按拒绝处理）。
    #[allow(dead_code)]
    #[serde(default = "default_true")]
    pub(crate) requires_component_trigger: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdapterForeignBuild {
    pub(crate) id: String,
    pub(crate) source: String,
    #[serde(default = "default_true")]
    pub(crate) provides_trigger_symbol: bool,
}

fn default_true() -> bool {
    true
}

impl Adapter {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let parsed: serde_json::Value =
            toml::from_str(text).map_err(|error| format!("adapter TOML 解析失败: {error}"))?;
        let version = parsed
            .get("schema_version")
            .and_then(serde_json::Value::as_str)
            .ok_or("adapter 缺少 schema_version")?;
        if version != ADAPTER_SCHEMA {
            return Err(format!(
                "不支持的 adapter schema {version}，当前要求 {ADAPTER_SCHEMA}"
            ));
        }
        toml::from_str(text).map_err(|error| format!("adapter TOML 解析失败: {error}"))
    }

    /// 组件在 Rust 代码里的标识符名（hyphen → underscore）。
    pub(crate) fn component_ident(&self) -> String {
        self.target.crate_name.replace('-', "_")
    }

    /// 形状对应的注册表单类。三对一一对应；错位说明 plan 与 adapter 不相容。
    fn expected_form(shape: HarnessShape) -> &'static str {
        match shape {
            HarnessShape::BorrowedCaptureEscapingScope => "non_static_capture",
            HarnessShape::GuardDefeatedBypass => "receiver_tied_capture",
            HarnessShape::AllocationFreedByWrapper => "static_capture",
        }
    }
}

/// 生成一个客户端 crate 所需的全部文件内容。
#[derive(Clone, Debug)]
pub(crate) struct GeneratedClient {
    pub(crate) dir_name: String,
    pub(crate) package_name: String,
    pub(crate) cargo_toml: String,
    pub(crate) build_rs: String,
    pub(crate) main_rs: String,
    pub(crate) main_rs_sha256: String,
}

/// 一个 plan 能导出哪些变体。owned_callback 只在 `'static` 形状且 adapter 提供
/// 同表单第二方法时可用——其余形状结构上不存在「换一个所有权语义」的入口。
pub(crate) fn exportable_variants(plan: &WitnessPlan, adapter: &Adapter) -> Vec<ClientVariant> {
    let mut variants = vec![ClientVariant::Primary];
    variants.push(ClientVariant::NoTrigger);
    if plan.shape == HarnessShape::GuardDefeatedBypass {
        variants.push(ClientVariant::UnregisterBeforeDrop);
    }
    if plan.shape == HarnessShape::AllocationFreedByWrapper
        && select_alternative_static_method(plan, adapter).is_ok()
    {
        variants.push(ClientVariant::OwnedCallback);
    }
    variants
}

pub(crate) fn generate_client(
    plan: &WitnessPlan,
    variant: ClientVariant,
    adapter: &Adapter,
    repo_root: &Path,
) -> Result<GeneratedClient, WitnessPlanRefusal> {
    let component_path = adapter
        .target
        .path_from_repo_root
        .clone()
        .ok_or(WitnessPlanRefusal::NoTemplateForContractShape)?;
    if !repo_root.join(&component_path).join("Cargo.toml").is_file() {
        return Err(WitnessPlanRefusal::NoTemplateForContractShape);
    }

    let registration = select_registration(plan, variant, adapter)?;
    let steps = effective_steps(plan, variant);
    let main_body = render_main(plan, variant, adapter, &registration, &steps)?;

    // 结构性非空检查：语句必须恰好覆盖 plan 的每一步，顺序不得改变。
    assert_eq!(
        annotated_steps(&main_body),
        steps
            .iter()
            .map(|step| format!("{step:?}"))
            .collect::<Vec<_>>(),
        "生成的语句序列必须与 plan.steps 一一对应"
    );

    let dir_name = format!("{}{}", plan.plan_id, variant.dir_suffix());
    let package_name = format!("bw-witness-{}", dir_name.replace('_', "-"));
    // path 依赖相对 harness 的 Cargo.toml 解析，而 harness 落在任意的输出目录里，
    // 因此写组件的绝对路径；adapter 里的仓库相对路径保留在清单与回执里。
    let component_absolute = repo_root.join(&component_path);
    // Cargo.toml 的依赖键是**包名**（保留连字符）；Rust 代码里的导入名才是
    // 下划线形式（component_ident）。
    let cargo_toml = render_cargo_toml(
        &package_name,
        &adapter.target.crate_name,
        &component_absolute.display().to_string(),
        adapter,
    );
    Ok(GeneratedClient {
        dir_name: dir_name.clone(),
        package_name,
        cargo_toml,
        // 组件自带外部库（links_foreign_directly = false）时客户端不得再链一份：
        // 符号会冲突。空 build_rs 让写出端跳过这个文件。
        build_rs: if adapter.target.links_foreign_directly {
            BUILD_RS.to_owned()
        } else {
            String::new()
        },
        main_rs: main_body.clone(),
        main_rs_sha256: hex_digest(Sha256::digest(main_body.as_bytes())),
    })
}

/// 选出注册方法与它的表单。
///
/// 方法名来自 **plan 携带的 safe_entry_instance**（编译器的观察结果），不是从
/// adapter 里挑一个像的；adapter 只负责确认这个方法存在并给出它的签名形状。
fn select_registration(
    plan: &WitnessPlan,
    variant: ClientVariant,
    adapter: &Adapter,
) -> Result<(String, AdapterRegistrationForm), WitnessPlanRefusal> {
    if variant == ClientVariant::OwnedCallback {
        return select_alternative_static_method(plan, adapter);
    }
    let method = method_from_instance(&plan.hand_off.safe_entry_instance)
        .ok_or(WitnessPlanRefusal::NoTemplateForContractShape)?;
    let form = adapter
        .registration_forms
        .iter()
        .find(|form| form.methods.iter().any(|name| name == &method))
        .cloned()
        .ok_or(WitnessPlanRefusal::NoTemplateForContractShape)?;
    // 双重一致性：表单类与「是否返回守卫」都必须与 plan 形状吻合。任何一侧
    // 错了（判定推导或 adapter 冻结数据）都不能靠硬套模板掩盖。
    let expected_returns_guard = plan.shape == HarnessShape::GuardDefeatedBypass;
    if form.form != Adapter::expected_form(plan.shape)
        || form.returns_guard != expected_returns_guard
    {
        return Err(WitnessPlanRefusal::NoTemplateForContractShape);
    }
    Ok((method, form))
}

fn select_alternative_static_method(
    plan: &WitnessPlan,
    adapter: &Adapter,
) -> Result<(String, AdapterRegistrationForm), WitnessPlanRefusal> {
    if plan.shape != HarnessShape::AllocationFreedByWrapper {
        return Err(WitnessPlanRefusal::NoTemplateForContractShape);
    }
    let used = method_from_instance(&plan.hand_off.safe_entry_instance)
        .ok_or(WitnessPlanRefusal::NoTemplateForContractShape)?;
    let mut alternatives = adapter
        .registration_forms
        .iter()
        .filter(|form| form.form == Adapter::expected_form(plan.shape))
        .flat_map(|form| {
            form.methods
                .iter()
                .filter(|name| name.as_str() != used)
                .map(move |name| (name.clone(), form.clone()))
        })
        .collect::<Vec<_>>();
    alternatives.sort_by(|left, right| left.0.cmp(&right.0));
    alternatives
        .into_iter()
        .next()
        .ok_or(WitnessPlanRefusal::NoTemplateForContractShape)
}

/// `Registry::register_guarded::<F>` → `register_guarded`。
///
/// 从右向左找第一个以标识符字符开头的段：泛型参数段（`<F>`）与 turbofish 留下的
/// 空段都被跳过，因此 `path::method::<T>` 与 `path::method` 都能解析。
fn method_from_instance(instance: &str) -> Option<String> {
    for segment in instance.rsplit("::").map(str::trim) {
        let Some(first) = segment.chars().next() else {
            continue;
        };
        if !(first.is_ascii_alphabetic() || first == '_') {
            continue;
        }
        let name: String = segment
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
    }
    None
}

/// 从公开签名形状读出闭包参数列表，**带显式类型标注**。
///
/// 只按顶层逗号切：`FnMut()` → `[]`，
/// `FnMut(rusqlite::hooks::Action, &str, &str, i64)` →
/// `["_p0: rusqlite::hooks::Action", "_p1: &str", ...]`。
///
/// 类型必须写出来，不能靠推断：带环境捕获的闭包交给高阶 fn trait 边界时，
/// 推断出的 impl 会落「implementation of `FnMut` is not general enough」
/// （nightly trait solver 对捕获 + 高阶生命周期的已知形状）；显式标注让闭包
/// 签名确定，实测可编译并触发。类型文本只是公开签名的转写，不是行为语义。
/// 参数带下划线前缀：闭包体只解引用捕获的 subject，形参本身允许未使用。
pub(crate) fn closure_params(callback_signature: &str) -> Vec<String> {
    let Some(open) = callback_signature.find('(') else {
        return Vec::new();
    };
    let Some(close) = callback_signature[open..].rfind(')') else {
        return Vec::new();
    };
    let inner = &callback_signature[open + 1..open + close];
    if inner.trim().is_empty() {
        return Vec::new();
    }
    // 顶层逗号分割：尖括号与嵌套括号里的逗号不算。
    let mut params = Vec::<String>::new();
    let mut depth = 0usize;
    let mut current = String::new();
    for ch in inner.chars() {
        match ch {
            '<' | '(' | '[' => {
                depth += 1;
                current.push(ch);
            }
            '>' | ')' | ']' => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if depth == 0 => {
                params.push(param_name(&params, &current));
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        params.push(param_name(&params, &current));
    }
    params
}

/// `_p0: <type>` 形式；类型取签名原文的 trim。
fn param_name(existing: &[String], type_text: &str) -> String {
    format!("_p{}: {}", existing.len(), type_text.trim())
}

/// 公开签名是否声明了返回类型（如 `FnMut() -> bool`）。
///
/// 声明了返回类型的回调，生成的闭包体以 `Default::default()` 收尾——这只是让
/// 闭包满足公开签名的**类型**要求；返回值的具体取值对反证无关（UAF 读取发生在
/// 回调被调用的瞬间，与其返回什么无关）。已知局限：不实现 Default 的返回类型
/// （如部分枚举）会编译失败；那类 API 目前都带 `'static` 界、不产生借用计划。
pub(crate) fn signature_has_return(callback_signature: &str) -> bool {
    let Some(close) = callback_signature.rfind(')') else {
        return false;
    };
    callback_signature[close + 1..]
        .trim_start()
        .starts_with("->")
}

/// 变体生效后的动作序列。控制组只做两种机械改动：删掉触发步，
/// 或者把触发步挪到所有失效动作之前。其余一律原样保留。
fn effective_steps(plan: &WitnessPlan, variant: ClientVariant) -> Vec<DangerStep> {
    match variant {
        ClientVariant::Primary | ClientVariant::OwnedCallback => plan.steps.clone(),
        ClientVariant::NoTrigger => plan
            .steps
            .iter()
            .copied()
            .filter(|step| *step != DangerStep::RequestForeignLateInvoke)
            .collect(),
        ClientVariant::UnregisterBeforeDrop => {
            let mut steps = plan.steps.clone();
            let Some(fire_position) = steps
                .iter()
                .position(|step| *step == DangerStep::RequestForeignLateInvoke)
            else {
                return steps;
            };
            let fire = steps.remove(fire_position);
            // 触发必须早于第一个失效动作（释放 guard 或主体结束），晚于注册。
            let first_invalidating = steps
                .iter()
                .position(|step| {
                    matches!(
                        step,
                        DangerStep::ReleaseRegistrationGuard | DangerStep::EndSubjectLifetime
                    )
                })
                .unwrap_or(fire_position);
            steps.insert(first_invalidating, fire);
            steps
        }
    }
}

fn render_main(
    plan: &WitnessPlan,
    variant: ClientVariant,
    adapter: &Adapter,
    registration: &(String, AdapterRegistrationForm),
    steps: &[DangerStep],
) -> Result<String, WitnessPlanRefusal> {
    let component = adapter.component_ident();
    let method = &registration.0;
    let receiver: String = adapter
        .setup
        .first()
        .map(|setup_step| {
            setup_step
                .rust
                .split('=')
                .next()
                .unwrap_or("registry")
                .trim_start_matches("let ")
                .trim()
                .to_owned()
        })
        .unwrap_or_else(|| "registry".to_owned());
    let trigger_statement = adapter.trigger.rust.replace("registry", &receiver);

    let mut body = String::new();
    let push = |body: &mut String, text: &str| {
        body.push_str("    ");
        body.push_str(text);
        body.push('\n');
    };
    let note_step = |body: &mut String, step: DangerStep, extra: &str| {
        let marker = format!("    // @STEP@ {step:?}");
        body.push_str(&marker);
        if !extra.is_empty() {
            body.push_str(&format!(" ({extra})"));
        }
        body.push('\n');
    };

    // setup 行（构造接收者）不属于任何 plan 步骤，是合法使用的前置条件。
    for setup_step in &adapter.setup {
        push(&mut body, &setup_step.rust);
    }

    let guarded = plan.shape == HarnessShape::GuardDefeatedBypass;
    let allocation_shape = plan.shape == HarnessShape::AllocationFreedByWrapper;
    let params = closure_params(&registration.1.callback_signature);
    let param_list = params.join(", ");
    // 公开签名带返回类型时（FnMut() -> bool 等），闭包体补 Default::default()
    // 以满足类型；返回值取值对反证无关。
    let callback_body = if signature_has_return(&registration.1.callback_signature) {
        "std::hint::black_box(*payload); Default::default()"
    } else {
        "std::hint::black_box(*payload);"
    };
    // Option<F> 形状的注册入口（rusqlite）：回调表达式包一层 Some。
    let wrap_option = |expression: &str| -> String {
        if registration.1.wraps_callback_in_option {
            format!("Some({expression})")
        } else {
            expression.to_owned()
        }
    };

    for step in steps {
        match step {
            DangerStep::CreateHeapSubject => {
                note_step(&mut body, *step, "");
                push(&mut body, "let payload: Box<u64> = Box::new(7);");
            }
            DangerStep::CreateOwnedCallbackState => {
                note_step(&mut body, *step, "");
                push(&mut body, "let owned_state: Box<u64> = Box::new(84);");
            }
            DangerStep::ConstructCapturingCallback => {
                note_step(&mut body, *step, "");
                push(
                    &mut body,
                    // 必须是**解引用加载**而不是传递引用：black_box(&*payload)
                    // 只把指针值交给不透明函数，已释放的堆块从未被读——oracle
                    // 看不到任何访问。*payload 才是对失效内存的真实读取。
                    &format!("let callback = |{param_list}| {{ {callback_body} }};"),
                );
            }
            DangerStep::RegisterThroughSafeApi => {
                note_step(
                    &mut body,
                    *step,
                    if allocation_shape {
                        "闭包自己拥有状态；分配是否被组件回收由组件实现回答"
                    } else {
                        ""
                    },
                );
                if allocation_shape {
                    push(
                        &mut body,
                        &format!(
                            // 同上：加载闭包环境里的状态，而不是传引用。
                            "{receiver}.{method}({});",
                            wrap_option(&format!(
                                "move |{param_list}| {{ std::hint::black_box(*owned_state); }}"
                            ))
                        ),
                    );
                } else if guarded || variant == ClientVariant::UnregisterBeforeDrop {
                    push(
                        &mut body,
                        &format!(
                            "let guard = {receiver}.{method}({});",
                            wrap_option("callback")
                        ),
                    );
                } else {
                    push(
                        &mut body,
                        &format!("{receiver}.{method}({});", wrap_option("callback")),
                    );
                }
            }
            DangerStep::RetainRegistrationBeyondSubject => {
                note_step(&mut body, *step, "");
            }
            DangerStep::ReleaseRegistrationGuard => {
                note_step(&mut body, *step, "请求注销；是否真清槽由外部决定");
                push(&mut body, "drop(guard);");
            }
            DangerStep::EndSubjectLifetime => {
                note_step(&mut body, *step, "");
                if allocation_shape {
                    // 分配的提前回收发生在组件内部，不是客户端的一个动作；
                    // 这一步只留标注。
                } else {
                    push(&mut body, "drop(payload);");
                }
            }
            DangerStep::RequestForeignLateInvoke => {
                note_step(&mut body, *step, "");
                push(&mut body, &trigger_statement);
            }
            DangerStep::CallbackAccessesInvalidatedSubject => {
                note_step(&mut body, *step, "发生在外部发起的调用内部");
            }
        }
    }

    // adapter 的 setup/trigger 片段若已用全路径（`component::Registry`），
    // 再发 `use` 只会得到未使用导入警告；只有片段引用裸 `Registry` 时才需要。
    let snippets_use_full_path = adapter
        .setup
        .iter()
        .chain(adapter.teardown.iter())
        .map(|step| &step.rust)
        .chain(std::iter::once(&adapter.trigger.rust))
        .any(|text| text.contains(&format!("{component}::")));
    let import_line = if snippets_use_full_path {
        String::new()
    } else {
        format!("use {component}::Registry;\n\n")
    };

    let header = format!(
        "#![forbid(unsafe_code)]\n\
         //! BoundaryWitness 生成的反证客户端（{variant_token}）。\n\
         //!\n\
         //! plan: {plan_id}\n\
         //! 判定指纹: {digest}\n\
         //! 输入类别: {input_kind:?} / 形状: {shape:?}\n\
         //!\n\
         //! 每条 @STEP@ 标注对应上游判定推导的一个动作。本文件不含 unsafe；\n\
         //! 外部组件的晚调经它自己的安全入口请求，UB 只能来自组件自身的抽象破洞。\n\n\
         {import_line}\
         fn main() {{\n",
        variant_token = variant.token(),
        plan_id = plan.plan_id,
        digest = plan.verdict_digest,
        input_kind = plan.input_kind,
        shape = plan.shape,
    );
    Ok(format!("{header}{body}}}\n"))
}

const BUILD_RS: &str = r##"use std::{env, process::Command};

fn main() {
    let source = env::var("BW_FOREIGN_SOURCE")
        .expect("BW_FOREIGN_SOURCE 必须指向外部实现的 C 源文件");
    println!("cargo:rerun-if-env-changed=BW_FOREIGN_SOURCE");
    println!("cargo:rerun-if-changed={source}");
    println!("cargo:rerun-if-env-changed=BW_REAL_CC");

    let out_dir = env::var("OUT_DIR").expect("cargo 提供 OUT_DIR");
    let object = format!("{out_dir}/bwforeign.o");
    let archive = format!("{out_dir}/libbwforeign.a");

    let cc = env::var("BW_REAL_CC")
        .or_else(|_| env::var("CC"))
        .unwrap_or_else(|_| "clang".to_owned());
    run(Command::new(&cc).args(["-O0", "-g", "-c", &source, "-o", &object]));

    let ar = env::var("AR").unwrap_or_else(|_| "ar".to_owned());
    run(Command::new(&ar).args(["rcs", &archive, &object]));

    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=static=bwforeign");
}

fn run(command: &mut Command) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("无法执行 {command:?}: {error}"));
    assert!(status.success(), "{command:?} 以 {status} 失败");
}
"##;

fn render_cargo_toml(
    package_name: &str,
    component: &str,
    component_path: &str,
    adapter: &Adapter,
) -> String {
    let edition = adapter
        .target
        .edition
        .clone()
        .unwrap_or_else(|| "2024".to_owned());
    // 路径用 TOML 字面量字符串（单引号，无转义语义）；TOML 没有 r#"…"# 原始串。
    debug_assert!(!component_path.contains('\''));
    let features = match adapter.target.features.as_deref() {
        None | Some([]) => String::new(),
        Some(names) => {
            let list = names
                .iter()
                .map(|name| format!("'{name}'"))
                .collect::<Vec<_>>()
                .join(",");
            format!(", features = [{list}]")
        }
    };
    format!(
        "[package]\n\
         name = \"{package_name}\"\n\
         version = \"0.0.0\"\n\
         edition = \"{edition}\"\n\
         publish = false\n\
         \n\
         [workspace]\n\
         \n\
         [dependencies]\n\
         {component} = {{ path = '{component_path}'{features} }}\n\
         \n\
         [[bin]]\n\
         name = \"witness\"\n\
         path = \"src/main.rs\"\n"
    )
}

/// 从生成物里回读 @STEP@ 标注，供覆盖断言与测试使用。
pub(crate) fn annotated_steps(main_rs: &str) -> Vec<String> {
    main_rs
        .lines()
        .filter_map(|line| {
            let index = line.find("// @STEP@ ")?;
            let rest = &line[index + "// @STEP@ ".len()..];
            // 标注后面可以带给人读的括号说明；Debug 名本身不含空格。
            let end = rest.find(" (").unwrap_or(rest.len());
            Some(rest[..end].trim().to_owned())
        })
        .collect()
}

/// 计算外部构建源文件的绝对路径（repo_root 相对）。
pub(crate) fn resolve_foreign_source(repo_root: &Path, source: &str) -> PathBuf {
    if source.starts_with('/') {
        PathBuf::from(source)
    } else {
        repo_root.join(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bw_model::RegistrationGeneration;
    use std::fs;

    const MINIMAL_ADAPTER: &str = r#"
schema_version = "bw.adapter/0.1"
adapter_id = "adapter:test"

[target]
crate = "test-component"
version = "0.1.0"
path_from_repo_root = "component"
edition = "2024"

[[setup]]
step = "construct_registry"
rust = "let registry = test_component::Registry;"

[[registration_forms]]
form = "non_static_capture"
methods = ["register_borrowed"]
callback_signature = "FnMut()"
returns_guard = false

[[registration_forms]]
form = "receiver_tied_capture"
methods = ["register_guarded"]
callback_signature = "FnMut() + 'reg"
returns_guard = true

[[registration_forms]]
form = "static_capture"
methods = ["register_static_then_free", "register_static_owned"]
callback_signature = "FnMut() + 'static"
returns_guard = false

[trigger]
step = "request_stored_callback"
rust = "registry.fire();"
foreign_symbol = "fixture_fire"
requires_component_trigger = true

[[foreign_build]]
id = "stub-a"
source = "foreign/a.c"

[[foreign_build]]
id = "stub-sync"
source = "foreign/sync.c"
provides_trigger_symbol = false

[teardown]
step = "drop_registry"
rust = "drop(registry);"
"#;

    fn rust_key(method: &str) -> bw_model::RustHandOffKey {
        bw_model::RustHandOffKey {
            rust_artifact: "rust:test".to_owned(),
            build_profile: "test/dev".to_owned(),
            safe_entry_instance: format!("Registry::{method}"),
            rust_def_instance: format!("Registry::{method}::<F>"),
            call_occurrence: "site:test".to_owned(),
            foreign_symbol: "fixture_register".to_owned(),
            callback_arg_index: 0,
            userdata_arg_index: Some(1),
            registration_key: None,
            registration_generation: RegistrationGeneration::UniqueStaticSite,
        }
    }

    /// 直接构造一个计划（判定的推导由模型层测试钉住；这里只测生成引擎）。
    fn plan_for(method: &str, shape: HarnessShape) -> WitnessPlan {
        let key = rust_key(method);
        WitnessPlan {
            plan_id: format!("witness_Registry__{method}_subject_deadbeef"),
            api_id: format!("Registry::{method}"),
            hand_off: bw_model::HandOffId {
                rust_artifact: key.rust_artifact.clone(),
                foreign_artifact: "foreign:stub-a".to_owned(),
                build_profile: key.build_profile.clone(),
                safe_entry_instance: key.safe_entry_instance.clone(),
                rust_def_instance: key.rust_def_instance.clone(),
                call_occurrence: key.call_occurrence.clone(),
                foreign_symbol: key.foreign_symbol.clone(),
                callback_arg_index: key.callback_arg_index,
                userdata_arg_index: key.userdata_arg_index,
                registration_key: key.registration_key.clone(),
                registration_generation: key.registration_generation,
            },
            subject: bw_model::LifetimeSubject::CapturedReferent,
            input_kind: bw_model::WitnessInputKind::EstablishLateInvoke,
            shape,
            steps: match shape {
                HarnessShape::BorrowedCaptureEscapingScope => vec![
                    bw_model::DangerStep::CreateHeapSubject,
                    bw_model::DangerStep::ConstructCapturingCallback,
                    bw_model::DangerStep::RegisterThroughSafeApi,
                    bw_model::DangerStep::RetainRegistrationBeyondSubject,
                    bw_model::DangerStep::EndSubjectLifetime,
                    bw_model::DangerStep::RequestForeignLateInvoke,
                    bw_model::DangerStep::CallbackAccessesInvalidatedSubject,
                ],
                HarnessShape::GuardDefeatedBypass => vec![
                    bw_model::DangerStep::CreateHeapSubject,
                    bw_model::DangerStep::ConstructCapturingCallback,
                    bw_model::DangerStep::RegisterThroughSafeApi,
                    bw_model::DangerStep::RetainRegistrationBeyondSubject,
                    bw_model::DangerStep::ReleaseRegistrationGuard,
                    bw_model::DangerStep::EndSubjectLifetime,
                    bw_model::DangerStep::RequestForeignLateInvoke,
                    bw_model::DangerStep::CallbackAccessesInvalidatedSubject,
                ],
                HarnessShape::AllocationFreedByWrapper => vec![
                    bw_model::DangerStep::CreateOwnedCallbackState,
                    bw_model::DangerStep::RegisterThroughSafeApi,
                    bw_model::DangerStep::RetainRegistrationBeyondSubject,
                    bw_model::DangerStep::RequestForeignLateInvoke,
                    bw_model::DangerStep::CallbackAccessesInvalidatedSubject,
                ],
            },
            expected_evidence_class: bw_model::ExpectedEvidenceClass::HeapUseAfterFree,
            verdict_digest: "deadbeef".repeat(8),
            assumptions: Vec::new(),
        }
    }

    fn adapter() -> Adapter {
        Adapter::parse(MINIMAL_ADAPTER).expect("minimal adapter should parse")
    }

    fn repo_with_component(dir: &std::path::Path) -> std::path::PathBuf {
        let root = dir.join("repo");
        fs::create_dir_all(root.join("component")).unwrap();
        fs::write(
            root.join("component").join("Cargo.toml"),
            "[package]\nname = \"test-component\"\n",
        )
        .unwrap();
        root
    }

    #[test]
    fn method_is_extracted_from_the_safe_entry_instance_tail() {
        assert_eq!(
            method_from_instance("Registry::register_guarded::<F>").as_deref(),
            Some("register_guarded")
        );
        assert_eq!(
            method_from_instance("Registry::register_borrowed").as_deref(),
            Some("register_borrowed")
        );
        // 全是泛型/空段：没有方法名可取。
        assert_eq!(method_from_instance("<F>"), None);
        assert_eq!(method_from_instance(""), None);
    }

    #[test]
    fn no_trigger_variant_deletes_only_the_invoke_step() {
        let steps = effective_steps(
            &plan_for(
                "register_borrowed",
                HarnessShape::BorrowedCaptureEscapingScope,
            ),
            ClientVariant::NoTrigger,
        );
        assert!(!steps.contains(&bw_model::DangerStep::RequestForeignLateInvoke));
        assert_eq!(steps.len(), 6);
    }

    #[test]
    fn unregister_first_moves_fire_before_any_invalidating_step() {
        let steps = effective_steps(
            &plan_for("register_guarded", HarnessShape::GuardDefeatedBypass),
            ClientVariant::UnregisterBeforeDrop,
        );
        let fire = steps
            .iter()
            .position(|s| *s == bw_model::DangerStep::RequestForeignLateInvoke)
            .expect("fire stays in the sequence");
        assert!(
            steps[fire + 1..].iter().any(|s| matches!(
                s,
                bw_model::DangerStep::ReleaseRegistrationGuard
                    | bw_model::DangerStep::EndSubjectLifetime
            )),
            "fire 必须早于第一个失效动作"
        );
    }

    #[test]
    fn closure_params_counts_top_level_commas_only() {
        assert!(closure_params("FnMut()").is_empty());
        assert_eq!(
            closure_params("FnMut(rusqlite::hooks::Action, &str, &str, i64)"),
            vec![
                "_p0: rusqlite::hooks::Action",
                "_p1: &str",
                "_p2: &str",
                "_p3: i64"
            ]
        );
        // 泛型里的逗号不是分隔符。
        assert_eq!(
            closure_params("FnMut(Result<u8, ()>, &str)"),
            vec!["_p0: Result<u8, ()>", "_p1: &str"]
        );
        // 没有括号：零参数，不猜。
        assert!(closure_params("FnMut").is_empty());
    }

    #[test]
    fn return_type_detection_follows_the_public_signature() {
        assert!(!signature_has_return("FnMut()"));
        assert!(signature_has_return("FnMut() -> bool"));
        assert!(signature_has_return("FnMut(rusqlite::hooks::Action, &str, &str, i64)").eq(&false));
    }

    /// 带返回类型的回调（rusqlite commit_hook：FnMut() -> bool）：闭包体补
    /// Default::default() 满足公开签名，解引用加载不变。
    #[test]
    fn returning_callback_closures_satisfy_the_declared_return_type() {
        let mut adapter = adapter();
        adapter.registration_forms[0].callback_signature = "FnMut() -> bool".to_owned();
        adapter.registration_forms[0].wraps_callback_in_option = true;
        let dir = tempfile::tempdir().unwrap();
        let root = repo_with_component(dir.path());

        let client = generate_client(
            &plan_for(
                "register_borrowed",
                HarnessShape::BorrowedCaptureEscapingScope,
            ),
            ClientVariant::Primary,
            &adapter,
            &root,
        )
        .unwrap();

        assert!(
            client.main_rs.contains(
                "let callback = || { std::hint::black_box(*payload); Default::default() };"
            ),
            "零参 + 返回 bool 的闭包形状"
        );
        assert!(
            client
                .main_rs
                .contains(".register_borrowed(Some(callback));")
        );
    }

    /// 真实组件场景（rusqlite）：四参数回调闭包、组件 feature、Option 包裹、
    /// 以及组件自带外部库时不得再写 build.rs。
    #[test]
    fn component_provided_foreign_lib_omits_build_rs_and_types_the_closure() {
        let mut adapter = adapter();
        adapter.target.features = Some(vec!["bundled".to_owned(), "hooks".to_owned()]);
        adapter.target.links_foreign_directly = false;
        adapter.registration_forms[0].callback_signature =
            "FnMut(rusqlite::hooks::Action, &str, &str, i64)".to_owned();
        adapter.registration_forms[0].wraps_callback_in_option = true;
        let dir = tempfile::tempdir().unwrap();
        let root = repo_with_component(dir.path());

        let client = generate_client(
            &plan_for(
                "register_borrowed",
                HarnessShape::BorrowedCaptureEscapingScope,
            ),
            ClientVariant::Primary,
            &adapter,
            &root,
        )
        .unwrap();

        assert!(client.build_rs.is_empty(), "组件自带外部库时不带 build.rs");
        assert!(client.cargo_toml.contains("features = ['bundled','hooks']"));
        assert!(
            client
                .main_rs
                .contains("|_p0: rusqlite::hooks::Action, _p1: &str, _p2: &str, _p3: i64|"),
            "闭包必须与公开签名同元数且显式标注参数类型"
        );
        assert!(
            client
                .main_rs
                .contains(".register_borrowed(Some(callback));"),
            "Option<F> 形状的注册入口要包 Some"
        );
        // 解引用加载不变：oracle 仍然看得到对失效内存的真实读取。
        assert!(client.main_rs.contains("black_box(*payload)"));
    }

    #[test]
    fn generated_client_covers_every_plan_step_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo_with_component(dir.path());
        let adapter = adapter();
        for (method, shape) in [
            (
                "register_borrowed",
                HarnessShape::BorrowedCaptureEscapingScope,
            ),
            ("register_guarded", HarnessShape::GuardDefeatedBypass),
            (
                "register_static_then_free",
                HarnessShape::AllocationFreedByWrapper,
            ),
        ] {
            let plan = plan_for(method, shape);
            let client = generate_client(&plan, ClientVariant::Primary, &adapter, &root)
                .unwrap_or_else(|e| panic!("{method}: {e:?}"));
            assert!(client.main_rs.starts_with("#![forbid(unsafe_code)]"));
            assert_eq!(annotated_steps(&client.main_rs).len(), plan.steps.len());
            // borrow/allocation 形状必须包含真实的解引用加载；传引用读不到已释放内存。
            if method == "register_borrowed" {
                assert!(client.main_rs.contains("black_box(*payload)"));
            }
            if method == "register_static_then_free" {
                assert!(client.main_rs.contains("black_box(*owned_state)"));
                assert!(client.main_rs.contains("move || {"));
            }
            // primary 一定带触发步。
            assert!(client.main_rs.contains(".fire();"));
        }
    }

    #[test]
    fn no_trigger_client_omits_the_fire_statement_entirely() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo_with_component(dir.path());
        let client = generate_client(
            &plan_for(
                "register_borrowed",
                HarnessShape::BorrowedCaptureEscapingScope,
            ),
            ClientVariant::NoTrigger,
            &adapter(),
            &root,
        )
        .unwrap();
        assert!(!client.main_rs.contains(".fire();"));
        assert_eq!(annotated_steps(&client.main_rs).len(), 6);
    }

    #[test]
    fn exportable_variants_are_shape_gated() {
        let adapter = adapter();
        let borrowed = exportable_variants(
            &plan_for(
                "register_borrowed",
                HarnessShape::BorrowedCaptureEscapingScope,
            ),
            &adapter,
        );
        assert_eq!(
            borrowed,
            vec![ClientVariant::Primary, ClientVariant::NoTrigger]
        );

        let guarded = exportable_variants(
            &plan_for("register_guarded", HarnessShape::GuardDefeatedBypass),
            &adapter,
        );
        assert!(guarded.contains(&ClientVariant::UnregisterBeforeDrop));

        let allocation = exportable_variants(
            &plan_for(
                "register_static_then_free",
                HarnessShape::AllocationFreedByWrapper,
            ),
            &adapter,
        );
        assert!(allocation.contains(&ClientVariant::OwnedCallback));
    }

    #[test]
    fn owned_callback_requires_a_second_method_in_the_same_form() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo_with_component(dir.path());
        // register_static_owned 与 register_static_then_free 同表单，可作替代。
        let client = generate_client(
            &plan_for(
                "register_static_then_free",
                HarnessShape::AllocationFreedByWrapper,
            ),
            ClientVariant::OwnedCallback,
            &adapter(),
            &root,
        )
        .unwrap();
        assert!(client.main_rs.contains(".register_static_owned(move || {"));

        // 只有一个方法的表单没有替代品：owned_callback 被拒绝而不是硬造。
        let mut single = adapter();
        single.registration_forms[2].methods = vec!["register_static_then_free".to_owned()];
        let refusal = generate_client(
            &plan_for(
                "register_static_then_free",
                HarnessShape::AllocationFreedByWrapper,
            ),
            ClientVariant::OwnedCallback,
            &single,
            &root,
        )
        .unwrap_err();
        assert_eq!(refusal.token(), "no_template_for_contract_shape");
    }

    #[test]
    fn shape_and_form_mismatch_is_refused_not_patched() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo_with_component(dir.path());
        // plan 说 guard-defeated，方法却是无 guard 的 register_borrowed。
        let mismatch = plan_for("register_borrowed", HarnessShape::GuardDefeatedBypass);
        let error =
            generate_client(&mismatch, ClientVariant::Primary, &adapter(), &root).unwrap_err();
        assert_eq!(error.token(), "no_template_for_contract_shape");
    }

    #[test]
    fn adapter_parse_rejects_wrong_schema_and_unknown_fields() {
        let wrong_schema = MINIMAL_ADAPTER.replace("bw.adapter/0.1", "bw.adapter/9.9");
        assert!(Adapter::parse(&wrong_schema).is_err());

        let unknown_field =
            MINIMAL_ADAPTER.replacen("[trigger]", "[trigger]\nbehavior = \"retains\"", 1);
        assert!(Adapter::parse(&unknown_field).is_err());
    }

    /// 非空检查：把形状门的一半拆掉（表单类改名），预期所有生成都被拒。
    #[test]
    fn removing_form_classes_refuses_instead_of_emitting_garbage() {
        let mut broken = adapter();
        broken.registration_forms.clear();
        let dir = tempfile::tempdir().unwrap();
        let root = repo_with_component(dir.path());
        let result = generate_client(
            &plan_for(
                "register_borrowed",
                HarnessShape::BorrowedCaptureEscapingScope,
            ),
            ClientVariant::Primary,
            &broken,
            &root,
        );
        assert_eq!(
            result.unwrap_err().token(),
            "no_template_for_contract_shape"
        );
    }
}
