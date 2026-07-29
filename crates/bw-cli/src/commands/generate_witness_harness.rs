//! 从已绑定的 witness plan 生成本地受控 harness 源码。
//!
//! 生成器只覆盖它有模板的形状。覆盖不到时必须记录拒绝原因，不得回退到通用模板：
//! 一个编不过或语义不对的 harness 比没有 harness 更糟，它会把"没能验证"伪装成
//! "验证过没问题"。拒绝原因写进 generation manifest，使覆盖缺口可计数。

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use bw_model::{
    V32PatternFamily, V326WitnessObservedShape, V326WitnessPlanRecord, V326WitnessTarget,
};
use clap::Args;
use serde::Serialize;

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl, write_json_stdout},
    exit::{CliError, CommandStatus},
};

const RUSQLITE_CRATE_NAME: &str = "rusqlite";

/// 仓库里 vendored rusqlite 的存放位置。
///
/// 生成的 harness 带 `[patch.crates-io] rusqlite = { path = <vendor> }`，因此**能链接
/// 哪些版本完全由这个目录决定**，不是由一份手写常量决定。两者一旦漂移就会出静默错误：
/// 声明一个 vendor 里没有的版本时 patch 不匹配，cargo 转而去 crates.io 取真包，
/// harness 于是链接了一个未经审阅的 crate，而产物上看不出这件事。
const RUSQLITE_VENDOR_DIR: &str = "benchmarks/historical-cves/rusqlite/vendor";

/// harness 的生命周期模板。
///
/// 每个模板对应 shared crate 里一套受控封装；新增 API 必须同时有封装与模板，
/// 否则只能拒绝。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HarnessTemplate {
    UpdateHook,
    ScalarFunction,
}

impl HarnessTemplate {
    /// 按 api_id 选模板。认不出就是覆盖缺口，不回退到任意模板。
    fn for_api(api_id: &str) -> Option<Self> {
        match api_id {
            "api:rusqlite:update_hook:register"
            | "api:rusqlite:update_hook:unregister"
            | "api:rusqlite:update_hook:replace" => Some(Self::UpdateHook),
            "api:rusqlite:create_scalar_function:register" => Some(Self::ScalarFunction),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::UpdateHook => "update_hook",
            Self::ScalarFunction => "create_scalar_function",
        }
    }
}

/// 目前有模板的注册 API，供 manifest 记录覆盖面。
const SUPPORTED_APIS: [&str; 4] = [
    "api:rusqlite:update_hook:register",
    "api:rusqlite:update_hook:unregister",
    "api:rusqlite:update_hook:replace",
    "api:rusqlite:create_scalar_function:register",
];

#[derive(Args)]
pub struct GenerateWitnessHarnessArgs {
    #[arg(long)]
    plans: PathBuf,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    /// 仓库根目录，用于生成 harness 的 path 依赖。
    #[arg(long = "repo-root", default_value = ".")]
    repo_root: PathBuf,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

#[derive(Debug, Serialize)]
struct GenerateOutput {
    kind: &'static str,
    run_id: String,
    generated_count: u64,
    refused_count: u64,
    output_dir: String,
    manifest_path: String,
}

#[derive(Debug, Serialize)]
struct GeneratedHarness {
    plan_id: String,
    candidate_id: String,
    api_id: String,
    crate_name: String,
    crate_version: String,
    /// harness 链接的 API 提供方，与被扫 crate 是两回事。
    api_crate_name: String,
    api_crate_version: String,
    harness_dir: String,
    main_sha256: String,
    /// 这个 harness 复现的是哪种形状，以及静态侧还有什么没证明。
    ///
    /// 一次动态"确认"的适用范围，取决于它复现了什么、又有什么没被证明。把这些跟结论
    /// 放在一起，读的人才不会把"复现成功"当成"被扫 crate 有缺陷"。
    reproduces: HarnessCoverage,
}

#[derive(Debug, Serialize)]
struct HarnessCoverage {
    template: &'static str,
    pattern_family: String,
    /// 释放是被观察到的；顺序是否已被静态证明见下一个字段。
    release_observed: bool,
    /// false 表示顺序静态侧未定，由这次动态运行判定。
    release_before_callback_use: bool,
    callback_use_after_release: bool,
    still_unproven: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RefusedPlan {
    plan_id: String,
    candidate_id: String,
    reason: &'static str,
    detail: String,
}

/// 生成器为什么放弃某条 plan。这些原因是可计数的覆盖缺口，不是错误。
const REASON_NO_TARGET: &str = "plan_has_no_executable_target";
const REASON_UNSUPPORTED_API: &str = "no_harness_template_for_api";
const REASON_UNSUPPORTED_VERSION: &str = "crate_version_outside_template_support";
/// plan 绑定了 API，但没能确定是哪个 crate 的哪个版本提供的——无法生成能编译的 harness。
const REASON_UNRESOLVED_API_CRATE: &str = "api_crate_version_unresolved";
/// plan 不带静态侧观察到的形状，只能套固定剧本——那样的"确认"没有信息量。
const REASON_NO_OBSERVED_SHAPE: &str = "no_observed_shape_to_reproduce";
/// 观察到的模式家族没有对应的生成器。
const REASON_PATTERN_NOT_REPRODUCIBLE: &str = "pattern_family_not_reproducible";
/// 静态侧没观察到"owner 在 callback 仍注册时释放"，harness 结构上造不出要见证的序列。
const REASON_NO_RELEASE_ORDERING: &str = "no_release_ordering_observed";

pub fn run(args: GenerateWitnessHarnessArgs) -> Result<CommandStatus, CliError> {
    let plans = read_jsonl::<V326WitnessPlanRecord>(&args.plans, args.max_line_bytes)?;
    let plans = plans
        .into_iter()
        .map(|located| located.value)
        .collect::<Vec<_>>();
    let run_id = plans
        .first()
        .map(|plan| plan.run_id.clone())
        .unwrap_or_default();

    let repo_root = args.repo_root.canonicalize().map_err(|error| {
        CliError::input(
            "BW-V326-HARNESS-REPO-ROOT",
            format!("{}: {error}", args.repo_root.display()),
        )
    })?;

    let harness_root = args.output_dir.join("harnesses");
    fs::create_dir_all(&harness_root)?;

    let mut generated = Vec::<GeneratedHarness>::new();
    let mut refused = Vec::<RefusedPlan>::new();

    for plan in &plans {
        let Some(target) = plan.target.as_ref() else {
            refused.push(RefusedPlan {
                plan_id: plan.plan_id.clone(),
                candidate_id: plan.candidate_id.clone(),
                reason: REASON_NO_TARGET,
                detail: "the plan carries no api_id binding".to_owned(),
            });
            continue;
        };
        match generate_one(&harness_root, &repo_root, plan, target) {
            Ok(record) => generated.push(record),
            Err(refusal) => refused.push(refusal),
        }
    }

    let manifest = serde_json::json!({
        "schema_version": "boundary-witness.witness-harness-manifest/0.1",
        "run_id": run_id,
        "generated": generated,
        "refused": refused,
        "supported_apis": SUPPORTED_APIS,
        "supported_crate_versions": vendored_rusqlite_versions(&repo_root),
        "notes": [
            "a generated harness reproduces the lifecycle sequence the static analysis observed for that candidate",
            "reproducing a sequence is not a defect conclusion; read `reproduces.still_unproven` for what the run does not cover",
            "refusals are coverage gaps, not errors",
        ],
    });
    let manifest_path = args.output_dir.join("generation-manifest.json");
    write_json_file(&manifest_path, &manifest)?;

    let output = GenerateOutput {
        kind: "v3-2-6-witness-harness",
        run_id,
        generated_count: generated.len() as u64,
        refused_count: refused.len() as u64,
        output_dir: args.output_dir.display().to_string(),
        manifest_path: manifest_path.display().to_string(),
    };
    write_json_stdout(&output)?;
    Ok(CommandStatus::Success)
}

fn generate_one(
    harness_root: &Path,
    repo_root: &Path,
    plan: &V326WitnessPlanRecord,
    target: &V326WitnessTarget,
) -> Result<GeneratedHarness, RefusedPlan> {
    let refusal = |reason: &'static str, detail: String| RefusedPlan {
        plan_id: plan.plan_id.clone(),
        candidate_id: plan.candidate_id.clone(),
        reason,
        detail,
    };

    let Some(template) = HarnessTemplate::for_api(&target.api_id) else {
        return Err(refusal(
            REASON_UNSUPPORTED_API,
            format!("no template covers {}", target.api_id),
        ));
    };
    // 模板要链接的是**声明该 API 的 crate**，不是被扫 crate。拿被扫 crate 的版本去挑
    // 模板会把 `bw_app 0.1.0` 当成 `rusqlite 0.1.0`——两者几乎总是不同的 crate。
    let Some(api_crate) = &target.api_crate else {
        return Err(refusal(
            REASON_UNRESOLVED_API_CRATE,
            format!(
                "the crate declaring {} was not resolved to a version in {}",
                target.api_id, target.crate_name
            ),
        ));
    };
    if api_crate.name != RUSQLITE_CRATE_NAME {
        return Err(refusal(
            REASON_UNSUPPORTED_VERSION,
            format!("no harness links against {}", api_crate.name),
        ));
    }
    // 能链接哪些版本由 vendor 目录决定。声明一个没 vendored 的版本时 patch 不生效，
    // cargo 会转去 crates.io 取真包——harness 于是链接了未经审阅的代码，且产物上看不出来。
    let vendored = vendored_rusqlite_versions(repo_root);
    if !vendored.contains(&api_crate.version) {
        return Err(refusal(
            REASON_UNSUPPORTED_VERSION,
            format!(
                "{} {} is not vendored; the harness can only link {}",
                api_crate.name,
                api_crate.version,
                if vendored.is_empty() {
                    "nothing".to_owned()
                } else {
                    vendored.iter().cloned().collect::<Vec<_>>().join(", ")
                }
            ),
        ));
    }

    // 没有观察到的形状就只能套固定剧本，那样跑出来的违规是剧本自带的。宁可不生成。
    let Some(shape) = &target.observed_shape else {
        return Err(refusal(
            REASON_NO_OBSERVED_SHAPE,
            "the plan carries no observed lifecycle shape to reproduce".to_owned(),
        ));
    };
    if shape.pattern_family != V32PatternFamily::RetainedBorrowedCallback {
        return Err(refusal(
            REASON_PATTERN_NOT_REPRODUCIBLE,
            format!(
                "no generator reproduces the {:?} lifecycle shape",
                shape.pattern_family
            ),
        ));
    }
    // 门槛是"释放被观察到"，不是"释放顺序被证明"。闭包注册进外部库后调用点不在被扫
    // 函数里，顺序静态侧证不出来——用"已证明"当门槛会恰好拒掉动态见证唯一有意义的
    // 那一类。但完全没观察到释放时仍须拒绝：那样的 harness 结构上不可能违规，跑完的
    // "no findings" 会被读成"验证通过"，是假阴性的最坏形式。
    if !shape.release_observed {
        return Err(refusal(
            REASON_NO_RELEASE_ORDERING,
            "the candidate was never observed releasing the owner while the callback stayed \
             registered, so a harness could not exhibit the sequence it is meant to witness"
                .to_owned(),
        ));
    }

    let harness_name = sanitize_crate_name(&plan.plan_id);
    let harness_dir = harness_root.join(&harness_name);
    let source_dir = harness_dir.join("src");
    fs::create_dir_all(&source_dir).map_err(|error| {
        refusal(
            REASON_UNSUPPORTED_API,
            format!("{}: {error}", source_dir.display()),
        )
    })?;

    let main_source = match template {
        HarnessTemplate::UpdateHook => render_update_hook_main(plan, target, shape),
        HarnessTemplate::ScalarFunction => render_scalar_function_main(plan, target, shape),
    };
    let cargo_toml = render_cargo_toml(&harness_name, repo_root, target);
    fs::write(source_dir.join("main.rs"), &main_source).map_err(|error| {
        refusal(
            REASON_UNSUPPORTED_API,
            format!("{}: {error}", source_dir.display()),
        )
    })?;
    fs::write(harness_dir.join("Cargo.toml"), cargo_toml).map_err(|error| {
        refusal(
            REASON_UNSUPPORTED_API,
            format!("{}: {error}", harness_dir.display()),
        )
    })?;

    // 运行时用 bind_object 建立 capture，而编译器产出的静态事实用另一套 site id。
    // oracle 要求两侧一致，否则以 BW-ORACLE-STATIC-CAPTURE-MISSING 拒绝判定。
    // 这份 bridge 规格记录 harness 实际使用的 site id，供 bridge-witness-facts 合成
    // 对应的 CallbackSite/ObjectSite/CallbackCapture 事实。
    let slug = sanitize_site_slug(&plan.plan_id);
    let bridge = serde_json::json!({
        "schema_version": "boundary-witness.witness-site-bridge/0.1",
        "plan_id": plan.plan_id,
        "candidate_id": plan.candidate_id,
        "callback_site_id": format!("site:{slug}:callback"),
        "object_site_id": format!("site:{slug}:object"),
        "capture_site_id": format!("site:{slug}:capture"),
        "capture_mode": "borrowed",
    });
    write_json_file(&harness_dir.join("site-bridge.json"), &bridge)
        .map_err(|error| refusal(REASON_UNSUPPORTED_API, error.to_string()))?;

    Ok(GeneratedHarness {
        plan_id: plan.plan_id.clone(),
        candidate_id: plan.candidate_id.clone(),
        api_id: target.api_id.clone(),
        crate_name: target.crate_name.clone(),
        crate_version: target.crate_version.clone(),
        api_crate_name: api_crate.name.clone(),
        api_crate_version: api_crate.version.clone(),
        harness_dir: harness_dir.display().to_string(),
        main_sha256: sha256_hex(main_source.as_bytes()),
        reproduces: HarnessCoverage {
            template: template.as_str(),
            pattern_family: format!("{:?}", shape.pattern_family),
            release_observed: shape.release_observed,
            release_before_callback_use: shape.release_before_callback_use,
            callback_use_after_release: shape.callback_use_after_release,
            still_unproven: shape.unproven.clone(),
        },
    })
}

/// 按观察到的形状生成 `create_scalar_function` 生命周期 harness。
///
/// 与 update_hook 模板同构，区别只在注册的外部 API：标量函数注册在连接上按
/// (name, n_arg) 建键，回调由 SQL 求值触发而不是由写操作触发。
fn render_scalar_function_main(
    plan: &V326WitnessPlanRecord,
    target: &V326WitnessTarget,
    shape: &V326WitnessObservedShape,
) -> String {
    let plan_id = &plan.plan_id;
    let candidate_id = &plan.candidate_id;
    let api_id = &target.api_id;
    let pattern_family = format!("{:?}", shape.pattern_family);
    let callback_object_use = if shape.callback_use_after_release {
        r#"callback_runtime.emit_deferred(RuntimeEvent::ObjectUse(ObjectUseEvent {
                instance_id: callback_counter_id.clone(),
                use_site_id: callback_counter_site.clone(),
                use_kind: ObjectUseKind::Read,
            }));
            callback_counter.record(1);"#
    } else {
        r#"// 静态侧未观察到"释放后仍使用"，harness 不得替它制造这一步。
            let _ = (&callback_counter_id, &callback_counter_site, &callback_counter);"#
    };
    format!(
        r#"// Generated by `bw generate-witness-harness`. Do not edit by hand.
//
// plan:      {plan_id}
// candidate: {candidate_id}
// api:       {api_id}
// shape:     {pattern_family}
//
// The sequence below is derived from what the static analysis observed for this
// candidate, not from a fixed script: the owner is dropped here only because the
// candidate was observed to release it while the callback was still registered.
//
// The harness replays that sequence and emits a runtime trace. It asserts nothing:
// the oracle decides whether the sequence violates the contract. Reproducing a
// sequence is not a defect conclusion about the scanned crate.
use bw_model::{{CheckpointKind, ObjectUseEvent, ObjectUseKind, RuntimeEvent, SiteId}};
use bw_runtime::Tracked;
use rusqlite::{{functions::FunctionFlags, Connection}};
use rusqlite_lab_shared::{{
    runtime::{{benchmark_build_id, benchmark_runtime}},
    scalar_function::ScalarFunctionConnection,
    BorrowedCounter,
}};

fn main() -> Result<(), Box<dyn std::error::Error>> {{
    let runtime = benchmark_runtime("run:{plan_slug}", "trace:{plan_slug}")?;
    runtime.emit_trace_start(benchmark_build_id("build:{plan_slug}"))?;

    let connection = Connection::open_in_memory()?;

    let observed = ScalarFunctionConnection::open(runtime.clone(), site("site:{plan_slug}:connection"))?;
    let counter_site = site("site:{plan_slug}:object");
    let counter = Tracked::new(runtime.clone(), counter_site.clone(), BorrowedCounter::new());
    let token = observed.register("bw_witness", 0, site("site:{plan_slug}:callback"))?;
    // bind_object 的第二个参数是对象自身的 site id，不是 capture 事实的 site id。
    token.bind_object(counter.id(), &counter_site)?;
    runtime.emit_checkpoint(CheckpointKind::Registered)?;

    let callback_token = token.clone();
    let callback_runtime = runtime.clone();
    let callback_counter_id = counter.id().clone();
    let callback_counter_site = counter_site.clone();
    let callback_counter = counter.get();
    connection.create_scalar_function(
        "bw_witness",
        0,
        FunctionFlags::SQLITE_UTF8,
        move |_context| {{
            let _ = callback_token.invoke(site("site:{plan_slug}:invoke"));
            {callback_object_use}
            Ok(1_i64)
        }},
    )?;

    // 静态侧观察到 owner 在 callback 仍被外部持有时释放，这里复现那一步。
    drop(counter);
    runtime.emit_checkpoint(CheckpointKind::LaterCallbackPhase)?;
    let _: i64 = connection.query_row("SELECT bw_witness()", [], |row| row.get(0))?;
    observed.close(site("site:{plan_slug}:connection-drop"))?;
    runtime.emit_trace_end()?;
    runtime.finish()?;
    Ok(())
}}

fn site(value: &'static str) -> SiteId {{
    SiteId::from(value)
}}
"#,
        plan_id = plan_id,
        candidate_id = candidate_id,
        api_id = api_id,
        pattern_family = pattern_family,
        callback_object_use = callback_object_use,
        plan_slug = sanitize_site_slug(plan_id),
    )
}

/// 仓库里实际 vendored 的 rusqlite 版本。
///
/// 从目录名 `rusqlite-<version>` 读，而不是维护一份常量：常量与磁盘漂移时的失败是
/// 静默的（patch 落空 → cargo 去 crates.io 取真包），排查成本远高于多一次目录读取。
fn vendored_rusqlite_versions(repo_root: &Path) -> BTreeSet<String> {
    let Ok(entries) = fs::read_dir(repo_root.join(RUSQLITE_VENDOR_DIR)) else {
        return BTreeSet::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix("rusqlite-"))
                .map(ToOwned::to_owned)
        })
        .collect()
}

/// crate 名只允许 `[a-z0-9_]`，plan id 里的 `:`/`-` 需要折叠。
fn sanitize_crate_name(plan_id: &str) -> String {
    let mut name = String::with_capacity(plan_id.len() + 8);
    name.push_str("bw_witness_");
    for character in plan_id.chars() {
        if character.is_ascii_alphanumeric() {
            name.push(character.to_ascii_lowercase());
        } else {
            name.push('_');
        }
    }
    name
}

fn render_cargo_toml(harness_name: &str, repo_root: &Path, target: &V326WitnessTarget) -> String {
    let root = repo_root.display();
    format!(
        r#"# Generated by `bw generate-witness-harness`. Do not edit by hand.
#
# The pinned version is the API-declaring crate's version as resolved in the
# scanned crate, not the scanned crate's own version. The harness links against
# rusqlite-lab-shared, which pins rusqlite through a vendored patch.
[package]
name = "{harness_name}"
version = "0.1.0"
edition = "2021"
publish = false

[workspace]

[[bin]]
name = "{harness_name}"
path = "src/main.rs"

[dependencies]
bw-model = {{ path = "{root}/crates/bw-model" }}
bw-runtime = {{ path = "{root}/crates/bw-runtime" }}
rusqlite-lab-shared = {{ path = "{root}/benchmarks/historical-cves/rusqlite/shared" }}
rusqlite = {{ version = "={version}", features = ["bundled", "functions", "hooks"] }}

[patch.crates-io]
rusqlite = {{ path = "{root}/benchmarks/historical-cves/rusqlite/vendor/rusqlite-0.26.1" }}
"#,
        harness_name = harness_name,
        root = root,
        version = target
            .api_crate
            .as_ref()
            .map(|api_crate| api_crate.version.as_str())
            .unwrap_or_default(),
    )
}

/// 按**静态侧观察到的形状**生成 update_hook 生命周期 harness。
///
/// 序列不是写死的剧本：`drop(owner)` 只有在候选确实被观察到"owner 在 callback 仍注册
/// 期间释放"时才生成，callback 里对该对象的使用同理。固定剧本无条件制造这两步，跑出
/// 的违规是剧本自带的，与被扫 crate 无关。
///
/// harness 只重放序列并产出 runtime trace，判定由 oracle 做；重放成功本身不是结论。
fn render_update_hook_main(
    plan: &V326WitnessPlanRecord,
    target: &V326WitnessTarget,
    shape: &V326WitnessObservedShape,
) -> String {
    let plan_id = &plan.plan_id;
    let candidate_id = &plan.candidate_id;
    let api_id = &target.api_id;
    let pattern_family = format!("{:?}", shape.pattern_family);
    // callback 是否触碰该对象，取决于静态侧是否观察到释放后仍被使用。
    let callback_object_use = if shape.callback_use_after_release {
        r#"callback_runtime.emit_deferred(RuntimeEvent::ObjectUse(ObjectUseEvent {
                instance_id: callback_counter_id.clone(),
                use_site_id: callback_counter_site.clone(),
                use_kind: ObjectUseKind::Read,
            }));
            callback_counter.record(rowid);"#
    } else {
        r#"// 静态侧未观察到"释放后仍使用"，harness 不得替它制造这一步。
            let _ = (&callback_counter_id, &callback_counter_site, &callback_counter, rowid);"#
    };
    format!(
        r#"// Generated by `bw generate-witness-harness`. Do not edit by hand.
//
// plan:      {plan_id}
// candidate: {candidate_id}
// api:       {api_id}
// shape:     {pattern_family}
//
// The sequence below is derived from what the static analysis observed for this
// candidate, not from a fixed script: the owner is dropped here only because the
// candidate was observed to release it while the callback was still registered.
//
// The harness replays that sequence and emits a runtime trace. It asserts nothing:
// the oracle decides whether the sequence violates the contract. Reproducing a
// sequence is not a defect conclusion about the scanned crate.
use std::sync::Arc;

use bw_model::{{CheckpointKind, ObjectUseEvent, ObjectUseKind, RuntimeEvent, SiteId}};
use bw_runtime::Tracked;
use rusqlite::{{hooks::Action, Connection}};
use rusqlite_lab_shared::{{
    runtime::{{benchmark_build_id, benchmark_runtime}},
    update_hook::UpdateHookConnection,
    BorrowedCounter,
}};

fn main() -> Result<(), Box<dyn std::error::Error>> {{
    let runtime = benchmark_runtime("run:{plan_slug}", "trace:{plan_slug}")?;
    runtime.emit_trace_start(benchmark_build_id("build:{plan_slug}"))?;

    let connection = Connection::open_in_memory()?;
    connection.execute("CREATE TABLE item(id INTEGER PRIMARY KEY)", [])?;

    let observed = UpdateHookConnection::open(runtime.clone(), site("site:{plan_slug}:connection"))?;
    let counter_site = site("site:{plan_slug}:object");
    let counter = Tracked::new(runtime.clone(), counter_site.clone(), BorrowedCounter::new());
    let token = observed.register(site("site:{plan_slug}:callback"))?;
    // bind_object 的第二个参数是对象自身的 site id。bridge 里的 capture_site_id 只用作
    // CallbackCapture 事实自身的 site_id，两者不可互换。
    token.bind_object(counter.id(), &counter_site)?;
    runtime.emit_checkpoint(CheckpointKind::Registered)?;

    let callback_token = Arc::clone(&token);
    let callback_runtime = runtime.clone();
    let callback_counter_id = counter.id().clone();
    let callback_counter_site = counter_site.clone();
    let callback_counter = counter.get();
    connection.update_hook(Some(
        move |action: Action, database: &str, table: &str, rowid: i64| {{
            let _ = (action, database, table);
            let _ = callback_token.invoke(site("site:{plan_slug}:invoke"));
            {callback_object_use}
        }},
    ));

    // 静态侧观察到 owner 在 callback 仍被外部持有时释放，这里复现那一步。
    drop(counter);
    runtime.emit_checkpoint(CheckpointKind::LaterCallbackPhase)?;
    connection.execute("INSERT INTO item DEFAULT VALUES", [])?;
    observed.close(site("site:{plan_slug}:connection-drop"))?;
    runtime.emit_trace_end()?;
    runtime.finish()?;
    Ok(())
}}

fn site(value: &'static str) -> SiteId {{
    SiteId::from(value)
}}
"#,
        plan_id = plan_id,
        candidate_id = candidate_id,
        api_id = api_id,
        pattern_family = pattern_family,
        callback_object_use = callback_object_use,
        plan_slug = sanitize_site_slug(plan_id),
    )
}

/// site id 片段：保留可读性，去掉会破坏字符串字面量的字符。
fn sanitize_site_slug(plan_id: &str) -> String {
    plan_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// 与其它命令模块一致的本地 JSON 写出helper。
fn write_json_file(path: &Path, value: &impl serde::Serialize) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, value)
        .map_err(|error| CliError::internal(error.to_string()))?;
    file.write_all(b"\n")?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(plan_id: &str, target: Option<V326WitnessTarget>) -> V326WitnessPlanRecord {
        V326WitnessPlanRecord {
            schema_version: bw_model::V3_2_6_WITNESS_PLAN_SCHEMA_V1.to_owned(),
            run_id: "run:test".to_owned(),
            plan_id: plan_id.to_owned(),
            candidate_id: "candidate:test".to_owned(),
            lifecycle_graph_ref: "graphs-v3/candidate_test.json".to_owned(),
            target,
            actions: vec![bw_model::V326WitnessAction {
                action_id: "action:test:register".to_owned(),
                action_kind: bw_model::V326WitnessActionKind::RegisterCallback,
                graph_refs: vec![],
                notes: vec![],
            }],
            runtime_observers: vec![],
            oracle_assertions: vec![],
            replay_evidence_refs: vec![],
            notes: vec![],
        }
    }

    fn target(api_id: &str, version: &str) -> V326WitnessTarget {
        V326WitnessTarget {
            api_id: api_id.to_owned(),
            crate_name: "some_app".to_owned(),
            crate_version: "0.1.0".to_owned(),
            api_crate: Some(bw_model::V326WitnessApiCrate {
                name: "rusqlite".to_owned(),
                version: version.to_owned(),
            }),
            registration_source_ref: None,
            observed_shape: Some(shape(true, true)),
        }
    }

    /// 真实仓库根：生成器能链接哪些版本取自仓库的 vendor 目录，临时目录里没有。
    fn repo_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    }

    /// 静态侧观察到的形状。两个顺序位直接决定生成器造不造那一步。
    fn shape(
        release_before_callback_use: bool,
        callback_use_after_release: bool,
    ) -> V326WitnessObservedShape {
        V326WitnessObservedShape {
            pattern_family: V32PatternFamily::RetainedBorrowedCallback,
            release_observed: release_before_callback_use,
            release_before_callback_use,
            callback_use_after_release,
            unproven: vec!["release_order_proof_missing".to_owned()],
        }
    }

    #[test]
    fn sanitized_crate_name_is_a_valid_rust_identifier() {
        let name = sanitize_crate_name("witness-plan:candidate:alpha-001");
        assert!(
            name.chars().all(|character| character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '_'),
            "crate name must be usable as a package name: {name}"
        );
        assert!(name.starts_with("bw_witness_"));
    }

    #[test]
    fn refuses_an_api_without_a_template() {
        let temp = tempfile::tempdir().expect("tempdir");
        let plan = plan(
            "witness-plan:a",
            Some(target("api:openssl:set_ex_data", "0.26.1")),
        );
        let error = generate_one(
            temp.path(),
            &repo_root(),
            &plan,
            plan.target.as_ref().unwrap(),
        )
        .expect_err("an API with no template must be refused");
        assert_eq!(error.reason, REASON_UNSUPPORTED_API);
    }

    #[test]
    fn refuses_a_crate_version_the_shared_crate_cannot_link() {
        let temp = tempfile::tempdir().expect("tempdir");
        let plan = plan(
            "witness-plan:a",
            Some(target("api:rusqlite:update_hook:register", "0.31.0")),
        );
        let error = generate_one(
            temp.path(),
            &repo_root(),
            &plan,
            plan.target.as_ref().unwrap(),
        )
        .expect_err("an unlinkable version must be refused rather than generated");
        assert_eq!(error.reason, REASON_UNSUPPORTED_VERSION);
    }

    #[test]
    fn generates_a_harness_for_a_supported_update_hook_target() {
        let temp = tempfile::tempdir().expect("tempdir");
        let plan = plan(
            "witness-plan:candidate:alpha",
            Some(target("api:rusqlite:update_hook:register", "0.26.1")),
        );
        let record = generate_one(
            temp.path(),
            &repo_root(),
            &plan,
            plan.target.as_ref().unwrap(),
        )
        .expect("a supported target must generate");

        let harness_dir = PathBuf::from(&record.harness_dir);
        let main_source =
            fs::read_to_string(harness_dir.join("src/main.rs")).expect("main.rs should exist");
        let cargo_toml =
            fs::read_to_string(harness_dir.join("Cargo.toml")).expect("Cargo.toml should exist");

        assert!(main_source.contains("fn main()"));
        assert!(
            main_source.contains("CheckpointKind::Registered")
                && main_source.contains("CheckpointKind::LaterCallbackPhase"),
            "the oracle needs both checkpoints to consider a trace comparable"
        );
        assert!(
            main_source.contains("drop(counter)"),
            "the harness must drop the Rust owner while the callback is still registered"
        );
        assert!(
            cargo_toml.contains("rusqlite = { version = \"=0.26.1\""),
            "the dependency must be pinned to the linkable version: {cargo_toml}"
        );
        assert_eq!(record.main_sha256.len(), 64);
    }

    /// 静态侧没观察到释放顺序时，生成器必须拒绝而不是产出一个结构上不可能违规的
    /// harness——那种 harness 跑完的 "no findings" 会被读成"验证通过"。
    #[test]
    fn refuses_when_no_release_ordering_was_observed() {
        let temp = tempfile::tempdir().unwrap();
        let mut target = target("api:rusqlite:update_hook:register", "0.26.1");
        target.observed_shape = Some(shape(false, false));
        let plan = plan("witness-plan:candidate:beta", Some(target));

        let refusal = generate_one(
            temp.path(),
            &repo_root(),
            &plan,
            plan.target.as_ref().unwrap(),
        )
        .expect_err("a harness that cannot exhibit the sequence must not be generated");

        assert_eq!(refusal.reason, REASON_NO_RELEASE_ORDERING);
        assert!(
            !temp
                .path()
                .join(sanitize_crate_name(&plan.plan_id))
                .exists(),
            "a refused plan must leave no half-written harness behind"
        );
    }

    #[test]
    fn refuses_a_plan_without_an_observed_shape() {
        let temp = tempfile::tempdir().unwrap();
        let mut target = target("api:rusqlite:update_hook:register", "0.26.1");
        target.observed_shape = None;
        let plan = plan("witness-plan:candidate:gamma", Some(target));

        let refusal = generate_one(
            temp.path(),
            &repo_root(),
            &plan,
            plan.target.as_ref().unwrap(),
        )
        .expect_err("without an observed shape only a fixed script is possible");

        assert_eq!(refusal.reason, REASON_NO_OBSERVED_SHAPE);
    }

    /// callback 是否触碰对象来自观察，不是模板固定的。
    #[test]
    fn callback_touches_the_object_only_when_the_use_was_observed() {
        let plan_with_use = plan(
            "witness-plan:candidate:delta",
            Some(target("api:rusqlite:update_hook:register", "0.26.1")),
        );
        let target_with_use = plan_with_use.target.as_ref().unwrap();
        let with_use = render_update_hook_main(
            &plan_with_use,
            target_with_use,
            target_with_use.observed_shape.as_ref().unwrap(),
        );
        assert!(
            with_use.contains("RuntimeEvent::ObjectUse"),
            "an observed use-after-release must be reproduced"
        );

        let without_use =
            render_update_hook_main(&plan_with_use, target_with_use, &shape(true, false));
        assert!(
            !without_use.contains("RuntimeEvent::ObjectUse"),
            "the harness must not invent a use the static analysis never observed"
        );
    }

    #[test]
    fn scalar_function_registrations_have_a_template() {
        let temp = tempfile::tempdir().unwrap();
        let plan = plan(
            "witness-plan:candidate:scalar",
            Some(target(
                "api:rusqlite:create_scalar_function:register",
                "0.26.1",
            )),
        );

        let record = generate_one(
            temp.path(),
            &repo_root(),
            &plan,
            plan.target.as_ref().unwrap(),
        )
        .expect("create_scalar_function must be covered, not refused");

        assert_eq!(record.reproduces.template, "create_scalar_function");
        let main_source =
            fs::read_to_string(std::path::Path::new(&record.harness_dir).join("src/main.rs"))
                .expect("the harness source must be written");
        assert!(
            main_source.contains("create_scalar_function"),
            "the scalar template must register through the scalar API, not update_hook"
        );
        assert!(
            !main_source.contains("update_hook"),
            "templates must not bleed into each other: {main_source}"
        );
    }

    #[test]
    fn every_supported_api_resolves_to_a_template() {
        for api_id in SUPPORTED_APIS {
            assert!(
                HarnessTemplate::for_api(api_id).is_some(),
                "{api_id} is advertised as supported but has no template"
            );
        }
        assert!(
            HarnessTemplate::for_api("api:rusqlite:commit_hook:register").is_none(),
            "an API without a template must be refused rather than routed to a lookalike"
        );
    }

    /// 能链接哪些版本由 vendor 目录决定，不是常量。两者漂移会静默换成 crates.io 上的
    /// 真包，harness 于是链接了未经审阅的代码而产物看不出来。
    #[test]
    fn linkable_versions_come_from_the_vendor_directory() {
        let vendored = vendored_rusqlite_versions(&repo_root());
        assert!(
            vendored.contains("0.26.1"),
            "the repository vendors rusqlite 0.26.1; got {vendored:?}"
        );

        let temp = tempfile::tempdir().unwrap();
        let plan = plan(
            "witness-plan:candidate:unvendored",
            Some(target("api:rusqlite:update_hook:register", "0.99.0")),
        );
        let refusal = generate_one(
            temp.path(),
            &repo_root(),
            &plan,
            plan.target.as_ref().unwrap(),
        )
        .expect_err("a version that is not vendored cannot be linked");
        assert_eq!(refusal.reason, REASON_UNSUPPORTED_VERSION);
        assert!(
            refusal.detail.contains("0.26.1"),
            "the refusal must say what can be linked instead: {}",
            refusal.detail
        );
    }

    #[test]
    fn generated_source_is_byte_identical_for_the_same_plan() {
        let plan = plan(
            "witness-plan:candidate:alpha",
            Some(target("api:rusqlite:update_hook:register", "0.26.1")),
        );
        let target = plan.target.as_ref().unwrap();
        let observed = target.observed_shape.as_ref().unwrap();
        let first = render_update_hook_main(&plan, target, observed);
        let second = render_update_hook_main(&plan, target, observed);
        assert_eq!(
            first, second,
            "harness generation must be deterministic so its sha256 binds a run to its source"
        );
    }
}

// ---------------------------------------------------------------------------
// bridge-witness-facts
// ---------------------------------------------------------------------------

/// 把 harness 的运行时 site id 补进静态事实。
///
/// harness 在运行时通过 `bind_object` 建立 capture，编译器产出的静态事实使用另一套
/// site id，oracle 因此以 `BW-ORACLE-STATIC-CAPTURE-MISSING` 拒绝判定。本命令按
/// `site-bridge.json` 合成 CallbackSite / ObjectSite / CallbackCapture 三条事实，
/// build_id 取自既有静态事实，保证 oracle 的 build 一致性检查仍然生效。
#[derive(Args)]
pub struct BridgeWitnessFactsArgs {
    #[arg(long = "static-facts")]
    static_facts: PathBuf,
    #[arg(long)]
    bridge: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, serde::Deserialize)]
struct SiteBridge {
    plan_id: String,
    callback_site_id: String,
    object_site_id: String,
    capture_site_id: String,
    capture_mode: bw_model::CaptureMode,
}

#[derive(Debug, Serialize)]
struct BridgeOutput {
    kind: &'static str,
    plan_id: String,
    build_id: String,
    input_fact_count: u64,
    bridge_fact_count: u64,
    output: String,
}

pub fn run_bridge(args: BridgeWitnessFactsArgs) -> Result<CommandStatus, CliError> {
    let facts_text = fs::read_to_string(&args.static_facts)?;
    let mut lines = facts_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let first = lines.first().ok_or_else(|| {
        CliError::input(
            "BW-V326-BRIDGE-EMPTY-FACTS",
            format!("{} 没有静态事实", args.static_facts.display()),
        )
    })?;
    let build_id = bw_model::StaticFactEnvelope::from_json_str(first)
        .map_err(|error| {
            CliError::input(
                "BW-V326-BRIDGE-FACTS",
                format!("{}: {error}", args.static_facts.display()),
            )
        })?
        .build_id;

    let bridge: SiteBridge =
        serde_json::from_str(&fs::read_to_string(&args.bridge)?).map_err(|error| {
            CliError::input(
                "BW-V326-BRIDGE-SPEC",
                format!("{}: {error}", args.bridge.display()),
            )
        })?;

    let bridge_facts = bridge_facts(&bridge, &build_id);
    for fact in &bridge_facts {
        lines.push(
            serde_json::to_string(fact).map_err(|error| CliError::internal(error.to_string()))?,
        );
    }
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&args.output, lines.join("\n") + "\n")?;

    write_json_stdout(&BridgeOutput {
        kind: "v3-2-6-witness-site-bridge",
        plan_id: bridge.plan_id.clone(),
        build_id: build_id.0.clone(),
        input_fact_count: (lines.len() - bridge_facts.len()) as u64,
        bridge_fact_count: bridge_facts.len() as u64,
        output: args.output.display().to_string(),
    })?;
    Ok(CommandStatus::Success)
}

fn bridge_facts(
    bridge: &SiteBridge,
    build_id: &bw_model::BuildId,
) -> Vec<bw_model::StaticFactEnvelope> {
    let slug = sanitize_site_slug(&bridge.plan_id);
    let envelope = |suffix: &str, payload: bw_model::StaticFact| bw_model::StaticFactEnvelope {
        schema_version: bw_model::STATIC_SCHEMA_V01.to_owned(),
        record_id: bw_model::RecordId::from(format!("fact:bridge:{slug}:{suffix}")),
        producer: "bw-generate-witness-harness@0.1".to_owned(),
        build_id: build_id.clone(),
        artifact: None,
        source_ref: None,
        payload,
    };
    vec![
        envelope(
            "callback",
            bw_model::StaticFact::CallbackSite(bw_model::CallbackSiteFact {
                site_id: bw_model::SiteId::from(bridge.callback_site_id.as_str()),
                semantic_site_key: bw_model::SemanticSiteKey::from(format!(
                    "semantic:bridge:{slug}:callback"
                )),
                def_path: format!("runtime_bridge::{slug}::callback"),
            }),
        ),
        envelope(
            "object",
            bw_model::StaticFact::ObjectSite(bw_model::ObjectSiteFact {
                site_id: bw_model::SiteId::from(bridge.object_site_id.as_str()),
                semantic_site_key: bw_model::SemanticSiteKey::from(format!(
                    "semantic:bridge:{slug}:object"
                )),
                type_name: "runtime_bridge::tracked_object".to_owned(),
            }),
        ),
        envelope(
            "capture",
            bw_model::StaticFact::CallbackCapture(bw_model::CallbackCaptureFact {
                site_id: bw_model::SiteId::from(bridge.capture_site_id.as_str()),
                semantic_site_key: bw_model::SemanticSiteKey::from(format!(
                    "semantic:bridge:{slug}:capture"
                )),
                callback_site_id: bw_model::SiteId::from(bridge.callback_site_id.as_str()),
                object_site_id: bw_model::SiteId::from(bridge.object_site_id.as_str()),
                capture_ordinal: 0,
                capture_mode: bridge.capture_mode,
            }),
        ),
    ]
}
