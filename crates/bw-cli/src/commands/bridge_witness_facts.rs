//! bridge-witness-facts：把 harness 的运行时 site id 补进静态事实。
//!
//! 阶段 5.3 从 `generate_witness_harness.rs` 拆出：新生成器不再产出
//! `site-bridge.json`（runtime trace 降级为辅助定位），但旧 witness 链的
//! 重放与 bridge 命令仍有测试与文档引用，保留命令本身。
//!
//! harness 在运行时通过 `bind_object` 建立 capture，编译器产出的静态事实使用另一套
//! site id，oracle 因此以 `BW-ORACLE-STATIC-CAPTURE-MISSING` 拒绝判定。本命令按
//! `site-bridge.json` 合成 CallbackSite / ObjectSite / CallbackCapture 三条事实，
//! build_id 取自既有静态事实，保证 oracle 的 build 一致性检查仍然生效。

use std::{fs, path::PathBuf};

use bw_model::{
    BuildId, CaptureMode, RecordId, SemanticSiteKey, SiteId, StaticFact, StaticFactEnvelope,
    STATIC_SCHEMA_V01,
};
use clap::Args;
use serde::Serialize;

use crate::{
    commands::write_json_stdout,
    exit::{CliError, CommandStatus},
};

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
    capture_mode: CaptureMode,
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

pub fn run(args: BridgeWitnessFactsArgs) -> Result<CommandStatus, CliError> {
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
    let build_id = StaticFactEnvelope::from_json_str(first)
        .map_err(|error| {
            CliError::input(
                "BW-V326-BRIDGE-FACTS",
                format!("{}: {error}", args.static_facts.display()),
            )
        })?
        .build_id;

    let bridge: SiteBridge = serde_json::from_str(&fs::read_to_string(&args.bridge)?).map_err(
        |error| CliError::input("BW-V326-BRIDGE-SPEC", format!("{}: {error}", args.bridge.display())),
    )?;

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
    build_id: &BuildId,
) -> Vec<StaticFactEnvelope> {
    let slug = sanitize_site_slug(&bridge.plan_id);
    let envelope = |suffix: &str, payload: StaticFact| StaticFactEnvelope {
        schema_version: STATIC_SCHEMA_V01.to_owned(),
        record_id: RecordId::from(format!("fact:bridge:{slug}:{suffix}")),
        producer: "bw-generate-witness-harness@0.1".to_owned(),
        build_id: build_id.clone(),
        artifact: None,
        source_ref: None,
        payload,
    };
    vec![
        envelope(
            "callback",
            StaticFact::CallbackSite(bw_model::CallbackSiteFact {
                site_id: SiteId::from(bridge.callback_site_id.as_str()),
                semantic_site_key: SemanticSiteKey::from(format!(
                    "semantic:bridge:{slug}:callback"
                )),
                def_path: format!("runtime_bridge::{slug}::callback"),
            }),
        ),
        envelope(
            "object",
            StaticFact::ObjectSite(bw_model::ObjectSiteFact {
                site_id: SiteId::from(bridge.object_site_id.as_str()),
                semantic_site_key: SemanticSiteKey::from(format!(
                    "semantic:bridge:{slug}:object"
                )),
                type_name: "runtime_bridge::tracked_object".to_owned(),
            }),
        ),
        envelope(
            "capture",
            StaticFact::CallbackCapture(bw_model::CallbackCaptureFact {
                site_id: SiteId::from(bridge.capture_site_id.as_str()),
                semantic_site_key: SemanticSiteKey::from(format!(
                    "semantic:bridge:{slug}:capture"
                )),
                callback_site_id: SiteId::from(bridge.callback_site_id.as_str()),
                object_site_id: SiteId::from(bridge.object_site_id.as_str()),
                capture_ordinal: 0,
                capture_mode: bridge.capture_mode,
            }),
        ),
    ]
}

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
