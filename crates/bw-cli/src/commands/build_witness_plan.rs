use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Cursor, Write},
    path::{Path, PathBuf},
};

use bw_model::{
    V326LifecycleGraphV3Record, V326RankedCandidateRecord, V326WitnessAction,
    V326WitnessActionKind, V326WitnessPlanRecord, V326WitnessRoute,
    validate_v3_2_6_lifecycle_graph_v3, validate_v3_2_6_ranked_candidates,
    validate_v3_2_6_witness_plans,
};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    commands::{DEFAULT_MAX_LINE_BYTES, read_jsonl, read_to_string},
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct BuildWitnessPlanArgs {
    #[arg(long = "ranked-candidates")]
    ranked_candidates: PathBuf,
    #[arg(long = "graphs-dir")]
    graphs_dir: PathBuf,
    /// 生命周期事实。提供时 plan 才能带上可执行的 target；缺省时 plan 只能人工执行。
    #[arg(long)]
    facts: Option<PathBuf>,
    /// callback-retention API map，可重复。用于确定注册 API 由哪个 crate 声明。
    #[arg(long = "api-map")]
    api_maps: Vec<PathBuf>,
    /// extract-static-facts 写出的 resolved-dependencies.jsonl。
    /// 与 --api-map 同时提供时，plan 的 target 才能带上 harness 要链接的提供方版本。
    #[arg(long = "resolved-dependencies")]
    resolved_dependencies: Option<PathBuf>,
    #[arg(long = "output-dir")]
    output_dir: PathBuf,
    #[arg(long)]
    run_id: String,
    #[arg(long, default_value_t = 10)]
    limit: usize,
    #[arg(long, default_value_t = DEFAULT_MAX_LINE_BYTES)]
    max_line_bytes: usize,
}

#[derive(Serialize)]
struct BuildOutput {
    kind: &'static str,
    run_id: String,
    plan_count: u64,
    output_dir: String,
    plans_path: String,
    checksums_path: String,
}

pub fn run(args: BuildWitnessPlanArgs) -> Result<CommandStatus, CliError> {
    if args.run_id.trim().is_empty() {
        return Err(CliError::input("BW-V326-RUN-ID", "run_id 不能为空"));
    }
    if args.limit == 0 {
        return Err(CliError::input("BW-V326-WITNESS-LIMIT", "limit 必须大于 0"));
    }

    let ranked =
        read_jsonl::<V326RankedCandidateRecord>(&args.ranked_candidates, args.max_line_bytes)?;
    validate_v3_2_6_ranked_candidates(ranked.clone())?;
    let ranked = ranked
        .into_iter()
        .map(|located| located.value)
        .take(args.limit)
        .collect::<Vec<_>>();

    let registration_apis = match &args.facts {
        Some(facts_path) => registration_api_by_candidate(facts_path, args.max_line_bytes)?,
        None => BTreeMap::new(),
    };
    let api_declaring_crates = load_api_declaring_crates(&args.api_maps)?;
    let resolved_dependencies = match &args.resolved_dependencies {
        Some(path) => resolved_dependencies_by_crate(path, args.max_line_bytes)?,
        None => BTreeMap::new(),
    };

    let mut plans = Vec::<V326WitnessPlanRecord>::new();
    for candidate in &ranked {
        let graph_path = resolve_graph_path(&args.graphs_dir, candidate)?;
        let graph_ref = resolved_graph_ref(&args.graphs_dir, &graph_path)?;
        let graph_text = read_to_string(&graph_path)?;
        let graph: V326LifecycleGraphV3Record =
            serde_json::from_str(&graph_text).map_err(|error| {
                CliError::input("BW-JSON", format!("{}: {}", graph_path.display(), error))
            })?;
        validate_v3_2_6_lifecycle_graph_v3([bw_model::Located {
            path: graph_path.clone(),
            line: 1,
            value: graph.clone(),
        }])?;
        if graph.candidate_id != candidate.candidate_id || graph.crate_id != candidate.crate_id {
            return Err(CliError::input(
                "BW-V326-WITNESS-GRAPH-MISMATCH",
                format!(
                    "{} 与 ranked candidate {} / {} 不一致",
                    graph_path.display(),
                    candidate.candidate_id,
                    candidate.crate_id
                ),
            ));
        }
        let mut plan = plan_for_candidate(&args.run_id, candidate, &graph, graph_ref);
        plan.target = witness_target_for_candidate(
            candidate,
            &graph,
            &registration_apis,
            &api_declaring_crates,
            &resolved_dependencies,
        );
        match &plan.target {
            None => plan.notes.push(
                "no contract API binding was resolved; this plan is manual-review only".to_owned(),
            ),
            // 提供方版本缺失不降级成"没有 target"：API 绑定本身是成立的，只是不可自动执行。
            Some(target) if target.api_crate.is_none() => plan.notes.push(
                "the crate declaring this API was not resolved to a version; \
                 the plan is bound but not automatically executable"
                    .to_owned(),
            ),
            Some(_) => {}
        }
        plans.push(plan);
    }

    validate_v3_2_6_witness_plans(plans.iter().cloned().enumerate().map(|(index, value)| {
        bw_model::Located {
            path: args.output_dir.join("witness-plans.jsonl.zst"),
            line: index + 1,
            value,
        }
    }))?;

    fs::create_dir_all(&args.output_dir)?;
    let plans_path = args.output_dir.join("witness-plans.jsonl.zst");
    write_records(&plans_path, &plans)?;
    let stats = serde_json::json!({
        "schema_version": "v3.2.6.witness_plan_stats.1",
        "run_id": args.run_id,
        "plan_count": plans.len(),
    });
    write_json_file(&args.output_dir.join("witness-plan-stats.json"), &stats)?;

    let checksums_path = args.output_dir.join("checksums.txt");
    write_checksums(&args.output_dir, &checksums_path)?;

    let output = BuildOutput {
        kind: "v3-2-6-witness-plan",
        run_id: args.run_id,
        plan_count: plans.len() as u64,
        output_dir: args.output_dir.display().to_string(),
        plans_path: plans_path.display().to_string(),
        checksums_path: checksums_path.display().to_string(),
    };
    crate::commands::write_json_stdout(&output)?;
    Ok(CommandStatus::Success)
}

/// 从生命周期事实里取出每个候选的注册 API id。
///
/// api_id 只存在于事实的 `symbol_path` 上，graph 与 ranked candidate 都不携带它，
/// 因此没有事实输入时 plan 无法绑定到具体 API。
fn registration_api_by_candidate(
    facts_path: &std::path::Path,
    max_line_bytes: usize,
) -> Result<BTreeMap<String, String>, CliError> {
    let facts = read_jsonl::<bw_model::V326LifecycleFactRecord>(facts_path, max_line_bytes)?;
    let mut apis = BTreeMap::<String, String>::new();
    for located in facts {
        let fact = located.value;
        if fact.fact_kind != bw_model::V326LifecycleFactKind::RegisterCall {
            continue;
        }
        let Some(api_id) = fact.symbol_path.as_deref().map(str::trim) else {
            continue;
        };
        if !api_id.starts_with("api:") {
            continue;
        }
        // 同一候选出现多个注册 API 时不猜：留空，plan 退回人工。
        match apis.entry(fact.candidate_id.clone()) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(api_id.to_owned());
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                if slot.get() != api_id {
                    slot.insert(String::new());
                }
            }
        }
    }
    Ok(apis)
}

/// `crate:rusqlite:0.31.0` -> `("rusqlite", "0.31.0")`。
fn split_crate_id(crate_id: &str) -> Option<(String, String)> {
    let rest = crate_id.strip_prefix("crate:")?;
    let (name, version) = rest.rsplit_once(':')?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_owned(), version.to_owned()))
}

fn witness_target_for_candidate(
    candidate: &V326RankedCandidateRecord,
    graph: &V326LifecycleGraphV3Record,
    registration_apis: &BTreeMap<String, String>,
    api_declaring_crates: &BTreeMap<String, BTreeSet<String>>,
    resolved_dependencies: &BTreeMap<String, BTreeMap<String, String>>,
) -> Option<bw_model::V326WitnessTarget> {
    let registration_source_ref = graph
        .objects
        .iter()
        .find(|object| object.object_kind == bw_model::V326LifecycleObjectKind::UserData)
        .and_then(|object| object.source_ref.clone());
    witness_target_from_parts(
        &candidate.candidate_id,
        &candidate.crate_id,
        registration_apis,
        api_declaring_crates,
        resolved_dependencies,
        registration_source_ref,
        Some(observed_shape_for_candidate(candidate, graph)),
    )
}

/// 把静态侧观察到的形状收拢成 harness 的生成输入。
///
/// 两个顺序位来自 chain summary 里的分层证明，而不是模式家族的默认假设：
/// `release_ordering` 证明 owner 在 callback 仍注册时被释放，`use_ordering` 证明
/// callback 在那之后仍使用该对象。没有证明就是 false —— harness 不得替静态侧补证。
fn observed_shape_for_candidate(
    candidate: &V326RankedCandidateRecord,
    graph: &V326LifecycleGraphV3Record,
) -> bw_model::V326WitnessObservedShape {
    let summary = &candidate.chain_summary;
    let mut unproven = graph.incomplete_reasons.clone();
    unproven.extend(summary.chain_incomplete_reasons.iter().cloned());
    unproven.sort();
    unproven.dedup();
    bw_model::V326WitnessObservedShape {
        pattern_family: candidate.pattern_family,
        release_before_callback_use: summary.release_ordering_chain_count > 0
            || summary.complete_risk_chain_count > 0,
        callback_use_after_release: summary.use_ordering_chain_count > 0
            || summary.complete_risk_chain_count > 0,
        unproven,
    }
}

/// [`witness_target_for_candidate`] 的纯逻辑，便于在不构造完整 ranked/graph 记录的
/// 前提下测试绑定与拒绝绑定的条件。
fn witness_target_from_parts(
    candidate_id: &str,
    crate_id: &str,
    registration_apis: &BTreeMap<String, String>,
    api_declaring_crates: &BTreeMap<String, BTreeSet<String>>,
    resolved_dependencies: &BTreeMap<String, BTreeMap<String, String>>,
    registration_source_ref: Option<bw_model::V326SourceRef>,
    observed_shape: Option<bw_model::V326WitnessObservedShape>,
) -> Option<bw_model::V326WitnessTarget> {
    let api_id = registration_apis.get(candidate_id)?;
    if api_id.is_empty() {
        return None;
    }
    let (crate_name, crate_version) = split_crate_id(crate_id)?;
    let api_crate = resolve_api_crate(
        api_id,
        crate_id,
        api_declaring_crates,
        resolved_dependencies,
        &crate_name,
        &crate_version,
    );
    Some(bw_model::V326WitnessTarget {
        api_id: api_id.clone(),
        crate_name,
        crate_version,
        api_crate,
        registration_source_ref,
        observed_shape,
    })
}

/// 确定这个 api_id 由哪个 crate 的哪个版本提供。
///
/// 一个 api_id 可能被多个 crate 声明（同一个 API 家族的安全封装与 `-sys` 直调），所以
/// 不能只看 API map；真正生效的是被扫 crate 实际解析到的那个。取交集，唯一才绑定：
/// 零个说明依赖解析结果里根本没有提供方，多个说明分不清走的是哪条，两种都是缺证。
fn resolve_api_crate(
    api_id: &str,
    crate_id: &str,
    api_declaring_crates: &BTreeMap<String, BTreeSet<String>>,
    resolved_dependencies: &BTreeMap<String, BTreeMap<String, String>>,
    candidate_crate_name: &str,
    candidate_crate_version: &str,
) -> Option<bw_model::V326WitnessApiCrate> {
    let declaring = api_declaring_crates.get(api_id)?;
    // API 声明在被扫 crate 自己身上：提供方就是它自己，无需查依赖。
    if declaring.contains(candidate_crate_name) {
        return Some(bw_model::V326WitnessApiCrate {
            name: candidate_crate_name.to_owned(),
            version: candidate_crate_version.to_owned(),
        });
    }
    let resolved = resolved_dependencies.get(crate_id)?;
    let mut matches = declaring
        .iter()
        .filter_map(|name| {
            resolved
                .get(name)
                .map(|version| bw_model::V326WitnessApiCrate {
                    name: name.clone(),
                    version: version.clone(),
                })
        })
        .collect::<Vec<_>>();
    (matches.len() == 1).then(|| matches.remove(0))
}

/// api_id → 声明它的 crate 名集合，取自 API map 里 `rust_path` 的首段。
fn load_api_declaring_crates(
    paths: &[PathBuf],
) -> Result<BTreeMap<String, BTreeSet<String>>, CliError> {
    let mut declaring = BTreeMap::<String, BTreeSet<String>>::new();
    for path in paths {
        let text = fs::read_to_string(path).map_err(|error| {
            CliError::input(
                "BW-V326-WITNESS-API-MAP",
                format!("{}: {error}", path.display()),
            )
        })?;
        let api_map = bw_model::CallbackRetentionApiMap::from_toml_str(&text).map_err(|error| {
            CliError::input(
                "BW-V326-WITNESS-API-MAP",
                format!("{}: {error}", path.display()),
            )
        })?;
        for entry in api_map.apis {
            // `rust_path` 首段是 crate 名。没有 `::` 的条目（裸外部符号）说明不出提供方。
            let Some((krate, _)) = entry.rust_path.split_once("::") else {
                continue;
            };
            declaring
                .entry(entry.api_id)
                .or_default()
                .insert(krate.to_owned());
        }
    }
    Ok(declaring)
}

/// crate_id → {依赖包名: 版本}。同名多版本共存时不猜，整条丢弃留给缺证记录。
fn resolved_dependencies_by_crate(
    path: &Path,
    max_line_bytes: usize,
) -> Result<BTreeMap<String, BTreeMap<String, String>>, CliError> {
    #[derive(serde::Deserialize)]
    struct ResolvedDependenciesRecord {
        crate_id: String,
        #[serde(default)]
        packages: Vec<ResolvedPackage>,
    }
    #[derive(serde::Deserialize)]
    struct ResolvedPackage {
        name: String,
        version: String,
    }

    let records = read_jsonl::<ResolvedDependenciesRecord>(path, max_line_bytes)?;
    let mut by_crate = BTreeMap::<String, BTreeMap<String, String>>::new();
    for located in records {
        let record = located.value;
        let mut ambiguous = BTreeSet::<String>::new();
        let versions = by_crate.entry(record.crate_id).or_default();
        for package in record.packages {
            match versions.entry(package.name.clone()) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(package.version);
                }
                std::collections::btree_map::Entry::Occupied(slot) => {
                    if slot.get() != &package.version {
                        ambiguous.insert(package.name);
                    }
                }
            }
        }
        for name in ambiguous {
            versions.remove(&name);
        }
    }
    Ok(by_crate)
}

fn plan_for_candidate(
    run_id: &str,
    candidate: &V326RankedCandidateRecord,
    graph: &V326LifecycleGraphV3Record,
    graph_ref: String,
) -> V326WitnessPlanRecord {
    if returned_view_chain_present(graph, candidate) {
        return returned_view_plan_for_candidate(run_id, candidate, graph, graph_ref);
    }
    if external_buffer_chain_present(graph, candidate) {
        return external_buffer_plan_for_candidate(run_id, candidate, graph, graph_ref);
    }
    callback_plan_for_candidate(run_id, candidate, graph, graph_ref)
}

fn callback_plan_for_candidate(
    run_id: &str,
    candidate: &V326RankedCandidateRecord,
    graph: &V326LifecycleGraphV3Record,
    graph_ref: String,
) -> V326WitnessPlanRecord {
    let mut actions = vec![
        V326WitnessAction {
            action_id: format!("action:{}:setup", sanitize_id(&candidate.candidate_id)),
            action_kind: V326WitnessActionKind::SetupControlledFixture,
            graph_refs: graph
                .objects
                .iter()
                .map(|object| object.object_id.clone())
                .collect(),
            notes: vec!["prepare local controlled lifecycle fixture".to_owned()],
        },
        V326WitnessAction {
            action_id: format!("action:{}:register", sanitize_id(&candidate.candidate_id)),
            action_kind: V326WitnessActionKind::RegisterCallback,
            graph_refs: edge_refs(graph, "register"),
            notes: vec!["exercise candidate registration path in local harness".to_owned()],
        },
    ];

    actions.push(V326WitnessAction {
        action_id: format!(
            "action:{}:replace_or_unregister",
            sanitize_id(&candidate.candidate_id)
        ),
        action_kind: V326WitnessActionKind::ReplaceOrUnregister,
        graph_refs: edge_refs(graph, "release"),
        notes: vec!["exercise local replace or unregister lifecycle path".to_owned()],
    });
    actions.push(V326WitnessAction {
        action_id: format!("action:{}:drop_owner", sanitize_id(&candidate.candidate_id)),
        action_kind: V326WitnessActionKind::DropRustOwner,
        graph_refs: edge_refs(graph, "drop"),
        notes: vec!["observe Rust owner drop timing in local harness".to_owned()],
    });

    actions.push(V326WitnessAction {
        action_id: format!("action:{}:trigger", sanitize_id(&candidate.candidate_id)),
        action_kind: V326WitnessActionKind::TriggerCallbackInLocalHarness,
        graph_refs: graph.evidence_refs.clone(),
        notes: vec!["trigger callback only inside the controlled local harness".to_owned()],
    });
    actions.push(V326WitnessAction {
        action_id: format!("action:{}:collect", sanitize_id(&candidate.candidate_id)),
        action_kind: V326WitnessActionKind::CollectOracleEvidence,
        graph_refs: graph.evidence_refs.clone(),
        notes: vec!["collect runtime trace and oracle evidence".to_owned()],
    });

    V326WitnessPlanRecord {
        schema_version: bw_model::V3_2_6_WITNESS_PLAN_SCHEMA_V1.to_owned(),
        run_id: run_id.to_owned(),
        plan_id: format!("witness-plan:{}", sanitize_id(&candidate.candidate_id)),
        candidate_id: candidate.candidate_id.clone(),
        lifecycle_graph_ref: graph_ref,
        // 由 run() 在生成后按事实解析填充；三个 route 的构造点都不自行猜测 API。
        target: None,
        actions,
        runtime_observers: vec![
            "callback_register".to_owned(),
            "callback_unregister".to_owned(),
            "object_drop".to_owned(),
            "callback_trigger".to_owned(),
        ],
        oracle_assertions: vec![
            "trace evidence distinguishes callback lifetime state".to_owned(),
            "oracle evidence is scoped to the local controlled harness".to_owned(),
        ],
        replay_evidence_refs: candidate
            .feature_evidence_refs
            .values()
            .flatten()
            .cloned()
            .collect(),
        notes: vec![
            "controlled validation plan; candidate requires follow-up verification".to_owned(),
        ],
    }
}

fn external_buffer_plan_for_candidate(
    run_id: &str,
    candidate: &V326RankedCandidateRecord,
    graph: &V326LifecycleGraphV3Record,
    graph_ref: String,
) -> V326WitnessPlanRecord {
    let chain_refs = external_buffer_chain_refs(graph);
    let graph_refs = if chain_refs.is_empty() {
        graph.evidence_refs.clone()
    } else {
        chain_refs
    };
    let actions = vec![
        V326WitnessAction {
            action_id: format!("action:{}:setup", sanitize_id(&candidate.candidate_id)),
            action_kind: V326WitnessActionKind::SetupControlledFixture,
            graph_refs: graph
                .objects
                .iter()
                .map(|object| object.object_id.clone())
                .collect(),
            notes: vec!["prepare local controlled external-buffer fixture".to_owned()],
        },
        V326WitnessAction {
            action_id: format!(
                "action:{}:invalidate_owner",
                sanitize_id(&candidate.candidate_id)
            ),
            action_kind: V326WitnessActionKind::InvalidateOwner,
            graph_refs: graph_refs.clone(),
            notes: vec!["invalidate or drop the owner-side buffer in the local harness".to_owned()],
        },
        V326WitnessAction {
            action_id: format!("action:{}:miri", sanitize_id(&candidate.candidate_id)),
            action_kind: V326WitnessActionKind::RunMiriCheck,
            graph_refs: graph_refs.clone(),
            notes: vec!["run local Miri check for external-buffer lifetime state".to_owned()],
        },
        V326WitnessAction {
            action_id: format!("action:{}:collect", sanitize_id(&candidate.candidate_id)),
            action_kind: V326WitnessActionKind::CollectOracleEvidence,
            graph_refs,
            notes: vec!["collect local runtime, Miri, and oracle evidence".to_owned()],
        },
    ];

    let mut notes = vec![
        "controlled external-buffer validation plan; candidate requires follow-up verification"
            .to_owned(),
        "route:external_buffer_lifetime".to_owned(),
    ];
    notes.extend(
        graph
            .incomplete_reasons
            .iter()
            .map(|reason| format!("graph_incomplete_reason:{reason}")),
    );
    notes.extend(
        candidate
            .chain_summary
            .chain_incomplete_reasons
            .iter()
            .map(|reason| format!("chain_incomplete_reason:{reason}")),
    );

    V326WitnessPlanRecord {
        schema_version: bw_model::V3_2_6_WITNESS_PLAN_SCHEMA_V1.to_owned(),
        run_id: run_id.to_owned(),
        plan_id: format!("witness-plan:{}", sanitize_id(&candidate.candidate_id)),
        candidate_id: candidate.candidate_id.clone(),
        lifecycle_graph_ref: graph_ref,
        // 由 run() 在生成后按事实解析填充；三个 route 的构造点都不自行猜测 API。
        target: None,
        actions,
        runtime_observers: vec![
            "external_buffer_bind".to_owned(),
            "owner_invalidate_or_drop".to_owned(),
            "external_buffer_use".to_owned(),
            "miri_check".to_owned(),
        ],
        oracle_assertions: vec![
            "trace evidence distinguishes external-buffer lifecycle state".to_owned(),
            "Miri evidence is scoped to the local controlled harness".to_owned(),
        ],
        replay_evidence_refs: candidate
            .feature_evidence_refs
            .values()
            .flatten()
            .cloned()
            .collect(),
        notes,
    }
}

fn returned_view_plan_for_candidate(
    run_id: &str,
    candidate: &V326RankedCandidateRecord,
    graph: &V326LifecycleGraphV3Record,
    graph_ref: String,
) -> V326WitnessPlanRecord {
    let chain_refs = returned_view_chain_refs(graph);
    let graph_refs = if chain_refs.is_empty() {
        graph.evidence_refs.clone()
    } else {
        chain_refs
    };
    let actions = vec![
        V326WitnessAction {
            action_id: format!("action:{}:setup", sanitize_id(&candidate.candidate_id)),
            action_kind: V326WitnessActionKind::SetupControlledFixture,
            graph_refs: graph
                .objects
                .iter()
                .map(|object| object.object_id.clone())
                .collect(),
            notes: vec!["prepare local controlled returned-view fixture".to_owned()],
        },
        V326WitnessAction {
            action_id: format!(
                "action:{}:persist_returned_view",
                sanitize_id(&candidate.candidate_id)
            ),
            action_kind: V326WitnessActionKind::PersistReturnedView,
            graph_refs: graph_refs.clone(),
            notes: vec!["persist returned view in the local harness state".to_owned()],
        },
        V326WitnessAction {
            action_id: format!(
                "action:{}:invalidate_owner",
                sanitize_id(&candidate.candidate_id)
            ),
            action_kind: V326WitnessActionKind::InvalidateOwner,
            graph_refs: graph_refs.clone(),
            notes: vec!["invalidate or drop the owner in the local harness".to_owned()],
        },
        V326WitnessAction {
            action_id: format!(
                "action:{}:use_returned_view",
                sanitize_id(&candidate.candidate_id)
            ),
            action_kind: V326WitnessActionKind::UseReturnedView,
            graph_refs: graph_refs.clone(),
            notes: vec![
                "use the persisted returned view after the controlled transition".to_owned(),
            ],
        },
        V326WitnessAction {
            action_id: format!("action:{}:miri", sanitize_id(&candidate.candidate_id)),
            action_kind: V326WitnessActionKind::RunMiriCheck,
            graph_refs: graph_refs.clone(),
            notes: vec!["run local Miri check for returned-view lifecycle state".to_owned()],
        },
        V326WitnessAction {
            action_id: format!("action:{}:collect", sanitize_id(&candidate.candidate_id)),
            action_kind: V326WitnessActionKind::CollectOracleEvidence,
            graph_refs,
            notes: vec!["collect local runtime, Miri, and oracle evidence".to_owned()],
        },
    ];

    V326WitnessPlanRecord {
        schema_version: bw_model::V3_2_6_WITNESS_PLAN_SCHEMA_V1.to_owned(),
        run_id: run_id.to_owned(),
        plan_id: format!("witness-plan:{}", sanitize_id(&candidate.candidate_id)),
        candidate_id: candidate.candidate_id.clone(),
        lifecycle_graph_ref: graph_ref,
        // 由 run() 在生成后按事实解析填充；三个 route 的构造点都不自行猜测 API。
        target: None,
        actions,
        runtime_observers: vec![
            "returned_view_persist".to_owned(),
            "owner_invalidate".to_owned(),
            "returned_view_use".to_owned(),
            "miri_check".to_owned(),
        ],
        oracle_assertions: vec![
            "trace evidence distinguishes returned-view lifecycle state".to_owned(),
            "Miri evidence is scoped to the local controlled harness".to_owned(),
        ],
        replay_evidence_refs: candidate
            .feature_evidence_refs
            .values()
            .flatten()
            .cloned()
            .collect(),
        notes: vec![
            "controlled returned-view validation plan; candidate requires follow-up verification"
                .to_owned(),
        ],
    }
}

fn returned_view_chain_present(
    graph: &V326LifecycleGraphV3Record,
    candidate: &V326RankedCandidateRecord,
) -> bool {
    candidate
        .risk_features
        .iter()
        .chain(candidate.protective_features.iter())
        .any(|feature| {
            matches!(
                feature.as_str(),
                "has_returned_borrow_relation"
                    | "has_persisted_returned_borrow"
                    | "returned_borrow_persistence_before_invalidation"
                    | "returned_borrow_persistence_after_invalidation"
                    | "has_persisted_invalidation_use_chain"
            )
        })
        || graph.object_chains.iter().any(|chain| {
            chain.object_ids.iter().any(|object_id| {
                object_id.starts_with("returned_ref:") || object_id.starts_with("storage:")
            }) || chain
                .edge_ids
                .iter()
                .any(|edge_id| edge_id.contains("returned_view"))
        })
        || graph.edges.iter().any(|edge| {
            matches!(
                edge.relation,
                bw_model::V326LifecycleRelation::Persist
                    | bw_model::V326LifecycleRelation::Invalidate
                    | bw_model::V326LifecycleRelation::Use
            ) && (edge.from_object_id.starts_with("returned_ref:")
                || edge.to_object_id.starts_with("returned_ref:")
                || edge.from_object_id.starts_with("storage:")
                || edge.to_object_id.starts_with("storage:"))
        })
}

fn external_buffer_chain_present(
    graph: &V326LifecycleGraphV3Record,
    candidate: &V326RankedCandidateRecord,
) -> bool {
    candidate.chain_summary.recommended_witness_route == V326WitnessRoute::ExternalBufferLifetime
        || candidate.pattern_family == bw_model::V32PatternFamily::ExternalBufferView
        || candidate
            .risk_features
            .iter()
            .chain(candidate.protective_features.iter())
            .any(|feature| {
                matches!(
                    feature.as_str(),
                    "has_external_buffer_binding" | "has_external_buffer_lifetime_bound"
                )
            })
        || graph.object_chains.iter().any(|chain| {
            chain.object_ids.iter().any(|object_id| {
                object_id.starts_with("user_data:") || object_id.starts_with("rust_owner:")
            }) && chain
                .fact_refs
                .iter()
                .any(|fact_ref| fact_ref.contains("external"))
        })
        || graph.edges.iter().any(|edge| {
            edge.relation == bw_model::V326LifecycleRelation::RawEscape
                && edge.from_object_id.starts_with("rust_owner:")
                && edge.to_object_id.starts_with("user_data:")
        })
}

fn external_buffer_chain_refs(graph: &V326LifecycleGraphV3Record) -> Vec<String> {
    let mut refs = graph
        .object_chains
        .iter()
        .filter(|chain| {
            chain.object_ids.iter().any(|object_id| {
                object_id.starts_with("user_data:") || object_id.starts_with("rust_owner:")
            }) && chain
                .fact_refs
                .iter()
                .any(|fact_ref| fact_ref.contains("external"))
        })
        .flat_map(|chain| {
            std::iter::once(chain.chain_id.clone())
                .chain(chain.edge_ids.iter().cloned())
                .chain(chain.fact_refs.iter().cloned())
        })
        .collect::<Vec<_>>();
    if refs.is_empty() {
        refs = graph
            .edges
            .iter()
            .filter(|edge| {
                edge.relation == bw_model::V326LifecycleRelation::RawEscape
                    && edge.from_object_id.starts_with("rust_owner:")
                    && edge.to_object_id.starts_with("user_data:")
            })
            .map(|edge| edge.edge_id.clone())
            .collect();
    }
    refs.sort();
    refs.dedup();
    refs
}

fn returned_view_chain_refs(graph: &V326LifecycleGraphV3Record) -> Vec<String> {
    let mut refs = graph
        .object_chains
        .iter()
        .filter(|chain| {
            chain.object_ids.iter().any(|object_id| {
                object_id.starts_with("returned_ref:") || object_id.starts_with("storage:")
            })
        })
        .flat_map(|chain| {
            std::iter::once(chain.chain_id.clone())
                .chain(chain.edge_ids.iter().cloned())
                .chain(chain.fact_refs.iter().cloned())
        })
        .collect::<Vec<_>>();
    if refs.is_empty() {
        refs = graph
            .edges
            .iter()
            .filter(|edge| {
                edge.from_object_id.starts_with("returned_ref:")
                    || edge.to_object_id.starts_with("returned_ref:")
                    || edge.from_object_id.starts_with("storage:")
                    || edge.to_object_id.starts_with("storage:")
            })
            .map(|edge| edge.edge_id.clone())
            .collect();
    }
    refs.sort();
    refs.dedup();
    refs
}

fn resolve_graph_path(
    graphs_dir: &Path,
    candidate: &V326RankedCandidateRecord,
) -> Result<PathBuf, CliError> {
    let ranked_path = Path::new(&candidate.lifecycle_graph_path);
    if ranked_path.is_absolute()
        || ranked_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(CliError::input(
            "BW-V326-WITNESS-GRAPH-PATH",
            "ranked lifecycle_graph_path 必须是相对路径",
        ));
    }
    if let Some(parent) = graphs_dir.parent() {
        let from_ranked = parent.join(ranked_path);
        if from_ranked.is_file() {
            return Ok(from_ranked);
        }
    }
    if let Some(file_name) = ranked_path.file_name() {
        let from_graphs_dir = graphs_dir.join(file_name);
        if from_graphs_dir.is_file() {
            return Ok(from_graphs_dir);
        }
    }
    Ok(graphs_dir.join(format!("{}.json", sanitize_id(&candidate.candidate_id))))
}

fn resolved_graph_ref(graphs_dir: &Path, graph_path: &Path) -> Result<String, CliError> {
    if let Some(parent) = graphs_dir.parent()
        && let Ok(relative) = graph_path.strip_prefix(parent)
    {
        return Ok(relative.to_string_lossy().replace('\\', "/"));
    }
    graph_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            let dir = graphs_dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("graphs-v3");
            format!("{dir}/{name}")
        })
        .ok_or_else(|| {
            CliError::input(
                "BW-V326-WITNESS-GRAPH-PATH",
                format!("无法为 {} 构造相对 graph ref", graph_path.display()),
            )
        })
}

fn edge_refs(graph: &V326LifecycleGraphV3Record, relation: &str) -> Vec<String> {
    let refs = graph
        .edges
        .iter()
        .filter(|edge| format!("{:?}", edge.relation).eq_ignore_ascii_case(relation))
        .map(|edge| edge.edge_id.clone())
        .collect::<Vec<_>>();
    if refs.is_empty() {
        graph.evidence_refs.clone()
    } else {
        refs
    }
}

fn write_records<T: Serialize>(path: &Path, records: &[T]) -> Result<(), CliError> {
    let mut bytes = Vec::<u8>::new();
    for record in records {
        serde_json::to_writer(&mut bytes, record)
            .map_err(|error| CliError::internal(error.to_string()))?;
        bytes.push(b'\n');
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(path)?;
    if path.extension().is_some_and(|extension| extension == "zst") {
        zstd::stream::copy_encode(Cursor::new(bytes), file, 0)
            .map_err(|error| CliError::input("BW-IO", error.to_string()))?;
    } else {
        let mut file = file;
        file.write_all(&bytes)?;
    }
    Ok(())
}

fn write_json_file(path: &Path, value: &impl Serialize) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, value)
        .map_err(|error| CliError::internal(error.to_string()))?;
    file.write_all(b"\n")?;
    Ok(())
}

fn write_checksums(output_dir: &Path, checksums_path: &Path) -> Result<(), CliError> {
    let mut lines = vec![
        format!(
            "{}  {}",
            sha256_file(&output_dir.join("witness-plans.jsonl.zst"))?,
            "witness-plans.jsonl.zst"
        ),
        format!(
            "{}  {}",
            sha256_file(&output_dir.join("witness-plan-stats.json"))?,
            "witness-plan-stats.json"
        ),
    ];
    lines.sort();
    let mut file = File::create(checksums_path)?;
    for line in lines {
        writeln!(file, "{line}")?;
    }
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

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod witness_target_tests {
    use super::*;

    fn apis(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn splits_a_versioned_crate_id() {
        assert_eq!(
            split_crate_id("crate:rusqlite:0.31.0"),
            Some(("rusqlite".to_owned(), "0.31.0".to_owned()))
        );
    }

    #[test]
    fn keeps_a_hyphenated_crate_name_intact() {
        assert_eq!(
            split_crate_id("crate:libsqlite3-sys:0.28.0"),
            Some(("libsqlite3-sys".to_owned(), "0.28.0".to_owned()))
        );
    }

    #[test]
    fn rejects_a_crate_id_without_a_usable_version() {
        assert_eq!(split_crate_id("crate:rusqlite"), None);
        assert_eq!(split_crate_id("rusqlite:0.31.0"), None);
        assert_eq!(split_crate_id("crate:rusqlite:"), None);
    }

    #[test]
    fn binds_when_exactly_one_registration_api_is_known() {
        let target = witness_target_from_parts(
            "candidate:a",
            "crate:rusqlite:0.31.0",
            &apis(&[("candidate:a", "api:rusqlite:update_hook:register")]),
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            None,
        )
        .expect("a single known registration API must bind the plan");
        assert_eq!(target.api_id, "api:rusqlite:update_hook:register");
        assert_eq!(target.crate_name, "rusqlite");
        assert_eq!(target.crate_version, "0.31.0");
    }

    #[test]
    fn refuses_to_bind_without_a_registration_api() {
        assert!(
            witness_target_from_parts(
                "candidate:a",
                "crate:rusqlite:0.31.0",
                &BTreeMap::new(),
                &BTreeMap::new(),
                &BTreeMap::new(),
                None,
                None
            )
            .is_none()
        );
    }

    #[test]
    fn refuses_to_bind_when_registration_apis_conflict() {
        // registration_api_by_candidate 用空串表示"同一候选出现多个不同 API"。
        assert!(
            witness_target_from_parts(
                "candidate:a",
                "crate:rusqlite:0.31.0",
                &apis(&[("candidate:a", "")]),
                &BTreeMap::new(),
                &BTreeMap::new(),
                None,
                None
            )
            .is_none(),
            "an ambiguous API must leave the plan manual-review only rather than pick one"
        );
    }

    #[test]
    fn refuses_to_bind_when_the_crate_id_carries_no_version() {
        assert!(
            witness_target_from_parts(
                "candidate:a",
                "crate:rusqlite",
                &apis(&[("candidate:a", "api:rusqlite:update_hook:register")]),
                &BTreeMap::new(),
                &BTreeMap::new(),
                None,
                None
            )
            .is_none(),
            "a harness cannot declare a dependency without a version"
        );
    }

    fn declaring(entries: &[(&str, &[&str])]) -> BTreeMap<String, BTreeSet<String>> {
        entries
            .iter()
            .map(|(api_id, crates)| {
                (
                    (*api_id).to_owned(),
                    crates.iter().map(|name| (*name).to_owned()).collect(),
                )
            })
            .collect()
    }

    fn resolved(entries: &[(&str, &[(&str, &str)])]) -> BTreeMap<String, BTreeMap<String, String>> {
        entries
            .iter()
            .map(|(crate_id, packages)| {
                (
                    (*crate_id).to_owned(),
                    packages
                        .iter()
                        .map(|(name, version)| ((*name).to_owned(), (*version).to_owned()))
                        .collect(),
                )
            })
            .collect()
    }

    /// 这是自动 0day 扫描的主形状：被扫 crate 只是 rusqlite 的使用者，harness 要链接的
    /// 是 rusqlite 的版本，不是被扫 crate 的版本。
    #[test]
    fn api_crate_is_the_declaring_crate_not_the_scanned_crate() {
        let target = witness_target_from_parts(
            "candidate:a",
            "crate:some_app:0.1.0",
            &apis(&[("candidate:a", "api:rusqlite:update_hook:register")]),
            &declaring(&[("api:rusqlite:update_hook:register", &["rusqlite"])]),
            &resolved(&[("crate:some_app:0.1.0", &[("rusqlite", "0.26.1")])]),
            None,
            None,
        )
        .expect("the plan must still bind");

        assert_eq!(target.crate_name, "some_app");
        assert_eq!(target.crate_version, "0.1.0");
        let api_crate = target
            .api_crate
            .expect("the declaring crate resolved to exactly one dependency");
        assert_eq!(api_crate.name, "rusqlite");
        assert_eq!(
            api_crate.version, "0.26.1",
            "the harness links the API provider's version, never the scanned crate's"
        );
    }

    #[test]
    fn api_crate_is_the_scanned_crate_when_it_declares_the_api_itself() {
        let target = witness_target_from_parts(
            "candidate:a",
            "crate:rusqlite:0.26.1",
            &apis(&[("candidate:a", "api:rusqlite:update_hook:register")]),
            &declaring(&[("api:rusqlite:update_hook:register", &["rusqlite"])]),
            &BTreeMap::new(),
            None,
            None,
        )
        .expect("the plan must still bind");

        let api_crate = target.api_crate.expect("the crate declares the API itself");
        assert_eq!(api_crate.name, "rusqlite");
        assert_eq!(api_crate.version, "0.26.1");
    }

    /// 同一个 api_id 可能被安全封装与 `-sys` 直调同时声明；两个都在依赖里就分不清
    /// 走的是哪条。缺证记录，不猜。
    #[test]
    fn ambiguous_declaring_crates_leave_the_api_crate_unresolved() {
        let target = witness_target_from_parts(
            "candidate:a",
            "crate:some_app:0.1.0",
            &apis(&[("candidate:a", "api:openssl:ssl_set_ex_data:register")]),
            &declaring(&[(
                "api:openssl:ssl_set_ex_data:register",
                &["openssl", "openssl_sys"],
            )]),
            &resolved(&[(
                "crate:some_app:0.1.0",
                &[("openssl", "0.10.66"), ("openssl_sys", "0.9.103")],
            )]),
            None,
            None,
        )
        .expect("an ambiguous provider must not unbind the API itself");

        assert!(
            target.api_crate.is_none(),
            "two possible providers must be recorded as a gap, not guessed between"
        );
    }

    #[test]
    fn missing_dependency_resolution_leaves_the_api_crate_unresolved() {
        let target = witness_target_from_parts(
            "candidate:a",
            "crate:some_app:0.1.0",
            &apis(&[("candidate:a", "api:rusqlite:update_hook:register")]),
            &declaring(&[("api:rusqlite:update_hook:register", &["rusqlite"])]),
            &BTreeMap::new(),
            None,
            None,
        )
        .expect("the API binding does not depend on dependency resolution");

        assert!(target.api_crate.is_none());
    }

    #[test]
    fn declaring_crates_come_from_the_rust_path_not_the_api_id() {
        // api_id 的第二段是家族名，未必等于提供方 crate：openssl 家族由 openssl_sys 提供。
        let temp =
            std::env::temp_dir().join(format!("bw-witness-api-map-{}.toml", std::process::id()));
        fs::write(
            &temp,
            r#"
schema_version = "bw.api-map/0.1"
map_id = "api-map:test"
producer = "boundary-witness@test"
contract_id = "contract:callback-retention"

[[apis]]
api_id = "api:openssl:ssl_set_ex_data:register"
rust_path = "openssl_sys::SSL_set_ex_data"
contract_api_id = "api:register"
callback_family = "openssl_ex_data"
"#,
        )
        .expect("temp api map should be written");

        let declaring = load_api_declaring_crates(&[temp.clone()]).expect("api map should load");
        fs::remove_file(&temp).ok();

        assert_eq!(
            declaring
                .get("api:openssl:ssl_set_ex_data:register")
                .map(|crates| crates.iter().cloned().collect::<Vec<_>>()),
            Some(vec!["openssl_sys".to_owned()]),
            "the provider crate is the rust_path's first segment"
        );
    }
}
