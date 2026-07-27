use std::{
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
        plans.push(plan_for_candidate(
            &args.run_id,
            candidate,
            &graph,
            graph_ref,
        ));
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
