use std::{
    env,
    error::Error,
    fs,
    io::Write,
    iter::Peekable,
    path::{Path, PathBuf},
    process::ExitCode,
};

use bw_experiment::{
    ActionDecodeOptions, ActionSequence, ApiKind, CorpusPolicy, D1CampaignOutcome,
    D1CampaignRecord, D2BaselineConfigFile, D2BaselineGroupKind, MinimizedArtifact,
    ObjectiveClassification, ObjectiveClassifier, ObjectiveKind, ObjectiveObservation,
    ObjectivePolicy, RandomBaselineObservation, RandomBaselineRunner, ReplayConfig, ReplaySummary,
};
use bw_model::ExecutionEvidence;
use rusqlite_lab_shared::fuzzing::{
    evaluate_scalar_function_objective, evaluate_update_hook_objective,
    minimize_scalar_function_sequence, minimize_update_hook_sequence,
    replay_scalar_function_sequence, replay_update_hook_sequence,
    run_update_hook_sequence_with_observer, HarnessOutcome,
};
use serde::Deserialize;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bw-rusqlite-d1: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1).peekable();
    match args.next().as_deref() {
        Some("decode") => {
            let input = required_path(&mut args, "raw input path")?;
            let output = required_path(&mut args, "action json output path")?;
            let raw = fs::read(&input)?;
            let sequence = ActionSequence::decode_bytes(
                &raw,
                ActionDecodeOptions {
                    max_actions: 32,
                    source: "bw-rusqlite-d1 decode".to_owned(),
                },
            );
            write_json(&output, &sequence)?;
        }
        Some("materialize-corpus") => {
            let input = required_path(&mut args, "safe corpus jsonl path")?;
            let output_dir = required_path(&mut args, "raw corpus output directory")?;
            materialize_corpus(&input, &output_dir)?;
        }
        Some("d2-random-records") => {
            let config = required_path(&mut args, "D2 baseline config path")?;
            let records_root = required_path(&mut args, "D2 records root")?;
            write_d2_random_records(&config, &records_root)?;
        }
        Some("d2-coverage-record") => {
            let config = required_path(&mut args, "D2 baseline config path")?;
            let group = required_string(&mut args, "D2 coverage group")?;
            let records_root = required_path(&mut args, "D2 records root")?;
            let campaign_index = required_parse(&mut args, "campaign index")?;
            let seed = required_parse(&mut args, "campaign seed")?;
            let counters = required_path(&mut args, "counters json path")?;
            let artifact_dir = required_path(&mut args, "artifact directory")?;
            let fuzz_exit_status = required_parse(&mut args, "fuzz exit status")?;
            let elapsed_ms = required_parse(&mut args, "elapsed ms")?;
            write_d2_coverage_record(D2CoverageRecordInput {
                config_path: &config,
                group: &group,
                records_root: &records_root,
                campaign_index,
                seed,
                counters_path: &counters,
                artifact_dir: &artifact_dir,
                fuzz_exit_status,
                elapsed_ms,
            })?;
        }
        Some("evaluate") => {
            let api = parse_optional_api(&mut args)?;
            let input = required_path(&mut args, "action json path")?;
            let sequence = read_action_sequence(&input)?;
            let classification = evaluate_objective(api, &sequence)?;
            serde_json::to_writer_pretty(std::io::stdout(), &classification)?;
            println!();
        }
        Some("minimize") => {
            let api = parse_optional_api(&mut args)?;
            let input = required_path(&mut args, "action json path")?;
            let output = required_path(&mut args, "minimized output path")?;
            let sequence = read_action_sequence(&input)?;
            let minimized = minimize_sequence(api, &sequence)?;
            write_json(&output, &minimized)?;
        }
        Some("replay") => {
            let api = parse_optional_api(&mut args)?;
            let input = required_path(&mut args, "action or minimized json path")?;
            let output = required_path(&mut args, "replay summary output path")?;
            let repeat_count = parse_repeat_count(args)?;
            let (sequence, classification) = read_sequence_and_objective(&input, api)?;
            let summary = replay_sequence(api, &sequence, &classification, repeat_count)?;
            write_json(&output, &summary)?;
            if !summary.stable {
                return Err(
                    "replay did not reproduce the target objective in every attempt".into(),
                );
            }
        }
        _ => {
            eprintln!(
                "usage:\n  bw-rusqlite-d1 decode <raw-input> <actions.json>\n  bw-rusqlite-d1 evaluate [--api update_hook|create_scalar_function] <actions.json>\n  bw-rusqlite-d1 minimize [--api update_hook|create_scalar_function] <actions.json> <minimized.json>\n  bw-rusqlite-d1 replay [--api update_hook|create_scalar_function] <actions-or-minimized.json> <summary.json> [--repeat N]"
            );
            eprintln!(
                "  bw-rusqlite-d1 materialize-corpus <safe-fragments.jsonl> <raw-corpus-dir>"
            );
            eprintln!("  bw-rusqlite-d1 d2-random-records <d2-baselines.toml> <records-root>");
            eprintln!(
                "  bw-rusqlite-d1 d2-coverage-record <d2-baselines.toml> <coverage_only|coverage_state> <records-root> <campaign-index> <seed> <counters.json> <artifact-dir> <fuzz-exit-status> <elapsed-ms>"
            );
            return Err("invalid command".into());
        }
    }
    Ok(())
}

struct D2CoverageRecordInput<'a> {
    config_path: &'a Path,
    group: &'a str,
    records_root: &'a Path,
    campaign_index: usize,
    seed: u64,
    counters_path: &'a Path,
    artifact_dir: &'a Path,
    fuzz_exit_status: i32,
    elapsed_ms: u64,
}

fn write_d2_coverage_record(input: D2CoverageRecordInput<'_>) -> Result<(), Box<dyn Error>> {
    let config = D2BaselineConfigFile::from_path(input.config_path)?;
    let group = parse_d2_coverage_group(input.group)?;
    if !config.groups.contains(&group) {
        return Err(format!("D2 config does not enable {} group", group_dir(group)).into());
    }
    if !config.shared_budget.seed_list.contains(&input.seed) {
        return Err(format!(
            "campaign seed {} is not in shared_budget.seed_list",
            input.seed
        )
        .into());
    }

    let group_config = coverage_record_config(&config, group)?;
    let counters = read_fuzz_counters(input.counters_path)?;
    let group_root = input.records_root.join(group_dir(group));
    fs::create_dir_all(&group_root)?;
    let campaign_dir = input
        .artifact_dir
        .parent()
        .unwrap_or(input.artifact_dir)
        .to_path_buf();
    let artifact_path = first_artifact_path(input.artifact_dir)?;

    let mut representative_artifact_digest = None;
    let mut minimized_len = None;
    let mut replay_success_count = None;
    let outcome = if let Some(artifact_path) = artifact_path {
        let raw = fs::read(&artifact_path)?;
        representative_artifact_digest = Some(sha256_hex(&raw));
        let sequence = ActionSequence::decode_bytes(
            &raw,
            ActionDecodeOptions {
                max_actions: group_config.max_sequence_len,
                source: format!("libfuzzer:{}", group_config.target),
            },
        );
        write_json(&campaign_dir.join("decoded-actions.json"), &sequence)?;
        let minimized = minimize_sequence(group_config.api, &sequence)?;
        minimized_len = Some(minimized.report.minimized_len);
        write_json(&campaign_dir.join("minimized.json"), &minimized)?;
        let replay = replay_sequence(
            group_config.api,
            &minimized.sequence,
            &minimized.classification,
            group_config.replay_repeat_count,
        )?;
        replay_success_count = Some(replay.success_count);
        write_json(&campaign_dir.join("replay-summary.json"), &replay)?;
        D1CampaignOutcome::PrimaryFound
    } else if input.fuzz_exit_status == 0 {
        D1CampaignOutcome::Timeout
    } else {
        D1CampaignOutcome::ToolError
    };

    let primary_count = if outcome == D1CampaignOutcome::PrimaryFound && counters.primary_count == 0
    {
        1
    } else {
        counters.primary_count
    };
    let time_to_first_primary_ms = counters
        .time_to_first_primary_ms
        .or_else(|| (outcome == D1CampaignOutcome::PrimaryFound).then_some(input.elapsed_ms));
    let record = D1CampaignRecord {
        campaign_id: format!("{}-{:03}", group_config.baseline_id, input.campaign_index),
        api: group_config.api,
        target: group_config.target,
        seed: input.seed,
        cpu_minutes: group_config.cpu_minutes,
        executions: counters.executions,
        valid_sequence_count: counters.valid_sequence_count,
        invalid_sequence_count: counters.invalid_sequence_count,
        progress_count: counters.progress_count,
        secondary_count: counters.secondary_count,
        primary_count,
        time_to_first_primary_ms,
        minimized_len,
        replay_success_count,
        representative_artifact_digest,
        outcome,
    };

    let records_path = group_root.join("campaign-records.jsonl");
    let mut records_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&records_path)?;
    writeln!(records_file, "{}", serde_json::to_string(&record)?)?;
    add_progress_state_coverage(&group_root, counters.feedback_snapshot_coverage_count)?;
    Ok(())
}

#[derive(Clone, Debug)]
struct D2CoverageRecordConfig {
    baseline_id: String,
    api: ApiKind,
    target: String,
    cpu_minutes: u64,
    max_sequence_len: usize,
    replay_repeat_count: usize,
}

fn coverage_record_config(
    config: &D2BaselineConfigFile,
    group: D2BaselineGroupKind,
) -> Result<D2CoverageRecordConfig, Box<dyn Error>> {
    match group {
        D2BaselineGroupKind::CoverageOnly => {
            let coverage = config
                .coverage_only
                .as_ref()
                .ok_or("missing [coverage_only] group config")?;
            Ok(D2CoverageRecordConfig {
                baseline_id: coverage.baseline_id.clone(),
                api: coverage.api,
                target: coverage.target.clone(),
                cpu_minutes: coverage.cpu_minutes,
                max_sequence_len: coverage.max_sequence_len,
                replay_repeat_count: coverage.replay_repeat_count,
            })
        }
        D2BaselineGroupKind::CoverageState => {
            let state = config
                .coverage_state
                .as_ref()
                .ok_or("missing [coverage_state] group config")?;
            Ok(D2CoverageRecordConfig {
                baseline_id: state.baseline_id.clone(),
                api: state.api,
                target: state.target.clone(),
                cpu_minutes: state.cpu_minutes,
                max_sequence_len: state.max_sequence_len,
                replay_repeat_count: state.replay_repeat_count,
            })
        }
        D2BaselineGroupKind::RandomAction => Err("random_action is not a coverage group".into()),
    }
}

#[derive(Debug, Deserialize)]
struct FuzzCounters {
    executions: u64,
    valid_sequence_count: u64,
    invalid_sequence_count: u64,
    progress_count: u64,
    secondary_count: u64,
    primary_count: u64,
    time_to_first_primary_ms: Option<u64>,
    #[serde(default)]
    feedback_snapshot_coverage_count: u64,
}

fn read_fuzz_counters(path: &Path) -> Result<FuzzCounters, Box<dyn Error>> {
    let counters = serde_json::from_str::<FuzzCounters>(&fs::read_to_string(path)?)?;
    if counters.valid_sequence_count + counters.invalid_sequence_count != counters.executions {
        return Err(format!(
            "counter valid+invalid counts do not equal executions in {}",
            path.display()
        )
        .into());
    }
    Ok(counters)
}

fn first_artifact_path(dir: &Path) -> Result<Option<PathBuf>, Box<dyn Error>> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut files = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    files.sort();
    Ok(files.into_iter().next())
}

fn add_progress_state_coverage(group_root: &Path, delta: u64) -> Result<(), Box<dyn Error>> {
    let path = group_root.join("progress-state-coverage.txt");
    let current = if path.exists() {
        fs::read_to_string(&path)?.trim().parse::<u64>()?
    } else {
        0
    };
    fs::write(path, format!("{}\n", current.saturating_add(delta)))?;
    Ok(())
}

fn parse_d2_coverage_group(value: &str) -> Result<D2BaselineGroupKind, Box<dyn Error>> {
    match value {
        "coverage_only" => Ok(D2BaselineGroupKind::CoverageOnly),
        "coverage_state" => Ok(D2BaselineGroupKind::CoverageState),
        other => Err(format!("unsupported D2 coverage group: {other}").into()),
    }
}

fn group_dir(group: D2BaselineGroupKind) -> &'static str {
    match group {
        D2BaselineGroupKind::RandomAction => "random_action",
        D2BaselineGroupKind::CoverageOnly => "coverage_only",
        D2BaselineGroupKind::CoverageState => "coverage_state",
    }
}

fn write_d2_random_records(config_path: &Path, records_root: &Path) -> Result<(), Box<dyn Error>> {
    let config = D2BaselineConfigFile::from_path(config_path)?;
    if !config.groups.contains(&D2BaselineGroupKind::RandomAction) {
        return Err("D2 config does not enable random_action group".into());
    }
    if config.shared_budget.seed_list.len() != config.shared_budget.campaign_count as usize {
        return Err(format!(
            "shared_budget.seed_list length {} must equal campaign_count {} for D2 random records",
            config.shared_budget.seed_list.len(),
            config.shared_budget.campaign_count
        )
        .into());
    }

    let group_root = records_root.join("random_action");
    let artifacts_root = group_root.join("artifacts");
    fs::create_dir_all(&artifacts_root)?;
    let records_path = group_root.join("campaign-records.jsonl");
    let mut records = Vec::new();
    let mut progress_state_coverage = 0u64;

    for (index, seed) in config.shared_budget.seed_list.iter().copied().enumerate() {
        let mut random_config = config.random_action.clone();
        random_config.seed = seed;
        random_config.artifact_dir = artifacts_root.join(format!("campaign-{index:03}"));
        let runner = RandomBaselineRunner::new(random_config);
        let classifier = ObjectiveClassifier::new(ObjectivePolicy::callback_lifetime_default());
        let summary = runner.run(|sequence| random_observation(sequence, &classifier))?;
        progress_state_coverage =
            progress_state_coverage.saturating_add(summary.feedback_snapshot_coverage_count);
        records.push(D1CampaignRecord {
            campaign_id: format!("{}-{index:03}", summary.baseline_id),
            api: summary.api,
            target: summary.target,
            seed: summary.seed,
            cpu_minutes: summary.cpu_minutes,
            executions: summary.executions,
            valid_sequence_count: summary.valid_sequence_count,
            invalid_sequence_count: summary.invalid_sequence_count,
            progress_count: summary.progress_count,
            secondary_count: summary.secondary_count,
            primary_count: summary.primary_count,
            time_to_first_primary_ms: summary.time_to_first_primary_ms,
            minimized_len: summary.minimized_len,
            replay_success_count: summary.replay_success_count,
            representative_artifact_digest: summary.representative_artifact_digest,
            outcome: if summary.primary_count > 0 {
                D1CampaignOutcome::PrimaryFound
            } else {
                D1CampaignOutcome::NoPrimary
            },
        });
    }

    let mut body = String::new();
    for record in records {
        body.push_str(&serde_json::to_string(&record)?);
        body.push('\n');
    }
    fs::write(records_path, body)?;
    fs::write(
        group_root.join("progress-state-coverage.txt"),
        format!("{progress_state_coverage}\n"),
    )?;
    Ok(())
}

fn random_observation(
    sequence: &ActionSequence,
    classifier: &ObjectiveClassifier,
) -> RandomBaselineObservation {
    let Ok(result) = run_update_hook_sequence_with_observer(sequence) else {
        return RandomBaselineObservation {
            valid_sequence: false,
            objective: none_objective(),
            replay_success_count: None,
            feedback_key: None,
        };
    };
    let classification = classifier.classify(&ObjectiveObservation {
        evidence: ExecutionEvidence {
            has_contract_finding: !result.findings.is_empty(),
            has_asan_evidence: false,
            has_native_crash: false,
            has_panic: false,
            has_timeout: false,
        },
        findings: result.findings,
    });
    let feedback_key = result
        .feedback_snapshot
        .as_ref()
        .map(|snapshot| snapshot.feedback_key().to_owned())
        .filter(|key| !key.is_empty());
    RandomBaselineObservation {
        valid_sequence: result.outcome != HarnessOutcome::InvalidInput,
        objective: classification,
        replay_success_count: None,
        feedback_key,
    }
}

fn none_objective() -> ObjectiveClassification {
    ObjectiveClassification {
        objective_kind: ObjectiveKind::None,
        primary_rule_id: None,
        normalized_signature: None,
        progress_states: Vec::new(),
        secondary_findings: Vec::new(),
        evidence_refs: Vec::new(),
    }
}

fn materialize_corpus(input: &Path, output_dir: &Path) -> Result<(), Box<dyn Error>> {
    let jsonl = fs::read_to_string(input)?;
    CorpusPolicy.audit_jsonl_str(&jsonl)?;
    if output_dir.exists() && fs::read_dir(output_dir)?.next().is_some() {
        return Err(format!(
            "raw corpus output directory must be empty: {}",
            output_dir.display()
        )
        .into());
    }
    fs::create_dir_all(output_dir)?;
    for (index, line) in jsonl
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let sequence = ActionSequence::from_json_str(line)?;
        let output = output_dir.join(format!("seed-{index:06}"));
        fs::write(output, sequence.encode_seed_bytes())?;
    }
    Ok(())
}

fn read_sequence_and_objective(
    path: &Path,
    api: ApiKind,
) -> Result<(ActionSequence, ObjectiveClassification), Box<dyn Error>> {
    let input = fs::read_to_string(path)?;
    if let Ok(minimized) = serde_json::from_str::<MinimizedArtifact>(&input) {
        return Ok((minimized.sequence, minimized.classification));
    }
    let sequence = ActionSequence::from_json_str(&input)?;
    let classification = evaluate_objective(api, &sequence)?;
    Ok((sequence, classification))
}

fn read_action_sequence(path: &Path) -> Result<ActionSequence, Box<dyn Error>> {
    Ok(ActionSequence::from_json_str(&fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = fs::File::create(path)?;
    serde_json::to_writer_pretty(file, value)?;
    Ok(())
}

fn parse_repeat_count(args: impl Iterator<Item = String>) -> Result<usize, Box<dyn Error>> {
    let mut repeat_count = 20usize;
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--repeat" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --repeat".to_owned())?;
                repeat_count = value.parse()?;
            }
            other => return Err(format!("unexpected argument: {other}").into()),
        }
    }
    Ok(repeat_count)
}

fn parse_optional_api(
    args: &mut Peekable<impl Iterator<Item = String>>,
) -> Result<ApiKind, Box<dyn Error>> {
    let Some(flag) = args.peek() else {
        return Ok(ApiKind::UpdateHook);
    };
    if flag != "--api" {
        return Ok(ApiKind::UpdateHook);
    }
    args.next();
    let value = args
        .next()
        .ok_or_else(|| "missing value for --api".to_owned())?;
    match value.as_str() {
        "update_hook" => Ok(ApiKind::UpdateHook),
        "create_scalar_function" => Ok(ApiKind::CreateScalarFunction),
        other => Err(format!("unsupported --api value: {other}").into()),
    }
}

fn evaluate_objective(
    api: ApiKind,
    sequence: &ActionSequence,
) -> Result<ObjectiveClassification, Box<dyn Error>> {
    match api {
        ApiKind::UpdateHook => Ok(evaluate_update_hook_objective(sequence)?),
        ApiKind::CreateScalarFunction => Ok(evaluate_scalar_function_objective(sequence)?),
    }
}

fn minimize_sequence(
    api: ApiKind,
    sequence: &ActionSequence,
) -> Result<MinimizedArtifact, Box<dyn Error>> {
    match api {
        ApiKind::UpdateHook => Ok(minimize_update_hook_sequence(sequence)?),
        ApiKind::CreateScalarFunction => Ok(minimize_scalar_function_sequence(sequence)?),
    }
}

fn replay_sequence(
    api: ApiKind,
    sequence: &ActionSequence,
    classification: &ObjectiveClassification,
    repeat_count: usize,
) -> Result<ReplaySummary, Box<dyn Error>> {
    let config = ReplayConfig { repeat_count };
    match api {
        ApiKind::UpdateHook => Ok(replay_update_hook_sequence(
            sequence,
            classification,
            config,
        )?),
        ApiKind::CreateScalarFunction => Ok(replay_scalar_function_sequence(
            sequence,
            classification,
            config,
        )?),
    }
}

fn required_path(
    args: &mut impl Iterator<Item = String>,
    label: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {label}").into())
}

fn required_string(
    args: &mut impl Iterator<Item = String>,
    label: &str,
) -> Result<String, Box<dyn Error>> {
    args.next().ok_or_else(|| format!("missing {label}").into())
}

fn required_parse<T>(
    args: &mut impl Iterator<Item = String>,
    label: &str,
) -> Result<T, Box<dyn Error>>
where
    T: std::str::FromStr,
    T::Err: Error + 'static,
{
    Ok(required_string(args, label)?.parse()?)
}

fn sha256_hex(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    Sha256::digest(input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
