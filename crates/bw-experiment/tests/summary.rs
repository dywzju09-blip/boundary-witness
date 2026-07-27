use bw_experiment::{
    CallbackApi, ExecutionEvidence, PrimaryOutcome, ReplayRecord, summarize_replays,
};

#[test]
fn summary_counts_timeouts_and_keeps_distinct_signatures_separate() {
    let records = vec![
        replay(
            "replay-001",
            PrimaryOutcome::ContractFinding,
            Some("BW-LIFE-001:site-a"),
            evidence(true, false, false, false, false),
        ),
        replay(
            "replay-002",
            PrimaryOutcome::ContractFinding,
            Some("BW-LIFE-001:site-b"),
            evidence(true, false, false, false, false),
        ),
        replay(
            "replay-003",
            PrimaryOutcome::Timeout,
            None,
            evidence(false, false, false, false, true),
        ),
    ];

    let summary = summarize_replays(&records).unwrap();

    assert_eq!(summary.total_replays, 3);
    assert_eq!(summary.buckets.len(), 3);
    assert_eq!(summary.timeout_replays(), 1);

    let site_a = summary
        .bucket(
            CallbackApi::UpdateHook,
            "d0-uh-001",
            "d0-debug",
            PrimaryOutcome::ContractFinding,
            Some("BW-LIFE-001:site-a"),
        )
        .unwrap();
    let site_b = summary
        .bucket(
            CallbackApi::UpdateHook,
            "d0-uh-001",
            "d0-debug",
            PrimaryOutcome::ContractFinding,
            Some("BW-LIFE-001:site-b"),
        )
        .unwrap();
    assert_eq!(site_a.count, 1);
    assert_eq!(site_b.count, 1);
    assert_eq!(site_a.replay_ids, vec!["replay-001"]);
    assert_eq!(site_b.replay_ids, vec!["replay-002"]);

    let timeout = summary
        .bucket(
            CallbackApi::UpdateHook,
            "d0-uh-001",
            "d0-debug",
            PrimaryOutcome::Timeout,
            None,
        )
        .unwrap();
    assert_eq!(timeout.count, 1);
    assert_eq!(timeout.replay_ids, vec!["replay-003"]);
}

fn replay(
    replay_id: &str,
    primary_outcome: PrimaryOutcome,
    finding_signature: Option<&str>,
    evidence: ExecutionEvidence,
) -> ReplayRecord {
    ReplayRecord {
        api: CallbackApi::UpdateHook,
        case_id: "d0-uh-001".to_owned(),
        build_id: "d0-debug".to_owned(),
        replay_id: replay_id.to_owned(),
        primary_outcome,
        finding_signature: finding_signature.map(str::to_owned),
        evidence,
    }
}

fn evidence(
    has_contract_finding: bool,
    has_asan_evidence: bool,
    has_native_crash: bool,
    has_panic: bool,
    has_timeout: bool,
) -> ExecutionEvidence {
    ExecutionEvidence {
        has_contract_finding,
        has_asan_evidence,
        has_native_crash,
        has_panic,
        has_timeout,
    }
}
