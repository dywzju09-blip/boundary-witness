use bw_blind_model::BlindPolicy;

fn policy(tokens: &[&str]) -> String {
    let tokens = tokens
        .iter()
        .map(|token| format!("\"{token}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "schema_version = \"boundary-witness.blind-policy/0.1\"\nminimum_replay_attempts = 20\ngate_minimum_confirmed_cases = 1\nforbidden_public_filename_tokens = [{tokens}]\n"
    )
}

#[test]
fn empty_or_weak_policy_cannot_remove_mandatory_public_leak_markers() {
    for tokens in [&[][..], &["cve-"][..], &["custom-only"][..]] {
        let error = BlindPolicy::parse_toml(&policy(tokens))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("mandatory forbidden public token"),
            "{error}"
        );
    }
}

#[test]
fn mandatory_matcher_detects_every_synthetic_sensitive_marker() {
    let policy = BlindPolicy::parse_toml(&policy(&[
        "ground-truth",
        "ground_truth",
        "cve-",
        "ghsa-",
        "advisory",
        "poc",
        "proof-of-concept",
        "proof_of_concept",
        "expected-result",
        "expected_result",
        "expected result",
        "private",
    ]))
    .unwrap();

    for marker in [
        "synthetic-cve-marker",
        "synthetic-ghsa-marker",
        "synthetic-poc-marker",
        "synthetic-advisory-marker",
        "synthetic-expected-result-marker",
        "synthetic-private-marker",
    ] {
        assert!(
            policy.find_forbidden_public_token(marker).is_some(),
            "mandatory matcher missed {marker}"
        );
    }
}

#[test]
fn poc_marker_requires_token_boundaries_without_rejecting_epoch() {
    let policy = BlindPolicy::parse_toml(&policy(&[
        "ground-truth",
        "ground_truth",
        "cve-",
        "ghsa-",
        "advisory",
        "poc",
        "proof-of-concept",
        "proof_of_concept",
        "expected-result",
        "expected_result",
        "expected result",
        "private",
    ]))
    .unwrap();

    assert_eq!(policy.find_forbidden_public_token("epoch"), None);
    assert_eq!(policy.find_forbidden_public_token("spock"), None);

    for marker in ["poc", "synthetic-poc-marker", "case/POC/input"] {
        assert_eq!(
            policy.find_forbidden_public_token(marker),
            Some("poc"),
            "mandatory matcher missed bounded poc marker in {marker}"
        );
    }
}
