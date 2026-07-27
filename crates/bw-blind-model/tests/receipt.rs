use bw_blind_model::{
    BLIND_INSTALL_RECEIPT_SCHEMA_V01, BLIND_RUNNER_RECEIPT_SCHEMA_V01, FormalIsolationBackend,
    InstallReceipt, ReceiptTrust, RunnerReceipt, TestReceiptKey, canonical_receipt_json,
};
use sha2::{Digest, Sha256};

const TEST_SECRET_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const METHOD: &str = "0123456789abcdef0123456789abcdef01234567";
const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn install_receipt_signature_detects_tampering() {
    let key = TestReceiptKey::from_hex("test-key", TEST_SECRET_HEX).unwrap();
    let receipt = signed_install_receipt(&key);
    receipt.verify(&key).unwrap();

    let mut tampered = receipt.clone();
    tampered.public_manifest_sha256 = "b".repeat(64);
    let error = tampered.verify(&key).unwrap_err().to_string();
    assert!(error.contains("receipt signature mismatch"), "{error}");
}

#[test]
fn runner_receipt_requires_formal_isolation_backend() {
    let key = TestReceiptKey::from_hex("test-key", TEST_SECRET_HEX).unwrap();
    let mut receipt = signed_runner_receipt(&key);
    receipt.isolation_backend = FormalIsolationBackend::NativeUntrustedSmoke;
    let error = receipt.verify(&key).unwrap_err().to_string();
    assert!(
        error.contains("formal runner receipt requires trusted isolation"),
        "{error}"
    );
}

#[test]
fn native_smoke_receipt_can_be_signed_but_not_verified_as_formal() {
    let key = TestReceiptKey::from_hex("test-key", TEST_SECRET_HEX).unwrap();
    let mut receipt = signed_runner_receipt(&key);
    receipt.isolation_backend = FormalIsolationBackend::NativeUntrustedSmoke;

    key.sign_runner(&mut receipt).unwrap();
    let error = receipt.verify(&key).unwrap_err().to_string();
    assert!(
        error.contains("formal runner receipt requires trusted isolation"),
        "{error}"
    );
}

#[test]
fn runner_receipt_rejects_re_signed_unknown_split() {
    let key = TestReceiptKey::from_hex("test-key", TEST_SECRET_HEX).unwrap();
    let mut receipt = signed_runner_receipt(&key);
    receipt.split = "anything".to_owned();
    re_sign_runner_receipt(&mut receipt);

    let error = receipt.verify(&key).unwrap_err().to_string();
    assert!(
        error.contains("runner receipt split must be gate or evaluation"),
        "{error}"
    );
}

#[test]
fn runner_receipt_schema_allows_only_formal_isolation_backends() {
    let schema_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../experiments/schemas/blind-runner-receipt.schema.json"
    );
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(schema_path).expect("schema should be readable"),
    )
    .expect("schema should be JSON");

    assert_eq!(
        schema["properties"]["isolation_backend"]["enum"],
        serde_json::json!(["container", "cgroup-pid-namespace"])
    );
}

#[test]
fn receipt_rejects_forbidden_public_marker_in_public_fields() {
    let key = TestReceiptKey::from_hex("test-key", TEST_SECRET_HEX).unwrap();
    let mut receipt = signed_runner_receipt(&key);
    receipt.host_id = "runner-with-private-marker".to_owned();
    let error = receipt.verify(&key).unwrap_err().to_string();
    assert!(error.contains("forbidden public token"), "{error}");
}

fn signed_install_receipt(key: &TestReceiptKey) -> InstallReceipt {
    let mut receipt = InstallReceipt {
        schema_version: BLIND_INSTALL_RECEIPT_SCHEMA_V01.to_owned(),
        installer_version: "synthetic-installer-v1".to_owned(),
        installer_commit: METHOD.to_owned(),
        method_commit: METHOD.to_owned(),
        archive_sha256: SHA_A.to_owned(),
        deployment_json_sha256: SHA_A.to_owned(),
        public_manifest_sha256: SHA_A.to_owned(),
        policy_sha256: SHA_A.to_owned(),
        installed_pack_tree_sha256: SHA_A.to_owned(),
        installed_path: "packs/synthetic".to_owned(),
        created_at_utc: "2026-07-19T00:00:00Z".to_owned(),
        host_id: "synthetic-host".to_owned(),
        trust: empty_trust(),
    };
    key.sign_install(&mut receipt).unwrap();
    receipt
}

fn signed_runner_receipt(key: &TestReceiptKey) -> RunnerReceipt {
    let mut receipt = RunnerReceipt {
        schema_version: BLIND_RUNNER_RECEIPT_SCHEMA_V01.to_owned(),
        runner_version: "synthetic-runner-v1".to_owned(),
        runner_commit: METHOD.to_owned(),
        run_id: "synthetic-run-001".to_owned(),
        suite_id: "synthetic-suite".to_owned(),
        split: "gate".to_owned(),
        method_commit: METHOD.to_owned(),
        archive_sha256: SHA_A.to_owned(),
        deployment_json_sha256: SHA_A.to_owned(),
        install_receipt_sha256: SHA_A.to_owned(),
        public_manifest_sha256: SHA_A.to_owned(),
        policy_sha256: SHA_A.to_owned(),
        case_count: 1,
        isolation_backend: FormalIsolationBackend::Container,
        case_execution_snapshot_digest: SHA_B.to_owned(),
        observations_sha256: SHA_A.to_owned(),
        stdout_stderr_digest: SHA_A.to_owned(),
        witness_tree_sha256: SHA_A.to_owned(),
        run_checksums_sha256: SHA_A.to_owned(),
        created_at_utc: "2026-07-19T00:00:00Z".to_owned(),
        host_id: "synthetic-runner".to_owned(),
        trust: empty_trust(),
    };
    key.sign_runner(&mut receipt).unwrap();
    receipt
}

fn empty_trust() -> ReceiptTrust {
    ReceiptTrust {
        key_id: String::new(),
        signature_sha256: String::new(),
    }
}

fn re_sign_runner_receipt(receipt: &mut RunnerReceipt) {
    let mut payload = serde_json::to_value(&*receipt).unwrap();
    payload.as_object_mut().unwrap().remove("trust");
    let canonical_payload = canonical_receipt_json(&payload).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"boundary-witness.receipt-test-signature/0.1\0");
    hasher.update(b"test-key");
    hasher.update(b"\0");
    hasher.update(canonical_payload);
    hasher.update(b"\0");
    hasher.update((0u8..32).collect::<Vec<_>>());

    receipt.trust = ReceiptTrust {
        key_id: "test-key".to_owned(),
        signature_sha256: format!("{:x}", hasher.finalize()),
    };
}
