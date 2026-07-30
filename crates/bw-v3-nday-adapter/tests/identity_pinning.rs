//! 把两个 adapter 形态的身份钉死。
//!
//! `bw-rusqlite-v3-adapter` 与 `bw-v3-nday-adapter` 曾是两个 crate，452 行 `lib.rs`
//! 只差三个字面量（公开签名域、case root 环境变量名、witness schema_version）。
//! 合并为一个 crate 加两个 bin 之后，这三个值仍必须与合并前逐字节一致——它们进入
//! 公开签名、环境变量约定和 witness 产物，任何改动都会让历史 run 的 checksum 对不上。
//!
//! 已有的 `analyzer_signatures_are_rehashed_for_public_observations` 只断言结果是
//! 64 位小写十六进制，域前缀改了它照样通过。这里断言**具体摘要**。
//!
//! 期望摘要由独立实现算出（`sha256(domain || 0x00 || rule_id || 0x00 || signature)`），
//! 不是从被测代码抄回来的，因此改动实现无法让它自洽。

use bw_model::FindingClassification;
use bw_v3_nday_adapter::{
    AdapterIdentity, ObservationInput, RUSQLITE_V3_ADAPTER, V3_NDAY_ADAPTER,
    observation_from_findings,
};

const RULE_ID: &str = "callback-retention.uaf";
const RAW_SIGNATURE: &str = "callback-retention.uaf:site:runtime-evidence";

fn public_signature_for(identity: &'static AdapterIdentity) -> String {
    let observation = observation_from_findings(ObservationInput {
        identity,
        suite_id: "suite.identity-pinning".to_owned(),
        split: bw_blind_model::BlindSplit::Gate,
        case_id: bw_blind_model::BlindCaseId::parse("blind-0123456789abcdef").unwrap(),
        method_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        public_manifest_sha256: "a".repeat(64),
        findings: vec![(
            RULE_ID.to_owned(),
            FindingClassification::ConfirmedViolation,
            RAW_SIGNATURE.to_owned(),
            true,
        )],
        witness_path: Some("witness/witness.json".to_owned()),
        witness_sha256: Some("c".repeat(64)),
        replay_attempts: 20,
        replay_successes: 20,
    })
    .expect("a confirmed finding with a complete witness maps to an observation");
    observation.findings[0].normalized_signature.clone()
}

#[test]
fn rusqlite_identity_keeps_its_pre_merge_public_signature() {
    assert_eq!(
        RUSQLITE_V3_ADAPTER.signature_domain,
        "bw-rusqlite-v3-adapter.public-signature/0.1"
    );
    assert_eq!(
        RUSQLITE_V3_ADAPTER.case_root_env,
        "BW_RUSQLITE_V3_CASE_ROOT"
    );
    assert_eq!(
        RUSQLITE_V3_ADAPTER.witness_schema_version,
        "bw.rusqlite-v3-witness/0.1"
    );
    assert_eq!(
        public_signature_for(&RUSQLITE_V3_ADAPTER),
        "167bcd888646e7fd05c5f5c7c0fdc7947200b09f58068dc01349e758b5acd999"
    );
}

#[test]
fn generic_identity_keeps_its_pre_merge_public_signature() {
    assert_eq!(
        V3_NDAY_ADAPTER.signature_domain,
        "bw-v3-nday-adapter.public-signature/0.1"
    );
    assert_eq!(V3_NDAY_ADAPTER.case_root_env, "BW_V3_NDAY_CASE_ROOT");
    assert_eq!(
        V3_NDAY_ADAPTER.witness_schema_version,
        "bw.v3-nday-witness/0.1"
    );
    assert_eq!(
        public_signature_for(&V3_NDAY_ADAPTER),
        "eebf20048395de4d63caf2ce6912ca63b10ccaedef6351c707d17d368ab92aa4"
    );
}

/// 两个形态必须产出不同的公开签名。域前缀就是为此存在的：合并实现时若不小心让两
/// 者共用一个域，同一条 finding 在两个 suite 里会撞成同一个签名。
#[test]
fn the_two_identities_do_not_collide() {
    assert_ne!(
        public_signature_for(&RUSQLITE_V3_ADAPTER),
        public_signature_for(&V3_NDAY_ADAPTER)
    );
}
