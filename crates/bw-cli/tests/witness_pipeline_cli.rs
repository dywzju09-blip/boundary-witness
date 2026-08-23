//! P4 CLI 链路的集成测试：真实 wire 格式的判定/契约记录走完
//! plan-witnesses → generate-safe-client，控制矩阵的配置错误必须被拒绝。
//!
//! 判定与契约记录取自 2026-08-08 的 fixture run（结构不变，身份字段是确定性字符串），
//! 保证测试钉住的是**真实的 wire 契约**而不是测试手造的理想化形状。

use assert_cmd::Command;
use predicates::str::contains;

const RUN_ID: &str = "p4-fixture-2026-08-08";

const JOINT_LINE: &str = r#"{"schema_version":"bw.joint-verdict/0.1","run_id":"p4-fixture-2026-08-08","api_id":"Registry::register_borrowed","outcome":{"outcome":"joined","hand_off":{"rust_artifact":"callback-retention-relation@fixture","foreign_artifact":"callback-retention/retain_late_invoke_leaky","build_profile":"fixture-debug","safe_entry_instance":"Registry::register_borrowed","rust_def_instance":"Registry::register_borrowed","call_occurrence":"site:bbdbdd2428938a199299b948bd45d92c63baf466595c4e0262fcd5c3ef1f0085","foreign_symbol":"fixture_register","callback_arg_index":0,"userdata_arg_index":1,"registration_key":null,"registration_generation":"multiple_static_sites"},"slots":[{"base":{"kind":"global","symbol":"g_cached_callback"}},{"base":{"kind":"global","symbol":"g_cached_user_data"}},{"base":{"kind":"global","symbol":"g_callback"}},{"base":{"kind":"global","symbol":"g_user_data"}}],"verdicts":[{"hand_off":{"rust_artifact":"callback-retention-relation@fixture","foreign_artifact":"callback-retention/retain_late_invoke_leaky","build_profile":"fixture-debug","safe_entry_instance":"Registry::register_borrowed","rust_def_instance":"Registry::register_borrowed","call_occurrence":"site:bbdbdd2428938a199299b948bd45d92c63baf466595c4e0262fcd5c3ef1f0085","foreign_symbol":"fixture_register","callback_arg_index":0,"userdata_arg_index":1,"registration_key":null,"registration_generation":"multiple_static_sites"},"subject":"captured_referent","static_verdict":"insufficient_evidence","evidence_grade":"same_slot_invoke_candidate","witness_status":"not_attempted","witness_obligation":"establish_late_invoke","assumptions":["the same foreign symbol is registered from more than one static site; attributing a runtime registration to this one needs a witness","late invoke supported only by same-slot indirect call; reachability must be established by a witness"]},{"hand_off":{"rust_artifact":"callback-retention-relation@fixture","foreign_artifact":"callback-retention/retain_late_invoke_leaky","build_profile":"fixture-debug","safe_entry_instance":"Registry::register_borrowed","rust_def_instance":"Registry::register_borrowed","call_occurrence":"site:bbdbdd2428938a199299b948bd45d92c63baf466595c4e0262fcd5c3ef1f0085","foreign_symbol":"fixture_register","callback_arg_index":0,"userdata_arg_index":1,"registration_key":null,"registration_generation":"multiple_static_sites"},"subject":"callback_allocation","static_verdict":"compatible_within_analyzed_fragment","evidence_grade":null,"witness_status":"not_attempted","witness_obligation":null,"assumptions":["the same foreign symbol is registered from more than one static site; attributing a runtime registration to this one needs a witness"]}]}}"#;

const CONTRACT_LINE: &str = r#"{"schema_version":"bw.rust-contract/0.1","run_id":"p4-fixture-2026-08-08","api_id":"Registry::register_borrowed","foreign_symbol":"fixture_register","contract":{"allocation":"foreign_owned_until_unregister","capture_admission":"permits_non_static_capture","evidence":["site:7f7165a775cc5a965faaed59041d86d30fde3629b14db7d6b7314065dbb65427","site:a56f199dcd9847f28827f55e33c0bb0297f68f329a061e89b4b7968ccb13b555","site:bbdbdd2428938a199299b948bd45d92c63baf466595c4e0262fcd5c3ef1f0085","site:c97e040f28741b5dc325ae83ea100ea95a8009845bb50586f3d1f506390cadde","site:f2da613ba4183af830e35b91eea2e81bd9ccebe5bccbbc65b46cbfcc95d8d098"],"guard":"none","hand_off":{"build_profile":"fixture-debug","call_occurrence":"site:bbdbdd2428938a199299b948bd45d92c63baf466595c4e0262fcd5c3ef1f0085","callback_arg_index":0,"foreign_symbol":"fixture_register","registration_generation":"multiple_static_sites","rust_artifact":"callback-retention-relation@fixture","rust_def_instance":"Registry::register_borrowed","safe_entry_instance":"Registry::register_borrowed","userdata_arg_index":1}}}"#;

const ADAPTER: &str = r#"
schema_version = "bw.adapter/0.1"
adapter_id = "adapter:test"

[target]
crate = "callback-retention-relation"
version = "0.1.0"
path_from_repo_root = "component"
edition = "2024"

[[setup]]
step = "construct_registry"
rust = "let registry = callback_retention_relation::Registry;"

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
id = "retain_late_invoke_leaky"
source = "foreign/leaky.c"

[[foreign_build]]
id = "synchronous_only"
source = "foreign/sync.c"
provides_trigger_symbol = false

[teardown]
step = "drop_registry"
rust = "drop(registry);"
"#;

fn write_pipeline_inputs(temp: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let joint = temp.join("joint-verdicts.jsonl");
    let contracts = temp.join("rust-contracts.jsonl");
    std::fs::write(&joint, format!("{JOINT_LINE}\n")).unwrap();
    std::fs::write(&contracts, format!("{CONTRACT_LINE}\n")).unwrap();
    (joint, contracts)
}

#[test]
fn plan_witnesses_derives_plans_from_a_real_joined_trace() {
    let temp = tempfile::tempdir().unwrap();
    let (joint, contracts) = write_pipeline_inputs(temp.path());

    let output_dir = temp.path().join("plans");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "plan-witnesses",
            "--joint-verdicts",
            joint.to_str().unwrap(),
            "--rust-contracts",
            contracts.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--run-id",
            RUN_ID,
        ])
        .assert()
        .success()
        .stdout(contains("\"planned\":1"));

    let plans = std::fs::read_to_string(output_dir.join("witness-plans.jsonl")).unwrap();
    assert!(plans.contains("\"input_kind\":\"establish_late_invoke\""));
    assert!(plans.contains("\"shape\":\"borrowed_capture_escaping_scope\""));
    // 计划必须携带完整交出点身份供回查。
    assert!(plans.contains("fixture_register"));
    // 相容判定（callback_allocation）被拒绝并留痕：拒绝也是产物。
    let refusals = std::fs::read_to_string(output_dir.join("witness-plan-refusals.jsonl")).unwrap();
    assert!(refusals.contains("verdict_compatible_nothing_to_witness"));
}

#[test]
fn plan_witnesses_rejects_run_id_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let (joint, contracts) = write_pipeline_inputs(temp.path());

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "plan-witnesses",
            "--joint-verdicts",
            joint.to_str().unwrap(),
            "--rust-contracts",
            contracts.to_str().unwrap(),
            "--output-dir",
            temp.path().join("out").to_str().unwrap(),
            "--run-id",
            "some-other-run",
        ])
        .assert()
        .code(2)
        .stderr(contains("BW-WITNESS-PLAN-INPUT"));
}

#[test]
fn generate_safe_client_emits_forbidden_unsafe_crates_with_step_markers() {
    let temp = tempfile::tempdir().unwrap();
    // 组件目录：生成器要求 repo-root 下存在可解析的组件 crate。
    std::fs::create_dir_all(temp.path().join("component")).unwrap();
    std::fs::write(
        temp.path().join("component").join("Cargo.toml"),
        "[package]\nname = \"callback-retention-relation\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();

    // 先产出计划。
    let (joint, contracts) = write_pipeline_inputs(temp.path());
    let plans_dir = temp.path().join("plans");
    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "plan-witnesses",
            "--joint-verdicts",
            joint.to_str().unwrap(),
            "--rust-contracts",
            contracts.to_str().unwrap(),
            "--output-dir",
            plans_dir.to_str().unwrap(),
            "--run-id",
            RUN_ID,
        ])
        .assert()
        .success();

    let adapter_path = temp.path().join("adapter.toml");
    std::fs::write(&adapter_path, ADAPTER).unwrap();
    let clients_dir = temp.path().join("clients");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "generate-safe-client",
            "--plans",
            plans_dir.join("witness-plans.jsonl").to_str().unwrap(),
            "--adapter",
            adapter_path.to_str().unwrap(),
            "--output-dir",
            clients_dir.to_str().unwrap(),
            "--repo-root",
            temp.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(contains("\"generated\":2"));

    // primary 与 no-trigger 两个变体；primary 必须带触发步与 forbid 属性，
    // 且闭包体是对失效内存的真实解引用加载——传引用读不到已释放内存，oracle 会瞎。
    for entry in std::fs::read_dir(&clients_dir).unwrap().flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy().to_string();
        if !name.starts_with("witness_") {
            continue;
        }
        let main_rs = std::fs::read_to_string(entry.path().join("src").join("main.rs")).unwrap();
        assert!(main_rs.starts_with("#![forbid(unsafe_code)]"), "{name}");
        assert!(main_rs.contains("// @STEP@ "), "{name}");
        if name.ends_with("-no-trigger") {
            assert!(!main_rs.contains(".fire();"), "{name}");
        } else {
            assert!(main_rs.contains(".fire();"), "{name}");
            assert!(main_rs.contains("black_box(*payload)"), "{name}");
        }
    }
}

const MINIMAL_MANIFEST: &str = r#"{"schema_version":"bw.safe-client/0.1","run_id":"r","adapter_id":"a","component_crate":"c","component_version":null,"output_root":"/tmp","generated":[],"refused":[],"foreign_builds":[{"id":"x","source":"x.c","source_sha256":"aa","provides_trigger_symbol":true}],"notes":[]}"#;

fn write_minimal_clients_dir(temp: &std::path::Path) -> std::path::PathBuf {
    let clients_dir = temp.join("clients");
    std::fs::create_dir_all(&clients_dir).unwrap();
    std::fs::write(
        clients_dir.join("generation-manifest.json"),
        MINIMAL_MANIFEST,
    )
    .unwrap();
    std::fs::write(clients_dir.join("clients.jsonl"), "").unwrap();
    clients_dir
}

/// 产物必须带 checksums.sha256，且 verify-run 能用该清单核对整个目录；
/// 篡改一个字节必须在预期错误码上失败。这是 stage6 收口的契约：
/// 「历史结果不自动证明当前 commit」由逐字节核对兜底。
#[test]
fn plan_output_is_checksummed_and_verify_run_catches_tampering() {
    let temp = tempfile::tempdir().unwrap();
    let (joint, contracts) = write_pipeline_inputs(temp.path());
    let output_dir = temp.path().join("plans");

    let assert = |output_dir: &std::path::Path| {
        Command::cargo_bin("bw")
            .unwrap()
            .args([
                "plan-witnesses",
                "--joint-verdicts",
                joint.to_str().unwrap(),
                "--rust-contracts",
                contracts.to_str().unwrap(),
                "--output-dir",
                output_dir.to_str().unwrap(),
                "--run-id",
                RUN_ID,
            ])
            .assert()
            .success();
    };
    assert(&output_dir);

    // 清单存在且 verify-run 通过。
    assert!(output_dir.join("checksums.sha256").exists());
    Command::cargo_bin("bw")
        .unwrap()
        .args(["verify-run", "--run-dir", output_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("\"verified_count\":3"));

    // 篡改一个字节：verify 必须失败。
    let summary = output_dir.join("witness-plan-summary.json");
    let mut text = std::fs::read_to_string(&summary).unwrap();
    text.push(' ');
    std::fs::write(&summary, text).unwrap();
    Command::cargo_bin("bw")
        .unwrap()
        .args(["verify-run", "--run-dir", output_dir.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(contains("BW-V32-VERIFY-CHECKSUM"));

    // 未登记文件：verify 必须失败。
    assert(&output_dir);
    std::fs::write(output_dir.join("stray.txt"), "x").unwrap();
    Command::cargo_bin("bw")
        .unwrap()
        .args(["verify-run", "--run-dir", output_dir.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(contains("BW-V32-VERIFY-EXTRA-FILE"));
}

#[test]
fn run_safe_client_rejects_target_dir_inside_the_verified_run_dir() {
    let temp = tempfile::tempdir().unwrap();
    let controls = temp.path().join("controls.toml");
    std::fs::write(
        &controls,
        "schema_version = \"bw.controls/0.1\"\n[[control]]\nrole = \"primary\"\nbuild_id = \"x\"\nclient_variant = \"primary\"\nexpectation = \"confirmed\"\n",
    )
    .unwrap();
    let clients_dir = write_minimal_clients_dir(temp.path());
    let out = temp.path().join("out");

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "run-safe-client",
            "--clients-dir",
            clients_dir.to_str().unwrap(),
            "--controls",
            controls.to_str().unwrap(),
            "--output-dir",
            out.to_str().unwrap(),
            "--target-dir",
            out.join("target").to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(contains("BW-RUN-SAFE-CLIENT-INPUT"));
}

#[test]
fn run_safe_client_rejects_unknown_client_variant_tokens() {
    let temp = tempfile::tempdir().unwrap();
    let controls = temp.path().join("controls.toml");
    std::fs::write(
        &controls,
        "schema_version = \"bw.controls/0.1\"\n\n[[control]]\nrole = \"primary\"\nbuild_id = \"x\"\nclient_variant = \"bogus_variant\"\nexpectation = \"confirmed\"\n",
    )
    .unwrap();
    let clients_dir = write_minimal_clients_dir(temp.path());

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "run-safe-client",
            "--clients-dir",
            clients_dir.to_str().unwrap(),
            "--controls",
            controls.to_str().unwrap(),
            "--output-dir",
            temp.path().join("out").to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(contains("BW-CONTROLS-SCHEMA"));
}

#[test]
fn run_safe_client_rejects_wrong_controls_schema_version() {
    let temp = tempfile::tempdir().unwrap();
    let controls = temp.path().join("controls.toml");
    std::fs::write(
        &controls,
        "schema_version = \"bw.controls/9.9\"\n[[control]]\nrole = \"primary\"\nbuild_id = \"x\"\nclient_variant = \"primary\"\nexpectation = \"confirmed\"\n",
    )
    .unwrap();
    let clients_dir = write_minimal_clients_dir(temp.path());

    Command::cargo_bin("bw")
        .unwrap()
        .args([
            "run-safe-client",
            "--clients-dir",
            clients_dir.to_str().unwrap(),
            "--controls",
            controls.to_str().unwrap(),
            "--output-dir",
            temp.path().join("out").to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(contains("不支持的 controls schema"));
}
