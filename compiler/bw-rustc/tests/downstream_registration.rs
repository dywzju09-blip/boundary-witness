//! 跨 crate 注册识别的端到端回归。
//!
//! 单元测试可以断言 `classify_call` 对某个 def path 的判定，但断言不了 rustc 究竟
//! 打印出哪个 def path。这条路径正是自动 0day 扫描的主路径——被扫的 crate 只是
//! 第三方 API 的使用者——所以形状必须由真实编译产物钉住：rustc 换了打印方式，
//! 这里就该红，而不是安静地退回零个注册点。

use std::{collections::BTreeSet, fs, process::Command};

use bw_model::{StaticFact, StaticFactEnvelope};

#[test]
fn registration_in_a_crate_that_only_depends_on_the_api_is_recognised() {
    let repo = repo_root();
    let fixture = repo.join("benchmarks/compiler-fixtures/downstream-registration/Cargo.toml");
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let analysis_dir = temp.path().join("analysis");
    let target_dir = temp.path().join("target");
    fs::create_dir(&analysis_dir).expect("analysis dir should be created");

    let metadata = Command::new("cargo")
        .args([
            "metadata",
            "--format-version=1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(&fixture)
        .output()
        .expect("cargo metadata should run");
    assert!(
        metadata.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata_path = temp.path().join("metadata.json");
    fs::write(&metadata_path, metadata.stdout).expect("metadata should be written");

    // allowlist 只放 app：被分析的是使用者，提供 API 的 crate 不参与分析。
    let config = temp.path().join("bw-rustc-config.json");
    fs::write(
        &config,
        serde_json::json!({
            "output_dir": analysis_dir,
            "metadata_path": metadata_path,
            "allowlist": [
                {
                    "crate_name": "downstream_app",
                    "package_name": "downstream-app",
                    "version": "0.1.0",
                    "target": "lib"
                }
            ]
        })
        .to_string(),
    )
    .expect("config should be written");

    // 与 extract-static-facts 施加的 RUSTFLAGS 保持一致：依赖不带 MIR 就看不穿
    // 依赖里的注册封装，跨 crate 摘要那条断言会失去意义。
    let status = Command::new("cargo")
        .args(["check", "--manifest-path"])
        .arg(&fixture)
        .arg("-p")
        .arg("downstream-app")
        .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_bw-rustc"))
        .env("BW_RUSTC_CONFIG", &config)
        .env("CARGO_TARGET_DIR", &target_dir)
        .env("RUSTFLAGS", "-Zalways-encode-mir")
        .status()
        .expect("cargo check should run");
    assert!(status.success(), "fixture cargo check failed: {status}");

    let facts = fs::read_to_string(analysis_dir.join("static-facts.jsonl"))
        .expect("static facts should be written")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<StaticFactEnvelope>(line).expect("fact should parse"))
        .collect::<Vec<_>>();

    let registrations = facts
        .iter()
        .filter_map(|envelope| match &envelope.payload {
            StaticFact::RegistrationSite(fact) => Some((
                fact.api_id.clone(),
                envelope
                    .source_ref
                    .as_ref()
                    .and_then(|source_ref| source_ref.symbol_path.clone())
                    .unwrap_or_default(),
            )),
            _ => None,
        })
        .collect::<BTreeSet<_>>();

    let api_ids = registrations
        .iter()
        .map(|(api_id, _)| api_id.clone())
        .collect::<BTreeSet<_>>();
    assert!(
        api_ids.contains("api:rusqlite:update_hook:register"),
        "a crate that only depends on rusqlite must still produce a registration site; got {registrations:?}"
    );
    assert!(
        api_ids.contains("api:rusqlite:update_hook:unregister"),
        "the literal-None call must be classified as an unregistration; got {registrations:?}"
    );

    // 放宽跨 crate 匹配的代价边界：同名方法挂在别的 owner 上不能算注册。
    let owners = registrations
        .iter()
        .map(|(_, symbol_path)| symbol_path.as_str())
        .collect::<BTreeSet<_>>();
    assert!(
        !owners.contains("calls_same_name_on_another_type"),
        "Statement::update_hook shares the method name but is not the contract API; got {registrations:?}"
    );

    // 注册包在依赖 crate 的一层封装里，调用点不含合约 API 的名字。认出它要求读到
    // 依赖的函数体——这正是此前 `as_local()?` 直接放弃的那条路径。
    assert!(
        owners.contains("registers_through_a_dependency_helper"),
        "a registration wrapped in a dependency's helper must be seen through; got {registrations:?}"
    );
}

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
