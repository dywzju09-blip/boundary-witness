use assert_cmd::Command;

#[test]
fn help_lists_public_commands() {
    let output = Command::cargo_bin("bw")
        .expect("bw binary should build")
        .arg("--help")
        .output()
        .expect("bw --help should run");
    let stdout = String::from_utf8(output.stdout).expect("help should be UTF-8");

    assert!(output.status.success());
    assert!(stdout.contains("validate"));
    assert!(stdout.contains("analyze"));
    assert!(stdout.contains("build-precheck"));
    assert!(stdout.contains("index-boundaries"));
    assert!(stdout.contains("emit-candidates"));
    assert!(stdout.contains("rank-lifecycle"));
    assert!(stdout.contains("extract-lifecycle-evidence"));
    assert!(stdout.contains("extract-rust-contracts"));
    assert!(stdout.contains("extract-foreign-facts"));
    assert!(stdout.contains("judge-hand-offs"));
    assert!(stdout.contains("build-lifecycle-graph-v3"));
    assert!(stdout.contains("rank-lifecycle-v2"));
    assert!(stdout.contains("build-witness-plan"));
    assert!(stdout.contains("audit-lifecycle-contracts"));
    assert!(stdout.contains("compare-anonymous-pairs"));
    assert!(stdout.contains("account-adapter-effort"));
    assert!(stdout.contains("build-failure-taxonomy"));
    assert!(stdout.contains("reveal-static-ranking"));
    assert!(stdout.contains("verify-run"));
    assert!(stdout.contains("diff"));
}
