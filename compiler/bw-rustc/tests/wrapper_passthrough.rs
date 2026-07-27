use std::{fs, process::Command};

#[test]
fn rustc_version_probe_without_crate_name_is_passthrough() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let output = Command::new(env!("CARGO_BIN_EXE_bw-rustc"))
        .arg(rustc)
        .arg("-vV")
        .output()
        .expect("wrapper should run");
    assert!(
        output.status.success(),
        "version probe should be passed through, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("rustc"));
}

#[test]
fn rustc_target_probe_with_multiple_crate_types_is_passthrough() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let output = Command::new(env!("CARGO_BIN_EXE_bw-rustc"))
        .arg(rustc)
        .args([
            "-",
            "--crate-name",
            "___",
            "--print=file-names",
            "--crate-type",
            "bin",
            "--crate-type",
            "rlib",
            "--crate-type",
            "dylib",
            "--print=sysroot",
        ])
        .output()
        .expect("wrapper should run");
    assert!(
        output.status.success(),
        "target probe should be passed through, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.is_empty());
}

#[test]
fn non_allowlisted_crate_is_compiled_by_real_rustc() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let src = temp.path().join("main.rs");
    let out_dir = temp.path().join("out");
    fs::create_dir(&out_dir).expect("out dir should be created");
    fs::write(
        &src,
        r#"
fn main() {
    println!("passthrough-ok");
}
"#,
    )
    .expect("source should be written");

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let status = Command::new(env!("CARGO_BIN_EXE_bw-rustc"))
        .arg(rustc)
        .args([
            "--crate-name",
            "plain_passthrough",
            "--crate-type",
            "bin",
            "--edition",
            "2024",
        ])
        .arg(&src)
        .arg("--out-dir")
        .arg(&out_dir)
        .status()
        .expect("wrapper should run");
    assert!(status.success(), "wrapper exit status was {status}");

    let binary = out_dir.join(format!("plain_passthrough{}", std::env::consts::EXE_SUFFIX));
    let output = Command::new(binary)
        .output()
        .expect("compiled binary should run");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "passthrough-ok\n"
    );
}
