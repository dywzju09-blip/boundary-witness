#[test]
fn compiler_private_toolchain_is_available() {
    let version = std::process::Command::new("rustc")
        .args(["--version", "--verbose"])
        .output()
        .expect("rustc should be available");
    assert!(version.status.success());
    let version = String::from_utf8(version.stdout).expect("rustc version should be utf-8");
    assert!(
        version.contains("release: 1."),
        "unexpected rustc --version --verbose output:\n{version}"
    );

    let libdir = std::process::Command::new("rustc")
        .args(["--print", "target-libdir"])
        .output()
        .expect("rustc target libdir should be available");
    assert!(libdir.status.success());
    let libdir = String::from_utf8(libdir.stdout).expect("target libdir should be utf-8");
    let has_driver = std::fs::read_dir(libdir.trim())
        .expect("target libdir should be readable")
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().contains("rustc_driver"));
    assert!(
        has_driver,
        "rustc_driver was not found in {}",
        libdir.trim()
    );
}
