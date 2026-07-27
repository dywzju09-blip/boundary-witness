use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[test]
fn required_rusqlite_symbols_are_reported_with_versioned_mir_coverage() {
    let repo = repo_root();
    let config = repo.join("experiments/configs/rusqlite-mir.toml");
    let required = repo.join("fixtures/compiler/rusqlite-required-symbols.txt");
    let cases = runnable_cases(&repo);

    assert!(
        config.exists(),
        "rusqlite MIR config is missing at {}",
        config.display()
    );

    let required_symbols = load_required_symbols(&required);
    assert_required_symbol_intent(&required_symbols);
    assert_blind_inputs(&config);
    assert_blind_inputs(&required);

    let temp = tempfile::tempdir().expect("tempdir should be created");
    let analysis_dir = temp.path().join("analysis");
    fs::create_dir(&analysis_dir).expect("analysis dir should be created");

    for case in &cases {
        assert!(
            case.manifest.exists(),
            "rusqlite benchmark manifest is missing at {}",
            case.manifest.display()
        );
        let case_dir = temp.path().join(case.app_crate);
        let target_dir = case_dir.join("target");
        let metadata_path = case_dir.join("metadata.json");
        fs::create_dir(&case_dir).expect("case dir should be created");

        let metadata = Command::new("cargo")
            .args(["metadata", "--format-version=1", "--manifest-path"])
            .arg(&case.manifest)
            .output()
            .expect("cargo metadata should run");
        assert!(
            metadata.status.success(),
            "cargo metadata failed for {}: {}",
            case.manifest.display(),
            String::from_utf8_lossy(&metadata.stderr)
        );
        fs::write(&metadata_path, metadata.stdout).expect("metadata should be written");

        let status = Command::new("cargo")
            .args(["check", "--locked", "--manifest-path"])
            .arg(&case.manifest)
            .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_bw-rustc"))
            .env("BW_RUSTC_CONFIG", &config)
            .env("BW_RUSQLITE_APP_CRATE", case.app_crate)
            .env("BW_RUSQLITE_OUTPUT_DIR", &analysis_dir)
            .env("BW_RUSQLITE_METADATA_PATH", &metadata_path)
            .env("CARGO_TARGET_DIR", &target_dir)
            .status()
            .expect("cargo check should run");
        assert!(
            status.success(),
            "rusqlite cargo check failed for {}: {status}",
            case.manifest.display()
        );
    }

    let coverage_path = analysis_dir.join("mir-coverage.json");
    let coverage: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&coverage_path)
            .unwrap_or_else(|error| panic!("{}: {error}", coverage_path.display())),
    )
    .expect("coverage should parse as json");

    for required in &required_symbols {
        assert_seen_body(&coverage, required);
    }
    for case in &cases {
        assert_seen_body(
            &coverage,
            &RequiredSymbol {
                package: case.app_crate.to_owned(),
                version: "0.1.0".to_owned(),
                target: "bin".to_owned(),
                symbol_fragment: "main".to_owned(),
            },
        );
    }
}

#[derive(Debug)]
struct RunnableCase {
    manifest: PathBuf,
    app_crate: &'static str,
}

fn runnable_cases(repo: &Path) -> Vec<RunnableCase> {
    let root = repo.join("benchmarks/historical-cves/rusqlite");
    vec![
        RunnableCase {
            manifest: root.join("update-hook/vulnerable/Cargo.toml"),
            app_crate: "bw_rusqlite_update_0261_borrowed",
        },
        RunnableCase {
            manifest: root.join("update-hook/fixed/Cargo.toml"),
            app_crate: "bw_rusqlite_update_0262_owned",
        },
        RunnableCase {
            manifest: root.join("scalar-function/vulnerable/Cargo.toml"),
            app_crate: "bw_rusqlite_scalar_0261_borrowed",
        },
        RunnableCase {
            manifest: root.join("scalar-function/fixed/Cargo.toml"),
            app_crate: "bw_rusqlite_scalar_0262_owned",
        },
    ]
}

#[derive(Debug)]
struct RequiredSymbol {
    package: String,
    version: String,
    target: String,
    symbol_fragment: String,
}

fn load_required_symbols(path: &Path) -> Vec<RequiredSymbol> {
    let input =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let symbols = input
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let fields = line.split_whitespace().collect::<Vec<_>>();
            assert_eq!(
                fields.len(),
                4,
                "{}:{} must use: <package> <version> <target> <symbol-fragment>",
                path.display(),
                index + 1
            );
            Some(RequiredSymbol {
                package: fields[0].to_owned(),
                version: fields[1].to_owned(),
                target: fields[2].to_owned(),
                symbol_fragment: fields[3].to_owned(),
            })
        })
        .collect::<Vec<_>>();
    assert!(
        !symbols.is_empty(),
        "{} must contain required symbols",
        path.display()
    );
    symbols
}

fn assert_required_symbol_intent(symbols: &[RequiredSymbol]) {
    for version in ["0.26.1", "0.26.2"] {
        assert_symbol_for(version, symbols, "update_hook");
        assert_symbol_for(version, symbols, "create_scalar_function");
        assert_symbol_for(version, symbols, "update_hook::call_boxed_closure");
        assert_symbol_for(
            version,
            symbols,
            "create_scalar_function::call_boxed_closure",
        );
    }
}

fn assert_symbol_for(version: &str, symbols: &[RequiredSymbol], fragment: &str) {
    assert!(
        symbols.iter().any(|symbol| {
            symbol.package == "rusqlite"
                && symbol.version == version
                && symbol.target == "lib"
                && symbol.symbol_fragment.contains(fragment)
        }),
        "required-symbol list must include rusqlite {version} lib symbol containing {fragment}"
    );
}

fn assert_blind_inputs(path: &Path) {
    let input =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let lower = input.to_lowercase();
    for banned in ["cve", "vulnerable", "fixed", "expected"] {
        assert!(
            !lower.contains(banned),
            "{} must not encode oracle label {banned}",
            path.display()
        );
    }
}

fn assert_seen_body(coverage: &serde_json::Value, required: &RequiredSymbol) {
    let bodies = coverage["seen_bodies"]
        .as_array()
        .expect("seen_bodies should be an array");
    assert!(
        bodies.iter().any(|body| {
            body["package"] == required.package
                && body["version"] == required.version
                && body["target"] == required.target
                && body["def_path"]
                    .as_str()
                    .is_some_and(|def_path| def_path.contains(&required.symbol_fragment))
        }),
        "coverage missing required symbol {:?}; seen bodies were {bodies:#?}",
        required
    );
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
