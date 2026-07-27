use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite_lab_shared::artifact_staging::{
    V3BlindSourceOptions, write_m12_v3_blind_source,
};

#[test]
fn writes_m12_v3_private_source_without_public_path_leaks() {
    let fixture = Fixture::new();

    write_m12_v3_blind_source(&V3BlindSourceOptions {
        artifact_root: fixture.artifact_root.clone(),
        output_root: fixture.output_root.clone(),
        adapter_binary: fixture.adapter_binary.clone(),
        bw_binary: fixture.bw_binary.clone(),
        contract: fixture.contract.clone(),
    })
    .expect("v3 source should be generated");

    let source = fs::read_to_string(fixture.output_root.join("source.toml")).unwrap();
    assert!(source.contains("suite_id = \"suite.rusqlite.m12.v3\""));
    assert!(source.contains("curator_key = \"m12-case-0001\""));
    assert!(source.contains("split = \"gate\""));
    assert!(source.contains("role = \"violation\""));
    assert!(source.contains("component = \"sqlite-wrapper\""));
    assert!(source.contains("api = \"callback-api-a\""));
    assert!(source.contains("root_cause_key = \"retained-borrowed-callback\""));
    assert!(source.contains("paired_with = [\"m12-case-0002\"]"));
    assert!(source.contains("source_revision = \"rusqlite-m12\""));
    assert!(source.contains("case_dir = \"cases/m12-0001\""));
    assert!(
        source.contains("public_command = { program = \"adapter/bin/driver\", args = [], env = {} }")
    );

    assert!(fixture.output_root.join("cases/m12-0001/adapter/bin/driver").is_file());
    assert!(fixture.output_root.join("cases/m12-0001/payload/bin/case").is_file());
    assert!(fixture.output_root.join("cases/m12-0001/payload/bin/bw").is_file());
    assert!(
        fixture
            .output_root
            .join("cases/m12-0001/payload/static-facts.jsonl")
            .is_file()
    );
    assert!(
        fixture
            .output_root
            .join("cases/m12-0001/payload/contract.toml")
            .is_file()
    );

    let forbidden = [
        "vulnerable",
        "fixed",
        "ground-truth",
        "ground_truth",
        "cve-",
        "ghsa-",
        "advisory",
        "poc",
        "expected-result",
        "expected_result",
    ];
    for path in walk_paths(&fixture.output_root) {
        let relative = path
            .strip_prefix(&fixture.output_root)
            .unwrap()
            .to_string_lossy()
            .to_lowercase();
        for token in forbidden {
            assert!(
                !relative.contains(token),
                "generated source path leaked {token}: {relative}"
            );
        }
    }
}

struct Fixture {
    _root: PathBuf,
    artifact_root: PathBuf,
    output_root: PathBuf,
    adapter_binary: PathBuf,
    bw_binary: PathBuf,
    contract: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = temp_dir("v3-blind-source");
        let artifact_root = root.join("artifacts");
        let output_root = root.join("source");
        let adapter_binary = root.join("bin/adapter");
        let bw_binary = root.join("bin/bw");
        let contract = root.join("contract.toml");
        fs::create_dir_all(artifact_root.join("bin")).unwrap();
        fs::create_dir_all(artifact_root.join("static")).unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
        for index in 1..=10 {
            let case_id = format!("case-{index:04}");
            fs::write(artifact_root.join("bin").join(&case_id), format!("bin {case_id}\n")).unwrap();
            fs::write(
                artifact_root.join("static").join(format!("{case_id}.jsonl")),
                format!("static {case_id}\n"),
            )
            .unwrap();
        }
        fs::write(&adapter_binary, "adapter\n").unwrap();
        fs::write(&bw_binary, "bw\n").unwrap();
        fs::write(&contract, "contract\n").unwrap();
        Self {
            _root: root,
            artifact_root,
            output_root,
            adapter_binary,
            bw_binary,
            contract,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self._root.exists() {
            fs::remove_dir_all(&self._root).unwrap();
        }
    }
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("bw-rusqlite-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}

fn walk_paths(root: &Path) -> Vec<PathBuf> {
    fn visit(path: &Path, paths: &mut Vec<PathBuf>) {
        let mut entries = fs::read_dir(path)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            paths.push(path.clone());
            if path.is_dir() {
                visit(&path, paths);
            }
        }
    }

    let mut paths = Vec::new();
    visit(root, &mut paths);
    paths
}
