use assert_cmd::Command;
use std::path::Path;

#[test]
fn public_fixture_samples_validate_against_declared_kinds() {
    let samples = [
        (
            "v3-2-adapter-effort",
            "fixtures/v3-2/adapter-effort.sample.jsonl",
        ),
        (
            "v3-2-boundary-index",
            "fixtures/v3-2/boundary-index.sample.jsonl",
        ),
        (
            "v3-2-buildability",
            "fixtures/v3-2/buildability.sample.jsonl",
        ),
        ("v3-2-candidate", "fixtures/v3-2/candidate.sample.jsonl"),
        (
            "v3-2-corpus-manifest",
            "fixtures/v3-2/corpus-manifest.sample.jsonl",
        ),
        (
            "v3-2-failure-taxonomy",
            "fixtures/v3-2/failure-taxonomy.sample.jsonl",
        ),
        (
            "v3-2-lifecycle-graph",
            "fixtures/v3-2/lifecycle-graph.sample.json",
        ),
        (
            "v3-2-ranked-candidate",
            "fixtures/v3-2/ranked-candidate.sample.jsonl",
        ),
        (
            "v3-2-corpus-manifest",
            "fixtures/v3-2-5/public-corpus-manifest.sample.jsonl",
        ),
        (
            "v3-2-5-private-ground-truth",
            "fixtures/v3-2-5/private-ground-truth.sample.jsonl",
        ),
        (
            "v3-2-5-static-ranking-reveal",
            "fixtures/v3-2-5/static-ranking-reveal.sample.json",
        ),
    ];
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate should live under crates/");

    for (kind, path) in samples {
        Command::cargo_bin("bw")
            .expect("bw binary should build")
            .args(["validate", "--kind", kind])
            .arg(workspace_root.join(path))
            .assert()
            .success();
    }
}
