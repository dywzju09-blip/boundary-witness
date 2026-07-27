use std::{
    fs,
    path::{Path, PathBuf},
};

use bw_blind_curator::{PackOptions, pack};
use bw_blind_model::{BlindPublicManifest, BlindSplit};
use bw_blind_runner::audit_public_pack;
use tempfile::TempDir;

const SALT: &str = "00112233445566778899aabbccddeeff";
const METHOD_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn pack_is_deterministic_and_splits_public_from_private_truth() {
    let fixture = Fixture::new(&[
        SourceCase::new("opaque-alpha", "gate", "violation"),
        SourceCase::new("opaque-beta", "evaluation", "fixed_control"),
    ]);
    let physical_root = fixture.root.path().canonicalize().unwrap();
    let first_public = physical_root.join("public-first");
    let first_private = physical_root.join("private-first");
    let second_public = physical_root.join("public-second");
    let second_private = physical_root.join("private-second");

    let first = pack(fixture.options(&first_public, &first_private)).expect("first pack");
    let second = pack(fixture.options(&second_public, &second_private)).expect("second pack");

    assert_eq!(first.suite_id, "synthetic-suite");
    assert_eq!(first.split_counts[&BlindSplit::Gate], 1);
    assert_eq!(first.split_counts[&BlindSplit::Evaluation], 1);
    assert_eq!(first.public_manifest_sha256, second.public_manifest_sha256);
    assert_eq!(
        fs::read(first_public.join("nday-gate/manifest.json")).unwrap(),
        fs::read(second_public.join("nday-gate/manifest.json")).unwrap()
    );
    assert_eq!(
        fs::read(first_public.join("nday-eval/manifest.json")).unwrap(),
        fs::read(second_public.join("nday-eval/manifest.json")).unwrap()
    );
    assert_eq!(
        fs::read(first_private.join("ground-truth/nday-gate.json")).unwrap(),
        fs::read(second_private.join("ground-truth/nday-gate.json")).unwrap()
    );
    assert_eq!(
        fs::read(first_private.join("ground-truth/nday-eval.json")).unwrap(),
        fs::read(second_private.join("ground-truth/nday-eval.json")).unwrap()
    );

    for split_dir in ["nday-gate", "nday-eval"] {
        let public_root = first_public.join(split_dir);
        let manifest = BlindPublicManifest::from_path(public_root.join("manifest.json")).unwrap();
        assert_eq!(manifest.cases.len(), 1);
        let expected_id = match manifest.split {
            BlindSplit::Gate => "blind-5663c349e5dd32e6",
            BlindSplit::Evaluation => "blind-2b022aa4dc843131",
        };
        assert_eq!(manifest.cases[0].case_id.as_str(), expected_id);
        let case_root = public_root.join(&manifest.cases[0].case_root);
        assert!(case_root.is_dir());
        assert!(case_root.join("COMPLETE").is_file());

        let audit = audit_public_pack(&public_root).expect("curator pack should pass runner audit");
        assert_eq!(audit.split, manifest.split);
        assert_eq!(audit.case_count, 1);
        assert_eq!(
            audit.case_digests[&manifest.cases[0].case_id],
            manifest.cases[0].case_sha256
        );

        let truth: serde_json::Value = serde_json::from_slice(
            &fs::read(
                first_private
                    .join("ground-truth")
                    .join(format!("{split_dir}.json")),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            truth["schema_version"],
            "boundary-witness.blind-ground-truth/0.1"
        );
        assert_eq!(
            truth["public_manifest_sha256"],
            first.public_manifest_sha256[&manifest.split]
        );
        assert_eq!(
            truth["cases"][0]["case_id"],
            manifest.cases[0].case_id.as_str()
        );
        assert!(truth["cases"][0].get("role").is_some());
        assert!(
            manifest.cases[0]
                .command
                .program
                .ends_with("adapter/bin/driver")
        );
    }
}

#[test]
fn public_pack_never_contains_truth_or_advisory_tokens() {
    let mut source = SourceCase::new("cve-synthetic-alpha", "gate", "violation");
    source.component = "advisory-synthetic-component";
    source.root_cause_key = "poc-synthetic-root";
    source.source_revision = "ghsa-synthetic-revision";
    let fixture = Fixture::new(&[source]);
    let public_out = fixture.root.path().join("public");
    let private_out = fixture.root.path().join("private");

    pack(fixture.options(&public_out, &private_out)).expect("pack should anonymize metadata");

    let forbidden = [
        "ground-truth",
        "ground_truth",
        "cve-",
        "ghsa-",
        "advisory",
        "poc",
    ];
    for path in walk_paths(&public_out) {
        let relative = path
            .strip_prefix(&public_out)
            .unwrap()
            .to_string_lossy()
            .to_lowercase();
        for token in forbidden {
            assert!(
                !relative.contains(token),
                "public path leaked {token}: {relative}"
            );
        }
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let text = fs::read_to_string(&path).unwrap().to_lowercase();
            for token in forbidden {
                assert!(
                    !text.contains(token),
                    "public JSON leaked {token}: {relative}"
                );
            }
        }
    }

    let private_truth =
        fs::read_to_string(private_out.join("ground-truth/nday-gate.json")).unwrap();
    assert!(private_truth.contains("cve-synthetic-alpha"));
    assert!(private_truth.contains("advisory-synthetic-component"));
}

#[test]
fn pack_rejects_forbidden_tokens_in_public_case_contents() {
    let fixture = Fixture::new(&[SourceCase::new("opaque-alpha", "gate", "violation")]);
    fs::write(
        fixture.source_root.join("cases/opaque-alpha/src/lib.rs"),
        "pub const SYNTHETIC_NOTE: &str = \"ghsa-synthetic-marker\";\n",
    )
    .unwrap();

    let error = pack(fixture.default_options()).unwrap_err().to_string();

    assert_eq!(
        error,
        "invalid pack source: public case contents in src/lib.rs contains forbidden token: ghsa-"
    );
}

#[test]
fn pack_skips_non_utf8_binary_case_contents_for_forbidden_token_scanning() {
    let fixture = Fixture::new(&[SourceCase::new("opaque-alpha", "gate", "violation")]);
    fs::write(
        fixture
            .source_root
            .join("cases/opaque-alpha/adapter/bin/driver"),
        b"\x7fELF\0serde/src/private/de.rs\0debug/path/vulnerable/main.rs\0",
    )
    .unwrap();

    pack(fixture.default_options())
        .expect("binary contents are bound by digest but not scanned as text");
}

#[test]
fn pack_rejects_all_mandatory_synthetic_leak_markers_in_public_contents() {
    for marker in [
        "synthetic-cve-marker",
        "synthetic-ghsa-marker",
        "synthetic-poc-marker",
        "synthetic-advisory-marker",
        "synthetic-expected-result-marker",
        "synthetic-private-marker",
    ] {
        let fixture = Fixture::new(&[SourceCase::new("opaque-alpha", "gate", "violation")]);
        fs::write(
            fixture.source_root.join("cases/opaque-alpha/src/lib.rs"),
            format!("pub const SYNTHETIC_MARKER: &str = \"{marker}\";\n"),
        )
        .unwrap();

        let error = pack(fixture.default_options()).unwrap_err().to_string();

        assert!(error.contains("forbidden token"), "{marker}: {error}");
    }
}

#[test]
fn pack_rejects_empty_or_weak_leak_policy_before_scanning() {
    for tokens in ["", "\"custom-only\"", "\"cve-\""] {
        let fixture = Fixture::new(&[SourceCase::new("opaque-alpha", "gate", "violation")]);
        fs::write(
            &fixture.policy_path,
            format!(
                "schema_version = \"boundary-witness.blind-policy/0.1\"\nminimum_replay_attempts = 2\ngate_minimum_confirmed_cases = 1\nforbidden_public_filename_tokens = [{tokens}]\n"
            ),
        )
        .unwrap();

        let error = pack(fixture.default_options()).unwrap_err().to_string();

        assert!(
            error.contains("mandatory forbidden public token"),
            "{tokens}: {error}"
        );
    }
}

#[test]
fn pack_rejects_a_source_owned_complete_marker() {
    let fixture = Fixture::new(&[SourceCase::new("opaque-alpha", "gate", "violation")]);
    fs::write(
        fixture.source_root.join("cases/opaque-alpha/COMPLETE"),
        "source-owned\n",
    )
    .unwrap();

    let error = pack(fixture.default_options()).unwrap_err().to_string();

    assert_eq!(
        error,
        "invalid pack source: case_dir must not contain curator-owned COMPLETE marker"
    );
}

#[cfg(unix)]
#[test]
fn pack_rejects_symlink_absolute_and_parent_paths() {
    use std::os::unix::fs::symlink;

    let symlink_fixture = Fixture::new(&[SourceCase::new("opaque-alpha", "gate", "violation")]);
    symlink(
        symlink_fixture.root.path().join("outside"),
        symlink_fixture
            .source_root
            .join("cases/opaque-alpha/adapter/bin/link"),
    )
    .unwrap();
    let error = pack(symlink_fixture.default_options())
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "invalid pack source: case_dir contains symlink: adapter/bin/link"
    );

    let parent_symlink_fixture =
        Fixture::new(&[SourceCase::new("opaque-alpha", "gate", "violation")]);
    symlink(
        parent_symlink_fixture.source_root.join("cases"),
        parent_symlink_fixture.source_root.join("linked-cases"),
    )
    .unwrap();
    let source_manifest = parent_symlink_fixture.source_root.join("source.toml");
    let source_text = fs::read_to_string(&source_manifest)
        .unwrap()
        .replace("cases/opaque-alpha", "linked-cases/opaque-alpha");
    fs::write(source_manifest, source_text).unwrap();
    let error = pack(parent_symlink_fixture.default_options())
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "invalid pack source: case_dir contains symlink: linked-cases"
    );

    let mut absolute = SourceCase::new("opaque-alpha", "gate", "violation");
    absolute.case_dir = "/synthetic/absolute";
    let absolute_fixture = Fixture::new(&[absolute]);
    let error = pack(absolute_fixture.default_options())
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "invalid pack source: case_dir must be a non-empty relative path"
    );

    let mut parent = SourceCase::new("opaque-alpha", "gate", "violation");
    parent.case_dir = "cases/../opaque-alpha";
    let parent_fixture = Fixture::new(&[parent]);
    let error = pack(parent_fixture.default_options())
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "invalid pack source: case_dir must not contain '.' or '..' components"
    );

    let mut current = SourceCase::new("opaque-alpha", "gate", "violation");
    current.case_dir = "cases/./opaque-alpha";
    let current_fixture = Fixture::new(&[current]);
    let error = pack(current_fixture.default_options())
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "invalid pack source: case_dir must not contain '.' or '..' components"
    );

    let overlapping_fixture = Fixture::new(&[SourceCase::new("opaque-alpha", "gate", "violation")]);
    let shared_out = overlapping_fixture.root.path().join("shared-out");
    let error = pack(overlapping_fixture.options(&shared_out, &shared_out))
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "invalid pack source: public_out and private_out must be separate directory trees"
    );

    let non_empty_fixture = Fixture::new(&[SourceCase::new("opaque-alpha", "gate", "violation")]);
    let public_out = non_empty_fixture.root.path().join("public");
    fs::create_dir(&public_out).unwrap();
    fs::write(public_out.join("existing"), "synthetic").unwrap();
    let error = pack(non_empty_fixture.default_options())
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        format!(
            "invalid pack source: refusing to overwrite non-empty output directory: {}",
            public_out.display()
        )
    );
}

#[cfg(unix)]
#[test]
fn pack_rejects_output_symlinks_targeting_the_same_directory() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new(&[SourceCase::new("opaque-alpha", "gate", "violation")]);
    let shared_out = fixture.root.path().join("shared-out");
    let existing_out = shared_out.join("existing");
    let public_link = fixture.root.path().join("public-link");
    let private_link = fixture.root.path().join("private-link");
    let public_out = public_link.join("nested/missing");
    let private_out = private_link.join("nested/missing");
    fs::create_dir_all(&existing_out).unwrap();
    fs::create_dir(existing_out.join("nested")).unwrap();
    symlink(&existing_out, &public_link).unwrap();
    symlink(&existing_out, &private_link).unwrap();

    let error = pack(fixture.options(&public_out, &private_out))
        .unwrap_err()
        .to_string();

    assert_eq!(
        error,
        format!(
            "invalid pack source: output path contains symlink: {}",
            public_link.display()
        )
    );
    assert!(
        fs::read_dir(existing_out.join("nested"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn pack_rejects_output_symlink_before_parent_aliases() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new(&[SourceCase::new("opaque-alpha", "gate", "violation")]);
    let physical = fixture.root.path().join("physical");
    let public_parent = fixture.root.path().join("a");
    let private_parent = fixture.root.path().join("b");
    let public_link = public_parent.join("link");
    let private_link = private_parent.join("link");
    let public_out = public_link.join("../out");
    let private_out = private_link.join("../out");
    fs::create_dir_all(physical.join("x")).unwrap();
    fs::create_dir(&public_parent).unwrap();
    fs::create_dir(&private_parent).unwrap();
    symlink(physical.join("x"), &public_link).unwrap();
    symlink(physical.join("x"), &private_link).unwrap();

    let error = pack(fixture.options(&public_out, &private_out))
        .unwrap_err()
        .to_string();

    assert_eq!(
        error,
        format!(
            "invalid pack source: output path must not contain '.' or '..' components: {}",
            public_out.display()
        )
    );
    assert!(!physical.join("out").exists());
}

#[test]
fn pack_rejects_current_output_components() {
    let fixture = Fixture::new(&[SourceCase::new("opaque-alpha", "gate", "violation")]);
    let public_out = fixture.root.path().join("public/./out");
    let private_out = fixture.root.path().join("private");

    let error = pack(fixture.options(&public_out, &private_out))
        .unwrap_err()
        .to_string();

    assert_eq!(
        error,
        format!(
            "invalid pack source: output path must not contain '.' or '..' components: {}",
            public_out.display()
        )
    );
}

#[test]
fn pack_rejects_missing_or_one_way_pairs() {
    let mut missing = SourceCase::new("opaque-alpha", "gate", "violation");
    missing.paired_with = vec!["missing-control"];
    let missing_fixture = Fixture::new(&[missing]);
    let error = pack(missing_fixture.default_options())
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "invalid pack source: paired_with references missing curator_key: missing-control"
    );

    let mut violation = SourceCase::new("opaque-alpha", "gate", "violation");
    violation.paired_with = vec!["opaque-beta"];
    let control = SourceCase::new("opaque-beta", "gate", "safe_control");
    let one_way_fixture = Fixture::new(&[violation, control]);
    let error = pack(one_way_fixture.default_options())
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "invalid pack source: pairing must be reciprocal: opaque-alpha -> opaque-beta"
    );
}

#[test]
fn pack_rejects_empty_ground_truth_fields() {
    for (field, mutate) in [
        (
            "component",
            (|case: &mut SourceCase| case.component = "") as fn(&mut SourceCase),
        ),
        ("api", |case: &mut SourceCase| case.api = ""),
        ("root_cause_key", |case: &mut SourceCase| {
            case.root_cause_key = "";
        }),
        ("source_revision", |case: &mut SourceCase| {
            case.source_revision = "";
        }),
    ] {
        let mut source = SourceCase::new("opaque-alpha", "gate", "violation");
        mutate(&mut source);
        let fixture = Fixture::new(&[source]);

        let error = pack(fixture.default_options()).unwrap_err().to_string();

        assert_eq!(
            error,
            format!("invalid pack source: {field} must be non-empty")
        );
    }
}

struct Fixture {
    root: TempDir,
    source_root: PathBuf,
    policy_path: PathBuf,
}

impl Fixture {
    fn new(cases: &[SourceCase]) -> Self {
        let root = tempfile::tempdir().unwrap();
        let source_root = root.path().join("source");
        fs::create_dir_all(&source_root).unwrap();

        let mut source_toml = String::from("suite_id = \"synthetic-suite\"\n");
        for case in cases {
            let case_root = source_root.join(case.fixture_dir());
            fs::create_dir_all(case_root.join("src")).unwrap();
            fs::create_dir_all(case_root.join("adapter/bin")).unwrap();
            fs::write(
                case_root.join("Cargo.toml"),
                "[package]\nname = \"synthetic-case\"\n",
            )
            .unwrap();
            fs::write(case_root.join("src/lib.rs"), "pub fn synthetic() {}\n").unwrap();
            fs::write(case_root.join("adapter/bin/driver"), "synthetic-driver\n").unwrap();
            source_toml.push_str(&case.to_toml());
        }
        fs::write(source_root.join("source.toml"), source_toml).unwrap();

        let policy_path = root.path().join("policy.toml");
        fs::write(
            &policy_path,
            r#"schema_version = "boundary-witness.blind-policy/0.1"
minimum_replay_attempts = 2
gate_minimum_confirmed_cases = 1
forbidden_public_filename_tokens = ["ground-truth", "ground_truth", "cve-", "ghsa-", "advisory", "poc", "proof-of-concept", "proof_of_concept", "expected-result", "expected_result", "expected result", "private"]
"#,
        )
        .unwrap();

        Self {
            root,
            source_root,
            policy_path,
        }
    }

    fn options(&self, public_out: &Path, private_out: &Path) -> PackOptions {
        PackOptions {
            source_root: self.source_root.clone(),
            policy_path: self.policy_path.clone(),
            public_out: public_out.to_owned(),
            private_out: private_out.to_owned(),
            id_salt_hex: SALT.to_owned(),
            method_commit: METHOD_COMMIT.to_owned(),
        }
    }

    fn default_options(&self) -> PackOptions {
        self.options(
            &self.root.path().join("public"),
            &self.root.path().join("private"),
        )
    }
}

struct SourceCase {
    curator_key: &'static str,
    split: &'static str,
    role: &'static str,
    component: &'static str,
    api: &'static str,
    root_cause_key: &'static str,
    paired_with: Vec<&'static str>,
    source_revision: &'static str,
    case_dir: &'static str,
}

impl SourceCase {
    fn new(curator_key: &'static str, split: &'static str, role: &'static str) -> Self {
        Self {
            curator_key,
            split,
            role,
            component: "synthetic-component",
            api: "synthetic-api",
            root_cause_key: "synthetic-root",
            paired_with: Vec::new(),
            source_revision: "synthetic-revision",
            case_dir: match curator_key {
                "opaque-beta" => "cases/opaque-beta",
                _ => "cases/opaque-alpha",
            },
        }
    }

    fn fixture_dir(&self) -> &'static str {
        match self.curator_key {
            "opaque-beta" => "cases/opaque-beta",
            _ => "cases/opaque-alpha",
        }
    }

    fn to_toml(&self) -> String {
        let paired_with = self
            .paired_with
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"
[[cases]]
curator_key = "{}"
split = "{}"
role = "{}"
component = "{}"
api = "{}"
root_cause_key = "{}"
paired_with = [{}]
source_revision = "{}"
case_dir = "{}"
public_command = {{ program = "adapter/bin/driver", args = ["run"], env = {{}} }}
timeout_seconds = 30
"#,
            self.curator_key,
            self.split,
            self.role,
            self.component,
            self.api,
            self.root_cause_key,
            paired_with,
            self.source_revision,
            self.case_dir,
        )
    }
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
