use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use bw_blind_model::{
    BLIND_POLICY_SCHEMA_V01, BLIND_PUBLIC_SCHEMA_V01, BlindCaseId, BlindCommandSpec, BlindPolicy,
    BlindPublicCase, BlindPublicManifest, BlindSplit, MANDATORY_FORBIDDEN_PUBLIC_TOKENS,
};
use bw_blind_runner::audit_public_pack;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const CASE_ID: &str = "blind-8f34a923d01c77ab";
const METHOD_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn audits_a_valid_public_pack_without_scanning_source_contents() {
    let fixture = Fixture::new();

    let audit = audit_public_pack(&fixture.pack).expect("valid public pack");

    assert_eq!(audit.suite_id, "synthetic-suite");
    assert_eq!(audit.split, BlindSplit::Gate);
    assert_eq!(audit.method_commit, METHOD_COMMIT);
    assert_eq!(audit.manifest_sha256, sha256_path(&fixture.manifest_path()));
    assert_eq!(audit.case_count, 1);
    assert_eq!(
        audit.case_digests[&BlindCaseId::parse(CASE_ID).unwrap()],
        tree_digest(&fixture.case_root())
    );
}

#[test]
fn rejects_invalid_manifest_schema() {
    let fixture = Fixture::new();
    fixture.mutate_manifest(|manifest| {
        manifest["schema_version"] = serde_json::json!("boundary-witness.blind-public/9.9");
    });

    assert_error_contains(&fixture, "unsupported blind public schema_version");
}

#[test]
fn rejects_an_unchecksummed_extra_file() {
    let fixture = Fixture::new();
    fs::write(fixture.case_root().join("extra.txt"), "not checksummed\n").unwrap();

    assert_error_contains(&fixture, "unchecksummed file");
}

#[test]
fn rejects_a_wrong_case_digest() {
    let fixture = Fixture::new();
    fixture.mutate_manifest(|manifest| {
        manifest["cases"][0]["case_sha256"] = serde_json::json!("0".repeat(64));
    });

    assert_error_contains(&fixture, "case tree digest mismatch");
}

#[cfg(unix)]
#[test]
fn rejects_a_symlink_under_the_case_root() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    symlink(
        fixture.root.path().join("outside"),
        fixture.case_root().join("adapter/bin/link"),
    )
    .unwrap();

    assert_error_contains(&fixture, "symlink");
}

#[cfg(unix)]
#[test]
fn rejects_a_symlinked_pack_root_ancestor() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let physical_root = fixture.pack.parent().unwrap();
    let linked_root = physical_root.join("linked-root");
    symlink(physical_root, &linked_root).unwrap();

    assert_audit_error_contains(&linked_root.join("pack"), "symlink");
}

#[cfg(unix)]
#[test]
fn rejects_a_symlink_before_parent_traversal_in_pack_root() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let physical_root = fixture.pack.parent().unwrap();
    let symlink_target = physical_root.join("symlink-target");
    fs::create_dir(&symlink_target).unwrap();
    let link = physical_root.join("link");
    symlink(&symlink_target, &link).unwrap();

    assert_audit_error_contains(&link.join("../pack"), "'.' or '..'");
}

#[test]
fn rejects_a_literal_current_component_in_pack_root() {
    let fixture = Fixture::new();

    assert_audit_error_contains(
        &fixture.pack.parent().unwrap().join("./pack"),
        "'.' or '..'",
    );
}

#[test]
fn rejects_a_command_program_outside_the_case_root() {
    let fixture = Fixture::new();
    fixture.mutate_manifest(|manifest| {
        manifest["cases"][0]["command"]["program"] = serde_json::json!("policy.toml");
    });

    assert_error_contains(&fixture, "command program is not a regular case file");
}

#[test]
fn rejects_an_absolute_command_path() {
    let fixture = Fixture::new();
    fixture.mutate_manifest(|manifest| {
        manifest["cases"][0]["command"]["program"] = serde_json::json!("/bin/driver");
    });

    assert_error_contains(
        &fixture,
        "command program must be a non-empty relative slash path",
    );
}

#[test]
fn rejects_parent_traversal_in_a_command_path() {
    let fixture = Fixture::new();
    fixture.mutate_manifest(|manifest| {
        manifest["cases"][0]["command"]["program"] = serde_json::json!("../adapter/bin/driver");
    });

    assert_error_contains(
        &fixture,
        "command program must be a non-empty relative slash path",
    );
}

#[test]
fn rejects_a_forbidden_filename_token_case_insensitively() {
    let fixture = Fixture::new();
    fs::write(fixture.case_root().join("src/CVE-synthetic.rs"), "safe\n").unwrap();
    fixture.refresh_case_digest_and_checksums();

    assert_error_contains(&fixture, "filename contains forbidden token: cve-");
}

#[test]
fn rejects_a_missing_complete_marker_even_with_consistent_digests() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.case_root().join("COMPLETE")).unwrap();
    fixture.refresh_case_digest_and_checksums();

    assert_error_contains(&fixture, "missing COMPLETE marker");
}

#[test]
fn rejects_uppercase_checksum_digests() {
    let fixture = Fixture::new();
    let checksums = fs::read_to_string(fixture.pack.join("checksums.sha256")).unwrap();
    fs::write(
        fixture.pack.join("checksums.sha256"),
        checksums.to_ascii_uppercase(),
    )
    .unwrap();

    assert_error_contains(&fixture, "checksum digest must be lowercase hexadecimal");
}

#[test]
fn rejects_unsorted_checksum_entries() {
    let fixture = Fixture::new();
    let checksums_path = fixture.pack.join("checksums.sha256");
    let checksums = fs::read_to_string(&checksums_path).unwrap();
    let mut lines = checksums.lines().collect::<Vec<_>>();
    lines.swap(0, 1);
    fs::write(checksums_path, format!("{}\n", lines.join("\n"))).unwrap();

    assert_error_contains(&fixture, "checksum paths must be sorted");
}

#[test]
fn rejects_a_policy_digest_mismatch() {
    let fixture = Fixture::new();
    let policy_path = fixture.pack.join("policy.toml");
    let policy = fs::read_to_string(&policy_path)
        .unwrap()
        .replace("minimum_replay_attempts = 3", "minimum_replay_attempts = 4");
    fs::write(policy_path, policy).unwrap();
    write_checksums(&fixture.pack);

    assert_error_contains(&fixture, "policy digest mismatch");
}

fn assert_error_contains(fixture: &Fixture, expected: &str) {
    assert_audit_error_contains(&fixture.pack, expected);
}

fn assert_audit_error_contains(root: &Path, expected: &str) {
    let error = audit_public_pack(root).unwrap_err().to_string();
    assert!(
        error.contains(expected),
        "expected error containing {expected:?}, got {error:?}"
    );
}

struct Fixture {
    root: TempDir,
    pack: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let pack = root.path().canonicalize().unwrap().join("pack");
        let fixture = Self { root, pack };
        let case_root = fixture.case_root();
        fs::create_dir_all(case_root.join("src")).unwrap();
        fs::create_dir_all(case_root.join("adapter/bin")).unwrap();
        fs::write(
            case_root.join("Cargo.toml"),
            "[package]\nname = \"opaque\"\n",
        )
        .unwrap();
        fs::write(
            case_root.join("src/lib.rs"),
            "// cve-synthetic-content-is-hashed-but-not-scanned\npub fn probe() {}\n",
        )
        .unwrap();
        fs::write(case_root.join("adapter/bin/driver"), "synthetic driver\n").unwrap();
        fs::write(case_root.join("COMPLETE"), "complete\n").unwrap();

        let policy = BlindPolicy {
            schema_version: BLIND_POLICY_SCHEMA_V01.to_owned(),
            minimum_replay_attempts: 3,
            gate_minimum_confirmed_cases: 1,
            forbidden_public_filename_tokens: mandatory_policy_tokens(),
        };
        let policy_text = toml_text(&policy);
        fs::write(fixture.pack.join("policy.toml"), &policy_text).unwrap();

        let manifest = BlindPublicManifest {
            schema_version: BLIND_PUBLIC_SCHEMA_V01.to_owned(),
            suite_id: "synthetic-suite".to_owned(),
            split: BlindSplit::Gate,
            method_commit: METHOD_COMMIT.to_owned(),
            policy_sha256: sha256_bytes(policy_text.as_bytes()),
            cases: vec![BlindPublicCase {
                case_id: BlindCaseId::parse(CASE_ID).unwrap(),
                case_root: format!("cases/{CASE_ID}"),
                case_sha256: tree_digest(&fixture.case_root()),
                command: BlindCommandSpec {
                    program: "adapter/bin/driver".to_owned(),
                    args: vec!["--synthetic".to_owned()],
                    env: BTreeMap::new(),
                },
                timeout_seconds: 30,
            }],
        };
        write_manifest(&fixture.manifest_path(), &manifest);
        write_checksums(&fixture.pack);
        fixture
    }

    fn case_root(&self) -> PathBuf {
        self.pack.join("cases").join(CASE_ID)
    }

    fn manifest_path(&self) -> PathBuf {
        self.pack.join("manifest.json")
    }

    fn mutate_manifest(&self, mutate: impl FnOnce(&mut serde_json::Value)) {
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(self.manifest_path()).unwrap()).unwrap();
        mutate(&mut manifest);
        let mut bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        bytes.push(b'\n');
        fs::write(self.manifest_path(), bytes).unwrap();
        write_checksums(&self.pack);
    }

    fn refresh_case_digest_and_checksums(&self) {
        self.mutate_manifest(|manifest| {
            manifest["cases"][0]["case_sha256"] = serde_json::json!(tree_digest(&self.case_root()));
        });
    }
}

fn mandatory_policy_tokens() -> Vec<String> {
    MANDATORY_FORBIDDEN_PUBLIC_TOKENS
        .iter()
        .map(|token| (*token).to_owned())
        .collect()
}

fn toml_text(policy: &BlindPolicy) -> String {
    let tokens = policy
        .forbidden_public_filename_tokens
        .iter()
        .map(|token| format!("\"{token}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "schema_version = \"{}\"\nminimum_replay_attempts = {}\ngate_minimum_confirmed_cases = {}\nforbidden_public_filename_tokens = [{tokens}]\n",
        policy.schema_version, policy.minimum_replay_attempts, policy.gate_minimum_confirmed_cases
    )
}

fn write_manifest(path: &Path, manifest: &BlindPublicManifest) {
    let mut bytes = serde_json::to_vec_pretty(manifest).unwrap();
    bytes.push(b'\n');
    fs::write(path, bytes).unwrap();
}

fn write_checksums(root: &Path) {
    let mut output = String::new();
    for relative in regular_files(root) {
        if relative == "checksums.sha256" {
            continue;
        }
        writeln!(
            &mut output,
            "{}  {}",
            sha256_path(&root.join(&relative)),
            relative
        )
        .unwrap();
    }
    fs::write(root.join("checksums.sha256"), output).unwrap();
}

fn tree_digest(case_root: &Path) -> String {
    let mut hasher = Sha256::new();
    for relative in regular_files(case_root) {
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(sha256_path(&case_root.join(relative)).as_bytes());
    }
    hex_lower(&hasher.finalize())
}

fn regular_files(root: &Path) -> Vec<String> {
    fn visit(root: &Path, current: &Path, output: &mut Vec<String>) {
        let mut entries = fs::read_dir(current)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                visit(root, &path, output);
            } else if file_type.is_file() {
                output.push(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }

    let mut output = Vec::new();
    visit(root, root, &mut output);
    output.sort();
    output
}

fn sha256_path(path: &Path) -> String {
    sha256_bytes(&fs::read(path).unwrap())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}
