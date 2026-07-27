use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

use bw_blind_model::{
    BLIND_PUBLIC_SCHEMA_V01, BlindCaseId, BlindModelError, BlindPolicy, BlindPublicCase,
    BlindPublicManifest, BlindSplit,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::private::{
    BLIND_GROUND_TRUTH_SCHEMA_V01, BlindGroundTruth, BlindTruthCase, PackSourceCase, TruthSource,
};

const COMPLETE_MARKER: &str = "COMPLETE";
const COMPLETE_MARKER_CONTENTS: &[u8] = b"complete\n";

#[derive(Debug, Error)]
pub enum CuratorError {
    #[error("failed to read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to write {}: {source}", path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("invalid source TOML: {0}")]
    InvalidToml(#[from] toml::de::Error),

    #[error("failed to serialize pack JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error(transparent)]
    PublicModel(#[from] BlindModelError),

    #[error(transparent)]
    Model(#[from] bw_model::ModelError),

    #[error(transparent)]
    Experiment(#[from] bw_experiment::ExperimentError),

    #[error(transparent)]
    Audit(#[from] bw_blind_runner::AuditError),

    #[error("invalid pack source: {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, CuratorError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackSource {
    pub truth: TruthSource,
}

impl PackSource {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let input = read(path)?;
        let truth = toml::from_str(
            std::str::from_utf8(&input)
                .map_err(|_| validation("source.toml must be valid UTF-8"))?,
        )?;
        Ok(Self { truth })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackOptions {
    pub source_root: PathBuf,
    pub policy_path: PathBuf,
    pub public_out: PathBuf,
    pub private_out: PathBuf,
    pub id_salt_hex: String,
    pub method_commit: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PackReport {
    pub suite_id: String,
    pub split_counts: BTreeMap<BlindSplit, usize>,
    pub public_roots: Vec<PathBuf>,
    pub ground_truth_files: Vec<PathBuf>,
    pub public_manifest_sha256: BTreeMap<BlindSplit, String>,
}

struct PreparedCase<'a> {
    source: &'a PackSourceCase,
    case_id: BlindCaseId,
    paired_case_ids: Vec<BlindCaseId>,
    files: Vec<SourceFile>,
    tree_sha256: String,
}

#[derive(Debug)]
struct SourceFile {
    relative: String,
    bytes: Vec<u8>,
    permissions: fs::Permissions,
}

pub fn pack(options: PackOptions) -> Result<PackReport> {
    ensure_separate_outputs(&options.public_out, &options.private_out)?;
    ensure_empty_or_missing(&options.public_out)?;
    ensure_empty_or_missing(&options.private_out)?;

    let source = PackSource::from_path(options.source_root.join("source.toml"))?;
    let policy_bytes = read(&options.policy_path)?;
    let policy_text = std::str::from_utf8(&policy_bytes)
        .map_err(|_| validation("policy.toml must be valid UTF-8"))?;
    let policy = BlindPolicy::parse_toml(policy_text)?;
    let salt = decode_hex(&options.id_salt_hex)?;
    validate_method_commit(&options.method_commit)?;
    validate_suite_id(
        &source.truth.suite_id,
        &options.method_commit,
        sha256_hex(&policy_bytes),
    )?;

    let ids = derive_and_validate_ids(&source.truth.cases, &salt)?;
    validate_pairs(&source.truth.cases)?;

    let mut prepared = Vec::with_capacity(source.truth.cases.len());
    for case in &source.truth.cases {
        validate_source_case(case)?;
        ensure_case_path_has_no_symlink(&options.source_root, &case.case_dir)?;
        let case_root = options.source_root.join(&case.case_dir);
        let files = collect_regular_files(&case_root)?;
        if files.iter().any(|file| file.relative == COMPLETE_MARKER) {
            return Err(validation(
                "case_dir must not contain curator-owned COMPLETE marker",
            ));
        }
        ensure_command_is_file(case, &files)?;
        ensure_public_values_clean(case, &source.truth.suite_id, &policy)?;
        ensure_public_paths_clean(&files, &policy)?;
        ensure_public_contents_clean(&files, &policy)?;
        let tree_sha256 = tree_digest(&files)?;
        let mut paired_case_ids = case
            .paired_with
            .iter()
            .map(|key| ids[key].clone())
            .collect::<Vec<_>>();
        paired_case_ids.sort();
        prepared.push(PreparedCase {
            source: case,
            case_id: ids[&case.curator_key].clone(),
            paired_case_ids,
            files,
            tree_sha256,
        });
    }
    prepared.sort_by(|left, right| left.case_id.cmp(&right.case_id));

    fs::create_dir_all(&options.public_out).map_err(|source| CuratorError::Write {
        path: options.public_out.clone(),
        source,
    })?;
    fs::create_dir_all(options.private_out.join("ground-truth")).map_err(|source| {
        CuratorError::Write {
            path: options.private_out.join("ground-truth"),
            source,
        }
    })?;

    let policy_sha256 = sha256_hex(&policy_bytes);
    let mut split_counts = BTreeMap::new();
    let mut public_roots = Vec::new();
    let mut ground_truth_files = Vec::new();
    let mut public_manifest_sha256 = BTreeMap::new();

    for split in [BlindSplit::Gate, BlindSplit::Evaluation] {
        let split_name = split_name(split);
        let public_root = options.public_out.join(split_name);
        let ground_truth_file = options
            .private_out
            .join("ground-truth")
            .join(format!("{split_name}.json"));
        fs::create_dir_all(public_root.join("cases")).map_err(|source| CuratorError::Write {
            path: public_root.join("cases"),
            source,
        })?;

        let split_cases = prepared
            .iter()
            .filter(|case| case.source.split == split)
            .collect::<Vec<_>>();
        for case in &split_cases {
            copy_case(case, &public_root)?;
        }

        write(&public_root.join("policy.toml"), &policy_bytes)?;
        let manifest = BlindPublicManifest {
            schema_version: BLIND_PUBLIC_SCHEMA_V01.to_owned(),
            suite_id: source.truth.suite_id.clone(),
            split,
            method_commit: options.method_commit.clone(),
            policy_sha256: policy_sha256.clone(),
            cases: split_cases
                .iter()
                .map(|case| BlindPublicCase {
                    case_id: case.case_id.clone(),
                    case_root: format!("cases/{}", case.case_id),
                    case_sha256: case.tree_sha256.clone(),
                    command: case.source.public_command.clone(),
                    timeout_seconds: case.source.timeout_seconds,
                })
                .collect(),
        };
        manifest.validate()?;
        let manifest_bytes = pretty_json(&manifest)?;
        ensure_bytes_clean(&manifest_bytes, &policy)?;
        write(&public_root.join("manifest.json"), &manifest_bytes)?;
        let manifest_sha256 = sha256_hex(&manifest_bytes);

        let truth = BlindGroundTruth {
            schema_version: BLIND_GROUND_TRUTH_SCHEMA_V01.to_owned(),
            suite_id: source.truth.suite_id.clone(),
            split,
            public_manifest_sha256: manifest_sha256.clone(),
            cases: split_cases
                .iter()
                .map(|case| BlindTruthCase {
                    case_id: case.case_id.clone(),
                    curator_key: case.source.curator_key.clone(),
                    role: case.source.role.clone(),
                    component: case.source.component.clone(),
                    api: case.source.api.clone(),
                    root_cause_key: case.source.root_cause_key.clone(),
                    paired_case_ids: case.paired_case_ids.clone(),
                    source_revision: case.source.source_revision.clone(),
                })
                .collect(),
        };
        write(&ground_truth_file, &pretty_json(&truth)?)?;
        write_checksums(&public_root)?;
        let audited_root = fs::canonicalize(&public_root).map_err(|source| CuratorError::Read {
            path: public_root.clone(),
            source,
        })?;
        let audit = bw_blind_runner::audit_public_pack(&audited_root)?;
        if audit.split != split
            || audit.method_commit != options.method_commit
            || audit.manifest_sha256 != manifest_sha256
        {
            return Err(validation(format!(
                "generated public pack audit identity mismatch for {split_name}"
            )));
        }

        split_counts.insert(split, split_cases.len());
        public_roots.push(public_root);
        ground_truth_files.push(ground_truth_file);
        public_manifest_sha256.insert(split, manifest_sha256);
    }

    let report = PackReport {
        suite_id: source.truth.suite_id,
        split_counts,
        public_roots,
        ground_truth_files,
        public_manifest_sha256,
    };
    write(
        &options.private_out.join("pack-report.json"),
        &pretty_json(&report)?,
    )?;
    Ok(report)
}

fn derive_and_validate_ids(
    cases: &[PackSourceCase],
    salt: &[u8],
) -> Result<BTreeMap<String, BlindCaseId>> {
    let mut ids = BTreeMap::new();
    let mut unique_ids = BTreeSet::new();
    for case in cases {
        if case.curator_key.is_empty() {
            return Err(validation("curator_key must be non-empty"));
        }
        if ids.contains_key(&case.curator_key) {
            return Err(validation(format!(
                "curator_key must be unique: {}",
                case.curator_key
            )));
        }
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update([0]);
        hasher.update(case.curator_key.as_bytes());
        let hex = hex_lower(&hasher.finalize());
        let case_id = BlindCaseId::parse(&format!("blind-{}", &hex[..16]))?;
        if !unique_ids.insert(case_id.clone()) {
            return Err(validation(format!("derived case_id collision: {case_id}")));
        }
        ids.insert(case.curator_key.clone(), case_id);
    }
    Ok(ids)
}

fn validate_pairs(cases: &[PackSourceCase]) -> Result<()> {
    let by_key = cases
        .iter()
        .map(|case| (case.curator_key.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    for case in cases {
        let mut seen = BTreeSet::new();
        for paired_key in &case.paired_with {
            if !seen.insert(paired_key) {
                return Err(validation(format!(
                    "paired_with contains duplicate curator_key: {paired_key}"
                )));
            }
            let Some(paired) = by_key.get(paired_key.as_str()) else {
                return Err(validation(format!(
                    "paired_with references missing curator_key: {paired_key}"
                )));
            };
            if paired.split != case.split {
                return Err(validation(format!(
                    "paired cases must use the same split: {} -> {paired_key}",
                    case.curator_key
                )));
            }
            if !paired
                .paired_with
                .iter()
                .any(|key| key == &case.curator_key)
            {
                return Err(validation(format!(
                    "pairing must be reciprocal: {} -> {paired_key}",
                    case.curator_key
                )));
            }
        }
    }
    Ok(())
}

fn validate_source_case(case: &PackSourceCase) -> Result<()> {
    for (field, value) in [
        ("component", case.component.as_str()),
        ("api", case.api.as_str()),
        ("root_cause_key", case.root_cause_key.as_str()),
        ("source_revision", case.source_revision.as_str()),
    ] {
        if value.is_empty() {
            return Err(validation(format!("{field} must be non-empty")));
        }
    }
    validate_relative_path("case_dir", &case.case_dir)?;
    validate_relative_path("public_command.program", &case.public_command.program)?;
    if case.timeout_seconds == 0 {
        return Err(validation("timeout_seconds must be non-zero"));
    }
    Ok(())
}

fn validate_relative_path(field: &str, value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty() || path.is_absolute() {
        return Err(validation(format!(
            "{field} must be a non-empty relative path"
        )));
    }
    if value.contains('\\') {
        return Err(validation(format!("{field} must use '/' separators")));
    }
    if value
        .split('/')
        .any(|component| matches!(component, "." | ".."))
    {
        return Err(validation(format!(
            "{field} must not contain '.' or '..' components"
        )));
    }
    Ok(())
}

fn collect_regular_files(case_root: &Path) -> Result<Vec<SourceFile>> {
    let metadata = fs::symlink_metadata(case_root).map_err(|source| CuratorError::Read {
        path: case_root.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(validation("case_dir must identify a regular directory"));
    }
    let mut files = Vec::new();
    collect_at(case_root, case_root, &mut files)?;
    files.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(files)
}

fn ensure_case_path_has_no_symlink(source_root: &Path, case_dir: &str) -> Result<()> {
    let mut current = source_root.to_owned();
    let mut relative = PathBuf::new();
    for component in Path::new(case_dir).components() {
        let Component::Normal(component) = component else {
            return Err(validation("case_dir components must be relative"));
        };
        current.push(component);
        relative.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|source| CuratorError::Read {
            path: current.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(validation(format!(
                "case_dir contains symlink: {}",
                relative.to_string_lossy().replace('\\', "/")
            )));
        }
    }
    Ok(())
}

fn collect_at(case_root: &Path, directory: &Path, files: &mut Vec<SourceFile>) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| CuratorError::Read {
            path: directory.to_owned(),
            source,
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source| CuratorError::Read {
            path: directory.to_owned(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let relative = slash_relative(case_root, &path)?;
        let file_type = entry.file_type().map_err(|source| CuratorError::Read {
            path: path.clone(),
            source,
        })?;
        if file_type.is_symlink() {
            return Err(validation(format!("case_dir contains symlink: {relative}")));
        }
        if file_type.is_dir() {
            collect_at(case_root, &path, files)?;
        } else if file_type.is_file() {
            files.push(snapshot_regular_file(&path, relative)?);
        } else {
            return Err(validation(format!(
                "case_dir contains non-regular file: {relative}"
            )));
        }
    }
    Ok(())
}

fn ensure_command_is_file(case: &PackSourceCase, files: &[SourceFile]) -> Result<()> {
    if files
        .iter()
        .any(|file| file.relative == case.public_command.program)
    {
        Ok(())
    } else {
        Err(validation(format!(
            "public_command.program is not a regular case file: {}",
            case.public_command.program
        )))
    }
}

fn ensure_public_values_clean(
    case: &PackSourceCase,
    suite_id: &str,
    policy: &BlindPolicy,
) -> Result<()> {
    let values = std::iter::once(suite_id)
        .chain(std::iter::once(case.public_command.program.as_str()))
        .chain(case.public_command.args.iter().map(String::as_str))
        .chain(case.public_command.env.keys().map(String::as_str))
        .chain(case.public_command.env.values().map(String::as_str));
    for value in values {
        reject_forbidden(value, policy, "public manifest value")?;
    }
    Ok(())
}

fn ensure_public_paths_clean(files: &[SourceFile], policy: &BlindPolicy) -> Result<()> {
    for file in files {
        reject_forbidden(&file.relative, policy, "public case path")?;
    }
    Ok(())
}

fn ensure_public_contents_clean(files: &[SourceFile], policy: &BlindPolicy) -> Result<()> {
    for file in files {
        let Some(contents) = text_contents(&file.bytes) else {
            continue;
        };
        reject_forbidden(
            contents,
            policy,
            &format!("public case contents in {}", file.relative),
        )?;
    }
    Ok(())
}

fn text_contents(bytes: &[u8]) -> Option<&str> {
    if bytes.contains(&0) {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

fn ensure_bytes_clean(bytes: &[u8], policy: &BlindPolicy) -> Result<()> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| validation("public manifest JSON must be valid UTF-8"))?;
    reject_forbidden(text, policy, "public manifest JSON")
}

fn reject_forbidden(value: &str, policy: &BlindPolicy, context: &str) -> Result<()> {
    if let Some(token) = policy.find_forbidden_public_token(value) {
        Err(validation(format!(
            "{context} contains forbidden token: {token}"
        )))
    } else {
        Ok(())
    }
}

fn tree_digest(files: &[SourceFile]) -> Result<String> {
    let mut entries = files
        .iter()
        .map(|file| (file.relative.as_str(), sha256_hex(&file.bytes)))
        .collect::<Vec<_>>();
    entries.push((COMPLETE_MARKER, sha256_hex(COMPLETE_MARKER_CONTENTS)));
    entries.sort_by(|left, right| left.0.cmp(right.0));

    let mut hasher = Sha256::new();
    for (relative, digest) in entries {
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(digest.as_bytes());
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn copy_case(case: &PreparedCase<'_>, public_root: &Path) -> Result<()> {
    let output_root = public_root.join("cases").join(case.case_id.as_str());
    fs::create_dir_all(&output_root).map_err(|source| CuratorError::Write {
        path: output_root.clone(),
        source,
    })?;
    for file in &case.files {
        let destination = output_root.join(&file.relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|source| CuratorError::Write {
                path: parent.to_owned(),
                source,
            })?;
        }
        write(&destination, &file.bytes)?;
        fs::set_permissions(&destination, file.permissions.clone()).map_err(|source| {
            CuratorError::Write {
                path: destination,
                source,
            }
        })?;
    }
    write(&output_root.join(COMPLETE_MARKER), COMPLETE_MARKER_CONTENTS)?;
    Ok(())
}

fn snapshot_regular_file(path: &Path, relative: String) -> Result<SourceFile> {
    snapshot_regular_file_with(path, relative, || Ok(()))
}

fn snapshot_regular_file_with(
    path: &Path,
    relative: String,
    after_open: impl FnOnce() -> Result<()>,
) -> Result<SourceFile> {
    let before = fs::symlink_metadata(path).map_err(|source| CuratorError::Read {
        path: path.to_owned(),
        source,
    })?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(validation(format!(
            "case_dir contains non-regular file: {relative}"
        )));
    }
    let mut file = File::open(path).map_err(|source| CuratorError::Read {
        path: path.to_owned(),
        source,
    })?;
    let opened = file.metadata().map_err(|source| CuratorError::Read {
        path: path.to_owned(),
        source,
    })?;
    if !same_identity(&before, &opened) {
        return Err(validation(format!(
            "source changed while snapshotting: {relative}"
        )));
    }
    after_open()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| CuratorError::Read {
            path: path.to_owned(),
            source,
        })?;
    let after_handle = file.metadata().map_err(|source| CuratorError::Read {
        path: path.to_owned(),
        source,
    })?;
    let after_path = fs::symlink_metadata(path).map_err(|source| CuratorError::Read {
        path: path.to_owned(),
        source,
    })?;
    if !stable_metadata(&opened, &after_handle)
        || !same_identity(&opened, &after_path)
        || after_path.file_type().is_symlink()
    {
        return Err(validation(format!(
            "source changed while snapshotting: {relative}"
        )));
    }
    Ok(SourceFile {
        relative,
        bytes,
        permissions: opened.permissions(),
    })
}

#[cfg(unix)]
fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.file_type() == right.file_type()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

#[cfg(unix)]
fn stable_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    same_identity(left, right)
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn stable_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    same_identity(left, right)
}

fn write_checksums(public_root: &Path) -> Result<()> {
    let files = collect_regular_files(public_root)?;
    let mut checksums = String::new();
    for file in files {
        if file.relative == "checksums.sha256" {
            continue;
        }
        checksums.push_str(&sha256_hex(&file.bytes));
        checksums.push_str("  ");
        checksums.push_str(&file.relative);
        checksums.push('\n');
    }
    write(&public_root.join("checksums.sha256"), checksums.as_bytes())
}

fn validate_suite_id(suite_id: &str, method_commit: &str, policy_sha256: String) -> Result<()> {
    BlindPublicManifest {
        schema_version: BLIND_PUBLIC_SCHEMA_V01.to_owned(),
        suite_id: suite_id.to_owned(),
        split: BlindSplit::Gate,
        method_commit: method_commit.to_owned(),
        policy_sha256,
        cases: Vec::new(),
    }
    .validate()?;
    Ok(())
}

fn validate_method_commit(method_commit: &str) -> Result<()> {
    if method_commit.len() == 40
        && method_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(validation(
            "method_commit must be 40 lowercase hexadecimal characters",
        ))
    }
}

fn decode_hex(input: &str) -> Result<Vec<u8>> {
    if input.is_empty()
        || !input.len().is_multiple_of(2)
        || !input.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(validation(
            "id_salt_hex must contain a non-empty even number of hexadecimal characters",
        ));
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("ASCII hex was checked");
            u8::from_str_radix(pair, 16).map_err(|_| validation("id_salt_hex is invalid"))
        })
        .collect()
}

fn ensure_empty_or_missing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(validation(format!(
            "output path contains symlink: {}",
            path.display()
        ))),
        Ok(metadata) if !metadata.is_dir() => Err(validation(format!(
            "output path must be a directory: {}",
            path.display()
        ))),
        Ok(_) => {
            let mut entries = fs::read_dir(path).map_err(|source| CuratorError::Read {
                path: path.to_owned(),
                source,
            })?;
            if entries
                .next()
                .transpose()
                .map_err(|source| CuratorError::Read {
                    path: path.to_owned(),
                    source,
                })?
                .is_some()
            {
                Err(validation(format!(
                    "refusing to overwrite non-empty output directory: {}",
                    path.display()
                )))
            } else {
                Ok(())
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CuratorError::Read {
            path: path.to_owned(),
            source,
        }),
    }
}

fn ensure_separate_outputs(public_out: &Path, private_out: &Path) -> Result<()> {
    ensure_output_path_has_no_dot_components(public_out)?;
    ensure_output_path_has_no_dot_components(private_out)?;
    let public_absolute = normalize_path(&absolute_path(public_out)?);
    let private_absolute = normalize_path(&absolute_path(private_out)?);
    let trusted_ancestor = existing_common_ancestor(&public_absolute, &private_absolute)?;
    ensure_output_path_has_no_symlink(&public_absolute, &trusted_ancestor)?;
    ensure_output_path_has_no_symlink(&private_absolute, &trusted_ancestor)?;
    let public_destination = physical_destination(&public_absolute)?;
    let private_destination = physical_destination(&private_absolute)?;
    if public_destination == private_destination
        || public_destination.starts_with(&private_destination)
        || private_destination.starts_with(&public_destination)
    {
        Err(validation(
            "public_out and private_out must be separate directory trees",
        ))
    } else {
        Ok(())
    }
}

fn ensure_output_path_has_no_dot_components(path: &Path) -> Result<()> {
    let has_dot_component = path
        .as_os_str()
        .as_encoded_bytes()
        .split(|byte| *byte == b'/' || (cfg!(windows) && *byte == b'\\'))
        .any(|component| component == b"." || component == b"..");
    if has_dot_component {
        Err(validation(format!(
            "output path must not contain '.' or '..' components: {}",
            path.display()
        )))
    } else {
        Ok(())
    }
}

fn existing_common_ancestor(left: &Path, right: &Path) -> Result<PathBuf> {
    let mut common = PathBuf::new();
    for (left_component, right_component) in left.components().zip(right.components()) {
        if left_component != right_component {
            break;
        }
        common.push(left_component.as_os_str());
    }
    loop {
        match fs::symlink_metadata(&common) {
            Ok(metadata) if metadata.file_type().is_symlink() => {}
            Ok(_) => return Ok(common),
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CuratorError::Read {
                    path: common,
                    source,
                });
            }
        }
        if !common.pop() {
            return Err(validation("output paths have no existing common ancestor"));
        }
    }
}

fn ensure_output_path_has_no_symlink(path: &Path, trusted_ancestor: &Path) -> Result<()> {
    let relative = path
        .strip_prefix(trusted_ancestor)
        .map_err(|_| validation("output path escaped its trusted ancestor"))?;
    let mut current = trusted_ancestor.to_owned();
    for component in relative.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(validation(format!(
                    "output path contains symlink: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CuratorError::Read {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn physical_destination(path: &Path) -> Result<PathBuf> {
    let mut ancestor = normalize_path(&absolute_path(path)?);
    let mut missing_components = Vec::new();
    loop {
        match fs::canonicalize(&ancestor) {
            Ok(mut destination) => {
                for component in missing_components.iter().rev() {
                    destination.push(component);
                }
                return Ok(destination);
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                let component = ancestor.file_name().ok_or_else(|| {
                    validation(format!(
                        "output path has no existing ancestor: {}",
                        path.display()
                    ))
                })?;
                missing_components.push(component.to_os_string());
                ancestor.pop();
            }
            Err(source) => {
                return Err(CuratorError::Read {
                    path: ancestor,
                    source,
                });
            }
        }
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        let current_dir = std::env::current_dir().map_err(|source| CuratorError::Read {
            path: PathBuf::from("."),
            source,
        })?;
        Ok(current_dir.join(path))
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn split_name(split: BlindSplit) -> &'static str {
    match split {
        BlindSplit::Gate => "nday-gate",
        BlindSplit::Evaluation => "nday-eval",
    }
}

fn slash_relative(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| validation("case file escaped case_dir"))?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(value) => value
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| validation("case paths must be valid UTF-8")),
            _ => Err(validation("case file paths must be relative")),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(components.join("/"))
}

fn pretty_json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| CuratorError::Read {
        path: path.to_owned(),
        source,
    })
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).map_err(|source| CuratorError::Write {
        path: path.to_owned(),
        source,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn validation(message: impl Into<String>) -> CuratorError {
    CuratorError::Validation(message.into())
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    #[test]
    fn rejects_path_replacement_after_opening_source_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let replacement = root.path().join("replacement");
        fs::write(&source, b"public bytes").unwrap();
        fs::write(&replacement, b"private replacement").unwrap();

        let error = snapshot_regular_file_with(&source, "source".to_owned(), || {
            fs::rename(&replacement, &source).map_err(|source| CuratorError::Write {
                path: PathBuf::from("source"),
                source,
            })?;
            Ok(())
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("source changed while snapshotting"));
    }
}
