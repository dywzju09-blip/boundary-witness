use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs::{self, File},
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

use bw_blind_model::{
    BlindCaseId, BlindModelError, BlindPolicy, BlindPublicCase, BlindPublicManifest, BlindSplit,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const CHECKSUM_FILE: &str = "checksums.sha256";

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("failed to read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error(transparent)]
    PublicModel(#[from] BlindModelError),

    #[error(transparent)]
    Experiment(#[from] bw_experiment::ExperimentError),

    #[error("failed to write {}: {source}", path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to serialize blind observation: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("invalid public pack: {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, AuditError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicPackAudit {
    pub suite_id: String,
    pub split: BlindSplit,
    pub method_commit: String,
    pub manifest_sha256: String,
    pub case_count: usize,
    pub case_digests: BTreeMap<BlindCaseId, String>,
}

pub fn audit_public_pack(root: impl AsRef<Path>) -> Result<PublicPackAudit> {
    let root = root.as_ref();
    let files = collect_regular_files(root)?;

    for required in ["manifest.json", "policy.toml", CHECKSUM_FILE] {
        if !files.contains_key(required) {
            return Err(validation(format!("missing required file: {required}")));
        }
    }
    ensure_cases_directory(root)?;

    let policy_bytes = read(&root.join("policy.toml"))?;
    let policy = BlindPolicy::parse_toml(utf8(&policy_bytes, "policy.toml")?)?;
    let manifest_bytes = read(&root.join("manifest.json"))?;
    let manifest = BlindPublicManifest::parse_json(utf8(&manifest_bytes, "manifest.json")?)?;

    let checksum_bytes = read(&root.join(CHECKSUM_FILE))?;
    let checksum_text = utf8(&checksum_bytes, CHECKSUM_FILE)?;
    let checksums = parse_checksums(checksum_text)?;
    verify_checksum_coverage(root, &files, &checksums)?;
    ensure_filenames_clean(files.keys(), &policy)?;

    let policy_sha256 = sha256_bytes(&policy_bytes);
    if manifest.policy_sha256 != policy_sha256 {
        return Err(validation(format!(
            "policy digest mismatch: expected {}, got {policy_sha256}",
            manifest.policy_sha256
        )));
    }

    let case_digests = audit_cases(root, &files, &manifest)?;
    let manifest_sha256 = sha256_bytes(&manifest_bytes);
    Ok(PublicPackAudit {
        suite_id: manifest.suite_id,
        split: manifest.split,
        method_commit: manifest.method_commit,
        manifest_sha256,
        case_count: manifest.cases.len(),
        case_digests,
    })
}

fn audit_cases(
    root: &Path,
    files: &BTreeMap<String, PathBuf>,
    manifest: &BlindPublicManifest,
) -> Result<BTreeMap<BlindCaseId, String>> {
    let mut case_digests = BTreeMap::new();
    let mut claimed_case_files = BTreeSet::new();

    for case in &manifest.cases {
        let digest = audit_case(root, files, case, &mut claimed_case_files)?;
        case_digests.insert(case.case_id.clone(), digest);
    }

    for relative in files.keys().filter(|path| path.starts_with("cases/")) {
        if !claimed_case_files.contains(relative) {
            return Err(validation(format!(
                "case file is outside a manifest case root: {relative}"
            )));
        }
    }
    Ok(case_digests)
}

fn audit_case(
    root: &Path,
    files: &BTreeMap<String, PathBuf>,
    case: &BlindPublicCase,
    claimed_case_files: &mut BTreeSet<String>,
) -> Result<String> {
    validate_safe_relative_path(&case.case_root)?;
    let case_root = root.join(&case.case_root);
    let metadata = fs::symlink_metadata(&case_root).map_err(|source| AuditError::Read {
        path: case_root.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(validation(format!(
            "case_root is not a regular directory: {}",
            case.case_root
        )));
    }

    let prefix = format!("{}/", case.case_root);
    let case_files = files
        .iter()
        .filter_map(|(relative, absolute)| {
            relative
                .strip_prefix(&prefix)
                .map(|case_relative| (relative, case_relative, absolute))
        })
        .collect::<Vec<_>>();
    let complete = format!("{}/COMPLETE", case.case_root);
    if !files.contains_key(&complete) {
        return Err(validation(format!(
            "case {} is missing COMPLETE marker",
            case.case_id
        )));
    }

    validate_safe_relative_path(&case.command.program)?;
    let command_relative = format!("{}/{}", case.case_root, case.command.program);
    if !files.contains_key(&command_relative) {
        return Err(validation(format!(
            "command program is not a regular case file: {}",
            case.command.program
        )));
    }

    let mut hasher = Sha256::new();
    for (pack_relative, case_relative, absolute) in case_files {
        claimed_case_files.insert(pack_relative.clone());
        hasher.update(case_relative.as_bytes());
        hasher.update([0]);
        hasher.update(sha256_path(absolute)?.as_bytes());
    }
    let actual = hex_lower(&hasher.finalize());
    if actual != case.case_sha256 {
        return Err(validation(format!(
            "case tree digest mismatch for {}: expected {}, got {actual}",
            case.case_id, case.case_sha256
        )));
    }
    Ok(actual)
}

fn ensure_cases_directory(root: &Path) -> Result<()> {
    let cases = root.join("cases");
    let metadata = fs::symlink_metadata(&cases).map_err(|source| AuditError::Read {
        path: cases.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(validation("cases directory is a symlink"));
    }
    if !metadata.is_dir() {
        return Err(validation("cases is not a directory"));
    }
    Ok(())
}

fn parse_checksums(input: &str) -> Result<BTreeMap<String, String>> {
    let mut checksums = BTreeMap::new();
    let mut previous: Option<String> = None;
    for (index, line) in input.lines().enumerate() {
        if line.is_empty() {
            return Err(validation(format!("empty checksum line {}", index + 1)));
        }
        let Some((digest, path)) = line.split_once("  ") else {
            return Err(validation(format!("invalid checksum line {}", index + 1)));
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(validation(format!(
                "checksum digest must be lowercase hexadecimal on line {}",
                index + 1
            )));
        }
        validate_safe_relative_path(path)?;
        if path == CHECKSUM_FILE {
            return Err(validation("checksums.sha256 must not checksum itself"));
        }
        if previous.as_deref().is_some_and(|previous| previous >= path) {
            return Err(validation("checksum paths must be sorted and unique"));
        }
        previous = Some(path.to_owned());
        checksums.insert(path.to_owned(), digest.to_owned());
    }
    Ok(checksums)
}

fn verify_checksum_coverage(
    root: &Path,
    files: &BTreeMap<String, PathBuf>,
    checksums: &BTreeMap<String, String>,
) -> Result<()> {
    for (relative, absolute) in files {
        if relative == CHECKSUM_FILE {
            continue;
        }
        let Some(expected) = checksums.get(relative) else {
            return Err(validation(format!("unchecksummed file: {relative}")));
        };
        let actual = sha256_path(absolute)?;
        if &actual != expected {
            return Err(validation(format!(
                "checksum mismatch for {relative}: expected {expected}, got {actual}"
            )));
        }
    }
    for relative in checksums.keys() {
        if !files.contains_key(relative) {
            return Err(validation(format!(
                "checksum references missing file: {relative}"
            )));
        }
        let absolute = root.join(relative);
        if absolute == root.join(CHECKSUM_FILE) {
            return Err(validation("checksums.sha256 must not checksum itself"));
        }
    }
    Ok(())
}

fn ensure_filenames_clean<'a>(
    filenames: impl Iterator<Item = &'a String>,
    policy: &BlindPolicy,
) -> Result<()> {
    for filename in filenames {
        if let Some(token) = policy.find_forbidden_public_token(filename) {
            return Err(validation(format!(
                "filename contains forbidden token: {token}: {filename}"
            )));
        }
    }
    Ok(())
}

fn collect_regular_files(root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    ensure_pack_root_path_is_safe(root)?;
    let metadata = fs::symlink_metadata(root).map_err(|source| AuditError::Read {
        path: root.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(validation(format!(
            "public pack root is a symlink: {}",
            root.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(validation(format!(
            "public pack root is not a directory: {}",
            root.display()
        )));
    }

    let mut output = BTreeMap::new();
    collect_at(root, root, &mut output)?;
    Ok(output)
}

pub(crate) fn ensure_pack_root_path_is_safe(root: &Path) -> Result<()> {
    let has_dot_component = root
        .as_os_str()
        .as_encoded_bytes()
        .split(|byte| *byte == b'/' || (cfg!(windows) && *byte == b'\\'))
        .any(|component| component == b"." || component == b"..");
    if has_dot_component {
        return Err(validation(format!(
            "public pack root must not contain '.' or '..' components: {}",
            root.display()
        )));
    }

    let absolute = if root.is_absolute() {
        root.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|source| AuditError::Read {
                path: PathBuf::from("."),
                source,
            })?
            .join(root)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(validation(format!(
                    "public pack root path contains symlink: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(AuditError::Read {
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn collect_at(root: &Path, directory: &Path, output: &mut BTreeMap<String, PathBuf>) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| AuditError::Read {
            path: directory.to_owned(),
            source,
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|source| AuditError::Read {
            path: directory.to_owned(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let relative = relative_slash_path(root, &path)?;
        let file_type = entry.file_type().map_err(|source| AuditError::Read {
            path: path.clone(),
            source,
        })?;
        if file_type.is_symlink() {
            return Err(validation(format!(
                "public pack contains symlink: {relative}"
            )));
        }
        if file_type.is_dir() {
            collect_at(root, &path, output)?;
        } else if file_type.is_file() {
            output.insert(relative, path);
        } else {
            return Err(validation(format!(
                "public pack contains non-regular file: {relative}"
            )));
        }
    }
    Ok(())
}

fn relative_slash_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| validation(format!("path escapes public pack root: {}", path.display())))?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let Component::Normal(value) = component else {
            return Err(validation(format!(
                "unsafe path in public pack: {}",
                relative.display()
            )));
        };
        let Some(value) = value.to_str() else {
            return Err(validation(format!(
                "public pack path is not UTF-8: {}",
                relative.display()
            )));
        };
        parts.push(value);
    }
    let relative = parts.join("/");
    validate_safe_relative_path(&relative)?;
    Ok(relative)
}

fn validate_safe_relative_path(path: &str) -> Result<()> {
    if path.is_empty()
        || Path::new(path).is_absolute()
        || path.contains('\\')
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(validation(format!("unsafe relative path: {path}")));
    }
    Ok(())
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| AuditError::Read {
        path: path.to_owned(),
        source,
    })
}

fn utf8<'a>(bytes: &'a [u8], name: &str) -> Result<&'a str> {
    std::str::from_utf8(bytes).map_err(|_| validation(format!("{name} must be valid UTF-8")))
}

fn sha256_path(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|source| AuditError::Read {
        path: path.to_owned(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file.read(&mut buffer).map_err(|source| AuditError::Read {
            path: path.to_owned(),
            source,
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn validation(message: impl Into<String>) -> AuditError {
    AuditError::Validation(message.into())
}
