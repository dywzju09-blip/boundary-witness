use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};

use sha2::{Digest, Sha256};

use crate::{CuratorError, Result};

const CHECKSUMS: &str = "checksums.sha256";
const REQUIRED_FINAL_FILES: &[&str] = &[
    "manifest.json",
    "findings.jsonl",
    "summary.json",
    "COMPLETE",
];

/// A single, checksum-verified view of a finalized run. All reveal parsing must use these bytes.
pub(crate) struct VerifiedRunSnapshot {
    pub(crate) run_id: String,
    pub(crate) manifest_bytes: Vec<u8>,
    pub(crate) summary_bytes: Vec<u8>,
    pub(crate) observations_bytes: Vec<u8>,
    pub(crate) runner_receipt_bytes: Vec<u8>,
    #[allow(dead_code)] // Retained raw snapshot evidence for future curator checks.
    pub(crate) checksums_bytes: Vec<u8>,
    #[allow(dead_code)] // Retained raw snapshot evidence for future curator checks.
    pub(crate) witness_files: BTreeMap<String, Vec<u8>>,
    pub(crate) checksums_sha256: String,
    files: BTreeMap<String, Vec<u8>>,
}

impl VerifiedRunSnapshot {
    pub(crate) fn capture(run_directory: &Path) -> Result<Self> {
        let root = open_run_root(run_directory)?;
        let root_before = root.metadata(run_directory)?;
        let checksums_bytes = read_regular_no_follow(&root, run_directory, CHECKSUMS)?;
        let checksums = parse_checksums(&checksums_bytes)?;
        for required in REQUIRED_FINAL_FILES {
            if !checksums.contains_key(*required) {
                return Err(validation(format!(
                    "missing checksummed run file: {required}"
                )));
            }
        }
        for required in ["artifacts/observations.jsonl"] {
            if !checksums.contains_key(required) {
                return Err(validation(format!(
                    "missing checksummed run file: {required}"
                )));
            }
        }
        if !checksums.contains_key("artifacts/blind-runner-receipt.json") {
            return Err(validation("runner receipt is required"));
        }

        let (actual, directories) = collect_regular_files(&root, run_directory)?;
        ensure_evidence_tree_roots(&actual, &directories)?;
        let expected = checksums.keys().cloned().collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(validation(
                "run checksum manifest does not exactly describe finalized run files",
            ));
        }

        let mut files = BTreeMap::new();
        for (relative, expected_digest) in &checksums {
            let bytes = read_regular_no_follow(&root, run_directory, relative)?;
            if sha256_hex(&bytes) != *expected_digest {
                return Err(validation(format!(
                    "run evidence checksum mismatch: {relative}"
                )));
            }
            files.insert(relative.clone(), bytes);
        }
        if !same_metadata(&root_before, &root.metadata(run_directory)?) {
            return Err(validation("run directory changed while capturing snapshot"));
        }

        let manifest_bytes = required_bytes(&files, "manifest.json")?;
        let summary_bytes = required_bytes(&files, "summary.json")?;
        let observations_bytes = required_bytes(&files, "artifacts/observations.jsonl")?;
        let runner_receipt_bytes = required_bytes(&files, "artifacts/blind-runner-receipt.json")?;
        let witness_files = files
            .iter()
            .filter(|(path, _)| path.starts_with("artifacts/witnesses/"))
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect();
        let run_id = run_directory
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| validation("run directory must have a UTF-8 name"))?
            .to_owned();
        Ok(Self {
            run_id,
            manifest_bytes,
            summary_bytes,
            observations_bytes,
            runner_receipt_bytes,
            checksums_sha256: runner_evidence_digest(&files, &directories)?,
            checksums_bytes,
            witness_files,
            files,
        })
    }

    pub(crate) fn file(&self, relative: &str) -> Option<&[u8]> {
        self.files.get(relative).map(Vec::as_slice)
    }
}

fn required_bytes(files: &BTreeMap<String, Vec<u8>>, path: &str) -> Result<Vec<u8>> {
    files
        .get(path)
        .cloned()
        .ok_or_else(|| validation(format!("missing checksummed run file: {path}")))
}

fn parse_checksums(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| validation("checksums.sha256 must be valid UTF-8"))?;
    let mut checksums = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let Some((digest, path)) = line.split_once("  ") else {
            return Err(validation(format!("invalid checksum line {}", index + 1)));
        };
        if !is_sha256(digest) {
            return Err(validation(format!(
                "invalid checksum digest on line {}",
                index + 1
            )));
        }
        validate_relative(path)?;
        if path == CHECKSUMS {
            return Err(validation("checksums.sha256 must not checksum itself"));
        }
        if checksums
            .insert(path.to_owned(), digest.to_owned())
            .is_some()
        {
            return Err(validation(format!("duplicate checksum path: {path}")));
        }
    }
    Ok(checksums)
}

#[cfg(unix)]
struct OpenFd(libc::c_int);

#[cfg(unix)]
impl Drop for OpenFd {
    fn drop(&mut self) {
        // SAFETY: this type exclusively owns the descriptor.
        unsafe { libc::close(self.0) };
    }
}

#[cfg(unix)]
impl OpenFd {
    fn metadata(&self, path: &Path) -> Result<std::fs::Metadata> {
        use std::os::fd::FromRawFd;

        // SAFETY: dup creates an independently-owned descriptor for the temporary File.
        let duplicate = unsafe { libc::dup(self.0) };
        if duplicate < 0 {
            return Err(read_error(path));
        }
        // SAFETY: File takes exclusive ownership of the descriptor returned by dup.
        unsafe { std::fs::File::from_raw_fd(duplicate) }
            .metadata()
            .map_err(|_| read_error(path))
    }
}

#[cfg(unix)]
fn open_run_root(path: &Path) -> Result<OpenFd> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_os_str().as_bytes();
    let path = std::ffi::CString::new(bytes)
        .map_err(|_| validation("run directory is not a regular directory"))?;
    // SAFETY: path is NUL-terminated and lives through the open call.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_DIRECTORY
                | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(validation("run directory is not a regular directory"));
    }
    let root = OpenFd(descriptor);
    if !root.metadata(Path::new("."))?.is_dir() {
        return Err(validation("run directory is not a regular directory"));
    }
    Ok(root)
}

#[cfg(not(unix))]
struct OpenFd;

#[cfg(not(unix))]
fn open_run_root(_path: &Path) -> Result<OpenFd> {
    Err(validation(
        "verified run snapshot requires Unix no-follow support",
    ))
}

#[cfg(not(unix))]
impl OpenFd {
    fn metadata(&self, _path: &Path) -> Result<std::fs::Metadata> {
        Err(validation(
            "verified run snapshot requires Unix no-follow support",
        ))
    }
}

#[cfg(unix)]
fn open_entry(
    parent: &OpenFd,
    name: &std::ffi::OsStr,
    path: &Path,
    directory: bool,
) -> Result<OpenFd> {
    use std::os::unix::ffi::OsStrExt;

    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| unsafe_path(path))?;
    let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    if directory {
        flags |= libc::O_DIRECTORY;
    }
    // SAFETY: parent is an owned directory descriptor and name is a single NUL-terminated entry.
    let descriptor = unsafe { libc::openat(parent.0, name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(unsafe_path(path));
    }
    Ok(OpenFd(descriptor))
}

#[cfg(unix)]
fn read_entries(directory: &OpenFd, path: &Path) -> Result<Vec<std::ffi::OsString>> {
    use std::os::unix::ffi::OsStringExt;

    let before = directory.metadata(path)?;
    // SAFETY: dup creates an independently-owned descriptor for fdopendir to consume.
    let duplicate = unsafe { libc::dup(directory.0) };
    if duplicate < 0 {
        return Err(read_error(path));
    }
    // SAFETY: fdopendir consumes duplicate on success; it is closed below on failure.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: fdopendir did not take ownership on failure.
        unsafe { libc::close(duplicate) };
        return Err(read_error(path));
    }
    let mut entries = Vec::new();
    loop {
        set_errno_zero();
        // SAFETY: stream remains valid until closed below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            if last_errno() != 0 {
                // SAFETY: closedir consumes the descriptor owned by stream.
                unsafe { libc::closedir(stream) };
                return Err(read_error(path));
            }
            break;
        }
        // SAFETY: d_name is NUL-terminated for this readdir result's lifetime.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            entries.push(std::ffi::OsString::from_vec(name.to_vec()));
        }
    }
    // SAFETY: closedir consumes stream and its descriptor exactly once.
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(read_error(path));
    }
    entries.sort();
    if !same_metadata(&before, &directory.metadata(path)?) {
        return Err(validation(format!(
            "run directory changed while reading: {}",
            path.display()
        )));
    }
    Ok(entries)
}

#[cfg(unix)]
fn collect_regular_files(
    root: &OpenFd,
    root_path: &Path,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let mut output = BTreeSet::new();
    let mut directories = BTreeSet::new();
    collect_regular_files_inner(
        root,
        root_path,
        Path::new(""),
        &mut output,
        &mut directories,
    )?;
    output.remove(CHECKSUMS);
    Ok((output, directories))
}

#[cfg(unix)]
fn collect_regular_files_inner(
    directory: &OpenFd,
    root_path: &Path,
    relative_directory: &Path,
    output: &mut BTreeSet<String>,
    directories: &mut BTreeSet<String>,
) -> Result<()> {
    for name in read_entries(directory, &root_path.join(relative_directory))? {
        let relative = relative_directory.join(&name);
        let relative_text = relative_path(&relative)?;
        let path = root_path.join(&relative);
        let entry = open_entry(directory, &name, &path, false)?;
        let metadata = entry.metadata(&path)?;
        if metadata.is_dir() {
            let directory_entry = open_entry(directory, &name, &path, true)?;
            if !directory_entry.metadata(&path)?.is_dir() {
                return Err(unsafe_path(&path));
            }
            directories.insert(relative_text);
            collect_regular_files_inner(
                &directory_entry,
                root_path,
                &relative,
                output,
                directories,
            )?;
        } else if metadata.is_file() {
            output.insert(relative_text);
        } else {
            return Err(validation(format!(
                "run snapshot rejects non-regular file: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_regular_no_follow(root: &OpenFd, root_path: &Path, relative: &str) -> Result<Vec<u8>> {
    use std::{io::Read, os::fd::FromRawFd};

    validate_relative(relative)?;
    let path = root_path.join(relative);
    let mut components = Path::new(relative)
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_owned()),
            _ => Err(validation(format!("unsafe run checksum path: {relative}"))),
        })
        .collect::<Result<Vec<_>>>()?;
    let file_name = components
        .pop()
        .ok_or_else(|| validation(format!("unsafe run checksum path: {relative}")))?;
    let mut parent = duplicate_fd(root, root_path)?;
    for component in components {
        let directory_path = root_path.join(relative);
        let next = open_entry(&parent, &component, &directory_path, true)?;
        if !next.metadata(&directory_path)?.is_dir() {
            return Err(unsafe_path(&directory_path));
        }
        parent = next;
    }
    let entry = open_entry(&parent, &file_name, &path, false)?;
    let before = entry.metadata(&path)?;
    if !before.is_file() {
        return Err(validation(format!(
            "run evidence is not a regular file: {}",
            path.display()
        )));
    }
    // SAFETY: File takes exclusive ownership of the descriptor from entry.
    let mut file = unsafe { std::fs::File::from_raw_fd(entry.0) };
    std::mem::forget(entry);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| read_error(&path))?;
    let after = file.metadata().map_err(|_| read_error(&path))?;
    if !same_metadata(&before, &after) {
        return Err(validation(format!(
            "run evidence changed while reading: {relative}"
        )));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn collect_regular_files(
    _root: &OpenFd,
    _root_path: &Path,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    Err(validation(
        "verified run snapshot requires Unix no-follow support",
    ))
}

#[cfg(not(unix))]
fn read_regular_no_follow(_root: &OpenFd, _root_path: &Path, _relative: &str) -> Result<Vec<u8>> {
    Err(validation(
        "verified run snapshot requires Unix no-follow support",
    ))
}

#[cfg(unix)]
fn duplicate_fd(fd: &OpenFd, path: &Path) -> Result<OpenFd> {
    // SAFETY: dup creates a new descriptor referring to the same opened object.
    let duplicate = unsafe { libc::dup(fd.0) };
    if duplicate < 0 {
        return Err(read_error(path));
    }
    Ok(OpenFd(duplicate))
}

#[cfg(unix)]
fn same_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.size() == right.size()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_metadata(_left: &std::fs::Metadata, _right: &std::fs::Metadata) -> bool {
    false
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    #[test]
    fn same_metadata_rejects_mode_only_change() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let before = temporary.as_file().metadata().unwrap();
        let before_mode = before.permissions().mode();
        let changed_mode = if before_mode & 0o100 == 0 {
            before_mode | 0o100
        } else {
            before_mode & !0o100
        };

        std::fs::set_permissions(
            temporary.path(),
            std::fs::Permissions::from_mode(changed_mode),
        )
        .unwrap();
        let after = temporary.as_file().metadata().unwrap();

        assert_ne!(before.mode(), after.mode());
        assert!(!same_metadata(&before, &after));
    }

    #[test]
    fn runner_evidence_digest_matches_runner_depth_first_tree_order() {
        let mut files = BTreeMap::new();
        files.insert("findings.jsonl".to_owned(), b"findings\n".to_vec());
        files.insert(
            "artifacts/observations.jsonl".to_owned(),
            b"observations\n".to_vec(),
        );
        files.insert(
            "logs/children/case/attempts/0/trace/segment.jsonl".to_owned(),
            b"segment\n".to_vec(),
        );
        files.insert(
            "logs/children/case/attempts/0/trace.jsonl".to_owned(),
            b"flat\n".to_vec(),
        );

        let directories = BTreeSet::from([
            "artifacts".to_owned(),
            "logs".to_owned(),
            "logs/children".to_owned(),
            "logs/children/case".to_owned(),
            "logs/children/case/attempts".to_owned(),
            "logs/children/case/attempts/0".to_owned(),
            "logs/children/case/attempts/0/trace".to_owned(),
        ]);

        let actual = runner_evidence_digest(&files, &directories).unwrap();
        let expected = expected_runner_order_digest(&files);

        assert_eq!(actual, expected);
    }

    fn expected_runner_order_digest(files: &BTreeMap<String, Vec<u8>>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"boundary-witness.runner-evidence-digest/0.1\0");
        hash_test_file(&mut hasher, files, "findings.jsonl");
        hash_test_file(&mut hasher, files, "artifacts/observations.jsonl");
        hash_test_absent_tree(&mut hasher, "artifacts/witnesses");
        hasher.update(b"T");
        hasher.update(b"logs/children");
        hasher.update([0]);
        hasher.update(b"present");
        hash_test_file(
            &mut hasher,
            files,
            "logs/children/case/attempts/0/trace/segment.jsonl",
        );
        hash_test_file(
            &mut hasher,
            files,
            "logs/children/case/attempts/0/trace.jsonl",
        );
        hash_test_absent_tree(&mut hasher, "traces");
        sha256_digest(hasher)
    }

    fn hash_test_file(hasher: &mut Sha256, files: &BTreeMap<String, Vec<u8>>, relative: &str) {
        let bytes = files.get(relative).unwrap();
        hasher.update(b"F");
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(Sha256::digest(bytes));
    }

    fn hash_test_absent_tree(hasher: &mut Sha256, relative: &str) {
        hasher.update(b"T");
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(b"absent");
    }
}

fn relative_path(relative: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(validation("invalid run snapshot path"));
        };
        parts.push(
            part.to_str()
                .ok_or_else(|| validation("run snapshot path must be UTF-8"))?,
        );
    }
    let path = parts.join("/");
    validate_relative(&path)?;
    Ok(path)
}

fn ensure_evidence_tree_roots(
    files: &BTreeSet<String>,
    directories: &BTreeSet<String>,
) -> Result<()> {
    for root in ["artifacts/witnesses", "logs/children", "traces"] {
        if files.contains(root) {
            return Err(validation(format!(
                "runner evidence root is not a directory: {root}"
            )));
        }
        let prefix = format!("{root}/");
        if files.iter().any(|path| path.starts_with(&prefix)) && !directories.contains(root) {
            return Err(validation(format!(
                "runner evidence root is not a directory: {root}"
            )));
        }
    }
    Ok(())
}

fn read_error(path: &Path) -> CuratorError {
    CuratorError::Validation(format!(
        "failed to read verified run snapshot: {}",
        path.display()
    ))
}

fn unsafe_path(path: &Path) -> CuratorError {
    CuratorError::Validation(format!(
        "run snapshot rejects symlink or unsafe path: {}",
        path.display()
    ))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_errno_zero() {
    // SAFETY: libc exposes thread-local errno storage on supported Unix targets.
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(target_os = "macos")]
fn set_errno_zero() {
    // SAFETY: libc exposes thread-local errno storage on macOS.
    unsafe { *libc::__error() = 0 };
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn set_errno_zero() {}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn last_errno() -> libc::c_int {
    // SAFETY: libc exposes thread-local errno storage on supported Unix targets.
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn last_errno() -> libc::c_int {
    // SAFETY: libc exposes thread-local errno storage on macOS.
    unsafe { *libc::__error() }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn last_errno() -> libc::c_int {
    0
}

fn validate_relative(path: &str) -> Result<()> {
    if path.is_empty() || Path::new(path).is_absolute() || path.contains('\\') {
        return Err(validation(format!("unsafe run checksum path: {path}")));
    }
    for component in Path::new(path).components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(validation(format!("unsafe run checksum path: {path}")));
        }
    }
    Ok(())
}

fn runner_evidence_digest(
    files: &BTreeMap<String, Vec<u8>>,
    directories: &BTreeSet<String>,
) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"boundary-witness.runner-evidence-digest/0.1\0");
    hash_evidence_file(&mut hasher, files, "findings.jsonl")?;
    hash_evidence_file(&mut hasher, files, "artifacts/observations.jsonl")?;
    for root in ["artifacts/witnesses", "logs/children", "traces"] {
        hash_evidence_tree(&mut hasher, files, directories, root);
    }
    Ok(sha256_digest(hasher))
}

fn hash_evidence_file(
    hasher: &mut Sha256,
    files: &BTreeMap<String, Vec<u8>>,
    relative: &str,
) -> Result<()> {
    let bytes = files
        .get(relative)
        .ok_or_else(|| validation(format!("missing runner evidence file: {relative}")))?;
    hasher.update(b"F");
    hasher.update(relative.as_bytes());
    hasher.update([0]);
    hasher.update(Sha256::digest(bytes));
    Ok(())
}

fn hash_evidence_tree(
    hasher: &mut Sha256,
    files: &BTreeMap<String, Vec<u8>>,
    directories: &BTreeSet<String>,
    root: &str,
) {
    hasher.update(b"T");
    hasher.update(root.as_bytes());
    hasher.update([0]);
    let prefix = format!("{root}/");
    if directories.contains(root) || files.keys().any(|path| path.starts_with(&prefix)) {
        hasher.update(b"present");
        hash_evidence_tree_entries(hasher, files, directories, root);
    } else {
        hasher.update(b"absent");
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceTreeEntry {
    Directory,
    File,
}

fn hash_evidence_tree_entries(
    hasher: &mut Sha256,
    files: &BTreeMap<String, Vec<u8>>,
    directories: &BTreeSet<String>,
    directory: &str,
) {
    for (name, kind) in immediate_evidence_children(files, directories, directory) {
        let relative = format!("{directory}/{name}");
        match kind {
            EvidenceTreeEntry::Directory => {
                hash_evidence_tree_entries(hasher, files, directories, &relative);
            }
            EvidenceTreeEntry::File => {
                hash_evidence_file(hasher, files, &relative)
                    .expect("immediate evidence file must exist");
            }
        }
    }
}

fn immediate_evidence_children(
    files: &BTreeMap<String, Vec<u8>>,
    directories: &BTreeSet<String>,
    directory: &str,
) -> BTreeMap<String, EvidenceTreeEntry> {
    let prefix = format!("{directory}/");
    let mut children = BTreeMap::new();
    for child_directory in directories.range(prefix.clone()..) {
        if !child_directory.starts_with(&prefix) {
            break;
        }
        if let Some(name) = immediate_child_name(&prefix, child_directory) {
            children.insert(name.to_owned(), EvidenceTreeEntry::Directory);
        }
    }
    for child_file in files.range(prefix.clone()..) {
        let path = child_file.0;
        if !path.starts_with(&prefix) {
            break;
        }
        let Some(name) = immediate_child_name(&prefix, path) else {
            continue;
        };
        let kind = if path[prefix.len() + name.len()..].starts_with('/') {
            EvidenceTreeEntry::Directory
        } else {
            EvidenceTreeEntry::File
        };
        children.entry(name.to_owned()).or_insert(kind);
    }
    children
}

fn immediate_child_name<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    let rest = path.strip_prefix(prefix)?;
    if rest.is_empty() {
        return None;
    }
    Some(rest.split_once('/').map_or(rest, |(name, _)| name))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sha256_hex(bytes: &[u8]) -> String {
    sha256_digest(Sha256::new_with_prefix(bytes))
}
fn sha256_digest(hasher: Sha256) -> String {
    format!("{:x}", hasher.finalize())
}
fn validation(message: impl Into<String>) -> CuratorError {
    CuratorError::Validation(message.into())
}
