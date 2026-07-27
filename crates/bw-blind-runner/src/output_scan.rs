use std::path::Path;

use bw_blind_model::BlindPolicy;

use crate::{AuditError, Result};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct OutputScanReport {
    pub scanned_files: usize,
}

pub(crate) fn scan_child_output(root: &Path, policy: &BlindPolicy) -> Result<OutputScanReport> {
    scan_output(root, policy)
}

pub(crate) fn scan_finalized_candidate(
    root: &Path,
    policy: &BlindPolicy,
) -> Result<OutputScanReport> {
    scan_output(root, policy)
}

pub(crate) fn scan_summary_value(summary: &serde_json::Value, policy: &BlindPolicy) -> Result<()> {
    let serialized = serde_json::to_string(summary)?;
    if let Some(token) = policy.find_forbidden_public_token(&serialized) {
        return Err(AuditError::Validation(format!(
            "runner output summary contains forbidden public token: {token}"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn scan_output(root: &Path, policy: &BlindPolicy) -> Result<OutputScanReport> {
    use std::{
        fs::File,
        io::Read,
        os::{
            fd::FromRawFd,
            unix::{ffi::OsStringExt, fs::MetadataExt},
        },
    };

    struct OpenFd(libc::c_int);

    impl Drop for OpenFd {
        fn drop(&mut self) {
            // SAFETY: this type exclusively owns the descriptor unless converted into File.
            unsafe { libc::close(self.0) };
        }
    }

    impl OpenFd {
        fn into_file(self) -> File {
            let descriptor = self.0;
            std::mem::forget(self);
            // SAFETY: ownership of this valid descriptor moves from OpenFd to File.
            unsafe { File::from_raw_fd(descriptor) }
        }
    }

    fn open_root(path: &Path) -> Result<OpenFd> {
        use std::os::unix::ffi::OsStrExt;

        let bytes = path.as_os_str().as_bytes();
        let c_path = std::ffi::CString::new(bytes).map_err(|_| unsafe_output(path))?;
        // SAFETY: c_path is NUL-terminated and remains alive for this call.
        let descriptor = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            return Err(unsafe_output(path));
        }
        Ok(OpenFd(descriptor))
    }

    fn open_entry(parent: &OpenFd, name: &std::ffi::OsStr, path: &Path) -> Result<OpenFd> {
        use std::os::unix::ffi::OsStrExt;

        let c_name = std::ffi::CString::new(name.as_bytes()).map_err(|_| unsafe_output(path))?;
        // SAFETY: parent is an open directory descriptor and c_name is a single NUL-terminated
        // directory entry name sourced from readdir.
        let descriptor = unsafe {
            libc::openat(
                parent.0,
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            return Err(unsafe_output(path));
        }
        Ok(OpenFd(descriptor))
    }

    fn metadata(fd: &OpenFd, path: &Path) -> Result<libc::stat> {
        // SAFETY: stat is initialized by fstat on success and fd is valid while OpenFd is alive.
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: stat points to writable storage for the fstat result.
        if unsafe { libc::fstat(fd.0, &mut stat) } != 0 {
            return Err(unsafe_output(path));
        }
        Ok(stat)
    }

    fn is_directory(stat: &libc::stat) -> bool {
        stat.st_mode & libc::S_IFMT == libc::S_IFDIR
    }

    fn is_regular_file(stat: &libc::stat) -> bool {
        stat.st_mode & libc::S_IFMT == libc::S_IFREG
    }

    fn read_entries(fd: &OpenFd, path: &Path) -> Result<Vec<std::ffi::OsString>> {
        // SAFETY: dup creates an independently owned descriptor for fdopendir to consume.
        let duplicate = unsafe { libc::dup(fd.0) };
        if duplicate < 0 {
            return Err(unsafe_output(path));
        }
        // SAFETY: fdopendir consumes duplicate on success; on failure we close it below.
        let directory = unsafe { libc::fdopendir(duplicate) };
        if directory.is_null() {
            // SAFETY: fdopendir did not take ownership on failure.
            unsafe { libc::close(duplicate) };
            return Err(unsafe_output(path));
        }

        let mut entries = Vec::new();
        loop {
            set_errno_zero();
            // SAFETY: directory remains valid until closed below.
            let entry = unsafe { libc::readdir(directory) };
            if entry.is_null() {
                if last_errno() != 0 {
                    // SAFETY: closedir consumes the directory descriptor.
                    unsafe { libc::closedir(directory) };
                    return Err(unsafe_output(path));
                }
                break;
            }
            // SAFETY: d_name is NUL-terminated for the lifetime of the directory stream.
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                entries.push(std::ffi::OsString::from_vec(name.to_vec()));
            }
        }
        // SAFETY: closedir consumes the directory descriptor exactly once.
        if unsafe { libc::closedir(directory) } != 0 {
            return Err(unsafe_output(path));
        }
        entries.sort();
        Ok(entries)
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

    fn scan_directory(
        root: &Path,
        directory: &OpenFd,
        relative_directory: &Path,
        policy: &BlindPolicy,
        report: &mut OutputScanReport,
    ) -> Result<()> {
        for name in read_entries(directory, &root.join(relative_directory))? {
            let relative = relative_directory.join(&name);
            scan_name(&relative, policy)?;
            let path = root.join(&relative);
            let entry = open_entry(directory, &name, &path)?;
            let stat = metadata(&entry, &path)?;
            if is_directory(&stat) {
                scan_directory(root, &entry, &relative, policy, report)?;
            } else if is_regular_file(&stat) {
                if stat.st_nlink > 1 {
                    return Err(unsafe_output(&path));
                }
                let mut contents = Vec::new();
                let mut file = entry.into_file();
                file.read_to_end(&mut contents)
                    .map_err(|source| AuditError::Read {
                        path: path.clone(),
                        source,
                    })?;
                if file.metadata().map_err(|_| unsafe_output(&path))?.nlink() > 1 {
                    return Err(unsafe_output(&path));
                }
                if let Some(token) =
                    policy.find_forbidden_public_token(&String::from_utf8_lossy(&contents))
                {
                    return Err(forbidden_output(token, &relative));
                }
                report.scanned_files += 1;
            } else {
                return Err(unsafe_output(&path));
            }
        }
        Ok(())
    }

    let root_fd = open_root(root)?;
    if !is_directory(&metadata(&root_fd, root)?) {
        return Err(unsafe_output(root));
    }
    let mut report = OutputScanReport::default();
    scan_directory(root, &root_fd, Path::new(""), policy, &mut report)?;
    Ok(report)
}

#[cfg(not(unix))]
fn scan_output(root: &Path, _policy: &BlindPolicy) -> Result<OutputScanReport> {
    Err(AuditError::Validation(format!(
        "runner output scan requires Unix no-follow support: {}",
        root.display()
    )))
}

fn scan_name(relative: &Path, policy: &BlindPolicy) -> Result<()> {
    let name = relative.to_string_lossy();
    if let Some(token) = policy.find_forbidden_public_token(&name) {
        return Err(forbidden_output(token, relative));
    }
    Ok(())
}

fn forbidden_output(token: &str, relative: &Path) -> AuditError {
    AuditError::Validation(format!(
        "runner output contains forbidden token: {token}: {}",
        relative.to_string_lossy()
    ))
}

fn unsafe_output(path: &Path) -> AuditError {
    AuditError::Validation(format!(
        "runner output contains unsafe path: {}",
        path.display()
    ))
}
