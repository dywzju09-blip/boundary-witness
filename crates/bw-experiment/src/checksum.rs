use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs::{self, File},
    io::Read,
    path::{Component, Path},
};

use sha2::{Digest, Sha256};

use crate::{ExperimentError, Result, layout::validate_safe_relative_path};

const CHECKSUM_FILE: &str = "checksums.sha256";
const REQUIRED_FINAL_FILES: &[&str] = &[
    "manifest.json",
    "findings.jsonl",
    "summary.json",
    "COMPLETE",
];

pub(crate) fn write_run_checksums(run_path: &Path) -> Result<()> {
    let files = collect_regular_files(run_path)?;
    let checksum_path = run_path.join(CHECKSUM_FILE);
    let mut output = String::new();
    for relative in files {
        let absolute = run_path.join(&relative);
        let digest = sha256_path(&absolute)?;
        writeln!(&mut output, "{digest}  {relative}").expect("writing to String cannot fail");
    }
    fs::write(&checksum_path, output).map_err(|error| ExperimentError::io(checksum_path, error))
}

pub fn verify_run_integrity(run_path: impl AsRef<Path>) -> Result<()> {
    let run_path = run_path.as_ref();
    if !run_path.is_dir() {
        return Err(ExperimentError::InvalidInput(format!(
            "run directory does not exist: {}",
            run_path.display()
        )));
    }

    let checksum_path = run_path.join(CHECKSUM_FILE);
    let checksum_text = fs::read_to_string(&checksum_path)
        .map_err(|error| ExperimentError::io(&checksum_path, error))?;
    let expected = parse_checksums(&checksum_text)?;

    for required in REQUIRED_FINAL_FILES {
        if !expected.contains_key(*required) {
            return Err(ExperimentError::MissingChecksummedFile {
                path: (*required).to_owned(),
            });
        }
    }

    for (relative, expected_digest) in &expected {
        let absolute = run_path.join(relative);
        let metadata = fs::symlink_metadata(&absolute).map_err(|_| {
            ExperimentError::MissingChecksummedFile {
                path: relative.clone(),
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ExperimentError::Symlink { path: absolute });
        }
        if !metadata.is_file() {
            return Err(ExperimentError::UnsupportedFileType { path: absolute });
        }
        let actual_digest = sha256_path(&absolute)?;
        if &actual_digest != expected_digest {
            return Err(ExperimentError::ChecksumMismatch {
                path: relative.clone(),
                actual: actual_digest,
                expected: expected_digest.clone(),
            });
        }
    }

    let actual_files: BTreeSet<String> = collect_regular_files(run_path)?.into_iter().collect();
    for actual in actual_files {
        if !expected.contains_key(&actual) {
            return Err(ExperimentError::UnchecksummedFile { path: actual });
        }
    }

    Ok(())
}

fn parse_checksums(input: &str) -> Result<BTreeMap<String, String>> {
    let mut checksums = BTreeMap::new();
    for (index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Some((digest, path)) = line.split_once("  ") else {
            return Err(ExperimentError::InvalidInput(format!(
                "invalid checksum line {}",
                index + 1
            )));
        };
        if digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(ExperimentError::InvalidInput(format!(
                "invalid checksum digest on line {}",
                index + 1
            )));
        }
        validate_safe_relative_path(path)?;
        if path == CHECKSUM_FILE {
            return Err(ExperimentError::UnsafePath {
                path: path.to_owned(),
            });
        }
        if checksums
            .insert(path.to_owned(), digest.to_ascii_lowercase())
            .is_some()
        {
            return Err(ExperimentError::InvalidInput(format!(
                "duplicate checksum path: {path}"
            )));
        }
    }
    Ok(checksums)
}

fn collect_regular_files(root: &Path) -> Result<Vec<String>> {
    let mut output = Vec::new();
    collect_regular_files_inner(root, root, &mut output)?;
    output.sort();
    Ok(output)
}

fn collect_regular_files_inner(
    root: &Path,
    current: &Path,
    output: &mut Vec<String>,
) -> Result<()> {
    let metadata =
        fs::symlink_metadata(current).map_err(|error| ExperimentError::io(current, error))?;
    if metadata.file_type().is_symlink() {
        return Err(ExperimentError::Symlink {
            path: current.to_path_buf(),
        });
    }
    if metadata.is_dir() {
        let mut entries = fs::read_dir(current)
            .map_err(|error| ExperimentError::io(current, error))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| ExperimentError::io(current, error))?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            collect_regular_files_inner(root, &entry.path(), output)?;
        }
        return Ok(());
    }
    if metadata.is_file() {
        let relative = relative_slash_path(root, current)?;
        if relative != CHECKSUM_FILE {
            output.push(relative);
        }
        return Ok(());
    }
    Err(ExperimentError::UnsupportedFileType {
        path: current.to_path_buf(),
    })
}

fn relative_slash_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ExperimentError::UnsafePath {
            path: path.display().to_string(),
        })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => {
                let Some(value) = value.to_str() else {
                    return Err(ExperimentError::UnsafePath {
                        path: relative.display().to_string(),
                    });
                };
                parts.push(value.to_owned());
            }
            _ => {
                return Err(ExperimentError::UnsafePath {
                    path: relative.display().to_string(),
                });
            }
        }
    }
    let result = parts.join("/");
    validate_safe_relative_path(&result)?;
    Ok(result)
}

fn sha256_path(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|error| ExperimentError::io(path, error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| ExperimentError::io(path, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
}
