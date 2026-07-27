use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    commands::write_json_stdout,
    exit::{CliError, CommandStatus},
};

#[derive(Args)]
pub struct VerifyRunArgs {
    #[arg(long = "run-dir")]
    run_dir: PathBuf,
    #[arg(long, default_value = "checksums.sha256")]
    checksums: PathBuf,
}

#[derive(Serialize)]
struct VerifyRunOutput {
    kind: &'static str,
    run_dir: String,
    checksums_path: String,
    verified_count: u64,
}

pub fn run(args: VerifyRunArgs) -> Result<CommandStatus, CliError> {
    let checksums_path = resolve_checksums_path(&args.run_dir, &args.checksums)?;
    let checksum_text = fs::read_to_string(&checksums_path).map_err(|error| {
        CliError::input(
            "BW-V32-VERIFY-IO",
            format!("{}: {error}", checksums_path.display()),
        )
    })?;
    let expected = parse_checksums(&checksum_text)?;
    let actual_files = collect_regular_files(&args.run_dir)?;
    let checksums_relative = args.checksums.to_string_lossy().replace('\\', "/");

    for relative in actual_files {
        if relative == checksums_relative
            || relative == "checksums.sha256"
            || relative.ends_with("/checksums.sha256")
        {
            continue;
        }
        if !expected.contains_key(&relative) {
            return Err(CliError::input(
                "BW-V32-VERIFY-EXTRA-FILE",
                format!("run directory contains unchecksummed file `{relative}`"),
            ));
        }
    }

    for (relative, expected_digest) in &expected {
        let path = args.run_dir.join(relative);
        let actual = sha256_file(&path)?;
        if &actual != expected_digest {
            return Err(CliError::input(
                "BW-V32-VERIFY-CHECKSUM",
                format!(
                    "checksum mismatch for `{relative}`: expected {expected_digest}, got {actual}"
                ),
            ));
        }
    }

    write_json_stdout(&VerifyRunOutput {
        kind: "v3-2-verify-run",
        run_dir: args.run_dir.display().to_string(),
        checksums_path: checksums_path.display().to_string(),
        verified_count: expected.len() as u64,
    })?;
    Ok(CommandStatus::Success)
}

fn resolve_checksums_path(run_dir: &Path, checksums: &Path) -> Result<PathBuf, CliError> {
    if checksums.is_absolute()
        || checksums
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(CliError::input(
            "BW-V32-VERIFY-CHECKSUM-PATH",
            "checksums 必须是 run-dir 下的相对路径，不能是绝对路径或包含 ..",
        ));
    }
    Ok(run_dir.join(checksums))
}

fn parse_checksums(input: &str) -> Result<BTreeMap<String, String>, CliError> {
    let mut checksums = BTreeMap::<String, String>::new();
    for (index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            return Err(CliError::input(
                "BW-V32-VERIFY-CHECKSUM-LINE",
                format!("checksums.sha256 line {} 不能为空", index + 1),
            ));
        }
        let Some((digest, path)) = line.split_once("  ") else {
            return Err(CliError::input(
                "BW-V32-VERIFY-CHECKSUM-LINE",
                format!(
                    "checksums.sha256 line {} 必须是 `<sha256>  <path>`",
                    index + 1
                ),
            ));
        };
        validate_digest(index + 1, digest)?;
        validate_relative_checksum_path(index + 1, path)?;
        if checksums
            .insert(path.to_owned(), digest.to_owned())
            .is_some()
        {
            return Err(CliError::input(
                "BW-V32-VERIFY-CHECKSUM-DUPLICATE",
                format!("checksums.sha256 line {} 的路径重复", index + 1),
            ));
        }
    }
    if checksums.is_empty() {
        return Err(CliError::input(
            "BW-V32-VERIFY-CHECKSUM-EMPTY",
            "checksums.sha256 至少需要一条记录",
        ));
    }
    Ok(checksums)
}

fn validate_digest(line: usize, digest: &str) -> Result<(), CliError> {
    if digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(CliError::input(
            "BW-V32-VERIFY-CHECKSUM-DIGEST",
            format!("line {line} 的 sha256 digest 必须是 64 位十六进制"),
        ));
    }
    if digest.chars().any(|ch| ch.is_ascii_uppercase()) {
        return Err(CliError::input(
            "BW-V32-VERIFY-CHECKSUM-DIGEST",
            format!("line {line} 的 sha256 digest 必须使用小写十六进制"),
        ));
    }
    Ok(())
}

fn validate_relative_checksum_path(line: usize, path: &str) -> Result<(), CliError> {
    if path.trim().is_empty() {
        return Err(CliError::input(
            "BW-V32-VERIFY-CHECKSUM-PATH",
            format!("line {line} 的 checksum path 不能为空"),
        ));
    }
    let path_ref = Path::new(path);
    if path == "checksums.sha256"
        || path_ref.is_absolute()
        || path_ref.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(CliError::input(
            "BW-V32-VERIFY-CHECKSUM-PATH",
            format!("line {line} 的 checksum path 必须是安全相对路径且不能指向 checksums.sha256"),
        ));
    }
    Ok(())
}

fn collect_regular_files(root: &Path) -> Result<BTreeSet<String>, CliError> {
    let mut files = BTreeSet::<String>::new();
    collect_regular_files_inner(root, root, &mut files)?;
    Ok(files)
}

fn collect_regular_files_inner(
    root: &Path,
    dir: &Path,
    files: &mut BTreeSet<String>,
) -> Result<(), CliError> {
    for entry in fs::read_dir(dir).map_err(|error| {
        CliError::input("BW-V32-VERIFY-IO", format!("{}: {error}", dir.display()))
    })? {
        let entry =
            entry.map_err(|error| CliError::input("BW-V32-VERIFY-IO", error.to_string()))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            CliError::input("BW-V32-VERIFY-IO", format!("{}: {error}", path.display()))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CliError::input(
                "BW-V32-VERIFY-SYMLINK",
                format!("run directory contains symlink `{}`", path.display()),
            ));
        }
        if metadata.is_dir() {
            collect_regular_files_inner(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path.strip_prefix(root).map_err(|error| {
                CliError::input("BW-V32-VERIFY-IO", format!("{}: {error}", path.display()))
            })?;
            files.insert(relative.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, CliError> {
    let bytes = fs::read(path).map_err(|error| {
        CliError::input("BW-V32-VERIFY-IO", format!("{}: {error}", path.display()))
    })?;
    Ok(hex_digest(Sha256::digest(bytes)))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
