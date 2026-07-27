use std::{
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};

use crate::site::SiteIdentityError;

pub fn stable_relative_path(
    path: &Path,
    repo_root: Option<&Path>,
) -> Result<String, SiteIdentityError> {
    let relative = match repo_root {
        Some(root) => path
            .strip_prefix(root)
            .map_err(|_| SiteIdentityError::AbsolutePath {
                path: path.to_path_buf(),
            })?
            .to_path_buf(),
        None if path.is_absolute() => {
            return Err(SiteIdentityError::AbsolutePath {
                path: path.to_path_buf(),
            });
        }
        None => path.to_path_buf(),
    };
    normalize_relative(&relative)
}

fn normalize_relative(path: &Path) -> Result<String, SiteIdentityError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(os_to_string(part)?),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(SiteIdentityError::AbsolutePath {
                    path: PathBuf::from(path),
                });
            }
        }
    }
    if parts.is_empty() {
        return Err(SiteIdentityError::EmptyRelativePath);
    }
    Ok(parts.join("/"))
}

fn os_to_string(value: &OsStr) -> Result<String, SiteIdentityError> {
    value
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or(SiteIdentityError::NonUtf8Path)
}
