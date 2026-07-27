use std::{fmt, fs, path::PathBuf};

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct CargoMetadata {
    pub packages: Vec<MetadataPackage>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MetadataPackage {
    #[serde(rename = "id")]
    pub _id: String,
    pub name: String,
    pub version: String,
    #[serde(rename = "manifest_path")]
    pub _manifest_path: PathBuf,
    #[serde(default)]
    pub targets: Vec<MetadataTarget>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MetadataTarget {
    pub name: String,
    #[serde(default)]
    pub kind: Vec<String>,
    #[serde(default)]
    pub crate_types: Vec<String>,
    pub src_path: PathBuf,
}

impl MetadataPackage {
    pub fn has_target(&self, crate_name: &str, target_kind: &str) -> bool {
        self.targets
            .iter()
            .any(|target| target.matches(crate_name, target_kind))
    }
}

impl MetadataTarget {
    fn matches(&self, crate_name: &str, target_kind: &str) -> bool {
        let crate_name_matches =
            self.name == crate_name || self.name.replace('-', "_") == crate_name;
        let kind_matches = self.kind.iter().any(|kind| kind == target_kind)
            || self
                .crate_types
                .iter()
                .any(|crate_type| crate_type == target_kind);
        crate_name_matches && kind_matches && !self.src_path.as_os_str().is_empty()
    }
}

impl CargoMetadata {
    pub fn from_path(path: PathBuf) -> Result<Self, MetadataError> {
        let input = fs::read_to_string(&path).map_err(|source| MetadataError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&input).map_err(|source| MetadataError::Parse { path, source })
    }

    pub fn package(&self, name: &str, version: Option<&str>) -> Option<&MetadataPackage> {
        self.packages.iter().find(|package| {
            package.name == name && version.is_none_or(|version| version == package.version)
        })
    }
}

#[derive(Debug)]
pub enum MetadataError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
}

impl fmt::Display for MetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(formatter, "{}: {}", path.display(), source),
            Self::Parse { path, source } => write!(formatter, "{}: {}", path.display(), source),
        }
    }
}

impl std::error::Error for MetadataError {}
