use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, OpenOptions},
    io::ErrorKind,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::config::AnalysisRequest;

pub const MIR_COVERAGE_SCHEMA_V01: &str = "bw.mir-coverage/0.1";

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedPackage {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeenTarget {
    pub package: String,
    pub version: String,
    pub target: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeenBody {
    pub package: String,
    pub version: String,
    pub target: String,
    pub def_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkippedBody {
    pub package: String,
    pub version: String,
    pub target: String,
    pub def_path: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirCoverageReport {
    pub schema_version: String,
    pub expected_packages: Vec<ExpectedPackage>,
    pub seen_packages: Vec<ExpectedPackage>,
    pub seen_targets: Vec<SeenTarget>,
    pub seen_bodies: Vec<SeenBody>,
    pub skipped: Vec<SkippedBody>,
}

impl MirCoverageReport {
    fn empty(expected_packages: Vec<ExpectedPackage>) -> Self {
        Self {
            schema_version: MIR_COVERAGE_SCHEMA_V01.to_owned(),
            expected_packages,
            seen_packages: Vec::new(),
            seen_targets: Vec::new(),
            seen_bodies: Vec::new(),
            skipped: Vec::new(),
        }
    }

    fn merge(&mut self, other: Self) {
        self.expected_packages = union(
            self.expected_packages.iter().cloned(),
            other.expected_packages,
        );
        self.seen_packages = union(self.seen_packages.iter().cloned(), other.seen_packages);
        self.seen_targets = union(self.seen_targets.iter().cloned(), other.seen_targets);
        self.seen_bodies = union(self.seen_bodies.iter().cloned(), other.seen_bodies);
        self.skipped = union(self.skipped.iter().cloned(), other.skipped);
    }
}

pub fn write_mir_coverage(
    request: &AnalysisRequest,
    seen_bodies: &[String],
) -> Result<(), CoverageError> {
    fs::create_dir_all(&request.output_dir)?;
    let _lock = MirCoverageWriteLock::acquire(&request.output_dir)?;
    let final_path = request.output_dir.join("mir-coverage.json");
    let mut report = read_existing(&final_path)?
        .unwrap_or_else(|| MirCoverageReport::empty(request.expected_packages.clone()));
    report.merge(process_report(request, seen_bodies));
    let partial_path = request
        .output_dir
        .join(format!("mir-coverage.json.{}.partial", std::process::id()));
    fs::write(&partial_path, serde_json::to_vec_pretty(&report)?)?;
    fs::rename(&partial_path, final_path)?;
    Ok(())
}

fn process_report(request: &AnalysisRequest, seen_bodies: &[String]) -> MirCoverageReport {
    let mut report = MirCoverageReport::empty(request.expected_packages.clone());
    report.seen_packages.push(ExpectedPackage {
        name: request.package_name.clone(),
        version: request.package_version.clone(),
    });
    report.seen_targets.push(SeenTarget {
        package: request.package_name.clone(),
        version: request.package_version.clone(),
        target: request.target.clone(),
    });
    report.seen_bodies = seen_bodies
        .iter()
        .map(|def_path| SeenBody {
            package: request.package_name.clone(),
            version: request.package_version.clone(),
            target: request.target.clone(),
            def_path: def_path.clone(),
        })
        .collect();
    report
}

fn read_existing(path: &Path) -> Result<Option<MirCoverageReport>, CoverageError> {
    if !path.exists() {
        return Ok(None);
    }
    let input = fs::read_to_string(path).map_err(|source| CoverageError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&input)
        .map(Some)
        .map_err(|source| CoverageError::Parse {
            path: path.to_path_buf(),
            source,
        })
}

fn union<T>(left: impl IntoIterator<Item = T>, right: impl IntoIterator<Item = T>) -> Vec<T>
where
    T: Ord,
{
    left.into_iter()
        .chain(right)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[derive(Debug)]
pub enum CoverageError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    Io(std::io::Error),
    Serde(serde_json::Error),
    LockTimeout {
        path: PathBuf,
    },
}

struct MirCoverageWriteLock {
    path: PathBuf,
    _file: fs::File,
}

impl MirCoverageWriteLock {
    fn acquire(output_dir: &Path) -> Result<Self, CoverageError> {
        let path = output_dir.join(".mir-coverage.lock");
        for _ in 0..200 {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok(Self { path, _file: file }),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(CoverageError::Io(error)),
            }
        }
        Err(CoverageError::LockTimeout { path })
    }
}

impl Drop for MirCoverageWriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl fmt::Display for CoverageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(formatter, "{}: {}", path.display(), source),
            Self::Parse { path, source } => write!(formatter, "{}: {}", path.display(), source),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Serde(error) => write!(formatter, "{error}"),
            Self::LockTimeout { path } => {
                write!(
                    formatter,
                    "timed out waiting for MIR coverage lock {}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for CoverageError {}

impl From<std::io::Error> for CoverageError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for CoverageError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serde(value)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{Arc, Barrier},
        thread,
    };

    use tempfile::tempdir;

    use super::*;

    fn request(output_dir: &std::path::Path, package: &str, target: &str) -> AnalysisRequest {
        AnalysisRequest {
            crate_name: package.to_owned(),
            crate_id: package.to_owned(),
            package_name: package.to_owned(),
            package_version: "1.0.0".to_owned(),
            target: target.to_owned(),
            output_dir: output_dir.to_owned(),
            package_root: output_dir.to_owned(),
            expected_packages: vec![],
            collection_lookup_contracts: vec![],
            callback_retention_api_maps: vec![],
        }
    }

    #[test]
    fn concurrent_writes_retain_packages_targets_and_bodies() {
        let temp = tempdir().expect("tempdir should be created");
        let barrier = Arc::new(Barrier::new(2));
        let first_request = request(temp.path(), "package-a", "target-a");
        let second_request = request(temp.path(), "package-b", "target-b");

        let first_barrier = Arc::clone(&barrier);
        let first = thread::spawn(move || {
            first_barrier.wait();
            write_mir_coverage(&first_request, &["body-a".to_owned()])
        });
        let second_barrier = Arc::clone(&barrier);
        let second = thread::spawn(move || {
            second_barrier.wait();
            write_mir_coverage(&second_request, &["body-b".to_owned()])
        });

        first
            .join()
            .expect("first writer should not panic")
            .expect("first write should succeed");
        second
            .join()
            .expect("second writer should not panic")
            .expect("second write should succeed");

        let report: MirCoverageReport = serde_json::from_str(
            &fs::read_to_string(temp.path().join("mir-coverage.json"))
                .expect("coverage report should be written"),
        )
        .expect("coverage report should parse");
        assert_eq!(
            report.seen_packages,
            vec![
                ExpectedPackage {
                    name: "package-a".to_owned(),
                    version: "1.0.0".to_owned()
                },
                ExpectedPackage {
                    name: "package-b".to_owned(),
                    version: "1.0.0".to_owned()
                },
            ]
        );
        assert_eq!(report.seen_targets.len(), 2);
        assert_eq!(report.seen_bodies.len(), 2);
        assert!(
            report
                .seen_targets
                .iter()
                .any(|target| target.target == "target-a")
        );
        assert!(
            report
                .seen_targets
                .iter()
                .any(|target| target.target == "target-b")
        );
        assert!(
            report
                .seen_bodies
                .iter()
                .any(|body| body.def_path == "body-a")
        );
        assert!(
            report
                .seen_bodies
                .iter()
                .any(|body| body.def_path == "body-b")
        );
    }
}
