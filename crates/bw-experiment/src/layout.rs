use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use bw_model::ExecutionResult;
use serde::Serialize;
use serde_json::Value;

use crate::{
    ExperimentError, Result,
    checksum::{verify_run_integrity, write_run_checksums},
    manifest::{RunMetadata, build_manifest, now_utc_string, write_json_file},
};

#[derive(Debug)]
pub struct RunDirectory {
    run_id: String,
    partial_path: PathBuf,
    final_path: PathBuf,
    metadata: RunMetadata,
    started_at_utc: String,
}

#[derive(Debug, Clone)]
pub struct FinalizedRun {
    run_id: String,
    path: PathBuf,
}

#[derive(Debug)]
pub struct FinalizeRun {
    pub summary: Value,
    pub execution: Option<ExecutionResult>,
    pub required_trace_files: Vec<String>,
    pub required_log_files: Vec<String>,
}

#[derive(Serialize)]
struct SummaryDocument<'a> {
    schema_version: &'static str,
    run_id: &'a str,
    status: &'static str,
    finalized_at_utc: &'a str,
    required_trace_files: &'a [String],
    required_log_files: &'a [String],
    user_summary: &'a Value,
}

impl RunDirectory {
    pub fn create(
        runs_root: impl AsRef<Path>,
        run_id: impl Into<String>,
        metadata: RunMetadata,
    ) -> Result<Self> {
        let run_id = run_id.into();
        validate_run_id(&run_id)?;

        let runs_root = runs_root.as_ref();
        fs::create_dir_all(runs_root).map_err(|error| ExperimentError::io(runs_root, error))?;

        let partial_path = runs_root.join(format!("{run_id}.partial"));
        let final_path = runs_root.join(&run_id);
        if partial_path.exists() {
            return Err(ExperimentError::InvalidInput(format!(
                "partial run directory already exists: {}",
                partial_path.display()
            )));
        }
        if final_path.exists() {
            return Err(ExperimentError::InvalidInput(format!(
                "final run directory already exists: {}",
                final_path.display()
            )));
        }

        fs::create_dir(&partial_path).map_err(|error| ExperimentError::io(&partial_path, error))?;
        for dir in ["input", "traces", "artifacts", "logs"] {
            let path = partial_path.join(dir);
            fs::create_dir(&path).map_err(|error| ExperimentError::io(&path, error))?;
        }

        let findings_path = partial_path.join("findings.jsonl");
        fs::write(&findings_path, "")
            .map_err(|error| ExperimentError::io(&findings_path, error))?;

        let started_at_utc = now_utc_string();
        let manifest = build_manifest(&run_id, &metadata, &started_at_utc, None, None);
        write_json_file(&partial_path.join("manifest.json"), &manifest)?;

        Ok(Self {
            run_id,
            partial_path,
            final_path,
            metadata,
            started_at_utc,
        })
    }

    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    #[must_use]
    pub fn partial_path(&self) -> &Path {
        &self.partial_path
    }

    #[must_use]
    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    #[must_use]
    pub fn input_dir(&self) -> PathBuf {
        self.partial_path.join("input")
    }

    #[must_use]
    pub fn traces_dir(&self) -> PathBuf {
        self.partial_path.join("traces")
    }

    #[must_use]
    pub fn artifacts_dir(&self) -> PathBuf {
        self.partial_path.join("artifacts")
    }

    #[must_use]
    pub fn logs_dir(&self) -> PathBuf {
        self.partial_path.join("logs")
    }

    #[must_use]
    pub fn findings_path(&self) -> PathBuf {
        self.partial_path.join("findings.jsonl")
    }

    pub fn finalize(self, input: FinalizeRun) -> Result<FinalizedRun> {
        let completed_at_utc = now_utc_string();
        self.finalize_at(input, completed_at_utc)
    }

    pub fn summary_document(&self, input: &FinalizeRun, completed_at_utc: &str) -> Result<Value> {
        let summary = SummaryDocument {
            schema_version: "boundary-witness.run-integrity/0.1",
            run_id: &self.run_id,
            status: "finalized",
            finalized_at_utc: completed_at_utc,
            required_trace_files: &input.required_trace_files,
            required_log_files: &input.required_log_files,
            user_summary: &input.summary,
        };
        Ok(serde_json::to_value(&summary)?)
    }

    pub fn finalize_at(self, input: FinalizeRun, completed_at_utc: String) -> Result<FinalizedRun> {
        validate_required_files(
            &self.partial_path.join("traces"),
            "trace",
            &input.required_trace_files,
        )?;
        validate_required_files(
            &self.partial_path.join("logs"),
            "log",
            &input.required_log_files,
        )?;

        let summary = self.summary_document(&input, &completed_at_utc)?;
        write_json_file(&self.partial_path.join("summary.json"), &summary)?;

        let complete_path = self.partial_path.join("COMPLETE");
        fs::write(&complete_path, format!("{completed_at_utc}\n"))
            .map_err(|error| ExperimentError::io(&complete_path, error))?;

        let manifest = build_manifest(
            &self.run_id,
            &self.metadata,
            &self.started_at_utc,
            Some(completed_at_utc),
            input.execution,
        );
        write_json_file(&self.partial_path.join("manifest.json"), &manifest)?;

        write_run_checksums(&self.partial_path)?;
        verify_run_integrity(&self.partial_path)?;

        fs::rename(&self.partial_path, &self.final_path)
            .map_err(|error| ExperimentError::io(&self.final_path, error))?;

        Ok(FinalizedRun {
            run_id: self.run_id,
            path: self.final_path,
        })
    }
}

impl FinalizedRun {
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn validate_run_id(run_id: &str) -> Result<()> {
    if run_id.is_empty() {
        return Err(ExperimentError::InvalidInput(
            "run_id must not be empty".to_owned(),
        ));
    }
    if run_id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Ok(());
    }
    Err(ExperimentError::InvalidInput(format!(
        "run_id contains unsafe characters: {run_id}"
    )))
}

fn validate_required_files(
    root: &Path,
    kind: &'static str,
    relative_paths: &[String],
) -> Result<()> {
    for relative in relative_paths {
        validate_safe_relative_path(relative)?;
        let path = root.join(relative);
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| ExperimentError::MissingRequiredFile {
                kind,
                path: path.clone(),
            })?;
        if metadata.file_type().is_symlink() {
            return Err(ExperimentError::Symlink { path });
        }
        if !metadata.is_file() {
            return Err(ExperimentError::MissingRequiredFile { kind, path });
        }
    }
    Ok(())
}

pub(crate) fn validate_safe_relative_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(ExperimentError::UnsafePath {
            path: path.to_owned(),
        });
    }
    let path_obj = Path::new(path);
    if path_obj.is_absolute() {
        return Err(ExperimentError::UnsafePath {
            path: path.to_owned(),
        });
    }
    for component in path_obj.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(ExperimentError::UnsafePath {
                    path: path.to_owned(),
                });
            }
        }
    }
    Ok(())
}
