use std::{
    error::Error,
    fmt, fs,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use bw_model::{
    CallbackCaptureFact, CallbackSiteFact, CaptureMode, ObjectSiteFact, RecordId, SemanticSiteKey,
    SiteId, StaticFact, StaticFactEnvelope, STATIC_SCHEMA_V01,
};
use serde::Serialize;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagingLayout {
    pub repo_root: PathBuf,
    pub artifact_root: PathBuf,
    pub mir_config: PathBuf,
}

impl StagingLayout {
    #[must_use]
    pub fn m12_default(repo_root: &Path) -> Self {
        Self {
            repo_root: repo_root.to_path_buf(),
            artifact_root: repo_root.join("experiments/artifacts/rusqlite-m12"),
            mir_config: repo_root.join("experiments/configs/rusqlite-mir.toml"),
        }
    }

    #[must_use]
    pub fn d0_default(repo_root: &Path) -> Self {
        Self {
            repo_root: repo_root.to_path_buf(),
            artifact_root: repo_root.join("experiments/artifacts/d0"),
            mir_config: repo_root.join("experiments/configs/rusqlite-mir.toml"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseStagingInput {
    pub source_manifest: PathBuf,
    pub app_crate: String,
    pub binary_name: String,
    pub runtime_site_bridge: Option<RuntimeSiteBridge>,
}

impl CaseStagingInput {
    #[must_use]
    pub fn m12_cases(repo_root: PathBuf) -> Vec<Self> {
        let root = repo_root.join("benchmarks/historical-cves/rusqlite");
        vec![
            case(
                &root,
                "update-hook/vulnerable/Cargo.toml",
                "bw_rusqlite_update_0261_borrowed",
                Some(update_bridge(CaptureMode::Borrowed)),
            ),
            case(
                &root,
                "update-hook/fixed/Cargo.toml",
                "bw_rusqlite_update_0262_owned",
                Some(update_bridge(CaptureMode::Owned)),
            ),
            case(
                &root,
                "update-hook/safe-move/Cargo.toml",
                "bw_rusqlite_update_0261_safe_move",
                Some(update_bridge(CaptureMode::Owned)),
            ),
            case(
                &root,
                "update-hook/unregister-before-drop/Cargo.toml",
                "bw_rusqlite_update_0261_unregister_before_drop",
                Some(update_bridge(CaptureMode::Borrowed)),
            ),
            case(
                &root,
                "update-hook/no-trigger/Cargo.toml",
                "bw_rusqlite_update_0261_no_trigger",
                Some(update_bridge(CaptureMode::Borrowed)),
            ),
            case(
                &root,
                "scalar-function/vulnerable/Cargo.toml",
                "bw_rusqlite_scalar_0261_borrowed",
                Some(scalar_bridge(CaptureMode::Borrowed)),
            ),
            case(
                &root,
                "scalar-function/fixed/Cargo.toml",
                "bw_rusqlite_scalar_0262_owned",
                Some(scalar_bridge(CaptureMode::Owned)),
            ),
            case(
                &root,
                "scalar-function/safe-move/Cargo.toml",
                "bw_rusqlite_scalar_0261_safe_move",
                Some(scalar_bridge(CaptureMode::Owned)),
            ),
            case(
                &root,
                "scalar-function/unregister-before-drop/Cargo.toml",
                "bw_rusqlite_scalar_0261_unregister_before_drop",
                Some(scalar_bridge(CaptureMode::Borrowed)),
            ),
            case(
                &root,
                "scalar-function/no-trigger/Cargo.toml",
                "bw_rusqlite_scalar_0261_no_trigger",
                Some(scalar_bridge(CaptureMode::Borrowed)),
            ),
        ]
    }

    #[must_use]
    pub fn d0_runtime_cases(repo_root: PathBuf) -> Vec<(String, Self)> {
        let root = repo_root.join("benchmarks/historical-cves/rusqlite");
        vec![
            (
                "d0-uh-001",
                case(
                    &root,
                    "update-hook/vulnerable/Cargo.toml",
                    "bw_rusqlite_update_0261_borrowed",
                    Some(update_bridge(CaptureMode::Borrowed)),
                ),
            ),
            (
                "d0-uh-002",
                case(
                    &root,
                    "update-hook/safe-move/Cargo.toml",
                    "bw_rusqlite_update_0261_safe_move",
                    Some(update_bridge(CaptureMode::Owned)),
                ),
            ),
            (
                "d0-uh-003",
                case(
                    &root,
                    "update-hook/unregister-before-drop/Cargo.toml",
                    "bw_rusqlite_update_0261_unregister_before_drop",
                    Some(update_bridge(CaptureMode::Borrowed)),
                ),
            ),
            (
                "d0-uh-004",
                case(
                    &root,
                    "update-hook/no-trigger/Cargo.toml",
                    "bw_rusqlite_update_0261_no_trigger",
                    Some(update_bridge(CaptureMode::Borrowed)),
                ),
            ),
            (
                "d0-uh-005",
                case(
                    &root,
                    "update-hook/fixed/Cargo.toml",
                    "bw_rusqlite_update_0262_owned",
                    Some(update_bridge(CaptureMode::Owned)),
                ),
            ),
            (
                "d0-sf-001",
                case(
                    &root,
                    "scalar-function/vulnerable/Cargo.toml",
                    "bw_rusqlite_scalar_0261_borrowed",
                    Some(scalar_bridge(CaptureMode::Borrowed)),
                ),
            ),
            (
                "d0-sf-002",
                case(
                    &root,
                    "scalar-function/safe-move/Cargo.toml",
                    "bw_rusqlite_scalar_0261_safe_move",
                    Some(scalar_bridge(CaptureMode::Owned)),
                ),
            ),
            (
                "d0-sf-003",
                case(
                    &root,
                    "scalar-function/unregister-before-drop/Cargo.toml",
                    "bw_rusqlite_scalar_0261_unregister_before_drop",
                    Some(scalar_bridge(CaptureMode::Borrowed)),
                ),
            ),
            (
                "d0-sf-004",
                case(
                    &root,
                    "scalar-function/no-trigger/Cargo.toml",
                    "bw_rusqlite_scalar_0261_no_trigger",
                    Some(scalar_bridge(CaptureMode::Borrowed)),
                ),
            ),
            (
                "d0-sf-005",
                case(
                    &root,
                    "scalar-function/fixed/Cargo.toml",
                    "bw_rusqlite_scalar_0262_owned",
                    Some(scalar_bridge(CaptureMode::Owned)),
                ),
            ),
        ]
        .into_iter()
        .map(|(case_id, input)| (case_id.to_owned(), input))
        .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompileCheckStagingInput {
    pub source_manifest: PathBuf,
}

impl CompileCheckStagingInput {
    #[must_use]
    pub fn d0_compile_checks(repo_root: PathBuf) -> Vec<(String, Self)> {
        let root = repo_root.join("benchmarks/historical-cves/rusqlite");
        vec![
            (
                "d0-uh-006".to_owned(),
                Self {
                    source_manifest: root.join("update-hook/fixed-borrowed-reject/Cargo.toml"),
                },
            ),
            (
                "d0-sf-006".to_owned(),
                Self {
                    source_manifest: root.join("scalar-function/fixed-borrowed-reject/Cargo.toml"),
                },
            ),
        ]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeSiteBridge {
    pub callback_site_id: &'static str,
    pub object_site_id: &'static str,
    pub capture_site_id: &'static str,
    pub capture_mode: CaptureMode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagingPlan {
    pub schema_version: String,
    pub artifact_root: PathBuf,
    pub mir_config: PathBuf,
    pub cases: Vec<StagedCase>,
    pub compile_checks: Vec<StagedCompileCheck>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagedCase {
    pub case_id: String,
    pub source_manifest: PathBuf,
    pub app_crate: String,
    pub binary_name: String,
    pub metadata_path: PathBuf,
    pub analysis_dir: PathBuf,
    pub target_dir: PathBuf,
    pub build_binary_path: PathBuf,
    pub public_static_facts: PathBuf,
    pub public_executable: PathBuf,
    #[serde(skip_serializing)]
    pub runtime_site_bridge: Option<RuntimeSiteBridge>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagedCompileCheck {
    pub case_id: String,
    pub source_manifest: PathBuf,
    pub public_source_dir: PathBuf,
    pub public_manifest: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageOptions {
    pub layout: StagingLayout,
    pub bw_rustc: PathBuf,
    pub rustup_toolchain: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3BlindSourceOptions {
    pub artifact_root: PathBuf,
    pub output_root: PathBuf,
    pub adapter_binary: PathBuf,
    pub bw_binary: PathBuf,
    pub contract: PathBuf,
}

pub const STAGING_PLAN_SCHEMA_V01: &str = "bw.rusqlite-artifact-staging/0.1";
pub const V3_SOURCE_SCHEMA_V01: &str = "bw.rusqlite-v3-source/0.1";
pub const V3_M12_SUITE_ID: &str = "suite.rusqlite.m12.v3";

#[must_use]
pub fn m12_staging_plan(layout: &StagingLayout) -> StagingPlan {
    let cases = CaseStagingInput::m12_cases(layout.repo_root.clone())
        .into_iter()
        .enumerate()
        .map(|(index, input)| staged_runtime_case(layout, format!("case-{:04}", index + 1), input))
        .collect();
    StagingPlan {
        schema_version: STAGING_PLAN_SCHEMA_V01.to_owned(),
        artifact_root: layout.artifact_root.clone(),
        mir_config: layout.mir_config.clone(),
        cases,
        compile_checks: Vec::new(),
    }
}

#[must_use]
pub fn d0_staging_plan(layout: &StagingLayout) -> StagingPlan {
    let cases = CaseStagingInput::d0_runtime_cases(layout.repo_root.clone())
        .into_iter()
        .map(|(case_id, input)| staged_runtime_case(layout, case_id, input))
        .collect();
    let compile_checks = CompileCheckStagingInput::d0_compile_checks(layout.repo_root.clone())
        .into_iter()
        .map(|(case_id, input)| staged_compile_check(layout, case_id, input))
        .collect();
    StagingPlan {
        schema_version: STAGING_PLAN_SCHEMA_V01.to_owned(),
        artifact_root: layout.artifact_root.clone(),
        mir_config: layout.mir_config.clone(),
        cases,
        compile_checks,
    }
}

pub fn stage_m12_artifacts(options: &StageOptions) -> Result<StagingPlan, ArtifactStagingError> {
    let plan = m12_staging_plan(&options.layout);
    stage_artifacts(plan, options)
}

pub fn stage_d0_artifacts(options: &StageOptions) -> Result<StagingPlan, ArtifactStagingError> {
    let plan = d0_staging_plan(&options.layout);
    stage_artifacts(plan, options)
}

pub fn write_m12_v3_blind_source(
    options: &V3BlindSourceOptions,
) -> Result<(), ArtifactStagingError> {
    reset_directory(&options.output_root, "reset v3 blind source directory")?;
    let mut source_toml = format!("suite_id = \"{V3_M12_SUITE_ID}\"\n");
    for case in m12_v3_cases() {
        stage_v3_case(options, &case)?;
        source_toml.push_str(&case.to_source_toml());
    }
    fs::write(options.output_root.join("source.toml"), source_toml).map_err(|source| {
        ArtifactStagingError::Io {
            action: "write v3 source manifest",
            path: options.output_root.join("source.toml"),
            source,
        }
    })
}

fn stage_artifacts(
    plan: StagingPlan,
    options: &StageOptions,
) -> Result<StagingPlan, ArtifactStagingError> {
    let cargo_toolchain = CargoToolchain::resolve(options.rustup_toolchain.as_deref())?;

    for directory in [
        plan.artifact_root.join("bin"),
        plan.artifact_root.join("static"),
        plan.artifact_root.join("source"),
        plan.artifact_root.join("metadata"),
        plan.artifact_root.join("analysis"),
        plan.artifact_root.join("targets"),
    ] {
        fs::create_dir_all(&directory).map_err(|source| ArtifactStagingError::Io {
            action: "create artifact directory",
            path: directory,
            source,
        })?;
    }

    for case in &plan.cases {
        stage_case(&plan, case, &options.bw_rustc, &cargo_toolchain)?;
    }
    for case in &plan.compile_checks {
        stage_compile_check_source(case)?;
    }

    let index_path = plan.artifact_root.join("staging-plan.json");
    write_json(&index_path, &plan)?;
    Ok(plan)
}

fn stage_v3_case(
    options: &V3BlindSourceOptions,
    case: &V3BlindCaseSpec,
) -> Result<(), ArtifactStagingError> {
    let case_root = options.output_root.join(case.case_dir);
    copy_executable_file(
        &options.adapter_binary,
        &case_root.join("adapter/bin/driver"),
        "copy v3 adapter",
    )?;
    copy_executable_file(
        &options.artifact_root.join("bin").join(case.source_case_id),
        &case_root.join("payload/bin/case"),
        "copy m12 case executable",
    )?;
    copy_executable_file(
        &options.bw_binary,
        &case_root.join("payload/bin/bw"),
        "copy bw analyzer binary",
    )?;
    copy_file(
        &options
            .artifact_root
            .join("static")
            .join(format!("{}.jsonl", case.source_case_id)),
        &case_root.join("payload/static-facts.jsonl"),
        "copy m12 static facts",
    )?;
    copy_file(
        &options.contract,
        &case_root.join("payload/contract.toml"),
        "copy callback contract",
    )
}

fn staged_runtime_case(
    layout: &StagingLayout,
    case_id: String,
    input: CaseStagingInput,
) -> StagedCase {
    let metadata_path = layout
        .artifact_root
        .join("metadata")
        .join(&case_id)
        .join("metadata.json");
    let analysis_dir = layout.artifact_root.join("analysis").join(&case_id);
    let target_dir = layout.artifact_root.join("targets").join(&case_id);
    let build_binary_path = target_dir.join("debug").join(format!(
        "{}{}",
        input.binary_name,
        std::env::consts::EXE_SUFFIX
    ));
    StagedCase {
        case_id: case_id.clone(),
        source_manifest: input.source_manifest,
        app_crate: input.app_crate,
        binary_name: input.binary_name,
        metadata_path,
        analysis_dir,
        target_dir,
        build_binary_path,
        public_static_facts: layout
            .artifact_root
            .join("static")
            .join(format!("{case_id}.jsonl")),
        public_executable: layout.artifact_root.join("bin").join(case_id),
        runtime_site_bridge: input.runtime_site_bridge,
    }
}

fn staged_compile_check(
    layout: &StagingLayout,
    case_id: String,
    input: CompileCheckStagingInput,
) -> StagedCompileCheck {
    let public_source_dir = layout.artifact_root.join("source").join(&case_id);
    StagedCompileCheck {
        case_id,
        source_manifest: input.source_manifest,
        public_manifest: public_source_dir.join("Cargo.toml"),
        public_source_dir,
    }
}

fn stage_case(
    plan: &StagingPlan,
    case: &StagedCase,
    bw_rustc: &Path,
    cargo_toolchain: &CargoToolchain,
) -> Result<(), ArtifactStagingError> {
    if let Some(parent) = case.metadata_path.parent() {
        fs::create_dir_all(parent).map_err(|source| ArtifactStagingError::Io {
            action: "create metadata directory",
            path: parent.to_path_buf(),
            source,
        })?;
    }
    reset_directory(&case.analysis_dir, "reset analysis directory")?;
    reset_directory(&case.target_dir, "reset target directory")?;

    let mut metadata_command = cargo_command(cargo_toolchain);
    let metadata = metadata_command
        .args([
            "metadata",
            "--format-version=1",
            "--locked",
            "--manifest-path",
        ])
        .arg(&case.source_manifest)
        .output()
        .map_err(|source| ArtifactStagingError::CommandStart {
            case_id: case.case_id.clone(),
            step: "cargo metadata",
            source,
        })?;
    if !metadata.status.success() {
        return Err(command_failed(
            &case.case_id,
            "cargo metadata",
            metadata.status,
            &metadata.stderr,
        ));
    }
    fs::write(&case.metadata_path, metadata.stdout).map_err(|source| ArtifactStagingError::Io {
        action: "write metadata",
        path: case.metadata_path.clone(),
        source,
    })?;

    let mut build_command = cargo_command(cargo_toolchain);
    let status = build_command
        .args(["build", "--locked", "--manifest-path"])
        .arg(&case.source_manifest)
        .env("RUSTC_WRAPPER", bw_rustc)
        .env("BW_RUSTC_CONFIG", &plan.mir_config)
        .env("BW_RUSQLITE_APP_CRATE", &case.app_crate)
        .env("BW_RUSQLITE_OUTPUT_DIR", &case.analysis_dir)
        .env("BW_RUSQLITE_METADATA_PATH", &case.metadata_path)
        .env("CARGO_TARGET_DIR", &case.target_dir)
        .status()
        .map_err(|source| ArtifactStagingError::CommandStart {
            case_id: case.case_id.clone(),
            step: "cargo build",
            source,
        })?;
    if !status.success() {
        return Err(command_failed(&case.case_id, "cargo build", status, &[]));
    }

    copy_file(
        &case.build_binary_path,
        &case.public_executable,
        "copy executable",
    )?;
    write_public_static_facts(
        &case.analysis_dir.join("static-facts.jsonl"),
        &case.public_static_facts,
        &case.case_id,
        case.runtime_site_bridge,
    )
}

fn copy_file(
    source: &Path,
    destination: &Path,
    action: &'static str,
) -> Result<(), ArtifactStagingError> {
    let parent = destination
        .parent()
        .ok_or_else(|| ArtifactStagingError::InvalidPath(destination.to_path_buf()))?;
    fs::create_dir_all(parent).map_err(|source| ArtifactStagingError::Io {
        action: "create artifact parent",
        path: parent.to_path_buf(),
        source,
    })?;
    fs::copy(source, destination).map_err(|source_error| ArtifactStagingError::Io {
        action,
        path: source.to_path_buf(),
        source: source_error,
    })?;
    Ok(())
}

fn copy_executable_file(
    source: &Path,
    destination: &Path,
    action: &'static str,
) -> Result<(), ArtifactStagingError> {
    copy_file(source, destination, action)?;
    set_executable(destination)
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), ArtifactStagingError> {
    let mut permissions = fs::metadata(path)
        .map_err(|source| ArtifactStagingError::Io {
            action: "read executable metadata",
            path: path.to_path_buf(),
            source,
        })?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).map_err(|source| ArtifactStagingError::Io {
        action: "set executable permissions",
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<(), ArtifactStagingError> {
    Ok(())
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ArtifactStagingError> {
    let parent = path
        .parent()
        .ok_or_else(|| ArtifactStagingError::InvalidPath(path.to_path_buf()))?;
    fs::create_dir_all(parent).map_err(|source| ArtifactStagingError::Io {
        action: "create json parent",
        path: parent.to_path_buf(),
        source,
    })?;
    let json = serde_json::to_vec_pretty(value).map_err(ArtifactStagingError::Json)?;
    fs::write(path, json).map_err(|source| ArtifactStagingError::Io {
        action: "write json",
        path: path.to_path_buf(),
        source,
    })
}

fn stage_compile_check_source(case: &StagedCompileCheck) -> Result<(), ArtifactStagingError> {
    let source_dir = case
        .source_manifest
        .parent()
        .ok_or_else(|| ArtifactStagingError::InvalidPath(case.source_manifest.clone()))?;
    reset_directory(
        &case.public_source_dir,
        "reset compile-check source directory",
    )?;
    let public_src = case.public_source_dir.join("src");
    fs::create_dir_all(&public_src).map_err(|source| ArtifactStagingError::Io {
        action: "create compile-check source directory",
        path: public_src.clone(),
        source,
    })?;
    copy_file(
        &source_dir.join("src/main.rs"),
        &public_src.join("main.rs"),
        "copy compile-check main",
    )?;
    copy_file(
        &source_dir.join("Cargo.lock"),
        &case.public_source_dir.join("Cargo.lock"),
        "copy compile-check lockfile",
    )?;
    write_compile_check_manifest(case)
}

fn write_compile_check_manifest(case: &StagedCompileCheck) -> Result<(), ArtifactStagingError> {
    let original =
        fs::read_to_string(&case.source_manifest).map_err(|source| ArtifactStagingError::Io {
            action: "read compile-check manifest",
            path: case.source_manifest.clone(),
            source,
        })?;
    let adjusted = original.replace(
        "rusqlite-lab-shared = { path = \"../../shared\" }",
        "rusqlite-lab-shared = { path = \"../../../../../benchmarks/historical-cves/rusqlite/shared\" }",
    );
    fs::write(&case.public_manifest, adjusted).map_err(|source| ArtifactStagingError::Io {
        action: "write compile-check manifest",
        path: case.public_manifest.clone(),
        source,
    })
}

fn reset_directory(path: &Path, action: &'static str) -> Result<(), ArtifactStagingError> {
    if path.exists() {
        fs::remove_dir_all(path).map_err(|source| ArtifactStagingError::Io {
            action,
            path: path.to_path_buf(),
            source,
        })?;
    }
    fs::create_dir_all(path).map_err(|source| ArtifactStagingError::Io {
        action,
        path: path.to_path_buf(),
        source,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CargoToolchain {
    rustup_toolchain: Option<String>,
    dynamic_library_paths: Vec<PathBuf>,
}

impl CargoToolchain {
    fn resolve(rustup_toolchain: Option<&str>) -> Result<Self, ArtifactStagingError> {
        let rustup_toolchain = rustup_toolchain
            .map(str::trim)
            .filter(|toolchain| !toolchain.is_empty())
            .map(ToOwned::to_owned);
        let dynamic_library_paths = rustup_toolchain
            .as_deref()
            .map(dynamic_library_paths_for_rustup_toolchain)
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            rustup_toolchain,
            dynamic_library_paths,
        })
    }
}

fn cargo_command(cargo_toolchain: &CargoToolchain) -> Command {
    let mut command = Command::new("cargo");
    if let Some(toolchain) = &cargo_toolchain.rustup_toolchain {
        command.env("RUSTUP_TOOLCHAIN", toolchain);
    }
    if !cargo_toolchain.dynamic_library_paths.is_empty() {
        command.env(
            dynamic_library_path_variable(),
            joined_dynamic_library_path(&cargo_toolchain.dynamic_library_paths),
        );
    }
    command
}

fn dynamic_library_paths_for_rustup_toolchain(
    toolchain: &str,
) -> Result<Vec<PathBuf>, ArtifactStagingError> {
    let output = Command::new("rustc")
        .arg(format!("+{toolchain}"))
        .args(["--print", "sysroot"])
        .output()
        .map_err(|source| ArtifactStagingError::CommandStart {
            case_id: "toolchain".to_owned(),
            step: "rustc --print sysroot",
            source,
        })?;
    if !output.status.success() {
        return Err(command_failed(
            "toolchain",
            "rustc --print sysroot",
            output.status,
            &output.stderr,
        ));
    }

    let sysroot = String::from_utf8(output.stdout)
        .map_err(|error| ArtifactStagingError::Config(format!("invalid rustc sysroot: {error}")))?;
    let sysroot = PathBuf::from(sysroot.trim());
    let host = rustc_host_triple(toolchain)?;

    Ok(vec![
        sysroot.join("lib"),
        sysroot.join("lib").join("rustlib").join(host).join("lib"),
    ])
}

fn rustc_host_triple(toolchain: &str) -> Result<String, ArtifactStagingError> {
    let output = Command::new("rustc")
        .arg(format!("+{toolchain}"))
        .arg("-vV")
        .output()
        .map_err(|source| ArtifactStagingError::CommandStart {
            case_id: "toolchain".to_owned(),
            step: "rustc -vV",
            source,
        })?;
    if !output.status.success() {
        return Err(command_failed(
            "toolchain",
            "rustc -vV",
            output.status,
            &output.stderr,
        ));
    }
    let version = String::from_utf8(output.stdout)
        .map_err(|error| ArtifactStagingError::Config(format!("invalid rustc -vV: {error}")))?;
    version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| ArtifactStagingError::Config("rustc -vV did not print host".to_owned()))
}

fn dynamic_library_path_variable() -> &'static str {
    if cfg!(target_os = "macos") {
        "DYLD_FALLBACK_LIBRARY_PATH"
    } else if cfg!(windows) {
        "PATH"
    } else {
        "LD_LIBRARY_PATH"
    }
}

fn joined_dynamic_library_path(paths: &[PathBuf]) -> std::ffi::OsString {
    let mut joined = paths.to_vec();
    if let Some(existing) =
        std::env::var_os(dynamic_library_path_variable()).filter(|value| !value.is_empty())
    {
        joined.extend(std::env::split_paths(&existing));
    }
    std::env::join_paths(joined).unwrap_or_default()
}

fn write_public_static_facts(
    source: &Path,
    destination: &Path,
    case_id: &str,
    bridge: Option<RuntimeSiteBridge>,
) -> Result<(), ArtifactStagingError> {
    copy_file(source, destination, "copy static facts")?;
    if let Some(bridge) = bridge {
        let build_id = static_build_id(source)?;
        let mut output = OpenOptions::new()
            .append(true)
            .open(destination)
            .map_err(|source| ArtifactStagingError::Io {
                action: "open public static facts for bridge append",
                path: destination.to_path_buf(),
                source,
            })?;
        output
            .write_all(b"\n")
            .map_err(|source| ArtifactStagingError::Io {
                action: "write static bridge separator",
                path: destination.to_path_buf(),
                source,
            })?;
        for fact in bridge_facts(case_id, &build_id, bridge) {
            serde_json::to_writer(&mut output, &fact).map_err(ArtifactStagingError::Json)?;
            output
                .write_all(b"\n")
                .map_err(|source| ArtifactStagingError::Io {
                    action: "write static bridge fact",
                    path: destination.to_path_buf(),
                    source,
                })?;
        }
    }
    Ok(())
}

fn static_build_id(source: &Path) -> Result<bw_model::BuildId, ArtifactStagingError> {
    let input = File::open(source).map_err(|source_error| ArtifactStagingError::Io {
        action: "open static facts for build id",
        path: source.to_path_buf(),
        source: source_error,
    })?;
    for (line_number, line) in BufReader::new(input).lines().enumerate() {
        let line = line.map_err(|source_error| ArtifactStagingError::Io {
            action: "read static facts for build id",
            path: source.to_path_buf(),
            source: source_error,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let fact = StaticFactEnvelope::from_json_str(&line).map_err(|error| {
            ArtifactStagingError::Config(format!(
                "invalid static fact {}:{}: {error}",
                source.display(),
                line_number + 1
            ))
        })?;
        return Ok(fact.build_id);
    }
    Err(ArtifactStagingError::Config(format!(
        "static facts {} did not contain a build_id",
        source.display()
    )))
}

fn bridge_facts(
    case_id: &str,
    build_id: &bw_model::BuildId,
    bridge: RuntimeSiteBridge,
) -> Vec<StaticFactEnvelope> {
    vec![
        bridge_envelope(
            case_id,
            "callback",
            build_id,
            StaticFact::CallbackSite(CallbackSiteFact {
                site_id: SiteId::from(bridge.callback_site_id),
                semantic_site_key: SemanticSiteKey::from(format!(
                    "semantic:bridge:{case_id}:callback"
                )),
                def_path: format!("runtime_bridge::{case_id}::callback"),
            }),
        ),
        bridge_envelope(
            case_id,
            "object",
            build_id,
            StaticFact::ObjectSite(ObjectSiteFact {
                site_id: SiteId::from(bridge.object_site_id),
                semantic_site_key: SemanticSiteKey::from(format!(
                    "semantic:bridge:{case_id}:object"
                )),
                type_name: "runtime_bridge::tracked_object".to_owned(),
            }),
        ),
        bridge_envelope(
            case_id,
            "capture",
            build_id,
            StaticFact::CallbackCapture(CallbackCaptureFact {
                site_id: SiteId::from(bridge.capture_site_id),
                semantic_site_key: SemanticSiteKey::from(format!(
                    "semantic:bridge:{case_id}:capture"
                )),
                callback_site_id: SiteId::from(bridge.callback_site_id),
                object_site_id: SiteId::from(bridge.object_site_id),
                capture_ordinal: 0,
                capture_mode: bridge.capture_mode,
            }),
        ),
    ]
}

fn bridge_envelope(
    case_id: &str,
    suffix: &str,
    build_id: &bw_model::BuildId,
    payload: StaticFact,
) -> StaticFactEnvelope {
    StaticFactEnvelope {
        schema_version: STATIC_SCHEMA_V01.to_owned(),
        record_id: RecordId::from(format!("fact:bridge:{case_id}:{suffix}")),
        producer: "bw-rusqlite-stage-artifacts@0.1".to_owned(),
        build_id: build_id.clone(),
        artifact: None,
        source_ref: None,
        payload,
    }
}

fn command_failed(
    case_id: &str,
    step: &'static str,
    status: ExitStatus,
    stderr: &[u8],
) -> ArtifactStagingError {
    ArtifactStagingError::CommandFailed {
        case_id: case_id.to_owned(),
        step,
        status: status.code(),
        stderr: String::from_utf8_lossy(stderr).into_owned(),
    }
}

fn case(
    root: &Path,
    manifest: &str,
    binary_name: &str,
    runtime_site_bridge: Option<RuntimeSiteBridge>,
) -> CaseStagingInput {
    CaseStagingInput {
        source_manifest: root.join(manifest),
        app_crate: binary_name.to_owned(),
        binary_name: binary_name.to_owned(),
        runtime_site_bridge,
    }
}

fn update_bridge(capture_mode: CaptureMode) -> RuntimeSiteBridge {
    RuntimeSiteBridge {
        callback_site_id: "site:update:callback",
        object_site_id: "site:update:object",
        capture_site_id: "site:update:capture",
        capture_mode,
    }
}

fn scalar_bridge(capture_mode: CaptureMode) -> RuntimeSiteBridge {
    RuntimeSiteBridge {
        callback_site_id: "site:scalar:callback",
        object_site_id: "site:scalar:object",
        capture_site_id: "site:scalar:capture",
        capture_mode,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct V3BlindCaseSpec {
    source_case_id: &'static str,
    curator_key: &'static str,
    role: &'static str,
    api: &'static str,
    paired_with: &'static [&'static str],
    case_dir: &'static str,
}

impl V3BlindCaseSpec {
    fn to_source_toml(&self) -> String {
        let paired_with = self
            .paired_with
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"
[[cases]]
curator_key = "{curator_key}"
split = "gate"
role = "{role}"
component = "sqlite-wrapper"
api = "{api}"
root_cause_key = "retained-borrowed-callback"
paired_with = [{paired_with}]
source_revision = "rusqlite-m12"
case_dir = "{case_dir}"
public_command = {{ program = "adapter/bin/driver", args = [], env = {{}} }}
timeout_seconds = 120
"#,
            curator_key = self.curator_key,
            role = self.role,
            api = self.api,
            paired_with = paired_with,
            case_dir = self.case_dir,
        )
    }
}

fn m12_v3_cases() -> [V3BlindCaseSpec; 10] {
    [
        V3BlindCaseSpec {
            source_case_id: "case-0001",
            curator_key: "m12-case-0001",
            role: "violation",
            api: "callback-api-a",
            paired_with: &["m12-case-0002"],
            case_dir: "cases/m12-0001",
        },
        V3BlindCaseSpec {
            source_case_id: "case-0002",
            curator_key: "m12-case-0002",
            role: "fixed_control",
            api: "callback-api-a",
            paired_with: &["m12-case-0001"],
            case_dir: "cases/m12-0002",
        },
        V3BlindCaseSpec {
            source_case_id: "case-0003",
            curator_key: "m12-case-0003",
            role: "safe_control",
            api: "callback-api-a",
            paired_with: &[],
            case_dir: "cases/m12-0003",
        },
        V3BlindCaseSpec {
            source_case_id: "case-0004",
            curator_key: "m12-case-0004",
            role: "safe_control",
            api: "callback-api-a",
            paired_with: &[],
            case_dir: "cases/m12-0004",
        },
        V3BlindCaseSpec {
            source_case_id: "case-0005",
            curator_key: "m12-case-0005",
            role: "safe_control",
            api: "callback-api-a",
            paired_with: &[],
            case_dir: "cases/m12-0005",
        },
        V3BlindCaseSpec {
            source_case_id: "case-0006",
            curator_key: "m12-case-0006",
            role: "violation",
            api: "callback-api-b",
            paired_with: &["m12-case-0007"],
            case_dir: "cases/m12-0006",
        },
        V3BlindCaseSpec {
            source_case_id: "case-0007",
            curator_key: "m12-case-0007",
            role: "fixed_control",
            api: "callback-api-b",
            paired_with: &["m12-case-0006"],
            case_dir: "cases/m12-0007",
        },
        V3BlindCaseSpec {
            source_case_id: "case-0008",
            curator_key: "m12-case-0008",
            role: "safe_control",
            api: "callback-api-b",
            paired_with: &[],
            case_dir: "cases/m12-0008",
        },
        V3BlindCaseSpec {
            source_case_id: "case-0009",
            curator_key: "m12-case-0009",
            role: "safe_control",
            api: "callback-api-b",
            paired_with: &[],
            case_dir: "cases/m12-0009",
        },
        V3BlindCaseSpec {
            source_case_id: "case-0010",
            curator_key: "m12-case-0010",
            role: "safe_control",
            api: "callback-api-b",
            paired_with: &[],
            case_dir: "cases/m12-0010",
        },
    ]
}

#[derive(Debug)]
pub enum ArtifactStagingError {
    Io {
        action: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    Json(serde_json::Error),
    Config(String),
    CommandStart {
        case_id: String,
        step: &'static str,
        source: std::io::Error,
    },
    CommandFailed {
        case_id: String,
        step: &'static str,
        status: Option<i32>,
        stderr: String,
    },
    InvalidPath(PathBuf),
}

impl fmt::Display for ArtifactStagingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                action,
                path,
                source,
            } => {
                write!(formatter, "{action} {}: {source}", path.display())
            }
            Self::Json(error) => write!(formatter, "serialize json: {error}"),
            Self::Config(message) => formatter.write_str(message),
            Self::CommandStart {
                case_id,
                step,
                source,
            } => write!(formatter, "{case_id} {step} failed to start: {source}"),
            Self::CommandFailed {
                case_id,
                step,
                status,
                stderr,
            } => write!(
                formatter,
                "{case_id} {step} exited with {:?}: {}",
                status,
                stderr.trim()
            ),
            Self::InvalidPath(path) => {
                write!(formatter, "invalid artifact path {}", path.display())
            }
        }
    }
}

impl Error for ArtifactStagingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json(error) => Some(error),
            Self::CommandStart { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs, time::SystemTime};

    use super::*;

    #[test]
    fn reset_directory_removes_stale_files_before_reuse() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        let directory = env::temp_dir().join(format!(
            "bw-rusqlite-stage-reset-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(directory.join("nested")).expect("stale directory should be created");
        fs::write(
            directory.join("nested/stale.rmeta"),
            b"old compiler artifact",
        )
        .expect("stale file should be created");

        reset_directory(&directory, "reset test directory").expect("directory should reset");

        assert!(directory.is_dir());
        assert!(!directory.join("nested/stale.rmeta").exists());

        fs::remove_dir_all(&directory).expect("test directory should be removed");
    }
}
