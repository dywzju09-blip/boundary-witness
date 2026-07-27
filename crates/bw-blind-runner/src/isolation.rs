use std::{
    collections::BTreeMap,
    fs::{self, File},
    io,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bw_blind_model::FormalIsolationBackend;
use bw_experiment::{ChildRunResult, ChildStatus};

use crate::{AuditError, Result};

static CONTAINER_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The execution mechanism selected by the trusted runner.
pub(crate) enum IsolationExecutor {
    NativeUntrustedSmoke,
    Container(ContainerExecutor),
}

/// Linux container configuration for one formal runner invocation.
pub(crate) struct ContainerExecutor {
    pub(crate) engine: ContainerEngine,
    pub(crate) image: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContainerEngine {
    Docker,
    Podman,
}

pub(crate) struct ContainerSpec<'a> {
    pub(crate) image: &'a str,
    pub(crate) execution_root: &'a Path,
    pub(crate) work_dir: &'a Path,
    pub(crate) program: &'a str,
    pub(crate) args: &'a [String],
}

pub(crate) struct ContainerCommand {
    pub(crate) args: Vec<String>,
}

impl IsolationExecutor {
    pub(crate) fn from_formal_backend(
        backend: FormalIsolationBackend,
        image: &str,
    ) -> Result<Self> {
        match backend {
            FormalIsolationBackend::NativeUntrustedSmoke => {
                if image != "native-untrusted-smoke" {
                    return Err(AuditError::Validation(
                        "formal run requires trusted isolation; native-untrusted-smoke requires image_digest=native-untrusted-smoke".to_owned(),
                    ));
                }
                Ok(Self::NativeUntrustedSmoke)
            }
            FormalIsolationBackend::Container => {
                ensure_linux_trusted_backend()?;
                if image.is_empty() || image == "native-untrusted-smoke" {
                    return Err(AuditError::Validation(
                        "container isolation requires a non-native container image".to_owned(),
                    ));
                }
                Ok(Self::Container(ContainerExecutor {
                    engine: ContainerEngine::from_environment()?,
                    image: image.to_owned(),
                }))
            }
            FormalIsolationBackend::CgroupPidNamespace => {
                ensure_linux_trusted_backend()?;
                Err(AuditError::Validation(
                    "cgroup-pid-namespace trusted backend is not implemented; use --isolation container on a Linux trusted runner".to_owned(),
                ))
            }
        }
    }

    /// Check that a formal backend is usable before a run directory is created.
    pub(crate) fn preflight(&self) -> Result<()> {
        match self {
            Self::NativeUntrustedSmoke => Ok(()),
            Self::Container(container) => container.preflight(),
        }
    }
}

impl ContainerEngine {
    fn from_environment() -> Result<Self> {
        match std::env::var("BW_CONTAINER_ENGINE")
            .as_deref()
            .unwrap_or("docker")
        {
            "docker" => Ok(Self::Docker),
            "podman" => Ok(Self::Podman),
            value => Err(AuditError::Validation(format!(
                "BW_CONTAINER_ENGINE must be docker or podman, got {value:?}"
            ))),
        }
    }

    fn program(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

impl ContainerExecutor {
    fn preflight(&self) -> Result<()> {
        preflight_container_engine(self.engine.program(), &self.image)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run_case(
        &self,
        child_root: &Path,
        execution_root: &Path,
        program: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        timeout: Duration,
    ) -> Result<ChildRunResult> {
        let work_dir = create_child_work_dir(child_root)?;
        let stdout_path = work_dir.join("stdout.log");
        let stderr_path = work_dir.join("stderr.log");
        let stdout_file = create_file(&stdout_path)?;
        let stderr_file = create_file(&stderr_path)?;
        let container_name = unique_container_name();
        let mut command = build_container_command(ContainerSpec {
            image: &self.image,
            execution_root,
            work_dir: &work_dir,
            program,
            args,
        });
        let image_index = command.args.len() - args.len() - 2;
        for (key, value) in env {
            command.args.splice(
                image_index..image_index,
                ["--env".to_owned(), format!("{key}={value}")],
            );
        }
        command.args.splice(
            image_index..image_index,
            ["--name".to_owned(), container_name.clone()],
        );

        let mut child = Command::new(self.engine.program())
            .args(&command.args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .map_err(|source| AuditError::Read {
                path: PathBuf::from(self.engine.program()),
                source,
            })?;
        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait().map_err(|source| AuditError::Read {
                path: PathBuf::from(self.engine.program()),
                source,
            })? {
                if status.code() == Some(125) {
                    return Err(AuditError::Validation(format!(
                        "container engine failed to start case (exit 125): {}",
                        self.engine.program()
                    )));
                }
                return Ok(ChildRunResult {
                    work_dir,
                    stdout_path,
                    stderr_path,
                    status: status_to_child_status(status),
                    timed_out: false,
                });
            }
            if started.elapsed() >= timeout {
                remove_container(self.engine, &container_name)?;
                let status = child.wait().map_err(|source| AuditError::Read {
                    path: PathBuf::from(self.engine.program()),
                    source,
                })?;
                if status.code() == Some(125) {
                    return Err(AuditError::Validation(format!(
                        "container engine failed while cleaning up timed-out case (exit 125): {}",
                        self.engine.program()
                    )));
                }
                return Ok(ChildRunResult {
                    work_dir,
                    stdout_path,
                    stderr_path,
                    status: ChildStatus::TimedOut,
                    timed_out: true,
                });
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn preflight_container_engine(program: &str, image: &str) -> Result<()> {
    let status = Command::new(program)
        .args(["image", "inspect", image])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|source| {
            AuditError::Validation(format!(
                "container engine preflight failed to execute {program:?}: {source}"
            ))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(AuditError::Validation(format!(
            "container engine preflight failed for image {image:?} using {program:?}: {status}"
        )))
    }
}

pub(crate) fn build_container_command(spec: ContainerSpec<'_>) -> ContainerCommand {
    let program = container_program(spec.program).expect("audited case command must be relative");
    let mut args = vec![
        "run".to_owned(),
        "--rm".to_owned(),
        "--network=none".to_owned(),
        "--read-only".to_owned(),
        "--user".to_owned(),
        "65532:65532".to_owned(),
        "--cap-drop=ALL".to_owned(),
        "--security-opt".to_owned(),
        "no-new-privileges".to_owned(),
        "-v".to_owned(),
        format!("{}:/case:ro", spec.execution_root.display()),
        "-v".to_owned(),
        format!("{}:/work:rw", spec.work_dir.display()),
        "-w".to_owned(),
        "/work".to_owned(),
        spec.image.to_owned(),
        program,
    ];
    args.extend(spec.args.iter().cloned());
    ContainerCommand { args }
}

fn ensure_linux_trusted_backend() -> Result<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(AuditError::Validation(
            "Linux-only trusted isolation backend: container and cgroup formal runs are not supported on this platform".to_owned(),
        ))
    }
}

fn container_program(program: &str) -> Option<String> {
    let path = Path::new(program);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }
    Some(format!("/case/{program}"))
}

fn create_child_work_dir(root: &Path) -> Result<PathBuf> {
    fs::create_dir_all(root).map_err(|source| AuditError::Write {
        path: root.to_owned(),
        source,
    })?;
    let process_id = std::process::id();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0..32 {
        let counter = CONTAINER_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!(
            "container-{process_id}-{timestamp}-{counter}-{attempt}"
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                make_work_dir_writable_by_container_user(&path)?;
                return Ok(path);
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(AuditError::Write { path, source });
            }
        }
    }
    Err(AuditError::Validation(
        "could not create a unique container child work directory".to_owned(),
    ))
}

#[cfg(unix)]
fn make_work_dir_writable_by_container_user(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|source| AuditError::Read {
            path: path.to_owned(),
            source,
        })?
        .permissions();
    permissions.set_mode(0o777);
    fs::set_permissions(path, permissions).map_err(|source| AuditError::Write {
        path: path.to_owned(),
        source,
    })
}

#[cfg(not(unix))]
fn make_work_dir_writable_by_container_user(_path: &Path) -> Result<()> {
    Ok(())
}

fn create_file(path: &Path) -> Result<File> {
    File::create(path).map_err(|source| AuditError::Write {
        path: path.to_owned(),
        source,
    })
}

fn unique_container_name() -> String {
    let counter = CONTAINER_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("bw-blind-case-{}-{counter}", std::process::id())
}

fn remove_container(engine: ContainerEngine, name: &str) -> Result<()> {
    remove_container_with_program(engine.program(), name)
}

fn remove_container_with_program(program: &str, name: &str) -> Result<()> {
    let status = Command::new(program)
        .args(["rm", "--force", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|source| {
            AuditError::Validation(format!(
                "container cleanup failed to execute {program:?} for {name:?}: {source}"
            ))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(AuditError::Validation(format!(
            "container cleanup failed for {name:?} using {program:?}: {status}"
        )))
    }
}

fn status_to_child_status(status: std::process::ExitStatus) -> ChildStatus {
    if let Some(code) = status.code() {
        return ChildStatus::Exited(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        ChildStatus::Signaled(status.signal().unwrap_or(-1))
    }
    #[cfg(not(unix))]
    {
        ChildStatus::Signaled(-1)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        ContainerSpec, build_container_command, preflight_container_engine,
        remove_container_with_program,
    };

    #[test]
    fn missing_container_engine_preflight_fails_before_any_case_can_run() {
        let error = preflight_container_engine(
            "__bw_missing_container_engine__",
            "boundary-witness-runner:test",
        )
        .expect_err("a missing engine must reject formal container execution");

        assert!(error.to_string().contains("container engine preflight"));
    }

    #[test]
    fn missing_container_engine_cleanup_fails_closed() {
        let error =
            remove_container_with_program("__bw_missing_container_engine__", "bw-blind-case-test")
                .expect_err("container cleanup must fail closed when the engine cannot start");

        assert!(error.to_string().contains("container cleanup"));
    }

    #[test]
    fn container_command_uses_read_only_case_and_writable_work_dir() {
        let command = build_container_command(ContainerSpec {
            image: "boundary-witness-runner:test",
            execution_root: Path::new("/runner/cases/case-a"),
            work_dir: Path::new("/runner/work/case-a"),
            program: "adapter.sh",
            args: &[],
        });

        assert!(command.args.contains(&"--rm".to_owned()));
        assert!(command.args.contains(&"--network=none".to_owned()));
        assert!(command.args.contains(&"--read-only".to_owned()));
        assert!(command.args.contains(&"65532:65532".to_owned()));
        assert!(command.args.contains(&"--cap-drop=ALL".to_owned()));
        assert!(
            command.args.windows(2).any(|args| {
                args == ["--security-opt".to_owned(), "no-new-privileges".to_owned()]
            })
        );
        assert!(
            command
                .args
                .windows(2)
                .any(|args| args == ["-w".to_owned(), "/work".to_owned()])
        );
        assert!(command.args.iter().any(|arg| arg.ends_with(":/case:ro")));
        assert!(command.args.iter().any(|arg| arg.ends_with(":/work:rw")));
        assert_eq!(command.args.last().unwrap(), "/case/adapter.sh");
    }
}
