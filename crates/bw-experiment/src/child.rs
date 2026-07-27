use std::{
    collections::BTreeMap,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{ExperimentError, Result};

static CHILD_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct ChildRunner {
    root: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ChildSpec {
    program: PathBuf,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    work_dir_env: Option<String>,
    timeout: Duration,
    terminate_grace: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildStatus {
    Exited(i32),
    Signaled(i32),
    TimedOut,
}

#[derive(Clone, Debug)]
pub struct ChildRunResult {
    pub work_dir: PathBuf,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub status: ChildStatus,
    pub timed_out: bool,
}

impl ChildRunner {
    #[must_use]
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    pub fn run(&self, spec: ChildSpec) -> Result<ChildRunResult> {
        if let Some(key) = &spec.work_dir_env {
            validate_work_dir_env_key(key)?;
        }
        fs::create_dir_all(&self.root).map_err(|error| ExperimentError::io(&self.root, error))?;
        let work_dir = self.create_child_work_dir()?;
        let stdout_path = work_dir.join("stdout.log");
        let stderr_path = work_dir.join("stderr.log");
        let stdout_file =
            File::create(&stdout_path).map_err(|error| ExperimentError::io(&stdout_path, error))?;
        let stderr_file =
            File::create(&stderr_path).map_err(|error| ExperimentError::io(&stderr_path, error))?;

        let mut command = Command::new(&spec.program);
        command
            .args(&spec.args)
            .env_clear()
            .envs(&spec.env)
            .current_dir(&work_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));
        if let Some(key) = &spec.work_dir_env {
            command.env(key, &work_dir);
        }

        #[cfg(unix)]
        configure_child_process_group(&mut command);

        let mut child = command
            .spawn()
            .map_err(|error| ExperimentError::io(&spec.program, error))?;
        let (status, timed_out) =
            wait_with_timeout(&mut child, spec.timeout, spec.terminate_grace)?;
        #[cfg(unix)]
        terminate_child_process_group(child.id(), spec.terminate_grace)?;

        Ok(ChildRunResult {
            work_dir,
            stdout_path,
            stderr_path,
            status,
            timed_out,
        })
    }

    fn create_child_work_dir(&self) -> Result<PathBuf> {
        let process_id = std::process::id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for attempt in 0..32 {
            let counter = CHILD_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = self.root.join(format!(
                "child-{process_id}-{timestamp}-{counter}-{attempt}"
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(ExperimentError::io(path, error)),
            }
        }
        Err(ExperimentError::InvalidInput(
            "could not create a unique child work directory".to_owned(),
        ))
    }
}

#[cfg(unix)]
fn configure_child_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: pre_exec runs only in the freshly forked child. It uses only async-signal-safe
    // setpgid and returns an OS error to abort spawn if the group cannot be isolated.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
}

impl ChildSpec {
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            work_dir_env: None,
            timeout: Duration::from_secs(30),
            terminate_grace: Duration::from_secs(2),
        }
    }

    #[must_use]
    pub fn arg(mut self, value: impl Into<String>) -> Self {
        self.args.push(value.into());
        self
    }

    #[must_use]
    pub fn args(mut self, values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args.extend(values.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn inherit_env(mut self, key: impl Into<String>) -> Self {
        let key = key.into();
        if let Ok(value) = std::env::var(&key) {
            self.env.insert(key, value);
        }
        self
    }

    #[must_use]
    pub fn work_dir_env(mut self, key: impl Into<String>) -> Self {
        self.work_dir_env = Some(key.into());
        self
    }

    #[must_use]
    pub fn timeout(mut self, value: Duration) -> Self {
        self.timeout = value;
        self
    }

    #[must_use]
    pub fn terminate_grace(mut self, value: Duration) -> Self {
        self.terminate_grace = value;
        self
    }
}

fn validate_work_dir_env_key(key: &str) -> Result<()> {
    if key.is_empty() || key.contains('=') {
        return Err(ExperimentError::InvalidInput(
            "work directory environment key must be non-empty and must not contain '='".to_owned(),
        ));
    }
    Ok(())
}

fn wait_with_timeout(
    child: &mut Child,
    timeout: Duration,
    terminate_grace: Duration,
) -> Result<(ChildStatus, bool)> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| ExperimentError::io("<child>", error))?
        {
            return Ok((status_to_child_status(status), false));
        }
        if started.elapsed() >= timeout {
            terminate_child(child, terminate_grace)?;
            return Ok((ChildStatus::TimedOut, true));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn terminate_child(child: &mut Child, terminate_grace: Duration) -> Result<()> {
    send_term(child);

    let grace_started = Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|error| ExperimentError::io("<child>", error))?
            .is_some()
        {
            return Ok(());
        }
        if grace_started.elapsed() >= terminate_grace {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    child
        .kill()
        .map_err(|error| ExperimentError::io("<child>", error))?;
    child
        .wait()
        .map_err(|error| ExperimentError::io("<child>", error))?;
    Ok(())
}

#[cfg(unix)]
fn terminate_child_process_group(process_id: u32, terminate_grace: Duration) -> Result<()> {
    let group_id = i32::try_from(process_id).map_err(|_| {
        ExperimentError::InvalidInput("child process id does not fit a process group id".to_owned())
    })?;
    let target = -group_id;
    send_signal_to_process_group(target, libc::SIGTERM)?;

    let grace_started = Instant::now();
    while process_group_exists(target)? {
        if grace_started.elapsed() >= terminate_grace {
            send_signal_to_process_group(target, libc::SIGKILL)?;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let kill_started = Instant::now();
    while process_group_exists(target)? {
        if kill_started.elapsed() >= terminate_grace {
            return Err(ExperimentError::InvalidInput(
                "child process group did not terminate".to_owned(),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

#[cfg(unix)]
fn send_signal_to_process_group(target: i32, signal: libc::c_int) -> Result<()> {
    // SAFETY: target is a negative process-group id created specifically for this child.
    if unsafe { libc::kill(target, signal) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(ExperimentError::io("<child process group>", error))
    }
}

#[cfg(unix)]
fn process_group_exists(target: i32) -> Result<bool> {
    // SAFETY: signal 0 only checks process-group existence and permissions.
    if unsafe { libc::kill(target, 0) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(false)
    } else {
        Err(ExperimentError::io("<child process group>", error))
    }
}

#[cfg(unix)]
fn send_term(child: &Child) {
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(not(unix))]
fn send_term(_child: &Child) {}

fn status_to_child_status(status: ExitStatus) -> ChildStatus {
    if let Some(code) = status.code() {
        return ChildStatus::Exited(code);
    }
    signal_status(status)
}

#[cfg(unix)]
fn signal_status(status: ExitStatus) -> ChildStatus {
    use std::os::unix::process::ExitStatusExt;

    ChildStatus::Signaled(status.signal().unwrap_or(-1))
}

#[cfg(not(unix))]
fn signal_status(_status: ExitStatus) -> ChildStatus {
    ChildStatus::Signaled(-1)
}
