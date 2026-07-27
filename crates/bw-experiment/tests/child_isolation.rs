use std::{fs, time::Duration};

use bw_experiment::{ChildRunner, ChildSpec, ChildStatus};
use tempfile::tempdir;

#[test]
fn child_runs_get_isolated_workdirs_and_log_files() {
    let temp = tempdir().unwrap();
    let runner = ChildRunner::new(temp.path());

    let first = runner
        .run(
            ChildSpec::new("/bin/sh")
                .arg("-c")
                .arg("printf first; printf err1 >&2")
                .timeout(Duration::from_secs(2)),
        )
        .unwrap();
    let second = runner
        .run(
            ChildSpec::new("/bin/sh")
                .arg("-c")
                .arg("printf second; printf err2 >&2")
                .timeout(Duration::from_secs(2)),
        )
        .unwrap();

    assert_eq!(first.status, ChildStatus::Exited(0));
    assert_eq!(second.status, ChildStatus::Exited(0));
    assert_ne!(first.work_dir, second.work_dir);
    assert!(first.stdout_path.starts_with(&first.work_dir));
    assert!(first.stderr_path.starts_with(&first.work_dir));
    assert_eq!(fs::read_to_string(first.stdout_path).unwrap(), "first");
    assert_eq!(fs::read_to_string(first.stderr_path).unwrap(), "err1");
    assert_eq!(fs::read_to_string(second.stdout_path).unwrap(), "second");
    assert_eq!(fs::read_to_string(second.stderr_path).unwrap(), "err2");
}

#[test]
fn timeout_child_is_classified_without_reusing_process_state() {
    let temp = tempdir().unwrap();
    let runner = ChildRunner::new(temp.path());

    let timed_out = runner
        .run(
            ChildSpec::new("/bin/sh")
                .arg("-c")
                .arg("sleep 5")
                .timeout(Duration::from_millis(100))
                .terminate_grace(Duration::from_millis(50)),
        )
        .unwrap();
    assert_eq!(timed_out.status, ChildStatus::TimedOut);
    assert!(timed_out.timed_out);

    let after_timeout = runner
        .run(
            ChildSpec::new("/bin/sh")
                .arg("-c")
                .arg("printf after-timeout")
                .timeout(Duration::from_secs(2)),
        )
        .unwrap();
    assert_eq!(after_timeout.status, ChildStatus::Exited(0));
    assert_eq!(
        fs::read_to_string(after_timeout.stdout_path).unwrap(),
        "after-timeout"
    );
}

#[test]
fn child_work_dir_can_be_injected_into_the_child_environment() {
    let temp = tempdir().unwrap();
    let case_work_dir = temp.path().join("case-work");
    let runner = ChildRunner::new(&case_work_dir);
    let run = || {
        runner
            .run(
                ChildSpec::new("/bin/sh")
                    .arg("-c")
                    .arg(
                        "printf '%s' \"$BW_CHILD_WORK_DIR\"; \
                         printf '{\"status\":\"completed\"}\n' \
                           > \"$BW_CHILD_WORK_DIR/observation.json\"",
                    )
                    .arg("write-observation")
                    .work_dir_env("BW_CHILD_WORK_DIR"),
            )
            .unwrap()
    };

    let first = run();
    let second = run();

    for result in [&first, &second] {
        let printed_path = fs::read_to_string(&result.stdout_path).unwrap();
        assert_eq!(printed_path, result.work_dir.to_string_lossy());
        assert!(result.work_dir.exists());
        assert!(result.work_dir.starts_with(&case_work_dir));
        assert!(result.work_dir.join("observation.json").is_file());
    }
    assert_ne!(first.work_dir, second.work_dir);
}

#[test]
fn child_work_dir_environment_key_must_be_a_valid_name() {
    let temp = tempdir().unwrap();
    let runner = ChildRunner::new(temp.path());

    for key in ["", "INVALID=KEY"] {
        let error = runner
            .run(ChildSpec::new("/bin/true").work_dir_env(key))
            .unwrap_err()
            .to_string();
        assert!(error.contains("work directory environment key"), "{error}");
    }
}

#[test]
fn child_does_not_inherit_operator_environment_without_an_explicit_allowlist() {
    const HELPER: &str = "BW_ENV_ISOLATION_HELPER";
    const PRIVATE_SENTINEL: &str = "BW_OPERATOR_PRIVATE_SENTINEL";
    if std::env::var(HELPER).as_deref() != Ok("1") {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "child_does_not_inherit_operator_environment_without_an_explicit_allowlist",
            ])
            .env(HELPER, "1")
            .env(PRIVATE_SENTINEL, "private-do-not-leak")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    assert_eq!(
        std::env::var(PRIVATE_SENTINEL).as_deref(),
        Ok("private-do-not-leak")
    );
    let temp = tempdir().unwrap();
    let runner = ChildRunner::new(temp.path());

    let result = runner
        .run(
            ChildSpec::new("/bin/sh")
                .arg("-c")
                .arg("printf '%s' \"${BW_OPERATOR_PRIVATE_SENTINEL-unset}\""),
        )
        .unwrap();

    assert_eq!(result.status, ChildStatus::Exited(0));
    assert_eq!(fs::read_to_string(result.stdout_path).unwrap(), "unset");
}
