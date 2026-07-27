use std::{collections::VecDeque, env, error::Error, path::PathBuf, process::ExitCode};

use rusqlite_lab_shared::artifact_staging::{
    d0_staging_plan, m12_staging_plan, stage_d0_artifacts, stage_m12_artifacts, StageOptions,
    StagingLayout, V3BlindSourceOptions, V3_M12_SUITE_ID, V3_SOURCE_SCHEMA_V01,
    write_m12_v3_blind_source,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bw-rusqlite-stage-artifacts: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1).collect::<VecDeque<_>>();
    match args.pop_front().as_deref() {
        Some("plan") => {
            let suite = optional_suite_or_default(&mut args);
            let repo_root = optional_path(&mut args).unwrap_or_else(|| PathBuf::from("."));
            let layout = layout_for_suite(suite, &repo_root);
            match suite {
                Suite::M12 => {
                    serde_json::to_writer_pretty(std::io::stdout(), &m12_staging_plan(&layout))?;
                }
                Suite::D0 => {
                    serde_json::to_writer_pretty(std::io::stdout(), &d0_staging_plan(&layout))?;
                }
            }
            println!();
        }
        Some("stage") => {
            let suite = optional_suite_or_default(&mut args);
            let rustup_toolchain = optional_rustup_toolchain(&mut args)?
                .or_else(|| env::var("BW_RUSQLITE_RUSTUP_TOOLCHAIN").ok())
                .filter(|toolchain| !toolchain.trim().is_empty());
            let repo_root = canonical_required_path(&mut args, "repo root")?;
            let bw_rustc = canonical_required_path(&mut args, "bw-rustc binary")?;
            let layout = layout_for_suite(suite, &repo_root);
            let plan = match suite {
                Suite::M12 => stage_m12_artifacts(&StageOptions {
                    layout,
                    bw_rustc,
                    rustup_toolchain,
                })?,
                Suite::D0 => stage_d0_artifacts(&StageOptions {
                    layout,
                    bw_rustc,
                    rustup_toolchain,
                })?,
            };
            serde_json::to_writer_pretty(std::io::stdout(), &plan)?;
            println!();
        }
        Some("v3-source") => {
            let suite = required_suite(&mut args)?;
            if suite != Suite::M12 {
                return Err("v3-source currently supports only m12".into());
            }
            let artifact_root = canonical_required_path(&mut args, "artifact root")?;
            let output_root = required_path(&mut args, "output root")?;
            let adapter_binary = canonical_required_path(&mut args, "adapter binary")?;
            let bw_binary = canonical_required_path(&mut args, "bw binary")?;
            let contract = canonical_required_path(&mut args, "contract")?;
            write_m12_v3_blind_source(&V3BlindSourceOptions {
                artifact_root,
                output_root: output_root.clone(),
                adapter_binary,
                bw_binary,
                contract,
            })?;
            serde_json::to_writer_pretty(
                std::io::stdout(),
                &serde_json::json!({
                    "schema_version": V3_SOURCE_SCHEMA_V01,
                    "suite_id": V3_M12_SUITE_ID,
                    "source_root": output_root,
                    "case_count": 10,
                }),
            )?;
            println!();
        }
        _ => {
            eprintln!(
                "usage:\n  bw-rusqlite-stage-artifacts plan [d0|m12] [repo-root]\n  bw-rusqlite-stage-artifacts stage [d0|m12] [--rustup-toolchain <toolchain>] <repo-root> <bw-rustc-binary>\n  bw-rusqlite-stage-artifacts v3-source m12 <artifact-root> <output-root> <adapter-binary> <bw-binary> <contract>"
            );
            return Err("invalid command".into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Suite {
    M12,
    D0,
}

fn optional_suite_or_default(args: &mut VecDeque<String>) -> Suite {
    match args.front().map(String::as_str) {
        Some("d0") => {
            args.pop_front();
            Suite::D0
        }
        Some("m12") => {
            args.pop_front();
            Suite::M12
        }
        None => Suite::M12,
        Some(_) => Suite::M12,
    }
}

fn required_suite(args: &mut VecDeque<String>) -> Result<Suite, Box<dyn Error>> {
    match args.pop_front().as_deref() {
        Some("d0") => Ok(Suite::D0),
        Some("m12") => Ok(Suite::M12),
        Some(value) => Err(format!("unknown suite: {value}").into()),
        None => Err("missing suite".into()),
    }
}

fn layout_for_suite(suite: Suite, repo_root: &std::path::Path) -> StagingLayout {
    match suite {
        Suite::M12 => StagingLayout::m12_default(repo_root),
        Suite::D0 => StagingLayout::d0_default(repo_root),
    }
}

fn optional_path(args: &mut VecDeque<String>) -> Option<PathBuf> {
    args.pop_front().map(PathBuf::from)
}

fn required_path(args: &mut VecDeque<String>, label: &str) -> Result<PathBuf, Box<dyn Error>> {
    args.pop_front()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {label}").into())
}

fn optional_rustup_toolchain(
    args: &mut VecDeque<String>,
) -> Result<Option<String>, Box<dyn Error>> {
    match args.front().map(String::as_str) {
        Some("--rustup-toolchain") => {
            args.pop_front();
            args.pop_front()
                .map(Some)
                .ok_or_else(|| "missing --rustup-toolchain value".into())
        }
        _ => Ok(None),
    }
}

fn canonical_required_path(
    args: &mut VecDeque<String>,
    label: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    let path = required_path(args, label)?;
    path.canonicalize()
        .map_err(|error| format!("canonicalize {label} {}: {error}", path.display()).into())
}
