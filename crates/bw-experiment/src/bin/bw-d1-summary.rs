use std::{env, error::Error, path::PathBuf};

use bw_experiment::summarize_d1_run_dirs;

fn main() {
    if let Err(error) = run() {
        eprintln!("bw-d1-summary: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let paths = env::args().skip(1).map(PathBuf::from).collect::<Vec<_>>();
    if paths.is_empty() {
        return Err("usage: bw-d1-summary <d1-run-dir> [<d1-run-dir> ...]".into());
    }
    let summary = summarize_d1_run_dirs(&paths)?;
    serde_json::to_writer_pretty(std::io::stdout(), &summary)?;
    println!();
    Ok(())
}
