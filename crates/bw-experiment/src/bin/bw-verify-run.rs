use std::{env, error::Error, path::Path};

use bw_experiment::verify_run_integrity;

fn main() {
    if let Err(error) = run() {
        eprintln!("bw-verify-run: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let Some(path) = env::args().nth(1) else {
        return Err("usage: bw-verify-run <final-run-directory>".into());
    };
    let path = Path::new(&path);
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".partial"))
    {
        return Err("refusing to verify .partial run directory".into());
    }
    verify_run_integrity(path)?;
    println!(
        "{{\"status\":\"ok\",\"path\":\"{}\"}}",
        path.display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    );
    Ok(())
}
