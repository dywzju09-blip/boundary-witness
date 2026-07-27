use std::{error::Error, path::PathBuf};

use bw_experiment::D2BaselineConfigFile;

fn main() -> Result<(), Box<dyn Error>> {
    let Some(path) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: bw-d2-random <d2-baselines.toml>");
        std::process::exit(2);
    };
    let config = D2BaselineConfigFile::from_path(path)?;
    println!("{}", serde_json::to_string_pretty(&config.random_action)?);
    Ok(())
}
