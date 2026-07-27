use std::{error::Error, path::PathBuf};

use bw_experiment::{D2ComparisonSummary, render_d2_summary_markdown};

fn main() -> Result<(), Box<dyn Error>> {
    let Some(path) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: bw-d2-summary <d2-comparison-summary.json>");
        std::process::exit(2);
    };
    let input = std::fs::read_to_string(path)?;
    let summary: D2ComparisonSummary = serde_json::from_str(&input)?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    println!();
    println!("{}", render_d2_summary_markdown(&summary));
    Ok(())
}
