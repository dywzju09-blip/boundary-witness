use std::{error::Error, path::PathBuf};

use bw_experiment::{
    D2BaselineConfigFile, comparison_summary, comparison_summary_from_record_root,
    format_d2_config_field,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let Some(path) = args.next().map(PathBuf::from) else {
        eprintln!(
            "usage: bw-d2-compare <d2-baselines.toml> [--records-root <dir>] [--print-field <field>]"
        );
        std::process::exit(2);
    };
    let mut records_root = None;
    let mut print_field = None;
    while let Some(arg) = args.next() {
        if arg == "--records-root" {
            let Some(value) = args.next() else {
                eprintln!("bw-d2-compare: --records-root requires a value");
                std::process::exit(2);
            };
            records_root = Some(PathBuf::from(value));
        } else if arg == "--print-field" {
            let Some(value) = args.next() else {
                eprintln!("bw-d2-compare: --print-field requires a value");
                std::process::exit(2);
            };
            print_field = Some(value.to_string_lossy().into_owned());
        } else {
            eprintln!("bw-d2-compare: unknown argument: {}", arg.to_string_lossy());
            std::process::exit(2);
        }
    }
    let config = D2BaselineConfigFile::from_path(path)?;
    if let Some(field) = print_field {
        print!("{}", format_d2_config_field(&config, &field)?);
        return Ok(());
    }
    let summary = if let Some(records_root) = records_root {
        comparison_summary_from_record_root(&config, records_root)?
    } else {
        comparison_summary(&config)?
    };
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}
