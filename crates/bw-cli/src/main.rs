use std::process::ExitCode;

use clap::Parser;

mod commands;
mod exit;

#[derive(Parser)]
#[command(name = "bw")]
struct Cli {
    #[command(subcommand)]
    command: commands::Command,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match commands::run(cli.command) {
        Ok(status) => ExitCode::from(status.code()),
        Err(error) => {
            eprintln!("{}: {}", error.code(), error.message());
            ExitCode::from(error.exit_code())
        }
    }
}
