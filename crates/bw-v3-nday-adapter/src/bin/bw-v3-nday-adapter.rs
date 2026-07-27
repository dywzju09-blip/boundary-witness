use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bw-v3-nday-adapter: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> anyhow::Result<()> {
    bw_v3_nday_adapter::run_from_env()
}
