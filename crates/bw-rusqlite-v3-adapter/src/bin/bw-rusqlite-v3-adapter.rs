use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bw-rusqlite-v3-adapter: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> anyhow::Result<()> {
    bw_rusqlite_v3_adapter::run_from_env()
}
