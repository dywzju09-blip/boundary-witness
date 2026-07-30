//! 通用 V3 N-day adapter 入口。rusqlite 形态见 `bw-rusqlite-v3-adapter`。

use std::process::ExitCode;

fn main() -> ExitCode {
    match bw_v3_nday_adapter::run_from_env(&bw_v3_nday_adapter::V3_NDAY_ADAPTER) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bw-v3-nday-adapter: {error:#}");
            ExitCode::from(1)
        }
    }
}
