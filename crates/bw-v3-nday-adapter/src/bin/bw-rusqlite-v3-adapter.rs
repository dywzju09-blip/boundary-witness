//! rusqlite 形态的 adapter 入口。
//!
//! 与 `bw-v3-nday-adapter` 共用同一份实现，只换 [`RUSQLITE_V3_ADAPTER`] 这一组身份
//! 常量。此前这是一个独立 crate，452 行 `lib.rs` 只与通用形态差三个字面量。

use std::process::ExitCode;

fn main() -> ExitCode {
    match bw_v3_nday_adapter::run_from_env(&bw_v3_nday_adapter::RUSQLITE_V3_ADAPTER) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bw-rusqlite-v3-adapter: {error:#}");
            ExitCode::from(1)
        }
    }
}
