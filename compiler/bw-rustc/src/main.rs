#![feature(rustc_private)]

mod args;
mod callbacks;
mod cargo_metadata;
mod config;
mod coverage;
mod domain;
mod registration;
mod rustc_api;

use std::{env, process};

use config::CompilerConfig;

fn main() {
    let invocation = match args::WrapperInvocation::parse(env::args_os()) {
        Ok(invocation) => invocation,
        Err(error) => exit_error("BW-RUSTC-ARGS", &error.to_string()),
    };

    let Some(config_path) = env::var_os("BW_RUSTC_CONFIG") else {
        process::exit(pass_through(&invocation));
    };
    let config = match CompilerConfig::from_path(config_path) {
        Ok(config) => config,
        Err(error) => exit_error("BW-RUSTC-CONFIG", &error.to_string()),
    };
    let Some(request) = config.analysis_request(&invocation) else {
        process::exit(pass_through(&invocation));
    };

    process::exit(rustc_api::run_after_analysis(invocation, request));
}

fn pass_through(invocation: &args::WrapperInvocation) -> i32 {
    let status = match process::Command::new(&invocation.real_rustc)
        .args(&invocation.rustc_args)
        .status()
    {
        Ok(status) => status,
        Err(error) => exit_error("BW-RUSTC-PASSTHROUGH", &error.to_string()),
    };
    status.code().unwrap_or(1)
}

fn exit_error(code: &str, message: &str) -> ! {
    eprintln!("{code}: {message}");
    process::exit(2);
}
