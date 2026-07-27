use std::{fs, path::PathBuf};

use bw_experiment::{SanitizerKind, parse_asan_log};

#[test]
fn positive_asan_log_extracts_kind_error_and_first_frame() {
    let report = parse_asan_log(&fixture("positive.log"))
        .expect("positive fixture should parse an ASan report");

    assert_eq!(report.kind, SanitizerKind::AddressSanitizer);
    assert_eq!(report.error_kind, "heap-use-after-free");
    assert_eq!(
        report
            .first_frame
            .as_ref()
            .map(|frame| frame.symbol.as_str()),
        Some("rusqlite_update_hook_callback")
    );
    assert_eq!(
        report
            .first_frame
            .as_ref()
            .and_then(|frame| frame.location.as_deref()),
        Some("/workspace/rusqlite/src/hooks.rs:42:7")
    );
    assert!(report.summary.contains("heap-use-after-free"));
}

#[test]
fn ordinary_text_that_mentions_asan_is_not_a_sanitizer_report() {
    assert!(parse_asan_log(&fixture("negative.log")).is_none());
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/experiment/asan")
        .join(name);
    fs::read_to_string(path).unwrap()
}
