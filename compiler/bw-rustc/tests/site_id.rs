use bw_rustc::{SiteDescriptor, SiteRole};

#[test]
fn absolute_checkout_path_does_not_change_site_id() {
    let a = descriptor("/tmp/a/repo/src/main.rs").with_repo_root("/tmp/a/repo");
    let b = descriptor("/work/b/repo/src/main.rs").with_repo_root("/work/b/repo");

    assert_eq!(a.site_id(), b.site_id());
    assert_eq!(a.semantic_key(), b.semantic_key());
}

#[test]
fn capture_ordinals_produce_distinct_sites() {
    let first = descriptor_with_capture(0);
    let second = descriptor_with_capture(1);

    assert_ne!(first.site_id(), second.site_id());
    assert_ne!(first.semantic_key(), second.semantic_key());
}

#[test]
fn span_changes_site_id_but_not_semantic_key() {
    let first = descriptor("/repo/src/main.rs")
        .with_repo_root("/repo")
        .with_span("src/main.rs:10:5");
    let second = descriptor("/repo/src/main.rs")
        .with_repo_root("/repo")
        .with_span("src/main.rs:11:5");

    assert_ne!(first.site_id(), second.site_id());
    assert_eq!(first.semantic_key(), second.semantic_key());
}

#[test]
fn absolute_paths_are_rejected_in_identity_inputs() {
    let error = descriptor("/repo/src/main.rs")
        .with_repo_root("/other")
        .try_site_id()
        .expect_err("path outside repo root should be rejected");

    assert!(error.to_string().contains("absolute path"));
}

fn descriptor(path: &str) -> SiteDescriptor {
    SiteDescriptor::new(
        "package:app",
        "target:bin",
        "app::main::{{closure}}",
        SiteRole::Capture,
        path,
    )
    .with_mir_location("bb0[3]")
    .with_capture_ordinal(0)
    .with_span("src/main.rs:10:5")
}

fn descriptor_with_capture(ordinal: u32) -> SiteDescriptor {
    descriptor("/repo/src/main.rs")
        .with_repo_root("/repo")
        .with_capture_ordinal(ordinal)
}
