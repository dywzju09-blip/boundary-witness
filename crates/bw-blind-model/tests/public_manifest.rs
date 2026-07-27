use bw_blind_model::BlindPublicManifest;

const VALID_MANIFEST: &str = r#"{
  "schema_version":"boundary-witness.blind-public/0.1",
  "suite_id":"suite-2026-001",
  "split":"gate",
  "method_commit":"0123456789abcdef0123456789abcdef01234567",
  "policy_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "cases":[{
    "case_id":"blind-8f34a923d01c77ab",
    "case_root":"cases/blind-8f34a923d01c77ab",
    "case_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "command":{"program":"adapter/bin/driver","args":["run"],"env":{}},
    "timeout_seconds":60
  }]
}"#;

#[test]
fn opaque_manifest_validates() {
    BlindPublicManifest::parse_json(VALID_MANIFEST)
        .expect("opaque public manifest should validate");
}

#[test]
fn unknown_cve_field_is_rejected() {
    let manifest = VALID_MANIFEST.replace("\"cases\":[{", "\"cve\":\"synthetic\",\"cases\":[{");
    assert!(BlindPublicManifest::parse_json(&manifest).is_err());
}

#[test]
fn parent_path_is_rejected() {
    let manifest = VALID_MANIFEST.replace("adapter/bin/driver", "../escape");
    assert!(BlindPublicManifest::parse_json(&manifest).is_err());
}

#[test]
fn duplicate_case_ids_are_rejected() {
    let duplicate = r#"{
      "case_id":"blind-8f34a923d01c77ab",
      "case_root":"cases/blind-8f34a923d01c77ab-2",
      "case_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "command":{"program":"adapter/bin/driver","args":["run"],"env":{}},
      "timeout_seconds":60
    }"#;
    let manifest = VALID_MANIFEST.replace("\n  }]\n}", &format!(",{duplicate}\n  }}]\n}}"));
    assert!(BlindPublicManifest::parse_json(&manifest).is_err());
}

#[test]
fn uppercase_digest_is_rejected() {
    let manifest = VALID_MANIFEST.replace(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    );
    assert!(BlindPublicManifest::parse_json(&manifest).is_err());
}

#[test]
fn zero_timeout_is_rejected() {
    let manifest = VALID_MANIFEST.replace("\"timeout_seconds\":60", "\"timeout_seconds\":0");
    assert!(BlindPublicManifest::parse_json(&manifest).is_err());
}

#[test]
fn schema_disallows_unknown_root_case_and_command_fields() {
    let schema_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../experiments/schemas/blind-public-manifest.schema.json"
    );
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(schema_path).expect("schema should be readable"),
    )
    .expect("schema should be JSON");

    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["$defs"]["case"]["additionalProperties"], false);
    assert_eq!(schema["$defs"]["command"]["additionalProperties"], false);
}

#[test]
fn schema_command_program_pattern_matches_model_path_rules() {
    let schema_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../experiments/schemas/blind-public-manifest.schema.json"
    );
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(schema_path).expect("schema should be readable"),
    )
    .expect("schema should be JSON");
    let pattern = schema["$defs"]["command"]["properties"]["program"]["pattern"]
        .as_str()
        .expect("command program should have a pattern");
    let pattern = regex::Regex::new(pattern).expect("schema program pattern should compile");

    for invalid_path in ["adapter//driver", "adapter/", r"adapter\driver"] {
        assert!(
            !pattern.is_match(invalid_path),
            "schema should reject invalid command program {invalid_path:?}"
        );
    }
    assert!(pattern.is_match("adapter/bin/driver"));
}
