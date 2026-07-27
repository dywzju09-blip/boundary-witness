use bw_model::{
    BuildId, CONTRACT_SCHEMA_V01, CallbackApiEntry, CallbackRetentionApiMap,
    CallbackRetentionContract, CallbackRetentionRegistry, CaptureBindEvent, ContractClause,
    ContractClauseKind, EvidenceReference, EvidenceSourceKind, ExecutionEvidence, ExecutionResult,
    FINDING_SCHEMA_V01, Finding, FindingClassification, FindingStateSnapshot, InstanceId,
    InvokeRole, OpaqueHandleApiRole, OpaqueHandleIdentityComponent, PrimaryOutcome, RUN_SCHEMA_V01,
    RecordId, RegistrationRole, ReleaseBehavior, RunId, RunManifest, RuntimeEvent,
    RuntimeEventEnvelope, SiteId, TRACE_SCHEMA_V01, ToolchainVersions, TraceId,
    V33ScannerFreezeRecord, validate_v3_3_scanner_freeze,
};

#[test]
fn runtime_event_roundtrips() {
    let event = RuntimeEventEnvelope {
        schema_version: TRACE_SCHEMA_V01.to_owned(),
        record_id: RecordId::from("event:3"),
        run_id: RunId::from("run:test"),
        trace_id: TraceId::from("trace:test"),
        seq: 3,
        thread_id: "main".to_owned(),
        source: "bw-runtime".to_owned(),
        payload: RuntimeEvent::CaptureBind(CaptureBindEvent {
            callback_instance_id: InstanceId::from("callback:1"),
            callback_site_id: SiteId::from("site:callback"),
            object_instance_id: InstanceId::from("object:1"),
            object_site_id: SiteId::from("site:object"),
        }),
    };

    let json = serde_json::to_string(&event).expect("runtime event should serialize");
    assert_eq!(
        RuntimeEventEnvelope::from_json_str(&json).expect("runtime event should parse"),
        event
    );
}

#[test]
fn contract_roundtrips() {
    let contract = CallbackRetentionContract {
        schema_version: CONTRACT_SCHEMA_V01.to_owned(),
        contract_id: "contract:retained-callback".to_owned(),
        producer: "boundary-witness@test-commit".to_owned(),
        clauses: vec![ContractClause {
            clause_id: "clause:register-retains".to_owned(),
            kind: ContractClauseKind::RetainAfterRegister,
            description: "注册后外部 owner 可以保留 callback".to_owned(),
        }],
        api_entries: vec![CallbackApiEntry {
            clause_id: "clause:register-retains".to_owned(),
            api_id: "api:register".to_owned(),
            registration_role: Some(RegistrationRole::Register),
            release_behavior: ReleaseBehavior::None,
            owner_kind: "external_owner".to_owned(),
            invoke_role: Some(InvokeRole::Callback),
        }],
    };

    let toml = toml::to_string(&contract).expect("contract should serialize to TOML");
    assert_eq!(
        CallbackRetentionContract::from_toml_str(&toml).expect("contract should parse"),
        contract
    );
}

#[test]
fn callback_retention_api_map_rejects_unknown_fields_and_invalid_schema() {
    let api_map = fixture_api_map();
    let unknown_field = format!("{api_map}\nunexpected = true\n");
    assert!(CallbackRetentionApiMap::from_toml_str(&unknown_field).is_err());

    let invalid_schema = api_map.replace("bw.api-map/0.1", "bw.api-map/999");
    assert!(CallbackRetentionApiMap::from_toml_str(&invalid_schema).is_err());
}

#[test]
fn callback_retention_contract_rejects_unresolved_clause_reference() {
    let invalid = fixture_contract().replacen(
        "clause_id = \"clause:register-retains\"\napi_id = \"api:register\"",
        "clause_id = \"clause:missing\"\napi_id = \"api:register\"",
        1,
    );

    assert!(CallbackRetentionContract::from_toml_str(&invalid).is_err());
}

#[test]
fn callback_retention_registry_rejects_mismatched_contract_and_invalid_api_entries() {
    let contract = fixture_contract();
    let api_map = fixture_api_map();

    let mismatched_contract = api_map.replace(
        "contract_id = \"contract:callback-retention\"",
        "contract_id = \"contract:other\"",
    );
    assert!(CallbackRetentionRegistry::from_toml_strs(&contract, &mismatched_contract).is_err());

    let duplicate_api_id = format!(
        "{api_map}\n[[apis]]\napi_id = \"api:rusqlite:update_hook:register\"\nrust_path = \"rusqlite::Connection::duplicate\"\ncontract_api_id = \"api:register\"\ncallback_family = \"sqlite_update_hook\"\nnotes = \"duplicate\"\n"
    );
    assert!(CallbackRetentionRegistry::from_toml_strs(&contract, &duplicate_api_id).is_err());

    let empty_rust_path = api_map.replace(
        "rust_path = \"rusqlite::Connection::update_hook\"",
        "rust_path = \"\"",
    );
    assert!(CallbackRetentionRegistry::from_toml_strs(&contract, &empty_rust_path).is_err());

    let empty_callback_family = api_map.replace(
        "callback_family = \"sqlite_update_hook\"",
        "callback_family = \"\"",
    );
    assert!(CallbackRetentionRegistry::from_toml_strs(&contract, &empty_callback_family).is_err());
}

#[test]
fn callback_retention_api_map_validates_opaque_handle_roles() {
    let openssl_api_map = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/callback-retention/openssl-api-map.toml"),
    )
    .unwrap();
    let parsed = CallbackRetentionApiMap::from_toml_str(&openssl_api_map)
        .expect("OpenSSL API map should parse with opaque handle roles");

    let ssl_set = parsed
        .apis
        .iter()
        .find(|entry| entry.api_id == "api:openssl:ssl_set_ex_data:register")
        .expect("SSL_set_ex_data set entry should exist");
    assert_eq!(ssl_set.opaque_handle_role, Some(OpaqueHandleApiRole::Set));
    assert_eq!(ssl_set.opaque_handle_arg_index, Some(0));
    assert_eq!(ssl_set.opaque_key_arg_index, Some(1));
    assert_eq!(ssl_set.opaque_payload_arg_index, Some(2));
    assert_eq!(ssl_set.user_data_arg_indices, vec![2]);
    assert_eq!(
        ssl_set.opaque_generation_key,
        vec![
            OpaqueHandleIdentityComponent::BindingApiId,
            OpaqueHandleIdentityComponent::HandleArg,
            OpaqueHandleIdentityComponent::KeyArg,
            OpaqueHandleIdentityComponent::PayloadArg,
        ]
    );

    let ssl_get = parsed
        .apis
        .iter()
        .find(|entry| entry.api_id == "api:openssl:ssl_get_ex_data:get")
        .expect("SSL_get_ex_data get entry should exist");
    assert_eq!(ssl_get.opaque_handle_role, Some(OpaqueHandleApiRole::Get));
    assert_eq!(
        ssl_get.opaque_binding_api_id.as_deref(),
        Some("api:openssl:ssl_set_ex_data:register")
    );
    assert_eq!(ssl_get.opaque_handle_arg_index, Some(0));
    assert_eq!(ssl_get.opaque_key_arg_index, Some(1));
    assert_eq!(ssl_get.opaque_payload_arg_index, None);
    assert!(ssl_get.user_data_arg_indices.is_empty());
    assert_eq!(
        ssl_get.opaque_generation_key,
        vec![
            OpaqueHandleIdentityComponent::BindingApiId,
            OpaqueHandleIdentityComponent::HandleArg,
            OpaqueHandleIdentityComponent::KeyArg,
        ]
    );

    let missing_binding = openssl_api_map.replace(
        "opaque_binding_api_id = \"api:openssl:ssl_set_ex_data:register\"",
        "opaque_binding_api_id = \"api:openssl:missing:set\"",
    );
    assert!(CallbackRetentionApiMap::from_toml_str(&missing_binding).is_err());

    let missing_generation_key = openssl_api_map.replacen(
        "opaque_generation_key = [\"binding_api_id\", \"handle_arg\", \"key_arg\", \"payload_arg\"]\n",
        "",
        1,
    );
    assert!(CallbackRetentionApiMap::from_toml_str(&missing_generation_key).is_err());

    let missing_handle_identity = openssl_api_map.replacen(
        "opaque_generation_key = [\"binding_api_id\", \"handle_arg\", \"key_arg\", \"payload_arg\"]",
        "opaque_generation_key = [\"binding_api_id\", \"key_arg\", \"payload_arg\"]",
        1,
    );
    assert!(CallbackRetentionApiMap::from_toml_str(&missing_handle_identity).is_err());

    let get_with_payload = openssl_api_map.replace(
        "api_id = \"api:openssl:ssl_get_ex_data:get\"\nrust_path = \"openssl_sys::SSL_get_ex_data\"",
        "api_id = \"api:openssl:ssl_get_ex_data:get\"\nrust_path = \"openssl_sys::SSL_get_ex_data\"\nopaque_payload_arg_index = 2",
    );
    assert!(CallbackRetentionApiMap::from_toml_str(&get_with_payload).is_err());

    let missing_role = openssl_api_map.replace("opaque_handle_role = \"set\"\n", "");
    assert!(CallbackRetentionApiMap::from_toml_str(&missing_role).is_err());

    let mismatched_binding_family = openssl_api_map.replace(
        "opaque_binding_api_id = \"api:openssl:ssl_set_ex_data:register\"",
        "opaque_binding_api_id = \"api:openssl:ssl_ctx_set_ex_data:register\"",
    );
    assert!(CallbackRetentionApiMap::from_toml_str(&mismatched_binding_family).is_err());
}

fn fixture_contract() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/callback-retention/contract.toml"),
    )
    .unwrap()
}

fn fixture_api_map() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/callback-retention/rusqlite-api-map.toml"),
    )
    .unwrap()
}

#[test]
fn finding_keeps_machine_readable_evidence_separate_from_message() {
    let finding = Finding {
        schema_version: FINDING_SCHEMA_V01.to_owned(),
        record_id: RecordId::from("finding:1"),
        rule_id: "BW-LIFE-002".to_owned(),
        classification: FindingClassification::ConfirmedViolation,
        subject_object: Some(InstanceId::from("object:1")),
        subject_callback: Some(InstanceId::from("callback:1")),
        first_violation_event: RecordId::from("event:9"),
        evidence: vec![EvidenceReference {
            record_id: RecordId::from("fact:capture-1"),
            source_kind: EvidenceSourceKind::StaticFact,
            description_code: "BW-EVIDENCE-CAPTURE".to_owned(),
        }],
        context_rule_ids: Vec::new(),
        state_before: FindingStateSnapshot::default(),
        state_after: FindingStateSnapshot {
            object_state: Some("ended".to_owned()),
            capture_state: Some("ended".to_owned()),
            callback_state: Some("retained".to_owned()),
            owner_state: Some("open".to_owned()),
        },
        normalized_signature: "BW-LIFE-002|semantic:callback|semantic:object".to_owned(),
        producer: "bw-oracle@test-commit".to_owned(),
        build_id: BuildId::from("build:test"),
        run_id: RunId::from("run:test"),
        message: "callback 在 borrow 结束后被调用".to_owned(),
    };

    let json = serde_json::to_string(&finding).expect("finding should serialize");
    assert_eq!(
        Finding::from_json_str(&json).expect("finding should parse"),
        finding
    );
}

#[test]
fn primary_outcome_and_evidence_are_separate() {
    let result = ExecutionResult {
        primary_outcome: PrimaryOutcome::ContractFinding,
        evidence: ExecutionEvidence {
            has_contract_finding: true,
            has_asan_evidence: true,
            has_native_crash: false,
            has_panic: false,
            has_timeout: false,
        },
    };
    let json = serde_json::to_string(&result).expect("execution result should serialize");

    assert_eq!(
        serde_json::from_str::<ExecutionResult>(&json).expect("execution result should parse"),
        result
    );
    assert_eq!(result.primary_outcome, PrimaryOutcome::ContractFinding);
    assert!(result.evidence.has_asan_evidence);
}

#[test]
fn run_manifest_roundtrips() {
    let manifest = RunManifest {
        schema_version: RUN_SCHEMA_V01.to_owned(),
        run_id: RunId::from("run:test"),
        build_id: BuildId::from("build:test"),
        git_commit: "0123456789abcdef".to_owned(),
        deployment_sha256: "sha256:deployment".to_owned(),
        image_digest: "sha256:image".to_owned(),
        config_digest: "sha256:config".to_owned(),
        host: "linux-test".to_owned(),
        cpu_limit: Some(1),
        seed: Some(42),
        toolchains: ToolchainVersions {
            stable: "rustc 1.97.0".to_owned(),
            compiler_nightly: Some("nightly-2026-07-08".to_owned()),
        },
        started_at_utc: "2026-07-18T00:00:00Z".to_owned(),
        completed_at_utc: None,
        execution: None,
    };

    let json = serde_json::to_string(&manifest).expect("manifest should serialize");
    assert_eq!(
        RunManifest::from_json_str(&json).expect("manifest should parse"),
        manifest
    );
}

#[test]
fn unknown_runtime_event_kind_is_rejected() {
    let json = r#"{
        "schema_version":"bw.trace/0.1",
        "record_id":"event:1",
        "run_id":"run:test",
        "trace_id":"trace:test",
        "seq":1,
        "thread_id":"main",
        "source":"bw-runtime",
        "payload":{"kind":"invented_event"}
    }"#;

    assert!(serde_json::from_str::<RuntimeEventEnvelope>(json).is_err());
}

#[test]
fn scanner_freeze_rejects_unknown_fields_and_invalid_hashes() {
    let valid = scanner_freeze_fixture();
    let record: V33ScannerFreezeRecord =
        serde_json::from_str(&valid).expect("scanner freeze should parse");
    validate_v3_3_scanner_freeze(&record).expect("scanner freeze should validate");

    let unknown = valid.replacen(
        r#""notes":["candidate/ranking is not a vulnerability conclusion"]"#,
        r#""notes":["candidate/ranking is not a vulnerability conclusion"],"unexpected":true"#,
        1,
    );
    assert!(serde_json::from_str::<V33ScannerFreezeRecord>(&unknown).is_err());

    let bad_hash = valid.replacen(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "not-a-sha",
        1,
    );
    let bad_record: V33ScannerFreezeRecord =
        serde_json::from_str(&bad_hash).expect("bad hash record still parses");
    assert!(validate_v3_3_scanner_freeze(&bad_record).is_err());
}

#[test]
fn v3_2_x_schemas_cover_static_lifecycle_candidate_shapes() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let boundary_schema = read_schema(&root, "schemas/v3-2/boundary-index.schema.json");
    assert_schema_enum_contains(&boundary_schema, "boundary_kind", "returned_borrow");
    assert_schema_enum_contains(&boundary_schema, "boundary_kind", "external_buffer");

    for path in [
        "schemas/v3-2/candidate.schema.json",
        "schemas/v3-2/lifecycle-graph.schema.json",
        "schemas/v3-2/ranked-candidate.schema.json",
        "schemas/v3-2/adapter-effort.schema.json",
        "schemas/v3-2-5/private-ground-truth.schema.json",
        "schemas/v3-2-6/lifecycle-graph-v2.schema.json",
        "schemas/v3-2-6/lifecycle-feature.schema.json",
        "schemas/v3-2-6/ranked-candidate-v2.schema.json",
    ] {
        let schema = read_schema(&root, path);
        assert_schema_text_contains(&schema, path, "returned_borrow_view");
        assert_schema_text_contains(&schema, path, "external_buffer_view");
    }

    let graph_v3_schema = read_schema(&root, "schemas/v3-2-6/lifecycle-graph-v3.schema.json");
    for layer in [
        "identity_transport",
        "lifecycle_ordering",
        "complete_risk_chain",
    ] {
        assert_schema_text_contains(
            &graph_v3_schema,
            "schemas/v3-2-6/lifecycle-graph-v3.schema.json",
            layer,
        );
    }

    let feature_schema = read_schema(&root, "schemas/v3-2-6/lifecycle-feature.schema.json");
    assert_schema_text_contains(
        &feature_schema,
        "schemas/v3-2-6/lifecycle-feature.schema.json",
        "manual_drop_prevention_without_drop_guard",
    );
    assert_schema_text_contains(
        &feature_schema,
        "schemas/v3-2-6/lifecycle-feature.schema.json",
        "has_returned_borrow_relation",
    );
    assert_schema_text_contains(
        &feature_schema,
        "schemas/v3-2-6/lifecycle-feature.schema.json",
        "has_unconstrained_return_lifetime",
    );
    assert_schema_text_contains(
        &feature_schema,
        "schemas/v3-2-6/lifecycle-feature.schema.json",
        "has_persisted_returned_borrow",
    );
    assert_schema_text_contains(
        &feature_schema,
        "schemas/v3-2-6/lifecycle-feature.schema.json",
        "returned_borrow_persistence_before_invalidation",
    );
    assert_schema_text_contains(
        &feature_schema,
        "schemas/v3-2-6/lifecycle-feature.schema.json",
        "returned_borrow_persistence_after_invalidation",
    );
    assert_schema_text_contains(
        &feature_schema,
        "schemas/v3-2-6/lifecycle-feature.schema.json",
        "has_external_buffer_binding",
    );
    assert_schema_text_contains(
        &feature_schema,
        "schemas/v3-2-6/lifecycle-feature.schema.json",
        "has_external_buffer_lifetime_bound",
    );

    let ranked_schema = read_schema(&root, "schemas/v3-2-6/ranked-candidate-v2.schema.json");
    assert_schema_text_contains(
        &ranked_schema,
        "schemas/v3-2-6/ranked-candidate-v2.schema.json",
        "manual_drop_prevention_without_drop_guard",
    );
    assert_schema_text_contains(
        &ranked_schema,
        "schemas/v3-2-6/ranked-candidate-v2.schema.json",
        "has_returned_borrow_relation",
    );
    assert_schema_text_contains(
        &ranked_schema,
        "schemas/v3-2-6/ranked-candidate-v2.schema.json",
        "has_unconstrained_return_lifetime",
    );
    assert_schema_text_contains(
        &ranked_schema,
        "schemas/v3-2-6/ranked-candidate-v2.schema.json",
        "has_persisted_returned_borrow",
    );
    assert_schema_text_contains(
        &ranked_schema,
        "schemas/v3-2-6/ranked-candidate-v2.schema.json",
        "returned_borrow_persistence_before_invalidation",
    );
    assert_schema_text_contains(
        &ranked_schema,
        "schemas/v3-2-6/ranked-candidate-v2.schema.json",
        "returned_borrow_persistence_after_invalidation",
    );
    assert_schema_text_contains(
        &ranked_schema,
        "schemas/v3-2-6/ranked-candidate-v2.schema.json",
        "has_external_buffer_binding",
    );
    assert_schema_text_contains(
        &ranked_schema,
        "schemas/v3-2-6/ranked-candidate-v2.schema.json",
        "has_external_buffer_lifetime_bound",
    );
    assert_schema_text_contains(
        &ranked_schema,
        "schemas/v3-2-6/ranked-candidate-v2.schema.json",
        "chain_summary",
    );
    assert_schema_text_contains(
        &ranked_schema,
        "schemas/v3-2-6/ranked-candidate-v2.schema.json",
        "recommended_witness_route",
    );
    assert_schema_text_contains(
        &ranked_schema,
        "schemas/v3-2-6/ranked-candidate-v2.schema.json",
        "returned_view_miri",
    );
    for summary_field in [
        "identity_transport_chain_count",
        "lifecycle_ordering_chain_count",
        "complete_risk_chain_count",
    ] {
        assert_schema_text_contains(
            &ranked_schema,
            "schemas/v3-2-6/ranked-candidate-v2.schema.json",
            summary_field,
        );
    }

    let fact_schema = read_schema(&root, "schemas/v3-2-6/lifecycle-fact.schema.json");
    assert_schema_enum_contains(&fact_schema, "fact_kind", "returned_borrow_relation");
    assert_schema_enum_contains(&fact_schema, "fact_kind", "persisted_returned_borrow");
    assert_schema_enum_contains(
        &fact_schema,
        "fact_kind",
        "returned_borrow_invalidation_order",
    );
    assert_schema_enum_contains(&fact_schema, "fact_kind", "external_buffer_binding");
    assert_schema_enum_contains(&fact_schema, "fact_kind", "atomic_ordering");
    assert_schema_enum_contains(&fact_schema, "fact_kind", "object_binding_gap");
    assert_schema_enum_contains(&fact_schema, "fact_kind", "object_flow");
    assert!(
        !fact_schema.to_string().contains("contract_retention"),
        "public lifecycle fact schema must not expose contract_retention"
    );

    let witness_schema = read_schema(&root, "schemas/v3-2-6/witness-plan.schema.json");
    for action_kind in [
        "persist_returned_view",
        "invalidate_owner",
        "use_returned_view",
        "run_miri_check",
    ] {
        assert_schema_text_contains(
            &witness_schema,
            "schemas/v3-2-6/witness-plan.schema.json",
            action_kind,
        );
    }

    let corpus_schema = read_schema(&root, "schemas/v3-2/corpus-manifest.schema.json");
    for reason in [
        "pure_rust",
        "iterator_api_candidate",
        "container_lifecycle_surface",
        "wrapper_api_candidate",
        "destructure_lifecycle_surface",
        "allocator_api_candidate",
        "iterator_lifetime_surface",
        "concurrent_cell_surface",
        "conversion_api_candidate",
        "slice_view_surface",
    ] {
        assert_schema_text_contains(
            &corpus_schema,
            "schemas/v3-2/corpus-manifest.schema.json",
            reason,
        );
    }

    let freeze_schema = read_schema(&root, "schemas/v3-3/scanner-freeze.schema.json");
    assert_schema_text_contains(
        &freeze_schema,
        "schemas/v3-3/scanner-freeze.schema.json",
        "v3.3.scanner_freeze.1",
    );
    assert_schema_text_contains(
        &freeze_schema,
        "schemas/v3-3/scanner-freeze.schema.json",
        "ranked_candidates_sha256",
    );
}

fn scanner_freeze_fixture() -> String {
    r#"{
        "schema_version":"v3.3.scanner_freeze.1",
        "run_id":"v3-3-sealed-r2-test",
        "frozen_at_utc":"2026-07-24T08:00:00Z",
        "method":{
            "commit":"0123456789abcdef0123456789abcdef01234567",
            "branch":"docs-v3-1-nday-gate",
            "worktree_required_clean":true
        },
        "inputs":{
            "corpus_manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "anonymous_pairs_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "feature_profile_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "source_checksums_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "contract_toml_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "api_map_sha256":{"rusqlite":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
        },
        "toolchain":{
            "cargo_build_locked_for_method":true,
            "scanner_build_precheck_locked":true,
            "static_facts_rustup_toolchain":"nightly-2026-07-08",
            "static_facts_dyld_library_path":"/toolchain/lib",
            "stable_rustc":"rustc 1.97.0"
        },
        "source_identity_scan":{
            "scanner_metadata_forbidden_tokens":"pass",
            "source_tree_strong_identity_tokens_zero":true,
            "generic_source_token_counts":{"expected":0,"fixed":0,"patch":0}
        },
        "outputs":{
            "buildability_sha256":"1111111111111111111111111111111111111111111111111111111111111111",
            "boundary_index_sha256":"2222222222222222222222222222222222222222222222222222222222222222",
            "static_facts_sha256":"3333333333333333333333333333333333333333333333333333333333333333",
            "mir_coverage_sha256":"4444444444444444444444444444444444444444444444444444444444444444",
            "candidates_sha256":"5555555555555555555555555555555555555555555555555555555555555555",
            "contracts_sha256":"6666666666666666666666666666666666666666666666666666666666666666",
            "lifecycle_evidence_sha256":"7777777777777777777777777777777777777777777777777777777777777777",
            "lifecycle_facts_sha256":"8888888888888888888888888888888888888888888888888888888888888888",
            "lifecycle_coverage_sha256":"9999999999999999999999999999999999999999999999999999999999999999",
            "lifecycle_features_sha256":"abababababababababababababababababababababababababababababababab",
            "ranked_candidates_sha256":"babababababababababababababababababababababababababababababababa"
        },
        "notes":["candidate/ranking is not a vulnerability conclusion"]
    }"#
    .to_owned()
}

fn read_schema(root: &std::path::Path, path: &str) -> serde_json::Value {
    let text = std::fs::read_to_string(root.join(path)).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn assert_schema_text_contains(schema: &serde_json::Value, path: &str, needle: &str) {
    assert!(
        schema.to_string().contains(needle),
        "{path} should contain {needle}"
    );
}

fn assert_schema_enum_contains(schema: &serde_json::Value, property: &str, needle: &str) {
    let values = schema
        .get("properties")
        .and_then(|properties| properties.get(property))
        .and_then(|property| property.get("enum"))
        .and_then(|enum_values| enum_values.as_array())
        .unwrap_or_else(|| panic!("{property} enum should exist"));
    assert!(
        values.iter().any(|value| value.as_str() == Some(needle)),
        "{property} enum should contain {needle}"
    );
}
