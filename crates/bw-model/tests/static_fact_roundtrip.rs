use bw_model::{
    AtomicOperationKind, AtomicOrderingFact, AtomicOrderingKind, BuildId, CallbackCaptureFact,
    CallbackReleaseUseOrderFact, CallbackReleaseUseOrdering, CaptureMode, ObjectBindingGapFact,
    ObjectBindingGapKind, ObjectFlowFact, ObjectFlowKind, ObjectFlowObjectKind, RecordId,
    ReturnedBorrowInvalidationOrderFact, ReturnedBorrowInvalidationOrdering, STATIC_SCHEMA_V01,
    STATIC_SCHEMA_V02, SemanticSiteKey, SiteId, StaticArtifactIdentity, StaticFact,
    StaticFactEnvelope, StaticSourceRef,
};

fn callback_capture() -> StaticFactEnvelope {
    StaticFactEnvelope {
        schema_version: STATIC_SCHEMA_V01.to_owned(),
        record_id: RecordId("fact:capture-1".to_owned()),
        producer: "bw-rustc@test-commit".to_owned(),
        build_id: BuildId("build:test".to_owned()),
        artifact: None,
        source_ref: None,
        payload: StaticFact::CallbackCapture(CallbackCaptureFact {
            site_id: SiteId("site:capture".to_owned()),
            semantic_site_key: SemanticSiteKey("semantic:capture".to_owned()),
            callback_site_id: SiteId("site:callback".to_owned()),
            object_site_id: SiteId("site:object".to_owned()),
            capture_ordinal: 0,
            capture_mode: CaptureMode::Borrowed,
        }),
    }
}

#[test]
fn callback_capture_roundtrips() {
    let fact = callback_capture();
    let json = serde_json::to_string(&fact).expect("static fact should serialize");

    assert_eq!(
        serde_json::from_str::<StaticFactEnvelope>(&json).expect("static fact should deserialize"),
        fact
    );
    assert_eq!(
        StaticFactEnvelope::from_json_str(&json).expect("known schema should be accepted"),
        fact
    );
    assert!(
        !fact.is_authoritative_lifecycle_binding(),
        "v0.1 facts must never be treated as authoritative lifecycle bindings"
    );
}

#[test]
fn complete_v02_fact_roundtrips_and_is_authoritative_for_lifecycle_binding() {
    let mut fact = callback_capture();
    fact.schema_version = STATIC_SCHEMA_V02.to_owned();
    fact.artifact = Some(StaticArtifactIdentity {
        crate_id: "crate:alpha".to_owned(),
        package_name: "alpha".to_owned(),
        package_version: "1.2.3".to_owned(),
        target: "x86_64-unknown-linux-gnu".to_owned(),
    });
    fact.source_ref = Some(StaticSourceRef {
        path: "src/lib.rs".to_owned(),
        line_start: 12,
        line_end: 15,
        symbol_path: Some("alpha::register".to_owned()),
    });

    let json = serde_json::to_string(&fact).expect("v0.2 static fact should serialize");
    let decoded = StaticFactEnvelope::from_json_str(&json)
        .expect("complete v0.2 static fact should deserialize");

    assert_eq!(decoded, fact);
    assert!(decoded.is_authoritative_lifecycle_binding());
}

#[test]
fn returned_borrow_invalidation_order_roundtrips_as_authoritative_static_fact() {
    let fact = StaticFactEnvelope {
        schema_version: STATIC_SCHEMA_V02.to_owned(),
        record_id: RecordId("fact:returned-borrow-order".to_owned()),
        producer: "bw-rustc@test-commit".to_owned(),
        build_id: BuildId("build:test".to_owned()),
        artifact: Some(StaticArtifactIdentity {
            crate_id: "crate:alpha".to_owned(),
            package_name: "alpha".to_owned(),
            package_version: "1.2.3".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(StaticSourceRef {
            path: "src/statement_iterator.rs".to_owned(),
            line_start: 24,
            line_end: 24,
            symbol_path: Some("alpha::NamedStatementIterator::next".to_owned()),
        }),
        payload: StaticFact::ReturnedBorrowInvalidationOrder(ReturnedBorrowInvalidationOrderFact {
            site_id: SiteId("site:order".to_owned()),
            semantic_site_key: SemanticSiteKey("semantic:order".to_owned()),
            persisted_site_id: SiteId("site:persisted".to_owned()),
            invalidation_site_id: SiteId("site:invalidation".to_owned()),
            use_site_id: SiteId("site:use".to_owned()),
            api_id: "alpha::Statement::field_name".to_owned(),
            invalidation_api_id: "alpha::StatementUse::step".to_owned(),
            ordering: ReturnedBorrowInvalidationOrdering::PersistenceBeforeInvalidationUse,
        }),
    };

    let json = serde_json::to_string(&fact).expect("ordering fact should serialize");
    let decoded = StaticFactEnvelope::from_json_str(&json)
        .expect("ordering fact should deserialize through schema gate");

    assert_eq!(decoded, fact);
    assert!(decoded.is_authoritative_lifecycle_binding());
}

#[test]
fn callback_release_use_order_roundtrips_as_authoritative_static_fact() {
    let fact = StaticFactEnvelope {
        schema_version: STATIC_SCHEMA_V02.to_owned(),
        record_id: RecordId("fact:callback-release-use-order".to_owned()),
        producer: "bw-rustc@test-commit".to_owned(),
        build_id: BuildId("build:test".to_owned()),
        artifact: Some(StaticArtifactIdentity {
            crate_id: "crate:alpha".to_owned(),
            package_name: "alpha".to_owned(),
            package_version: "1.2.3".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(StaticSourceRef {
            path: "src/callback.rs".to_owned(),
            line_start: 38,
            line_end: 38,
            symbol_path: Some("alpha::stream_callback".to_owned()),
        }),
        payload: StaticFact::CallbackReleaseUseOrder(CallbackReleaseUseOrderFact {
            site_id: SiteId("site:callback-release-use-order".to_owned()),
            semantic_site_key: SemanticSiteKey("semantic:callback-release-use-order".to_owned()),
            registration_site_id: SiteId("site:register".to_owned()),
            release_site_id: SiteId("site:release".to_owned()),
            use_site_id: SiteId("site:callback-use".to_owned()),
            object_site_id: SiteId("site:userdata".to_owned()),
            api_id: "api:alpha:register".to_owned(),
            ordering: CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
        }),
    };

    let json = serde_json::to_string(&fact).expect("callback release/use order should serialize");
    let decoded = StaticFactEnvelope::from_json_str(&json)
        .expect("callback release/use order should deserialize through schema gate");

    assert_eq!(decoded, fact);
    assert!(decoded.is_authoritative_lifecycle_binding());
}

#[test]
fn atomic_ordering_roundtrips_as_authoritative_static_fact() {
    let fact = StaticFactEnvelope {
        schema_version: STATIC_SCHEMA_V02.to_owned(),
        record_id: RecordId("fact:atomic-ordering".to_owned()),
        producer: "bw-rustc@test-commit".to_owned(),
        build_id: BuildId("build:test".to_owned()),
        artifact: Some(StaticArtifactIdentity {
            crate_id: "crate:alpha".to_owned(),
            package_name: "alpha".to_owned(),
            package_version: "1.2.3".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(StaticSourceRef {
            path: "src/raw_iter.rs".to_owned(),
            line_start: 42,
            line_end: 42,
            symbol_path: Some("alpha::RawIter::<T>::next".to_owned()),
        }),
        payload: StaticFact::AtomicOrdering(AtomicOrderingFact {
            site_id: SiteId("site:atomic:load".to_owned()),
            semantic_site_key: SemanticSiteKey("semantic:atomic:load".to_owned()),
            api_id: "alpha::RawIter::<T>::next".to_owned(),
            operation: AtomicOperationKind::Load,
            ordering: AtomicOrderingKind::Relaxed,
            target_type_name: "core::sync::atomic::AtomicPtr<Node<T>>".to_owned(),
        }),
    };

    let json = serde_json::to_string(&fact).expect("atomic ordering fact should serialize");
    let decoded = StaticFactEnvelope::from_json_str(&json)
        .expect("atomic ordering fact should deserialize through schema gate");

    assert_eq!(decoded, fact);
    assert!(decoded.is_authoritative_lifecycle_binding());
}

#[test]
fn object_binding_gap_roundtrips_as_authoritative_static_fact() {
    let fact = StaticFactEnvelope {
        schema_version: STATIC_SCHEMA_V02.to_owned(),
        record_id: RecordId("fact:object-binding-gap".to_owned()),
        producer: "bw-rustc@test-commit".to_owned(),
        build_id: BuildId("build:test".to_owned()),
        artifact: Some(StaticArtifactIdentity {
            crate_id: "crate:alpha".to_owned(),
            package_name: "alpha".to_owned(),
            package_version: "1.2.3".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(StaticSourceRef {
            path: "src/iter.rs".to_owned(),
            line_start: 44,
            line_end: 44,
            symbol_path: Some("alpha::IterHolder::next".to_owned()),
        }),
        payload: StaticFact::ObjectBindingGap(ObjectBindingGapFact {
            site_id: SiteId("site:gap:chain".to_owned()),
            semantic_site_key: SemanticSiteKey("semantic:gap:chain".to_owned()),
            api_id: "alpha::IterHolder::next".to_owned(),
            gap_kind: ObjectBindingGapKind::MergedSources,
            field_path: Some("field:slot".to_owned()),
            container_type_name: None,
            adapter: Some("chain".to_owned()),
        }),
    };

    let json = serde_json::to_string(&fact).expect("object binding gap fact should serialize");
    let decoded = StaticFactEnvelope::from_json_str(&json)
        .expect("object binding gap fact should deserialize through schema gate");

    assert_eq!(decoded, fact);
    assert!(decoded.is_authoritative_lifecycle_binding());
}

#[test]
fn object_flow_roundtrips_as_authoritative_static_fact() {
    let fact = StaticFactEnvelope {
        schema_version: STATIC_SCHEMA_V02.to_owned(),
        record_id: RecordId("fact:object-flow".to_owned()),
        producer: "bw-rustc@test-commit".to_owned(),
        build_id: BuildId("build:test".to_owned()),
        artifact: Some(StaticArtifactIdentity {
            crate_id: "crate:alpha".to_owned(),
            package_name: "alpha".to_owned(),
            package_version: "1.2.3".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(StaticSourceRef {
            path: "src/lib.rs".to_owned(),
            line_start: 64,
            line_end: 64,
            symbol_path: Some("alpha::Registry::install".to_owned()),
        }),
        payload: StaticFact::ObjectFlow(ObjectFlowFact {
            site_id: SiteId("site:flow:field-store".to_owned()),
            semantic_site_key: SemanticSiteKey("semantic:flow:field-store".to_owned()),
            from_site_id: SiteId("site:userdata".to_owned()),
            from_object_kind: ObjectFlowObjectKind::UserData,
            to_site_id: SiteId("site:storage".to_owned()),
            to_object_kind: ObjectFlowObjectKind::Storage,
            flow_kind: ObjectFlowKind::FieldStore,
            api_id: "alpha::Registry::install".to_owned(),
            field_path: Some("Registry::slot".to_owned()),
            container_type_name: None,
        }),
    };

    let json = serde_json::to_string(&fact).expect("object flow fact should serialize");
    let decoded = StaticFactEnvelope::from_json_str(&json)
        .expect("object flow fact should deserialize through schema gate");

    assert_eq!(decoded, fact);
    assert!(decoded.is_authoritative_lifecycle_binding());
}

#[test]
fn incomplete_or_invalid_v02_fact_is_not_authoritative_for_lifecycle_binding() {
    let mut fact = callback_capture();
    fact.schema_version = STATIC_SCHEMA_V02.to_owned();
    assert!(!fact.is_authoritative_lifecycle_binding());

    fact.artifact = Some(StaticArtifactIdentity {
        crate_id: "crate:alpha".to_owned(),
        package_name: "alpha".to_owned(),
        package_version: "1.2.3".to_owned(),
        target: "x86_64-unknown-linux-gnu".to_owned(),
    });
    assert!(!fact.is_authoritative_lifecycle_binding());

    fact.source_ref = Some(StaticSourceRef {
        path: "src/lib.rs".to_owned(),
        line_start: 0,
        line_end: 15,
        symbol_path: None,
    });
    assert!(!fact.is_authoritative_lifecycle_binding());

    fact.source_ref.as_mut().expect("source ref set").line_start = 16;
    assert!(!fact.is_authoritative_lifecycle_binding());

    let source_ref = fact.source_ref.as_mut().expect("source ref set");
    source_ref.line_start = 15;
    source_ref.line_end = 15;
    assert!(fact.is_authoritative_lifecycle_binding());

    let StaticFact::CallbackCapture(capture) = &mut fact.payload else {
        panic!("fixture must carry a callback capture");
    };
    capture.semantic_site_key = SemanticSiteKey(" ".to_owned());
    assert!(!fact.is_authoritative_lifecycle_binding());
}

#[test]
fn unknown_static_schema_is_rejected() {
    let json = r#"{"schema_version":"bw.static/9.0"}"#;
    let error = StaticFactEnvelope::from_json_str(json).expect_err("unknown schema must fail");

    assert!(error.to_string().contains("bw.static/9.0"));
    assert_eq!(error.code(), "BW-SCHEMA-UNSUPPORTED");
}

#[test]
fn direct_deserialization_cannot_bypass_schema_check() {
    let json = serde_json::to_string(&callback_capture())
        .expect("static fact should serialize")
        .replace(STATIC_SCHEMA_V01, "bw.static/9.0");

    let error = serde_json::from_str::<StaticFactEnvelope>(&json)
        .expect_err("serde must reject an unknown schema");
    assert!(error.to_string().contains("bw.static/9.0"));
}

#[test]
fn unknown_callback_release_use_ordering_roundtrips_with_its_own_token() {
    let fact = StaticFactEnvelope {
        schema_version: STATIC_SCHEMA_V02.to_owned(),
        record_id: RecordId("fact:callback-release-use-order-unknown".to_owned()),
        producer: "bw-rustc@test-commit".to_owned(),
        build_id: BuildId("build:test".to_owned()),
        artifact: Some(StaticArtifactIdentity {
            crate_id: "crate:alpha".to_owned(),
            package_name: "alpha".to_owned(),
            package_version: "1.2.3".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(StaticSourceRef {
            path: "src/callback.rs".to_owned(),
            line_start: 51,
            line_end: 51,
            symbol_path: Some("alpha::looping_callback".to_owned()),
        }),
        payload: StaticFact::CallbackReleaseUseOrder(CallbackReleaseUseOrderFact {
            site_id: SiteId("site:callback-release-use-order-unknown".to_owned()),
            semantic_site_key: SemanticSiteKey(
                "semantic:callback-release-use-order-unknown".to_owned(),
            ),
            registration_site_id: SiteId("site:register".to_owned()),
            release_site_id: SiteId("site:release".to_owned()),
            use_site_id: SiteId("site:callback-use".to_owned()),
            object_site_id: SiteId("site:userdata".to_owned()),
            api_id: "api:alpha:register".to_owned(),
            ordering: CallbackReleaseUseOrdering::UnknownOrdering,
        }),
    };

    let json = serde_json::to_string(&fact).expect("unknown ordering should serialize");
    assert!(
        json.contains("\"ordering\":\"unknown_ordering\""),
        "unknown ordering must serialize under its own token, not silently alias a proven one: {json}"
    );

    let decoded = StaticFactEnvelope::from_json_str(&json)
        .expect("unknown ordering should deserialize through schema gate");
    assert_eq!(decoded, fact);
    assert!(
        decoded.is_authoritative_lifecycle_binding(),
        "an unproven ordering is still an authoritative binding record; only its ordering is unproven"
    );
}
