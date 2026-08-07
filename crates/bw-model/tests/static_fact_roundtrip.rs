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

#[test]
fn call_boundary_object_binding_gap_roundtrips_with_its_own_token() {
    let fact = StaticFactEnvelope {
        schema_version: STATIC_SCHEMA_V02.to_owned(),
        record_id: RecordId("fact:object-binding-gap-call-boundary".to_owned()),
        producer: "bw-rustc@test-commit".to_owned(),
        build_id: BuildId("build:test".to_owned()),
        artifact: Some(StaticArtifactIdentity {
            crate_id: "crate:alpha".to_owned(),
            package_name: "alpha".to_owned(),
            package_version: "1.2.3".to_owned(),
            target: "lib".to_owned(),
        }),
        source_ref: Some(StaticSourceRef {
            path: "src/register.rs".to_owned(),
            line_start: 12,
            line_end: 12,
            symbol_path: Some("alpha::register_through_helper".to_owned()),
        }),
        payload: StaticFact::ObjectBindingGap(ObjectBindingGapFact {
            site_id: SiteId("site:object-binding-gap-call-boundary".to_owned()),
            semantic_site_key: SemanticSiteKey("semantic:call-boundary".to_owned()),
            api_id: "alpha::register_through_helper".to_owned(),
            gap_kind: ObjectBindingGapKind::CallBoundary,
            field_path: None,
            container_type_name: None,
            adapter: Some("api:alpha:register".to_owned()),
        }),
    };

    let json = serde_json::to_string(&fact).expect("call boundary gap should serialize");
    assert!(
        json.contains("\"gap_kind\":\"call_boundary\""),
        "the call boundary gap needs its own token so coverage gaps stay countable: {json}"
    );

    let decoded = StaticFactEnvelope::from_json_str(&json)
        .expect("call boundary gap should deserialize through schema gate");
    assert_eq!(decoded, fact);
}

// ---------------------------------------------------------------------------
// wire token 登记表（执行计划阶段 4.2 / codebase-realignment 的 D2）
// ---------------------------------------------------------------------------

/// 每个 [`StaticFact`] 变体在产物里的 `kind` 取值。
///
/// # 这个 match 不许写通配分支
///
/// wire token 是**协议身份**：产物里写什么、消费方认什么，全靠它。新增一个事实种类时
/// 这个 match 编不过，作者被迫回答「这条事实在产物里叫什么」。
///
/// **这个机制已经生效过。** 阶段 4 新增 `ForeignSymbolBinding` 时，模型层与两个消费方
/// 一共六处穷尽匹配同时报错；靠人逐条检查一定会漏，D2 的纪律说的就是这件事。
fn wire_token(fact: &StaticFact) -> &'static str {
    match fact {
        StaticFact::ObjectSite(_) => "object_site",
        StaticFact::CallbackSite(_) => "callback_site",
        StaticFact::CallbackCapture(_) => "callback_capture",
        StaticFact::DropSite(_) => "drop_site",
        StaticFact::DropPrevention(_) => "drop_prevention",
        StaticFact::CallbackUserDataReconstruction(_) => "callback_user_data_reconstruction",
        StaticFact::RegistrationSite(_) => "registration_site",
        StaticFact::RawPointerTransfer(_) => "raw_pointer_transfer",
        StaticFact::ReleasePathProof(_) => "release_path_proof",
        StaticFact::CallbackReleaseUseOrder(_) => "callback_release_use_order",
        StaticFact::ExternalCallSite(_) => "external_call_site",
        StaticFact::CallbackLifetimeBound(_) => "callback_lifetime_bound",
        StaticFact::RegistrationGuard(_) => "registration_guard",
        StaticFact::AllocationOwnership(_) => "allocation_ownership",
        StaticFact::SafeEntryLineage(_) => "safe_entry_lineage",
        StaticFact::ForeignSymbolBinding(_) => "foreign_symbol_binding",
        StaticFact::ReturnedBorrowRelation(_) => "returned_borrow_relation",
        StaticFact::PersistedReturnedBorrow(_) => "persisted_returned_borrow",
        StaticFact::ReturnedBorrowInvalidationOrder(_) => "returned_borrow_invalidation_order",
        StaticFact::ExternalBufferBinding(_) => "external_buffer_binding",
        StaticFact::AtomicOrdering(_) => "atomic_ordering",
        StaticFact::ObjectBindingGap(_) => "object_binding_gap",
        StaticFact::ObjectFlow(_) => "object_flow",
    }
}

/// 序列化出来的 `kind` 必须与登记表一致。
///
/// 光有上面那个 match 只保证「有人登记过」，不保证登记的名字与 serde 实际写出的一致。
/// 两者对不上时，产物里的 token 会跟着 `rename_all` 悄悄变，而登记表纹丝不动。
#[test]
fn the_serialised_kind_matches_the_registered_wire_token() {
    let samples = [
        callback_capture().payload,
        StaticFact::ForeignSymbolBinding(bw_model::ForeignSymbolBindingFact {
            site_id: SiteId("site:binding".to_owned()),
            semantic_site_key: SemanticSiteKey("semantic:binding".to_owned()),
            api_id: "demo::register".to_owned(),
            callback_param: "F".to_owned(),
            symbol: Some("demo_register".to_owned()),
            callback_arg_index: Some(0),
            userdata_arg_index: Some(1),
            resolution: bw_model::ForeignSymbolResolution::ExternItemName,
        }),
    ];
    for fact in samples {
        let value = serde_json::to_value(&fact).expect("fact should serialize");
        assert_eq!(
            value["kind"].as_str(),
            Some(wire_token(&fact)),
            "serde 写出的 kind 与登记表不一致：{fact:?}"
        );
    }
}

/// 符号解析成功与失败的两种形状都必须能原样往返。
///
/// **失败形状不许带半个符号。** 模型层的 `has_required_identifiers` 会拒绝
/// `resolution` 说没解析出来、`symbol` 却有值的记录——半个符号比没有更糟，下游会拿它
/// 去联结。
#[test]
fn foreign_symbol_binding_roundtrips_in_both_shapes() {
    for (symbol, callback_arg_index, resolution) in [
        (
            Some("demo_register".to_owned()),
            Some(0),
            bw_model::ForeignSymbolResolution::ExternItemName,
        ),
        (
            None,
            None,
            bw_model::ForeignSymbolResolution::AmbiguousForeignCalls,
        ),
    ] {
        let envelope = StaticFactEnvelope {
            schema_version: STATIC_SCHEMA_V02.to_owned(),
            record_id: RecordId("fact:binding-1".to_owned()),
            producer: "bw-rustc@test-commit".to_owned(),
            build_id: BuildId("build:test".to_owned()),
            artifact: None,
            source_ref: None,
            payload: StaticFact::ForeignSymbolBinding(bw_model::ForeignSymbolBindingFact {
                site_id: SiteId("site:binding".to_owned()),
                semantic_site_key: SemanticSiteKey("semantic:binding".to_owned()),
                api_id: "demo::register".to_owned(),
                callback_param: "F".to_owned(),
                symbol,
                callback_arg_index,
                userdata_arg_index: None,
                resolution,
            }),
        };
        let json = serde_json::to_string(&envelope).expect("envelope should serialize");
        assert_eq!(
            StaticFactEnvelope::from_json_str(&json).expect("envelope should parse"),
            envelope
        );
    }
}
