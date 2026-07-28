use std::{collections::BTreeSet, fs, process::Command};

use bw_model::{
    DropKind, ExternalCallRole, ObjectBindingGapKind, RawPointerTransferKind, RegistrationRole,
    SiteId, StaticFact, StaticFactEnvelope,
};
use sha2::{Digest, Sha256};

const COLLECTION_LOOKUP_CONTRACT_REGISTRY_SCHEMA_V01: &str =
    "bw-rustc.collection_lookup_contract_registry.0.1";
const COLLECTION_LOOKUP_CONTRACT_REGISTRY_MANIFEST_SCHEMA_V01: &str =
    "bw-rustc.collection_lookup_contract_registry_manifest.0.1";

#[test]
fn callback_site_fixture_emits_mir_site_facts() {
    let repo = repo_root();
    let fixture = repo.join("benchmarks/compiler-fixtures/callback-sites/Cargo.toml");
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let analysis_dir = temp.path().join("analysis");
    let target_dir = temp.path().join("target");
    fs::create_dir(&analysis_dir).expect("analysis dir should be created");
    let config = temp.path().join("bw-rustc-config.json");
    fs::write(
        &config,
        serde_json::json!({
            "output_dir": analysis_dir,
            "allowlist": [
                { "crate_name": "rusqlite", "target": "lib" }
            ]
        })
        .to_string(),
    )
    .expect("config should be written");

    let status = Command::new("cargo")
        .args(["check", "--manifest-path"])
        .arg(&fixture)
        .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_bw-rustc"))
        .env("BW_RUSTC_CONFIG", &config)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status()
        .expect("cargo check should run");
    assert!(status.success(), "fixture cargo check failed: {status}");

    let facts = read_static_facts(&analysis_dir.join("static-facts.jsonl"));
    let facts_text = fs::read_to_string(analysis_dir.join("static-facts.jsonl"))
        .expect("static facts should be readable as text");
    assert!(
        facts
            .iter()
            .all(StaticFactEnvelope::is_authoritative_lifecycle_binding),
        "compiler-produced facts must carry v0.2 artifact identity and source anchors"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact.payload,
            StaticFact::DropSite(ref drop) if drop.drop_kind == DropKind::Explicit
        )),
        "explicit drop site should be extracted"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact.payload,
            StaticFact::DropSite(ref drop) if drop.drop_kind == DropKind::ScopeEnd
        )),
        "scope-end drop site should be extracted"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact.payload,
            StaticFact::RegistrationSite(ref registration)
                if registration.role == RegistrationRole::Register
                    && registration.api_id == "api:rusqlite:update_hook:register"
        )),
        "update_hook registration should be classified"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:update_hook:register"
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("update_hook_registration_site"))
        )),
        "registration source anchors must identify the enclosing MIR function"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact.payload,
            StaticFact::RegistrationSite(ref registration)
                if registration.role == RegistrationRole::Register
                    && registration.api_id == "api:rusqlite:create_scalar_function:register"
        )),
        "create_scalar_function registration should be classified"
    );
    let foreign_destructor_user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::IntoRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("foreign_destructor_release_registration_site")
                }) =>
            {
                Some(transfer.user_data_site_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !foreign_destructor_user_data_site_ids.is_empty(),
        "foreign destructor fixture must emit a source-scoped into_raw user-data identity"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:create_scalar_function:register"
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("foreign_destructor_release_registration_site")
                })
                && registration
                    .user_data_site_id
                    .as_ref()
                    .is_some_and(|site_id| foreign_destructor_user_data_site_ids.contains(site_id))
        )),
        "foreign destructor registration must bind exact user-data"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::FromRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("foreign_destructor_release_registration_site")
                })
                && foreign_destructor_user_data_site_ids.contains(&transfer.user_data_site_id)
        )),
        "foreign destructor release proof must bind registration user-data to destructor release endpoint"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref.symbol_path.as_deref().is_some_and(|path| {
                path.ends_with("foreign_destructor_release_registration_site")
            })
                && foreign_destructor_user_data_site_ids.contains(&proof.object_site_id)
        )),
        "foreign destructor release proof must emit a release path proof for the registered object"
    );
    let missing_destructor_user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:create_scalar_function:register"
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("foreign_destructor_missing_registration_site")
                }) =>
            {
                registration.user_data_site_id.clone()
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !missing_destructor_user_data_site_ids.is_empty(),
        "missing-destructor fixture must still classify the registration"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if missing_destructor_user_data_site_ids.contains(&proof.object_site_id)
        )),
        "a None destructor must not emit a release path proof"
    );
    let different_source_destructor_user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:create_scalar_function:register"
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("foreign_destructor_different_source_registration_site")
                }) =>
            {
                registration.user_data_site_id.clone()
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !different_source_destructor_user_data_site_ids.is_empty(),
        "different-source destructor fixture must still classify the registration"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if different_source_destructor_user_data_site_ids.contains(&proof.object_site_id)
        )),
        "a destructor that releases a different source must not emit a release path proof"
    );
    let pyo3_capsule_user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::IntoRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("pyo3_capsule_release_registration_site")
                }) =>
            {
                Some(transfer.user_data_site_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !pyo3_capsule_user_data_site_ids.is_empty(),
        "PyCapsule fixture must emit a source-scoped into_raw user-data identity"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:pyo3:pycapsule_new:register"
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("pyo3_capsule_release_registration_site")
                })
                && registration
                    .user_data_site_id
                    .as_ref()
                    .is_some_and(|site_id| pyo3_capsule_user_data_site_ids.contains(site_id))
        )),
        "PyCapsule_New registration must bind exact capsule user-data"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::FromRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("pyo3_capsule_release_registration_site")
                })
                && pyo3_capsule_user_data_site_ids.contains(&transfer.user_data_site_id)
        )),
        "PyCapsule destructor release must bind GetPointer result back to registration user-data"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref.symbol_path.as_deref().is_some_and(|path| {
                path.ends_with("pyo3_capsule_release_registration_site")
            })
                && pyo3_capsule_user_data_site_ids.contains(&proof.object_site_id)
        )),
        "PyCapsule_New with destructor must emit a release path proof for the registered object"
    );
    let previous_hook_registered_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:update_hook:register"
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("previous_hook_release_registration_site")
                }) =>
            {
                registration.user_data_site_id.clone()
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !previous_hook_registered_site_ids.is_empty(),
        "previous-hook fixture must still classify the registering FFI call"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::FromRaw
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("previous_hook_release_registration_site"))
                && !previous_hook_registered_site_ids.contains(&transfer.user_data_site_id)
        )),
        "a stored free function call must emit a FromRaw fact for the returned previous hook object"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref
                .symbol_path
                .as_deref()
                .is_some_and(|path| path.ends_with("previous_hook_release_registration_site"))
                && previous_hook_registered_site_ids.contains(&proof.object_site_id)
        )),
        "releasing the returned previous hook must not be reported as coverage for the newly registered object"
    );
    let non_releasing_previous_hook_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:update_hook:register"
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("previous_hook_non_releasing_free_registration_site")
                }) =>
            {
                registration.user_data_site_id.clone()
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !non_releasing_previous_hook_site_ids.is_empty(),
        "non-releasing previous-hook fixture must still classify the registering FFI call"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::FromRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("previous_hook_non_releasing_free_registration_site")
                })
        )),
        "a stored free function without a raw-pointer release endpoint must not emit FromRaw"
    );
    let field_state_update_site_ids = registration_user_data_site_ids(
        &facts,
        "HookFieldState::install_update_hook",
        "api:rusqlite:update_hook:register",
    );
    assert!(
        !field_state_update_site_ids.is_empty(),
        "field-state update hook fixture must classify the registering FFI call"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "HookFieldState::install_update_hook",
            &field_state_update_site_ids,
        ),
        "same-field hook state-machine proof must emit a FromRaw fact for the registered object"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "HookFieldState::install_update_hook",
            &field_state_update_site_ids,
        ),
        "same-field hook state-machine proof must cover the registered object"
    );
    let wrong_field_update_site_ids = registration_user_data_site_ids(
        &facts,
        "HookFieldState::install_update_hook_wrong_field",
        "api:rusqlite:update_hook:register",
    );
    assert!(
        !wrong_field_update_site_ids.is_empty(),
        "wrong-field hook fixture must still classify the registering FFI call"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "HookFieldState::install_update_hook_wrong_field",
            &wrong_field_update_site_ids,
        ),
        "a different stored release field must not cover the registered update hook object"
    );
    let non_releasing_field_site_ids = registration_user_data_site_ids(
        &facts,
        "HookFieldState::install_update_hook_non_releasing_field",
        "api:rusqlite:update_hook:register",
    );
    assert!(
        !non_releasing_field_site_ids.is_empty(),
        "non-releasing field-state fixture must still classify the registering FFI call"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "HookFieldState::install_update_hook_non_releasing_field",
            &non_releasing_field_site_ids,
        ),
        "a stored field whose function does not release raw user-data must not emit a proof"
    );
    let openssl_ex_data_site_ids = registration_user_data_site_ids(
        &facts,
        "OpenSslExDataDropRelease::openssl_ex_data_drop_release_registration_site",
        "api:openssl:ssl_set_ex_data:register",
    );
    assert!(
        !openssl_ex_data_site_ids.is_empty(),
        "OpenSSL ex_data fixture must classify the registering FFI call"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "OpenSslExDataDropRelease::openssl_ex_data_drop_release_registration_site",
            &openssl_ex_data_site_ids,
        ),
        "OpenSSL ex_data Drop release must bind FromRaw to the registered user-data object"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "OpenSslExDataDropRelease::openssl_ex_data_drop_release_registration_site",
            &openssl_ex_data_site_ids,
        ),
        "conditional OpenSSL ex_data Drop release must not be upgraded to a release path proof"
    );
    let openssl_unconditional_site_ids = registration_user_data_site_ids(
        &facts,
        "OpenSslExDataUnconditionalDropRelease::openssl_ex_data_unconditional_drop_release_registration_site",
        "api:openssl:ssl_set_ex_data:register",
    );
    assert!(
        !openssl_unconditional_site_ids.is_empty(),
        "OpenSSL unconditional ex_data fixture must classify the registering FFI call"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "OpenSslExDataUnconditionalDropRelease::openssl_ex_data_unconditional_drop_release_registration_site",
            &openssl_unconditional_site_ids,
        ),
        "unconditional OpenSSL ex_data Drop release must bind the registered user-data object to exact same handle and slot release proof"
    );
    let openssl_wrong_slot_site_ids = registration_user_data_site_ids(
        &facts,
        "OpenSslExDataWrongSlot::openssl_ex_data_wrong_slot_registration_site",
        "api:openssl:ssl_set_ex_data:register",
    );
    assert!(
        !openssl_wrong_slot_site_ids.is_empty(),
        "OpenSSL wrong-slot fixture must still classify the registering FFI call"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "OpenSslExDataWrongSlot::openssl_ex_data_wrong_slot_registration_site",
            &openssl_wrong_slot_site_ids,
        ),
        "OpenSSL ex_data release through a different slot must not cover the registered object"
    );
    let openssl_same_name_wrong_slot_site_ids = registration_user_data_site_ids(
        &facts,
        "OpenSslExDataSameNameWrongSlot::openssl_ex_data_same_name_wrong_slot_registration_site",
        "api:openssl:ssl_set_ex_data:register",
    );
    assert!(
        !openssl_same_name_wrong_slot_site_ids.is_empty(),
        "OpenSSL same-name wrong-slot fixture must still classify the registering FFI call"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "OpenSslExDataSameNameWrongSlot::openssl_ex_data_same_name_wrong_slot_registration_site",
            &openssl_same_name_wrong_slot_site_ids,
        ),
        "OpenSSL ex_data release through a local variable named slot with a different value must not cover the registered object"
    );
    let openssl_nested_get_site_ids = registration_user_data_site_ids(
        &facts,
        "OpenSslExDataNestedGet::openssl_ex_data_nested_get_registration_site",
        "api:openssl:ssl_set_ex_data:register",
    );
    assert!(
        !openssl_nested_get_site_ids.is_empty(),
        "OpenSSL nested-get fixture must still classify the registering FFI call"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "OpenSslExDataNestedGet::openssl_ex_data_nested_get_registration_site",
            &openssl_nested_get_site_ids,
        ),
        "a nested local openssl_sys module must not be treated as the OpenSSL get-side release API"
    );
    let openssl_wrong_handle_site_ids = registration_user_data_site_ids(
        &facts,
        "OpenSslExDataWrongHandle::openssl_ex_data_wrong_handle_registration_site",
        "api:openssl:ssl_set_ex_data:register",
    );
    assert!(
        !openssl_wrong_handle_site_ids.is_empty(),
        "OpenSSL wrong-handle fixture must still classify the registering FFI call"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "OpenSslExDataWrongHandle::openssl_ex_data_wrong_handle_registration_site",
            &openssl_wrong_handle_site_ids,
        ),
        "OpenSSL ex_data release through a different SSL handle field must not cover the registered object"
    );
    let openssl_aliased_handle_site_ids = registration_user_data_site_ids(
        &facts,
        "OpenSslExDataAliasedHandle::openssl_ex_data_aliased_handle_registration_site",
        "api:openssl:ssl_set_ex_data:register",
    );
    assert!(
        !openssl_aliased_handle_site_ids.is_empty(),
        "OpenSSL aliased-handle fixture must still classify the registering FFI call"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "OpenSslExDataAliasedHandle::openssl_ex_data_aliased_handle_registration_site",
            &openssl_aliased_handle_site_ids,
        ),
        "OpenSSL ex_data release through a local alias of the same SSL handle field must cover the registered object"
    );
    let openssl_aliased_store_paths = object_flow_field_paths_for_symbol_kind(
        &facts,
        "OpenSslExDataAliasedHandle::openssl_ex_data_aliased_handle_registration_site",
        bw_model::ObjectFlowKind::FieldStore,
    );
    let openssl_aliased_load_paths = object_flow_field_paths_for_symbol_kind(
        &facts,
        "OpenSslExDataAliasedHandle::openssl_ex_data_aliased_handle_registration_site",
        bw_model::ObjectFlowKind::FieldLoad,
    );
    assert!(
        openssl_aliased_store_paths
            .iter()
            .any(|path| path.starts_with("openssl_ex_data:api:openssl:ssl_set_ex_data:register:")),
        "OpenSSL exact handle+slot evidence must produce field_store ObjectFlow for retained user_data; paths={openssl_aliased_store_paths:?}"
    );
    assert!(
        openssl_aliased_load_paths
            .iter()
            .any(|path| path.starts_with("openssl_ex_data:api:openssl:ssl_set_ex_data:register:")),
        "OpenSSL exact handle+slot evidence must produce field_load ObjectFlow for retained user_data release; paths={openssl_aliased_load_paths:?}"
    );
    let openssl_aliased_wrong_handle_site_ids = registration_user_data_site_ids(
        &facts,
        "OpenSslExDataAliasedWrongHandle::openssl_ex_data_aliased_wrong_handle_registration_site",
        "api:openssl:ssl_set_ex_data:register",
    );
    assert!(
        !openssl_aliased_wrong_handle_site_ids.is_empty(),
        "OpenSSL aliased wrong-handle fixture must still classify the registering FFI call"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "OpenSslExDataAliasedWrongHandle::openssl_ex_data_aliased_wrong_handle_registration_site",
            &openssl_aliased_wrong_handle_site_ids,
        ),
        "OpenSSL ex_data release through same-named local aliases of different SSL handle fields must not cover the registered object"
    );
    assert!(
        !has_object_flow_for_symbol_kind_with_field_path_prefix(
            &facts,
            "OpenSslExDataAliasedWrongHandle::openssl_ex_data_aliased_wrong_handle_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            "openssl_ex_data:api:openssl:ssl_set_ex_data:register:",
        ),
        "OpenSSL exact-key ObjectFlow must not connect a release loaded from a different handle field"
    );
    let openssl_helper_holder_site_ids = registration_user_data_site_ids(
        &facts,
        "OpenSslExDataHelperHolderRelease::openssl_ex_data_helper_holder_registration_site",
        "api:openssl:ssl_set_ex_data:register",
    );
    assert!(
        !openssl_helper_holder_site_ids.is_empty(),
        "OpenSSL helper-holder fixture must classify the caller-scoped registering helper call"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "OpenSslExDataHelperHolderRelease::openssl_ex_data_helper_holder_registration_site",
            &openssl_helper_holder_site_ids,
        ),
        "OpenSSL helper holder set/get must prove exact same handle field, slot field, and user-data release"
    );
    let openssl_helper_holder_store_paths = object_flow_field_paths_for_symbol_kind(
        &facts,
        "OpenSslExDataHelperHolderRelease::openssl_ex_data_helper_holder_registration_site",
        bw_model::ObjectFlowKind::FieldStore,
    );
    let openssl_helper_holder_load_paths = object_flow_field_paths_for_symbol_kind(
        &facts,
        "OpenSslExDataHelperHolderRelease::openssl_ex_data_helper_holder_registration_site",
        bw_model::ObjectFlowKind::FieldLoad,
    );
    assert!(
        openssl_helper_holder_store_paths
            .iter()
            .any(|path| path.starts_with("openssl_ex_data:api:openssl:ssl_set_ex_data:register:")),
        "OpenSSL helper holder exact-key evidence must produce field_store ObjectFlow; paths={openssl_helper_holder_store_paths:?}"
    );
    assert!(
        openssl_helper_holder_load_paths
            .iter()
            .any(|path| path.starts_with("openssl_ex_data:api:openssl:ssl_set_ex_data:register:")),
        "OpenSSL helper holder exact-key evidence must produce field_load ObjectFlow; paths={openssl_helper_holder_load_paths:?}"
    );
    let openssl_helper_wrong_handle_site_ids = registration_user_data_site_ids(
        &facts,
        "OpenSslExDataHelperHolderWrongHandle::openssl_ex_data_helper_holder_wrong_handle_registration_site",
        "api:openssl:ssl_set_ex_data:register",
    );
    assert!(
        !openssl_helper_wrong_handle_site_ids.is_empty(),
        "OpenSSL helper-holder wrong-handle fixture must still classify the registering helper call"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "OpenSslExDataHelperHolderWrongHandle::openssl_ex_data_helper_holder_wrong_handle_registration_site",
            &openssl_helper_wrong_handle_site_ids,
        ),
        "OpenSSL helper holder get through a sibling handle field must not cover the registered object"
    );
    assert!(
        !has_object_flow_for_symbol_kind_with_field_path_prefix(
            &facts,
            "OpenSslExDataHelperHolderWrongHandle::openssl_ex_data_helper_holder_wrong_handle_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            "openssl_ex_data:api:openssl:ssl_set_ex_data:register:",
        ),
        "OpenSSL helper holder exact-key ObjectFlow must not connect a load from a sibling handle field"
    );
    let openssl_no_release_site_ids = registration_user_data_site_ids(
        &facts,
        "OpenSslExDataNoRelease::openssl_ex_data_no_release_registration_site",
        "api:openssl:ssl_set_ex_data:register",
    );
    assert!(
        !openssl_no_release_site_ids.is_empty(),
        "OpenSSL no-release fixture must still classify the registering FFI call"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "OpenSslExDataNoRelease::openssl_ex_data_no_release_registration_site",
            &openssl_no_release_site_ids,
        ),
        "OpenSSL ex_data get without Box::from_raw must not emit a release proof"
    );
    let openssl_foreign_free_site_ids = registration_user_data_site_ids(
        &facts,
        "OpenSslExDataForeignFreeContract::openssl_ex_data_foreign_free_contract_registration_site",
        "api:openssl:ssl_set_ex_data:register",
    );
    assert!(
        !openssl_foreign_free_site_ids.is_empty(),
        "OpenSSL foreign-free fixture must classify the registering FFI call"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "OpenSslExDataForeignFreeContract::openssl_ex_data_foreign_free_contract_registration_site",
            &openssl_foreign_free_site_ids,
        ),
        "OpenSSL CRYPTO_get_ex_new_index free callback must bind FromRaw to registered user-data"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "OpenSslExDataForeignFreeContract::openssl_ex_data_foreign_free_contract_registration_site",
            &openssl_foreign_free_site_ids,
        ),
        "OpenSSL CRYPTO_get_ex_new_index free callback contract must emit a release proof for registered user-data"
    );
    let openssl_missing_free_site_ids = registration_user_data_site_ids(
        &facts,
        "OpenSslExDataForeignFreeMissingDestructor::openssl_ex_data_foreign_free_missing_destructor_registration_site",
        "api:openssl:ssl_set_ex_data:register",
    );
    assert!(
        !openssl_missing_free_site_ids.is_empty(),
        "OpenSSL missing-free fixture must still classify the registering FFI call"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "OpenSslExDataForeignFreeMissingDestructor::openssl_ex_data_foreign_free_missing_destructor_registration_site",
            &openssl_missing_free_site_ids,
        ),
        "OpenSSL ex_data slot without a free callback must not emit a release proof"
    );
    let openssl_non_releasing_free_site_ids = registration_user_data_site_ids(
        &facts,
        "OpenSslExDataForeignFreeNonReleasingDestructor::openssl_ex_data_foreign_free_non_releasing_destructor_registration_site",
        "api:openssl:ssl_set_ex_data:register",
    );
    assert!(
        !openssl_non_releasing_free_site_ids.is_empty(),
        "OpenSSL non-releasing-free fixture must still classify the registering FFI call"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "OpenSslExDataForeignFreeNonReleasingDestructor::openssl_ex_data_foreign_free_non_releasing_destructor_registration_site",
            &openssl_non_releasing_free_site_ids,
        ),
        "OpenSSL ex_data free callback without Box::from_raw must not emit a release proof"
    );
    let user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match &fact.payload {
            StaticFact::RawPointerTransfer(transfer)
                if transfer.transfer_kind == RawPointerTransferKind::IntoRaw =>
            {
                Some(transfer.user_data_site_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !user_data_site_ids.is_empty(),
        "Box::into_raw must emit a compiler-derived user-data transfer fact"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact.payload,
            StaticFact::RegistrationSite(ref registration)
                if registration.api_id == "api:rusqlite:set_callback_with_user_data:register"
                    && registration
                        .user_data_site_id
                        .as_ref()
                        .is_some_and(|site_id| user_data_site_ids.contains(site_id))
        )),
        "a registered raw pointer must bind to the exact compiler-derived user-data site"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact.payload,
            StaticFact::RawPointerTransfer(ref transfer)
                if transfer.transfer_kind == RawPointerTransferKind::FromRaw
                    && user_data_site_ids.contains(&transfer.user_data_site_id)
        )),
        "Box::from_raw must retain the original user-data object identity"
    );
    assert!(
        facts_text.contains(r#""transfer_kind":"from_raw_parts""#)
            && facts_text.contains("raw_parts_ownership_transfer_site"),
        "Vec::from_raw_parts must emit a distinct raw parts ownership transfer fact"
    );
    assert!(
        facts_text.contains(r#""kind":"drop_prevention""#)
            && facts_text.contains(r#""prevention_kind":"mem_forget""#)
            && facts_text.contains("raw_parts_ownership_transfer_with_forget_site"),
        "mem::forget after Vec::from_raw_parts must emit a drop-prevention fact"
    );
    assert!(
        facts_text.contains(r#""kind":"callback_user_data_reconstruction""#),
        "extern callback userdata owner reconstruction should be extracted"
    );
    assert!(
        facts_text.contains(r#""reconstruction_kind":"owner_from_transmute""#),
        "mem::transmute(user_data) in extern callback should be classified"
    );
    assert!(
        facts_text.contains(r#""reconstruction_kind":"leak_from_raw""#),
        "Box::leak(Box::from_raw(user_data)) in extern callback should be classified"
    );
    let callback_roundtrip_store_paths = object_flow_field_paths_for_symbol_kind(
        &facts,
        "ffi_callback_user_data_roundtrip_registration_site",
        bw_model::ObjectFlowKind::FieldStore,
    );
    let callback_roundtrip_load_paths = object_flow_field_paths_for_symbol_kind(
        &facts,
        "retained_userdata_roundtrip_callback",
        bw_model::ObjectFlowKind::FieldLoad,
    );
    assert!(
        callback_roundtrip_store_paths
            .iter()
            .any(|path| path.starts_with("callback_user_data:api:rusqlite:update_hook:register:")),
        "exact callback + userdata registration must produce callback_user_data field_store ObjectFlow; paths={callback_roundtrip_store_paths:?}"
    );
    assert!(
        callback_roundtrip_load_paths
            .iter()
            .any(|path| path.starts_with("callback_user_data:api:rusqlite:update_hook:register:")),
        "exact callback userdata reconstruction must produce matching callback_user_data field_load ObjectFlow; paths={callback_roundtrip_load_paths:?}"
    );
    let helper_user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::IntoRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("ffi_callback_user_data_helper_roundtrip_registration_site")
                }) =>
            {
                Some(transfer.user_data_site_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !helper_user_data_site_ids.is_empty(),
        "helper roundtrip fixture must emit caller-scoped into_raw user-data identity"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:update_hook:register"
                && registration
                    .user_data_site_id
                    .as_ref()
                    .is_some_and(|site_id| helper_user_data_site_ids.contains(site_id))
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("ffi_callback_user_data_helper_roundtrip_registration_site")
                })
        )),
        "same-crate registration helper must emit caller-scoped registration bound to exact user_data"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if helper_user_data_site_ids.contains(&proof.object_site_id)
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("ffi_callback_user_data_helper_roundtrip_registration_site")
                })
        )),
        "same-crate registration helper must allow caller-scoped release proof only when the helper registration is unconditional"
    );
    let helper_callback_store_paths = object_flow_field_paths_for_symbol_kind(
        &facts,
        "ffi_callback_user_data_helper_roundtrip_registration_site",
        bw_model::ObjectFlowKind::FieldStore,
    );
    let helper_callback_load_paths = object_flow_field_paths_for_symbol_kind(
        &facts,
        "retained_userdata_helper_roundtrip_callback",
        bw_model::ObjectFlowKind::FieldLoad,
    );
    assert!(
        helper_callback_store_paths
            .iter()
            .any(|path| path.starts_with("callback_user_data:api:rusqlite:update_hook:register:")),
        "same-crate registration helper must produce callback_user_data field_store ObjectFlow; paths={helper_callback_store_paths:?}"
    );
    assert!(
        helper_callback_load_paths
            .iter()
            .any(|path| path.starts_with("callback_user_data:api:rusqlite:update_hook:register:")),
        "same-crate helper callback reconstruction must produce matching callback_user_data field_load ObjectFlow; paths={helper_callback_load_paths:?}"
    );
    let after_release_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "ffi_callback_user_data_after_release_use_registration_site",
        "api:rusqlite:update_hook:register",
    );
    assert!(
        !after_release_user_data_site_ids.is_empty(),
        "after-release callback-use fixture must classify the registering FFI call"
    );
    assert!(
        has_callback_release_use_order_for_symbol_objects(
            &facts,
            "ffi_callback_user_data_after_release_use_registration_site",
            &after_release_user_data_site_ids,
            bw_model::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
        ),
        "release-before-direct-callback-use must emit a callback release/use ordering proof"
    );
    let before_release_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "ffi_callback_user_data_before_release_use_registration_site",
        "api:rusqlite:update_hook:register",
    );
    assert!(
        !before_release_user_data_site_ids.is_empty(),
        "before-release callback-use fixture must classify the registering FFI call"
    );
    assert!(
        !has_callback_release_use_order_for_symbol_objects(
            &facts,
            "ffi_callback_user_data_before_release_use_registration_site",
            &before_release_user_data_site_ids,
            bw_model::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
        ),
        "callback use before release must not be treated as release-before-use proof"
    );
    let loop_order_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "ffi_callback_user_data_loop_order_registration_site",
        "api:rusqlite:update_hook:register",
    );
    assert!(
        !loop_order_user_data_site_ids.is_empty(),
        "loop-order callback-use fixture must classify the registering FFI call"
    );
    assert!(
        has_callback_release_use_order_for_symbol_objects(
            &facts,
            "ffi_callback_user_data_loop_order_registration_site",
            &loop_order_user_data_site_ids,
            bw_model::CallbackReleaseUseOrdering::UnknownOrdering,
        ),
        "a release and a callback use in one loop body cannot be ordered and must be recorded as unknown rather than dropped"
    );
    assert!(
        !has_callback_release_use_order_for_symbol_objects(
            &facts,
            "ffi_callback_user_data_loop_order_registration_site",
            &loop_order_user_data_site_ids,
            bw_model::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
        ),
        "an unorderable release/use pair must never be reported as a release-before-use proof"
    );
    let helper_after_release_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "ffi_callback_user_data_helper_after_release_use_registration_site",
        "api:rusqlite:update_hook:register",
    );
    assert!(
        !helper_after_release_user_data_site_ids.is_empty(),
        "helper after-release callback-use fixture must classify the registering FFI call"
    );
    assert!(
        has_callback_release_use_order_for_symbol_objects(
            &facts,
            "ffi_callback_user_data_helper_after_release_use_registration_site",
            &helper_after_release_user_data_site_ids,
            bw_model::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
        ),
        "release-before-helper-callback-use must emit a callback release/use ordering proof"
    );
    let helper_before_release_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "ffi_callback_user_data_helper_before_release_use_registration_site",
        "api:rusqlite:update_hook:register",
    );
    assert!(
        !helper_before_release_user_data_site_ids.is_empty(),
        "helper before-release callback-use fixture must classify the registering FFI call"
    );
    assert!(
        !has_callback_release_use_order_for_symbol_objects(
            &facts,
            "ffi_callback_user_data_helper_before_release_use_registration_site",
            &helper_before_release_user_data_site_ids,
            bw_model::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
        ),
        "helper callback use before release must not be treated as release-before-use proof"
    );
    let helper_alias_after_release_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "ffi_callback_user_data_helper_alias_after_release_use_registration_site",
        "api:rusqlite:update_hook:register",
    );
    assert!(
        !helper_alias_after_release_user_data_site_ids.is_empty(),
        "helper alias after-release callback-use fixture must classify the registering FFI call"
    );
    assert!(
        has_callback_release_use_order_for_symbol_objects(
            &facts,
            "ffi_callback_user_data_helper_alias_after_release_use_registration_site",
            &helper_alias_after_release_user_data_site_ids,
            bw_model::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
        ),
        "helper-local callback/user_data aliases must preserve exact release-before-use proof"
    );
    let helper_wrong_object_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "ffi_callback_user_data_helper_wrong_object_registration_site",
        "api:rusqlite:update_hook:register",
    );
    assert!(
        !helper_wrong_object_user_data_site_ids.is_empty(),
        "helper wrong-object callback-use fixture must classify the registering FFI call"
    );
    assert!(
        !has_callback_release_use_order_for_symbol_objects(
            &facts,
            "ffi_callback_user_data_helper_wrong_object_registration_site",
            &helper_wrong_object_user_data_site_ids,
            bw_model::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
        ),
        "helper use of a different raw pointer argument must not prove release/use order for the registered object"
    );
    let helper_holder_after_release_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "ffi_callback_user_data_helper_holder_after_release_use_registration_site",
        "api:rusqlite:update_hook:register",
    );
    assert!(
        !helper_holder_after_release_user_data_site_ids.is_empty(),
        "helper holder after-release callback-use fixture must classify the registering FFI call"
    );
    assert!(
        has_callback_release_use_order_for_symbol_objects(
            &facts,
            "ffi_callback_user_data_helper_holder_after_release_use_registration_site",
            &helper_holder_after_release_user_data_site_ids,
            bw_model::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
        ),
        "wrapper field projections must preserve exact callback/user_data release-before-use proof"
    );
    let helper_holder_wrong_field_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "ffi_callback_user_data_helper_holder_wrong_field_registration_site",
        "api:rusqlite:update_hook:register",
    );
    assert!(
        !helper_holder_wrong_field_user_data_site_ids.is_empty(),
        "helper holder wrong-field callback-use fixture must classify the registering FFI call"
    );
    assert!(
        !has_callback_release_use_order_for_symbol_objects(
            &facts,
            "ffi_callback_user_data_helper_holder_wrong_field_registration_site",
            &helper_holder_wrong_field_user_data_site_ids,
            bw_model::CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse,
        ),
        "wrapper field use of a sibling raw pointer must not prove release/use order for the registered object"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:update_hook:register"
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("ffi_callback_user_data_conditional_helper_registration_site")
                })
        )),
        "conditional registration helper must not be summarized as an unconditional caller-scoped registration"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(_),
                ..
            } if source_ref.symbol_path.as_deref().is_some_and(|path| {
                path.ends_with("ffi_callback_user_data_conditional_helper_registration_site")
            })
        )),
        "conditional registration helper must not produce caller-scoped release proof"
    );
    let ambiguous_callback_store_paths = object_flow_field_paths_for_symbol_kind(
        &facts,
        "ffi_callback_user_data_ambiguous_registration_site",
        bw_model::ObjectFlowKind::FieldStore,
    );
    assert!(
        ambiguous_callback_store_paths
            .iter()
            .all(|path| !path.starts_with("callback_user_data:api:rusqlite:update_hook:register:")),
        "same callback registered with multiple userdata objects must not get exact callback_user_data ObjectFlow; paths={ambiguous_callback_store_paths:?}"
    );
    assert!(
        facts
            .iter()
            .any(|fact| matches!(fact.payload, StaticFact::ReleasePathProof(_))),
        "a same-body release endpoint that is unavoidable after registration must emit a CFG path proof"
    );
    let alias_user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::IntoRaw
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("user_data_alias_registration_site")) =>
            {
                Some(transfer.user_data_site_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !alias_user_data_site_ids.is_empty(),
        "alias fixture must emit a source-scoped into_raw user-data identity"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:set_callback_with_user_data:register"
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("user_data_alias_registration_site"))
                && registration
                    .user_data_site_id
                    .as_ref()
                    .is_some_and(|site_id| alias_user_data_site_ids.contains(site_id))
        )),
        "a raw pointer copied through a local alias must still bind to the registration"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::FromRaw
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("user_data_alias_registration_site"))
                && alias_user_data_site_ids.contains(&transfer.user_data_site_id)
        )),
        "a raw pointer copied through a local alias must still bind to the release endpoint"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref
                .symbol_path
                .as_deref()
                .is_some_and(|path| path.ends_with("user_data_alias_registration_site"))
                && alias_user_data_site_ids.contains(&proof.object_site_id)
        )),
        "an unavoidable alias-mediated same-body release endpoint must emit a CFG path proof"
    );
    let field_user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::IntoRaw
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("user_data_field_registration_site")) =>
            {
                Some(transfer.user_data_site_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !field_user_data_site_ids.is_empty(),
        "field fixture must emit a source-scoped into_raw user-data identity"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:set_callback_with_user_data:register"
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("user_data_field_registration_site"))
                && registration
                    .user_data_site_id
                    .as_ref()
                    .is_some_and(|site_id| field_user_data_site_ids.contains(site_id))
        )),
        "a raw pointer stored in an exact field place must bind to the registration"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::FromRaw
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("user_data_field_registration_site"))
                && field_user_data_site_ids.contains(&transfer.user_data_site_id)
        )),
        "a raw pointer loaded from an exact field place must bind to the release endpoint"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref
                .symbol_path
                .as_deref()
                .is_some_and(|path| path.ends_with("user_data_field_registration_site"))
                && field_user_data_site_ids.contains(&proof.object_site_id)
        )),
        "an unavoidable field-mediated same-body release endpoint must emit a CFG path proof"
    );
    let different_field_registered_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:set_callback_with_user_data:register"
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_different_field_release_registration_site")
                }) =>
            {
                registration.user_data_site_id.clone()
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !different_field_registered_site_ids.is_empty(),
        "different-field fixture must still bind the registered field"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref.symbol_path.as_deref().is_some_and(|path| {
                path.ends_with("user_data_different_field_release_registration_site")
            }) && different_field_registered_site_ids.contains(&proof.object_site_id)
        )),
        "a release from a different field must not emit coverage for the registered field"
    );
    let field_reassigned_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_field_reassigned_negative_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !field_reassigned_user_data_site_ids.is_empty(),
        "field reassignment fixture must bind the originally registered field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_field_reassigned_negative_registration_site",
            &field_reassigned_user_data_site_ids,
        ),
        "a release after exact field reassignment must not prove coverage for the originally registered object"
    );
    assert!(
        has_object_binding_gap_for_symbol_kind_field_path(
            &facts,
            "user_data_field_reassigned_negative_registration_site",
            ObjectBindingGapKind::ReassignmentBarrier,
            "field:0",
        ),
        "exact field reassignment must emit an ObjectBindingGap barrier for the same object-flow field key"
    );
    let passthrough_user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::IntoRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_passthrough_registration_site")
                }) =>
            {
                Some(transfer.user_data_site_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !passthrough_user_data_site_ids.is_empty(),
        "passthrough fixture must emit a source-scoped into_raw user-data identity"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:set_callback_with_user_data:register"
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("user_data_passthrough_registration_site"))
                && registration
                    .user_data_site_id
                    .as_ref()
                    .is_some_and(|site_id| passthrough_user_data_site_ids.contains(site_id))
        )),
        "a raw pointer returned by a local passthrough function must still bind to the registration"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::FromRaw
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("user_data_passthrough_registration_site"))
                && passthrough_user_data_site_ids.contains(&transfer.user_data_site_id)
        )),
        "a raw pointer returned by a local passthrough function must still bind to the release endpoint"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref
                .symbol_path
                .as_deref()
                .is_some_and(|path| path.ends_with("user_data_passthrough_registration_site"))
                && passthrough_user_data_site_ids.contains(&proof.object_site_id)
        )),
        "an unavoidable passthrough-mediated same-body release endpoint must emit a CFG path proof"
    );
    let release_wrapper_user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::IntoRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_release_wrapper_registration_site")
                }) =>
            {
                Some(transfer.user_data_site_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !release_wrapper_user_data_site_ids.is_empty(),
        "release wrapper fixture must emit a source-scoped into_raw user-data identity"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::FromRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_release_wrapper_registration_site")
                })
                && release_wrapper_user_data_site_ids.contains(&transfer.user_data_site_id)
        )),
        "an unconditional release wrapper call must bind the caller user-data to a release endpoint"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_release_wrapper_registration_site")
                })
                && release_wrapper_user_data_site_ids.contains(&proof.object_site_id)
        )),
        "an unconditional release wrapper that postdominates registration must emit a CFG path proof"
    );
    let field_release_wrapper_user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::IntoRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_field_release_wrapper_registration_site")
                }) =>
            {
                Some(transfer.user_data_site_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !field_release_wrapper_user_data_site_ids.is_empty(),
        "field release wrapper fixture must emit a source-scoped into_raw user-data identity"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:set_callback_with_user_data:register"
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_field_release_wrapper_registration_site")
                })
                && registration
                    .user_data_site_id
                    .as_ref()
                    .is_some_and(|site_id| field_release_wrapper_user_data_site_ids.contains(site_id))
        )),
        "a registered raw pointer stored in a holder field must bind before the wrapper release"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::FromRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_field_release_wrapper_registration_site")
                })
                && field_release_wrapper_user_data_site_ids.contains(&transfer.user_data_site_id)
        )),
        "a holder-field release wrapper call must bind the caller user-data to a release endpoint"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_field_release_wrapper_registration_site")
                })
                && field_release_wrapper_user_data_site_ids.contains(&proof.object_site_id)
        )),
        "a holder-field release wrapper that postdominates registration must emit a CFG path proof"
    );
    let aggregate_field_wrapper_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_aggregate_field_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !aggregate_field_wrapper_user_data_site_ids.is_empty(),
        "ADT aggregate holder fixture must bind the aggregate field user-data to registration"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "user_data_aggregate_field_release_wrapper_registration_site",
            &aggregate_field_wrapper_user_data_site_ids,
        ),
        "an ADT aggregate holder-field release wrapper call must bind the caller user-data to a release endpoint"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_aggregate_field_release_wrapper_registration_site",
            &aggregate_field_wrapper_user_data_site_ids,
        ),
        "an ADT aggregate holder-field release wrapper must emit a same-object CFG path proof"
    );
    let helper_return_field_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_helper_return_field_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !helper_return_field_user_data_site_ids.is_empty(),
        "local helper returning an ADT holder must bind the returned field user-data to registration"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "user_data_helper_return_field_release_wrapper_registration_site",
            &helper_return_field_user_data_site_ids,
        ),
        "a local helper-returned holder-field release wrapper call must bind the caller user-data to a release endpoint"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_helper_return_field_release_wrapper_registration_site",
            &helper_return_field_user_data_site_ids,
        ),
        "a local helper-returned holder-field release wrapper must emit a same-object CFG path proof"
    );
    let nested_aggregate_field_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_nested_aggregate_field_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !nested_aggregate_field_user_data_site_ids.is_empty(),
        "nested ADT aggregate holder fixture must bind the nested field user-data to registration"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "user_data_nested_aggregate_field_release_wrapper_registration_site",
            &nested_aggregate_field_user_data_site_ids,
        ),
        "a nested ADT aggregate holder-field release wrapper call must bind the caller user-data to a release endpoint"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_nested_aggregate_field_release_wrapper_registration_site",
            &nested_aggregate_field_user_data_site_ids,
        ),
        "a nested ADT aggregate holder-field release wrapper must emit a same-object CFG path proof"
    );
    let helper_return_nested_field_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_helper_return_nested_field_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !helper_return_nested_field_user_data_site_ids.is_empty(),
        "same-crate helper returning a nested ADT holder must bind the nested field user-data to registration"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "user_data_helper_return_nested_field_release_wrapper_registration_site",
            &helper_return_nested_field_user_data_site_ids,
        ),
        "a helper-returned nested holder release wrapper call must bind the caller user-data to a release endpoint"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_helper_return_nested_field_release_wrapper_registration_site",
            &helper_return_nested_field_user_data_site_ids,
        ),
        "a helper-returned nested holder release wrapper must emit a same-object CFG path proof"
    );
    let tuple_aggregate_field_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_tuple_aggregate_field_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !tuple_aggregate_field_user_data_site_ids.is_empty(),
        "tuple aggregate holder fixture must bind the tuple field user-data to registration"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "user_data_tuple_aggregate_field_release_wrapper_registration_site",
            &tuple_aggregate_field_user_data_site_ids,
        ),
        "a tuple aggregate holder-field release wrapper call must bind the caller user-data to a release endpoint"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_tuple_aggregate_field_release_wrapper_registration_site",
            &tuple_aggregate_field_user_data_site_ids,
        ),
        "a tuple aggregate holder-field release wrapper must emit a same-object CFG path proof"
    );
    let helper_return_tuple_field_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_helper_return_tuple_field_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !helper_return_tuple_field_user_data_site_ids.is_empty(),
        "same-crate helper returning a tuple holder must bind the tuple field user-data to registration"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "user_data_helper_return_tuple_field_release_wrapper_registration_site",
            &helper_return_tuple_field_user_data_site_ids,
        ),
        "a helper-returned tuple holder release wrapper call must bind the caller user-data to a release endpoint"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_helper_return_tuple_field_release_wrapper_registration_site",
            &helper_return_tuple_field_user_data_site_ids,
        ),
        "a helper-returned tuple holder release wrapper must emit a same-object CFG path proof"
    );
    let option_field_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_option_field_release_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !option_field_user_data_site_ids.is_empty(),
        "Option::Some holder fixture must bind the Some field user-data to registration"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "user_data_option_field_release_registration_site",
            &option_field_user_data_site_ids,
        ),
        "an Option::Some field release must bind the caller user-data to a release endpoint"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_option_field_release_registration_site",
            &option_field_user_data_site_ids,
        ),
        "an Option::Some field release must emit a same-object CFG path proof"
    );
    let helper_return_option_field_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_helper_return_option_field_release_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !helper_return_option_field_user_data_site_ids.is_empty(),
        "same-crate helper returning Option::Some must bind the Some field user-data to registration"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "user_data_helper_return_option_field_release_registration_site",
            &helper_return_option_field_user_data_site_ids,
        ),
        "a helper-returned Option::Some field release must bind the caller user-data to a release endpoint"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_helper_return_option_field_release_registration_site",
            &helper_return_option_field_user_data_site_ids,
        ),
        "a helper-returned Option::Some field release must emit a same-object CFG path proof"
    );
    let different_field_wrapper_user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::IntoRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_different_field_release_wrapper_registration_site")
                }) =>
            {
                Some(transfer.user_data_site_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !different_field_wrapper_user_data_site_ids.is_empty(),
        "different-field release wrapper fixture must emit source-scoped into_raw identities"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_different_field_release_wrapper_registration_site")
                })
                && different_field_wrapper_user_data_site_ids.contains(&proof.object_site_id)
        )),
        "a wrapper that releases a different field must not emit a release path proof"
    );
    let aggregate_different_field_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_aggregate_different_field_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !aggregate_different_field_user_data_site_ids.is_empty(),
        "ADT aggregate different-field fixture must bind the registered field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_aggregate_different_field_release_wrapper_registration_site",
            &aggregate_different_field_user_data_site_ids,
        ),
        "an ADT aggregate wrapper that releases a sibling field must not emit a release path proof for the registered field"
    );
    let helper_return_different_field_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_helper_return_different_field_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !helper_return_different_field_user_data_site_ids.is_empty(),
        "local helper returning a pair holder must bind the registered field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_helper_return_different_field_release_wrapper_registration_site",
            &helper_return_different_field_user_data_site_ids,
        ),
        "a local helper-returned pair holder that releases a sibling field must not emit a release path proof for the registered field"
    );
    let nested_different_field_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_nested_aggregate_different_field_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !nested_different_field_user_data_site_ids.is_empty(),
        "nested ADT aggregate different-field fixture must bind the registered nested field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_nested_aggregate_different_field_release_wrapper_registration_site",
            &nested_different_field_user_data_site_ids,
        ),
        "a nested ADT aggregate wrapper that releases a sibling field must not emit a release path proof for the registered nested field"
    );
    let tuple_different_field_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_tuple_aggregate_different_field_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !tuple_different_field_user_data_site_ids.is_empty(),
        "tuple aggregate different-field fixture must bind the registered tuple field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_tuple_aggregate_different_field_release_wrapper_registration_site",
            &tuple_different_field_user_data_site_ids,
        ),
        "a tuple aggregate wrapper that releases a sibling field must not emit a release path proof for the registered tuple field"
    );
    let aggregate_reassigned_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_aggregate_field_reassigned_negative_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !aggregate_reassigned_user_data_site_ids.is_empty(),
        "ADT aggregate reassignment fixture must bind the originally registered field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_aggregate_field_reassigned_negative_registration_site",
            &aggregate_reassigned_user_data_site_ids,
        ),
        "whole-object aggregate reassignment must clear the stale registered field before wrapper release"
    );
    assert!(
        has_object_binding_gap_for_symbol_kind_field_path(
            &facts,
            "user_data_aggregate_field_reassigned_negative_registration_site",
            ObjectBindingGapKind::ReassignmentBarrier,
            "field:0",
        ),
        "whole-object aggregate reassignment must emit an ObjectBindingGap barrier for the overwritten field key"
    );
    let helper_return_reassigned_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_helper_return_field_reassigned_negative_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !helper_return_reassigned_user_data_site_ids.is_empty(),
        "local helper-returned holder reassignment fixture must bind the originally registered field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_helper_return_field_reassigned_negative_registration_site",
            &helper_return_reassigned_user_data_site_ids,
        ),
        "whole-object helper-return reassignment must clear the stale registered field before wrapper release"
    );
    let nested_reassigned_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_nested_aggregate_field_reassigned_negative_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !nested_reassigned_user_data_site_ids.is_empty(),
        "nested ADT aggregate reassignment fixture must bind the originally registered nested field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_nested_aggregate_field_reassigned_negative_registration_site",
            &nested_reassigned_user_data_site_ids,
        ),
        "nested whole-object aggregate reassignment must clear the stale registered field before wrapper release"
    );
    let tuple_reassigned_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_tuple_aggregate_field_reassigned_negative_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !tuple_reassigned_user_data_site_ids.is_empty(),
        "tuple aggregate reassignment fixture must bind the originally registered tuple field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_tuple_aggregate_field_reassigned_negative_registration_site",
            &tuple_reassigned_user_data_site_ids,
        ),
        "tuple whole-object aggregate reassignment must clear the stale registered field before wrapper release"
    );
    let option_reassigned_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_option_field_reassigned_negative_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !option_reassigned_user_data_site_ids.is_empty(),
        "Option reassignment fixture must bind the originally registered Some field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_option_field_reassigned_negative_registration_site",
            &option_reassigned_user_data_site_ids,
        ),
        "Option reassignment must not release-proof the stale registered Some field"
    );
    let result_ok_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_result_ok_field_release_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !result_ok_user_data_site_ids.is_empty(),
        "Result::Ok fixture must bind the registered success field"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_result_ok_field_release_registration_site",
            &result_ok_user_data_site_ids,
        ),
        "Result::Ok field unwrap must preserve same raw-pointer release proof"
    );
    let helper_result_ok_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_helper_return_result_ok_field_release_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !helper_result_ok_user_data_site_ids.is_empty(),
        "helper-returned Result::Ok fixture must bind the registered success field"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_helper_return_result_ok_field_release_registration_site",
            &helper_result_ok_user_data_site_ids,
        ),
        "same-crate helper-returned Result::Ok must preserve same raw-pointer release proof"
    );
    let result_err_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_result_err_field_negative_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !result_err_user_data_site_ids.is_empty(),
        "Result::Err negative fixture must still bind the explicitly registered pointer"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_result_err_field_negative_registration_site",
            &result_err_user_data_site_ids,
        ),
        "Result::Err field unwrap must not be treated as the supported success holder"
    );
    let boxed_holder_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_boxed_holder_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !boxed_holder_user_data_site_ids.is_empty(),
        "Box-owned holder fixture must bind the registered unique-owner field"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "user_data_boxed_holder_release_wrapper_registration_site",
            &boxed_holder_user_data_site_ids,
        ),
        "Box-owned holder field release wrapper must preserve same raw-pointer release endpoint"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_boxed_holder_release_wrapper_registration_site",
            &boxed_holder_user_data_site_ids,
        ),
        "Box-owned holder release keeps CFG coverage conservative because registration unwind can drop the owner before the wrapper call"
    );
    let boxed_pair_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_boxed_pair_different_field_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !boxed_pair_user_data_site_ids.is_empty(),
        "Box-owned pair fixture must bind the registered unique-owner field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_boxed_pair_different_field_release_wrapper_registration_site",
            &boxed_pair_user_data_site_ids,
        ),
        "Box-owned sibling field release must not cover the registered field"
    );
    let arc_holder_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_arc_holder_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !arc_holder_user_data_site_ids.is_empty(),
        "Arc-owned holder fixture must bind the registered shared-owner field"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "user_data_arc_holder_release_wrapper_registration_site",
            &arc_holder_user_data_site_ids,
        ),
        "Arc-owned holder field release wrapper must preserve same raw-pointer release endpoint"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_arc_holder_release_wrapper_registration_site",
            &arc_holder_user_data_site_ids,
        ),
        "Arc-owned holder release keeps CFG coverage conservative; the shared-owner deref endpoint is evidence, not full release coverage proof"
    );
    let arc_clone_holder_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_arc_clone_holder_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !arc_clone_holder_user_data_site_ids.is_empty(),
        "Arc::clone holder fixture must bind the registered shared-owner field"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "user_data_arc_clone_holder_release_wrapper_registration_site",
            &arc_clone_holder_user_data_site_ids,
        ),
        "Arc::clone must preserve the same raw-pointer holder field for the release endpoint"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_arc_clone_holder_release_wrapper_registration_site",
            &arc_clone_holder_user_data_site_ids,
        ),
        "Arc::clone release remains CFG-conservative and must not be upgraded to full release coverage proof"
    );
    let arc_pair_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_arc_pair_different_field_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !arc_pair_user_data_site_ids.is_empty(),
        "Arc-owned pair fixture must bind the registered shared-owner field"
    );
    assert!(
        !has_from_raw_for_symbol_objects(
            &facts,
            "user_data_arc_pair_different_field_release_wrapper_registration_site",
            &arc_pair_user_data_site_ids,
        ),
        "Arc-owned sibling field release must not be attributed to the registered field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_arc_pair_different_field_release_wrapper_registration_site",
            &arc_pair_user_data_site_ids,
        ),
        "Arc-owned sibling field release must not cover the registered field"
    );
    let arc_clone_pair_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_arc_clone_pair_different_field_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !arc_clone_pair_user_data_site_ids.is_empty(),
        "Arc::clone pair fixture must bind the registered shared-owner field"
    );
    assert!(
        !has_from_raw_for_symbol_objects(
            &facts,
            "user_data_arc_clone_pair_different_field_release_wrapper_registration_site",
            &arc_clone_pair_user_data_site_ids,
        ),
        "Arc::clone sibling field release must not be attributed to the registered field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_arc_clone_pair_different_field_release_wrapper_registration_site",
            &arc_clone_pair_user_data_site_ids,
        ),
        "Arc::clone sibling field release must not cover the registered field"
    );
    let rc_holder_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_rc_holder_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !rc_holder_user_data_site_ids.is_empty(),
        "Rc-owned holder fixture must bind the registered shared-owner field"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "user_data_rc_holder_release_wrapper_registration_site",
            &rc_holder_user_data_site_ids,
        ),
        "Rc-owned holder field release wrapper must preserve same raw-pointer release endpoint"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_rc_holder_release_wrapper_registration_site",
            &rc_holder_user_data_site_ids,
        ),
        "Rc-owned holder release keeps CFG coverage conservative; the shared-owner deref endpoint is evidence, not full release coverage proof"
    );
    let rc_clone_holder_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_rc_clone_holder_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !rc_clone_holder_user_data_site_ids.is_empty(),
        "Rc::clone holder fixture must bind the registered shared-owner field"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "user_data_rc_clone_holder_release_wrapper_registration_site",
            &rc_clone_holder_user_data_site_ids,
        ),
        "Rc::clone must preserve the same raw-pointer holder field for the release endpoint"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_rc_clone_holder_release_wrapper_registration_site",
            &rc_clone_holder_user_data_site_ids,
        ),
        "Rc::clone release remains CFG-conservative and must not be upgraded to full release coverage proof"
    );
    let nonnull_holder_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_nonnull_holder_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !nonnull_holder_user_data_site_ids.is_empty(),
        "NonNull holder fixture must bind the registered field"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "user_data_nonnull_holder_release_wrapper_registration_site",
            &nonnull_holder_user_data_site_ids,
        ),
        "NonNull holder field release wrapper must preserve same raw-pointer release endpoint"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_nonnull_holder_release_wrapper_registration_site",
            &nonnull_holder_user_data_site_ids,
        ),
        "NonNull holder release wrapper has no owner-drop unwind edge and may produce an exact release path proof"
    );
    let nonnull_pair_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_nonnull_pair_different_field_release_wrapper_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !nonnull_pair_user_data_site_ids.is_empty(),
        "NonNull pair fixture must bind the registered field"
    );
    assert!(
        !has_from_raw_for_symbol_objects(
            &facts,
            "user_data_nonnull_pair_different_field_release_wrapper_registration_site",
            &nonnull_pair_user_data_site_ids,
        ),
        "NonNull sibling field release must not be attributed to the registered field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_nonnull_pair_different_field_release_wrapper_registration_site",
            &nonnull_pair_user_data_site_ids,
        ),
        "NonNull sibling field release must not cover the registered field"
    );
    let boxed_reassigned_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "user_data_boxed_holder_reassigned_negative_registration_site",
        "api:rusqlite:set_callback_with_user_data:register",
    );
    assert!(
        !boxed_reassigned_user_data_site_ids.is_empty(),
        "Box-owned reassignment fixture must bind the originally registered field"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "user_data_boxed_holder_reassigned_negative_registration_site",
            &boxed_reassigned_user_data_site_ids,
        ),
        "Box-owned whole-object reassignment must clear the stale registered field before wrapper release"
    );
    let receiver_method_user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::IntoRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_receiver_method_release_registration_site")
                }) =>
            {
                Some(transfer.user_data_site_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !receiver_method_user_data_site_ids.is_empty(),
        "receiver-method release fixture must emit a source-scoped into_raw user-data identity"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:set_callback_with_user_data:register"
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_receiver_method_release_registration_site")
                })
                && registration
                    .user_data_site_id
                    .as_ref()
                    .is_some_and(|site_id| receiver_method_user_data_site_ids.contains(site_id))
        )),
        "a registered raw pointer stored in a holder field must bind before the receiver-method release"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::FromRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_receiver_method_release_registration_site")
                })
                && receiver_method_user_data_site_ids.contains(&transfer.user_data_site_id)
        )),
        "a receiver-method release wrapper call must bind the caller user-data to a release endpoint"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_receiver_method_release_registration_site")
                })
                && receiver_method_user_data_site_ids.contains(&proof.object_site_id)
        )),
        "a receiver-method release wrapper that postdominates registration must emit a CFG path proof"
    );
    let different_field_receiver_registered_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:set_callback_with_user_data:register"
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_different_field_receiver_method_registration_site")
                }) =>
            {
                registration.user_data_site_id.clone()
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !different_field_receiver_registered_site_ids.is_empty(),
        "different-field receiver method fixture must bind the registered field"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref.symbol_path.as_deref().is_some_and(|path| {
                path.ends_with("user_data_different_field_receiver_method_registration_site")
            })
                && different_field_receiver_registered_site_ids.contains(&proof.object_site_id)
        )),
        "a receiver method that releases a different field must not emit a release path proof"
    );
    let conditional_wrapper_user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::IntoRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_conditional_release_wrapper_registration_site")
                }) =>
            {
                Some(transfer.user_data_site_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !conditional_wrapper_user_data_site_ids.is_empty(),
        "conditional release wrapper fixture must emit a source-scoped into_raw user-data identity"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("user_data_conditional_release_wrapper_registration_site")
                })
                && conditional_wrapper_user_data_site_ids.contains(&proof.object_site_id)
        )),
        "a conditional release wrapper must not emit a release path proof"
    );
    let local_same_name_user_data_site_ids = facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::IntoRaw
                && source_ref.symbol_path.as_deref().is_some_and(|path| {
                    path.ends_with("local_sqlite3_update_hook_same_name_site")
                }) =>
            {
                Some(transfer.user_data_site_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !local_same_name_user_data_site_ids.is_empty(),
        "local same-name fixture must still emit a source-scoped into_raw user-data identity"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == "api:rusqlite:update_hook:register"
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("local_sqlite3_update_hook_same_name_site"))
        )),
        "a local same-name sqlite3_update_hook function must not be treated as SQLite FFI registration"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref
                .symbol_path
                .as_deref()
                .is_some_and(|path| path.ends_with("local_sqlite3_update_hook_same_name_site"))
                && local_same_name_user_data_site_ids.contains(&proof.object_site_id)
        )),
        "release proof must not be inferred from a registration that was rejected as local same-name"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(_),
                ..
            } if source_ref
                .symbol_path
                .as_deref()
                .is_some_and(|path| path.ends_with("user_data_branch_without_proven_release_registration_site"))
        )),
        "a release endpoint that a branch can bypass must not be emitted as a release path proof"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact.payload,
            StaticFact::RegistrationSite(ref registration)
                if registration.role == RegistrationRole::Unregister
                    && registration.api_id == "api:rusqlite:update_hook:unregister"
        )),
        "an explicit None callback must be classified as unregister, not register"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(_),
                ..
            } if source_ref
                .symbol_path
                .as_deref()
                .is_some_and(|path| path.ends_with("update_hook_forwarded_callback"))
        )),
        "an unresolved forwarded callback must not be classified as unregister"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(_),
                ..
            } if source_ref
                .symbol_path
                .as_deref()
                .is_some_and(|path| path.ends_with("unrelated_update_hook_site"))
        )),
        "an API-map entry must not classify a same-crate, same-method-name call with a different Rust path"
    );
    let callback_site_ids = facts
        .iter()
        .filter_map(|fact| match &fact.payload {
            StaticFact::CallbackSite(callback) => Some(callback.site_id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        facts.iter().any(|fact| matches!(
            fact.payload,
            StaticFact::RegistrationSite(ref registration)
                if registration.api_id == "api:rusqlite:update_hook:register"
                    && registration
                        .callback_site_id
                        .as_ref()
                        .is_some_and(|site_id| callback_site_ids.contains(site_id))
        )),
        "registration facts must bind a closure argument to an emitted callback site"
    );
    let named_callback_site_ids = facts
        .iter()
        .filter_map(|fact| match &fact.payload {
            StaticFact::CallbackSite(callback)
                if callback.def_path.ends_with("named_update_callback") =>
            {
                Some(callback.site_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        !named_callback_site_ids.is_empty()
            && facts.iter().any(|fact| matches!(
                fact.payload,
                StaticFact::RegistrationSite(ref registration)
                    if registration.api_id == "api:rusqlite:update_hook:register"
                        && registration
                            .callback_site_id
                            .as_ref()
                            .is_some_and(|site_id| named_callback_site_ids.contains(site_id))
            )),
        "registration facts must also bind a named function callback"
    );
    let captured_object_site_ids = facts
        .iter()
        .filter_map(|fact| match &fact.payload {
            StaticFact::CallbackCapture(capture) => Some(capture.object_site_id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert!(
        facts.iter().any(|fact| matches!(
            fact.payload,
            StaticFact::DropSite(ref drop) if captured_object_site_ids.contains(&drop.object_site_id)
        )),
        "dropping a closure must preserve the captured owner identity"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact.payload,
            StaticFact::ExternalCallSite(ref external)
                if external.role == ExternalCallRole::Invoke
                    && external.api_id == "api:rusqlite:callback:invoke"
        )),
        "callback trampoline invoke should be classified"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowRelation(relation),
                ..
            } if relation.api_id.ends_with("returned_borrow_relation_site")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("returned_borrow_relation_site"))
        )),
        "a returned reference tied to an input owner must emit a returned-borrow relation fact"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ExternalBufferBinding(binding),
                ..
            } if binding.api_id.ends_with("external_buffer_binding_site")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("external_buffer_binding_site"))
        )),
        "a returned buffer that stores an input borrow-derived pointer must emit an external-buffer binding fact"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ExternalBufferBinding(binding),
                ..
            } if binding.api_id.ends_with("foreign_selector_unbound_returned_buffer_site")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("foreign_selector_unbound_returned_buffer_site"))
        )),
        "a foreign selector that writes an output pointer returned as a borrowed buffer must emit an external-buffer binding fact"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ExternalBufferBinding(binding),
                ..
            } if binding.api_id.ends_with("foreign_selector_bound_returned_buffer_site")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("foreign_selector_bound_returned_buffer_site"))
        )),
        "a lifetime-bound foreign selector wrapper must still emit the neutral external-buffer binding fact"
    );

    let actual = normalized_mir_lines(&facts);
    let expected = read_expected_lines(&repo.join("fixtures/compiler/mir-sites.expected.jsonl"));
    if expected != actual {
        let first_difference = expected
            .iter()
            .zip(actual.iter())
            .position(|(left, right)| left != right)
            .unwrap_or_else(|| expected.len().min(actual.len()));
        eprintln!(
            "normalized MIR mismatch: expected_len={} actual_len={} first_difference={}",
            expected.len(),
            actual.len(),
            first_difference
        );
        eprintln!(
            "expected_at_diff={:?}",
            expected.get(first_difference).map(String::as_str)
        );
        eprintln!(
            "actual_at_diff={:?}",
            actual.get(first_difference).map(String::as_str)
        );
    }
    assert_eq!(expected, actual);
}

#[test]
fn object_flow_fixture_emits_minimal_shared_object_flows() {
    let repo = repo_root();
    let fixture = repo.join("benchmarks/compiler-fixtures/callback-sites/Cargo.toml");
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let analysis_dir = temp.path().join("analysis");
    let target_dir = temp.path().join("target");
    fs::create_dir(&analysis_dir).expect("analysis dir should be created");
    let config = temp.path().join("bw-rustc-config.json");
    fs::write(
        &config,
        serde_json::json!({
            "output_dir": analysis_dir,
            "allowlist": [
                { "crate_name": "rusqlite", "target": "lib" }
            ]
        })
        .to_string(),
    )
    .expect("config should be written");

    let status = Command::new("cargo")
        .args(["check", "--manifest-path"])
        .arg(&fixture)
        .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_bw-rustc"))
        .env("BW_RUSTC_CONFIG", &config)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status()
        .expect("cargo check should run");
    assert!(status.success(), "fixture cargo check failed: {status}");

    let facts = read_static_facts(&analysis_dir.join("static-facts.jsonl"));
    assert!(
        facts
            .iter()
            .any(|fact| matches!(fact.payload, StaticFact::ObjectFlow(_))),
        "compiler must emit at least one minimal ObjectFlow fact"
    );
    assert!(
        has_release_proof_object_flow_for_symbol(&facts, "HookFieldState::install_update_hook"),
        "same-field state-machine release proof must produce a static-site ObjectFlow chain edge"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "HookFieldState::install_update_hook",
            bw_model::ObjectFlowKind::FieldStore,
            Some("registration:user_data"),
        ),
        "same-field release proof must express registration state storing the registered user_data"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "HookFieldState::install_update_hook",
            bw_model::ObjectFlowKind::FieldStore,
            Some("hook_release_slot:rusqlite:update_hook:field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "HookFieldState::install_update_hook",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("hook_release_slot:rusqlite:update_hook:field:0"),
        ),
        "state-machine release proof must carry exact same receiver release-slot field ObjectFlow"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "HookFieldState::install_update_hook_wrong_field",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("hook_release_slot:rusqlite:update_hook:field:1"),
        ),
        "wrong release field must not produce an update-hook release-slot ObjectFlow chain"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_field_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("field:0"),
        ),
        "storing compiler-proven user_data into holder.user_data must emit a field_store ObjectFlow"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_field_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("field:0"),
        ),
        "loading compiler-proven user_data from holder.user_data must emit a field_load ObjectFlow"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_passthrough_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            None,
        ),
        "a local raw-pointer passthrough wrapper must emit a wrapper_move ObjectFlow"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            None,
        ),
        "passing compiler-proven user_data into an unconditional local release wrapper must emit wrapper_move"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            None,
        ),
        "an unconditional local release wrapper must emit a wrapper_destructure ObjectFlow"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "a holder-field release wrapper must emit field-scoped wrapper_move and wrapper_destructure ObjectFlow"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_aggregate_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_aggregate_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_aggregate_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_aggregate_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ) && has_release_proof_object_flow_for_symbol(
            &facts,
            "user_data_aggregate_field_release_wrapper_registration_site",
        ),
        "an ADT aggregate holder-field release must preserve field:0 object identity through store/load/wrapper release"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ) && has_release_proof_object_flow_for_symbol(
            &facts,
            "user_data_helper_return_field_release_wrapper_registration_site",
        ),
        "a local helper-returned ADT holder must preserve field:0 identity through helper return, registration, and release"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_nested_aggregate_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("field:0.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_nested_aggregate_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("field:0.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_nested_aggregate_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_nested_aggregate_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0.field:0"),
        ) && has_release_proof_object_flow_for_symbol(
            &facts,
            "user_data_nested_aggregate_field_release_wrapper_registration_site",
        ),
        "a nested ADT aggregate holder-field release must preserve field:0.field:0 identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_nested_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("field:0.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_nested_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("field:0.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_nested_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_nested_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0.field:0"),
        ) && has_release_proof_object_flow_for_symbol(
            &facts,
            "user_data_helper_return_nested_field_release_wrapper_registration_site",
        ),
        "a helper-returned nested ADT holder must preserve field:0.field:0 identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_tuple_aggregate_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_tuple_aggregate_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_tuple_aggregate_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_tuple_aggregate_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ) && has_release_proof_object_flow_for_symbol(
            &facts,
            "user_data_tuple_aggregate_field_release_wrapper_registration_site",
        ),
        "a tuple aggregate holder-field release must preserve field:0 identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_tuple_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_tuple_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_tuple_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_tuple_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ) && has_release_proof_object_flow_for_symbol(
            &facts,
            "user_data_helper_return_tuple_field_release_wrapper_registration_site",
        ),
        "a helper-returned tuple holder must preserve field:0 identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_option_field_release_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_option_field_release_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("field:0"),
        ),
        "an Option::Some holder-field release must preserve field:0 store/load identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_option_field_release_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_option_field_release_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("field:0"),
        ),
        "a helper-returned Option::Some holder must preserve field:0 store/load identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_result_ok_field_release_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_result_ok_field_release_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("field:0"),
        ),
        "a Result::Ok holder-field release must preserve field:0 store/load identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_result_ok_field_release_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_result_ok_field_release_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("field:0"),
        ),
        "a helper-returned Result::Ok holder must preserve field:0 store/load identity"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "user_data_result_err_field_negative_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("field:0"),
        ),
        "Result::Err field unwrap must remain outside the Result::Ok holder binding"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_boxed_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_boxed_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_boxed_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("deref.field:0"),
        ),
        "Box-owned holder release wrapper must preserve unique-owner store, field load and wrapper destructure identity"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "user_data_boxed_pair_different_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("deref.field:0"),
        ),
        "Box-owned sibling field release wrapper must not emit deref.field:0 wrapper_destructure"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_arc_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_arc_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_arc_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_arc_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("deref.field:0"),
        ),
        "Arc-owned holder release wrapper must preserve shared-owner store, field load and wrapper destructure identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_arc_clone_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_arc_clone_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_arc_clone_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_arc_clone_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("deref.field:0"),
        ),
        "Arc::clone holder release wrapper must preserve cloned shared-owner field identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_rc_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_rc_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_rc_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_rc_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("deref.field:0"),
        ),
        "Rc-owned holder release wrapper must preserve shared-owner store, field load and wrapper destructure identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_rc_clone_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_rc_clone_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_rc_clone_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_rc_clone_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("deref.field:0"),
        ),
        "Rc::clone holder release wrapper must preserve cloned shared-owner field identity"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "user_data_arc_pair_different_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_arc_pair_different_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("deref.field:1"),
        ),
        "Arc-owned sibling field release wrapper must remain field-specific and must not emit deref.field:0 wrapper_destructure"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "user_data_arc_clone_pair_different_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("deref.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_arc_clone_pair_different_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("deref.field:1"),
        ),
        "Arc::clone sibling field release wrapper must remain field-specific and must not emit deref.field:0 wrapper_destructure"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_nonnull_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldStore,
            Some("field:0.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_nonnull_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::FieldLoad,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_nonnull_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_nonnull_holder_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0.field:0"),
        ),
        "NonNull holder release wrapper must preserve constructor, as_ptr and wrapper destructure identity"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "user_data_nonnull_pair_different_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0.field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_nonnull_pair_different_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:1.field:0"),
        ),
        "NonNull sibling field release wrapper must remain field-specific and must not emit field:0.field:0 wrapper_destructure"
    );
    assert!(
        !has_release_proof_object_flow_for_symbol(
            &facts,
            "user_data_boxed_holder_reassigned_negative_registration_site",
        ),
        "Box-owned whole-object reassignment must not leave a stale release-proof ObjectFlow chain"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "user_data_aggregate_different_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "an ADT aggregate different-field release wrapper must not emit field:0 wrapper_destructure for the registered field"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "user_data_helper_return_different_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "a local helper-returned pair holder that releases a sibling field must not emit field:0 wrapper_destructure"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "user_data_nested_aggregate_different_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0.field:0"),
        ),
        "a nested ADT aggregate different-field release wrapper must not emit field:0.field:0 wrapper_destructure"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "user_data_tuple_aggregate_different_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "a tuple aggregate different-field release wrapper must not emit field:0 wrapper_destructure"
    );
    assert!(
        !has_release_proof_object_flow_for_symbol(
            &facts,
            "user_data_aggregate_field_reassigned_negative_registration_site",
        ),
        "ADT aggregate whole-object reassignment must not leave a stale release-proof ObjectFlow chain"
    );
    assert!(
        !has_release_proof_object_flow_for_symbol(
            &facts,
            "user_data_helper_return_field_reassigned_negative_registration_site",
        ),
        "local helper-return whole-object reassignment must not leave a stale release-proof ObjectFlow chain"
    );
    assert!(
        !has_release_proof_object_flow_for_symbol(
            &facts,
            "user_data_nested_aggregate_field_reassigned_negative_registration_site",
        ),
        "nested ADT aggregate whole-object reassignment must not leave a stale release-proof ObjectFlow chain"
    );
    assert!(
        !has_release_proof_object_flow_for_symbol(
            &facts,
            "user_data_tuple_aggregate_field_reassigned_negative_registration_site",
        ),
        "tuple aggregate whole-object reassignment must not leave a stale release-proof ObjectFlow chain"
    );
    assert!(
        !has_release_proof_object_flow_for_symbol(
            &facts,
            "user_data_option_field_reassigned_negative_registration_site",
        ),
        "Option reassignment must not leave a stale release-proof ObjectFlow chain"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "user_data_different_field_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "a different-field release wrapper must not emit field:0 wrapper_destructure for the registered field"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "user_data_receiver_method_release_registration_site",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "user_data_receiver_method_release_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "a receiver-method field release wrapper must emit field-scoped wrapper ObjectFlow"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "user_data_different_field_receiver_method_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "a receiver method that releases a different field must not emit field:0 wrapper_destructure"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "user_data_conditional_release_wrapper_registration_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            None,
        ),
        "a conditional release wrapper must not emit wrapper_destructure ObjectFlow"
    );
    assert!(
        !has_release_proof_object_flow_for_symbol(
            &facts,
            "HookFieldState::install_update_hook_wrong_field"
        ),
        "different-field state-machine negative must not produce a release-proof ObjectFlow chain edge"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "HookFieldState::install_update_hook_wrong_field",
            bw_model::ObjectFlowKind::FieldStore,
            Some("registration:user_data"),
        ),
        "different-field negative must not synthesize a registration-store ObjectFlow without release proof"
    );
    assert!(
        !has_release_proof_object_flow_for_symbol(
            &facts,
            "user_data_conditional_release_wrapper_registration_site"
        ),
        "conditional release wrapper negative must not produce a release-proof ObjectFlow chain edge"
    );
}

#[test]
fn diesel_site_fixture_emits_crate_local_destructor_release_proof() {
    let repo = repo_root();
    let fixture = repo.join("benchmarks/compiler-fixtures/diesel-sites/Cargo.toml");
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let analysis_dir = temp.path().join("analysis");
    let target_dir = temp.path().join("target");
    fs::create_dir(&analysis_dir).expect("analysis dir should be created");
    let config = temp.path().join("bw-rustc-config.json");
    fs::write(
        &config,
        serde_json::json!({
            "output_dir": analysis_dir,
            "allowlist": [
                { "crate_name": "diesel", "target": "lib" }
            ]
        })
        .to_string(),
    )
    .expect("config should be written");

    let status = Command::new("cargo")
        .args(["check", "--manifest-path"])
        .arg(&fixture)
        .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_bw-rustc"))
        .env("BW_RUSTC_CONFIG", &config)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status()
        .expect("cargo check should run");
    assert!(status.success(), "fixture cargo check failed: {status}");

    let facts = read_static_facts(&analysis_dir.join("static-facts.jsonl"));
    let user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "register_sql_function_site",
        "api:diesel:sqlite3_create_function_v2:register",
    );
    assert!(
        !user_data_site_ids.is_empty(),
        "Diesel crate-local sqlite3_create_function_v2 must bind exact user-data"
    );
    assert!(
        has_from_raw_for_symbol_objects(&facts, "register_sql_function_site", &user_data_site_ids),
        "Diesel destructor must emit a FromRaw fact for the registered user-data"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "register_sql_function_site",
            &user_data_site_ids
        ),
        "Diesel destructor must emit a release path proof for the registered user-data"
    );
    let drop_impl_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "register_sql_function_drop_impl_release_site",
        "api:diesel:sqlite3_create_function_v2:register",
    );
    assert!(
        !drop_impl_user_data_site_ids.is_empty(),
        "Drop impl release fixture must bind registered user-data"
    );
    assert!(
        has_from_raw_for_symbol_objects(
            &facts,
            "register_sql_function_drop_impl_release_site",
            &drop_impl_user_data_site_ids,
        ),
        "unconditional Drop impl field release must emit a FromRaw fact for the registered user-data"
    );
    assert!(
        has_release_path_proof_for_symbol_objects(
            &facts,
            "register_sql_function_drop_impl_release_site",
            &drop_impl_user_data_site_ids,
        ),
        "unconditional Drop impl field release must emit a release path proof for registered user-data"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "register_sql_function_drop_impl_release_site",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "register_sql_function_drop_impl_release_site",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "unconditional Drop impl field release must emit a wrapper move/destructure ObjectFlow pair for the registered field"
    );
    let wrong_field_drop_impl_user_data_site_ids = registration_user_data_site_ids(
        &facts,
        "register_sql_function_wrong_field_drop_impl_release_site",
        "api:diesel:sqlite3_create_function_v2:register",
    );
    assert!(
        !wrong_field_drop_impl_user_data_site_ids.is_empty(),
        "wrong-field Drop impl fixture must still bind registered user-data"
    );
    assert!(
        !has_release_path_proof_for_symbol_objects(
            &facts,
            "register_sql_function_wrong_field_drop_impl_release_site",
            &wrong_field_drop_impl_user_data_site_ids,
        ),
        "Drop impl releasing a different field must not cover the registered user-data"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowRelation(relation),
                ..
            } if relation.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("Statement::field_name"))
        )),
        "Diesel sqlite3_column_name borrowed CStr view must emit a returned-borrow relation"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::PersistedReturnedBorrow(persisted),
                ..
            } if persisted.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("NamedStatementIterator") && path.ends_with("::new")
                    })
        )),
        "Persisting a borrowed sqlite column-name view into collection storage must emit a persisted returned-borrow fact"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("NamedStatementIterator")
                            && path.ends_with("::step_then_lookup")
                    })
        )),
        "HashMap::insert/get with a dynamic key must not prove the same returned-borrow element"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "NamedStatementIterator::<'a>::step_then_lookup",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "dynamic-key HashMap lookup must not emit collection_load ObjectFlow from base map matching"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::PersistedReturnedBorrow(persisted),
                ..
            } if persisted.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("ConstKeyMapIterator")
                            && path.ends_with("::populate_column_names")
                    })
        )),
        "HashMap::insert with a const key and returned view value must emit persisted returned-borrow storage"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("ConstKeyMapIterator")
                            && path.ends_with("::step_then_first")
                    })
                && order.ordering
                    == bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse
        )),
        "same const-key HashMap::insert/get must preserve returned-borrow entry identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "ConstKeyMapIterator::<'a>::step_then_first",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same const-key HashMap lookup must emit collection_load ObjectFlow"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("ConstKeyMapIterator")
                            && path.ends_with("::step_then_other")
                    })
        )),
        "different const-key HashMap lookup must not match the persisted returned-borrow entry"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "ConstKeyMapIterator::<'a>::step_then_other",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "different const-key HashMap lookup must not emit collection_load ObjectFlow"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("SameLocalKeyMapIterator")
                            && path.ends_with("::cache_then_step_lookup")
                    })
                && order.ordering
                    == bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse
        )),
        "same owner-body dynamic HashMap key local must preserve returned-borrow entry identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "SameLocalKeyMapIterator::<'a>::cache_then_step_lookup",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same owner-body dynamic HashMap key local must emit collection_load ObjectFlow"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("SameLocalKeyMapIterator")
                            && path.ends_with("::cache_then_step_other")
                    })
        )),
        "different dynamic HashMap key locals must not preserve returned-borrow entry identity"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "SameLocalKeyMapIterator::<'a>::cache_then_step_other",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "different dynamic HashMap key locals must not emit collection_load ObjectFlow"
    );
    for symbol in [
        "BorrowEquivalentKeyMapIterator::<'a>::cache_owned_key_then_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_string_key_then_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_from_key_then_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_key_then_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_then_step_helper_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_then_step_nested_helper_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_remove_other_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_nested_remove_other_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_replace_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_replace_returned_via_helper_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_insert_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_insert_entry_get_mut_assignment_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_match_slot_assignment_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_match_returned_slot_helper_assignment_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_match_returned_slot_helper_assignment_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_helper_slot_assignment_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_helper_slot_assignment_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_return_helper_and_modify_or_insert_with_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_return_helper_and_modify_or_insert_with_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_return_helper_match_insert_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_return_helper_match_insert_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_and_modify_or_insert_with_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_if_else_entry_and_modify_or_insert_with_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_split_entry_and_modify_or_insert_with_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_slot_assignment_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_match_both_insert_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_nested_entry_match_both_insert_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_empty_helper_entry_insert_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_or_insert_preserves_existing_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_empty_entry_or_insert_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_empty_entry_or_insert_with_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_and_modify_or_insert_same_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_and_modify_or_insert_with_same_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_split_entry_and_modify_or_insert_with_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_and_modify_or_insert_with_key_same_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_and_modify_or_insert_with_if_else_same_return_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_slot_assignment_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_match_slot_assignment_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_match_both_insert_same_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_match_vacant_insert_same_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_match_promote_vacant_insert_entry_slot_assignment_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_match_promote_vacant_insert_entry_slot_assignment_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_insert_entry_replace_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_insert_entry_then_occupied_insert_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_insert_entry_then_get_mut_assignment_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_insert_entry_then_occupied_insert_return_old_step_return",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_match_occupied_insert_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_empty_entry_match_vacant_insert_returned_step_lookup",
    ] {
        assert!(
            facts.iter().any(|fact| matches!(
                fact,
                StaticFactEnvelope {
                    source_ref: Some(source_ref),
                    payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                    ..
                } if order.api_id.ends_with("Statement::field_name")
                    && source_ref
                        .symbol_path
                        .as_deref()
                        .is_some_and(|path| path.ends_with(symbol))
                    && order.ordering
                        == bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse
            )),
            "same owner-body String/&str borrow-equivalent HashMap key must preserve returned-borrow entry identity for {symbol}"
        );
        assert!(
            has_object_flow_for_symbol_kind(
                &facts,
                symbol,
                bw_model::ObjectFlowKind::CollectionLoad,
                None,
            ),
            "same owner-body String/&str borrow-equivalent HashMap key must emit collection_load ObjectFlow for {symbol}"
        );
    }
    for symbol in [
        "HashEquivalentKeyMapIterator::<'a>::cache_newtype_key_then_step_lookup",
        "HashEquivalentKeyMapIterator::<'a>::cache_helper_newtype_key_then_step_lookup",
    ] {
        assert!(
            facts.iter().any(|fact| matches!(
                fact,
                StaticFactEnvelope {
                    source_ref: Some(source_ref),
                    payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                    ..
                } if order.api_id.ends_with("Statement::field_name")
                    && source_ref
                        .symbol_path
                        .as_deref()
                        .is_some_and(|path| path.ends_with(symbol))
                    && order.ordering
                        == bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse
            )),
            "same owner-body hash-equivalent key wrapper must preserve returned-borrow entry identity for {symbol}"
        );
        assert!(
            has_object_flow_for_symbol_kind(
                &facts,
                symbol,
                bw_model::ObjectFlowKind::CollectionLoad,
                None,
            ),
            "same owner-body hash-equivalent key wrapper must emit collection_load ObjectFlow for {symbol}"
        );
    }
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("BorrowEquivalentKeyMapIterator")
                            && path.ends_with("::cache_owned_key_then_step_other")
                    })
        )),
        "different String/&str borrow-equivalent HashMap key sources must not preserve returned-borrow entry identity"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "BorrowEquivalentKeyMapIterator::<'a>::cache_owned_key_then_step_other",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "different String/&str borrow-equivalent HashMap key sources must not emit collection_load ObjectFlow"
    );
    for symbol in [
        "HashEquivalentKeyMapIterator::<'a>::cache_newtype_key_then_step_other",
        "HashEquivalentKeyMapIterator::<'a>::cache_ambiguous_newtype_key_then_step_lookup",
        "HashEquivalentKeyMapIterator::<'a>::cache_salted_newtype_key_then_step_lookup",
        "HashEquivalentKeyMapIterator::<'a>::cache_duplicate_newtype_key_then_step_lookup",
        "HashEquivalentKeyMapIterator::<'a>::cache_manual_hash_newtype_key_then_step_lookup",
    ] {
        assert!(
            facts.iter().all(|fact| !matches!(
                fact,
                StaticFactEnvelope {
                    source_ref: Some(source_ref),
                    payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                    ..
                } if order.api_id.ends_with("Statement::field_name")
                    && source_ref
                        .symbol_path
                        .as_deref()
                        .is_some_and(|path| path.ends_with(symbol))
            )),
            "hash-equivalent key wrapper must not preserve ambiguous, multi-field or different-key returned-borrow identity for {symbol}"
        );
        assert!(
            !has_object_flow_for_symbol_kind(
                &facts,
                symbol,
                bw_model::ObjectFlowKind::CollectionLoad,
                None,
            ),
            "hash-equivalent key wrapper must not emit collection_load for ambiguous, multi-field or different-key source {symbol}"
        );
    }
    for symbol in [
        "HashEquivalentKeyMapIterator::<'a>::cache_ambiguous_newtype_key_then_step_lookup",
        "HashEquivalentKeyMapIterator::<'a>::cache_salted_newtype_key_then_step_lookup",
        "HashEquivalentKeyMapIterator::<'a>::cache_duplicate_newtype_key_then_step_lookup",
        "HashEquivalentKeyMapIterator::<'a>::cache_manual_hash_newtype_key_then_step_lookup",
    ] {
        assert_object_binding_gap_for_symbol(
            &facts,
            symbol,
            ObjectBindingGapKind::KeyContract,
            "key_contract",
            "unsupported hash-equivalent key wrapper must explain the missing key contract",
        );
    }
    assert_object_binding_gap_for_symbol(
        &facts,
        "BorrowEquivalentKeyMapIterator::<'a>::cache_external_helper_lookup_missing_contract_step_lookup",
        ObjectBindingGapKind::KeyContract,
        "cross_crate_collection_lookup",
        "cross-crate collection lookup helper without an audited contract must explain the missing contract",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "BorrowEquivalentKeyMapIterator::<'a>::cache_external_helper_lookup_missing_contract_step_lookup",
        "cross-crate collection lookup helper without contract must not prove returned-borrow use ordering",
    );
    for symbol in [
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_key_then_step_other",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_ambiguous_helper_key_then_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_then_step_helper_lookup_other",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_then_step_nested_helper_lookup_other",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_then_step_ambiguous_helper_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_remove_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_nested_remove_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_nested_remove_ambiguous_key_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_clear_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_nested_clear_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_replace_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_replace_ambiguous_returned_helper_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_helper_entry_insert_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_helper_entry_and_modify_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_insert_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_insert_entry_get_mut_assignment_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_match_slot_assignment_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_match_returned_slot_helper_assignment_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_match_returned_slot_helper_assignment_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_helper_slot_assignment_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_helper_slot_assignment_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_return_helper_and_modify_or_insert_with_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_return_helper_and_modify_or_insert_with_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_return_helper_match_insert_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_return_helper_match_insert_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_and_modify_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_and_modify_or_insert_with_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_helper_entry_and_modify_or_insert_with_value_wrapper_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_split_entry_and_modify_or_insert_with_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_conditional_entry_and_modify_or_insert_with_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_conditional_entry_slot_assignment_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_match_single_vacant_insert_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_nested_entry_match_single_vacant_insert_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_and_modify_replace_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_or_insert_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_or_insert_with_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_match_single_occupied_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_match_single_vacant_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_match_single_vacant_insert_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_match_divergent_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_match_returned_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_match_conditional_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_and_modify_or_insert_with_fallback_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_and_modify_or_insert_with_conditional_return_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_split_entry_and_modify_or_insert_with_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_conditional_entry_slot_assignment_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_match_slot_assignment_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_and_modify_or_insert_with_value_wrapper_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_match_promote_vacant_insert_entry_slot_assignment_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_entry_match_promote_vacant_insert_entry_slot_assignment_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_insert_entry_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_insert_entry_then_occupied_insert_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_insert_entry_then_get_mut_assignment_placeholder_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::cache_entry_match_occupied_insert_placeholder_vacant_returned_step_lookup",
        "BorrowEquivalentKeyMapIterator::<'a>::local_empty_entry_match_occupied_returned_vacant_placeholder_step_lookup",
    ] {
        assert!(
            facts.iter().all(|fact| !matches!(
                fact,
                StaticFactEnvelope {
                    source_ref: Some(source_ref),
                    payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                    ..
                } if order.api_id.ends_with("Statement::field_name")
                    && source_ref
                        .symbol_path
                        .as_deref()
                        .is_some_and(|path| path.ends_with(symbol))
            )),
            "cross-function String/&str key summary must not preserve ambiguous or different-key returned-borrow identity for {symbol}"
        );
        assert!(
            !has_object_flow_for_symbol_kind(
                &facts,
                symbol,
                bw_model::ObjectFlowKind::CollectionLoad,
                None,
            ),
            "cross-function String/&str key summary must not emit collection_load for ambiguous or different-key source {symbol}"
        );
    }
    assert_object_binding_gap_for_symbol(
        &facts,
        "BorrowEquivalentKeyMapIterator::<'a>::local_unknown_entry_and_modify_or_insert_with_value_wrapper_step_lookup",
        ObjectBindingGapKind::MappedValue,
        "entry_value_wrapper",
        "unsupported Entry value wrapper must explain the missing value-transform binding",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "BorrowEquivalentKeyMapIterator::<'a>::local_helper_entry_and_modify_or_insert_with_value_wrapper_step_lookup",
        ObjectBindingGapKind::MappedValue,
        "entry_value_wrapper",
        "same-crate helper Entry value wrapper must explain the missing caller-side value-transform binding",
    );
    for symbol in [
        "SameLocalKeyMapIterator::<'a>::cache_remove_step_lookup",
        "SameLocalKeyMapIterator::<'a>::cache_clear_step_lookup",
        "SameLocalKeyMapIterator::<'a>::cache_replace_step_lookup",
    ] {
        assert!(
            facts.iter().all(|fact| !matches!(
                fact,
                StaticFactEnvelope {
                    source_ref: Some(source_ref),
                    payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                    ..
                } if order.api_id.ends_with("Statement::field_name")
                    && source_ref
                        .symbol_path
                        .as_deref()
                        .is_some_and(|path| path.ends_with(symbol))
            )),
            "keyed map mutation/replacement barrier must prevent stale returned-borrow ordering for {symbol}"
        );
        assert!(
            !has_object_flow_for_symbol_kind(
                &facts,
                symbol,
                bw_model::ObjectFlowKind::CollectionLoad,
                None,
            ),
            "keyed map mutation/replacement barrier must prevent stale collection_load ObjectFlow for {symbol}"
        );
    }
    for symbol in [
        "SameLocalKeyMapIterator::<'a>::cache_remove_step_lookup",
        "SameLocalKeyMapIterator::<'a>::cache_replace_step_lookup",
    ] {
        assert!(
            has_object_binding_gap_for_symbol_kind_adapter_field_path_contains(
                &facts,
                symbol,
                ObjectBindingGapKind::MutationBarrier,
                "returned_borrow_storage_mutation",
                ":map_key:",
            ),
            "exact keyed map mutation/replacement must emit a binding-keyed ObjectBindingGap barrier for {symbol}"
        );
    }
    assert!(
        has_object_binding_gap_for_symbol_kind_adapter_prefix_field_path_contains(
            &facts,
            "SameLocalKeyMapIterator::<'a>::cache_clear_step_lookup",
            ObjectBindingGapKind::MutationBarrier,
            "returned_borrow_storage_prefix_mutation:",
            ":map_key:",
        ),
        "HashMap::clear must emit a map-family mutation barrier diagnostic instead of silently relying on missing collection_load"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("SameLocalKeyMapIterator")
                            && path.ends_with("::cache_remove_return_step_use")
                    })
                && order.ordering
                    == bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse
        )),
        "same-key HashMap::remove return value must preserve the removed returned-borrow entry identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "SameLocalKeyMapIterator::<'a>::cache_remove_return_step_use",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-key HashMap::remove return value used after step must emit collection_load ObjectFlow"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("SameLocalKeyMapIterator")
                            && path.ends_with("::cache_remove_other_return_step_use")
                    })
        )),
        "different-key HashMap::remove return value must not preserve a returned-borrow entry identity"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "SameLocalKeyMapIterator::<'a>::cache_remove_other_return_step_use",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "different-key HashMap::remove return value must not emit collection_load ObjectFlow"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("BorrowEquivalentKeyMapIterator")
                            && path.ends_with("::cache_owned_key_remove_return_step_use")
                    })
                && order.ordering
                    == bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse
        )),
        "String/&str borrow-equivalent HashMap::remove return value must preserve the removed returned-borrow entry identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "BorrowEquivalentKeyMapIterator::<'a>::cache_owned_key_remove_return_step_use",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "String/&str borrow-equivalent HashMap::remove return value used after step must emit collection_load ObjectFlow"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("BorrowEquivalentKeyMapIterator")
                            && path.ends_with("::cache_helper_key_remove_return_step_use")
                    })
                && order.ordering
                    == bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse
        )),
        "cross-function String/&str key summary must preserve HashMap::remove return value identity"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_key_remove_return_step_use",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "cross-function String/&str key summary remove return value used after step must emit collection_load ObjectFlow"
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_remove_return_step_use",
        "same-crate remove-return helper must preserve the removed returned-borrow entry as a local persisted view used after step",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "BorrowEquivalentKeyMapIterator::<'a>::cache_helper_remove_other_return_step_use",
        "same-crate remove-return helper using a transformed key must not be treated as the cached entry",
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("SameLocalKeyMapIterator")
                            && path.ends_with("::cache_replace_returned_step_lookup")
                    })
                && order.ordering
                    == bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse
        )),
        "same-key replacement with a new returned view must track the replacement entry rather than the stale entry"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "SameLocalKeyMapIterator::<'a>::cache_replace_returned_step_lookup",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-key replacement with a new returned view must emit collection_load ObjectFlow for the replacement entry"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::PersistedReturnedBorrow(persisted),
                ..
            } if persisted.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("NamedStatementCollectIterator") && path.ends_with("::new")
                    })
        )),
        "Collecting borrowed sqlite column-name views into HashMap storage must emit a persisted returned-borrow fact"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && order.ordering
                    == bw_model::ReturnedBorrowInvalidationOrdering::PersistenceBeforeInvalidationUse
        )),
        "constructor-collected borrowed sqlite column-name views must emit persistence-before-invalidation ordering"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.contains("::LazyNamedStatementCollectIterator"))
                && order.ordering
                    == bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse
        )),
        "lazy collected borrowed sqlite column-name views must emit invalidation-before-persistence ordering"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.contains("RealisticLazyNamedStatementCollectIterator"))
                && order.ordering
                    == bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse
        )),
        "realistic lazy collected borrowed sqlite column-name views must emit invalidation-before-persistence ordering"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("RealisticLazyNamedStatementCollectIterator")
                            && path.contains(" as ")
                            && path.ends_with("::next::{closure#0}")
                    })
                && order.ordering
                    == bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse
        )),
        "realistic trait-impl lazy collected borrowed sqlite column-name views must emit invalidation-before-persistence ordering"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::PersistedReturnedBorrow(persisted),
                ..
            } if persisted.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("VecLazyNamedStatementCollectIterator")
                            && path.ends_with("::populate_column_names")
                    })
        )),
        "Collecting borrowed sqlite column-name views into Vec storage must emit a persisted returned-borrow fact"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "VecLazyNamedStatementCollectIterator::<'a>::populate_column_names",
            bw_model::ObjectFlowKind::CollectionStore,
            None,
        ),
        "Collecting borrowed sqlite column-name views into Vec storage must emit a collection_store ObjectFlow"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("VecLazyNamedStatementCollectIterator")
                            && path.ends_with("::step_then_first")
                    })
                && order.ordering
                    == bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse
        )),
        "lazy Vec storage use after step must emit invalidation-before-persistence ordering"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "VecLazyNamedStatementCollectIterator::<'a>::step_then_first",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Using the saved Vec column-name view after step must emit a collection_load ObjectFlow"
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "VecLazyNamedStatementCollectIterator::<'a>::step_then_first_as_deref",
        "Option<Vec<_>>::as_deref() should preserve returned-borrow collection identity",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "VecLazyNamedStatementCollectIterator::<'a>::step_then_first_as_deref_if_let",
        "Option<Vec<_>>::as_deref() if-let unwrap should preserve returned-borrow collection identity",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "VecLazyNamedStatementCollectIterator::<'a>::step_then_first_as_deref_helper",
        "same-crate Option<Vec<_>>::as_deref() helper should preserve returned-borrow collection identity",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "VecLazyNamedStatementCollectIterator::<'a>::step_then_first_as_ref_helper",
        "same-crate Option<Vec<_>>::as_ref() helper should preserve returned-borrow collection identity",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "VecLazyNamedStatementCollectIterator::<'a>::step_then_as_deref_discard_helper",
        "same-crate Option<Vec<_>>::as_deref() helper must not prove a use when the closure discards the storage",
    );
    assert!(
        has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_return_field"
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_return_field",
            bw_model::ObjectFlowKind::FieldStore,
            None,
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_return_field",
            bw_model::ObjectFlowKind::FieldLoad,
            None,
        ),
        "reading a field-stored returned view after invalidation should preserve the same storage key and emit field store/load flows",
    );
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_other_then_step_return_field"
        ) && !has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_other_then_step_return_field",
            bw_model::ObjectFlowKind::FieldLoad,
            None,
        ),
        "reading a different field must not satisfy the stored returned-view use ordering proof",
    );
    assert!(
        has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_pass_field_to_helper"
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_pass_field_to_helper",
            bw_model::ObjectFlowKind::FieldStore,
            None,
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_pass_field_to_helper",
            bw_model::ObjectFlowKind::FieldLoad,
            None,
        ),
        "passing a field-stored returned view to a same-crate helper after invalidation should preserve the same storage key and emit field store/load flows",
    );
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_other_then_step_pass_field_to_helper"
        ) && !has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_other_then_step_pass_field_to_helper",
            bw_model::ObjectFlowKind::FieldLoad,
            None,
        ),
        "passing a sibling field to a helper must not satisfy the stored returned-view use ordering proof",
    );
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_discard_field_in_helper"
        ) && !has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_discard_field_in_helper",
            bw_model::ObjectFlowKind::FieldLoad,
            None,
        ),
        "passing a field-stored returned view to a same-crate helper that discards it must not be treated as a proven use",
    );
    assert!(
        has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_wrapper_into_inner"
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_wrapper_into_inner",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_wrapper_into_inner",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "wrapping a returned view in a local single-field wrapper and later into_inner after invalidation should preserve the same object chain",
    );
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_wrapper_into_other"
        ) && !has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_wrapper_into_other",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "destructuring a different wrapper field must not satisfy the returned-view ordering proof",
    );
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_wrapper_discard"
        ) && !has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_wrapper_discard",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "calling a wrapper method that discards the stored view must not be treated as wrapper destructure",
    );
    assert!(
        has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_moved_wrapper_into_inner"
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_moved_wrapper_into_inner",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_moved_wrapper_into_inner",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "moving a local returned-view wrapper to another local before into_inner should preserve wrapper-field object identity",
    );
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_moved_wrapper_into_other"
        ) && !has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_moved_wrapper_into_other",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "moving a wrapper and destructuring a sibling field must not satisfy the returned-view ordering proof",
    );
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_replaced_wrapper_into_inner"
        ) && !has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_replaced_wrapper_into_inner",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "overwriting a local wrapper before into_inner must clear the old wrapper-field object identity",
    );
    assert!(
        has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_take_wrapper_field"
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_take_wrapper_field",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_take_wrapper_field",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "Option::take on the same wrapper field after invalidation should preserve wrapper-field object identity",
    );
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_take_other_wrapper_field"
        ) && !has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_take_other_wrapper_field",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "Option::take on a sibling wrapper field must not satisfy the returned-view ordering proof",
    );
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_rewrite_field_step_take"
        ) && !has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_rewrite_field_step_take",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "overwriting a wrapper field before Option::take must clear the old returned-view identity",
    );
    assert!(
        has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_replace_wrapper_field"
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_replace_wrapper_field",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_then_step_replace_wrapper_field",
            bw_model::ObjectFlowKind::WrapperDestructure,
            Some("field:0"),
        ),
        "mem::replace on the same wrapper field after invalidation should preserve the replaced-out returned-view identity",
    );
    for symbol in [
        "FieldStoredViewIterator::<'a>::cache_then_step_wrapper_take_inner",
        "FieldStoredViewIterator::<'a>::cache_then_step_wrapper_mem_take_inner",
        "FieldStoredViewIterator::<'a>::cache_then_step_wrapper_replace_inner_none",
    ] {
        assert!(
            has_returned_borrow_invalidation_order_for_symbol(&facts, symbol)
                && has_object_flow_for_symbol_kind(
                    &facts,
                    symbol,
                    bw_model::ObjectFlowKind::WrapperMove,
                    Some("field:0"),
                )
                && has_object_flow_for_symbol_kind(
                    &facts,
                    symbol,
                    bw_model::ObjectFlowKind::WrapperDestructure,
                    Some("field:0"),
                ),
            "same-crate wrapper helper must prove mutation destructure of field0 old value for {symbol}",
        );
    }
    assert!(
        has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_take_before_step_then_return_taken",
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_take_before_step_then_return_taken",
            bw_model::ObjectFlowKind::WrapperMove,
            Some("field:0"),
        ) && has_object_flow_for_symbol_kind(
            &facts,
            "FieldStoredViewIterator::<'a>::cache_take_before_step_then_return_taken",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "returned old value taken before invalidation and returned after invalidation should keep a proven order without relabelling the return-local use as wrapper destructure",
    );
    for symbol in [
        "FieldStoredViewIterator::<'a>::cache_then_step_wrapper_take_other",
        "FieldStoredViewIterator::<'a>::cache_then_step_wrapper_take_then_into_inner",
    ] {
        assert!(
            !has_returned_borrow_invalidation_order_for_symbol(&facts, symbol)
                && !has_object_flow_for_symbol_kind(
                    &facts,
                    symbol,
                    bw_model::ObjectFlowKind::WrapperDestructure,
                    Some("field:0"),
                ),
            "same-crate wrapper helper must not preserve stale or sibling-field identity for {symbol}",
        );
    }
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("DualVecStorageIterator")
                            && path.ends_with("::step_then_alias_first")
                    })
        )),
        "using a different collection field must not be linked to the persisted column-name view"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::PersistedReturnedBorrow(persisted),
                ..
            } if persisted.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("BoxedVecLazyNamedStatementCollectIterator")
                            && path.ends_with("::populate_column_names")
                    })
        )),
        "Box<Option<Vec<_>>> storage must keep a deref-scoped persisted returned-borrow key"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("BoxedVecLazyNamedStatementCollectIterator")
                            && path.ends_with("::step_then_first")
                    })
                && order.ordering
                    == bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse
        )),
        "Box-owned collection storage must preserve same-object invalidation/use ordering through a conservative deref key"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "BoxedVecLazyNamedStatementCollectIterator::<'a>::step_then_first",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Box-owned collection storage use after step must emit a collection_load ObjectFlow"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("RawPtrVecStorageIterator")
                            && path.ends_with("::step_then_first")
                    })
        )),
        "raw-pointer-deref collection storage must remain incomplete instead of falling back to file-scope matching"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::PersistedReturnedBorrow(persisted),
                ..
            } if persisted.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("NestedClosureVecLazyIterator")
                            && path.ends_with("::populate_column_names")
                    })
        )),
        "Nested-closure fixture must persist a returned sqlite column-name view before nested use"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("NestedClosureVecLazyIterator")
                            && path.contains("::step_then_nested_self_first::{closure#0}::{closure#0}")
                    })
                && order.ordering
                    == bw_model::ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse
        )),
        "nested closure capture must preserve keyed storage binding through both closure environments"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "NestedClosureVecLazyIterator::<'a>::step_then_nested_self_first::{closure#0}::{closure#0}",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "nested closure use after step must emit a collection_load ObjectFlow"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "SharedOwnerVecIterator::<'a>::clone_column_names_owner",
            bw_model::ObjectFlowKind::WrapperMove,
            None,
        ),
        "Arc::clone on a shared owner must emit a conservative wrapper_move ObjectFlow"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ObjectSite(object),
                ..
            } if object.type_name.contains("Arc<")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.ends_with("SharedOwnerVecIterator::<'a>::clone_column_names_owner")
                    })
        )),
        "Arc::clone ObjectFlow endpoints must remain auditable ObjectSite facts"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("SharedOwnerVecIterator")
                            && path.ends_with("::step_then_first_from_cloned_owner")
                    })
        )),
        "Arc::new + Arc::clone + deref must preserve returned-borrow storage binding to the later use"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "SharedOwnerVecIterator::<'a>::step_then_first_from_cloned_owner",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Arc shared-owner deref use must emit a collection_load ObjectFlow when storage binding is preserved"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("SharedOwnerVecIterator")
                            && path.ends_with("::step_then_first_after_make_mut")
                    })
        )),
        "Arc::make_mut may detach the shared allocation, so it must break the returned-borrow storage binding"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "SharedOwnerVecIterator::<'a>::step_then_first_after_make_mut",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Arc::make_mut negative must not emit collection_load ObjectFlow from stale storage binding"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("InteriorMutableVecIterator")
                            && path.ends_with("::step_then_first_from_borrow")
                    })
        )),
        "RefCell::new + borrow + deref must preserve returned-borrow storage binding for read-only guard use"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "InteriorMutableVecIterator::<'a>::step_then_first_from_borrow",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "read-only RefCell borrow must emit collection_load ObjectFlow when storage binding is preserved"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("InteriorMutableVecIterator")
                            && path.ends_with("::step_then_first_after_borrow_mut")
                    })
        )),
        "RefCell::borrow_mut is a mutation barrier and must break stale returned-borrow storage binding"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "InteriorMutableVecIterator::<'a>::step_then_first_after_borrow_mut",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "RefCell::borrow_mut negative must not emit collection_load ObjectFlow from stale storage binding"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("IndexedVecStorageIterator")
                            && path.ends_with("::step_then_second_after_second_insert")
                    })
        )),
        "exact-index Vec::insert/get on the same index must preserve returned-borrow storage binding"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "IndexedVecStorageIterator::<'a>::step_then_second_after_second_insert",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-index collection use must emit collection_load ObjectFlow"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("IndexedVecStorageIterator")
                            && path.ends_with("::step_then_first_after_second_insert")
                    })
        )),
        "exact-index Vec::insert/get on different indices must not prove same returned-borrow object"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "IndexedVecStorageIterator::<'a>::step_then_first_after_second_insert",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "different-index collection use must not emit stale collection_load ObjectFlow"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("IndexedVecStorageIterator")
                            && path.ends_with("::step_then_dynamic_after_dynamic_insert")
                    })
        )),
        "dynamic Vec::insert/get indices are not a stable same-object binding and must remain incomplete"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "IndexedVecStorageIterator::<'a>::step_then_dynamic_after_dynamic_insert",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "dynamic-index collection use must not emit collection_load ObjectFlow from base collection matching"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("IndexedVecStorageIterator")
                            && path.ends_with("::step_then_range_after_second_insert")
                    })
        )),
        "range Vec::get cannot identify a single returned-borrow element and must remain incomplete"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "IndexedVecStorageIterator::<'a>::step_then_range_after_second_insert",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "range collection use must not emit collection_load ObjectFlow for an exact returned-borrow element"
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_after_second_insert",
        ObjectBindingGapKind::RangeOrSlice,
        "get",
        "range Vec::get should expose the missing single-element object binding",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_second_inner_first_after_second_insert",
        "Vec::get(const range).and_then(slice.get(const)) should map back to the original exact element",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_first_inner_first_after_second_insert",
        "Vec::get(const range).and_then(slice.get(const)) must not match a different original element",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_inclusive_second_inner_first_after_second_insert",
        "Vec::get(const inclusive range).and_then(slice.get(const)) should map back to the original exact element",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_to_second_inner_second_after_second_insert",
        "Vec::get(const RangeTo) followed by slice.get(const) should map back to the original exact element",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_to_last_second_after_second_insert",
        "Vec::get(const bounded range) followed by slice.last() should map back to the original exact element",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_to_inclusive_second_inner_second_after_second_insert",
        "Vec::get(const RangeToInclusive) followed by slice.get(const) should map back to the original exact element",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_to_last_first_after_second_insert",
        "Vec::get(const bounded range) followed by slice.last() must not match a different original element",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_to_first_inner_first_after_second_insert",
        "Vec::get(const RangeTo).and_then(slice.get(const)) must not match a different original element",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_from_second_inner_first_after_second_insert",
        "Vec::get(const RangeFrom) followed by slice.get(const) should map back to the original exact element",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_from_first_inner_first_after_second_insert",
        "Vec::get(const RangeFrom) followed by slice.get(const) must not match a different original element",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_from_last_after_second_insert",
        "Vec::get(RangeFrom).last() must not prove an exact element when sequence length is unknown",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_from_last_after_second_insert",
        ObjectBindingGapKind::SequenceLengthUnknown,
        "last",
        "Vec::get(RangeFrom).last() should expose the missing sequence length proof",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_full_second_inner_second_after_second_insert",
        "Vec::get(RangeFull) followed by slice.get(const) should map back to the original exact element",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_full_last_after_second_insert",
        "Vec::get(RangeFull).last() must not prove an exact element when sequence length is unknown",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_full_last_after_second_insert",
        ObjectBindingGapKind::SequenceLengthUnknown,
        "last",
        "Vec::get(RangeFull).last() should expose the missing sequence length proof",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_full_first_inner_first_after_second_insert",
        "Vec::get(RangeFull) followed by slice.get(const) must not match a different original element",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_from_iter_nth_second_after_second_insert",
        "Vec::get(RangeFrom).iter().nth(const) should map back to the original exact element",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_from_iter_nth_first_after_second_insert",
        "Vec::get(RangeFrom).iter().nth(const) must not match a different original element",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_full_iter_skip_second_after_second_insert",
        "Vec::get(RangeFull).iter().skip(const).next() should map back to the original exact element",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_full_iter_skip_first_after_second_insert",
        "Vec::get(RangeFull).iter().skip(const).next() must not match a different original element",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_full_last_helper_after_second_insert",
        "same-crate RangeFull tail helper must not prove an exact element when caller sequence length is unknown",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "IndexedVecStorageIterator::<'a>::step_then_range_full_last_helper_after_second_insert",
        ObjectBindingGapKind::SequenceLengthUnknown,
        "tail_read",
        "same-crate RangeFull tail helper should expose missing caller sequence length proof",
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with("::step_then_first_after_push")
                    })
        )),
        "Vec::push has no proven element position here and must not match a later get(0)"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_first_after_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "unknown-position Vec::push must not emit collection_load ObjectFlow for get(0)"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with("::step_then_first_after_clear_and_push")
                    })
        )),
        "Vec::clear establishes an empty indexed sequence, so the next push may be matched to get(0)"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_first_after_clear_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "known-empty Vec::push must emit collection_load ObjectFlow for get(0)"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with("::step_then_second_after_clear_and_push")
                    })
        )),
        "known-empty Vec::push must not match a later get(1)"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_second_after_clear_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "known-empty Vec::push must not emit collection_load ObjectFlow for a different index"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_second_after_clear_placeholder_and_push"
                            )
                    })
        )),
        "tracked non-target Vec::push advances the known sequence length, so the next returned borrow may be matched to get(1)"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_second_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "known-length Vec::push must emit collection_load ObjectFlow for the matching later index"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_first_after_clear_placeholder_and_push"
                            )
                    })
        )),
        "known-length Vec::push must not match a later read of the earlier placeholder element"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_first_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "known-length Vec::push must not emit collection_load ObjectFlow for the wrong earlier index"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with("::step_then_first_method_after_clear_and_push")
                    })
        )),
        "Vec::first should be treated as an exact read of element_index:0 when the matching returned borrow is proven at index 0"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_first_method_after_clear_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::first must emit collection_load ObjectFlow for a proven returned borrow at element_index:0"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_first_method_after_clear_placeholder_and_push"
                            )
                    })
        )),
        "Vec::first must not match a returned borrow proven only at element_index:1"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_first_method_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::first must not emit collection_load ObjectFlow for the wrong earlier element"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecDequeStorageIterator")
                            && path.ends_with("::step_then_front_after_clear_and_push_back")
                    })
        )),
        "VecDeque::front should be treated as an exact read of element_index:0 when push_back proves the returned borrow at the front"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecDequeStorageIterator::<'a>::step_then_front_after_clear_and_push_back",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "VecDeque::front must emit collection_load ObjectFlow for a proven returned borrow at element_index:0"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecDequeStorageIterator")
                            && path.ends_with(
                                "::step_then_front_after_clear_placeholder_and_push_back"
                            )
                    })
        )),
        "VecDeque::front must not match a returned borrow proven only at element_index:1"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecDequeStorageIterator::<'a>::step_then_front_after_clear_placeholder_and_push_back",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "VecDeque::front must not emit collection_load ObjectFlow for the wrong earlier element"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_last_after_clear_placeholder_and_push"
                            )
                    })
        )),
        "Vec::last should use the known sequence length to read the proven returned borrow at the final index"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_last_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::last must emit collection_load ObjectFlow when the returned borrow is proven at the final known index"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_last_after_clear_push_and_placeholder"
                            )
                    })
        )),
        "Vec::last must not match a returned borrow that is followed by a later placeholder element"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_last_after_clear_push_and_placeholder",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::last must not emit collection_load ObjectFlow for a non-final returned borrow"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_as_slice_first_after_clear_and_push"
                            )
                    })
        )),
        "Vec::as_slice should preserve storage identity for a later const-index get(0)"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_as_slice_first_after_clear_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::as_slice().get(0) must emit collection_load ObjectFlow for a proven returned borrow at element_index:0"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_as_slice_second_after_clear_placeholder_and_push"
                            )
                    })
        )),
        "Vec::as_slice should preserve storage identity for a later const-index get(1)"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_as_slice_second_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::as_slice().get(1) must emit collection_load ObjectFlow for a proven returned borrow at element_index:1"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_as_slice_first_after_clear_placeholder_and_push"
                            )
                    })
        )),
        "Vec::as_slice().get(0) must not match a returned borrow proven only at element_index:1"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_as_slice_first_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::as_slice().get(0) must not emit collection_load ObjectFlow for the wrong earlier element"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with("::step_then_iter_next_after_clear_and_push")
                    })
        )),
        "Vec::iter().next() should read element_index:0 when the matching returned borrow is proven at the first element"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_next_after_clear_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::iter().next() must emit collection_load ObjectFlow for a proven returned borrow at element_index:0"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_next_after_clear_placeholder_and_push"
                            )
                    })
        )),
        "Vec::iter().next() must not match a returned borrow proven only at element_index:1"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_next_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::iter().next() must not emit collection_load ObjectFlow for the wrong first element"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with("::second_iter_next_after_first_before_step")
                    })
        )),
        "after the first iterator next consumes element_index:0 before invalidation, a later next after invalidation must not be treated as the same returned borrow"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::second_iter_next_after_first_before_step",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "repeated iterator next must not emit collection_load ObjectFlow for an already-consumed first element"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_nth_second_after_clear_placeholder_and_push"
                            )
                    })
        )),
        "Vec::iter().nth(1) should read element_index:1 when the matching returned borrow is proven at the second element"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_nth_second_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::iter().nth(1) must emit collection_load ObjectFlow for a proven returned borrow at element_index:1"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_nth_first_after_clear_placeholder_and_push"
                            )
                    })
        )),
        "Vec::iter().nth(0) must not match a returned borrow proven only at element_index:1"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_nth_first_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::iter().nth(0) must not emit collection_load ObjectFlow for the wrong first element"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_skip_one_next_after_clear_placeholder_and_push"
                            )
                    })
        )),
        "Vec::iter().skip(1).next() should read element_index:1 when the matching returned borrow is proven at the second element"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_skip_one_next_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::iter().skip(1).next() must emit collection_load ObjectFlow for a proven returned borrow at element_index:1"
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_local_const_get_after_clear_placeholder_and_push",
        "Vec::get(local const index) should preserve returned-borrow element identity",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_local_const_nth_after_clear_placeholder_and_push",
        "Vec::iter().nth(local const) should preserve returned-borrow element identity",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_local_const_skip_after_clear_placeholder_and_push",
        "Vec::iter().skip(local const).next() should preserve returned-borrow element identity",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_dynamic_get_after_clear_placeholder_and_push",
        "Vec::get(dynamic) must not prove the same returned-borrow element without an auditable index",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_dynamic_get_after_clear_placeholder_and_push",
        ObjectBindingGapKind::DynamicIndex,
        "get",
        "Vec::get(dynamic) should expose the missing dynamic-index object binding",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_dynamic_nth_after_clear_placeholder_and_push",
        "Vec::iter().nth(dynamic) must not prove the same returned-borrow element without an auditable offset",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_dynamic_nth_after_clear_placeholder_and_push",
        ObjectBindingGapKind::DynamicIndex,
        "nth",
        "Vec::iter().nth(dynamic) should expose the missing dynamic-index object binding",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_dynamic_skip_after_clear_placeholder_and_push",
        "Vec::iter().skip(dynamic).next() must not prove the same returned-borrow element without an auditable offset",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_dynamic_skip_after_clear_placeholder_and_push",
        ObjectBindingGapKind::DynamicIndex,
        "skip",
        "Vec::iter().skip(dynamic).next() should expose the missing dynamic-index object binding",
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_skip_one_next_after_clear_and_push"
                            )
                    })
        )),
        "Vec::iter().skip(1).next() must not match a returned borrow proven only at element_index:0"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_skip_one_next_after_clear_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::iter().skip(1).next() must not emit collection_load ObjectFlow for a skipped returned borrow"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_last_after_clear_placeholder_and_push"
                            )
                    })
        )),
        "Vec::iter().last() should read the known final element when the returned borrow is proven at the tail"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_last_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::iter().last() must emit collection_load ObjectFlow for a proven returned borrow at the known final index"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_last_after_clear_push_and_placeholder"
                            )
                    })
        )),
        "Vec::iter().last() must not match a returned borrow that is followed by a later placeholder element"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_last_after_clear_push_and_placeholder",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::iter().last() must not emit collection_load ObjectFlow for a non-final returned borrow"
    );
    assert!(
        has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "::step_then_iter_rev_next_after_clear_placeholder_and_push",
        ),
        "Vec::iter().rev().next() should read the known final element when the returned borrow is proven at the tail"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_rev_next_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::iter().rev().next() must emit collection_load ObjectFlow for a proven tail returned borrow"
    );
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "::step_then_iter_rev_next_after_clear_push_and_placeholder",
        ),
        "Vec::iter().rev().next() must not match a returned borrow followed by a placeholder"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_rev_next_after_clear_push_and_placeholder",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "Vec::iter().rev().next() must not emit collection_load ObjectFlow for a non-final returned borrow"
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_rev_nth_one_after_clear_push_and_placeholder",
        "Vec::iter().rev().nth(1) should read the proven returned borrow one slot from the tail",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_rev_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().rev().nth(1) must not match a returned borrow that is still at the tail",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_rev_skip_one_next_after_clear_push_and_placeholder",
        "Vec::iter().rev().skip(1).next() should read the proven returned borrow one slot from the tail",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_rev_skip_one_next_after_clear_placeholder_and_push",
        "Vec::iter().rev().skip(1).next() must not match a returned borrow that is still at the tail",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_skip_one_rev_next_after_clear_placeholder_and_push",
        "Vec::iter().skip(1).rev().next() should keep the front skip separate from tail direction",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_skip_one_rev_next_after_clear_push_and_placeholder",
        "Vec::iter().skip(1).rev().next() must not reinterpret the front skip as a tail offset",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_take_two_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().take(2).nth(1) should preserve element identity when the const take bound still includes the returned borrow",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_take_one_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().take(1).nth(1) must not read through a take bound that excludes the returned borrow",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_take_two_last_after_clear_placeholder_and_push",
        "Vec::iter().take(2).last() should read the returned borrow at the end of the bounded front range",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_take_one_last_after_clear_placeholder_and_push",
        "Vec::iter().take(1).last() must not reach the returned borrow outside the bounded front range",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_take_two_rev_next_after_clear_placeholder_and_push",
        "Vec::iter().take(2).rev().next() should read the end of the bounded front range",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_take_one_rev_next_after_clear_placeholder_and_push",
        "Vec::iter().take(1).rev().next() must not reach the returned borrow outside the bounded front range",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_enumerate_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().enumerate().nth(1) should preserve item identity through the index wrapper",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_copied_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().copied().nth(1) should preserve returned-borrow item identity",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_cloned_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().cloned().nth(1) should preserve returned-borrow item identity for Copy reference items",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_identity_map_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().map(identity).nth(1) should preserve returned-borrow item identity when the closure returns its item",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_value_map_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().map(value-transform).nth(1) must remain conservative because the mapped value is not the original item",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_value_map_nth_one_after_clear_placeholder_and_push",
        ObjectBindingGapKind::MappedValue,
        "map",
        "Vec::iter().map(value-transform).nth(1) should expose why object binding was not proven",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_identity_filter_map_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().filter_map(always Some identity).nth(1) should preserve returned-borrow item identity",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_value_filter_map_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().filter_map(value-transform).nth(1) must remain conservative because the mapped value is not the original item",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_value_filter_map_nth_one_after_clear_placeholder_and_push",
        ObjectBindingGapKind::MappedValue,
        "filter_map",
        "Vec::iter().filter_map(value-transform).nth(1) should expose why object binding was not proven",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_filter_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().filter(always true).nth(1) should preserve returned-borrow item identity",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_filter_false_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().filter(always false).nth(1) must remain conservative because predicate selection removes the item",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_filter_false_nth_one_after_clear_placeholder_and_push",
        ObjectBindingGapKind::SelectionPredicate,
        "filter",
        "Vec::iter().filter(always false).nth(1) should expose why object binding was not proven",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_chain_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().chain(...).nth(1) must remain conservative because multiple iterator sources are merged",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_chain_nth_one_after_clear_placeholder_and_push",
        ObjectBindingGapKind::MergedSources,
        "chain",
        "Vec::iter().chain(...).nth(1) should expose why object binding was not proven",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_zip_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().zip(...).nth(1) must remain conservative because tuple item binding is not proven",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_zip_nth_one_after_clear_placeholder_and_push",
        ObjectBindingGapKind::TupleProjection,
        "zip",
        "Vec::iter().zip(...).nth(1) should expose why object binding was not proven",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_flat_map_nth_one_after_clear_placeholder_and_push",
        "Vec::iter().flat_map(...).nth(1) must remain conservative because value/source cardinality is transformed",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_flat_map_nth_one_after_clear_placeholder_and_push",
        ObjectBindingGapKind::CardinalityTransform,
        "flat_map",
        "Vec::iter().flat_map(...).nth(1) should expose why object binding was not proven",
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_last_helper_after_clear_placeholder_and_push"
                            )
                    })
        )),
        "same-crate Vec::last helper should use caller known length to read a proven tail returned borrow"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_last_helper_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate Vec::last helper must emit collection_load ObjectFlow for a proven tail returned borrow"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_last_helper_after_clear_push_and_placeholder"
                            )
                    })
        )),
        "same-crate Vec::last helper must not match a returned borrow followed by a placeholder"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_last_helper_after_clear_push_and_placeholder",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate Vec::last helper must not emit collection_load ObjectFlow for a non-final returned borrow"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_last_helper_after_clear_placeholder_and_push"
                            )
                    })
        )),
        "same-crate Vec::iter().last helper should use caller known length to read a proven tail returned borrow"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_last_helper_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate Vec::iter().last helper must emit collection_load ObjectFlow for a proven tail returned borrow"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_last_helper_after_clear_push_and_placeholder"
                            )
                    })
        )),
        "same-crate Vec::iter().last helper must not match a returned borrow followed by a placeholder"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_last_helper_after_clear_push_and_placeholder",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate Vec::iter().last helper must not emit collection_load ObjectFlow for a non-final returned borrow"
    );
    assert!(
        has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "::step_then_iter_nth_helper_second_after_clear_placeholder_and_push",
        ),
        "same-crate Vec::iter().nth(1) helper should read element_index:1 when the returned borrow is proven at the second element"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_nth_helper_second_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate Vec::iter().nth(1) helper must emit collection_load ObjectFlow for a proven second element"
    );
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "::step_then_iter_nth_helper_first_after_clear_placeholder_and_push",
        ),
        "same-crate Vec::iter().nth(0) helper must not match a returned borrow proven only at element_index:1"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_nth_helper_first_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate Vec::iter().nth(0) helper must not emit collection_load ObjectFlow for the wrong first element"
    );
    assert!(
        has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "::step_then_iter_skip_helper_after_clear_placeholder_and_push",
        ),
        "same-crate Vec::iter().skip(1).next() helper should read element_index:1 when the returned borrow is proven at the second element"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_skip_helper_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate Vec::iter().skip(1).next() helper must emit collection_load ObjectFlow for a proven second element"
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_local_const_nth_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().nth(local const) helper should preserve returned-borrow element identity",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_local_const_skip_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().skip(local const).next() helper should preserve returned-borrow element identity",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_dynamic_nth_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().nth(dynamic) helper must not prove the same element without an auditable offset",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_dynamic_nth_helper_after_clear_placeholder_and_push",
        ObjectBindingGapKind::DynamicIndex,
        "nth",
        "same-crate Vec::iter().nth(dynamic) helper should propagate the missing dynamic-index binding",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_dynamic_skip_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().skip(dynamic).next() helper must not prove the same element without an auditable offset",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_dynamic_skip_helper_after_clear_placeholder_and_push",
        ObjectBindingGapKind::DynamicIndex,
        "skip",
        "same-crate Vec::iter().skip(dynamic).next() helper should propagate the missing dynamic-index binding",
    );
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "::step_then_iter_skip_helper_after_clear_and_push",
        ),
        "same-crate Vec::iter().skip(1).next() helper must not match a skipped returned borrow at element_index:0"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_skip_helper_after_clear_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate Vec::iter().skip(1).next() helper must not emit collection_load ObjectFlow for a skipped returned borrow"
    );
    assert!(
        has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "::step_then_as_slice_helper_second_after_clear_placeholder_and_push",
        ),
        "same-crate Vec::as_slice().get(1) helper should preserve identity for a proven second element"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_as_slice_helper_second_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate Vec::as_slice().get(1) helper must emit collection_load ObjectFlow for a proven second element"
    );
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "::step_then_as_slice_helper_first_after_clear_placeholder_and_push",
        ),
        "same-crate Vec::as_slice().get(0) helper must not match a returned borrow proven only at element_index:1"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_as_slice_helper_first_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate Vec::as_slice().get(0) helper must not emit collection_load ObjectFlow for the wrong first element"
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_range_helper_second_after_clear_placeholder_and_push",
        "same-crate range-slice helper should preserve exact element identity through iter().nth(const)",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_range_helper_first_after_clear_placeholder_and_push",
        "same-crate range-slice helper must not match a different element through iter().nth(const)",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_range_full_helper_second_after_clear_placeholder_and_push",
        "same-crate RangeFull slice helper should preserve exact element identity through iter().skip(const).next()",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_range_full_helper_first_after_clear_placeholder_and_push",
        "same-crate RangeFull slice helper must not match a different element through iter().skip(const).next()",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_range_tail_helper_second_after_clear_placeholder_and_push",
        "same-crate bounded range helper should preserve exact element identity through slice.last()",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_range_tail_helper_first_after_clear_placeholder_and_push",
        "same-crate bounded range helper must not match a different element through slice.last()",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_range_from_last_helper_second_after_clear_placeholder_and_push",
        "same-crate RangeFrom slice helper should use audited sequence length for slice.last()",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_range_full_last_helper_second_after_clear_placeholder_and_push",
        "same-crate RangeFull slice helper should use audited sequence length for slice.last()",
    );
    assert!(
        has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "::step_then_iter_rev_next_helper_after_clear_placeholder_and_push",
        ),
        "same-crate Vec::iter().rev().next() helper should read the known final element when the returned borrow is proven at the tail"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_rev_next_helper_after_clear_placeholder_and_push",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate Vec::iter().rev().next() helper must emit collection_load ObjectFlow for a proven tail returned borrow"
    );
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(
            &facts,
            "::step_then_iter_rev_next_helper_after_clear_push_and_placeholder",
        ),
        "same-crate Vec::iter().rev().next() helper must not match a returned borrow followed by a placeholder"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecStorageIterator::<'a>::step_then_iter_rev_next_helper_after_clear_push_and_placeholder",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate Vec::iter().rev().next() helper must not emit collection_load ObjectFlow for a non-final returned borrow"
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_rev_nth_one_helper_after_clear_push_and_placeholder",
        "same-crate Vec::iter().rev().nth(1) helper should preserve one-slot-from-tail identity",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_rev_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().rev().nth(1) helper must not match the tail returned borrow",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_rev_skip_one_next_helper_after_clear_push_and_placeholder",
        "same-crate Vec::iter().rev().skip(1).next() helper should preserve one-slot-from-tail identity",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_rev_skip_one_next_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().rev().skip(1).next() helper must not match the tail returned borrow",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_skip_one_rev_next_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().skip(1).rev().next() helper should preserve the front-offset guard before tail read",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_skip_one_rev_next_helper_after_clear_push_and_placeholder",
        "same-crate Vec::iter().skip(1).rev().next() helper must not treat front skip as a tail offset",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_take_two_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().take(2).nth(1) helper should preserve the const take bound",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_take_one_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().take(1).nth(1) helper must not read outside the take bound",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_take_two_last_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().take(2).last() helper should read the end of the bounded front range",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_take_one_last_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().take(1).last() helper must not reach outside the bounded front range",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_take_two_rev_next_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().take(2).rev().next() helper should read the end of the bounded front range",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_take_one_rev_next_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().take(1).rev().next() helper must not reach outside the bounded front range",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_enumerate_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().enumerate().nth(1) helper should preserve item identity through the index wrapper",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_copied_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().copied().nth(1) helper should preserve returned-borrow item identity",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_cloned_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().cloned().nth(1) helper should preserve returned-borrow item identity for Copy reference items",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_identity_map_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().map(identity).nth(1) helper should preserve returned-borrow item identity",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_value_map_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().map(value-transform).nth(1) helper must remain conservative because the mapped value is not the original item",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_value_map_nth_one_helper_after_clear_placeholder_and_push",
        ObjectBindingGapKind::MappedValue,
        "map",
        "same-crate Vec::iter().map(value-transform).nth(1) helper should propagate why object binding was not proven",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_identity_filter_map_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().filter_map(always Some identity).nth(1) helper should preserve returned-borrow item identity",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_value_filter_map_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().filter_map(value-transform).nth(1) helper must remain conservative because the mapped value is not the original item",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_value_filter_map_nth_one_helper_after_clear_placeholder_and_push",
        ObjectBindingGapKind::MappedValue,
        "filter_map",
        "same-crate Vec::iter().filter_map(value-transform).nth(1) helper should propagate why object binding was not proven",
    );
    assert_returned_borrow_order_and_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_filter_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().filter(always true).nth(1) helper should preserve returned-borrow item identity",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_filter_false_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().filter(always false).nth(1) helper must remain conservative because predicate selection removes the item",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_filter_false_nth_one_helper_after_clear_placeholder_and_push",
        ObjectBindingGapKind::SelectionPredicate,
        "filter",
        "same-crate Vec::iter().filter(always false).nth(1) helper should propagate why object binding was not proven",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_chain_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().chain(...).nth(1) helper must remain conservative because multiple iterator sources are merged",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_chain_nth_one_helper_after_clear_placeholder_and_push",
        ObjectBindingGapKind::MergedSources,
        "chain",
        "same-crate Vec::iter().chain(...).nth(1) helper should propagate why object binding was not proven",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_zip_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().zip(...).nth(1) helper must remain conservative because tuple item binding is not proven",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_zip_nth_one_helper_after_clear_placeholder_and_push",
        ObjectBindingGapKind::TupleProjection,
        "zip",
        "same-crate Vec::iter().zip(...).nth(1) helper should propagate why object binding was not proven",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_flat_map_nth_one_helper_after_clear_placeholder_and_push",
        "same-crate Vec::iter().flat_map(...).nth(1) helper must remain conservative because value/source cardinality is transformed",
    );
    assert_object_binding_gap_for_symbol(
        &facts,
        "PushVecStorageIterator::<'a>::step_then_iter_flat_map_nth_one_helper_after_clear_placeholder_and_push",
        ObjectBindingGapKind::CardinalityTransform,
        "flat_map",
        "same-crate Vec::iter().flat_map(...).nth(1) helper should propagate why object binding was not proven",
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecDequeStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_next_after_clear_and_push_back"
                            )
                    })
        )),
        "VecDeque::iter().next() should read element_index:0 when the matching returned borrow is proven at the first element"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecDequeStorageIterator::<'a>::step_then_iter_next_after_clear_and_push_back",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "VecDeque::iter().next() must emit collection_load ObjectFlow for a proven returned borrow at element_index:0"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecDequeStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_next_after_clear_placeholder_and_push_back"
                            )
                    })
        )),
        "VecDeque::iter().next() must not match a returned borrow proven only at element_index:1"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecDequeStorageIterator::<'a>::step_then_iter_next_after_clear_placeholder_and_push_back",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "VecDeque::iter().next() must not emit collection_load ObjectFlow for the wrong first element"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecDequeStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_last_after_clear_placeholder_and_push_back"
                            )
                    })
        )),
        "VecDeque::iter().last() should read the known final element when the returned borrow is proven at the tail"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecDequeStorageIterator::<'a>::step_then_iter_last_after_clear_placeholder_and_push_back",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "VecDeque::iter().last() must emit collection_load ObjectFlow for a proven returned borrow at the known final index"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecDequeStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_last_after_clear_push_back_and_placeholder"
                            )
                    })
        )),
        "VecDeque::iter().last() must not match a returned borrow that is followed by a later placeholder element"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecDequeStorageIterator::<'a>::step_then_iter_last_after_clear_push_back_and_placeholder",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "VecDeque::iter().last() must not emit collection_load ObjectFlow for a non-final returned borrow"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecDequeStorageIterator")
                            && path.ends_with(
                                "::step_then_back_helper_after_clear_placeholder_and_push_back"
                            )
                    })
        )),
        "same-crate VecDeque::back helper should use caller known length to read a proven tail returned borrow"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecDequeStorageIterator::<'a>::step_then_back_helper_after_clear_placeholder_and_push_back",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate VecDeque::back helper must emit collection_load ObjectFlow for a proven tail returned borrow"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecDequeStorageIterator")
                            && path.ends_with(
                                "::step_then_back_helper_after_clear_push_back_and_placeholder"
                            )
                    })
        )),
        "same-crate VecDeque::back helper must not match a returned borrow followed by a placeholder"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecDequeStorageIterator::<'a>::step_then_back_helper_after_clear_push_back_and_placeholder",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate VecDeque::back helper must not emit collection_load ObjectFlow for a non-final returned borrow"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecDequeStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_last_helper_after_clear_placeholder_and_push_back"
                            )
                    })
        )),
        "same-crate VecDeque::iter().last helper should use caller known length to read a proven tail returned borrow"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecDequeStorageIterator::<'a>::step_then_iter_last_helper_after_clear_placeholder_and_push_back",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate VecDeque::iter().last helper must emit collection_load ObjectFlow for a proven tail returned borrow"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecDequeStorageIterator")
                            && path.ends_with(
                                "::step_then_iter_last_helper_after_clear_push_back_and_placeholder"
                            )
                    })
        )),
        "same-crate VecDeque::iter().last helper must not match a returned borrow followed by a placeholder"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecDequeStorageIterator::<'a>::step_then_iter_last_helper_after_clear_push_back_and_placeholder",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "same-crate VecDeque::iter().last helper must not emit collection_load ObjectFlow for a non-final returned borrow"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecDequeStorageIterator")
                            && path.ends_with(
                                "::step_then_back_after_clear_placeholder_and_push_back"
                            )
                    })
        )),
        "VecDeque::back should use the known sequence length to read the proven returned borrow at the final index"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            &facts,
            "PushVecDequeStorageIterator::<'a>::step_then_back_after_clear_placeholder_and_push_back",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "VecDeque::back must emit collection_load ObjectFlow when the returned borrow is proven at the final known index"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| {
                        path.contains("PushVecDequeStorageIterator")
                            && path.ends_with(
                                "::step_then_back_after_clear_push_back_and_placeholder"
                            )
                    })
        )),
        "VecDeque::back must not match a returned borrow that is followed by a later placeholder element"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            &facts,
            "PushVecDequeStorageIterator::<'a>::step_then_back_after_clear_push_back_and_placeholder",
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "VecDeque::back must not emit collection_load ObjectFlow for a non-final returned borrow"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowRelation(relation),
                ..
            } if relation.api_id.contains("LruCache")
                && relation.api_id.ends_with("::peek_lru")
                && relation.relation_kind
                    == Some(bw_model::ReturnedBorrowRelationKind::UnconstrainedReturnLifetime)
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.contains("LruCache") && path.ends_with("::peek_lru"))
        )),
        "method-scoped lifetime that appears only in the returned view must emit a returned-borrow relation"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowRelation(relation),
                ..
            } if relation.api_id.contains("LruCache")
                && relation.api_id.ends_with("::iter")
                && relation.relation_kind
                    == Some(bw_model::ReturnedBorrowRelationKind::UnconstrainedReturnLifetime)
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.contains("LruCache") && path.ends_with("::iter"))
        )),
        "method-scoped lifetime nested in an iterator return type must emit a returned-borrow relation"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowRelation(relation),
                ..
            } if relation.api_id.contains("peek_lru_scoped")
                || source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.contains("peek_lru_scoped"))
        )),
        "receiver-scoped returned view must not be treated as an unconstrained returned-borrow relation"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowRelation(relation),
                ..
            } if relation.api_id.contains("iter_scoped")
                || source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.contains("iter_scoped"))
        )),
        "receiver-scoped iterator view must not be treated as an unconstrained returned-borrow relation"
    );
}

#[test]
fn diesel_site_fixture_uses_audited_cross_crate_lookup_contract() {
    let repo = repo_root();
    let fixture = repo.join("benchmarks/compiler-fixtures/diesel-sites/Cargo.toml");
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let analysis_dir = temp.path().join("analysis");
    let target_dir = temp.path().join("target");
    fs::create_dir(&analysis_dir).expect("analysis dir should be created");
    let config = temp.path().join("bw-rustc-config.json");
    let registry_ref = write_collection_lookup_contract_registry(
        temp.path(),
        serde_json::json!([
            {
                "callee": "diesel_helper_lookup::lookup_borrowed",
                "storage_arg_index": 0,
                "key_arg_index": 1,
                "returns_identity_preserving_borrow": true,
                "mutates_storage": false
            }
        ]),
    );
    fs::write(
        &config,
        serde_json::json!({
            "output_dir": analysis_dir,
            "allowlist": [
                { "crate_name": "diesel", "target": "lib" }
            ],
            "collection_lookup_contract_registries": [
                registry_ref
            ]
        })
        .to_string(),
    )
    .expect("config should be written");

    let status = Command::new("cargo")
        .args(["check", "--manifest-path"])
        .arg(&fixture)
        .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_bw-rustc"))
        .env("BW_RUSTC_CONFIG", &config)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status()
        .expect("cargo check should run");
    assert!(status.success(), "fixture cargo check failed: {status}");

    let facts = read_static_facts(&analysis_dir.join("static-facts.jsonl"));
    let symbol = "BorrowEquivalentKeyMapIterator::<'a>::cache_external_helper_lookup_with_contract_step_lookup";
    assert_returned_borrow_order_and_collection_load(
        &facts,
        symbol,
        "audited cross-crate helper contract must reconnect collection lookup to the same object chain",
    );
    assert!(
        !has_object_binding_gap_for_symbol(
            &facts,
            symbol,
            ObjectBindingGapKind::KeyContract,
            "cross_crate_collection_lookup"
        ),
        "audited cross-crate helper contract must not leave a missing-contract gap on the same callsite"
    );
}

#[test]
fn diesel_site_fixture_rejects_mutating_cross_crate_lookup_contract() {
    let repo = repo_root();
    let fixture = repo.join("benchmarks/compiler-fixtures/diesel-sites/Cargo.toml");
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let analysis_dir = temp.path().join("analysis");
    let target_dir = temp.path().join("target");
    fs::create_dir(&analysis_dir).expect("analysis dir should be created");
    let config = temp.path().join("bw-rustc-config.json");
    fs::write(
        &config,
        serde_json::json!({
            "output_dir": analysis_dir,
            "allowlist": [
                { "crate_name": "diesel", "target": "lib" }
            ],
            "collection_lookup_contracts": [
                {
                    "callee": "diesel_helper_lookup::lookup_borrowed",
                    "storage_arg_index": 0,
                    "key_arg_index": 1,
                    "returns_identity_preserving_borrow": true,
                    "mutates_storage": true
                }
            ]
        })
        .to_string(),
    )
    .expect("config should be written");

    let status = Command::new("cargo")
        .args(["check", "--manifest-path"])
        .arg(&fixture)
        .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_bw-rustc"))
        .env("BW_RUSTC_CONFIG", &config)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status()
        .expect("cargo check should run");
    assert!(status.success(), "fixture cargo check failed: {status}");

    let facts = read_static_facts(&analysis_dir.join("static-facts.jsonl"));
    let symbol = "BorrowEquivalentKeyMapIterator::<'a>::cache_external_helper_lookup_with_contract_step_lookup";
    assert_object_binding_gap_for_symbol(
        &facts,
        symbol,
        ObjectBindingGapKind::KeyContract,
        "cross_crate_collection_lookup",
        "mutating cross-crate helper contract must be rejected as a same-object lookup proof",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        symbol,
        "mutating cross-crate helper contract must not reconnect collection lookup",
    );
}

#[test]
fn diesel_site_fixture_rejects_misindexed_cross_crate_lookup_contract() {
    let repo = repo_root();
    let fixture = repo.join("benchmarks/compiler-fixtures/diesel-sites/Cargo.toml");
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let analysis_dir = temp.path().join("analysis");
    let target_dir = temp.path().join("target");
    fs::create_dir(&analysis_dir).expect("analysis dir should be created");
    let config = temp.path().join("bw-rustc-config.json");
    fs::write(
        &config,
        serde_json::json!({
            "output_dir": analysis_dir,
            "allowlist": [
                { "crate_name": "diesel", "target": "lib" }
            ],
            "collection_lookup_contracts": [
                {
                    "callee": "diesel_helper_lookup::lookup_borrowed",
                    "storage_arg_index": 0,
                    "key_arg_index": 0,
                    "returns_identity_preserving_borrow": true,
                    "mutates_storage": false
                }
            ]
        })
        .to_string(),
    )
    .expect("config should be written");

    let status = Command::new("cargo")
        .args(["check", "--manifest-path"])
        .arg(&fixture)
        .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_bw-rustc"))
        .env("BW_RUSTC_CONFIG", &config)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status()
        .expect("cargo check should run");
    assert!(status.success(), "fixture cargo check failed: {status}");

    let facts = read_static_facts(&analysis_dir.join("static-facts.jsonl"));
    let symbol = "BorrowEquivalentKeyMapIterator::<'a>::cache_external_helper_lookup_with_contract_step_lookup";
    assert_object_binding_gap_for_symbol(
        &facts,
        symbol,
        ObjectBindingGapKind::KeyContract,
        "cross_crate_collection_lookup",
        "misindexed cross-crate helper contract must be rejected as a same-object lookup proof",
    );
    assert_no_returned_borrow_order_or_collection_load(
        &facts,
        symbol,
        "misindexed cross-crate helper contract must not reconnect collection lookup",
    );
}

#[test]
fn arena_iterator_fixture_emits_unconstrained_into_iter_lifetime_only_when_missing_anchor() {
    let repo = repo_root();
    let fixture = repo.join("benchmarks/compiler-fixtures/arena-iterator-lifetime/Cargo.toml");
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let analysis_dir = temp.path().join("analysis");
    let target_dir = temp.path().join("target");
    fs::create_dir(&analysis_dir).expect("analysis dir should be created");
    let config = temp.path().join("bw-rustc-config.json");
    fs::write(
        &config,
        serde_json::json!({
            "output_dir": analysis_dir,
            "allowlist": [
                { "crate_name": "arena_iterator_lifetime", "target": "lib" }
            ]
        })
        .to_string(),
    )
    .expect("config should be written");

    let status = Command::new("cargo")
        .args(["check", "--manifest-path"])
        .arg(&fixture)
        .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_bw-rustc"))
        .env("BW_RUSTC_CONFIG", &config)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status()
        .expect("cargo check should run");
    assert!(status.success(), "fixture cargo check failed: {status}");

    let facts = read_static_facts(&analysis_dir.join("static-facts.jsonl"));
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowRelation(relation),
                ..
            } if relation.api_id.contains("ArenaVec")
                && relation.api_id.contains("IntoIterator")
                && relation.api_id.ends_with("::into_iter")
                && relation.relation_kind
                    == Some(bw_model::ReturnedBorrowRelationKind::UnconstrainedReturnLifetime)
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.contains("ArenaVec") && path.ends_with("::into_iter"))
        )),
        "arena-backed into_iter that returns IntoIter<T> must emit an unconstrained lifetime fact"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowRelation(relation),
                ..
            } if relation.api_id.contains("AnchoredArenaVec")
                || source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.contains("AnchoredArenaVec"))
        )),
        "arena-backed into_iter that returns IntoIter<'arena, T> must remain a negative control"
    );
}

#[test]
fn atomic_ordering_fixture_emits_pointer_iterator_loads_but_not_counter_loads() {
    let repo = repo_root();
    let fixture = repo.join("benchmarks/compiler-fixtures/atomic-ordering-lifecycle/Cargo.toml");
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let analysis_dir = temp.path().join("analysis");
    let target_dir = temp.path().join("target");
    fs::create_dir(&analysis_dir).expect("analysis dir should be created");
    let config = temp.path().join("bw-rustc-config.json");
    fs::write(
        &config,
        serde_json::json!({
            "output_dir": analysis_dir,
            "allowlist": [
                { "crate_name": "atomic_ordering_lifecycle", "target": "lib" }
            ]
        })
        .to_string(),
    )
    .expect("config should be written");

    let status = Command::new("cargo")
        .args(["check", "--manifest-path"])
        .arg(&fixture)
        .env("RUSTC_WRAPPER", env!("CARGO_BIN_EXE_bw-rustc"))
        .env("BW_RUSTC_CONFIG", &config)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status()
        .expect("cargo check should run");
    assert!(status.success(), "fixture cargo check failed: {status}");

    let facts = read_static_facts(&analysis_dir.join("static-facts.jsonl"));
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::AtomicOrdering(ordering),
                ..
            } if ordering.api_id.contains("RelaxedRawIter")
                && ordering.api_id.ends_with("::next")
                && ordering.operation == bw_model::AtomicOperationKind::Load
                && ordering.ordering == bw_model::AtomicOrderingKind::Relaxed
                && ordering.target_type_name.contains("Atomic")
                && ordering.target_type_name.contains("*mut")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.contains("RelaxedRawIter") && path.ends_with("::next"))
        )),
        "Relaxed AtomicPtr load in iterator next must emit an atomic ordering fact"
    );
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::AtomicOrdering(ordering),
                ..
            } if ordering.api_id.contains("AcquireRawIter")
                && ordering.api_id.ends_with("::next")
                && ordering.operation == bw_model::AtomicOperationKind::Load
                && ordering.ordering == bw_model::AtomicOrderingKind::Acquire
                && ordering.target_type_name.contains("Atomic")
                && ordering.target_type_name.contains("*mut")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.contains("AcquireRawIter") && path.ends_with("::next"))
        )),
        "Acquire AtomicPtr load in iterator next must emit an atomic ordering fact"
    );
    assert!(
        facts.iter().all(|fact| !matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::AtomicOrdering(ordering),
                ..
            } if ordering.api_id.contains("Counter")
                || ordering.target_type_name.contains("AtomicUsize")
                || source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.contains("Counter"))
        )),
        "generic AtomicUsize counter load must not be emitted as a lifecycle atomic ordering fact"
    );
}

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn read_static_facts(path: &std::path::Path) -> Vec<StaticFactEnvelope> {
    fs::read_to_string(path)
        .expect("static-facts.jsonl should be written")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("static fact should parse"))
        .collect()
}

fn read_expected_lines(path: &std::path::Path) -> Vec<String> {
    fs::read_to_string(path)
        .expect("mir-sites.expected.jsonl should exist")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn write_collection_lookup_contract_registry(
    base_dir: &std::path::Path,
    contracts: serde_json::Value,
) -> serde_json::Value {
    let registry_path = base_dir.join("collection-lookup-contracts.json");
    let registry_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": COLLECTION_LOOKUP_CONTRACT_REGISTRY_SCHEMA_V01,
        "contracts": contracts,
    }))
    .expect("contract registry should serialize");
    let registry_sha256 = sha256_hex(&registry_bytes);
    fs::write(&registry_path, &registry_bytes).expect("contract registry should be written");

    let source_evidence_path = base_dir.join("collection-lookup-source-audit.txt");
    let source_evidence = b"diesel_helper_lookup::lookup_borrowed returns map.get(key).copied() and does not mutate storage\n";
    fs::write(&source_evidence_path, source_evidence).expect("source evidence should be written");

    let manifest_path = base_dir.join("collection-lookup-contracts.manifest.json");
    let manifest_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": COLLECTION_LOOKUP_CONTRACT_REGISTRY_MANIFEST_SCHEMA_V01,
        "registry_path": registry_path
            .file_name()
            .expect("registry file name should exist")
            .to_string_lossy(),
        "registry_sha256": registry_sha256.clone(),
        "source_evidence": [
            {
                "path": source_evidence_path
                    .file_name()
                    .expect("source evidence file name should exist")
                    .to_string_lossy(),
                "sha256": sha256_hex(source_evidence),
                "description": "fixture source audit for identity-preserving non-mutating lookup helper"
            }
        ]
    }))
    .expect("contract registry manifest should serialize");
    fs::write(&manifest_path, &manifest_bytes)
        .expect("contract registry manifest should be written");

    serde_json::json!({
        "path": registry_path,
        "sha256": registry_sha256,
        "manifest_path": manifest_path,
        "manifest_sha256": sha256_hex(&manifest_bytes),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn registration_user_data_site_ids(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
    api_id: &str,
) -> BTreeSet<SiteId> {
    facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RegistrationSite(registration),
                ..
            } if registration.api_id == api_id
                && registration.role == RegistrationRole::Register
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with(symbol_suffix)) =>
            {
                registration.user_data_site_id.clone()
            }
            _ => None,
        })
        .collect()
}

fn has_from_raw_for_symbol_objects(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
    object_site_ids: &BTreeSet<SiteId>,
) -> bool {
    facts.iter().any(|fact| {
        matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::RawPointerTransfer(transfer),
                ..
            } if transfer.transfer_kind == RawPointerTransferKind::FromRaw
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with(symbol_suffix))
                && object_site_ids.contains(&transfer.user_data_site_id)
        )
    })
}

fn has_release_path_proof_for_symbol_objects(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
    object_site_ids: &BTreeSet<SiteId>,
) -> bool {
    facts.iter().any(|fact| {
        matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReleasePathProof(proof),
                ..
            } if source_ref
                .symbol_path
                .as_deref()
                .is_some_and(|path| path.ends_with(symbol_suffix))
                && object_site_ids.contains(&proof.object_site_id)
        )
    })
}

fn has_callback_release_use_order_for_symbol_objects(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
    object_site_ids: &BTreeSet<SiteId>,
    ordering: bw_model::CallbackReleaseUseOrdering,
) -> bool {
    facts.iter().any(|fact| {
        matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::CallbackReleaseUseOrder(order),
                ..
            } if source_ref
                .symbol_path
                .as_deref()
                .is_some_and(|path| path.ends_with(symbol_suffix))
                && object_site_ids.contains(&order.object_site_id)
                && order.ordering == ordering
        )
    })
}

fn has_release_proof_object_flow_for_symbol(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
) -> bool {
    facts.iter().any(|fact| {
        matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ObjectFlow(flow),
                ..
            } if flow.flow_kind == bw_model::ObjectFlowKind::FieldLoad
                && flow.from_object_kind == bw_model::ObjectFlowObjectKind::StaticSite
                && flow.to_object_kind == bw_model::ObjectFlowObjectKind::StaticSite
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with(symbol_suffix))
        )
    })
}

fn has_returned_borrow_invalidation_order_for_symbol(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
) -> bool {
    facts.iter().any(|fact| {
        matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ReturnedBorrowInvalidationOrder(order),
                ..
            } if order.api_id.ends_with("Statement::field_name")
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with(symbol_suffix))
        )
    })
}

fn assert_returned_borrow_order_and_collection_load(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
    context: &str,
) {
    assert!(
        has_returned_borrow_invalidation_order_for_symbol(facts, symbol_suffix),
        "{context}: missing ReturnedBorrowInvalidationOrder"
    );
    assert!(
        has_object_flow_for_symbol_kind(
            facts,
            symbol_suffix,
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "{context}: missing collection_load ObjectFlow"
    );
}

fn assert_no_returned_borrow_order_or_collection_load(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
    context: &str,
) {
    assert!(
        !has_returned_borrow_invalidation_order_for_symbol(facts, symbol_suffix),
        "{context}: unexpected ReturnedBorrowInvalidationOrder"
    );
    assert!(
        !has_object_flow_for_symbol_kind(
            facts,
            symbol_suffix,
            bw_model::ObjectFlowKind::CollectionLoad,
            None,
        ),
        "{context}: unexpected collection_load ObjectFlow"
    );
}

fn assert_object_binding_gap_for_symbol(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
    gap_kind: ObjectBindingGapKind,
    adapter: &str,
    context: &str,
) {
    assert!(
        facts.iter().any(|fact| matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ObjectBindingGap(gap),
                ..
            } if gap.gap_kind == gap_kind
                && gap.adapter.as_deref() == Some(adapter)
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with(symbol_suffix))
        )),
        "{context}: missing ObjectBindingGap({gap_kind:?}, adapter={adapter})"
    );
}

fn has_object_binding_gap_for_symbol(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
    gap_kind: ObjectBindingGapKind,
    adapter: &str,
) -> bool {
    facts.iter().any(|fact| {
        matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ObjectBindingGap(gap),
                ..
            } if gap.gap_kind == gap_kind
                && gap.adapter.as_deref() == Some(adapter)
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with(symbol_suffix))
        )
    })
}

fn has_object_binding_gap_for_symbol_kind_field_path(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
    gap_kind: ObjectBindingGapKind,
    field_path: &str,
) -> bool {
    facts.iter().any(|fact| {
        matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ObjectBindingGap(gap),
                ..
            } if gap.gap_kind == gap_kind
                && gap.field_path.as_deref() == Some(field_path)
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with(symbol_suffix))
        )
    })
}

fn has_object_binding_gap_for_symbol_kind_adapter_field_path_contains(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
    gap_kind: ObjectBindingGapKind,
    adapter: &str,
    field_path_fragment: &str,
) -> bool {
    facts.iter().any(|fact| {
        matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ObjectBindingGap(gap),
                ..
            } if gap.gap_kind == gap_kind
                && gap.adapter.as_deref() == Some(adapter)
                && gap
                    .field_path
                    .as_deref()
                    .is_some_and(|field_path| field_path.contains(field_path_fragment))
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with(symbol_suffix))
        )
    })
}

fn has_object_binding_gap_for_symbol_kind_adapter_prefix_field_path_contains(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
    gap_kind: ObjectBindingGapKind,
    adapter_prefix: &str,
    field_path_fragment: &str,
) -> bool {
    facts.iter().any(|fact| {
        matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ObjectBindingGap(gap),
                ..
            } if gap.gap_kind == gap_kind
                && gap
                    .adapter
                    .as_deref()
                    .is_some_and(|adapter| adapter.starts_with(adapter_prefix))
                && gap
                    .field_path
                    .as_deref()
                    .is_some_and(|field_path| field_path.contains(field_path_fragment))
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with(symbol_suffix))
        )
    })
}

fn has_object_flow_for_symbol_kind(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
    flow_kind: bw_model::ObjectFlowKind,
    field_path: Option<&str>,
) -> bool {
    facts.iter().any(|fact| {
        matches!(
            fact,
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ObjectFlow(flow),
                ..
            } if flow.flow_kind == flow_kind
                && field_path.is_none_or(|expected| flow.field_path.as_deref() == Some(expected))
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with(symbol_suffix))
        )
    })
}

fn has_object_flow_for_symbol_kind_with_field_path_prefix(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
    flow_kind: bw_model::ObjectFlowKind,
    field_path_prefix: &str,
) -> bool {
    object_flow_field_paths_for_symbol_kind(facts, symbol_suffix, flow_kind)
        .iter()
        .any(|field_path| field_path.starts_with(field_path_prefix))
}

fn object_flow_field_paths_for_symbol_kind(
    facts: &[StaticFactEnvelope],
    symbol_suffix: &str,
    flow_kind: bw_model::ObjectFlowKind,
) -> Vec<String> {
    facts
        .iter()
        .filter_map(|fact| match fact {
            StaticFactEnvelope {
                source_ref: Some(source_ref),
                payload: StaticFact::ObjectFlow(flow),
                ..
            } if flow.flow_kind == flow_kind
                && source_ref
                    .symbol_path
                    .as_deref()
                    .is_some_and(|path| path.ends_with(symbol_suffix)) =>
            {
                flow.field_path.clone()
            }
            _ => None,
        })
        .collect()
}

fn normalized_mir_lines(facts: &[StaticFactEnvelope]) -> Vec<String> {
    let mut lines = facts
        .iter()
        .filter_map(|fact| match &fact.payload {
            StaticFact::DropSite(drop) => Some(serde_json::json!({
                "kind": "drop_site",
                "drop_kind": drop.drop_kind,
            })),
            StaticFact::DropPrevention(prevention) => Some(serde_json::json!({
                "kind": "drop_prevention",
                "prevention_kind": prevention.prevention_kind,
            })),
            StaticFact::CallbackUserDataReconstruction(reconstruction) => Some(serde_json::json!({
                "kind": "callback_user_data_reconstruction",
                "reconstruction_kind": reconstruction.reconstruction_kind,
            })),
            StaticFact::RegistrationSite(registration) => Some(serde_json::json!({
                "kind": "registration_site",
                "api_id": registration.api_id,
                "role": registration.role,
            })),
            StaticFact::ReleasePathProof(_) => Some(serde_json::json!({
                "kind": "release_path_proof",
            })),
            StaticFact::CallbackReleaseUseOrder(order) => Some(serde_json::json!({
                "kind": "callback_release_use_order",
                "api_id": order.api_id,
                "ordering": order.ordering,
            })),
            StaticFact::ExternalCallSite(external) => Some(serde_json::json!({
                "kind": "external_call_site",
                "api_id": external.api_id,
                "role": external.role,
            })),
            StaticFact::ReturnedBorrowRelation(relation) => {
                let mut value = serde_json::json!({
                    "kind": "returned_borrow_relation",
                    "api_id": relation.api_id,
                });
                if let Some(relation_kind) = relation.relation_kind {
                    value["relation_kind"] = serde_json::json!(relation_kind);
                }
                Some(value)
            }
            StaticFact::PersistedReturnedBorrow(persisted) => Some(serde_json::json!({
                "kind": "persisted_returned_borrow",
                "api_id": persisted.api_id,
            })),
            StaticFact::ExternalBufferBinding(binding) => Some(serde_json::json!({
                "kind": "external_buffer_binding",
                "api_id": binding.api_id,
            })),
            _ => None,
        })
        .map(|value| serde_json::to_string(&value).expect("normalized fact should serialize"))
        .collect::<Vec<_>>();
    lines.sort();
    lines
}
