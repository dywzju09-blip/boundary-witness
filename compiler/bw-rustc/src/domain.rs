use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::ErrorKind,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use bw_model::{
    AtomicOperationKind, AtomicOrderingFact, AtomicOrderingKind, BuildId, CallbackCaptureFact,
    CallbackLifetimeBoundFact, CallbackLifetimeBoundScope, CallbackReleaseUseOrderFact,
    CallbackReleaseUseOrdering, CallbackSiteFact, CallbackUserDataReconstructionFact,
    CallbackUserDataReconstructionKind, CaptureMode, DropKind, DropPreventionFact,
    DropPreventionKind, DropSiteFact, ExternalBufferBindingFact, ExternalCallRole,
    ExternalCallSiteFact, ObjectBindingGapFact, ObjectBindingGapKind, ObjectFlowFact,
    ObjectFlowKind, ObjectFlowObjectKind, ObjectSiteFact, PersistedReturnedBorrowFact,
    AllocationOwnership, AllocationOwnershipFact, RawPointerTransferFact,
    RawPointerTransferKind, RecordId, RegistrationGuard,
    RegistrationGuardFact, RegistrationRole, RegistrationSiteFact, ReleasePathProofFact,
    ReturnedBorrowInvalidationOrderFact, ReturnedBorrowInvalidationOrdering,
    ReturnedBorrowRelationFact, ReturnedBorrowRelationKind, STATIC_SCHEMA_V02, SiteId,
    StaticArtifactIdentity, StaticFact, StaticFactEnvelope, StaticSourceRef,
};
use bw_rustc::{SiteDescriptor, SiteIdentityError, SiteRole, stable_relative_path};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureObservation {
    pub callback_def_path: String,
    pub callback_source_path: PathBuf,
    pub callback_span: String,
    pub capture_ordinal: u32,
    pub capture_mode: CaptureMode,
    pub capture_source_path: PathBuf,
    pub capture_span: String,
    pub object_source_path: PathBuf,
    pub object_span: String,
    pub object_type_name: String,
    pub captured_field_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticFactContext {
    pub package: String,
    pub crate_id: String,
    pub package_name: String,
    pub package_version: String,
    pub target: String,
    pub repo_root: PathBuf,
    pub build_id: BuildId,
    pub producer: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DropObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub object_type_name: String,
    pub drop_kind: DropKind,
    pub callback: Option<CallbackReference>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DropPreventionObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub object_type_name: String,
    pub prevention_kind: DropPreventionKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackUserDataReconstructionObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub object_type_name: String,
    pub user_data: RawPointerReference,
    pub reconstruction_kind: CallbackUserDataReconstructionKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackReference {
    pub def_path: String,
    pub source_path: PathBuf,
    pub span: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawPointerReference {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub type_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BorrowReference {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub type_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawPointerTransferObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub basic_block: usize,
    pub statement_index: usize,
    pub kind: RawPointerTransferKind,
    pub user_data: RawPointerReference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub basic_block: usize,
    pub statement_index: usize,
    pub api_id: String,
    pub role: RegistrationRole,
    pub callback: Option<CallbackReference>,
    pub user_data: Option<RawPointerReference>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasePathProofObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub registration: RegistrationObservation,
    pub release: RawPointerTransferObservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackReleaseUseOrderObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub registration: RegistrationObservation,
    pub release: RawPointerTransferObservation,
    pub reconstruction: CallbackUserDataReconstructionObservation,
    pub ordering: CallbackReleaseUseOrdering,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalCallObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub api_id: String,
    pub role: ExternalCallRole,
}

/// 一个回调泛型参数在定义点上的生命周期 bound。
///
/// 只来自 HIR 签名，没有 MIR location 之外的对象——这是**定义点**观察，不需要任何调用
/// 代码。它记录的是"这个安全 API 的签名允许回调借用什么"，也就是组件级缺陷的本体。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackLifetimeBoundObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub api_id: String,
    pub callback_param: String,
    pub bound_lifetime: Option<String>,
    pub bound_scope: CallbackLifetimeBoundScope,
}

/// 一个回调交出点上观察到的分配归属。
///
/// 与 [`CallbackLifetimeBoundObservation`] 正交：前者说回调**捕获**了什么，本观察说
/// `Box<F>` 这块分配交出后由谁负责释放。`'static` bound 不约束后者，两者必须分开。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationOwnershipObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub api_id: String,
    pub callback_param: String,
    /// 判据依据的 `into_raw` 位置的 MIR location。用于生成诊断用的 site id。
    pub into_raw_mir_location: Option<String>,
    /// 同一分配上被观察到的回收点的 MIR location。
    pub reclaim_mir_location: Option<String>,
    pub ownership: AllocationOwnership,
}

/// 一个回调交出点上观察到的 registration guard 形状。
///
/// 与 [`CallbackLifetimeBoundObservation`] 一一配对：同一个 `owner_def_path` +
/// `callback_param` 上，前者说"回调 bound 允不允许捕获借用"，本观察说"有没有 guard
/// 把注册的存活绑到被捕对象上"。判定关系需要两者齐备。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationGuardObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub api_id: String,
    pub callback_param: String,
    pub guard_type: Option<String>,
    pub foreign_release_callee: Option<String>,
    pub guard: RegistrationGuard,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReturnedBorrowRelationObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub api_id: String,
    pub relation_kind: Option<ReturnedBorrowRelationKind>,
    pub source: BorrowReference,
    pub returned_type_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedReturnedBorrowObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub mir_order_block: usize,
    pub mir_statement_index: usize,
    pub api_id: String,
    pub source: BorrowReference,
    pub returned_type_name: String,
    pub storage_type_name: String,
    pub storage_key: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReturnedBorrowInvalidationOrderObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub persisted: PersistedReturnedBorrowObservation,
    pub invalidation_owner_def_path: String,
    pub invalidation_source_path: PathBuf,
    pub invalidation_span: String,
    pub invalidation_mir_location: String,
    pub use_owner_def_path: String,
    pub use_source_path: PathBuf,
    pub use_span: String,
    pub use_mir_location: String,
    pub api_id: String,
    pub invalidation_api_id: String,
    pub ordering: ReturnedBorrowInvalidationOrdering,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalBufferBindingObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub api_id: String,
    pub source: BorrowReference,
    pub buffer_type_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicOrderingObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub api_id: String,
    pub operation: AtomicOperationKind,
    pub ordering: AtomicOrderingKind,
    pub target_type_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectBindingGapObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub api_id: String,
    pub gap_kind: ObjectBindingGapKind,
    pub field_path: Option<String>,
    pub container_type_name: Option<String>,
    pub adapter: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectFlowStaticSiteObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub type_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectFlowEndpointObservation {
    UserData(RawPointerReference),
    CallbackSite(CallbackReference),
    RegistrationSite(RegistrationObservation),
    RawPointerTransferSite(RawPointerTransferObservation),
    ReturnedBorrow(PersistedReturnedBorrowObservation),
    Storage(PersistedReturnedBorrowObservation),
    ReturnedBorrowUse(ReturnedBorrowInvalidationOrderObservation),
    StaticSite(ObjectFlowStaticSiteObservation),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectFlowObservation {
    pub owner_def_path: String,
    pub source_path: PathBuf,
    pub span: String,
    pub mir_location: String,
    pub api_id: String,
    pub from: ObjectFlowEndpointObservation,
    pub from_object_kind: ObjectFlowObjectKind,
    pub to: ObjectFlowEndpointObservation,
    pub to_object_kind: ObjectFlowObjectKind,
    pub flow_kind: ObjectFlowKind,
    pub field_path: Option<String>,
    pub container_type_name: Option<String>,
}

impl StaticFactContext {
    #[must_use]
    pub fn new(
        package: impl Into<String>,
        crate_id: impl Into<String>,
        package_name: impl Into<String>,
        package_version: impl Into<String>,
        target: impl Into<String>,
        repo_root: PathBuf,
    ) -> Self {
        let package = package.into();
        let crate_id = crate_id.into();
        let package_name = package_name.into();
        let package_version = package_version.into();
        let target = target.into();
        let build_identity = [
            crate_id.as_str(),
            package_name.as_str(),
            package_version.as_str(),
            target.as_str(),
        ]
        .join("\u{1f}");
        let build_hash = &hex_digest(Sha256::digest(build_identity.as_bytes()))[..16];
        Self {
            build_id: BuildId::from(format!(
                "build:{}:{}:{}",
                sanitize_file_component(&package),
                sanitize_file_component(&target),
                build_hash,
            )),
            producer: "bw-rustc@local".to_owned(),
            package,
            crate_id,
            package_name,
            package_version,
            target,
            repo_root,
        }
    }
}

pub fn facts_from_captures(
    context: &StaticFactContext,
    observations: &[CaptureObservation],
) -> Result<Vec<StaticFactEnvelope>, DomainError> {
    let mut facts = BTreeMap::<RecordId, StaticFactEnvelope>::new();
    for observation in observations {
        if !capture_observation_has_stable_sources(context, observation) {
            continue;
        }
        let callback_descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &observation.callback_def_path,
            SiteRole::Callback,
            source_path(context, &observation.callback_source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_span(&observation.callback_span);
        let callback_site_id = callback_descriptor.try_site_id()?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "callback",
                &callback_site_id,
                &observation.callback_source_path,
                &observation.callback_span,
                Some(&observation.callback_def_path),
                StaticFact::CallbackSite(CallbackSiteFact {
                    site_id: callback_site_id.clone(),
                    semantic_site_key: callback_descriptor.semantic_key(),
                    def_path: observation.callback_def_path.clone(),
                }),
            )?,
        );

        let object_descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &observation.callback_def_path,
            SiteRole::Object,
            source_path(context, &observation.object_source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_capture_ordinal(observation.capture_ordinal)
        .with_span(&observation.object_span);
        let object_site_id = object_descriptor.try_site_id()?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "object",
                &object_site_id,
                &observation.object_source_path,
                &observation.object_span,
                Some(&observation.callback_def_path),
                StaticFact::ObjectSite(ObjectSiteFact {
                    site_id: object_site_id.clone(),
                    semantic_site_key: object_descriptor.semantic_key(),
                    type_name: observation.object_type_name.clone(),
                }),
            )?,
        );

        let capture_descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &observation.callback_def_path,
            SiteRole::Capture,
            source_path(context, &observation.capture_source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_capture_ordinal(observation.capture_ordinal)
        .with_span(&observation.capture_span);
        let capture_site_id = capture_descriptor.try_site_id()?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "capture",
                &capture_site_id,
                &observation.capture_source_path,
                &observation.capture_span,
                Some(&observation.callback_def_path),
                StaticFact::CallbackCapture(CallbackCaptureFact {
                    site_id: capture_site_id.clone(),
                    semantic_site_key: capture_descriptor.semantic_key(),
                    callback_site_id: callback_site_id.clone(),
                    object_site_id: object_site_id.clone(),
                    capture_ordinal: observation.capture_ordinal,
                    capture_mode: observation.capture_mode,
                }),
            )?,
        );

        let flow_descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &observation.callback_def_path,
            SiteRole::ObjectFlow,
            source_path(context, &observation.capture_source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_capture_ordinal(observation.capture_ordinal)
        .with_span(&observation.capture_span);
        let flow_site_id = flow_descriptor.try_site_id()?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "object_flow",
                &flow_site_id,
                &observation.capture_source_path,
                &observation.capture_span,
                Some(&observation.callback_def_path),
                StaticFact::ObjectFlow(ObjectFlowFact {
                    site_id: flow_site_id.clone(),
                    semantic_site_key: flow_descriptor.semantic_key(),
                    from_site_id: object_site_id,
                    from_object_kind: ObjectFlowObjectKind::RustOwner,
                    to_site_id: callback_site_id,
                    to_object_kind: ObjectFlowObjectKind::Callback,
                    flow_kind: ObjectFlowKind::ClosureCapture,
                    api_id: observation.callback_def_path.clone(),
                    field_path: Some(closure_capture_object_flow_field_path(observation)),
                    container_type_name: None,
                }),
            )?,
        );
    }

    Ok(facts.into_values().collect())
}

pub(crate) fn closure_capture_object_flow_field_path(observation: &CaptureObservation) -> String {
    let mut field_path = format!("closure_capture_ordinal:{}", observation.capture_ordinal);
    if let Some(captured_field_path) = observation.captured_field_path.as_deref() {
        field_path.push(':');
        field_path.push_str(captured_field_path);
    }
    field_path
}

pub fn facts_from_mir_sites(
    context: &StaticFactContext,
    drops: &[DropObservation],
    drop_preventions: &[DropPreventionObservation],
    callback_user_data_reconstructions: &[CallbackUserDataReconstructionObservation],
    registrations: &[RegistrationObservation],
    raw_pointer_transfers: &[RawPointerTransferObservation],
    release_path_proofs: &[ReleasePathProofObservation],
    callback_release_use_orders: &[CallbackReleaseUseOrderObservation],
    external_calls: &[ExternalCallObservation],
    callback_lifetime_bounds: &[CallbackLifetimeBoundObservation],
    registration_guards: &[RegistrationGuardObservation],
    allocation_ownerships: &[AllocationOwnershipObservation],
    returned_borrow_relations: &[ReturnedBorrowRelationObservation],
    persisted_returned_borrows: &[PersistedReturnedBorrowObservation],
    returned_borrow_invalidation_orders: &[ReturnedBorrowInvalidationOrderObservation],
    external_buffer_bindings: &[ExternalBufferBindingObservation],
    atomic_orderings: &[AtomicOrderingObservation],
    object_binding_gaps: &[ObjectBindingGapObservation],
    object_flows: &[ObjectFlowObservation],
    capture_facts: &[StaticFactEnvelope],
) -> Result<Vec<StaticFactEnvelope>, DomainError> {
    let mut facts = BTreeMap::<RecordId, StaticFactEnvelope>::new();
    let captured_objects_by_callback = captured_objects_by_callback(capture_facts);
    for drop in drops {
        if !source_is_stable(context, &drop.source_path) {
            continue;
        }
        let captured_object_site_ids = drop
            .callback
            .as_ref()
            .filter(|callback| source_is_stable(context, &callback.source_path))
            .map(|callback| callback_site_id(context, callback, &mut facts))
            .transpose()?
            .and_then(|callback_site_id| {
                captured_objects_by_callback
                    .get(callback_site_id.as_str())
                    .cloned()
            })
            .unwrap_or_default();
        let object_site_ids = if captured_object_site_ids.is_empty() {
            vec![insert_dropped_object_fact(context, drop, &mut facts)?]
        } else {
            captured_object_site_ids
        };

        for (ordinal, object_site_id) in object_site_ids.into_iter().enumerate() {
            let mut drop_descriptor = SiteDescriptor::new(
                &context.package,
                &context.target,
                &drop.owner_def_path,
                SiteRole::Drop,
                source_path(context, &drop.source_path),
            )
            .with_repo_root(&context.repo_root)
            .with_mir_location(&drop.mir_location)
            .with_span(&drop.span);
            if drop.callback.is_some() {
                drop_descriptor = drop_descriptor.with_capture_ordinal(ordinal as u32);
            }
            let drop_site_id = drop_descriptor.try_site_id()?;
            insert_fact(
                &mut facts,
                envelope_with_source(
                    context,
                    "drop",
                    &drop_site_id,
                    &drop.source_path,
                    &drop.span,
                    Some(&drop.owner_def_path),
                    StaticFact::DropSite(DropSiteFact {
                        site_id: drop_site_id.clone(),
                        semantic_site_key: drop_descriptor.semantic_key(),
                        object_site_id,
                        drop_kind: drop.drop_kind,
                    }),
                )?,
            );
        }
    }

    for prevention in drop_preventions {
        if !source_is_stable(context, &prevention.source_path) {
            continue;
        }
        let object_site_id = insert_drop_prevention_object_fact(context, prevention, &mut facts)?;
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &prevention.owner_def_path,
            SiteRole::DropPrevention,
            source_path(context, &prevention.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(&prevention.mir_location)
        .with_span(&prevention.span);
        let site_id = descriptor.try_site_id()?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "drop_prevention",
                &site_id,
                &prevention.source_path,
                &prevention.span,
                Some(&prevention.owner_def_path),
                StaticFact::DropPrevention(DropPreventionFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    object_site_id,
                    prevention_kind: prevention.prevention_kind,
                }),
            )?,
        );
    }

    for reconstruction in callback_user_data_reconstructions {
        if !source_is_stable(context, &reconstruction.source_path)
            || !source_is_stable(context, &reconstruction.user_data.source_path)
        {
            continue;
        }
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &reconstruction.owner_def_path,
            SiteRole::CallbackUserDataReconstruction,
            source_path(context, &reconstruction.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(&reconstruction.mir_location)
        .with_span(&reconstruction.span);
        let site_id = descriptor.try_site_id()?;
        let callback_site_id = callback_site_id_for_owner(context, reconstruction, &mut facts)?;
        let user_data_site_id = user_data_site_id(context, &reconstruction.user_data, &mut facts)?;
        let object_site_id = insert_callback_user_data_reconstruction_object_fact(
            context,
            reconstruction,
            &mut facts,
        )?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "callback_user_data_reconstruction",
                &site_id,
                &reconstruction.source_path,
                &reconstruction.span,
                Some(&reconstruction.owner_def_path),
                StaticFact::CallbackUserDataReconstruction(CallbackUserDataReconstructionFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    callback_site_id,
                    user_data_site_id,
                    object_site_id,
                    reconstruction_kind: reconstruction.reconstruction_kind,
                }),
            )?,
        );
    }

    for registration in registrations {
        if !source_is_stable(context, &registration.source_path) {
            continue;
        }
        let descriptor = registration_site_descriptor(context, registration);
        let site_id = descriptor.try_site_id()?;
        let callback_site_id = registration
            .callback
            .as_ref()
            .filter(|callback| source_is_stable(context, &callback.source_path))
            .map(|callback| callback_site_id(context, callback, &mut facts))
            .transpose()?;
        let user_data_site_id = registration
            .user_data
            .as_ref()
            .filter(|user_data| source_is_stable(context, &user_data.source_path))
            .map(|user_data| user_data_site_id(context, user_data, &mut facts))
            .transpose()?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "registration",
                &site_id,
                &registration.source_path,
                &registration.span,
                Some(&registration.owner_def_path),
                StaticFact::RegistrationSite(RegistrationSiteFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    callback_site_id,
                    user_data_site_id,
                    api_id: registration.api_id.clone(),
                    role: registration.role,
                }),
            )?,
        );
    }

    for transfer in raw_pointer_transfers {
        if !source_is_stable(context, &transfer.source_path)
            || !source_is_stable(context, &transfer.user_data.source_path)
        {
            continue;
        }
        let descriptor = raw_pointer_transfer_site_descriptor(context, transfer);
        let site_id = descriptor.try_site_id()?;
        let user_data_site_id = user_data_site_id(context, &transfer.user_data, &mut facts)?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "raw_pointer_transfer",
                &site_id,
                &transfer.source_path,
                &transfer.span,
                Some(&transfer.owner_def_path),
                StaticFact::RawPointerTransfer(RawPointerTransferFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    user_data_site_id,
                    transfer_kind: transfer.kind,
                }),
            )?,
        );
    }

    for proof in release_path_proofs {
        if !release_path_proof_has_stable_sources(context, proof) {
            continue;
        }
        let (Some(registration_user_data), release_user_data) = (
            proof.registration.user_data.as_ref(),
            &proof.release.user_data,
        ) else {
            continue;
        };
        if registration_user_data != release_user_data {
            continue;
        }
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &proof.owner_def_path,
            SiteRole::ReleasePathProof,
            source_path(context, &proof.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(&proof.mir_location)
        .with_span(&proof.span);
        let site_id = descriptor.try_site_id()?;
        let registration_site_id =
            registration_site_descriptor(context, &proof.registration).try_site_id()?;
        let release_site_id =
            raw_pointer_transfer_site_descriptor(context, &proof.release).try_site_id()?;
        let object_site_id = user_data_site_id(context, registration_user_data, &mut facts)?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "release_path_proof",
                &site_id,
                &proof.source_path,
                &proof.span,
                Some(&proof.owner_def_path),
                StaticFact::ReleasePathProof(ReleasePathProofFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    registration_site_id,
                    release_site_id,
                    object_site_id,
                }),
            )?,
        );
    }

    for order in callback_release_use_orders {
        if !callback_release_use_order_has_stable_sources(context, order) {
            continue;
        }
        let Some(registration_user_data) = order.registration.user_data.as_ref() else {
            continue;
        };
        if registration_user_data != &order.release.user_data {
            continue;
        }
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &order.owner_def_path,
            SiteRole::CallbackReleaseUseOrder,
            source_path(context, &order.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(&order.mir_location)
        .with_span(&order.span);
        let site_id = descriptor.try_site_id()?;
        let registration_site_id =
            registration_site_descriptor(context, &order.registration).try_site_id()?;
        let release_site_id =
            raw_pointer_transfer_site_descriptor(context, &order.release).try_site_id()?;
        let use_site_id =
            callback_user_data_reconstruction_site_descriptor(context, &order.reconstruction)
                .try_site_id()?;
        let object_site_id = user_data_site_id(context, registration_user_data, &mut facts)?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "callback_release_use_order",
                &site_id,
                &order.source_path,
                &order.span,
                Some(&order.owner_def_path),
                StaticFact::CallbackReleaseUseOrder(CallbackReleaseUseOrderFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    registration_site_id,
                    release_site_id,
                    use_site_id,
                    object_site_id,
                    api_id: order.registration.api_id.clone(),
                    ordering: order.ordering,
                }),
            )?,
        );
    }

    for external_call in external_calls {
        if !source_is_stable(context, &external_call.source_path) {
            continue;
        }
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &external_call.owner_def_path,
            SiteRole::ExternalCall,
            source_path(context, &external_call.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(&external_call.mir_location)
        .with_span(&external_call.span);
        let site_id = descriptor.try_site_id()?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "external_call",
                &site_id,
                &external_call.source_path,
                &external_call.span,
                Some(&external_call.owner_def_path),
                StaticFact::ExternalCallSite(ExternalCallSiteFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    callback_site_id: None,
                    api_id: external_call.api_id.clone(),
                    role: external_call.role,
                }),
            )?,
        );
    }

    for bound in callback_lifetime_bounds {
        if !source_is_stable(context, &bound.source_path) {
            continue;
        }
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &bound.owner_def_path,
            SiteRole::CallbackLifetimeBound,
            source_path(context, &bound.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(&bound.mir_location)
        .with_span(&bound.span);
        let site_id = descriptor.try_site_id()?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "callback_lifetime_bound",
                &site_id,
                &bound.source_path,
                &bound.span,
                Some(&bound.owner_def_path),
                StaticFact::CallbackLifetimeBound(CallbackLifetimeBoundFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    api_id: bound.api_id.clone(),
                    callback_param: bound.callback_param.clone(),
                    bound_lifetime: bound.bound_lifetime.clone(),
                    bound_scope: bound.bound_scope,
                }),
            )?,
        );
    }

    for guard in registration_guards {
        if !source_is_stable(context, &guard.source_path) {
            continue;
        }
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &guard.owner_def_path,
            SiteRole::RegistrationGuard,
            source_path(context, &guard.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(&guard.mir_location)
        .with_span(&guard.span);
        let site_id = descriptor.try_site_id()?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "registration_guard",
                &site_id,
                &guard.source_path,
                &guard.span,
                Some(&guard.owner_def_path),
                StaticFact::RegistrationGuard(RegistrationGuardFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    api_id: guard.api_id.clone(),
                    callback_param: guard.callback_param.clone(),
                    guard_type: guard.guard_type.clone(),
                    foreign_release_callee: guard.foreign_release_callee.clone(),
                    guard: guard.guard,
                }),
            )?,
        );
    }

    for ownership in allocation_ownerships {
        if !source_is_stable(context, &ownership.source_path) {
            continue;
        }
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &ownership.owner_def_path,
            SiteRole::AllocationOwnership,
            source_path(context, &ownership.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(&ownership.mir_location)
        .with_span(&ownership.span);
        let site_id = descriptor.try_site_id()?;
        // 诊断用的 into_raw / 回收位置：与主 site 同源，只换 mir_location。
        let evidence_site = |mir_location: &Option<String>| -> Result<Option<SiteId>, DomainError> {
            let Some(mir_location) = mir_location else {
                return Ok(None);
            };
            let evidence = SiteDescriptor::new(
                &context.package,
                &context.target,
                &ownership.owner_def_path,
                SiteRole::AllocationOwnership,
                source_path(context, &ownership.source_path),
            )
            .with_repo_root(&context.repo_root)
            .with_mir_location(mir_location)
            .with_span(&ownership.span);
            Ok(Some(evidence.try_site_id()?))
        };
        let into_raw_site_id = evidence_site(&ownership.into_raw_mir_location)?;
        let reclaim_site_id = evidence_site(&ownership.reclaim_mir_location)?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "allocation_ownership",
                &site_id,
                &ownership.source_path,
                &ownership.span,
                Some(&ownership.owner_def_path),
                StaticFact::AllocationOwnership(AllocationOwnershipFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    api_id: ownership.api_id.clone(),
                    callback_param: ownership.callback_param.clone(),
                    into_raw_site_id,
                    reclaim_site_id,
                    ownership: ownership.ownership,
                }),
            )?,
        );
    }

    for relation in returned_borrow_relations {
        if !returned_borrow_relation_has_stable_sources(context, relation) {
            continue;
        }
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &relation.owner_def_path,
            SiteRole::ReturnedBorrowRelation,
            source_path(context, &relation.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(&relation.mir_location)
        .with_span(&relation.span);
        let site_id = descriptor.try_site_id()?;
        let source_site_id = borrow_source_site_id(context, &relation.source, &mut facts)?;
        let returned_site_id = returned_borrow_site_id(context, relation)?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "returned_borrow_relation",
                &site_id,
                &relation.source_path,
                &relation.span,
                Some(&relation.owner_def_path),
                StaticFact::ReturnedBorrowRelation(ReturnedBorrowRelationFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    source_site_id,
                    returned_site_id,
                    api_id: relation.api_id.clone(),
                    relation_kind: relation.relation_kind,
                }),
            )?,
        );
    }

    for persisted in persisted_returned_borrows {
        if !persisted_returned_borrow_has_stable_sources(context, persisted) {
            continue;
        }
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &persisted.owner_def_path,
            SiteRole::PersistedReturnedBorrow,
            source_path(context, &persisted.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(&persisted.mir_location)
        .with_span(&persisted.span);
        let site_id = descriptor.try_site_id()?;
        let source_site_id = borrow_source_site_id(context, &persisted.source, &mut facts)?;
        let returned_site_id = persisted_returned_borrow_site_id(context, persisted)?;
        let storage_site_id = returned_borrow_storage_site_id(context, persisted)?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "persisted_returned_borrow",
                &site_id,
                &persisted.source_path,
                &persisted.span,
                Some(&persisted.owner_def_path),
                StaticFact::PersistedReturnedBorrow(PersistedReturnedBorrowFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    source_site_id,
                    returned_site_id,
                    storage_site_id,
                    api_id: persisted.api_id.clone(),
                }),
            )?,
        );
    }

    for order in returned_borrow_invalidation_orders {
        if !returned_borrow_invalidation_order_has_stable_sources(context, order) {
            continue;
        }
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &order.owner_def_path,
            SiteRole::ReturnedBorrowInvalidationOrder,
            source_path(context, &order.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(&order.mir_location)
        .with_span(&order.span);
        let site_id = descriptor.try_site_id()?;
        let persisted_site_id = persisted_returned_borrow_site_id(context, &order.persisted)?;
        let invalidation_site_id = returned_borrow_invalidation_site_id(context, order)?;
        let use_site_id = returned_borrow_use_site_id(context, order)?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "returned_borrow_invalidation_order",
                &site_id,
                &order.source_path,
                &order.span,
                Some(&order.owner_def_path),
                StaticFact::ReturnedBorrowInvalidationOrder(ReturnedBorrowInvalidationOrderFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    persisted_site_id,
                    invalidation_site_id,
                    use_site_id,
                    api_id: order.api_id.clone(),
                    invalidation_api_id: order.invalidation_api_id.clone(),
                    ordering: order.ordering,
                }),
            )?,
        );
    }

    for binding in external_buffer_bindings {
        if !external_buffer_binding_has_stable_sources(context, binding) {
            continue;
        }
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &binding.owner_def_path,
            SiteRole::ExternalBufferBinding,
            source_path(context, &binding.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(&binding.mir_location)
        .with_span(&binding.span);
        let site_id = descriptor.try_site_id()?;
        let source_site_id = borrow_source_site_id(context, &binding.source, &mut facts)?;
        let buffer_site_id = external_buffer_site_id(context, binding)?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "external_buffer_binding",
                &site_id,
                &binding.source_path,
                &binding.span,
                Some(&binding.owner_def_path),
                StaticFact::ExternalBufferBinding(ExternalBufferBindingFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    source_site_id,
                    buffer_site_id,
                    api_id: binding.api_id.clone(),
                }),
            )?,
        );
    }

    for ordering in atomic_orderings {
        if !source_is_stable(context, &ordering.source_path) {
            continue;
        }
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &ordering.owner_def_path,
            SiteRole::AtomicOrdering,
            source_path(context, &ordering.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(&ordering.mir_location)
        .with_span(&ordering.span);
        let site_id = descriptor.try_site_id()?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "atomic_ordering",
                &site_id,
                &ordering.source_path,
                &ordering.span,
                Some(&ordering.owner_def_path),
                StaticFact::AtomicOrdering(AtomicOrderingFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    api_id: ordering.api_id.clone(),
                    operation: ordering.operation,
                    ordering: ordering.ordering,
                    target_type_name: ordering.target_type_name.clone(),
                }),
            )?,
        );
    }

    for gap in object_binding_gaps {
        if !source_is_stable(context, &gap.source_path) {
            continue;
        }
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &gap.owner_def_path,
            SiteRole::ObjectBindingGap,
            source_path(context, &gap.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(format!(
            "{}:object_binding_gap:{}",
            gap.mir_location,
            object_binding_gap_kind_token(gap.gap_kind)
        ))
        .with_span(&gap.span);
        let site_id = descriptor.try_site_id()?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "object_binding_gap",
                &site_id,
                &gap.source_path,
                &gap.span,
                Some(&gap.owner_def_path),
                StaticFact::ObjectBindingGap(ObjectBindingGapFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    api_id: gap.api_id.clone(),
                    gap_kind: gap.gap_kind,
                    field_path: gap.field_path.clone(),
                    container_type_name: gap.container_type_name.clone(),
                    adapter: gap.adapter.clone(),
                }),
            )?,
        );
    }

    for flow in object_flows {
        if !object_flow_has_stable_sources(context, flow) {
            continue;
        }
        let descriptor = SiteDescriptor::new(
            &context.package,
            &context.target,
            &flow.owner_def_path,
            SiteRole::ObjectFlow,
            source_path(context, &flow.source_path),
        )
        .with_repo_root(&context.repo_root)
        .with_mir_location(format!(
            "{}:object_flow:{}",
            flow.mir_location,
            object_flow_kind_token(flow.flow_kind)
        ))
        .with_span(&flow.span);
        let site_id = descriptor.try_site_id()?;
        let from_site_id = object_flow_endpoint_site_id(context, &flow.from, &mut facts)?;
        let to_site_id = object_flow_endpoint_site_id(context, &flow.to, &mut facts)?;
        insert_fact(
            &mut facts,
            envelope_with_source(
                context,
                "object_flow",
                &site_id,
                &flow.source_path,
                &flow.span,
                Some(&flow.owner_def_path),
                StaticFact::ObjectFlow(ObjectFlowFact {
                    site_id: site_id.clone(),
                    semantic_site_key: descriptor.semantic_key(),
                    from_site_id,
                    from_object_kind: flow.from_object_kind,
                    to_site_id,
                    to_object_kind: flow.to_object_kind,
                    flow_kind: flow.flow_kind,
                    api_id: flow.api_id.clone(),
                    field_path: flow.field_path.clone(),
                    container_type_name: flow.container_type_name.clone(),
                }),
            )?,
        );
    }

    Ok(facts.into_values().collect())
}

fn registration_site_descriptor(
    context: &StaticFactContext,
    registration: &RegistrationObservation,
) -> SiteDescriptor {
    SiteDescriptor::new(
        &context.package,
        &context.target,
        &registration.owner_def_path,
        SiteRole::Registration,
        source_path(context, &registration.source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&registration.mir_location)
    .with_span(&registration.span)
}

fn callback_user_data_reconstruction_site_descriptor(
    context: &StaticFactContext,
    reconstruction: &CallbackUserDataReconstructionObservation,
) -> SiteDescriptor {
    SiteDescriptor::new(
        &context.package,
        &context.target,
        &reconstruction.owner_def_path,
        SiteRole::CallbackUserDataReconstruction,
        source_path(context, &reconstruction.source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&reconstruction.mir_location)
    .with_span(&reconstruction.span)
}

fn raw_pointer_transfer_site_descriptor(
    context: &StaticFactContext,
    transfer: &RawPointerTransferObservation,
) -> SiteDescriptor {
    SiteDescriptor::new(
        &context.package,
        &context.target,
        &transfer.owner_def_path,
        SiteRole::RawPointerTransfer,
        source_path(context, &transfer.source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&transfer.mir_location)
    .with_span(&transfer.span)
}

fn capture_observation_has_stable_sources(
    context: &StaticFactContext,
    observation: &CaptureObservation,
) -> bool {
    source_is_stable(context, &observation.callback_source_path)
        && source_is_stable(context, &observation.capture_source_path)
        && source_is_stable(context, &observation.object_source_path)
}

fn release_path_proof_has_stable_sources(
    context: &StaticFactContext,
    proof: &ReleasePathProofObservation,
) -> bool {
    source_is_stable(context, &proof.source_path)
        && source_is_stable(context, &proof.registration.source_path)
        && source_is_stable(context, &proof.release.source_path)
        && proof
            .registration
            .user_data
            .as_ref()
            .is_none_or(|user_data| source_is_stable(context, &user_data.source_path))
        && source_is_stable(context, &proof.release.user_data.source_path)
}

fn callback_release_use_order_has_stable_sources(
    context: &StaticFactContext,
    order: &CallbackReleaseUseOrderObservation,
) -> bool {
    source_is_stable(context, &order.source_path)
        && source_is_stable(context, &order.registration.source_path)
        && source_is_stable(context, &order.release.source_path)
        && order
            .registration
            .user_data
            .as_ref()
            .is_none_or(|user_data| source_is_stable(context, &user_data.source_path))
        && source_is_stable(context, &order.release.user_data.source_path)
        && source_is_stable(context, &order.reconstruction.source_path)
        && source_is_stable(context, &order.reconstruction.user_data.source_path)
}

fn returned_borrow_relation_has_stable_sources(
    context: &StaticFactContext,
    relation: &ReturnedBorrowRelationObservation,
) -> bool {
    source_is_stable(context, &relation.source_path)
        && source_is_stable(context, &relation.source.source_path)
}

fn persisted_returned_borrow_has_stable_sources(
    context: &StaticFactContext,
    persisted: &PersistedReturnedBorrowObservation,
) -> bool {
    source_is_stable(context, &persisted.source_path)
        && source_is_stable(context, &persisted.source.source_path)
}

fn returned_borrow_invalidation_order_has_stable_sources(
    context: &StaticFactContext,
    order: &ReturnedBorrowInvalidationOrderObservation,
) -> bool {
    source_is_stable(context, &order.source_path)
        && persisted_returned_borrow_has_stable_sources(context, &order.persisted)
        && source_is_stable(context, &order.invalidation_source_path)
        && source_is_stable(context, &order.use_source_path)
}

fn external_buffer_binding_has_stable_sources(
    context: &StaticFactContext,
    binding: &ExternalBufferBindingObservation,
) -> bool {
    source_is_stable(context, &binding.source_path)
        && source_is_stable(context, &binding.source.source_path)
}

fn object_flow_has_stable_sources(
    context: &StaticFactContext,
    flow: &ObjectFlowObservation,
) -> bool {
    source_is_stable(context, &flow.source_path)
        && object_flow_endpoint_has_stable_source(context, &flow.from)
        && object_flow_endpoint_has_stable_source(context, &flow.to)
}

fn object_flow_endpoint_has_stable_source(
    context: &StaticFactContext,
    endpoint: &ObjectFlowEndpointObservation,
) -> bool {
    match endpoint {
        ObjectFlowEndpointObservation::UserData(user_data) => {
            source_is_stable(context, &user_data.source_path)
        }
        ObjectFlowEndpointObservation::CallbackSite(callback) => {
            source_is_stable(context, &callback.source_path)
        }
        ObjectFlowEndpointObservation::RegistrationSite(registration) => {
            source_is_stable(context, &registration.source_path)
        }
        ObjectFlowEndpointObservation::RawPointerTransferSite(transfer) => {
            source_is_stable(context, &transfer.source_path)
                && source_is_stable(context, &transfer.user_data.source_path)
        }
        ObjectFlowEndpointObservation::ReturnedBorrow(persisted)
        | ObjectFlowEndpointObservation::Storage(persisted) => {
            persisted_returned_borrow_has_stable_sources(context, persisted)
        }
        ObjectFlowEndpointObservation::ReturnedBorrowUse(order) => {
            returned_borrow_invalidation_order_has_stable_sources(context, order)
        }
        ObjectFlowEndpointObservation::StaticSite(site) => {
            source_is_stable(context, &site.source_path)
        }
    }
}

fn source_is_stable(context: &StaticFactContext, path: &Path) -> bool {
    stable_relative_path(&source_path(context, path), Some(&context.repo_root)).is_ok()
}

fn captured_objects_by_callback(facts: &[StaticFactEnvelope]) -> BTreeMap<String, Vec<SiteId>> {
    let mut objects_by_callback = BTreeMap::<String, Vec<SiteId>>::new();
    for fact in facts {
        if let StaticFact::CallbackCapture(capture) = &fact.payload {
            objects_by_callback
                .entry(capture.callback_site_id.to_string())
                .or_default()
                .push(capture.object_site_id.clone());
        }
    }
    for object_site_ids in objects_by_callback.values_mut() {
        object_site_ids.sort();
        object_site_ids.dedup();
    }
    objects_by_callback
}

fn insert_dropped_object_fact(
    context: &StaticFactContext,
    drop: &DropObservation,
    facts: &mut BTreeMap<RecordId, StaticFactEnvelope>,
) -> Result<SiteId, DomainError> {
    let object_descriptor = SiteDescriptor::new(
        &context.package,
        &context.target,
        &drop.owner_def_path,
        SiteRole::Object,
        source_path(context, &drop.source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&drop.mir_location)
    .with_span(&drop.span);
    let object_site_id = object_descriptor.try_site_id()?;
    insert_fact(
        facts,
        envelope_with_source(
            context,
            "object",
            &object_site_id,
            &drop.source_path,
            &drop.span,
            Some(&drop.owner_def_path),
            StaticFact::ObjectSite(ObjectSiteFact {
                site_id: object_site_id.clone(),
                semantic_site_key: object_descriptor.semantic_key(),
                type_name: drop.object_type_name.clone(),
            }),
        )?,
    );
    Ok(object_site_id)
}

fn insert_drop_prevention_object_fact(
    context: &StaticFactContext,
    prevention: &DropPreventionObservation,
    facts: &mut BTreeMap<RecordId, StaticFactEnvelope>,
) -> Result<SiteId, DomainError> {
    let object_descriptor = SiteDescriptor::new(
        &context.package,
        &context.target,
        &prevention.owner_def_path,
        SiteRole::Object,
        source_path(context, &prevention.source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&prevention.mir_location)
    .with_span(&prevention.span);
    let object_site_id = object_descriptor.try_site_id()?;
    insert_fact(
        facts,
        envelope_with_source(
            context,
            "object",
            &object_site_id,
            &prevention.source_path,
            &prevention.span,
            Some(&prevention.owner_def_path),
            StaticFact::ObjectSite(ObjectSiteFact {
                site_id: object_site_id.clone(),
                semantic_site_key: object_descriptor.semantic_key(),
                type_name: prevention.object_type_name.clone(),
            }),
        )?,
    );
    Ok(object_site_id)
}

fn insert_callback_user_data_reconstruction_object_fact(
    context: &StaticFactContext,
    reconstruction: &CallbackUserDataReconstructionObservation,
    facts: &mut BTreeMap<RecordId, StaticFactEnvelope>,
) -> Result<SiteId, DomainError> {
    let object_descriptor = SiteDescriptor::new(
        &context.package,
        &context.target,
        &reconstruction.owner_def_path,
        SiteRole::Object,
        source_path(context, &reconstruction.source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&reconstruction.mir_location)
    .with_span(&reconstruction.span);
    let object_site_id = object_descriptor.try_site_id()?;
    insert_fact(
        facts,
        envelope_with_source(
            context,
            "object",
            &object_site_id,
            &reconstruction.source_path,
            &reconstruction.span,
            Some(&reconstruction.owner_def_path),
            StaticFact::ObjectSite(ObjectSiteFact {
                site_id: object_site_id.clone(),
                semantic_site_key: object_descriptor.semantic_key(),
                type_name: reconstruction.object_type_name.clone(),
            }),
        )?,
    );
    Ok(object_site_id)
}

fn callback_site_id_for_owner(
    context: &StaticFactContext,
    reconstruction: &CallbackUserDataReconstructionObservation,
    facts: &mut BTreeMap<RecordId, StaticFactEnvelope>,
) -> Result<SiteId, DomainError> {
    let callback = CallbackReference {
        def_path: reconstruction.owner_def_path.clone(),
        source_path: reconstruction.source_path.clone(),
        span: reconstruction.span.clone(),
    };
    callback_site_id(context, &callback, facts)
}

fn callback_site_id(
    context: &StaticFactContext,
    callback: &CallbackReference,
    facts: &mut BTreeMap<RecordId, StaticFactEnvelope>,
) -> Result<SiteId, DomainError> {
    let descriptor = SiteDescriptor::new(
        &context.package,
        &context.target,
        &callback.def_path,
        SiteRole::Callback,
        source_path(context, &callback.source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_span(&callback.span);
    let site_id = descriptor.try_site_id()?;
    insert_fact(
        facts,
        envelope_with_source(
            context,
            "callback",
            &site_id,
            &callback.source_path,
            &callback.span,
            Some(&callback.def_path),
            StaticFact::CallbackSite(CallbackSiteFact {
                site_id: site_id.clone(),
                semantic_site_key: descriptor.semantic_key(),
                def_path: callback.def_path.clone(),
            }),
        )?,
    );
    Ok(site_id)
}

fn user_data_site_id(
    context: &StaticFactContext,
    user_data: &RawPointerReference,
    facts: &mut BTreeMap<RecordId, StaticFactEnvelope>,
) -> Result<SiteId, DomainError> {
    let descriptor = SiteDescriptor::new(
        &context.package,
        &context.target,
        &user_data.owner_def_path,
        SiteRole::Object,
        source_path(context, &user_data.source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&user_data.mir_location)
    .with_span(&user_data.span);
    let site_id = descriptor.try_site_id()?;
    insert_fact(
        facts,
        envelope_with_source(
            context,
            "user_data",
            &site_id,
            &user_data.source_path,
            &user_data.span,
            Some(&user_data.owner_def_path),
            StaticFact::ObjectSite(ObjectSiteFact {
                site_id: site_id.clone(),
                semantic_site_key: descriptor.semantic_key(),
                type_name: user_data.type_name.clone(),
            }),
        )?,
    );
    Ok(site_id)
}

fn borrow_source_site_id(
    context: &StaticFactContext,
    source: &BorrowReference,
    _facts: &mut BTreeMap<RecordId, StaticFactEnvelope>,
) -> Result<SiteId, DomainError> {
    let descriptor = SiteDescriptor::new(
        &context.package,
        &context.target,
        &source.owner_def_path,
        SiteRole::BorrowSource,
        source_path(context, &source.source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&source.mir_location)
    .with_span(&source.span);
    Ok(descriptor.try_site_id()?)
}

fn returned_borrow_site_id(
    context: &StaticFactContext,
    relation: &ReturnedBorrowRelationObservation,
) -> Result<SiteId, DomainError> {
    let descriptor = SiteDescriptor::new(
        &context.package,
        &context.target,
        &relation.owner_def_path,
        SiteRole::ReturnedBorrow,
        source_path(context, &relation.source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&relation.mir_location)
    .with_span(&relation.span);
    Ok(descriptor.try_site_id()?)
}

fn persisted_returned_borrow_site_id(
    context: &StaticFactContext,
    persisted: &PersistedReturnedBorrowObservation,
) -> Result<SiteId, DomainError> {
    let descriptor = SiteDescriptor::new(
        &context.package,
        &context.target,
        &persisted.owner_def_path,
        SiteRole::ReturnedBorrow,
        source_path(context, &persisted.source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&persisted.mir_location)
    .with_span(&persisted.span);
    Ok(descriptor.try_site_id()?)
}

fn returned_borrow_storage_site_id(
    context: &StaticFactContext,
    persisted: &PersistedReturnedBorrowObservation,
) -> Result<SiteId, DomainError> {
    let descriptor = SiteDescriptor::new(
        &context.package,
        &context.target,
        &persisted.owner_def_path,
        SiteRole::ReturnedBorrowStorage,
        source_path(context, &persisted.source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&persisted.mir_location)
    .with_span(&persisted.span);
    Ok(descriptor.try_site_id()?)
}

fn returned_borrow_invalidation_site_id(
    context: &StaticFactContext,
    order: &ReturnedBorrowInvalidationOrderObservation,
) -> Result<SiteId, DomainError> {
    let descriptor = SiteDescriptor::new(
        &context.package,
        &context.target,
        &order.invalidation_owner_def_path,
        SiteRole::ReturnedBorrowInvalidation,
        source_path(context, &order.invalidation_source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&order.invalidation_mir_location)
    .with_span(&order.invalidation_span);
    Ok(descriptor.try_site_id()?)
}

fn returned_borrow_use_site_id(
    context: &StaticFactContext,
    order: &ReturnedBorrowInvalidationOrderObservation,
) -> Result<SiteId, DomainError> {
    let descriptor = SiteDescriptor::new(
        &context.package,
        &context.target,
        &order.use_owner_def_path,
        SiteRole::ReturnedBorrowUse,
        source_path(context, &order.use_source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&order.use_mir_location)
    .with_span(&order.use_span);
    Ok(descriptor.try_site_id()?)
}

fn external_buffer_site_id(
    context: &StaticFactContext,
    binding: &ExternalBufferBindingObservation,
) -> Result<SiteId, DomainError> {
    let descriptor = SiteDescriptor::new(
        &context.package,
        &context.target,
        &binding.owner_def_path,
        SiteRole::ExternalBuffer,
        source_path(context, &binding.source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&binding.mir_location)
    .with_span(&binding.span);
    Ok(descriptor.try_site_id()?)
}

fn object_flow_endpoint_site_id(
    context: &StaticFactContext,
    endpoint: &ObjectFlowEndpointObservation,
    facts: &mut BTreeMap<RecordId, StaticFactEnvelope>,
) -> Result<SiteId, DomainError> {
    match endpoint {
        ObjectFlowEndpointObservation::UserData(user_data) => {
            user_data_site_id(context, user_data, facts)
        }
        ObjectFlowEndpointObservation::CallbackSite(callback) => {
            callback_site_id(context, callback, facts)
        }
        ObjectFlowEndpointObservation::RegistrationSite(registration) => {
            registration_site_descriptor(context, registration)
                .try_site_id()
                .map_err(Into::into)
        }
        ObjectFlowEndpointObservation::RawPointerTransferSite(transfer) => {
            raw_pointer_transfer_site_descriptor(context, transfer)
                .try_site_id()
                .map_err(Into::into)
        }
        ObjectFlowEndpointObservation::ReturnedBorrow(persisted) => {
            persisted_returned_borrow_site_id(context, persisted)
        }
        ObjectFlowEndpointObservation::Storage(persisted) => {
            returned_borrow_storage_site_id(context, persisted)
        }
        ObjectFlowEndpointObservation::ReturnedBorrowUse(order) => {
            returned_borrow_use_site_id(context, order)
        }
        ObjectFlowEndpointObservation::StaticSite(site) => {
            object_flow_static_site_id(context, site, facts)
        }
    }
}

fn object_flow_static_site_id(
    context: &StaticFactContext,
    site: &ObjectFlowStaticSiteObservation,
    facts: &mut BTreeMap<RecordId, StaticFactEnvelope>,
) -> Result<SiteId, DomainError> {
    let descriptor = SiteDescriptor::new(
        &context.package,
        &context.target,
        &site.owner_def_path,
        SiteRole::Object,
        source_path(context, &site.source_path),
    )
    .with_repo_root(&context.repo_root)
    .with_mir_location(&site.mir_location)
    .with_span(&site.span);
    let site_id = descriptor.try_site_id()?;
    insert_fact(
        facts,
        envelope_with_source(
            context,
            "object_flow_endpoint",
            &site_id,
            &site.source_path,
            &site.span,
            Some(&site.owner_def_path),
            StaticFact::ObjectSite(ObjectSiteFact {
                site_id: site_id.clone(),
                semantic_site_key: descriptor.semantic_key(),
                type_name: site.type_name.clone(),
            }),
        )?,
    );
    Ok(site_id)
}

fn object_flow_kind_token(kind: ObjectFlowKind) -> &'static str {
    match kind {
        ObjectFlowKind::Argument => "argument",
        ObjectFlowKind::ReturnValue => "return_value",
        ObjectFlowKind::FieldStore => "field_store",
        ObjectFlowKind::FieldLoad => "field_load",
        ObjectFlowKind::WrapperMove => "wrapper_move",
        ObjectFlowKind::WrapperDestructure => "wrapper_destructure",
        ObjectFlowKind::CollectionStore => "collection_store",
        ObjectFlowKind::CollectionLoad => "collection_load",
        ObjectFlowKind::ClosureCapture => "closure_capture",
    }
}

fn object_binding_gap_kind_token(kind: ObjectBindingGapKind) -> &'static str {
    match kind {
        ObjectBindingGapKind::SelectionPredicate => "selection_predicate",
        ObjectBindingGapKind::MappedValue => "mapped_value",
        ObjectBindingGapKind::MergedSources => "merged_sources",
        ObjectBindingGapKind::TupleProjection => "tuple_projection",
        ObjectBindingGapKind::CardinalityTransform => "cardinality_transform",
        ObjectBindingGapKind::DynamicIndex => "dynamic_index",
        ObjectBindingGapKind::RangeOrSlice => "range_or_slice",
        ObjectBindingGapKind::SequenceLengthUnknown => "sequence_length_unknown",
        ObjectBindingGapKind::KeyContract => "key_contract",
        ObjectBindingGapKind::ReassignmentBarrier => "reassignment_barrier",
        ObjectBindingGapKind::MutationBarrier => "mutation_barrier",
        ObjectBindingGapKind::CallBoundary => "call_boundary",
        ObjectBindingGapKind::UnresolvedCallee => "unresolved_callee",
    }
}

pub fn write_static_facts(
    output_dir: &Path,
    facts: &[StaticFactEnvelope],
) -> Result<(), DomainError> {
    fs::create_dir_all(output_dir)?;
    let shards_dir = output_dir.join("static-facts");
    fs::create_dir_all(&shards_dir)?;
    if let Some(artifact) = facts.first().and_then(|fact| fact.artifact.as_ref()) {
        if facts
            .iter()
            .any(|fact| fact.artifact.as_ref() != Some(artifact))
        {
            return Err(DomainError::MixedArtifactIdentity);
        }
        let shard_name = static_fact_shard_name(artifact);
        write_static_fact_records(&shards_dir.join(format!("{shard_name}.jsonl")), facts)?;
    }

    // Cargo can invoke the wrapper for multiple allowlisted crates concurrently. Shards are
    // immutable per artifact identity; the short lock only serializes deterministic aggregation.
    let _lock = StaticFactWriteLock::acquire(output_dir)?;
    aggregate_static_fact_shards(output_dir, &shards_dir)?;
    Ok(())
}

#[derive(Serialize)]
struct StaticFactShardManifest {
    schema_version: &'static str,
    shards: Vec<StaticFactShardManifestEntry>,
}

#[derive(Serialize)]
struct StaticFactShardManifestEntry {
    path: String,
    artifact: StaticArtifactIdentity,
    record_count: usize,
}

struct StaticFactWriteLock {
    path: PathBuf,
    _file: File,
}

impl StaticFactWriteLock {
    fn acquire(output_dir: &Path) -> Result<Self, DomainError> {
        let path = output_dir.join(".static-facts.lock");
        for _ in 0..200 {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok(Self { path, _file: file }),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(DomainError::Io(error)),
            }
        }
        Err(DomainError::StaticFactLockTimeout { path })
    }
}

impl Drop for StaticFactWriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn aggregate_static_fact_shards(output_dir: &Path, shards_dir: &Path) -> Result<(), DomainError> {
    let mut shard_paths = fs::read_dir(shards_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("jsonl"))
        .collect::<Vec<_>>();
    shard_paths.sort();

    let mut records = BTreeMap::<String, StaticFactEnvelope>::new();
    let mut shards = Vec::<StaticFactShardManifestEntry>::new();
    for shard_path in shard_paths {
        let shard_records = read_static_fact_records(&shard_path)?;
        let record_count = shard_records.len();
        let artifact = shard_records
            .first()
            .and_then(|fact| fact.artifact.clone())
            .ok_or_else(|| DomainError::StaticFactShardMissingArtifact {
                path: shard_path.clone(),
            })?;
        if shard_records
            .iter()
            .any(|fact| fact.artifact.as_ref() != Some(&artifact))
        {
            return Err(DomainError::MixedShardArtifactIdentity { path: shard_path });
        }
        for record in shard_records {
            let key = format!(
                "{}:{}:{}",
                record.record_id, record.build_id, artifact.crate_id
            );
            if let Some(existing) = records.get(&key)
                && existing != &record
            {
                return Err(DomainError::ConflictingStaticFactRecord { key });
            }
            records.insert(key, record);
        }
        shards.push(StaticFactShardManifestEntry {
            path: format!(
                "static-facts/{}",
                shard_path.file_name().unwrap().to_string_lossy()
            ),
            artifact,
            record_count,
        });
    }

    let final_path = output_dir.join("static-facts.jsonl");
    write_static_fact_records(&final_path, &records.into_values().collect::<Vec<_>>())?;
    write_json_atomic(
        &output_dir.join("static-facts.manifest.json"),
        &StaticFactShardManifest {
            schema_version: "bw.static-facts.manifest/0.1",
            shards,
        },
    )
}

fn write_static_fact_records(
    final_path: &Path,
    facts: &[StaticFactEnvelope],
) -> Result<(), DomainError> {
    let partial_path = final_path.with_extension(format!("jsonl.{}.partial", std::process::id()));
    let mut output = String::new();
    for fact in facts {
        output.push_str(&serde_json::to_string(fact)?);
        output.push('\n');
    }
    fs::write(&partial_path, output)?;
    fs::rename(partial_path, final_path)?;
    Ok(())
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<(), DomainError> {
    let partial_path = path.with_extension(format!("json.{}.partial", std::process::id()));
    fs::write(&partial_path, serde_json::to_vec_pretty(value)?)?;
    fs::rename(partial_path, path)?;
    Ok(())
}

fn read_static_fact_records(path: &Path) -> Result<Vec<StaticFactEnvelope>, DomainError> {
    let text = fs::read_to_string(path)?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()
        .map_err(DomainError::Serde)
}

fn static_fact_shard_name(artifact: &StaticArtifactIdentity) -> String {
    let identity = [
        artifact.crate_id.as_str(),
        artifact.package_name.as_str(),
        artifact.package_version.as_str(),
        artifact.target.as_str(),
    ]
    .join("\u{1f}");
    format!(
        "{}-{}-{}-{}",
        sanitize_file_component(&artifact.package_name),
        sanitize_file_component(&artifact.package_version),
        sanitize_file_component(&artifact.target),
        hex_digest(Sha256::digest(identity.as_bytes()))[..16].to_owned(),
    )
}

fn sanitize_file_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn envelope_with_source(
    context: &StaticFactContext,
    fact_kind: &str,
    site_id: &SiteId,
    source_path_value: &Path,
    span: &str,
    symbol_path: Option<&str>,
    payload: StaticFact,
) -> Result<StaticFactEnvelope, DomainError> {
    Ok(StaticFactEnvelope {
        schema_version: STATIC_SCHEMA_V02.to_owned(),
        record_id: record_id_for(fact_kind, site_id),
        producer: context.producer.clone(),
        build_id: context.build_id.clone(),
        artifact: Some(StaticArtifactIdentity {
            crate_id: context.crate_id.clone(),
            package_name: context.package_name.clone(),
            package_version: context.package_version.clone(),
            target: context.target.clone(),
        }),
        source_ref: Some(static_source_ref(
            context,
            source_path_value,
            span,
            symbol_path,
        )?),
        payload,
    })
}

fn static_source_ref(
    context: &StaticFactContext,
    source_path_value: &Path,
    span: &str,
    symbol_path: Option<&str>,
) -> Result<StaticSourceRef, DomainError> {
    let absolute_path = source_path(context, source_path_value);
    let path = stable_relative_path(&absolute_path, Some(&context.repo_root))?;
    let (line_start, line_end) = span_line_range(span).ok_or_else(|| DomainError::InvalidSpan {
        span: span.to_owned(),
    })?;
    Ok(StaticSourceRef {
        path,
        line_start,
        line_end,
        symbol_path: symbol_path.map(ToOwned::to_owned),
    })
}

fn span_line_range(span: &str) -> Option<(u64, u64)> {
    let (start, end) = span.split_once('-')?;
    let line_start = start.split_once(':')?.0.parse().ok()?;
    let line_end = end.split_once(':')?.0.parse().ok()?;
    (line_start >= 1 && line_end >= line_start).then_some((line_start, line_end))
}

fn record_id_for(fact_kind: &str, site_id: &SiteId) -> RecordId {
    RecordId::from(format!(
        "fact:{fact_kind}:{}",
        site_id
            .as_str()
            .strip_prefix("site:")
            .unwrap_or(site_id.as_str())
    ))
}

fn source_path(context: &StaticFactContext, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        context.repo_root.join(path)
    }
}

fn insert_fact(facts: &mut BTreeMap<RecordId, StaticFactEnvelope>, envelope: StaticFactEnvelope) {
    facts.entry(envelope.record_id.clone()).or_insert(envelope);
}

#[derive(Debug)]
pub enum DomainError {
    SiteIdentity(SiteIdentityError),
    InvalidSpan { span: String },
    MixedArtifactIdentity,
    StaticFactLockTimeout { path: PathBuf },
    StaticFactShardMissingArtifact { path: PathBuf },
    MixedShardArtifactIdentity { path: PathBuf },
    ConflictingStaticFactRecord { key: String },
    Io(std::io::Error),
    Serde(serde_json::Error),
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SiteIdentity(error) => write!(formatter, "{error}"),
            Self::InvalidSpan { span } => write!(formatter, "invalid source span {span}"),
            Self::MixedArtifactIdentity => {
                formatter.write_str("static fact batch mixes artifact identities")
            }
            Self::StaticFactLockTimeout { path } => {
                write!(
                    formatter,
                    "timed out waiting for static fact lock {}",
                    path.display()
                )
            }
            Self::StaticFactShardMissingArtifact { path } => {
                write!(
                    formatter,
                    "static fact shard {} has no artifact identity",
                    path.display()
                )
            }
            Self::MixedShardArtifactIdentity { path } => write!(
                formatter,
                "static fact shard {} mixes artifact identities",
                path.display()
            ),
            Self::ConflictingStaticFactRecord { key } => {
                write!(formatter, "conflicting static fact record {key}")
            }
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Serde(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for DomainError {}

impl From<SiteIdentityError> for DomainError {
    fn from(value: SiteIdentityError) -> Self {
        Self::SiteIdentity(value)
    }
}

impl From<std::io::Error> for DomainError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for DomainError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serde(value)
    }
}
