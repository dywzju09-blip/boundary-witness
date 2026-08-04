use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    ops::ControlFlow,
    path::PathBuf,
};

use super::rustc_hir::def::DefKind;
use super::rustc_hir::def_id::{DefId, LocalDefId};
use super::rustc_hir::{self as hir};
use super::rustc_index::Idx;
use super::rustc_middle::mir::{
    AggregateKind, BasicBlock, Body, Local, Location, Operand, Place, ProjectionElem, RETURN_PLACE,
    Rvalue, StatementKind, Terminator, TerminatorKind, visit::Visitor,
};
use super::rustc_middle::ty::{self, Ty, TyCtxt, TypeSuperVisitable, TypeVisitable, TypeVisitor};
use super::rustc_span::{FileName, RemapPathScopeComponents, Span};
use bw_model::{
    AllocationOwnership, AtomicOperationKind, AtomicOrderingKind, CallbackLifetimeBoundScope,
    CallbackReleaseUseOrdering, CallbackUserDataReconstructionKind, DropKind, DropPreventionKind,
    ObjectBindingGapKind, ObjectFlowKind, ObjectFlowObjectKind, RawPointerTransferKind,
    RegistrationGuard, ReturnedBorrowInvalidationOrdering, ReturnedBorrowRelationKind,
};
use sha2::{Digest, Sha256};

use crate::{
    config::CollectionLookupContract,
    domain::{
        AtomicOrderingObservation, BorrowReference, CallbackLifetimeBoundObservation,
        CallbackReference, CallbackReleaseUseOrderObservation,
        CallbackUserDataReconstructionObservation, CaptureObservation, DropObservation,
        DropPreventionObservation, ExternalBufferBindingObservation, ExternalCallObservation,
        ObjectBindingGapObservation, ObjectFlowEndpointObservation, ObjectFlowObservation,
        ObjectFlowStaticSiteObservation, PersistedReturnedBorrowObservation, RawPointerReference,
        AllocationOwnershipObservation, RawPointerTransferObservation,
        RegistrationGuardObservation, RegistrationObservation,
        ReleasePathProofObservation, ReturnedBorrowInvalidationOrderObservation,
        ReturnedBorrowRelationObservation, closure_capture_object_flow_field_path,
    },
    registration::{self, CallClassification, CallContext, RegistrationArgumentKind},
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MirSiteObservations {
    pub seen_bodies: Vec<String>,
    pub drops: Vec<DropObservation>,
    pub drop_preventions: Vec<DropPreventionObservation>,
    pub callback_user_data_reconstructions: Vec<CallbackUserDataReconstructionObservation>,
    pub registrations: Vec<RegistrationObservation>,
    pub raw_pointer_transfers: Vec<RawPointerTransferObservation>,
    pub release_path_proofs: Vec<ReleasePathProofObservation>,
    pub callback_release_use_orders: Vec<CallbackReleaseUseOrderObservation>,
    pub external_calls: Vec<ExternalCallObservation>,
    pub callback_lifetime_bounds: Vec<CallbackLifetimeBoundObservation>,
    pub registration_guards: Vec<RegistrationGuardObservation>,
    pub allocation_ownerships: Vec<AllocationOwnershipObservation>,
    pub returned_borrow_relations: Vec<ReturnedBorrowRelationObservation>,
    pub persisted_returned_borrows: Vec<PersistedReturnedBorrowObservation>,
    pub returned_borrow_invalidation_orders: Vec<ReturnedBorrowInvalidationOrderObservation>,
    pub external_buffer_bindings: Vec<ExternalBufferBindingObservation>,
    pub atomic_orderings: Vec<AtomicOrderingObservation>,
    pub object_binding_gaps: Vec<ObjectBindingGapObservation>,
    pub object_flows: Vec<ObjectFlowObservation>,
}

type ClosureStorageCaptureSummaries = BTreeMap<String, BTreeMap<Vec<String>, Option<String>>>;
type ClosureReturnedBorrowCaptureSummaries =
    BTreeMap<String, BTreeMap<Vec<String>, Option<ReturnedBorrowOrigin>>>;
type ClosureCaptureUseSummaries =
    BTreeMap<String, BTreeMap<Vec<String>, Option<ClosureCaptureUseSummary>>>;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClosureCaptureUseSummary {
    callback_def_path: String,
    callback_source_path: PathBuf,
    callback_span: String,
    field_path: String,
    object_type_name: String,
}

pub fn collect_mir_sites<'tcx>(
    tcx: TyCtxt<'tcx>,
    current_crate_name: &str,
    collection_lookup_contracts: &[CollectionLookupContract],
    captures: &[CaptureObservation],
) -> Result<MirSiteObservations, MirExtractionError> {
    let mut observations = MirSiteObservations::default();
    let mut returned_borrow_invalidations = Vec::<ReturnedBorrowInvalidationCall>::new();
    let mut returned_borrow_storage_uses = Vec::<ReturnedBorrowStorageUse>::new();
    let mut returned_borrow_storage_mutation_barriers =
        Vec::<ReturnedBorrowStorageMutationBarrier>::new();
    let mut local_method_calls = Vec::<LocalMethodCall>::new();
    let mut callback_user_data_invocations = Vec::<CallbackUserDataInvocation>::new();
    let mut mir_order_graphs = BTreeMap::<String, MirOrderGraph>::new();
    let mut openssl_ex_data_registrations = Vec::<OpenSslExDataRegistration>::new();
    let mut openssl_ex_data_releases = Vec::<OpenSslExDataRelease>::new();
    let mut openssl_ex_data_free_contracts = BTreeMap::<String, OpenSslExDataFreeContract>::new();
    let body_owners = tcx
        .hir_body_owners()
        .filter(|def_id| {
            is_optimized_mir_owner(tcx.def_kind(def_id.to_def_id()))
                && tcx.is_mir_available(def_id.to_def_id())
        })
        .collect::<Vec<_>>();
    let mut closure_storage_capture_summaries = ClosureStorageCaptureSummaries::new();
    let mut closure_returned_borrow_capture_summaries =
        ClosureReturnedBorrowCaptureSummaries::new();
    let closure_capture_use_summaries = closure_capture_use_summaries_from_captures(captures);
    for def_id in &body_owners {
        let body = tcx.optimized_mir(*def_id);
        let owner_def_path = tcx.def_path_str(def_id.to_def_id());
        let owner_is_foreign_callback = owner_is_foreign_callback(tcx, def_id.to_def_id());
        let mut visitor = MirSiteVisitor {
            tcx,
            body,
            current_crate_name,
            collection_lookup_contracts,
            owner_def_path,
            owner_is_foreign_callback,
            observations: MirSiteObservations::default(),
            raw_pointer_origins: BTreeMap::new(),
            raw_pointer_borrow_origins: BTreeMap::new(),
            closure_upvar_sources: BTreeMap::new(),
            receiver_borrow_locals: BTreeMap::new(),
            borrowed_foreign_pointer_origins: BTreeMap::new(),
            returned_borrow_origins: BTreeMap::new(),
            returned_borrow_return_origins: Vec::new(),
            returned_borrow_slot_assignment_origins: Vec::new(),
            returned_borrow_iterator_origins: BTreeMap::new(),
            fn_pointer_origins: BTreeMap::new(),
            option_fn_pointer_origins: BTreeMap::new(),
            fn_pointer_source_origins: BTreeMap::new(),
            option_fn_pointer_source_origins: BTreeMap::new(),
            option_fn_pointer_release_origins: BTreeMap::new(),
            previous_user_data_origins: BTreeMap::new(),
            hook_release_field_writes: Vec::new(),
            hook_previous_release_candidates: Vec::new(),
            borrow_origins: BTreeMap::new(),
            returned_borrow_storage_origins: BTreeMap::new(),
            returned_borrow_storage_reference_origins: BTreeMap::new(),
            returned_borrow_entry_value_reference_origins: BTreeMap::new(),
            pending_returned_borrow_entry_value_assignments: Vec::new(),
            returned_borrow_indexed_iterator_storage_origins: BTreeMap::new(),
            returned_borrow_slice_storage_origins: BTreeMap::new(),
            returned_borrow_unique_storage_origins: BTreeMap::new(),
            returned_borrow_local_wrapper_reference_origins: BTreeMap::new(),
            returned_borrow_invalidated_storage_keys: BTreeSet::new(),
            returned_borrow_sequence_lengths: BTreeMap::new(),
            returned_borrow_keyed_map_entry_origins: BTreeMap::new(),
            returned_borrow_keyed_map_entry_branch_writes: BTreeMap::new(),
            returned_borrow_keyed_map_split_entry_branch_writes: BTreeMap::new(),
            returned_borrow_keyed_map_known_empty: BTreeSet::new(),
            returned_borrow_keyed_map_known_occupied: BTreeSet::new(),
            stable_constant_origins: BTreeMap::new(),
            stable_range_origins: BTreeMap::new(),
            scoped_key_origins: BTreeMap::new(),
            unsupported_key_wrapper_origins: BTreeMap::new(),
            dynamic_key_generations: BTreeMap::new(),
            closure_storage_capture_summaries: closure_storage_capture_summaries.clone(),
            discovered_closure_storage_captures: BTreeMap::new(),
            closure_returned_borrow_capture_summaries: closure_returned_borrow_capture_summaries
                .clone(),
            discovered_closure_returned_borrow_captures: BTreeMap::new(),
            closure_capture_use_summaries: closure_capture_use_summaries.clone(),
            atomic_ordering_origins: BTreeMap::new(),
            external_buffer_binding_keys: BTreeSet::new(),
            returned_borrow_invalidations: Vec::new(),
            returned_borrow_storage_uses: Vec::new(),
            returned_borrow_storage_mutation_barriers: Vec::new(),
            local_method_calls: Vec::new(),
            callback_user_data_invocations: Vec::new(),
            openssl_ex_data_get_origins: BTreeMap::new(),
            openssl_ex_data_handle_origins: BTreeMap::new(),
            openssl_ex_data_slot_origins: BTreeMap::new(),
            openssl_ex_data_slot_free_contracts: BTreeMap::new(),
            openssl_ex_data_free_contracts: BTreeMap::new(),
            openssl_ex_data_registrations: Vec::new(),
            openssl_ex_data_releases: Vec::new(),
        };
        visitor.visit_body(body);
        merge_closure_storage_capture_summaries(
            &mut closure_storage_capture_summaries,
            visitor.discovered_closure_storage_captures,
        );
        merge_closure_returned_borrow_capture_summaries(
            &mut closure_returned_borrow_capture_summaries,
            visitor.discovered_closure_returned_borrow_captures,
        );
    }
    for def_id in body_owners {
        let body = tcx.optimized_mir(def_id);
        let owner_def_path = tcx.def_path_str(def_id.to_def_id());
        let owner_is_foreign_callback = owner_is_foreign_callback(tcx, def_id.to_def_id());
        observations.seen_bodies.push(owner_def_path.clone());
        mir_order_graphs.insert(owner_def_path.clone(), mir_order_graph(body));
        if let Some(relation) = unconstrained_return_lifetime_relation(tcx, def_id, &owner_def_path)
            .or_else(|| {
                arena_into_iter_unconstrained_lifetime_relation(tcx, def_id, &owner_def_path)
            })
        {
            observations.returned_borrow_relations.push(relation);
        }
        observations
            .callback_lifetime_bounds
            .extend(callback_lifetime_bounds(tcx, def_id, &owner_def_path));
        observations
            .registration_guards
            .extend(registration_guards(tcx, def_id, &owner_def_path));
        let mut visitor = MirSiteVisitor {
            tcx,
            body,
            current_crate_name,
            collection_lookup_contracts,
            owner_def_path,
            owner_is_foreign_callback,
            observations: MirSiteObservations::default(),
            raw_pointer_origins: BTreeMap::new(),
            raw_pointer_borrow_origins: BTreeMap::new(),
            closure_upvar_sources: BTreeMap::new(),
            receiver_borrow_locals: BTreeMap::new(),
            borrowed_foreign_pointer_origins: BTreeMap::new(),
            returned_borrow_origins: BTreeMap::new(),
            returned_borrow_return_origins: Vec::new(),
            returned_borrow_slot_assignment_origins: Vec::new(),
            returned_borrow_iterator_origins: BTreeMap::new(),
            fn_pointer_origins: BTreeMap::new(),
            option_fn_pointer_origins: BTreeMap::new(),
            fn_pointer_source_origins: BTreeMap::new(),
            option_fn_pointer_source_origins: BTreeMap::new(),
            option_fn_pointer_release_origins: BTreeMap::new(),
            previous_user_data_origins: BTreeMap::new(),
            hook_release_field_writes: Vec::new(),
            hook_previous_release_candidates: Vec::new(),
            borrow_origins: BTreeMap::new(),
            returned_borrow_storage_origins: BTreeMap::new(),
            returned_borrow_storage_reference_origins: BTreeMap::new(),
            returned_borrow_entry_value_reference_origins: BTreeMap::new(),
            pending_returned_borrow_entry_value_assignments: Vec::new(),
            returned_borrow_indexed_iterator_storage_origins: BTreeMap::new(),
            returned_borrow_slice_storage_origins: BTreeMap::new(),
            returned_borrow_unique_storage_origins: BTreeMap::new(),
            returned_borrow_local_wrapper_reference_origins: BTreeMap::new(),
            returned_borrow_invalidated_storage_keys: BTreeSet::new(),
            returned_borrow_sequence_lengths: BTreeMap::new(),
            returned_borrow_keyed_map_entry_origins: BTreeMap::new(),
            returned_borrow_keyed_map_entry_branch_writes: BTreeMap::new(),
            returned_borrow_keyed_map_split_entry_branch_writes: BTreeMap::new(),
            returned_borrow_keyed_map_known_empty: BTreeSet::new(),
            returned_borrow_keyed_map_known_occupied: BTreeSet::new(),
            stable_constant_origins: BTreeMap::new(),
            stable_range_origins: BTreeMap::new(),
            scoped_key_origins: BTreeMap::new(),
            unsupported_key_wrapper_origins: BTreeMap::new(),
            dynamic_key_generations: BTreeMap::new(),
            closure_storage_capture_summaries: closure_storage_capture_summaries.clone(),
            discovered_closure_storage_captures: BTreeMap::new(),
            closure_returned_borrow_capture_summaries: closure_returned_borrow_capture_summaries
                .clone(),
            discovered_closure_returned_borrow_captures: BTreeMap::new(),
            closure_capture_use_summaries: closure_capture_use_summaries.clone(),
            atomic_ordering_origins: BTreeMap::new(),
            external_buffer_binding_keys: BTreeSet::new(),
            returned_borrow_invalidations: Vec::new(),
            returned_borrow_storage_uses: Vec::new(),
            returned_borrow_storage_mutation_barriers: Vec::new(),
            local_method_calls: Vec::new(),
            callback_user_data_invocations: Vec::new(),
            openssl_ex_data_get_origins: BTreeMap::new(),
            openssl_ex_data_handle_origins: BTreeMap::new(),
            openssl_ex_data_slot_origins: BTreeMap::new(),
            openssl_ex_data_slot_free_contracts: BTreeMap::new(),
            openssl_ex_data_free_contracts: BTreeMap::new(),
            openssl_ex_data_registrations: Vec::new(),
            openssl_ex_data_releases: Vec::new(),
        };
        visitor.visit_body(body);
        visitor.infer_release_path_proofs();
        observations.drops.extend(visitor.observations.drops);
        observations
            .drop_preventions
            .extend(visitor.observations.drop_preventions);
        observations
            .callback_user_data_reconstructions
            .extend(visitor.observations.callback_user_data_reconstructions);
        observations
            .registrations
            .extend(visitor.observations.registrations);
        observations
            .allocation_ownerships
            .extend(allocation_ownerships(
                tcx,
                def_id,
                &visitor.owner_def_path,
                &visitor.observations.raw_pointer_transfers,
            ));
        observations
            .raw_pointer_transfers
            .extend(visitor.observations.raw_pointer_transfers);
        observations
            .release_path_proofs
            .extend(visitor.observations.release_path_proofs);
        observations
            .external_calls
            .extend(visitor.observations.external_calls);
        observations
            .returned_borrow_relations
            .extend(visitor.observations.returned_borrow_relations);
        observations
            .persisted_returned_borrows
            .extend(visitor.observations.persisted_returned_borrows);
        observations
            .external_buffer_bindings
            .extend(visitor.observations.external_buffer_bindings);
        observations
            .atomic_orderings
            .extend(visitor.observations.atomic_orderings);
        observations
            .object_binding_gaps
            .extend(visitor.observations.object_binding_gaps);
        observations
            .object_flows
            .extend(visitor.observations.object_flows);
        returned_borrow_invalidations.extend(visitor.returned_borrow_invalidations);
        returned_borrow_storage_uses.extend(visitor.returned_borrow_storage_uses);
        returned_borrow_storage_mutation_barriers
            .extend(visitor.returned_borrow_storage_mutation_barriers);
        local_method_calls.extend(visitor.local_method_calls);
        callback_user_data_invocations.extend(visitor.callback_user_data_invocations);
        for contract in visitor.openssl_ex_data_free_contracts.into_values() {
            openssl_ex_data_free_contracts.insert(contract.api_id.clone(), contract);
        }
        openssl_ex_data_registrations.extend(visitor.openssl_ex_data_registrations);
        openssl_ex_data_releases.extend(visitor.openssl_ex_data_releases);
    }
    let (openssl_releases, openssl_proofs) = infer_openssl_ex_data_release_path_proofs(
        &openssl_ex_data_registrations,
        &openssl_ex_data_releases,
    );
    let (openssl_contract_releases, openssl_contract_proofs) =
        infer_openssl_ex_data_free_callback_release_path_proofs(
            &openssl_ex_data_registrations,
            &openssl_ex_data_free_contracts,
        );
    observations
        .object_flows
        .extend(infer_openssl_ex_data_object_flows(
            &openssl_ex_data_registrations,
            &openssl_ex_data_releases,
            &openssl_ex_data_free_contracts,
        ));
    observations
        .object_flows
        .extend(infer_callback_user_data_object_flows(
            &observations.registrations,
            &observations.callback_user_data_reconstructions,
        ));
    observations.raw_pointer_transfers.extend(openssl_releases);
    observations
        .raw_pointer_transfers
        .extend(openssl_contract_releases);
    observations.release_path_proofs.extend(openssl_proofs);
    observations
        .release_path_proofs
        .extend(openssl_contract_proofs);
    observations.callback_release_use_orders = infer_callback_release_use_orders(
        &observations.release_path_proofs,
        &observations.callback_user_data_reconstructions,
        &callback_user_data_invocations,
        &mir_order_graphs,
    );
    observations.returned_borrow_invalidation_orders = infer_returned_borrow_invalidation_orders(
        &observations.persisted_returned_borrows,
        &returned_borrow_invalidations,
        &returned_borrow_storage_uses,
        &returned_borrow_storage_mutation_barriers,
        &local_method_calls,
        &mir_order_graphs,
    );
    observations
        .object_binding_gaps
        .extend(object_binding_gaps_from_storage_mutation_barriers(
            &returned_borrow_storage_mutation_barriers,
        ));
    observations
        .object_flows
        .extend(infer_object_flows(&observations));
    observations.drops.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
    });
    observations.drop_preventions.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
    });
    observations
        .callback_user_data_reconstructions
        .sort_by(|left, right| {
            left.owner_def_path
                .cmp(&right.owner_def_path)
                .then(left.mir_location.cmp(&right.mir_location))
        });
    observations.registrations.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
    });
    observations.raw_pointer_transfers.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
    });
    observations.release_path_proofs.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
    });
    observations
        .callback_release_use_orders
        .sort_by(|left, right| {
            left.owner_def_path
                .cmp(&right.owner_def_path)
                .then(left.mir_location.cmp(&right.mir_location))
                .then(
                    left.registration
                        .mir_location
                        .cmp(&right.registration.mir_location),
                )
        });
    observations.callback_release_use_orders.dedup();
    observations.external_calls.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
    });
    observations
        .returned_borrow_relations
        .sort_by(|left, right| {
            left.owner_def_path
                .cmp(&right.owner_def_path)
                .then(left.mir_location.cmp(&right.mir_location))
        });
    observations
        .persisted_returned_borrows
        .sort_by(|left, right| {
            left.owner_def_path
                .cmp(&right.owner_def_path)
                .then(left.mir_location.cmp(&right.mir_location))
        });
    observations
        .external_buffer_bindings
        .sort_by(|left, right| {
            left.owner_def_path
                .cmp(&right.owner_def_path)
                .then(left.mir_location.cmp(&right.mir_location))
        });
    observations.atomic_orderings.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
    });
    observations.object_binding_gaps.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
            .then(left.api_id.cmp(&right.api_id))
    });
    observations.object_binding_gaps.dedup();
    observations
        .returned_borrow_invalidation_orders
        .sort_by(|left, right| {
            left.owner_def_path
                .cmp(&right.owner_def_path)
                .then(left.mir_location.cmp(&right.mir_location))
        });
    observations.object_flows.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
            .then(left.api_id.cmp(&right.api_id))
    });
    observations.object_flows.dedup();
    observations.seen_bodies.sort();
    observations.seen_bodies.dedup();
    Ok(observations)
}

fn is_optimized_mir_owner(def_kind: DefKind) -> bool {
    matches!(
        def_kind,
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure | DefKind::Ctor(..)
    )
}

fn merge_closure_storage_capture_summaries(
    target: &mut ClosureStorageCaptureSummaries,
    source: ClosureStorageCaptureSummaries,
) {
    for (closure_def_path, captures) in source {
        for (projection, storage_key) in captures {
            merge_closure_storage_capture_summary(
                target,
                closure_def_path.clone(),
                projection,
                storage_key,
            );
        }
    }
}

fn remember_closure_storage_capture_summary(
    summaries: &mut ClosureStorageCaptureSummaries,
    closure_def_path: String,
    projection: Vec<String>,
    storage_key: String,
) {
    merge_closure_storage_capture_summary(
        summaries,
        closure_def_path,
        projection,
        Some(storage_key),
    );
}

fn merge_closure_storage_capture_summary(
    summaries: &mut ClosureStorageCaptureSummaries,
    closure_def_path: String,
    projection: Vec<String>,
    storage_key: Option<String>,
) {
    let capture = summaries
        .entry(closure_def_path)
        .or_default()
        .entry(projection)
        .or_insert_with(|| storage_key.clone());
    if capture.as_ref() != storage_key.as_ref() {
        *capture = None;
    }
}

fn merge_closure_returned_borrow_capture_summaries(
    target: &mut ClosureReturnedBorrowCaptureSummaries,
    source: ClosureReturnedBorrowCaptureSummaries,
) {
    for (closure_def_path, captures) in source {
        for (projection, origin) in captures {
            merge_closure_returned_borrow_capture_summary(
                target,
                closure_def_path.clone(),
                projection,
                origin,
            );
        }
    }
}

fn remember_closure_returned_borrow_capture_summary(
    summaries: &mut ClosureReturnedBorrowCaptureSummaries,
    closure_def_path: String,
    projection: Vec<String>,
    origin: ReturnedBorrowOrigin,
) {
    merge_closure_returned_borrow_capture_summary(
        summaries,
        closure_def_path,
        projection,
        Some(origin),
    );
}

fn merge_closure_returned_borrow_capture_summary(
    summaries: &mut ClosureReturnedBorrowCaptureSummaries,
    closure_def_path: String,
    projection: Vec<String>,
    origin: Option<ReturnedBorrowOrigin>,
) {
    let capture = summaries
        .entry(closure_def_path)
        .or_default()
        .entry(projection)
        .or_insert_with(|| origin.clone());
    if capture.as_ref() != origin.as_ref() {
        *capture = None;
    }
}

fn closure_capture_use_summaries_from_captures(
    captures: &[CaptureObservation],
) -> ClosureCaptureUseSummaries {
    let mut summaries = ClosureCaptureUseSummaries::new();
    for capture in captures {
        let projection = vec![format!("field:{}", capture.capture_ordinal)];
        let summary = ClosureCaptureUseSummary {
            callback_def_path: capture.callback_def_path.clone(),
            callback_source_path: capture.callback_source_path.clone(),
            callback_span: capture.callback_span.clone(),
            field_path: closure_capture_object_flow_field_path(capture),
            object_type_name: capture.object_type_name.clone(),
        };
        let slot = summaries
            .entry(capture.callback_def_path.clone())
            .or_default()
            .entry(projection)
            .or_insert_with(|| Some(summary.clone()));
        if slot.as_ref() != Some(&summary) {
            *slot = None;
        }
    }
    summaries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closure_storage_capture_summary_conflict_is_ambiguous() {
        let mut summaries = ClosureStorageCaptureSummaries::new();
        remember_closure_storage_capture_summary(
            &mut summaries,
            "crate::Owner::method::{closure#0}".to_owned(),
            vec!["field:0".to_owned()],
            "field:Owner:field:0".to_owned(),
        );
        remember_closure_storage_capture_summary(
            &mut summaries,
            "crate::Owner::method::{closure#0}".to_owned(),
            vec!["field:0".to_owned()],
            "field:Owner:field:1".to_owned(),
        );

        assert_eq!(
            summaries
                .get("crate::Owner::method::{closure#0}")
                .and_then(|captures| captures.get(&vec!["field:0".to_owned()])),
            Some(&None),
            "conflicting capture sources must be ambiguous, not first-source wins"
        );

        let mut other = ClosureStorageCaptureSummaries::new();
        remember_closure_storage_capture_summary(
            &mut other,
            "crate::Owner::method::{closure#1}".to_owned(),
            vec!["field:0".to_owned()],
            "field:Owner:field:0".to_owned(),
        );
        merge_closure_storage_capture_summaries(&mut summaries, other);
        assert_eq!(
            summaries
                .get("crate::Owner::method::{closure#1}")
                .and_then(|captures| captures.get(&vec!["field:0".to_owned()])),
            Some(&Some("field:Owner:field:0".to_owned()))
        );
    }
}

struct MirSiteVisitor<'a, 'tcx> {
    tcx: TyCtxt<'tcx>,
    body: &'a Body<'tcx>,
    current_crate_name: &'a str,
    collection_lookup_contracts: &'a [CollectionLookupContract],
    owner_def_path: String,
    owner_is_foreign_callback: bool,
    observations: MirSiteObservations,
    raw_pointer_origins: BTreeMap<RawPointerPlaceKey, Option<RawPointerReference>>,
    raw_pointer_borrow_origins: BTreeMap<Local, Option<RawPointerPlaceKey>>,
    /// 被移进某个闭包成为 upvar 的 local。
    ///
    /// 留存缺陷的形状是"闭包捕获的对象被销毁"，而不是"闭包本身被销毁"。要认出前者，
    /// drop 一个 local 时必须知道它是否已经进了某个闭包。
    closure_upvar_sources: BTreeMap<Local, DefId>,
    /// `receiver -> {由它借出的 local}`。
    ///
    /// `fn get(&self) -> &T { &self.value }` 这类方法把接收者的一部分借出去，闭包捕获
    /// 到的是借用而不是接收者本身。没有这层别名，drop 接收者与捕获借用就永远对不上号。
    receiver_borrow_locals: BTreeMap<Local, BTreeSet<Local>>,
    borrowed_foreign_pointer_origins: BTreeMap<RawPointerPlaceKey, Option<BorrowReference>>,
    returned_borrow_origins: BTreeMap<Local, Option<ReturnedBorrowOrigin>>,
    returned_borrow_return_origins: Vec<ReturnedBorrowReturnAssignment>,
    returned_borrow_slot_assignment_origins: Vec<ReturnedBorrowSlotAssignment>,
    returned_borrow_iterator_origins: BTreeMap<Local, Option<ReturnedBorrowOrigin>>,
    fn_pointer_origins: BTreeMap<RawPointerPlaceKey, Option<DefId>>,
    option_fn_pointer_origins: BTreeMap<RawPointerPlaceKey, Option<DefId>>,
    fn_pointer_source_origins: BTreeMap<RawPointerPlaceKey, Option<RawPointerPlaceKey>>,
    option_fn_pointer_source_origins: BTreeMap<RawPointerPlaceKey, Option<RawPointerPlaceKey>>,
    option_fn_pointer_release_origins: BTreeMap<RawPointerPlaceKey, HookReleaseOptionOrigin>,
    previous_user_data_origins: BTreeMap<RawPointerPlaceKey, Option<PreviousUserDataReturn>>,
    hook_release_field_writes: Vec<HookReleaseFieldWrite>,
    hook_previous_release_candidates: Vec<HookPreviousReleaseCandidate>,
    borrow_origins: BTreeMap<Local, Option<BorrowReference>>,
    returned_borrow_storage_origins: BTreeMap<String, Vec<PersistedReturnedBorrowObservation>>,
    returned_borrow_storage_reference_origins: BTreeMap<Local, Option<String>>,
    returned_borrow_entry_value_reference_origins:
        BTreeMap<Local, ReturnedBorrowEntryValueReferenceOrigin>,
    pending_returned_borrow_entry_value_assignments: Vec<PendingReturnedBorrowEntryValueAssignment>,
    returned_borrow_indexed_iterator_storage_origins:
        BTreeMap<Local, Option<IndexedIteratorStorageOrigin>>,
    returned_borrow_slice_storage_origins: BTreeMap<Local, ReturnedBorrowSliceStorageOrigin>,
    returned_borrow_unique_storage_origins: BTreeMap<Local, String>,
    returned_borrow_local_wrapper_reference_origins: BTreeMap<Local, Local>,
    returned_borrow_invalidated_storage_keys: BTreeSet<String>,
    returned_borrow_sequence_lengths: BTreeMap<String, usize>,
    returned_borrow_keyed_map_entry_origins: BTreeMap<Local, KeyedMapEntryOrigin>,
    returned_borrow_keyed_map_entry_branch_writes:
        BTreeMap<String, ReturnedBorrowKeyedMapEntryBranchWrites>,
    returned_borrow_keyed_map_split_entry_branch_writes:
        BTreeMap<String, ReturnedBorrowKeyedMapSplitEntryBranchWrites>,
    returned_borrow_keyed_map_known_empty: BTreeSet<String>,
    returned_borrow_keyed_map_known_occupied: BTreeSet<String>,
    stable_constant_origins: BTreeMap<Local, String>,
    stable_range_origins: BTreeMap<Local, ConstRangeBounds>,
    scoped_key_origins: BTreeMap<Local, String>,
    unsupported_key_wrapper_origins: BTreeMap<Local, String>,
    dynamic_key_generations: BTreeMap<Local, u32>,
    closure_storage_capture_summaries: ClosureStorageCaptureSummaries,
    discovered_closure_storage_captures: ClosureStorageCaptureSummaries,
    closure_returned_borrow_capture_summaries: ClosureReturnedBorrowCaptureSummaries,
    discovered_closure_returned_borrow_captures: ClosureReturnedBorrowCaptureSummaries,
    closure_capture_use_summaries: ClosureCaptureUseSummaries,
    atomic_ordering_origins: BTreeMap<Local, AtomicOrderingKind>,
    external_buffer_binding_keys: BTreeSet<String>,
    returned_borrow_invalidations: Vec<ReturnedBorrowInvalidationCall>,
    returned_borrow_storage_uses: Vec<ReturnedBorrowStorageUse>,
    returned_borrow_storage_mutation_barriers: Vec<ReturnedBorrowStorageMutationBarrier>,
    local_method_calls: Vec<LocalMethodCall>,
    callback_user_data_invocations: Vec<CallbackUserDataInvocation>,
    openssl_ex_data_get_origins: BTreeMap<RawPointerPlaceKey, Option<OpenSslExDataGetOrigin>>,
    openssl_ex_data_handle_origins: BTreeMap<RawPointerPlaceKey, Option<String>>,
    openssl_ex_data_slot_origins: BTreeMap<RawPointerPlaceKey, Option<String>>,
    openssl_ex_data_slot_free_contracts: BTreeMap<String, OpenSslExDataFreeContract>,
    openssl_ex_data_free_contracts: BTreeMap<String, OpenSslExDataFreeContract>,
    openssl_ex_data_registrations: Vec<OpenSslExDataRegistration>,
    openssl_ex_data_releases: Vec<OpenSslExDataRelease>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyedMapEntryOrigin {
    storage_key: String,
    storage_type_name: String,
    key: Option<String>,
    occupancy: KeyedMapEntryOccupancy,
    entry_site_id: String,
    projection_kind: Option<KeyedMapEntryProjectionKind>,
    projection_order_key: Option<MirOrderKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyedMapEntryOccupancy {
    Unknown,
    KnownOccupied,
    KnownVacant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReturnedBorrowKeyedMapEntryBranchWrites {
    storage_key: String,
    storage_type_name: String,
    occupied: KeyedMapEntryBranchWrite,
    vacant: KeyedMapEntryBranchWrite,
    merged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReturnedBorrowKeyedMapSplitEntryBranchWrites {
    storage_key: String,
    storage_type_name: String,
    occupied_entry_site_id: Option<String>,
    vacant_entry_site_id: Option<String>,
    occupied: KeyedMapEntryBranchWrite,
    vacant: KeyedMapEntryBranchWrite,
    merged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReturnedBorrowCollectionEntrySummaryBranchWrites {
    storage_arg_index: usize,
    key_arg_index: usize,
    entry_site_id: MirOrderKey,
    occupied: KeyedMapEntryBranchWrite,
    vacant: KeyedMapEntryBranchWrite,
    merged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReturnedBorrowCollectionSplitEntrySummaryBranchWrites {
    storage_arg_index: usize,
    key_arg_index: usize,
    occupied_entry_site_id: Option<MirOrderKey>,
    vacant_entry_site_id: Option<MirOrderKey>,
    occupied: KeyedMapEntryBranchWrite,
    vacant: KeyedMapEntryBranchWrite,
    merged: bool,
}

enum CollectionEntryBranchPersistOutcome {
    Irrelevant,
    Pending,
    Complete(ReturnedBorrowCollectionPersistSummary),
    Poison,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum KeyedMapEntryBranchWrite {
    Unseen,
    Returned(ReturnedBorrowOrigin),
    Blocked,
    Ambiguous,
}

#[derive(Clone, Debug)]
struct ReturnedBorrowSlotAssignment {
    write: KeyedMapEntryBranchWrite,
    location: Location,
}

#[derive(Clone, Debug)]
struct ReturnedBorrowReturnAssignment {
    write: KeyedMapEntryBranchWrite,
    location: Location,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReturnedBorrowOrigin {
    source: BorrowReference,
    api_id: String,
    returned_type_name: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MirOrderKey {
    basic_block: usize,
    statement_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MirOrderGraph {
    reachable_blocks: BTreeMap<usize, BTreeSet<usize>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReturnedBorrowInvalidationCall {
    owner_def_path: String,
    source_path: PathBuf,
    span: String,
    mir_location: String,
    order_key: MirOrderKey,
    api_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReturnedBorrowStorageUse {
    owner_def_path: String,
    source_path: PathBuf,
    span: String,
    mir_location: String,
    order_key: MirOrderKey,
    storage_keys: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReturnedBorrowStorageMutationBarrier {
    owner_def_path: String,
    source_path: PathBuf,
    span: String,
    mir_location: String,
    order_key: MirOrderKey,
    storage_keys: BTreeSet<String>,
    storage_prefixes: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalMethodCall {
    owner_def_path: String,
    callee_def_path: String,
    source_path: PathBuf,
    span: String,
    mir_location: String,
    order_key: MirOrderKey,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReturnedBorrowCollectionUseSummary {
    storage_arg_index: usize,
    key_arg_index: Option<usize>,
    index_key: Option<String>,
    index_from_tail: bool,
    min_sequence_len: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReturnedBorrowCollectionBindingGapSummary {
    storage_arg_index: usize,
    gap_kind: ObjectBindingGapKind,
    adapter: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ReturnedBorrowCollectionUseAnalysis {
    summary: Option<ReturnedBorrowCollectionUseSummary>,
    binding_gaps: Vec<ReturnedBorrowCollectionBindingGapSummary>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ReturnedBorrowCollectionPersistAnalysis {
    summary: Option<ReturnedBorrowCollectionPersistSummary>,
    binding_gaps: Vec<ReturnedBorrowCollectionBindingGapSummary>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReturnedBorrowValueUseSummary {
    value_arg_index: usize,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReturnedBorrowWrapperDestructureSummary {
    wrapper_arg_index: usize,
    field_path: Vec<String>,
    clears_source: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IndexedIteratorStorageOrigin {
    storage_key: String,
    front_offset: usize,
    back_offset: usize,
    take_limit: Option<usize>,
    take_from_back: Option<bool>,
    from_back: bool,
    allow_forward_without_sequence_length: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConstRangeBounds {
    start: usize,
    end: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SliceRangeKind {
    Range,
    RangeInclusive,
    RangeFrom,
    RangeTo,
    RangeToInclusive,
    RangeFull,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReturnedBorrowSliceStorageOrigin {
    storage_key: String,
    start_offset: usize,
    end_offset: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReturnedBorrowEntryValueReferenceOrigin {
    storage_key: String,
    storage_type_name: String,
    reference_order_keys: BTreeSet<MirOrderKey>,
}

#[derive(Clone, Debug)]
struct PendingReturnedBorrowEntryValueAssignment {
    local: Local,
    origin: ReturnedBorrowOrigin,
    span: Span,
    location: Location,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IndexedIteratorArgOrigin {
    storage_arg_index: usize,
    front_offset: usize,
    back_offset: usize,
    take_limit: Option<usize>,
    take_from_back: Option<bool>,
    from_back: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReturnedBorrowCollectionMutationSummary {
    storage_arg_index: usize,
    key_arg_index: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReturnedBorrowCollectionRemoveReturnSummary {
    storage_arg_index: usize,
    key_arg_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReturnedBorrowCollectionPersistSummary {
    storage_arg_index: usize,
    key_arg_index: usize,
    origin: ReturnedBorrowOrigin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReturnedBorrowCollectionEntrySummaryOrigin {
    storage_arg_index: usize,
    key_arg_index: Option<usize>,
    entry_site_id: MirOrderKey,
    projection_kind: Option<KeyedMapEntryProjectionKind>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReturnedBorrowCollectionEntryReturnSummary {
    storage_arg_index: usize,
    key_arg_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin {
    entry: ReturnedBorrowCollectionEntrySummaryOrigin,
    reference_order_keys: BTreeSet<MirOrderKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingReturnedBorrowCollectionEntryValueAssignmentSummary {
    local: Local,
    origin: ReturnedBorrowOrigin,
    assignment_order_key: MirOrderKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReturnedBorrowCollectionEntryValueReferenceReturnSummary {
    storage_arg_index: usize,
    key_arg_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OpenSslExDataGetOrigin {
    owner_family: String,
    api_id: String,
    handle_key: String,
    slot_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OpenSslExDataRegistration {
    owner_family: String,
    handle_key: String,
    slot_key: String,
    slot_uses_index_argument: bool,
    slot_free_contract: Option<OpenSslExDataFreeContract>,
    registration: RegistrationObservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OpenSslExDataFreeContract {
    api_id: String,
    owner_def_path: String,
    source_path: PathBuf,
    span: String,
    mir_location: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OpenSslExDataRelease {
    owner_family: String,
    owner_def_path: String,
    api_id: String,
    handle_key: String,
    slot_key: String,
    source_path: PathBuf,
    span: String,
    mir_location: String,
    basic_block: usize,
    statement_index: usize,
    postdominates_entry: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OpenSslExDataRegistrationCallSummary {
    api_id: String,
    handle_arg: RawPointerArgPlaceKey,
    slot_arg: OpenSslExDataSlotArgKey,
    user_data_arg: RawPointerArgPlaceKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OpenSslExDataGetCallSummary {
    api_id: String,
    handle_arg: RawPointerArgPlaceKey,
    slot_arg: OpenSslExDataSlotArgKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OpenSslExDataSlotArgKey {
    arg_index: usize,
    projection: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CallbackUserDataInvocation {
    owner_def_path: String,
    source_path: PathBuf,
    span: String,
    mir_location: String,
    order_key: MirOrderKey,
    callback_def_path: String,
    user_data: RawPointerReference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CallbackUserDataInvocationSummary {
    callback_arg: RawPointerArgPlaceKey,
    user_data_arg: RawPointerArgPlaceKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegistrationCallSummary {
    api_id: String,
    role: bw_model::RegistrationRole,
    callback_arg_index: Option<usize>,
    user_data_arg_index: Option<usize>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawPointerPlaceKey {
    local: usize,
    projection: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawPointerArgPlaceKey {
    arg_index: usize,
    projection: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawPointerReleaseCallReference {
    user_data: RawPointerReference,
    arg_index: usize,
    projection: Vec<String>,
    arg_type_name: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct HookReleaseOptionOrigin {
    release_def_paths: BTreeSet<String>,
    saw_non_releasing_some: bool,
    saw_unknown_some: bool,
}

impl HookReleaseOptionOrigin {
    fn release_endpoint(def_path: String) -> Self {
        let mut release_def_paths = BTreeSet::new();
        release_def_paths.insert(def_path);
        Self {
            release_def_paths,
            saw_non_releasing_some: false,
            saw_unknown_some: false,
        }
    }

    fn non_releasing_some() -> Self {
        Self {
            release_def_paths: BTreeSet::new(),
            saw_non_releasing_some: true,
            saw_unknown_some: false,
        }
    }

    fn unknown_some() -> Self {
        Self {
            release_def_paths: BTreeSet::new(),
            saw_non_releasing_some: false,
            saw_unknown_some: true,
        }
    }

    fn merge(&mut self, other: Self) {
        self.release_def_paths.extend(other.release_def_paths);
        self.saw_non_releasing_some |= other.saw_non_releasing_some;
        self.saw_unknown_some |= other.saw_unknown_some;
    }

    fn exact_release_endpoint(&self) -> bool {
        self.release_def_paths.len() == 1 && !self.saw_non_releasing_some && !self.saw_unknown_some
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum OptionFnReleaseAssignment {
    NoneValue,
    Origin(HookReleaseOptionOrigin),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreviousUserDataReturn {
    hook_family: String,
}

#[derive(Clone, Debug)]
struct HookReleaseFieldWrite {
    field_key: RawPointerPlaceKey,
    span: Span,
    location: Location,
    basic_block: usize,
}

#[derive(Clone, Debug)]
struct HookPreviousReleaseCandidate {
    hook_family: String,
    field_key: RawPointerPlaceKey,
    span: Span,
    location: Location,
    basic_block: usize,
}

impl<'tcx> Visitor<'tcx> for MirSiteVisitor<'_, 'tcx> {
    fn visit_terminator(&mut self, terminator: &Terminator<'tcx>, location: Location) {
        match &terminator.kind {
            TerminatorKind::Drop { place, .. } => {
                if let Some(drop) = self.drop_observation(
                    place,
                    terminator.source_info.span,
                    location,
                    DropKind::ScopeEnd,
                ) {
                    self.observations.drops.push(drop);
                }
                self.observe_drop_impl_release(place, terminator.source_info.span, location);
            }
            TerminatorKind::Call {
                func,
                args,
                fn_span,
                destination,
                ..
            } => self.visit_call(func, args, *fn_span, location, Some(destination)),
            TerminatorKind::TailCall { func, fn_span, .. } => {
                self.visit_call(func, &[], *fn_span, location, None);
            }
            TerminatorKind::Return => {
                self.observe_returned_borrow_return_terminator_use(
                    terminator.source_info.span,
                    location,
                );
            }
            _ => {}
        }
        self.super_terminator(terminator, location);
    }

    fn visit_assign(&mut self, place: &Place<'tcx>, rvalue: &Rvalue<'tcx>, location: Location) {
        self.observe_callback_user_data_transmute_assignment(place, rvalue, location);
        self.record_borrow_assignment(place, rvalue, location);
        self.record_returned_borrow_assignment(place, rvalue, location);
        self.observe_returned_borrow_slot_assignment(place, rvalue, location);
        self.clear_returned_borrow_storage_assignment_destination(place);
        self.observe_persisted_returned_borrow_assignment(place, rvalue, location);
        self.record_returned_borrow_storage_assignment(place, rvalue, location);
        self.observe_returned_borrow_storage_use_assignment(place, rvalue, location);
        self.observe_closure_capture_use_assignment(rvalue, location);
        self.record_closure_upvar_sources(rvalue);
        self.record_returned_borrow_indexed_iterator_assignment(place, rvalue);
        self.record_returned_borrow_slice_storage_assignment(place, rvalue);
        self.observe_returned_borrow_assignment(place, rvalue, location);
        self.record_stable_constant_assignment(place, rvalue);
        self.record_stable_range_assignment(place, rvalue);
        self.record_scoped_key_assignment(place, rvalue);
        self.record_returned_borrow_keyed_map_entry_assignment(place, rvalue, location);
        self.record_raw_pointer_borrow_assignment(place, rvalue);
        self.record_openssl_ex_data_handle_assignment(place, rvalue);
        self.record_openssl_ex_data_slot_assignment(place, rvalue);
        self.observe_raw_pointer_field_assignment_flows(place, rvalue, location);
        self.record_raw_pointer_assignment(place, rvalue, location);
        self.record_fn_pointer_assignment(place, rvalue, location);
        self.record_atomic_ordering_assignment(place, rvalue, location);
        self.super_assign(place, rvalue, location);
    }
}

impl<'tcx> MirSiteVisitor<'_, 'tcx> {
    fn visit_call(
        &mut self,
        func: &Operand<'tcx>,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
        destination: Option<&Place<'tcx>>,
    ) {
        self.observe_hook_state_previous_release_call(func, args, span, location);
        self.observe_openssl_ex_data_box_from_raw_call(args, span, location);
        let Some(callee_def_id) = func
            .const_fn_def()
            .map(|(def_id, _)| def_id)
            .or_else(|| self.fn_def_from_operand(func))
        else {
            // 间接调用且指针来源追踪不到定义：这次调用背后可能有注册，也可能没有，
            // 分析分辨不了。此前直接 return，于是它和"看过、确实没注册"在事实流里
            // 无法区分。记成缺证，让覆盖缺口可计数。
            self.record_object_binding_gap_at_callsite(
                ObjectBindingGapKind::UnresolvedCallee,
                None,
                span,
                location,
                "unresolved_callee",
            );
            return;
        };
        let callee_def_path = self.tcx.def_path_str(callee_def_id);
        self.observe_callback_user_data_invocation(
            callee_def_id,
            &callee_def_path,
            args,
            span,
            location,
        );
        self.observe_callback_user_data_summary_invocation(callee_def_id, args, span, location);
        self.record_local_method_call(&callee_def_path, span, location);
        self.record_receiver_borrow_call(callee_def_id, args, destination);
        self.observe_atomic_ordering_load(&callee_def_path, args, span, location);
        if let Some(destination) = destination {
            self.record_scoped_key_passthrough_call(
                callee_def_id,
                &callee_def_path,
                args,
                destination,
            );
            self.record_returned_borrow_keyed_map_entry_call(
                callee_def_id,
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
            self.record_returned_borrow_keyed_map_entry_value_reference_call(
                callee_def_id,
                &callee_def_path,
                args,
                destination,
                location,
            );
        }
        if let Some(destination) = destination {
            self.record_keyed_map_remove_returned_borrow_call(
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
            self.record_keyed_map_remove_returned_borrow_summary_call(
                callee_def_id,
                args,
                destination,
                span,
                location,
            );
        }
        self.observe_shared_owner_make_mut_storage_barrier(&callee_def_path, args);
        self.observe_raw_pointer_shared_owner_make_mut_barrier(&callee_def_path, args);
        self.observe_interior_mutability_storage_barrier(&callee_def_path, args);
        self.observe_returned_borrow_collection_mutation_barrier_call(
            &callee_def_path,
            args,
            span,
            location,
        );
        self.observe_returned_borrow_keyed_map_entry_and_modify_barrier_call(
            &callee_def_path,
            args,
            span,
            location,
        );
        self.observe_returned_borrow_keyed_map_entry_or_insert_call(
            &callee_def_path,
            args,
            span,
            location,
        );
        self.observe_returned_borrow_keyed_map_entry_or_insert_with_call(
            &callee_def_path,
            args,
            span,
            location,
        );
        self.observe_returned_borrow_keyed_map_entry_insert_call(
            &callee_def_path,
            args,
            destination,
            span,
            location,
        );
        self.observe_returned_borrow_indexed_sequence_mutation_barrier_call(&callee_def_path, args);
        self.observe_returned_borrow_collection_mutation_summary_call(
            callee_def_id,
            args,
            span,
            location,
        );
        self.observe_returned_borrow_collection_persist_summary_call(
            callee_def_id,
            args,
            span,
            location,
        );
        self.observe_returned_borrow_invalidation_call(&callee_def_path, span, location);
        self.observe_returned_borrow_storage_use_call(&callee_def_path, args, span, location);
        self.observe_returned_borrow_value_argument_use_call(
            callee_def_id,
            &callee_def_path,
            args,
            span,
            location,
        );
        self.observe_returned_borrow_wrapper_destructure_call(
            callee_def_id,
            args,
            destination,
            span,
            location,
        );
        self.observe_returned_borrow_option_take_replace_call(
            &callee_def_path,
            args,
            destination,
            span,
            location,
        );
        self.observe_returned_borrow_indexed_iterator_next_call(
            &callee_def_path,
            args,
            span,
            location,
        );
        self.observe_returned_borrow_storage_use_summary_call(callee_def_id, args, span, location);
        let cross_crate_contract_applied = self
            .observe_cross_crate_returned_borrow_collection_lookup_contract(
                callee_def_id,
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
        if !cross_crate_contract_applied {
            self.observe_cross_crate_returned_borrow_collection_lookup_gap(
                callee_def_id,
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
        }
        if let Some(destination) = destination {
            self.record_openssl_ex_data_new_index_call(
                callee_def_id,
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
            self.record_openssl_ex_data_get_call(
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
            self.record_openssl_ex_data_get_summary_call(
                callee_def_id,
                args,
                destination,
                span,
                location,
            );
            self.record_returned_borrow_call(
                callee_def_id,
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
            self.record_returned_borrow_storage_passthrough_call(
                &callee_def_path,
                args,
                destination,
            );
            self.record_shared_owner_returned_borrow_storage_passthrough_call(
                &callee_def_path,
                args,
                destination,
            );
            self.record_interior_mutability_returned_borrow_storage_passthrough_call(
                &callee_def_path,
                args,
                destination,
            );
            self.record_returned_borrow_storage_reference_passthrough_call(
                &callee_def_path,
                args,
                destination,
            );
            self.record_returned_borrow_range_slice_call(&callee_def_path, args, destination);
            self.record_stable_range_constructor_call(&callee_def_path, args, destination);
            self.observe_shared_owner_clone_object_flow(
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
            self.record_raw_pointer_shared_owner_clone_call(&callee_def_path, args, destination);
            self.record_returned_borrow_indexed_sequence_constructor_call(
                &callee_def_path,
                destination,
            );
            self.record_returned_borrow_keyed_map_constructor_call(&callee_def_path, destination);
            self.record_foreign_borrowed_pointer_return(
                &callee_def_path,
                destination,
                span,
                location,
            );
            self.record_borrowed_view_from_foreign_pointer(
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
            self.record_returned_borrow_iterator_adapter_call(&callee_def_path, args, destination);
            self.record_returned_borrow_indexed_sequence_iterator_call(
                &callee_def_path,
                args,
                destination,
            );
            self.record_returned_borrow_indexed_iterator_offset_adapter_call(
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
            self.observe_persisted_returned_borrow_collect_call(
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
            self.record_raw_pointer_non_null_as_ptr_call(
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
            self.record_raw_pointer_non_null_constructor_call(
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
            self.record_raw_pointer_deref_reference_call(&callee_def_path, args, destination);
            self.record_raw_pointer_unique_owner_constructor_call(
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
        }
        self.observe_persisted_returned_borrow_call(&callee_def_path, args, span, location);
        self.record_returned_borrow_indexed_sequence_length_mutation_call(&callee_def_path, args);
        if let Some(reconstruction) = self.callback_user_data_reconstruction_observation(
            &callee_def_path,
            args,
            span,
            location,
            destination,
        ) {
            self.observations
                .callback_user_data_reconstructions
                .push(reconstruction);
        }
        if let Some(kind) = raw_pointer_transfer_kind(&callee_def_path) {
            self.observe_raw_pointer_transfer(kind, args, span, location, destination);
            return;
        }
        if is_explicit_drop_call(&callee_def_path) {
            if let Some(first_arg) = args.first()
                && let Some(place) = first_arg.node.place()
                && let Some(drop) =
                    self.drop_observation(&place, first_arg.span, location, DropKind::Explicit)
            {
                self.observations.drops.push(drop);
            }
            return;
        }
        if is_mem_forget_call(&callee_def_path) {
            if let Some(first_arg) = args.first()
                && let Some(place) = first_arg.node.place()
                && let Some(prevention) = self.drop_prevention_observation(
                    &place,
                    first_arg.span,
                    location,
                    DropPreventionKind::MemForget,
                )
            {
                self.observations.drop_preventions.push(prevention);
            }
            return;
        }
        if let Some(destination) = destination
            && let Some(user_data) =
                self.raw_pointer_passthrough_call_reference(callee_def_id, args)
        {
            self.record_raw_pointer_destination(destination, user_data.clone());
            self.observe_raw_pointer_passthrough_object_flow(
                &callee_def_path,
                destination,
                user_data,
                span,
                location,
            );
        }
        if let Some(destination) = destination {
            self.record_raw_pointer_return_field_call(
                callee_def_id,
                &callee_def_path,
                args,
                destination,
                span,
                location,
            );
        }
        if let Some(release) = self.raw_pointer_release_call_reference(callee_def_id, args) {
            self.observe_raw_pointer_release_call(release, &callee_def_path, span, location);
        }
        self.observe_registration_summary_call(callee_def_id, args, span, location);
        self.observe_openssl_ex_data_registration_summary_call(callee_def_id, args, span, location);
        self.observe_openssl_ex_data_release_call(
            callee_def_id,
            &callee_def_path,
            args,
            span,
            location,
        );
        self.observe_external_buffer_binding(&callee_def_path, args, span, location);

        let call_context = CallContext {
            current_crate_name: self.current_crate_name,
            owner_def_path: Some(&self.owner_def_path),
        };
        let callback_arg_indices =
            registration::callback_argument_indices(&callee_def_path, call_context);
        let callback = self.callback_reference_from_args(args, &callback_arg_indices);
        let callback_argument_kind = if callback.is_some()
            || self.callback_argument_is_explicit_some(args, &callback_arg_indices)
        {
            RegistrationArgumentKind::CallbackPresent
        } else if self.callback_argument_is_explicit_none(args, &callback_arg_indices) {
            RegistrationArgumentKind::ExplicitNone
        } else {
            RegistrationArgumentKind::Unknown
        };
        match registration::classify_call(&callee_def_path, callback_argument_kind, call_context) {
            Some(CallClassification::Registration { api_id, role }) => {
                let user_data_arg_indices = registration::user_data_argument_indices(&api_id);
                let user_data = self.raw_pointer_reference_from_args(args, &user_data_arg_indices);
                if let Some(destination) = destination {
                    self.record_previous_user_data_return(&api_id, destination, span, location);
                }
                if let Ok(observation) = self.registration_observation(
                    api_id.clone(),
                    role,
                    callback,
                    user_data,
                    span,
                    location,
                ) {
                    if let Some(release) = self.foreign_destructor_release_observation(
                        &callee_def_path,
                        &api_id,
                        args,
                        &observation,
                        location,
                    ) {
                        self.observations
                            .raw_pointer_transfers
                            .push(release.clone());
                        self.observations
                            .release_path_proofs
                            .push(ReleasePathProofObservation {
                                owner_def_path: observation.owner_def_path.clone(),
                                source_path: release.source_path.clone(),
                                span: release.span.clone(),
                                mir_location: release.mir_location.clone(),
                                registration: observation.clone(),
                                release,
                            });
                    }
                    self.record_openssl_ex_data_registration(&api_id, args, &observation);
                    self.observations.registrations.push(observation);
                }
            }
            Some(CallClassification::ExternalCall { api_id, role }) => {
                if let Ok(observation) =
                    self.external_call_observation(api_id, role, span, location)
                {
                    self.observations.external_calls.push(observation);
                }
            }
            None => {}
        }
    }

    fn observe_shared_owner_clone_object_flow(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        if !shared_owner_clone_call(callee_def_path) {
            return;
        }
        let Some(first_arg) = args.first() else {
            return;
        };
        let Some(source_place) = first_arg.node.place() else {
            return;
        };
        let Some(source_type_name) =
            shared_owner_type_name(source_place.ty(&self.body.local_decls, self.tcx).ty)
        else {
            return;
        };
        let Some(destination_type_name) =
            shared_owner_type_name(destination.ty(&self.body.local_decls, self.tcx).ty)
        else {
            return;
        };
        if shared_owner_family_token(&source_type_name)
            != shared_owner_family_token(&destination_type_name)
        {
            return;
        }
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        let location = format!("{location:?}");
        self.observations.object_flows.push(object_flow_observation(
            &self.owner_def_path,
            &source_path,
            &stable_span,
            &format!("{location}:shared_owner_clone"),
            &self.owner_def_path,
            ObjectFlowEndpointObservation::StaticSite(ObjectFlowStaticSiteObservation {
                owner_def_path: self.owner_def_path.clone(),
                source_path: source_path.clone(),
                span: stable_span.clone(),
                mir_location: format!("{location}:shared_owner_clone_source"),
                type_name: source_type_name,
            }),
            ObjectFlowObjectKind::RustOwner,
            ObjectFlowEndpointObservation::StaticSite(ObjectFlowStaticSiteObservation {
                owner_def_path: self.owner_def_path.clone(),
                source_path: source_path.clone(),
                span: stable_span.clone(),
                mir_location: format!("{location}:shared_owner_clone_destination"),
                type_name: destination_type_name,
            }),
            ObjectFlowObjectKind::RustOwner,
            ObjectFlowKind::WrapperMove,
            None,
            None,
        ));
    }

    fn record_raw_pointer_shared_owner_clone_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
    ) {
        if !shared_owner_clone_call(callee_def_path) {
            return;
        }
        let destination_ty = destination.ty(&self.body.local_decls, self.tcx).ty;
        let Some(destination_family) = shared_owner_family_token(&destination_ty.to_string())
        else {
            return;
        };
        let Some(destination_key) = raw_pointer_place_key(destination) else {
            return;
        };
        if !destination_key.projection.is_empty() {
            return;
        }
        let Some(first_arg) = args.first() else {
            return;
        };
        if shared_owner_family_token(
            &first_arg
                .node
                .ty(&self.body.local_decls, self.tcx)
                .to_string(),
        ) != Some(destination_family)
        {
            return;
        }
        let Some(source_key) = self.raw_pointer_shared_owner_clone_source_key(&first_arg.node)
        else {
            return;
        };
        let mappings = self
            .raw_pointer_origins
            .iter()
            .filter_map(|(key, origin)| {
                if key.local != source_key.local
                    || !key.projection.starts_with(&source_key.projection)
                {
                    return None;
                }
                let mut projection = destination_key.projection.clone();
                projection.extend_from_slice(&key.projection[source_key.projection.len()..]);
                Some((
                    RawPointerPlaceKey {
                        local: destination_key.local,
                        projection,
                    },
                    origin.clone(),
                ))
            })
            .collect::<Vec<_>>();
        if mappings.is_empty() {
            return;
        }
        self.forget_raw_pointer_origin_prefix(&destination_key);
        for (key, origin) in mappings {
            self.record_raw_pointer_origin_key(key, origin);
        }
    }

    fn raw_pointer_shared_owner_clone_source_key(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<RawPointerPlaceKey> {
        let place = operand.place()?;
        if shared_owner_family_token(&operand.ty(&self.body.local_decls, self.tcx).to_string())
            .is_none()
        {
            return None;
        }
        if matches!(
            place.ty(&self.body.local_decls, self.tcx).ty.kind(),
            ty::Ref(..)
        ) && place.projection.is_empty()
            && let Some(source_key) = self
                .raw_pointer_borrow_origins
                .get(&place.local)
                .cloned()
                .flatten()
        {
            return Some(source_key);
        }
        raw_pointer_place_key(&place)
    }

    fn observe_raw_pointer_shared_owner_make_mut_barrier(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    ) {
        if !shared_owner_make_mut_call(callee_def_path) {
            return;
        }
        let Some(first_arg) = args.first() else {
            return;
        };
        let Some(source_key) = self.raw_pointer_shared_owner_clone_source_key(&first_arg.node)
        else {
            return;
        };
        self.forget_raw_pointer_origin_prefix(&source_key);
    }

    /// 记下哪些 local 被移进了闭包成为 upvar。
    ///
    /// 只看闭包聚合的实参，不做别名分析：这里要回答的是"这个 local 进没进那个闭包"，
    /// 是一个语法事实，不是可达性问题。
    fn record_closure_upvar_sources(&mut self, rvalue: &Rvalue<'tcx>) {
        let Rvalue::Aggregate(kind, operands) = rvalue else {
            return;
        };
        let Some(closure_def_id) = closure_def_id_from_aggregate_kind(kind) else {
            return;
        };
        for operand in operands.iter() {
            let Some(place) = operand.place() else {
                continue;
            };
            self.closure_upvar_sources
                .insert(place.local, closure_def_id);
        }
    }

    /// 记下 `dest = receiver.method()` 且该方法返回接收者内部借用的情况。
    ///
    /// 闭包捕获到的往往是这种借用，而 drop 的是接收者本身。没有这条别名，
    /// "被捕获的对象"与"被销毁的对象"是两个互不相识的 site。
    fn record_receiver_borrow_call(
        &mut self,
        callee_def_id: DefId,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: Option<&Place<'tcx>>,
    ) {
        let Some(destination) = destination else {
            return;
        };
        if !destination.projection.is_empty() {
            return;
        }
        if !callable_returns_receiver_borrow(self.tcx, callee_def_id) {
            return;
        }
        let Some(receiver) = args.first().and_then(|arg| arg.node.place()) else {
            return;
        };
        self.receiver_borrow_locals
            .entry(receiver.local)
            .or_default()
            .insert(destination.local);
    }

    /// 这次 drop 是否销毁了某个仍被注册 callback 捕获的对象。
    ///
    /// 直接捕获（闭包收下这个 local）与借用捕获（闭包收下从这个 local 借出的引用）
    /// 都算：两种情况下 callback 之后拿到的都是已失效的对象。
    fn captured_callback_for_dropped_local(&self, local: Local) -> Option<CallbackReference> {
        let closure_def_id = self
            .closure_upvar_sources
            .get(&local)
            .copied()
            .or_else(|| {
                self.receiver_borrow_locals.get(&local).and_then(|borrows| {
                    borrows
                        .iter()
                        .find_map(|borrow| self.closure_upvar_sources.get(borrow).copied())
                })
            })?;
        self.callback_reference_from_def_id(closure_def_id)
    }

    fn drop_observation(
        &self,
        place: &Place<'tcx>,
        span: Span,
        location: Location,
        drop_kind: DropKind,
    ) -> Option<DropObservation> {
        let object_ty = place.ty(&self.body.local_decls, self.tcx).ty;
        if !is_lifecycle_owner_ty(object_ty) {
            return None;
        }
        let object_type_name = object_ty.to_string();
        Some(DropObservation {
            owner_def_path: self.owner_def_path.clone(),
            source_path: source_path(self.tcx, span).ok()?,
            span: stable_span(self.tcx, span).ok()?,
            mir_location: format!("{location:?}"),
            object_type_name,
            drop_kind,
            callback: self
                .callback_reference_from_ty(object_ty)
                .or_else(|| self.captured_callback_for_dropped_local(place.local)),
        })
    }

    fn drop_prevention_observation(
        &self,
        place: &Place<'tcx>,
        span: Span,
        location: Location,
        prevention_kind: DropPreventionKind,
    ) -> Option<DropPreventionObservation> {
        let object_ty = place.ty(&self.body.local_decls, self.tcx).ty;
        if !is_lifecycle_owner_ty(object_ty) {
            return None;
        }
        Some(DropPreventionObservation {
            owner_def_path: self.owner_def_path.clone(),
            source_path: source_path(self.tcx, span).ok()?,
            span: stable_span(self.tcx, span).ok()?,
            mir_location: format!("{location:?}"),
            object_type_name: object_ty.to_string(),
            prevention_kind,
        })
    }

    fn callback_user_data_reconstruction_observation(
        &self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
        destination: Option<&Place<'tcx>>,
    ) -> Option<CallbackUserDataReconstructionObservation> {
        if !self.owner_is_foreign_callback {
            return None;
        }
        let snippet = self.tcx.sess.source_map().span_to_snippet(span).ok()?;
        let lower = snippet.to_ascii_lowercase();
        if !lower.contains("user_data") {
            return None;
        }
        let reconstruction_kind = if is_transmute_call(callee_def_path)
            || lower.contains("mem::transmute")
            || lower.contains("std::mem::transmute")
            || lower.contains("core::mem::transmute")
        {
            CallbackUserDataReconstructionKind::OwnerFromTransmute
        } else if is_box_leak_call(callee_def_path)
            && lower.contains("box::leak")
            && lower.contains("box::from_raw")
        {
            CallbackUserDataReconstructionKind::LeakFromRaw
        } else {
            return None;
        };
        let object_type_name = destination
            .map(|place| place.ty(&self.body.local_decls, self.tcx).ty.to_string())
            .unwrap_or_else(|| "callback_user_data_owner".to_owned());
        let user_data = args
            .iter()
            .find_map(|arg| self.raw_pointer_reference_from_operand(&arg.node))
            .or_else(|| {
                self.raw_pointer_reference_at(
                    span,
                    location,
                    "callback_user_data_raw_pointer".to_owned(),
                )
            })?;
        Some(CallbackUserDataReconstructionObservation {
            owner_def_path: self.owner_def_path.clone(),
            source_path: source_path(self.tcx, span).ok()?,
            span: stable_span(self.tcx, span).ok()?,
            mir_location: format!("{location:?}"),
            object_type_name,
            user_data,
            reconstruction_kind,
        })
    }

    fn observe_callback_user_data_invocation(
        &mut self,
        callee_def_id: DefId,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        if !owner_is_foreign_callback(self.tcx, callee_def_id) {
            return;
        }
        let Some(user_data) = args
            .iter()
            .find_map(|arg| self.raw_pointer_reference_from_operand(&arg.node))
        else {
            return;
        };
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.callback_user_data_invocations
            .push(CallbackUserDataInvocation {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:callback_user_data_invocation"),
                order_key: mir_order_key(location),
                callback_def_path: callee_def_path.to_owned(),
                user_data,
            });
    }

    fn observe_callback_user_data_summary_invocation(
        &mut self,
        callee_def_id: DefId,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        let Some(summary) =
            summarize_callback_user_data_invocation_callable(self.tcx, callee_def_id)
        else {
            return;
        };
        let Some(callback) = args.get(summary.callback_arg.arg_index).and_then(|arg| {
            self.callback_reference_from_operand_with_projection(
                &arg.node,
                &summary.callback_arg.projection,
            )
        }) else {
            return;
        };
        let Some(user_data) = args.get(summary.user_data_arg.arg_index).and_then(|arg| {
            self.raw_pointer_reference_from_operand_with_projection(
                &arg.node,
                &summary.user_data_arg.projection,
            )
        }) else {
            return;
        };
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.callback_user_data_invocations
            .push(CallbackUserDataInvocation {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:callback_user_data_summary_invocation"),
                order_key: mir_order_key(location),
                callback_def_path: callback.def_path,
                user_data,
            });
    }

    fn observe_callback_user_data_transmute_assignment(
        &mut self,
        place: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        if !self.owner_is_foreign_callback {
            return;
        }
        let Rvalue::Cast(_, operand, _) = rvalue else {
            return;
        };
        let Some(span) = self.statement_span(location) else {
            return;
        };
        let Ok(snippet) = self.tcx.sess.source_map().span_to_snippet(span) else {
            return;
        };
        let lower = snippet.to_ascii_lowercase();
        if !lower.contains("transmute") || !lower.contains("user_data") {
            return;
        }
        let object_ty = place.ty(&self.body.local_decls, self.tcx).ty;
        if !is_lifecycle_owner_ty(object_ty) {
            return;
        }
        let user_data = self
            .raw_pointer_reference_from_operand(operand)
            .or_else(|| {
                self.raw_pointer_reference_at(
                    span,
                    location,
                    "callback_user_data_raw_pointer".to_owned(),
                )
            });
        let Some(user_data) = user_data else {
            return;
        };
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.observations.callback_user_data_reconstructions.push(
            CallbackUserDataReconstructionObservation {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}"),
                object_type_name: object_ty.to_string(),
                user_data,
                reconstruction_kind: CallbackUserDataReconstructionKind::OwnerFromTransmute,
            },
        );
    }

    fn statement_span(&self, location: Location) -> Option<Span> {
        self.body
            .basic_blocks
            .get(location.block)?
            .statements
            .get(location.statement_index)
            .map(|statement| statement.source_info.span)
    }

    fn record_atomic_ordering_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        if !destination.projection.is_empty() {
            return;
        }
        if let Some(ordering) = self.atomic_ordering_from_rvalue(rvalue, location) {
            self.atomic_ordering_origins
                .insert(destination.local, ordering);
        }
    }

    fn atomic_ordering_from_rvalue(
        &self,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) -> Option<AtomicOrderingKind> {
        if let Some(span) = self.statement_span(location)
            && let Ok(snippet) = self.tcx.sess.source_map().span_to_snippet(span)
            && let Some(ordering) = atomic_ordering_from_text(&snippet)
        {
            return Some(ordering);
        }
        match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                self.atomic_ordering_from_operand(operand)
            }
            _ => None,
        }
    }

    fn atomic_ordering_from_operand(&self, operand: &Operand<'tcx>) -> Option<AtomicOrderingKind> {
        let place = operand.place()?;
        place
            .projection
            .is_empty()
            .then(|| self.atomic_ordering_origins.get(&place.local).copied())
            .flatten()
    }

    fn atomic_ordering_from_operand_or_span(
        &self,
        operand: &Operand<'tcx>,
        span: Span,
    ) -> Option<AtomicOrderingKind> {
        self.atomic_ordering_from_operand(operand).or_else(|| {
            self.tcx
                .sess
                .source_map()
                .span_to_snippet(span)
                .ok()
                .and_then(|snippet| atomic_ordering_from_text(&snippet))
        })
    }

    fn observe_atomic_ordering_load(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        if !is_atomic_load_call(callee_def_path)
            || !owner_is_atomic_lifecycle_scope(&self.owner_def_path)
        {
            return;
        }
        let Some(receiver) = args.first() else {
            return;
        };
        let target_type_name = receiver
            .node
            .ty(&self.body.local_decls, self.tcx)
            .to_string();
        if !is_pointer_like_atomic_type(&target_type_name)
            && !is_pointer_like_atomic_type(callee_def_path)
        {
            return;
        }
        let Some(ordering) = args
            .iter()
            .rev()
            .find_map(|arg| self.atomic_ordering_from_operand_or_span(&arg.node, arg.span))
            .or_else(|| {
                self.tcx
                    .sess
                    .source_map()
                    .span_to_snippet(span)
                    .ok()
                    .and_then(|snippet| atomic_ordering_from_text(&snippet))
            })
        else {
            return;
        };
        if !matches!(
            ordering,
            AtomicOrderingKind::Relaxed | AtomicOrderingKind::Acquire
        ) {
            return;
        }
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.observations
            .atomic_orderings
            .push(AtomicOrderingObservation {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:atomic_load"),
                api_id: self.owner_def_path.clone(),
                operation: AtomicOperationKind::Load,
                ordering,
                target_type_name,
            });
    }

    fn registration_observation(
        &self,
        api_id: String,
        role: bw_model::RegistrationRole,
        callback: Option<CallbackReference>,
        user_data: Option<RawPointerReference>,
        span: Span,
        location: Location,
    ) -> Result<RegistrationObservation, MirExtractionError> {
        Ok(RegistrationObservation {
            owner_def_path: self.owner_def_path.clone(),
            source_path: source_path(self.tcx, span)?,
            span: stable_span(self.tcx, span)?,
            mir_location: format!("{location:?}"),
            basic_block: location.block.index(),
            statement_index: location.statement_index,
            api_id,
            role,
            callback,
            user_data,
        })
    }

    fn observe_registration_summary_call(
        &mut self,
        callee_def_id: DefId,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        let Some(summary) =
            summarize_registration_callable(self.tcx, self.current_crate_name, callee_def_id)
        else {
            return;
        };
        if summary.role != bw_model::RegistrationRole::Register {
            return;
        }
        let callback = summary
            .callback_arg_index
            .and_then(|index| self.callback_reference_from_args(args, &[index]));
        let callback_argument_kind = if callback.is_some()
            || summary
                .callback_arg_index
                .is_some_and(|index| self.callback_argument_is_explicit_some(args, &[index]))
        {
            RegistrationArgumentKind::CallbackPresent
        } else if summary
            .callback_arg_index
            .is_some_and(|index| self.callback_argument_is_explicit_none(args, &[index]))
        {
            RegistrationArgumentKind::ExplicitNone
        } else {
            RegistrationArgumentKind::Unknown
        };
        if callback_argument_kind != RegistrationArgumentKind::CallbackPresent {
            return;
        }
        let user_data = summary
            .user_data_arg_index
            .and_then(|index| self.raw_pointer_reference_from_args(args, &[index]));
        if callback.is_none() || user_data.is_none() {
            // callee 已被证明是注册 helper 且参数下标已知，但调用者一侧的实参解析不回被
            // 跟踪的对象。此前这里直接 return，缺口不进入事实流，下游无法区分"绑定丢了"
            // 与"这里没有注册"。记录为 call boundary 缺证，使覆盖缺口可度量。
            self.record_object_binding_gap_at_callsite(
                ObjectBindingGapKind::CallBoundary,
                Some(summary.api_id.clone()),
                span,
                location,
                "registration_summary_user_data",
            );
            return;
        }
        if let Ok(observation) = self.registration_observation(
            summary.api_id,
            summary.role,
            callback,
            user_data,
            span,
            location,
        ) {
            if !self
                .observations
                .registrations
                .iter()
                .any(|existing| existing == &observation)
            {
                self.observations.registrations.push(observation);
            }
        }
    }

    fn callback_reference_from_args(
        &self,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        indices: &[usize],
    ) -> Option<CallbackReference> {
        let mut callback_def_id = None;
        for candidate in indexed_args(args, indices).filter_map(|arg| {
            callback_def_id_from_ty(arg.node.ty(&self.body.local_decls, self.tcx))
                .or_else(|| self.fn_def_from_operand(&arg.node))
                .or_else(|| self.option_fn_def_from_operand(&arg.node))
        }) {
            if let Some(existing) = callback_def_id
                && existing != candidate
            {
                return None;
            }
            callback_def_id = Some(candidate);
        }
        let callback_def_id = callback_def_id?;
        self.callback_reference_from_def_id(callback_def_id)
    }

    fn callback_reference_from_operand_with_projection(
        &self,
        operand: &Operand<'tcx>,
        projection: &[String],
    ) -> Option<CallbackReference> {
        let callback_def_id = if projection.is_empty() {
            callback_def_id_from_ty(operand.ty(&self.body.local_decls, self.tcx))
                .or_else(|| self.fn_def_from_operand(operand))
                .or_else(|| self.option_fn_def_from_operand(operand))?
        } else {
            let place = operand.place()?;
            let mut key = fn_pointer_place_key(self.body, &place)?;
            key.projection.extend_from_slice(projection);
            self.fn_pointer_origins
                .get(&key)
                .cloned()
                .flatten()
                .or_else(|| self.option_fn_pointer_origins.get(&key).cloned().flatten())?
        };
        self.callback_reference_from_def_id(callback_def_id)
    }

    fn observe_raw_pointer_transfer(
        &mut self,
        kind: RawPointerTransferKind,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
        destination: Option<&Place<'tcx>>,
    ) {
        let user_data = match kind {
            RawPointerTransferKind::IntoRaw => {
                let type_name = args
                    .first()
                    .map(|arg| arg.node.ty(&self.body.local_decls, self.tcx).to_string())
                    .unwrap_or_else(|| "raw_pointer".to_owned());
                let Some(user_data) = self.raw_pointer_reference_at(span, location, type_name)
                else {
                    return;
                };
                let Some(destination) = destination else {
                    return;
                };
                self.record_raw_pointer_destination(destination, user_data.clone());
                if let Some((storage_site, field_path)) = self
                    .object_flow_static_site_endpoint_from_place(
                        destination,
                        span,
                        location,
                        "field_store",
                    )
                {
                    let flow_source_path =
                        object_flow_endpoint_source_path(&storage_site).to_path_buf();
                    let flow_span = object_flow_endpoint_span(&storage_site).to_owned();
                    self.observations.object_flows.push(object_flow_observation(
                        &self.owner_def_path,
                        &flow_source_path,
                        &flow_span,
                        &format!("{location:?}:field_store:{field_path}"),
                        &self.owner_def_path,
                        ObjectFlowEndpointObservation::UserData(user_data.clone()),
                        ObjectFlowObjectKind::UserData,
                        storage_site,
                        ObjectFlowObjectKind::Storage,
                        ObjectFlowKind::FieldStore,
                        Some(field_path),
                        None,
                    ));
                }
                user_data
            }
            RawPointerTransferKind::FromRaw => {
                let Some(user_data) = args
                    .first()
                    .and_then(|arg| self.raw_pointer_reference_from_operand(&arg.node))
                else {
                    return;
                };
                user_data
            }
            RawPointerTransferKind::FromRawParts => {
                let Some(user_data) = args
                    .first()
                    .and_then(|arg| self.raw_pointer_reference_from_operand(&arg.node))
                    .or_else(|| {
                        let type_name = args
                            .first()
                            .map(|arg| arg.node.ty(&self.body.local_decls, self.tcx).to_string())
                            .unwrap_or_else(|| "raw_parts_pointer".to_owned());
                        self.raw_pointer_reference_at(span, location, type_name)
                    })
                else {
                    return;
                };
                user_data
            }
        };
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.observations
            .raw_pointer_transfers
            .push(RawPointerTransferObservation {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}"),
                basic_block: location.block.index(),
                statement_index: location.statement_index,
                kind,
                user_data,
            });
    }

    fn raw_pointer_reference_at(
        &self,
        span: Span,
        location: Location,
        type_name: String,
    ) -> Option<RawPointerReference> {
        Some(RawPointerReference {
            owner_def_path: self.owner_def_path.clone(),
            source_path: source_path(self.tcx, span).ok()?,
            span: stable_span(self.tcx, span).ok()?,
            mir_location: format!("{location:?}"),
            type_name,
        })
    }

    fn infer_release_path_proofs(&mut self) {
        let registrations = self.observations.registrations.clone();
        let releases = self
            .observations
            .raw_pointer_transfers
            .iter()
            .filter(|transfer| transfer.kind == RawPointerTransferKind::FromRaw)
            .cloned()
            .collect::<Vec<_>>();
        for registration in registrations.iter().filter(|registration| {
            registration.role == bw_model::RegistrationRole::Register
                && registration.user_data.is_some()
        }) {
            let Some(user_data) = registration.user_data.as_ref() else {
                continue;
            };
            for release in &releases {
                if release.owner_def_path != registration.owner_def_path
                    || &release.user_data != user_data
                    || !release_postdominates_registration(
                        self.body,
                        registration.basic_block,
                        release.basic_block,
                    )
                {
                    continue;
                }
                self.observations
                    .release_path_proofs
                    .push(ReleasePathProofObservation {
                        owner_def_path: registration.owner_def_path.clone(),
                        source_path: release.source_path.clone(),
                        span: release.span.clone(),
                        mir_location: release.mir_location.clone(),
                        registration: registration.clone(),
                        release: release.clone(),
                    });
            }
        }
        self.infer_hook_state_machine_release_path_proofs();
    }

    fn record_raw_pointer_destination(
        &mut self,
        destination: &Place<'tcx>,
        user_data: RawPointerReference,
    ) {
        let Some(key) = raw_pointer_place_key(destination) else {
            return;
        };
        match self.raw_pointer_origins.get_mut(&key) {
            Some(existing) if existing.as_ref().is_some_and(|item| item != &user_data) => {
                *existing = None;
            }
            Some(_) => {}
            None => {
                self.raw_pointer_origins.insert(key, Some(user_data));
            }
        }
    }

    fn observe_raw_pointer_field_assignment_flows(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        if let Rvalue::Aggregate(kind, operands) = rvalue
            && raw_pointer_aggregate_kind_tracks_fields(kind)
        {
            self.observe_raw_pointer_aggregate_field_store_flows(
                destination,
                operands.iter().enumerate(),
                location,
            );
        }

        if !matches!(
            destination.ty(&self.body.local_decls, self.tcx).ty.kind(),
            ty::RawPtr(..)
        ) {
            return;
        }

        let span = self.body.source_info(location).span;
        let destination_key = raw_pointer_place_key(destination);
        let incoming_user_data = self.raw_pointer_reference_from_rvalue(rvalue);
        if destination_key
            .as_ref()
            .is_some_and(|key| !key.projection.is_empty())
            && let Some(key) = destination_key.as_ref()
            && let Some(field_path) = raw_pointer_field_path_from_key(key)
        {
            self.record_raw_pointer_field_reassignment_barrier_if_needed(
                key,
                incoming_user_data.as_ref(),
                &field_path,
                span,
                location,
                "field_assignment",
            );
        }
        if destination_key
            .as_ref()
            .is_some_and(|key| !key.projection.is_empty())
            && let Some(user_data) = incoming_user_data
            && let Some((storage_site, field_path)) = self
                .object_flow_static_site_endpoint_from_place(
                    destination,
                    span,
                    location,
                    "field_store",
                )
        {
            let flow_source_path = object_flow_endpoint_source_path(&storage_site).to_path_buf();
            let flow_span = object_flow_endpoint_span(&storage_site).to_owned();
            self.observations.object_flows.push(object_flow_observation(
                &self.owner_def_path,
                &flow_source_path,
                &flow_span,
                &format!("{location:?}:field_store:{field_path}"),
                &self.owner_def_path,
                ObjectFlowEndpointObservation::UserData(user_data),
                ObjectFlowObjectKind::UserData,
                storage_site,
                ObjectFlowObjectKind::Storage,
                ObjectFlowKind::FieldStore,
                Some(field_path),
                None,
            ));
        }

        if destination_key
            .as_ref()
            .is_some_and(|key| key.projection.is_empty())
            && let Some((source_place, user_data)) =
                self.raw_pointer_field_source_from_rvalue(rvalue)
            && let Some((storage_site, field_path)) = self
                .object_flow_static_site_endpoint_from_place(
                    &source_place,
                    span,
                    location,
                    "field_load",
                )
        {
            let flow_source_path = object_flow_endpoint_source_path(&storage_site).to_path_buf();
            let flow_span = object_flow_endpoint_span(&storage_site).to_owned();
            self.observations.object_flows.push(object_flow_observation(
                &self.owner_def_path,
                &flow_source_path,
                &flow_span,
                &format!("{location:?}:field_load:{field_path}"),
                &self.owner_def_path,
                storage_site,
                ObjectFlowObjectKind::Storage,
                ObjectFlowEndpointObservation::UserData(user_data),
                ObjectFlowObjectKind::UserData,
                ObjectFlowKind::FieldLoad,
                Some(field_path),
                None,
            ));
        }
    }

    fn observe_raw_pointer_aggregate_field_store_flows<'a>(
        &mut self,
        destination: &Place<'tcx>,
        operands: impl Iterator<Item = (usize, &'a Operand<'tcx>)>,
        location: Location,
    ) where
        'tcx: 'a,
    {
        let Some(destination_key) = raw_pointer_place_key(destination) else {
            return;
        };
        let span = self.body.source_info(location).span;
        for (field_index, operand) in operands {
            for (field_key, origin) in self.raw_pointer_aggregate_operand_field_origins(
                &destination_key,
                field_index,
                operand,
            ) {
                let Some(user_data) = origin else {
                    continue;
                };
                let field_path = field_key.projection.join(".");
                let Some(storage_site) = self.object_flow_static_site_endpoint_for_field_key(
                    span,
                    location,
                    "field_store",
                    &field_path,
                    operand.ty(&self.body.local_decls, self.tcx).to_string(),
                ) else {
                    continue;
                };
                let flow_source_path =
                    object_flow_endpoint_source_path(&storage_site).to_path_buf();
                let flow_span = object_flow_endpoint_span(&storage_site).to_owned();
                self.observations.object_flows.push(object_flow_observation(
                    &self.owner_def_path,
                    &flow_source_path,
                    &flow_span,
                    &format!("{location:?}:field_store:{field_path}"),
                    &self.owner_def_path,
                    ObjectFlowEndpointObservation::UserData(user_data),
                    ObjectFlowObjectKind::UserData,
                    storage_site,
                    ObjectFlowObjectKind::Storage,
                    ObjectFlowKind::FieldStore,
                    Some(field_path),
                    None,
                ));
            }
        }
    }

    fn raw_pointer_aggregate_operand_field_origins(
        &self,
        destination_key: &RawPointerPlaceKey,
        field_index: usize,
        operand: &Operand<'tcx>,
    ) -> Vec<(RawPointerPlaceKey, Option<RawPointerReference>)> {
        let mut field_prefix = destination_key.clone();
        field_prefix.projection.push(format!("field:{field_index}"));
        if matches!(
            operand.ty(&self.body.local_decls, self.tcx).kind(),
            ty::RawPtr(..)
        ) {
            return self
                .raw_pointer_reference_from_operand(operand)
                .map(|origin| vec![(field_prefix, Some(origin))])
                .unwrap_or_default();
        }
        let Some(source_place) = operand.place() else {
            return Vec::new();
        };
        let Some(source_key) = raw_pointer_place_key(&source_place) else {
            return Vec::new();
        };
        self.raw_pointer_origins
            .iter()
            .filter_map(|(key, value)| {
                if key.local != source_key.local
                    || !key.projection.starts_with(&source_key.projection)
                {
                    return None;
                }
                let mut projection = field_prefix.projection.clone();
                projection.extend_from_slice(&key.projection[source_key.projection.len()..]);
                Some((
                    RawPointerPlaceKey {
                        local: field_prefix.local,
                        projection,
                    },
                    value.clone(),
                ))
            })
            .collect()
    }

    fn raw_pointer_reference_from_rvalue(
        &self,
        rvalue: &Rvalue<'tcx>,
    ) -> Option<RawPointerReference> {
        match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                self.raw_pointer_reference_from_operand(operand)
            }
            _ => None,
        }
    }

    fn raw_pointer_field_source_from_rvalue(
        &self,
        rvalue: &Rvalue<'tcx>,
    ) -> Option<(Place<'tcx>, RawPointerReference)> {
        let operand = match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => operand,
            _ => return None,
        };
        let place = operand.place()?;
        let key = self.raw_pointer_storage_field_key_from_place(&place)?;
        if key.projection.is_empty() {
            return None;
        }
        let user_data = self.raw_pointer_reference_from_operand(operand)?;
        Some((place, user_data))
    }

    fn object_flow_static_site_endpoint_from_place(
        &self,
        place: &Place<'tcx>,
        span: Span,
        location: Location,
        role: &str,
    ) -> Option<(ObjectFlowEndpointObservation, String)> {
        let key = self.raw_pointer_storage_field_key_from_place(place)?;
        if key.projection.is_empty() {
            return None;
        }
        let field_path = key.projection.join(".");
        let source_path = source_path(self.tcx, span).ok()?;
        let stable_span = stable_span(self.tcx, span).ok()?;
        let type_name = place.ty(&self.body.local_decls, self.tcx).ty.to_string();
        Some((
            ObjectFlowEndpointObservation::StaticSite(ObjectFlowStaticSiteObservation {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:{role}:{field_path}"),
                type_name,
            }),
            field_path,
        ))
    }

    fn raw_pointer_storage_field_key_from_place(
        &self,
        place: &Place<'tcx>,
    ) -> Option<RawPointerPlaceKey> {
        raw_pointer_place_key(place)
            .or_else(|| self.raw_pointer_borrowed_field_key(place))
            .or_else(|| self.raw_pointer_option_some_field_key(place))
            .or_else(|| self.raw_pointer_result_ok_field_key(place))
            .or_else(|| self.raw_pointer_unique_owner_field_key(place))
            .or_else(|| self.raw_pointer_storage_pointer_field_key(place))
    }

    fn raw_pointer_borrowed_field_key(&self, place: &Place<'tcx>) -> Option<RawPointerPlaceKey> {
        if place.projection.is_empty()
            || !matches!(self.body.local_decls[place.local].ty.kind(), ty::Ref(..))
        {
            return None;
        }
        let mut elements = place.projection.iter();
        if !matches!(elements.next(), Some(ProjectionElem::Deref)) {
            return None;
        }
        let mut borrowed_key = self
            .raw_pointer_borrow_origins
            .get(&place.local)
            .cloned()
            .flatten()?;
        for elem in elements {
            match elem {
                ProjectionElem::Field(field, _) => {
                    borrowed_key
                        .projection
                        .push(format!("field:{}", field.index()));
                }
                _ => return None,
            }
        }
        Some(borrowed_key)
    }

    fn raw_pointer_option_some_field_key(&self, place: &Place<'tcx>) -> Option<RawPointerPlaceKey> {
        raw_pointer_option_some_field_key_from_place(self.body, place)
    }

    fn raw_pointer_result_ok_field_key(&self, place: &Place<'tcx>) -> Option<RawPointerPlaceKey> {
        raw_pointer_result_ok_field_key_from_place(self.body, place)
    }

    fn raw_pointer_unique_owner_field_key(
        &self,
        place: &Place<'tcx>,
    ) -> Option<RawPointerPlaceKey> {
        raw_pointer_unique_owner_field_key_from_place(self.body, place)
    }

    fn raw_pointer_storage_pointer_field_key(
        &self,
        place: &Place<'tcx>,
    ) -> Option<RawPointerPlaceKey> {
        raw_pointer_storage_pointer_field_key_from_place(self.body, place)
    }

    fn object_flow_static_site_endpoint_at(
        &self,
        span: Span,
        location: Location,
        role: &str,
        type_name: String,
    ) -> Option<ObjectFlowEndpointObservation> {
        Some(ObjectFlowEndpointObservation::StaticSite(
            ObjectFlowStaticSiteObservation {
                owner_def_path: self.owner_def_path.clone(),
                source_path: source_path(self.tcx, span).ok()?,
                span: stable_span(self.tcx, span).ok()?,
                mir_location: format!("{location:?}:{role}"),
                type_name,
            },
        ))
    }

    fn object_flow_static_site_endpoint_for_field_key(
        &self,
        span: Span,
        location: Location,
        role: &str,
        field_path: &str,
        type_name: String,
    ) -> Option<ObjectFlowEndpointObservation> {
        Some(ObjectFlowEndpointObservation::StaticSite(
            ObjectFlowStaticSiteObservation {
                owner_def_path: self.owner_def_path.clone(),
                source_path: source_path(self.tcx, span).ok()?,
                span: stable_span(self.tcx, span).ok()?,
                mir_location: format!("{location:?}:{role}:{field_path}"),
                type_name,
            },
        ))
    }

    fn record_stable_constant_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
    ) {
        if !destination.projection.is_empty() {
            return;
        }
        self.bump_dynamic_key_generation(destination.local);
        self.unsupported_key_wrapper_origins
            .remove(&destination.local);
        let key = match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                self.stable_constant_key_from_operand(operand)
            }
            _ => None,
        };
        if let Some(key) = key {
            self.stable_constant_origins.insert(destination.local, key);
        } else {
            self.stable_constant_origins.remove(&destination.local);
        }
    }

    fn stable_constant_key_from_operand(&self, operand: &Operand<'tcx>) -> Option<String> {
        stable_constant_operand_key(operand).or_else(|| {
            let place = operand.place()?;
            place
                .projection
                .is_empty()
                .then(|| self.stable_constant_origins.get(&place.local).cloned())
                .flatten()
        })
    }

    fn record_stable_range_assignment(&mut self, destination: &Place<'tcx>, rvalue: &Rvalue<'tcx>) {
        if !destination.projection.is_empty() {
            return;
        }
        let type_name = destination
            .ty(&self.body.local_decls, self.tcx)
            .ty
            .to_string();
        let Some(range_kind) = slice_range_kind(&type_name) else {
            self.stable_range_origins.remove(&destination.local);
            return;
        };
        let bounds = match rvalue {
            Rvalue::Aggregate(_, operands) => self.const_range_bounds_from_operands(
                range_kind,
                operands.iter().collect::<Vec<_>>().as_slice(),
            ),
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                self.stable_range_bounds_from_operand(operand)
            }
            _ => None,
        };
        if let Some(bounds) = bounds {
            self.stable_range_origins.insert(destination.local, bounds);
        } else {
            self.stable_range_origins.remove(&destination.local);
        }
    }

    fn record_stable_range_constructor_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
    ) {
        if !destination.projection.is_empty() {
            return;
        }
        self.stable_range_origins.remove(&destination.local);
        let type_name = destination
            .ty(&self.body.local_decls, self.tcx)
            .ty
            .to_string();
        let Some(range_kind) = slice_range_kind(&type_name) else {
            return;
        };
        if range_kind != SliceRangeKind::RangeInclusive
            || method_name(callee_def_path).as_deref() != Some("new")
            || !callee_def_path.contains("RangeInclusive")
        {
            return;
        }
        let operands = args.iter().map(|arg| &arg.node).collect::<Vec<_>>();
        if let Some(bounds) = self.const_range_bounds_from_operands(range_kind, operands.as_slice())
        {
            self.stable_range_origins.insert(destination.local, bounds);
        }
    }

    fn const_range_bounds_from_operands(
        &self,
        range_kind: SliceRangeKind,
        operands: &[&Operand<'tcx>],
    ) -> Option<ConstRangeBounds> {
        match range_kind {
            SliceRangeKind::Range if operands.len() == 2 => {
                let start = self.usize_from_operand(operands[0])?;
                let end = self.usize_from_operand(operands[1])?;
                Some(ConstRangeBounds {
                    start,
                    end: Some(end),
                })
            }
            SliceRangeKind::RangeInclusive if operands.len() >= 2 => {
                let start = self.usize_from_operand(operands[0])?;
                let end = self.usize_from_operand(operands[1])?.checked_add(1)?;
                Some(ConstRangeBounds {
                    start,
                    end: Some(end),
                })
            }
            SliceRangeKind::RangeFrom if operands.len() == 1 => {
                let start = self.usize_from_operand(operands[0])?;
                Some(ConstRangeBounds { start, end: None })
            }
            SliceRangeKind::RangeTo if operands.len() == 1 => {
                let end = self.usize_from_operand(operands[0])?;
                Some(ConstRangeBounds {
                    start: 0,
                    end: Some(end),
                })
            }
            SliceRangeKind::RangeToInclusive if operands.len() == 1 => {
                let end = self.usize_from_operand(operands[0])?.checked_add(1)?;
                Some(ConstRangeBounds {
                    start: 0,
                    end: Some(end),
                })
            }
            SliceRangeKind::RangeFull if operands.is_empty() => Some(ConstRangeBounds {
                start: 0,
                end: None,
            }),
            _ => None,
        }
    }

    fn stable_range_bounds_from_operand(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<ConstRangeBounds> {
        if let Some(place) = operand.place() {
            if !place.projection.is_empty() {
                return None;
            }
            if let Some(bounds) = self.stable_range_origins.get(&place.local).copied() {
                return Some(bounds);
            }
        }
        self.const_range_bounds_from_constant_operand(operand)
    }

    fn const_range_bounds_from_constant_operand(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<ConstRangeBounds> {
        let type_name = operand.ty(&self.body.local_decls, self.tcx).to_string();
        let range_kind = slice_range_kind(&type_name)?;
        let snippet = format!("{operand:?}");
        match range_kind {
            SliceRangeKind::Range => {
                let start = debug_usize_field(&snippet, "start")?;
                let end = debug_usize_field(&snippet, "end")?;
                Some(ConstRangeBounds {
                    start,
                    end: Some(end),
                })
            }
            SliceRangeKind::RangeInclusive => {
                let start = debug_usize_field(&snippet, "start")?;
                let end = debug_usize_field(&snippet, "end")?.checked_add(1)?;
                Some(ConstRangeBounds {
                    start,
                    end: Some(end),
                })
            }
            SliceRangeKind::RangeFrom => {
                let start = debug_usize_field(&snippet, "start")?;
                Some(ConstRangeBounds { start, end: None })
            }
            SliceRangeKind::RangeTo => {
                let end = debug_usize_field(&snippet, "end")?;
                Some(ConstRangeBounds {
                    start: 0,
                    end: Some(end),
                })
            }
            SliceRangeKind::RangeToInclusive => {
                let end = debug_usize_field(&snippet, "end")?.checked_add(1)?;
                Some(ConstRangeBounds {
                    start: 0,
                    end: Some(end),
                })
            }
            SliceRangeKind::RangeFull => Some(ConstRangeBounds {
                start: 0,
                end: None,
            }),
        }
    }

    fn usize_from_operand(&self, operand: &Operand<'tcx>) -> Option<usize> {
        usize_constant_operand_key_with_origins(operand, &self.stable_constant_origins)
            .and_then(|key| key.parse::<usize>().ok())
    }

    fn record_scoped_key_assignment(&mut self, destination: &Place<'tcx>, rvalue: &Rvalue<'tcx>) {
        if !destination.projection.is_empty() {
            return;
        }
        let key = match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                self.scoped_key_origin_from_operand(operand)
            }
            Rvalue::Ref(_, _, source_place) => self.scoped_key_origin_from_place(source_place),
            _ => None,
        };
        if let Some(key) = key {
            self.scoped_key_origins.insert(destination.local, key);
            self.unsupported_key_wrapper_origins
                .remove(&destination.local);
        } else {
            self.scoped_key_origins.remove(&destination.local);
            self.unsupported_key_wrapper_origins
                .remove(&destination.local);
        }
    }

    fn record_scoped_key_passthrough_call(
        &mut self,
        callee_def_id: DefId,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
    ) {
        if !destination.projection.is_empty() {
            return;
        }
        let destination_type_name = destination
            .ty(&self.body.local_decls, self.tcx)
            .ty
            .to_string();
        let destination_is_string_key = string_like_key_type(&destination_type_name)
            || owned_string_key_type(&destination_type_name);
        let summary_arg_index = if string_key_passthrough_call(callee_def_path) {
            Some(0)
        } else {
            summarize_string_key_return_callable(self.tcx, callee_def_id)
        };
        let key = summary_arg_index.and_then(|arg_index| {
            args.get(arg_index).and_then(|arg| {
                string_like_key_type(&arg.node.ty(&self.body.local_decls, self.tcx).to_string())
                    .then(|| self.scoped_key_origin_from_operand(&arg.node))
                    .flatten()
            })
        });
        if !destination_is_string_key && key.is_none() {
            if summary_arg_index.is_none()
                && args.iter().any(|arg| {
                    string_like_key_type(&arg.node.ty(&self.body.local_decls, self.tcx).to_string())
                })
            {
                self.unsupported_key_wrapper_origins
                    .insert(destination.local, "key_contract".to_owned());
            }
            return;
        }
        self.bump_dynamic_key_generation(destination.local);
        self.stable_constant_origins.remove(&destination.local);
        self.unsupported_key_wrapper_origins
            .remove(&destination.local);
        if let Some(key) = key {
            self.scoped_key_origins.insert(destination.local, key);
        } else {
            self.scoped_key_origins.remove(&destination.local);
        }
    }

    fn scoped_key_origin_from_operand(&self, operand: &Operand<'tcx>) -> Option<String> {
        scoped_key_operand_key(
            operand,
            &self.stable_constant_origins,
            &self.scoped_key_origins,
            &self.dynamic_key_generations,
            &self.owner_def_path,
        )
    }

    fn scoped_key_origin_from_place(&self, place: &Place<'tcx>) -> Option<String> {
        place
            .projection
            .is_empty()
            .then(|| self.scoped_key_origins.get(&place.local).cloned())
            .flatten()
    }

    fn unsupported_key_wrapper_adapter_from_operand(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<String> {
        let place = operand.place()?;
        place
            .projection
            .is_empty()
            .then(|| {
                self.unsupported_key_wrapper_origins
                    .get(&place.local)
                    .cloned()
            })
            .flatten()
    }

    fn record_keyed_map_key_contract_gap_if_needed(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        storage_type_name: &str,
        span: Span,
        location: Location,
        location_suffix: &str,
    ) {
        if !returned_borrow_keyed_map_storage_type(storage_type_name)
            || !method_name(callee_def_path)
                .as_deref()
                .is_some_and(|method| matches!(method, "entry" | "insert" | "get" | "remove"))
        {
            return;
        }
        let Some(adapter) = args
            .get(1)
            .and_then(|arg| self.unsupported_key_wrapper_adapter_from_operand(&arg.node))
        else {
            return;
        };
        self.record_object_binding_gap_at_callsite(
            ObjectBindingGapKind::KeyContract,
            Some(adapter),
            span,
            location,
            location_suffix,
        );
    }

    fn record_returned_borrow_keyed_map_entry_call(
        &mut self,
        callee_def_id: DefId,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        if !destination.projection.is_empty() {
            return;
        }
        let origin = self
            .returned_borrow_keyed_map_entry_origin_from_call(callee_def_path, args, span, location)
            .or_else(|| {
                self.returned_borrow_keyed_map_entry_origin_from_same_crate_summary(
                    callee_def_id,
                    args,
                    location,
                )
            });
        if let Some(origin) = origin {
            self.returned_borrow_keyed_map_entry_origins
                .insert(destination.local, origin);
        } else {
            self.returned_borrow_keyed_map_entry_origins
                .remove(&destination.local);
        }
    }

    fn returned_borrow_keyed_map_entry_origin_from_same_crate_summary(
        &self,
        callee_def_id: DefId,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        location: Location,
    ) -> Option<KeyedMapEntryOrigin> {
        let summary = summarize_returned_borrow_collection_entry_callable(self.tcx, callee_def_id)?;
        let storage_arg = args.get(summary.storage_arg_index)?;
        let storage_type_name = storage_arg
            .node
            .ty(&self.body.local_decls, self.tcx)
            .to_string();
        let storage_key = storage_arg
            .node
            .place()
            .and_then(|place| self.returned_borrow_storage_key(&place))?;
        let key = args.get(summary.key_arg_index).and_then(|arg| {
            scoped_key_operand_key(
                &arg.node,
                &self.stable_constant_origins,
                &self.scoped_key_origins,
                &self.dynamic_key_generations,
                &self.owner_def_path,
            )
        })?;
        Some(KeyedMapEntryOrigin {
            occupancy: self.keyed_map_entry_occupancy(&storage_key, Some(&key)),
            storage_key,
            storage_type_name,
            key: Some(key),
            entry_site_id: format!("{}:{location:?}:entry_helper", self.owner_def_path),
            projection_kind: None,
            projection_order_key: None,
        })
    }

    fn record_returned_borrow_keyed_map_entry_value_reference_call(
        &mut self,
        callee_def_id: DefId,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        location: Location,
    ) {
        if !destination.projection.is_empty() {
            return;
        }
        let reference_origin = self
            .returned_borrow_entry_value_reference_origin_from_direct_call(
                callee_def_path,
                args,
                location,
            )
            .or_else(|| {
                self.returned_borrow_entry_value_reference_origin_from_same_crate_summary(
                    callee_def_id,
                    args,
                    location,
                )
            });
        let Some(reference_origin) = reference_origin else {
            self.returned_borrow_storage_reference_origins
                .remove(&destination.local);
            self.returned_borrow_entry_value_reference_origins
                .remove(&destination.local);
            return;
        };
        let storage_key = reference_origin.storage_key.clone();
        self.returned_borrow_storage_reference_origins
            .insert(destination.local, Some(storage_key.clone()));
        self.record_returned_borrow_entry_value_reference_origin(
            destination.local,
            reference_origin,
        );
        self.returned_borrow_keyed_map_known_occupied
            .insert(storage_key);
    }

    fn returned_borrow_entry_value_reference_origin_from_direct_call(
        &self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        location: Location,
    ) -> Option<ReturnedBorrowEntryValueReferenceOrigin> {
        let method = method_name(callee_def_path)?;
        let returns_entry_value_reference = matches!(
            method.as_str(),
            "or_insert"
                | "or_insert_with"
                | "or_insert_with_key"
                | "get_mut"
                | "into_mut"
                | "insert"
        );
        if !returns_entry_value_reference {
            return None;
        }
        let Some(entry_origin) = args.first().and_then(|arg| {
            self.returned_borrow_keyed_map_entry_use_origin_from_operand_at(&arg.node, location)
        }) else {
            return None;
        };
        let allowed_entry_value_reference = match method.as_str() {
            "or_insert" | "or_insert_with" | "or_insert_with_key" => true,
            "get_mut" | "into_mut" => {
                (entry_origin.occupancy == KeyedMapEntryOccupancy::KnownOccupied
                    && entry_origin.projection_kind.is_none())
                    || entry_origin.projection_kind == Some(KeyedMapEntryProjectionKind::Occupied)
            }
            "insert" => entry_origin.projection_kind == Some(KeyedMapEntryProjectionKind::Vacant),
            _ => false,
        };
        if !allowed_entry_value_reference {
            return None;
        }
        let Some(key) = &entry_origin.key else {
            return None;
        };
        let storage_key = keyed_map_returned_borrow_storage_key(&entry_origin.storage_key, key);
        Some(ReturnedBorrowEntryValueReferenceOrigin {
            storage_key,
            storage_type_name: entry_origin.storage_type_name.clone(),
            reference_order_keys: BTreeSet::from([mir_order_key(location)]),
        })
    }

    fn returned_borrow_entry_value_reference_origin_from_same_crate_summary(
        &self,
        callee_def_id: DefId,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        location: Location,
    ) -> Option<ReturnedBorrowEntryValueReferenceOrigin> {
        let summary = summarize_returned_borrow_collection_entry_value_reference_callable(
            self.tcx,
            self.current_crate_name,
            callee_def_id,
        )?;
        let storage_arg = args.get(summary.storage_arg_index)?;
        let base_storage_key = storage_arg
            .node
            .place()
            .and_then(|place| self.returned_borrow_storage_key(&place))?;
        let key = args.get(summary.key_arg_index).and_then(|arg| {
            scoped_key_operand_key(
                &arg.node,
                &self.stable_constant_origins,
                &self.scoped_key_origins,
                &self.dynamic_key_generations,
                &self.owner_def_path,
            )
        })?;
        Some(ReturnedBorrowEntryValueReferenceOrigin {
            storage_key: keyed_map_returned_borrow_storage_key(&base_storage_key, &key),
            storage_type_name: storage_arg
                .node
                .ty(&self.body.local_decls, self.tcx)
                .to_string(),
            reference_order_keys: BTreeSet::from([mir_order_key(location)]),
        })
    }

    fn record_returned_borrow_entry_value_reference_origin(
        &mut self,
        local: Local,
        origin: ReturnedBorrowEntryValueReferenceOrigin,
    ) {
        let Some(existing) = self
            .returned_borrow_entry_value_reference_origins
            .get_mut(&local)
        else {
            self.returned_borrow_entry_value_reference_origins
                .insert(local, origin);
            self.flush_pending_returned_borrow_entry_value_assignments(local);
            return;
        };
        if existing.storage_key == origin.storage_key
            && existing.storage_type_name == origin.storage_type_name
        {
            existing
                .reference_order_keys
                .extend(origin.reference_order_keys);
        } else {
            self.returned_borrow_entry_value_reference_origins
                .remove(&local);
            self.returned_borrow_storage_reference_origins
                .insert(local, None);
        }
        self.flush_pending_returned_borrow_entry_value_assignments(local);
    }

    fn flush_pending_returned_borrow_entry_value_assignments(&mut self, local: Local) {
        let Some(reference_origin) = self
            .returned_borrow_entry_value_reference_origins
            .get(&local)
            .cloned()
        else {
            return;
        };
        let mut remaining = Vec::new();
        for pending in std::mem::take(&mut self.pending_returned_borrow_entry_value_assignments) {
            if pending.local != local {
                remaining.push(pending);
                continue;
            }
            if !reference_origin
                .reference_order_keys
                .iter()
                .all(|reference_order_key| {
                    entry_value_assignment_postdominates_reference(
                        self.body,
                        *reference_order_key,
                        mir_order_key(pending.location),
                    )
                })
            {
                remaining.push(pending);
                continue;
            }
            self.remove_returned_borrow_origins_for_storage_key(&reference_origin.storage_key);
            self.returned_borrow_keyed_map_known_occupied
                .insert(reference_origin.storage_key.clone());
            self.record_returned_borrow_storage_mutation_barrier_for_key(
                reference_origin.storage_key.clone(),
                pending.span,
                pending.location,
                "entry_value_assignment",
            );
            self.push_persisted_returned_borrow(
                pending.origin,
                reference_origin.storage_type_name.clone(),
                pending.span,
                pending.location,
                Some(reference_origin.storage_key.clone()),
            );
        }
        self.pending_returned_borrow_entry_value_assignments = remaining;
    }

    fn record_returned_borrow_keyed_map_entry_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        if !destination.projection.is_empty() {
            return;
        }
        let origin = match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                self.returned_borrow_keyed_map_entry_use_origin_from_operand_at(operand, location)
            }
            Rvalue::Ref(_, _, source_place) => self
                .returned_borrow_keyed_map_entry_use_origin_from_place_at(source_place, location),
            _ => None,
        };
        if let Some(origin) = origin {
            self.returned_borrow_keyed_map_entry_origins
                .insert(destination.local, origin);
        } else {
            self.returned_borrow_keyed_map_entry_origins
                .remove(&destination.local);
        }
    }

    fn returned_borrow_keyed_map_entry_origin_from_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) -> Option<KeyedMapEntryOrigin> {
        let method = method_name(callee_def_path)?;
        if method == "and_modify" {
            return args.first().and_then(|arg| {
                self.returned_borrow_keyed_map_entry_origin_from_operand(&arg.node)
            });
        }
        if method == "insert_entry" {
            return args
                .first()
                .and_then(|arg| {
                    self.returned_borrow_keyed_map_entry_use_origin_from_operand_at(
                        &arg.node, location,
                    )
                })
                .map(|mut origin| {
                    origin.occupancy = KeyedMapEntryOccupancy::KnownOccupied;
                    origin.projection_kind = None;
                    origin.projection_order_key = None;
                    origin
                });
        }
        if method != "entry" {
            return None;
        }
        let first_arg = args.first()?;
        let storage_type_name = first_arg
            .node
            .ty(&self.body.local_decls, self.tcx)
            .to_string();
        if !returned_borrow_keyed_map_storage_type(&storage_type_name) {
            return None;
        }
        let storage_key = first_arg
            .node
            .place()
            .and_then(|place| self.returned_borrow_storage_key(&place))?;
        self.record_keyed_map_key_contract_gap_if_needed(
            callee_def_path,
            args,
            &storage_type_name,
            span,
            location,
            "key_contract",
        );
        let key = returned_borrow_keyed_map_argument_key(
            args,
            &self.stable_constant_origins,
            &self.scoped_key_origins,
            &self.dynamic_key_generations,
            &self.owner_def_path,
        );
        let occupancy = self.keyed_map_entry_occupancy(&storage_key, key.as_deref());
        Some(KeyedMapEntryOrigin {
            storage_key,
            storage_type_name,
            key,
            occupancy,
            entry_site_id: format!("{}:{location:?}:entry", self.owner_def_path),
            projection_kind: None,
            projection_order_key: None,
        })
    }

    fn keyed_map_entry_occupancy(
        &self,
        storage_key: &str,
        key: Option<&str>,
    ) -> KeyedMapEntryOccupancy {
        let Some(key) = key else {
            return KeyedMapEntryOccupancy::Unknown;
        };
        let keyed_storage_key = keyed_map_returned_borrow_storage_key(storage_key, key);
        if self
            .returned_borrow_keyed_map_known_occupied
            .contains(&keyed_storage_key)
            || self
                .returned_borrow_storage_origins
                .contains_key(&keyed_storage_key)
        {
            KeyedMapEntryOccupancy::KnownOccupied
        } else if self
            .returned_borrow_keyed_map_known_empty
            .contains(storage_key)
        {
            KeyedMapEntryOccupancy::KnownVacant
        } else {
            KeyedMapEntryOccupancy::Unknown
        }
    }

    fn returned_borrow_keyed_map_entry_origin_from_operand(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<KeyedMapEntryOrigin> {
        let place = operand.place()?;
        self.returned_borrow_keyed_map_entry_origin_from_place(&place)
    }

    fn returned_borrow_keyed_map_entry_origin_from_place(
        &self,
        place: &Place<'tcx>,
    ) -> Option<KeyedMapEntryOrigin> {
        if place.projection.is_empty() {
            let origin = self
                .returned_borrow_keyed_map_entry_origins
                .get(&place.local)
                .cloned()?;
            if origin.occupancy == KeyedMapEntryOccupancy::Unknown
                && origin.projection_kind.is_some()
            {
                return None;
            }
            return Some(origin);
        }
        let origin = self
            .returned_borrow_keyed_map_entry_origins
            .get(&place.local)?;
        match keyed_map_entry_projection_kind(place) {
            Some(KeyedMapEntryProjectionKind::Occupied)
                if origin.occupancy == KeyedMapEntryOccupancy::KnownOccupied =>
            {
                Some(keyed_map_entry_origin_with_projection(
                    origin,
                    KeyedMapEntryProjectionKind::Occupied,
                    None,
                ))
            }
            Some(KeyedMapEntryProjectionKind::Vacant)
                if origin.occupancy == KeyedMapEntryOccupancy::KnownVacant =>
            {
                Some(keyed_map_entry_origin_with_projection(
                    origin,
                    KeyedMapEntryProjectionKind::Vacant,
                    None,
                ))
            }
            _ => None,
        }
    }

    fn returned_borrow_keyed_map_entry_use_origin_from_operand_at(
        &self,
        operand: &Operand<'tcx>,
        location: Location,
    ) -> Option<KeyedMapEntryOrigin> {
        let place = operand.place()?;
        self.returned_borrow_keyed_map_entry_use_origin_from_place_at(&place, location)
    }

    fn returned_borrow_keyed_map_entry_use_origin_from_place_at(
        &self,
        place: &Place<'tcx>,
        location: Location,
    ) -> Option<KeyedMapEntryOrigin> {
        if place.projection.is_empty() {
            return self
                .returned_borrow_keyed_map_entry_origins
                .get(&place.local)
                .cloned();
        }
        let origin = self
            .returned_borrow_keyed_map_entry_origins
            .get(&place.local)?;
        match keyed_map_entry_projection_kind(place) {
            Some(KeyedMapEntryProjectionKind::Occupied)
                if matches!(
                    origin.occupancy,
                    KeyedMapEntryOccupancy::KnownOccupied | KeyedMapEntryOccupancy::Unknown
                ) =>
            {
                Some(keyed_map_entry_origin_with_projection(
                    origin,
                    KeyedMapEntryProjectionKind::Occupied,
                    Some(mir_order_key(location)),
                ))
            }
            Some(KeyedMapEntryProjectionKind::Vacant)
                if matches!(
                    origin.occupancy,
                    KeyedMapEntryOccupancy::KnownVacant | KeyedMapEntryOccupancy::Unknown
                ) =>
            {
                Some(keyed_map_entry_origin_with_projection(
                    origin,
                    KeyedMapEntryProjectionKind::Vacant,
                    Some(mir_order_key(location)),
                ))
            }
            _ => None,
        }
    }

    fn observe_returned_borrow_keyed_map_entry_and_modify_barrier_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        if method_name(callee_def_path).as_deref() != Some("and_modify") {
            return;
        }
        let Some(entry_origin) = args
            .first()
            .and_then(|arg| self.returned_borrow_keyed_map_entry_origin_from_operand(&arg.node))
        else {
            return;
        };
        let replacement_origin = args.get(1).and_then(|arg| {
            callback_def_id_from_ty(arg.node.ty(&self.body.local_decls, self.tcx)).and_then(
                |def_id| {
                    summarize_returned_borrow_slot_assignment_callable(
                        self.tcx,
                        self.current_crate_name,
                        def_id,
                        &self.closure_returned_borrow_capture_summaries,
                    )
                },
            )
        });
        let mut storage_keys = BTreeSet::new();
        let mut storage_prefixes = BTreeSet::new();
        if let Some(key) = &entry_origin.key {
            let storage_key = keyed_map_returned_borrow_storage_key(&entry_origin.storage_key, key);
            self.remove_returned_borrow_origins_for_storage_key(&storage_key);
            storage_keys.insert(storage_key);
        } else {
            let prefix = keyed_map_returned_borrow_storage_prefix(&entry_origin.storage_key);
            self.remove_returned_borrow_origins_for_storage_prefix(&prefix);
            storage_prefixes.insert(prefix);
        }
        if let Some(origin) = replacement_origin {
            match entry_origin.occupancy {
                KeyedMapEntryOccupancy::Unknown => {
                    let keyed_storage_key = entry_origin.key.as_ref().map(|key| {
                        keyed_map_returned_borrow_storage_key(&entry_origin.storage_key, key)
                    });
                    let occupied_branch_origin = keyed_map_entry_origin_with_projection(
                        &entry_origin,
                        KeyedMapEntryProjectionKind::Occupied,
                        Some(mir_order_key(location)),
                    );
                    self.record_unknown_keyed_map_entry_branch_write(
                        "and_modify",
                        &occupied_branch_origin,
                        Some(origin),
                        keyed_storage_key.as_deref(),
                        span,
                        location,
                    );
                }
                KeyedMapEntryOccupancy::KnownOccupied | KeyedMapEntryOccupancy::KnownVacant => {}
            }
        }
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.returned_borrow_storage_mutation_barriers
            .push(ReturnedBorrowStorageMutationBarrier {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:entry_and_modify"),
                order_key: mir_order_key(location),
                storage_keys,
                storage_prefixes,
            });
    }

    fn observe_returned_borrow_keyed_map_entry_or_insert_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        if method_name(callee_def_path).as_deref() != Some("or_insert") {
            return;
        }
        let origin = args.get(1).and_then(|arg| {
            self.returned_borrow_origin_from_operand(&arg.node, arg.span, location)
        });
        self.persist_known_empty_keyed_entry_insert(callee_def_path, args, span, location, origin);
    }

    fn observe_returned_borrow_keyed_map_entry_or_insert_with_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        if !method_name(callee_def_path)
            .as_deref()
            .is_some_and(|method| matches!(method, "or_insert_with" | "or_insert_with_key"))
        {
            return;
        }
        let callback_def_id = args
            .get(1)
            .and_then(|arg| callback_def_id_from_ty(arg.node.ty(&self.body.local_decls, self.tcx)));
        let entry_origin_seen = args.first().is_some_and(|arg| {
            self.returned_borrow_keyed_map_entry_use_origin_from_operand_at(&arg.node, location)
                .is_some()
        });
        let unsupported_value_wrapper = callback_def_id.as_ref().is_some_and(|def_id| {
            returned_borrow_callable_returns_ref_container(self.tcx, *def_id)
        });
        let origin = (!unsupported_value_wrapper)
            .then(|| {
                callback_def_id.and_then(|def_id| {
                    summarize_returned_borrow_callable_with_captures(
                        self.tcx,
                        self.current_crate_name,
                        def_id,
                        &self.closure_returned_borrow_capture_summaries,
                    )
                })
            })
            .flatten();
        if entry_origin_seen && callback_def_id.is_some() && origin.is_none() {
            self.record_object_binding_gap_at_callsite(
                ObjectBindingGapKind::MappedValue,
                Some("entry_value_wrapper".to_owned()),
                span,
                location,
                "entry_value_wrapper",
            );
        }
        self.persist_known_empty_keyed_entry_insert(callee_def_path, args, span, location, origin);
    }

    fn observe_returned_borrow_keyed_map_entry_insert_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: Option<&Place<'tcx>>,
        span: Span,
        location: Location,
    ) {
        let Some(method) = method_name(callee_def_path) else {
            return;
        };
        if !matches!(method.as_str(), "insert_entry" | "insert") {
            return;
        }
        let Some(entry_origin) = args.first().and_then(|arg| {
            self.returned_borrow_keyed_map_entry_use_origin_from_operand_at(&arg.node, location)
        }) else {
            return;
        };

        let keyed_storage_key = entry_origin
            .key
            .as_ref()
            .map(|key| keyed_map_returned_borrow_storage_key(&entry_origin.storage_key, key));
        let old_origin = if method == "insert" {
            keyed_storage_key
                .as_ref()
                .and_then(|storage_key| self.returned_borrow_storage_origins.get(storage_key))
                .and_then(|origins| {
                    unique_returned_borrow_origin_from_persisted_observations(origins)
                })
        } else {
            None
        };
        let new_origin = args.get(1).and_then(|arg| {
            self.returned_borrow_origin_from_operand(&arg.node, arg.span, location)
        });

        let mut storage_keys = BTreeSet::new();
        let mut storage_prefixes = BTreeSet::new();
        if let Some(storage_key) = &keyed_storage_key {
            self.remove_returned_borrow_origins_for_storage_key(storage_key);
            storage_keys.insert(storage_key.clone());
            self.returned_borrow_keyed_map_known_occupied
                .insert(storage_key.clone());
        } else {
            let prefix = keyed_map_returned_borrow_storage_prefix(&entry_origin.storage_key);
            self.remove_returned_borrow_origins_for_storage_prefix(&prefix);
            self.remove_keyed_map_known_occupied_for_storage_prefix(&prefix);
            storage_prefixes.insert(prefix);
        }
        self.returned_borrow_keyed_map_known_empty
            .remove(&entry_origin.storage_key);

        let unknown_branch_handled = self.record_unknown_keyed_map_entry_branch_write(
            &method,
            &entry_origin,
            new_origin.clone(),
            keyed_storage_key.as_deref(),
            span,
            location,
        );

        if let Some(destination) = destination
            && method == "insert"
            && destination.projection.is_empty()
            && ty_contains_ref(destination.ty(&self.body.local_decls, self.tcx).ty)
            && let Some(origin) = old_origin
        {
            self.returned_borrow_origins
                .insert(destination.local, Some(origin.clone()));
            let destination_type_name = destination
                .ty(&self.body.local_decls, self.tcx)
                .ty
                .to_string();
            let local_storage_key = self.returned_borrow_local_storage_key(destination.local);
            self.push_persisted_returned_borrow(
                origin,
                destination_type_name,
                span,
                location,
                Some(local_storage_key),
            );
        }

        if !unknown_branch_handled
            && let (Some(origin), Some(storage_key)) = (new_origin, keyed_storage_key)
        {
            self.push_persisted_returned_borrow(
                origin,
                entry_origin.storage_type_name,
                span,
                location,
                Some(storage_key),
            );
        }

        if storage_keys.is_empty() && storage_prefixes.is_empty() {
            return;
        }
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.returned_borrow_storage_mutation_barriers
            .push(ReturnedBorrowStorageMutationBarrier {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:entry_insert"),
                order_key: mir_order_key(location),
                storage_keys,
                storage_prefixes,
            });
    }

    fn record_unknown_keyed_map_entry_branch_write(
        &mut self,
        method: &str,
        entry_origin: &KeyedMapEntryOrigin,
        new_origin: Option<ReturnedBorrowOrigin>,
        keyed_storage_key: Option<&str>,
        span: Span,
        location: Location,
    ) -> bool {
        if entry_origin.occupancy != KeyedMapEntryOccupancy::Unknown {
            return false;
        }
        let Some(branch_kind) = entry_origin.projection_kind else {
            return false;
        };
        let Some(storage_key) = keyed_storage_key else {
            return true;
        };
        let branch_write_is_unconditional =
            self.keyed_map_entry_branch_write_is_unconditional(entry_origin, location);
        let branch_write = if matches!(
            (method, branch_kind),
            ("and_modify", KeyedMapEntryProjectionKind::Occupied)
                | ("or_insert", KeyedMapEntryProjectionKind::Vacant)
                | ("or_insert_with", KeyedMapEntryProjectionKind::Vacant)
                | ("or_insert_with_key", KeyedMapEntryProjectionKind::Vacant)
                | ("insert", KeyedMapEntryProjectionKind::Occupied)
                | ("insert", KeyedMapEntryProjectionKind::Vacant)
                | ("insert_entry", KeyedMapEntryProjectionKind::Vacant)
        ) && branch_write_is_unconditional
        {
            new_origin
                .map(KeyedMapEntryBranchWrite::Returned)
                .unwrap_or(KeyedMapEntryBranchWrite::Blocked)
        } else {
            KeyedMapEntryBranchWrite::Blocked
        };

        let branch_key = keyed_map_entry_branch_tracking_key(entry_origin, storage_key);
        let writes = self
            .returned_borrow_keyed_map_entry_branch_writes
            .entry(branch_key)
            .or_insert_with(|| ReturnedBorrowKeyedMapEntryBranchWrites {
                storage_key: storage_key.to_owned(),
                storage_type_name: entry_origin.storage_type_name.clone(),
                occupied: KeyedMapEntryBranchWrite::Unseen,
                vacant: KeyedMapEntryBranchWrite::Unseen,
                merged: false,
            });
        match branch_kind {
            KeyedMapEntryProjectionKind::Occupied => {
                merge_keyed_map_entry_branch_write(&mut writes.occupied, branch_write.clone());
            }
            KeyedMapEntryProjectionKind::Vacant => {
                merge_keyed_map_entry_branch_write(&mut writes.vacant, branch_write.clone());
            }
        }

        let merge_origin = if writes.merged {
            None
        } else {
            match (&writes.occupied, &writes.vacant) {
                (
                    KeyedMapEntryBranchWrite::Returned(occupied),
                    KeyedMapEntryBranchWrite::Returned(vacant),
                ) if occupied == vacant => {
                    writes.merged = true;
                    Some((
                        occupied.clone(),
                        writes.storage_type_name.clone(),
                        writes.storage_key.clone(),
                    ))
                }
                _ => None,
            }
        };
        if let Some((origin, storage_type_name, storage_key)) = merge_origin {
            self.push_persisted_returned_borrow(
                origin,
                storage_type_name,
                span,
                location,
                Some(storage_key),
            );
        }
        let split_branch_key = storage_key.to_owned();
        let split_writes = self
            .returned_borrow_keyed_map_split_entry_branch_writes
            .entry(split_branch_key)
            .or_insert_with(|| ReturnedBorrowKeyedMapSplitEntryBranchWrites {
                storage_key: storage_key.to_owned(),
                storage_type_name: entry_origin.storage_type_name.clone(),
                occupied_entry_site_id: None,
                vacant_entry_site_id: None,
                occupied: KeyedMapEntryBranchWrite::Unseen,
                vacant: KeyedMapEntryBranchWrite::Unseen,
                merged: false,
            });
        match branch_kind {
            KeyedMapEntryProjectionKind::Occupied => {
                let incoming = if split_writes
                    .occupied_entry_site_id
                    .as_ref()
                    .is_some_and(|site| site != &entry_origin.entry_site_id)
                {
                    KeyedMapEntryBranchWrite::Ambiguous
                } else {
                    split_writes.occupied_entry_site_id = Some(entry_origin.entry_site_id.clone());
                    branch_write
                };
                merge_keyed_map_entry_branch_write(&mut split_writes.occupied, incoming);
            }
            KeyedMapEntryProjectionKind::Vacant => {
                let incoming = if split_writes
                    .vacant_entry_site_id
                    .as_ref()
                    .is_some_and(|site| site != &entry_origin.entry_site_id)
                {
                    KeyedMapEntryBranchWrite::Ambiguous
                } else {
                    split_writes.vacant_entry_site_id = Some(entry_origin.entry_site_id.clone());
                    branch_write
                };
                merge_keyed_map_entry_branch_write(&mut split_writes.vacant, incoming);
            }
        }
        let split_merge_origin = if split_writes.merged {
            None
        } else {
            match (
                &split_writes.occupied_entry_site_id,
                &split_writes.vacant_entry_site_id,
                &split_writes.occupied,
                &split_writes.vacant,
            ) {
                (
                    Some(occupied_site),
                    Some(vacant_site),
                    KeyedMapEntryBranchWrite::Returned(occupied),
                    KeyedMapEntryBranchWrite::Returned(vacant),
                ) if occupied_site != vacant_site && occupied == vacant => {
                    split_writes.merged = true;
                    Some((
                        occupied.clone(),
                        split_writes.storage_type_name.clone(),
                        split_writes.storage_key.clone(),
                    ))
                }
                _ => None,
            }
        };
        if let Some((origin, storage_type_name, storage_key)) = split_merge_origin {
            self.push_persisted_returned_borrow(
                origin,
                storage_type_name,
                span,
                location,
                Some(storage_key),
            );
        }
        true
    }

    fn keyed_map_entry_branch_write_is_unconditional(
        &self,
        entry_origin: &KeyedMapEntryOrigin,
        write_location: Location,
    ) -> bool {
        let Some(projection_order_key) = entry_origin.projection_order_key else {
            return false;
        };
        let write_order_key = mir_order_key(write_location);
        if projection_order_key.basic_block == write_order_key.basic_block {
            return projection_order_key.statement_index <= write_order_key.statement_index;
        }
        state_machine_write_postdominates_registration(
            self.body,
            projection_order_key.basic_block,
            write_order_key.basic_block,
        )
    }

    fn persist_known_empty_keyed_entry_insert(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
        origin: Option<ReturnedBorrowOrigin>,
    ) {
        let Some(entry_origin) = args
            .first()
            .and_then(|arg| self.returned_borrow_keyed_map_entry_origin_from_operand(&arg.node))
        else {
            return;
        };
        if !self
            .returned_borrow_keyed_map_known_empty
            .contains(&entry_origin.storage_key)
        {
            if entry_origin.occupancy == KeyedMapEntryOccupancy::Unknown {
                let keyed_storage_key = entry_origin.key.as_ref().map(|key| {
                    keyed_map_returned_borrow_storage_key(&entry_origin.storage_key, key)
                });
                let vacant_branch_origin = keyed_map_entry_origin_with_projection(
                    &entry_origin,
                    KeyedMapEntryProjectionKind::Vacant,
                    Some(mir_order_key(location)),
                );
                self.record_unknown_keyed_map_entry_branch_write(
                    method_name(callee_def_path)
                        .as_deref()
                        .unwrap_or("or_insert"),
                    &vacant_branch_origin,
                    origin,
                    keyed_storage_key.as_deref(),
                    span,
                    location,
                );
            }
            return;
        }
        let Some(key) = &entry_origin.key else {
            self.returned_borrow_keyed_map_known_empty
                .remove(&entry_origin.storage_key);
            return;
        };
        if let Some(origin) = origin {
            let storage_key = keyed_map_returned_borrow_storage_key(&entry_origin.storage_key, key);
            self.returned_borrow_keyed_map_known_occupied
                .insert(storage_key.clone());
            self.push_persisted_returned_borrow(
                origin,
                entry_origin.storage_type_name,
                span,
                location,
                Some(storage_key),
            );
        } else {
            let storage_key = keyed_map_returned_borrow_storage_key(&entry_origin.storage_key, key);
            self.returned_borrow_keyed_map_known_occupied
                .insert(storage_key);
        }
        self.returned_borrow_keyed_map_known_empty
            .remove(&entry_origin.storage_key);
    }

    fn bump_dynamic_key_generation(&mut self, local: Local) {
        let generation = self.dynamic_key_generations.entry(local).or_insert(0);
        *generation = generation.saturating_add(1);
    }

    fn record_raw_pointer_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        let Some(key) = raw_pointer_place_key(destination) else {
            return;
        };
        let openssl_ex_data_origin = self.openssl_ex_data_get_origin_from_rvalue(rvalue);
        if !matches!(
            destination.ty(&self.body.local_decls, self.tcx).ty.kind(),
            ty::RawPtr(..)
        ) {
            self.record_raw_pointer_aggregate_field_assignment(destination, rvalue, location);
            self.record_raw_pointer_place_alias(destination, rvalue, location);
            update_optional_origin(
                &mut self.openssl_ex_data_get_origins,
                key,
                openssl_ex_data_origin,
            );
            return;
        }
        match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                let previous_user_data = self.previous_user_data_from_operand(operand);
                if let Some(user_data) = self.raw_pointer_reference_from_operand(operand) {
                    self.record_raw_pointer_destination(destination, user_data);
                } else if self
                    .record_raw_pointer_unique_owner_storage_pointer_alias(destination, operand)
                {
                } else {
                    self.raw_pointer_origins.insert(key.clone(), None);
                }
                update_optional_origin(
                    &mut self.previous_user_data_origins,
                    key,
                    previous_user_data,
                );
                update_optional_origin(
                    &mut self.openssl_ex_data_get_origins,
                    raw_pointer_place_key(destination)
                        .expect("destination key was already computed"),
                    openssl_ex_data_origin,
                );
            }
            _ => {
                self.raw_pointer_origins.insert(key.clone(), None);
                self.previous_user_data_origins.insert(key, None);
                if let Some(destination_key) = raw_pointer_place_key(destination) {
                    self.openssl_ex_data_get_origins
                        .insert(destination_key, None);
                }
            }
        }
    }

    fn record_raw_pointer_unique_owner_storage_pointer_alias(
        &mut self,
        destination: &Place<'tcx>,
        source: &Operand<'tcx>,
    ) -> bool {
        let Some(destination_key) = raw_pointer_place_key(destination) else {
            return false;
        };
        if !destination_key.projection.is_empty() {
            return false;
        }
        let Some(source_place) = source.place() else {
            return false;
        };
        let Some(source_key) =
            raw_pointer_unique_owner_storage_pointer_key_from_place(self.body, &source_place)
        else {
            return false;
        };
        let mappings = self
            .raw_pointer_origins
            .iter()
            .filter_map(|(key, origin)| {
                if key.local != source_key.local
                    || !key.projection.starts_with(&source_key.projection)
                {
                    return None;
                }
                let projection = key.projection[source_key.projection.len()..].to_vec();
                Some((
                    RawPointerPlaceKey {
                        local: destination_key.local,
                        projection,
                    },
                    origin.clone(),
                ))
            })
            .collect::<Vec<_>>();
        if mappings.is_empty() {
            return false;
        }
        self.forget_raw_pointer_origin_prefix(&destination_key);
        for (key, origin) in mappings {
            self.record_raw_pointer_origin_key(key, origin);
        }
        true
    }

    fn record_raw_pointer_aggregate_field_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        let Rvalue::Aggregate(kind, operands) = rvalue else {
            return;
        };
        if !raw_pointer_aggregate_kind_tracks_fields(kind) {
            return;
        }
        let Some(destination_key) = raw_pointer_place_key(destination) else {
            return;
        };
        let new_mappings = operands
            .iter()
            .enumerate()
            .flat_map(|(field_index, operand)| {
                self.raw_pointer_aggregate_operand_field_origins(
                    &destination_key,
                    field_index,
                    operand,
                )
            })
            .collect::<Vec<_>>();
        self.record_raw_pointer_aggregate_reassignment_barriers_if_needed(
            &destination_key,
            &new_mappings,
            self.assignment_span(location),
            location,
        );
        self.forget_raw_pointer_origin_prefix(&destination_key);
        for (field_key, origin) in new_mappings {
            self.record_raw_pointer_origin_key(field_key, origin);
        }
    }

    fn record_raw_pointer_field_reassignment_barrier_if_needed(
        &mut self,
        key: &RawPointerPlaceKey,
        incoming: Option<&RawPointerReference>,
        field_path: &str,
        span: Span,
        location: Location,
        location_suffix: &str,
    ) {
        let Some(previous) = self.raw_pointer_origins.get(key).cloned().flatten() else {
            return;
        };
        if incoming.is_some_and(|incoming| incoming == &previous) {
            return;
        }
        let gap_kind = if incoming.is_some() {
            ObjectBindingGapKind::ReassignmentBarrier
        } else {
            ObjectBindingGapKind::MutationBarrier
        };
        self.record_object_binding_gap_with_bindings(
            gap_kind,
            Some("raw_pointer_field_assignment".to_owned()),
            span,
            location,
            location_suffix,
            Some(field_path.to_owned()),
            None,
        );
    }

    fn record_raw_pointer_aggregate_reassignment_barriers_if_needed(
        &mut self,
        destination_key: &RawPointerPlaceKey,
        new_mappings: &[(RawPointerPlaceKey, Option<RawPointerReference>)],
        span: Span,
        location: Location,
    ) {
        let previous_mappings = self
            .raw_pointer_origins
            .iter()
            .filter_map(|(key, origin)| {
                if key.local == destination_key.local
                    && key.projection.starts_with(&destination_key.projection)
                {
                    Some((key.clone(), origin.clone()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if previous_mappings.is_empty() {
            return;
        }
        let new_by_key = new_mappings
            .iter()
            .cloned()
            .collect::<BTreeMap<RawPointerPlaceKey, Option<RawPointerReference>>>();
        for (key, previous) in previous_mappings {
            let Some(previous) = previous else {
                continue;
            };
            let incoming = new_by_key.get(&key).cloned().flatten();
            if incoming
                .as_ref()
                .is_some_and(|incoming| incoming == &previous)
            {
                continue;
            }
            let Some(field_path) = raw_pointer_field_path_from_key(&key) else {
                continue;
            };
            let gap_kind = if incoming.is_some() {
                ObjectBindingGapKind::ReassignmentBarrier
            } else {
                ObjectBindingGapKind::MutationBarrier
            };
            self.record_object_binding_gap_with_bindings(
                gap_kind,
                Some("raw_pointer_aggregate_assignment".to_owned()),
                span,
                location,
                "aggregate_assignment",
                Some(field_path),
                None,
            );
        }
    }

    fn forget_raw_pointer_origin_prefix(&mut self, prefix: &RawPointerPlaceKey) {
        self.raw_pointer_origins.retain(|key, _| {
            key.local != prefix.local || !key.projection.starts_with(&prefix.projection)
        });
    }

    fn record_raw_pointer_origin_key(
        &mut self,
        key: RawPointerPlaceKey,
        origin: Option<RawPointerReference>,
    ) {
        match self.raw_pointer_origins.get_mut(&key) {
            Some(existing)
                if existing
                    .as_ref()
                    .zip(origin.as_ref())
                    .is_some_and(|(left, right)| left != right) =>
            {
                *existing = None;
            }
            Some(existing) if existing.is_none() || origin.is_none() => {
                *existing = None;
            }
            Some(_) => {}
            None => {
                self.raw_pointer_origins.insert(key, origin);
            }
        }
    }

    fn record_openssl_ex_data_slot_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
    ) {
        let Some(destination_key) = raw_pointer_place_key(destination) else {
            return;
        };
        if !matches!(
            destination.ty(&self.body.local_decls, self.tcx).ty.kind(),
            ty::Int(_) | ty::Uint(_)
        ) {
            self.record_openssl_ex_data_slot_aggregate_assignment(&destination_key, rvalue);
            return;
        }
        let slot_key = self.openssl_ex_data_slot_key_from_rvalue(rvalue);
        update_optional_origin(
            &mut self.openssl_ex_data_slot_origins,
            destination_key,
            slot_key,
        );
    }

    fn record_openssl_ex_data_handle_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
    ) {
        let Some(destination_key) = raw_pointer_place_key(destination) else {
            return;
        };
        if !matches!(
            destination.ty(&self.body.local_decls, self.tcx).ty.kind(),
            ty::RawPtr(..)
        ) {
            self.record_openssl_ex_data_handle_aggregate_assignment(&destination_key, rvalue);
            return;
        }
        let handle_key = match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => self
                .openssl_ex_data_exact_handle_key_from_operand(operand)
                .flatten(),
            _ => None,
        };
        update_optional_origin(
            &mut self.openssl_ex_data_handle_origins,
            destination_key,
            handle_key,
        );
    }

    fn record_openssl_ex_data_handle_aggregate_assignment(
        &mut self,
        destination_key: &RawPointerPlaceKey,
        rvalue: &Rvalue<'tcx>,
    ) {
        match rvalue {
            Rvalue::Aggregate(kind, operands) if raw_pointer_aggregate_kind_tracks_fields(kind) => {
                let mappings = operands
                    .iter()
                    .enumerate()
                    .flat_map(|(field_index, operand)| {
                        self.openssl_ex_data_handle_aggregate_operand_origins(
                            destination_key,
                            field_index,
                            operand,
                        )
                    })
                    .collect::<Vec<_>>();
                forget_openssl_ex_data_string_origin_prefix(
                    &mut self.openssl_ex_data_handle_origins,
                    destination_key,
                );
                for (key, value) in mappings {
                    update_optional_origin(&mut self.openssl_ex_data_handle_origins, key, value);
                }
            }
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                copy_openssl_ex_data_string_origin_alias(
                    destination_key,
                    operand,
                    &mut self.openssl_ex_data_handle_origins,
                );
            }
            _ => {
                forget_openssl_ex_data_string_origin_prefix(
                    &mut self.openssl_ex_data_handle_origins,
                    destination_key,
                );
            }
        }
    }

    fn openssl_ex_data_handle_aggregate_operand_origins(
        &self,
        destination_key: &RawPointerPlaceKey,
        field_index: usize,
        operand: &Operand<'tcx>,
    ) -> Vec<(RawPointerPlaceKey, Option<String>)> {
        let mut field_prefix = destination_key.clone();
        field_prefix.projection.push(format!("field:{field_index}"));
        if matches!(
            operand.ty(&self.body.local_decls, self.tcx).kind(),
            ty::RawPtr(..)
        ) {
            return vec![(
                field_prefix,
                self.openssl_ex_data_exact_handle_key_from_operand(operand)
                    .flatten(),
            )];
        }
        openssl_ex_data_string_origin_prefixed_aliases(
            &self.openssl_ex_data_handle_origins,
            &field_prefix,
            operand,
        )
    }

    fn record_openssl_ex_data_slot_aggregate_assignment(
        &mut self,
        destination_key: &RawPointerPlaceKey,
        rvalue: &Rvalue<'tcx>,
    ) {
        match rvalue {
            Rvalue::Aggregate(kind, operands) if raw_pointer_aggregate_kind_tracks_fields(kind) => {
                let mappings = operands
                    .iter()
                    .enumerate()
                    .flat_map(|(field_index, operand)| {
                        self.openssl_ex_data_slot_aggregate_operand_origins(
                            destination_key,
                            field_index,
                            operand,
                        )
                    })
                    .collect::<Vec<_>>();
                forget_openssl_ex_data_string_origin_prefix(
                    &mut self.openssl_ex_data_slot_origins,
                    destination_key,
                );
                for (key, value) in mappings {
                    update_optional_origin(&mut self.openssl_ex_data_slot_origins, key, value);
                }
            }
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                copy_openssl_ex_data_string_origin_alias(
                    destination_key,
                    operand,
                    &mut self.openssl_ex_data_slot_origins,
                );
            }
            _ => {
                forget_openssl_ex_data_string_origin_prefix(
                    &mut self.openssl_ex_data_slot_origins,
                    destination_key,
                );
            }
        }
    }

    fn openssl_ex_data_slot_aggregate_operand_origins(
        &self,
        destination_key: &RawPointerPlaceKey,
        field_index: usize,
        operand: &Operand<'tcx>,
    ) -> Vec<(RawPointerPlaceKey, Option<String>)> {
        let mut field_prefix = destination_key.clone();
        field_prefix.projection.push(format!("field:{field_index}"));
        if matches!(
            operand.ty(&self.body.local_decls, self.tcx).kind(),
            ty::Int(_) | ty::Uint(_)
        ) {
            return vec![(
                field_prefix,
                self.openssl_ex_data_slot_key_from_operand(operand),
            )];
        }
        openssl_ex_data_string_origin_prefixed_aliases(
            &self.openssl_ex_data_slot_origins,
            &field_prefix,
            operand,
        )
    }

    fn openssl_ex_data_exact_handle_key_from_operand(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<Option<String>> {
        let place = operand.place()?;
        if !matches!(
            place.ty(&self.body.local_decls, self.tcx).ty.kind(),
            ty::RawPtr(..)
        ) {
            return None;
        }
        if let Some(place_key) = raw_pointer_place_key(&place)
            && let Some(origin) = self.openssl_ex_data_handle_origins.get(&place_key)
        {
            return Some(origin.clone());
        }
        self.openssl_ex_data_stable_handle_key_from_place(&place)
            .map(Some)
    }

    fn openssl_ex_data_stable_handle_key_from_place(&self, place: &Place<'tcx>) -> Option<String> {
        let arg_index = place.local.index().checked_sub(1)?;
        if arg_index >= self.body.arg_count {
            return None;
        }
        let projection = raw_pointer_arg_projection_key(self.body, place)?;
        let projection = if projection.is_empty() {
            "root".to_owned()
        } else {
            projection.join(".")
        };
        Some(format!("arg:{arg_index}:{projection}"))
    }

    fn record_raw_pointer_place_alias(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        let Some(destination_key) = raw_pointer_place_key(destination) else {
            return;
        };
        let Some(source_place) = (match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => operand.place(),
            _ => None,
        }) else {
            return;
        };
        let Some(source_key) = raw_pointer_place_key(&source_place) else {
            return;
        };
        let aliases = self
            .raw_pointer_origins
            .iter()
            .filter_map(|(key, value)| {
                if key.local != source_key.local
                    || !key.projection.starts_with(&source_key.projection)
                {
                    return None;
                }
                let mut projection = destination_key.projection.clone();
                projection.extend_from_slice(&key.projection[source_key.projection.len()..]);
                Some((
                    RawPointerPlaceKey {
                        local: destination_key.local,
                        projection,
                    },
                    value.clone(),
                ))
            })
            .collect::<Vec<_>>();
        self.record_raw_pointer_alias_reassignment_barriers_if_needed(
            &destination_key,
            &aliases,
            self.assignment_span(location),
            location,
        );
        for (key, value) in aliases {
            match self.raw_pointer_origins.get_mut(&key) {
                Some(existing)
                    if existing
                        .as_ref()
                        .zip(value.as_ref())
                        .is_some_and(|(left, right)| left != right) =>
                {
                    *existing = None;
                }
                Some(existing) if existing.is_none() || value.is_none() => {
                    *existing = None;
                }
                Some(_) => {}
                None => {
                    self.raw_pointer_origins.insert(key, value);
                }
            }
        }
    }

    fn record_raw_pointer_alias_reassignment_barriers_if_needed(
        &mut self,
        destination_key: &RawPointerPlaceKey,
        aliases: &[(RawPointerPlaceKey, Option<RawPointerReference>)],
        span: Span,
        location: Location,
    ) {
        if aliases.is_empty() {
            return;
        }
        let previous_mappings = self
            .raw_pointer_origins
            .iter()
            .filter_map(|(key, origin)| {
                if key.local == destination_key.local
                    && key.projection.starts_with(&destination_key.projection)
                {
                    Some((key.clone(), origin.clone()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let alias_by_key = aliases
            .iter()
            .cloned()
            .collect::<BTreeMap<RawPointerPlaceKey, Option<RawPointerReference>>>();
        for (key, previous) in previous_mappings {
            let Some(previous) = previous else {
                continue;
            };
            let incoming = alias_by_key.get(&key).cloned().flatten();
            if incoming
                .as_ref()
                .is_some_and(|incoming| incoming == &previous)
            {
                continue;
            }
            let Some(field_path) = raw_pointer_field_path_from_key(&key) else {
                continue;
            };
            let gap_kind = if incoming.is_some() {
                ObjectBindingGapKind::ReassignmentBarrier
            } else {
                ObjectBindingGapKind::MutationBarrier
            };
            self.record_object_binding_gap_with_bindings(
                gap_kind,
                Some("raw_pointer_place_alias".to_owned()),
                span,
                location,
                "place_alias",
                Some(field_path),
                None,
            );
        }
    }

    fn record_raw_pointer_borrow_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
    ) {
        if !destination.projection.is_empty()
            || !matches!(
                destination.ty(&self.body.local_decls, self.tcx).ty.kind(),
                ty::Ref(..)
            )
        {
            return;
        }
        let borrowed_key = match rvalue {
            Rvalue::Ref(_, _, source_place) => raw_pointer_place_key(source_place),
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                let source_place = operand.place();
                source_place.and_then(|place| {
                    if !place.projection.is_empty()
                        || !matches!(
                            place.ty(&self.body.local_decls, self.tcx).ty.kind(),
                            ty::Ref(..)
                        )
                    {
                        return None;
                    }
                    self.raw_pointer_borrow_origins
                        .get(&place.local)
                        .cloned()
                        .flatten()
                })
            }
            _ => None,
        };
        match self.raw_pointer_borrow_origins.get_mut(&destination.local) {
            Some(existing)
                if existing
                    .as_ref()
                    .zip(borrowed_key.as_ref())
                    .is_some_and(|(left, right)| left != right) =>
            {
                *existing = None;
            }
            Some(existing) if existing.is_none() || borrowed_key.is_none() => {
                *existing = None;
            }
            Some(_) => {}
            None => {
                self.raw_pointer_borrow_origins
                    .insert(destination.local, borrowed_key);
            }
        }
    }

    fn record_fn_pointer_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        let Some(destination_key) = fn_pointer_place_key(self.body, destination) else {
            return;
        };
        let destination_ty = destination.ty(&self.body.local_decls, self.tcx).ty;
        if is_fn_pointer_ty(destination_ty) {
            let fn_def_id = self.fn_def_from_rvalue(rvalue);
            let source_key = self.fn_pointer_source_key_from_rvalue(rvalue);
            update_optional_origin(
                &mut self.fn_pointer_origins,
                destination_key.clone(),
                fn_def_id,
            );
            update_optional_origin(
                &mut self.fn_pointer_source_origins,
                destination_key,
                source_key,
            );
            return;
        }
        if is_option_fn_pointer_ty(destination_ty) {
            let fn_def_id = self.option_fn_def_from_rvalue(rvalue);
            let source_key = self.option_fn_pointer_source_key_from_rvalue(rvalue);
            self.record_option_fn_pointer_release_origin(destination_key.clone(), rvalue);
            self.record_hook_release_field_write(&destination_key, location);
            update_optional_origin(
                &mut self.option_fn_pointer_origins,
                destination_key.clone(),
                fn_def_id,
            );
            update_optional_origin(
                &mut self.option_fn_pointer_source_origins,
                destination_key,
                source_key,
            );
            return;
        }
        if let Rvalue::Aggregate(kind, operands) = rvalue
            && matches!(**kind, AggregateKind::Adt(..))
        {
            for (field_index, operand) in operands.iter().enumerate() {
                let mut field_key = destination_key.clone();
                field_key.projection.push(format!("field:{field_index}"));
                let field_ty = operand.ty(&self.body.local_decls, self.tcx);
                if is_fn_pointer_ty(field_ty) {
                    let origin = self.fn_def_from_operand(operand);
                    let source_key = self.fn_pointer_source_key_from_operand(operand);
                    update_optional_origin(&mut self.fn_pointer_origins, field_key.clone(), origin);
                    update_optional_origin(
                        &mut self.fn_pointer_source_origins,
                        field_key,
                        source_key,
                    );
                } else if is_option_fn_pointer_ty(field_ty) {
                    let origin = self.option_fn_def_from_operand(operand);
                    let source_key = self.option_fn_pointer_source_key_from_operand(operand);
                    self.record_option_fn_pointer_release_origin_from_operand(
                        field_key.clone(),
                        operand,
                    );
                    update_optional_origin(
                        &mut self.option_fn_pointer_origins,
                        field_key.clone(),
                        origin,
                    );
                    update_optional_origin(
                        &mut self.option_fn_pointer_source_origins,
                        field_key,
                        source_key,
                    );
                }
            }
        }
    }

    fn observe_hook_state_previous_release_call(
        &mut self,
        func: &Operand<'tcx>,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        let Some(field_key) = self.fn_pointer_source_key_from_operand(func) else {
            return;
        };
        if !is_receiver_field_key(self.body, &field_key) {
            return;
        }
        let Some(previous_user_data) = args
            .first()
            .and_then(|arg| self.previous_user_data_from_operand(&arg.node))
        else {
            return;
        };
        self.hook_previous_release_candidates
            .push(HookPreviousReleaseCandidate {
                hook_family: previous_user_data.hook_family,
                field_key,
                span,
                location,
                basic_block: location.block.index(),
            });
    }

    fn infer_hook_state_machine_release_path_proofs(&mut self) {
        let registrations = self.observations.registrations.clone();
        let mut object_flows = Vec::new();
        for registration in registrations.iter().filter(|registration| {
            registration.role == bw_model::RegistrationRole::Register
                && registration.user_data.is_some()
        }) {
            let Some(user_data) = registration.user_data.clone() else {
                continue;
            };
            let Some(hook_family) = hook_family_from_api_id(&registration.api_id) else {
                continue;
            };
            for field_write in self.hook_release_field_writes.iter().filter(|write| {
                state_machine_write_postdominates_registration(
                    self.body,
                    registration.basic_block,
                    write.basic_block,
                )
            }) {
                let Some(previous_release) =
                    self.hook_previous_release_candidates
                        .iter()
                        .find(|candidate| {
                            candidate.hook_family == hook_family
                                && candidate.field_key == field_write.field_key
                        })
                else {
                    continue;
                };
                let (Ok(source_path), Ok(stable_span)) = (
                    source_path(self.tcx, previous_release.span),
                    stable_span(self.tcx, previous_release.span),
                ) else {
                    continue;
                };
                let release = RawPointerTransferObservation {
                    owner_def_path: self.owner_def_path.clone(),
                    source_path,
                    span: stable_span,
                    mir_location: format!(
                        "{:?}:state_machine_previous_user_data",
                        previous_release.location
                    ),
                    basic_block: previous_release.basic_block,
                    statement_index: previous_release.location.statement_index,
                    kind: RawPointerTransferKind::FromRaw,
                    user_data: user_data.clone(),
                };
                object_flows.extend(self.hook_state_machine_release_slot_object_flows(
                    registration,
                    &user_data,
                    hook_family,
                    field_write,
                    previous_release,
                    &release,
                ));
                if self.observations.release_path_proofs.iter().any(|proof| {
                    proof.registration.mir_location == registration.mir_location
                        && proof.release.mir_location == release.mir_location
                        && proof.release.user_data == release.user_data
                }) {
                    continue;
                }
                self.observations
                    .raw_pointer_transfers
                    .push(release.clone());
                self.observations
                    .release_path_proofs
                    .push(ReleasePathProofObservation {
                        owner_def_path: registration.owner_def_path.clone(),
                        source_path: release.source_path.clone(),
                        span: release.span.clone(),
                        mir_location: release.mir_location.clone(),
                        registration: registration.clone(),
                        release,
                    });
            }
        }
        self.observations.object_flows.extend(object_flows);
    }

    fn hook_state_machine_release_slot_object_flows(
        &self,
        registration: &RegistrationObservation,
        user_data: &RawPointerReference,
        hook_family: &str,
        field_write: &HookReleaseFieldWrite,
        previous_release: &HookPreviousReleaseCandidate,
        release: &RawPointerTransferObservation,
    ) -> Vec<ObjectFlowObservation> {
        let Some(field_path) = hook_release_slot_field_path(hook_family, &field_write.field_key)
        else {
            return Vec::new();
        };
        let Some(store_site) = hook_release_slot_static_site(
            self.tcx,
            &self.owner_def_path,
            field_write.span,
            field_write.location,
            "state_machine_release_slot_store",
            hook_family,
        ) else {
            return Vec::new();
        };
        let Some(load_site) = hook_release_slot_static_site(
            self.tcx,
            &self.owner_def_path,
            previous_release.span,
            previous_release.location,
            "state_machine_release_slot_load",
            hook_family,
        ) else {
            return Vec::new();
        };
        let store_source_path = object_flow_endpoint_source_path(&store_site).to_path_buf();
        let store_span = object_flow_endpoint_span(&store_site).to_owned();
        let load_source_path = object_flow_endpoint_source_path(&load_site).to_path_buf();
        let load_span = object_flow_endpoint_span(&load_site).to_owned();
        vec![
            object_flow_observation(
                &self.owner_def_path,
                &store_source_path,
                &store_span,
                &format!(
                    "{:?}:state_machine_release_slot_store:{field_path}",
                    field_write.location
                ),
                &registration.api_id,
                ObjectFlowEndpointObservation::UserData(user_data.clone()),
                ObjectFlowObjectKind::UserData,
                store_site,
                ObjectFlowObjectKind::StaticSite,
                ObjectFlowKind::FieldStore,
                Some(field_path.clone()),
                Some(hook_family.to_owned()),
            ),
            object_flow_observation(
                &self.owner_def_path,
                &load_source_path,
                &load_span,
                &format!(
                    "{:?}:state_machine_release_slot_load:{field_path}",
                    previous_release.location
                ),
                &registration.api_id,
                load_site,
                ObjectFlowObjectKind::StaticSite,
                ObjectFlowEndpointObservation::RawPointerTransferSite(release.clone()),
                ObjectFlowObjectKind::StaticSite,
                ObjectFlowKind::FieldLoad,
                Some(field_path),
                Some(hook_family.to_owned()),
            ),
        ]
    }

    fn record_option_fn_pointer_release_origin(
        &mut self,
        destination_key: RawPointerPlaceKey,
        rvalue: &Rvalue<'tcx>,
    ) {
        let origin = match self.option_fn_release_origin_from_rvalue(rvalue) {
            OptionFnReleaseAssignment::NoneValue => return,
            OptionFnReleaseAssignment::Origin(origin) => origin,
        };
        self.option_fn_pointer_release_origins
            .entry(destination_key)
            .or_default()
            .merge(origin);
    }

    fn record_option_fn_pointer_release_origin_from_operand(
        &mut self,
        destination_key: RawPointerPlaceKey,
        operand: &Operand<'tcx>,
    ) {
        let Some(origin) = self.option_fn_release_origin_from_operand(operand) else {
            return;
        };
        self.option_fn_pointer_release_origins
            .entry(destination_key)
            .or_default()
            .merge(origin);
    }

    fn record_hook_release_field_write(
        &mut self,
        destination_key: &RawPointerPlaceKey,
        location: Location,
    ) {
        if !is_receiver_field_key(self.body, destination_key) {
            return;
        }
        let Some(origin) = self.option_fn_pointer_release_origins.get(destination_key) else {
            return;
        };
        if !origin.exact_release_endpoint() {
            return;
        }
        self.hook_release_field_writes.push(HookReleaseFieldWrite {
            field_key: destination_key.clone(),
            span: self.assignment_span(location),
            location,
            basic_block: location.block.index(),
        });
    }

    fn option_fn_release_origin_from_rvalue(
        &self,
        rvalue: &Rvalue<'tcx>,
    ) -> OptionFnReleaseAssignment {
        match rvalue {
            Rvalue::Aggregate(kind, operands) if matches!(**kind, AggregateKind::Adt(..)) => {
                if operands.is_empty() {
                    OptionFnReleaseAssignment::NoneValue
                } else if operands.len() == 1 {
                    let operand = operands.iter().next().expect("one operand must exist");
                    OptionFnReleaseAssignment::Origin(
                        self.option_fn_release_origin_from_operand(operand)
                            .unwrap_or_else(HookReleaseOptionOrigin::unknown_some),
                    )
                } else {
                    OptionFnReleaseAssignment::Origin(HookReleaseOptionOrigin::unknown_some())
                }
            }
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                OptionFnReleaseAssignment::Origin(
                    self.option_fn_release_origin_from_operand(operand)
                        .unwrap_or_else(HookReleaseOptionOrigin::unknown_some),
                )
            }
            _ => OptionFnReleaseAssignment::Origin(HookReleaseOptionOrigin::unknown_some()),
        }
    }

    fn option_fn_release_origin_from_operand(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<HookReleaseOptionOrigin> {
        let place = operand.place();
        if let Some(place) = place
            && let Some(key) = fn_pointer_place_key(self.body, &place)
            && let Some(origin) = self.option_fn_pointer_release_origins.get(&key)
        {
            return Some(origin.clone());
        }
        let fn_def_id = self
            .fn_def_from_operand(operand)
            .or_else(|| self.option_fn_def_from_operand(operand))?;
        Some(self.hook_release_origin_from_fn_def(fn_def_id))
    }

    fn hook_release_origin_from_fn_def(&self, fn_def_id: DefId) -> HookReleaseOptionOrigin {
        let Some(released_arg) = raw_pointer_release_arg_place_key(self.tcx, fn_def_id, false)
        else {
            return HookReleaseOptionOrigin::non_releasing_some();
        };
        if released_arg.arg_index != 0 || !released_arg.projection.is_empty() {
            return HookReleaseOptionOrigin::non_releasing_some();
        }
        HookReleaseOptionOrigin::release_endpoint(self.tcx.def_path_str(fn_def_id))
    }

    fn previous_user_data_from_operand(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<PreviousUserDataReturn> {
        let place = operand.place()?;
        let key = raw_pointer_place_key(&place)?;
        self.previous_user_data_origins.get(&key).cloned().flatten()
    }

    fn fn_pointer_source_key_from_rvalue(
        &self,
        rvalue: &Rvalue<'tcx>,
    ) -> Option<RawPointerPlaceKey> {
        match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                self.fn_pointer_source_key_from_operand(operand)
            }
            _ => None,
        }
    }

    fn option_fn_pointer_source_key_from_rvalue(
        &self,
        rvalue: &Rvalue<'tcx>,
    ) -> Option<RawPointerPlaceKey> {
        match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                self.option_fn_pointer_source_key_from_operand(operand)
            }
            _ => None,
        }
    }

    fn fn_pointer_source_key_from_operand(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<RawPointerPlaceKey> {
        let place = operand.place()?;
        if let Some(key) = fn_pointer_place_key(self.body, &place)
            && let Some(origin) = self.fn_pointer_source_origins.get(&key).cloned().flatten()
        {
            return Some(origin);
        }
        if let Some(key) = option_fn_pointer_key_from_unwrapped_place(self.body, &place) {
            if let Some(origin) = self
                .option_fn_pointer_source_origins
                .get(&key)
                .cloned()
                .flatten()
            {
                return Some(origin);
            }
            if is_receiver_field_key(self.body, &key) {
                return Some(key);
            }
        }
        if let Some(key) = fn_pointer_place_key(self.body, &place)
            && is_receiver_field_key(self.body, &key)
        {
            return Some(key);
        }
        None
    }

    fn option_fn_pointer_source_key_from_operand(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<RawPointerPlaceKey> {
        let place = operand.place()?;
        let key = fn_pointer_place_key(self.body, &place)?;
        self.option_fn_pointer_source_origins
            .get(&key)
            .cloned()
            .flatten()
            .or_else(|| is_receiver_field_key(self.body, &key).then_some(key))
    }

    fn fn_def_from_rvalue(&self, rvalue: &Rvalue<'tcx>) -> Option<DefId> {
        match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                self.fn_def_from_operand(operand)
            }
            _ => None,
        }
    }

    fn option_fn_def_from_rvalue(&self, rvalue: &Rvalue<'tcx>) -> Option<DefId> {
        match rvalue {
            Rvalue::Aggregate(kind, operands)
                if matches!(**kind, AggregateKind::Adt(..)) && operands.len() == 1 =>
            {
                operands
                    .iter()
                    .next()
                    .and_then(|operand| self.fn_def_from_operand(operand))
            }
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                self.option_fn_def_from_operand(operand)
            }
            _ => None,
        }
    }

    fn fn_def_from_operand(&self, operand: &Operand<'tcx>) -> Option<DefId> {
        if let Some((def_id, _)) = operand.const_fn_def() {
            return Some(def_id);
        }
        let place = operand.place()?;
        if let Some(key) = fn_pointer_place_key(self.body, &place)
            && let Some(origin) = self.fn_pointer_origins.get(&key).cloned().flatten()
        {
            return Some(origin);
        }
        option_fn_pointer_key_from_unwrapped_place(self.body, &place)
            .and_then(|key| self.option_fn_pointer_origins.get(&key).cloned().flatten())
    }

    fn option_fn_def_from_operand(&self, operand: &Operand<'tcx>) -> Option<DefId> {
        let place = operand.place()?;
        let key = fn_pointer_place_key(self.body, &place)?;
        self.option_fn_pointer_origins.get(&key).cloned().flatten()
    }

    fn foreign_destructor_release_observation(
        &self,
        callee_def_path: &str,
        api_id: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        registration: &RegistrationObservation,
        location: Location,
    ) -> Option<RawPointerTransferObservation> {
        let user_data = registration.user_data.clone()?;
        let destructor_index = foreign_destructor_arg_index(api_id, callee_def_path)?;
        let destructor_arg = args.get(destructor_index)?;
        let destructor_def_id = self.option_fn_def_from_operand(&destructor_arg.node)?;
        let released_arg = raw_pointer_release_arg_place_key(
            self.tcx,
            destructor_def_id,
            foreign_destructor_allows_capsule_get_pointer(api_id),
        )?;
        if released_arg.arg_index != 0 || !released_arg.projection.is_empty() {
            return None;
        }
        let (Ok(source_path), Ok(stable_span)) = (
            source_path(self.tcx, destructor_arg.span),
            stable_span(self.tcx, destructor_arg.span),
        ) else {
            return None;
        };
        Some(RawPointerTransferObservation {
            owner_def_path: self.owner_def_path.clone(),
            source_path,
            span: stable_span,
            mir_location: format!("{location:?}:foreign_destructor"),
            basic_block: location.block.index(),
            statement_index: location.statement_index,
            kind: RawPointerTransferKind::FromRaw,
            user_data,
        })
    }

    fn record_borrow_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        if !destination.projection.is_empty()
            || !matches!(
                destination.ty(&self.body.local_decls, self.tcx).ty.kind(),
                ty::Ref(..)
            )
        {
            return;
        }
        let span = self.assignment_span(location);
        match self.borrow_reference_from_rvalue(rvalue, span, location) {
            Some(source) => {
                self.borrow_origins.insert(destination.local, Some(source));
            }
            None => {
                self.borrow_origins.insert(destination.local, None);
            }
        }
    }

    fn record_returned_borrow_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        if !destination.projection.is_empty() {
            return;
        }
        let span = self.assignment_span(location);
        match self.returned_borrow_origin_from_rvalue(rvalue, span, location) {
            Some(origin) => {
                if destination.local == Local::new(0) {
                    self.returned_borrow_return_origins
                        .push(ReturnedBorrowReturnAssignment {
                            write: KeyedMapEntryBranchWrite::Returned(origin.clone()),
                            location,
                        });
                }
                self.returned_borrow_origins
                    .insert(destination.local, Some(origin));
            }
            None => {
                if destination.local == Local::new(0)
                    && ty_contains_ref(destination.ty(&self.body.local_decls, self.tcx).ty)
                {
                    self.returned_borrow_return_origins
                        .push(ReturnedBorrowReturnAssignment {
                            write: KeyedMapEntryBranchWrite::Blocked,
                            location,
                        });
                }
                self.returned_borrow_origins.insert(destination.local, None);
            }
        }
    }

    fn observe_returned_borrow_slot_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        if destination.local.index() < 2
            || destination.local.index() > self.body.arg_count
            || !destination
                .projection
                .iter()
                .any(|projection| matches!(projection, ProjectionElem::Deref))
            || !ty_contains_ref(destination.ty(&self.body.local_decls, self.tcx).ty)
        {
            return;
        }
        let span = self.assignment_span(location);
        let write = self
            .returned_borrow_origin_from_rvalue(rvalue, span, location)
            .map(KeyedMapEntryBranchWrite::Returned)
            .unwrap_or(KeyedMapEntryBranchWrite::Blocked);
        self.returned_borrow_slot_assignment_origins
            .push(ReturnedBorrowSlotAssignment { write, location });
    }

    fn clear_returned_borrow_storage_assignment_destination(&mut self, destination: &Place<'tcx>) {
        if destination.projection.is_empty() {
            return;
        }
        if let Some(storage_key) = self.returned_borrow_storage_key(destination) {
            if storage_key.starts_with("local_wrapper_field:") {
                self.clear_returned_borrow_storage_key(&storage_key);
            }
        }
    }

    fn observe_persisted_returned_borrow_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        if destination.projection.is_empty() {
            return;
        }
        let span = self.assignment_span(location);
        let Some(origin) = self.returned_borrow_origin_from_rvalue(rvalue, span, location) else {
            return;
        };
        let storage_type_name = destination
            .ty(&self.body.local_decls, self.tcx)
            .ty
            .to_string();
        if destination
            .projection
            .iter()
            .any(|projection| matches!(projection, ProjectionElem::Deref))
            && let Some(reference_origin) = self
                .returned_borrow_entry_value_reference_origins
                .get(&destination.local)
                .cloned()
        {
            if !reference_origin
                .reference_order_keys
                .iter()
                .all(|reference_order_key| {
                    entry_value_assignment_postdominates_reference(
                        self.body,
                        *reference_order_key,
                        mir_order_key(location),
                    )
                })
            {
                return;
            }
            self.remove_returned_borrow_origins_for_storage_key(&reference_origin.storage_key);
            self.returned_borrow_keyed_map_known_occupied
                .insert(reference_origin.storage_key.clone());
            self.record_returned_borrow_storage_mutation_barrier_for_key(
                reference_origin.storage_key.clone(),
                span,
                location,
                "entry_value_assignment",
            );
            self.push_persisted_returned_borrow(
                origin,
                reference_origin.storage_type_name,
                span,
                location,
                Some(reference_origin.storage_key),
            );
            return;
        }
        if destination
            .projection
            .iter()
            .any(|projection| matches!(projection, ProjectionElem::Deref))
        {
            self.pending_returned_borrow_entry_value_assignments.push(
                PendingReturnedBorrowEntryValueAssignment {
                    local: destination.local,
                    origin: origin.clone(),
                    span,
                    location,
                },
            );
        }
        let storage_key = self
            .returned_borrow_storage_key(destination)
            .filter(|_| !returned_borrow_keyed_map_storage_type(&storage_type_name));
        if let Some(storage_key) = &storage_key
            && storage_key.contains(":map_key:")
            && destination
                .projection
                .iter()
                .any(|projection| matches!(projection, ProjectionElem::Deref))
        {
            let Some(reference_origin) = self
                .returned_borrow_entry_value_reference_origins
                .get(&destination.local)
            else {
                return;
            };
            if reference_origin.storage_key != *storage_key
                || !reference_origin
                    .reference_order_keys
                    .iter()
                    .all(|reference_order_key| {
                        entry_value_assignment_postdominates_reference(
                            self.body,
                            *reference_order_key,
                            mir_order_key(location),
                        )
                    })
            {
                return;
            }
            self.remove_returned_borrow_origins_for_storage_key(storage_key);
            self.returned_borrow_keyed_map_known_occupied
                .insert(storage_key.clone());
            self.record_returned_borrow_storage_mutation_barrier_for_key(
                storage_key.clone(),
                span,
                location,
                "entry_value_assignment",
            );
        }
        self.push_persisted_returned_borrow(origin, storage_type_name, span, location, storage_key);
    }

    fn observe_returned_borrow_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        let return_local = Local::new(0);
        if destination.local != return_local
            || !destination.projection.is_empty()
            || !ty_contains_ref(self.body.local_decls[return_local].ty)
        {
            return;
        }
        let span = self.assignment_span(location);
        let Some(source) = self.borrow_reference_from_rvalue(rvalue, span, location) else {
            return;
        };
        self.push_returned_borrow_relation(source, span, location);
    }

    fn push_returned_borrow_relation(
        &mut self,
        source: BorrowReference,
        span: Span,
        location: Location,
    ) {
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.observations
            .returned_borrow_relations
            .push(ReturnedBorrowRelationObservation {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}"),
                api_id: self.owner_def_path.clone(),
                relation_kind: None,
                source,
                returned_type_name: self.body.local_decls[Local::new(0)].ty.to_string(),
            });
    }

    fn push_persisted_returned_borrow(
        &mut self,
        origin: ReturnedBorrowOrigin,
        storage_type_name: String,
        span: Span,
        location: Location,
        storage_key: Option<String>,
    ) {
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        let persisted = PersistedReturnedBorrowObservation {
            owner_def_path: self.owner_def_path.clone(),
            source_path,
            span: stable_span,
            mir_location: format!("{location:?}"),
            mir_order_block: location.block.index(),
            mir_statement_index: location.statement_index,
            api_id: origin.api_id,
            source: origin.source,
            returned_type_name: origin.returned_type_name,
            storage_type_name,
            storage_key,
        };
        self.remember_persisted_returned_borrow(persisted);
    }

    fn remember_persisted_returned_borrow(
        &mut self,
        persisted: PersistedReturnedBorrowObservation,
    ) {
        if let Some(storage_key) = &persisted.storage_key {
            self.returned_borrow_storage_origins
                .entry(storage_key.clone())
                .or_default()
                .push(persisted.clone());
        }
        self.observations.persisted_returned_borrows.push(persisted);
    }

    fn record_returned_borrow_storage_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        let destination_storage_key = destination
            .projection
            .is_empty()
            .then(|| self.returned_borrow_storage_key(destination))
            .flatten();
        if destination.projection.is_empty() {
            if let Some(storage_key) = &destination_storage_key {
                self.returned_borrow_keyed_map_known_empty
                    .remove(storage_key);
                self.remove_keyed_map_known_occupied_for_storage_prefix(
                    &keyed_map_returned_borrow_storage_prefix(storage_key),
                );
            }
            self.returned_borrow_storage_reference_origins
                .remove(&destination.local);
            self.returned_borrow_entry_value_reference_origins
                .remove(&destination.local);
            self.returned_borrow_unique_storage_origins
                .remove(&destination.local);
            self.returned_borrow_local_wrapper_reference_origins
                .remove(&destination.local);
            self.returned_borrow_invalidated_storage_keys
                .remove(&self.returned_borrow_local_storage_key(destination.local));
            self.forget_returned_borrow_local_wrapper_field_origins(destination.local);
        }
        match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                if destination.projection.is_empty()
                    && let Some(place) = operand.place()
                {
                    self.returned_borrow_storage_reference_origins
                        .insert(destination.local, self.returned_borrow_storage_key(&place));
                    if let Some(reference_origin) = self
                        .returned_borrow_entry_value_reference_origins
                        .get(&place.local)
                        .cloned()
                        .filter(|_| place.projection.is_empty())
                    {
                        self.record_returned_borrow_entry_value_reference_origin(
                            destination.local,
                            reference_origin,
                        );
                    }
                    self.propagate_returned_borrow_local_wrapper_field_origins(destination, &place);
                    self.propagate_returned_borrow_local_wrapper_reference_origin(
                        destination.local,
                        &place,
                    );
                    if let Some(unique_key) =
                        self.unique_owned_storage_key_from_source_place(&place)
                    {
                        self.returned_borrow_unique_storage_origins
                            .insert(destination.local, unique_key);
                    }
                    if let Some(destination_storage_key) = &destination_storage_key
                        && let Some(source_storage_key) = self.returned_borrow_storage_key(&place)
                        && self
                            .returned_borrow_keyed_map_known_empty
                            .contains(&source_storage_key)
                    {
                        self.returned_borrow_keyed_map_known_empty
                            .insert(destination_storage_key.clone());
                    }
                }
                let origins = self.returned_borrow_storage_origins_from_operand(operand);
                self.propagate_returned_borrow_storage_origins(destination, origins);
            }
            Rvalue::Ref(_, _, source_place) => {
                if destination.projection.is_empty() {
                    self.returned_borrow_storage_reference_origins.insert(
                        destination.local,
                        self.returned_borrow_storage_key(source_place),
                    );
                    if let Some(reference_origin) = self
                        .returned_borrow_entry_value_reference_origins
                        .get(&source_place.local)
                        .cloned()
                        .filter(|_| source_place.projection.is_empty())
                    {
                        self.record_returned_borrow_entry_value_reference_origin(
                            destination.local,
                            reference_origin,
                        );
                    }
                    self.record_returned_borrow_local_wrapper_reference_origin(
                        destination.local,
                        source_place,
                    );
                    if let Some(unique_key) =
                        self.unique_owned_storage_key_from_source_place(source_place)
                    {
                        self.returned_borrow_unique_storage_origins
                            .insert(destination.local, unique_key);
                    }
                }
                let origins = self.returned_borrow_storage_origins_from_place(source_place);
                self.propagate_returned_borrow_storage_origins(destination, origins);
            }
            Rvalue::Aggregate(kind, operands) if matches!(**kind, AggregateKind::Adt(..)) => {
                let unique_origins =
                    self.unique_returned_borrow_storage_origins_from_operands(operands.iter());
                if operands.len() == 1 {
                    self.propagate_returned_borrow_storage_origins(destination, unique_origins);
                    if let Some(operand) = operands.iter().next() {
                        self.record_returned_borrow_wrapper_field_assignment(
                            destination,
                            0,
                            operand,
                            location,
                        );
                    }
                    return;
                }
                let Some(destination_projection) = storage_projection_key(self.body, destination)
                else {
                    return;
                };
                let Some(owner_family) = lifecycle_receiver_family(&self.owner_def_path) else {
                    return;
                };
                for (field_index, operand) in operands.iter().enumerate() {
                    self.record_returned_borrow_wrapper_field_assignment(
                        destination,
                        field_index,
                        operand,
                        location,
                    );
                    let origins = self.returned_borrow_storage_origins_from_operand(operand);
                    if origins.is_empty() {
                        continue;
                    }
                    let mut field_projection = destination_projection.clone();
                    field_projection.push(format!("field:{field_index}"));
                    let storage_key = field_storage_key(&owner_family, &field_projection);
                    self.remember_persisted_returned_borrow_at_storage_key(storage_key, origins);
                }
            }
            Rvalue::Aggregate(kind, operands)
                if closure_def_path_from_aggregate_kind(self.tcx, kind).is_some() =>
            {
                let closure_def_path =
                    closure_def_path_from_aggregate_kind(self.tcx, kind).expect("checked closure");
                for (field_index, operand) in operands.iter().enumerate() {
                    let Some(place) = operand.place() else {
                        continue;
                    };
                    let projection = vec![format!("field:{field_index}")];
                    if let Some(storage_key) = self.returned_borrow_storage_key(&place) {
                        remember_closure_storage_capture_summary(
                            &mut self.closure_storage_capture_summaries,
                            closure_def_path.clone(),
                            projection.clone(),
                            storage_key.clone(),
                        );
                        remember_closure_storage_capture_summary(
                            &mut self.discovered_closure_storage_captures,
                            closure_def_path.clone(),
                            projection.clone(),
                            storage_key,
                        );
                    }
                    if let Some(origin) = self.returned_borrow_origin_from_place(&place) {
                        remember_closure_returned_borrow_capture_summary(
                            &mut self.closure_returned_borrow_capture_summaries,
                            closure_def_path.clone(),
                            projection.clone(),
                            origin.clone(),
                        );
                        remember_closure_returned_borrow_capture_summary(
                            &mut self.discovered_closure_returned_borrow_captures,
                            closure_def_path.clone(),
                            projection,
                            origin,
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn observe_returned_borrow_storage_use_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        if !destination.projection.is_empty()
            || !ty_contains_ref(destination.ty(&self.body.local_decls, self.tcx).ty)
            || destination.local != Local::new(0)
        {
            return;
        }
        let Some(source_place) = returned_borrow_storage_use_source_place(rvalue) else {
            return;
        };
        let mut storage_keys = BTreeSet::new();
        if let Some(storage_key) = self.returned_borrow_storage_key(&source_place)
            && self
                .returned_borrow_storage_origins
                .contains_key(&storage_key)
        {
            storage_keys.insert(storage_key);
        }
        for origin in self.returned_borrow_storage_origins_from_place(&source_place) {
            if let Some(storage_key) = origin.storage_key {
                storage_keys.insert(storage_key);
            }
        }
        if storage_keys.is_empty() {
            return;
        }
        let span = self.assignment_span(location);
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.returned_borrow_storage_uses
            .push(ReturnedBorrowStorageUse {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:assignment_use"),
                order_key: mir_order_key(location),
                storage_keys,
            });
    }

    fn observe_closure_capture_use_assignment(
        &mut self,
        rvalue: &Rvalue<'tcx>,
        location: Location,
    ) {
        let Some(source_place) = closure_capture_use_source_place(rvalue) else {
            return;
        };
        let Some(summary) = self.closure_capture_use_summary(&source_place) else {
            return;
        };
        let span = self.assignment_span(location);
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        let use_site = ObjectFlowStaticSiteObservation {
            owner_def_path: self.owner_def_path.clone(),
            source_path: source_path.clone(),
            span: stable_span.clone(),
            mir_location: format!("{location:?}:closure_capture_use"),
            type_name: source_place
                .ty(&self.body.local_decls, self.tcx)
                .ty
                .to_string(),
        };
        let callback = CallbackReference {
            def_path: summary.callback_def_path.clone(),
            source_path: summary.callback_source_path.clone(),
            span: summary.callback_span.clone(),
        };
        self.observations.object_flows.push(object_flow_observation(
            &self.owner_def_path,
            &source_path,
            &stable_span,
            &format!("{location:?}:closure_capture_field_load"),
            &self.owner_def_path,
            ObjectFlowEndpointObservation::CallbackSite(callback),
            ObjectFlowObjectKind::Callback,
            ObjectFlowEndpointObservation::StaticSite(use_site),
            ObjectFlowObjectKind::StaticSite,
            ObjectFlowKind::FieldLoad,
            Some(summary.field_path.clone()),
            None,
        ));
    }

    fn closure_capture_use_summary(
        &self,
        source_place: &Place<'tcx>,
    ) -> Option<ClosureCaptureUseSummary> {
        if source_place.local != Local::new(1) {
            return None;
        }
        let projection = storage_projection_key(self.body, source_place)?;
        if projection.is_empty() {
            return None;
        }
        self.closure_capture_use_summaries
            .get(&self.owner_def_path)
            .and_then(|captures| captures.get(&projection))
            .cloned()
            .flatten()
    }

    fn record_returned_borrow_wrapper_field_assignment(
        &mut self,
        destination: &Place<'tcx>,
        field_index: usize,
        operand: &Operand<'tcx>,
        location: Location,
    ) {
        if !destination.projection.is_empty()
            || destination.local == Local::new(0)
            || destination.local.index() <= self.body.arg_count
        {
            return;
        }
        let field_path = vec![format!("field:{field_index}")];
        let storage_key =
            self.returned_borrow_local_wrapper_field_storage_key(destination.local, &field_path);
        let storage_type_name = destination
            .ty(&self.body.local_decls, self.tcx)
            .ty
            .to_string();
        let span = self.assignment_span(location);
        if let Some(origin) = self.unique_returned_borrow_origin_from_operands(
            std::iter::once(operand),
            span,
            location,
        ) {
            self.push_persisted_returned_borrow(
                origin,
                storage_type_name,
                span,
                location,
                Some(storage_key.clone()),
            );
        }
        let origins =
            self.unique_returned_borrow_storage_origins_from_operands(std::iter::once(operand));
        if !origins.is_empty() {
            self.remember_persisted_returned_borrow_at_storage_key(storage_key, origins);
        }
    }

    fn propagate_returned_borrow_local_wrapper_field_origins(
        &mut self,
        destination: &Place<'tcx>,
        source: &Place<'tcx>,
    ) {
        if !destination.projection.is_empty()
            || !source.projection.is_empty()
            || destination.local == source.local
        {
            return;
        }
        let source_prefix =
            self.returned_borrow_local_wrapper_field_storage_key_prefix(source.local);
        let entries = self
            .returned_borrow_storage_origins
            .iter()
            .filter_map(|(storage_key, origins)| {
                if !storage_key.starts_with(&source_prefix) || origins.is_empty() {
                    return None;
                }
                let field_path = local_wrapper_field_path_from_storage_key(storage_key)?
                    .split('.')
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>();
                Some((field_path, origins.clone()))
            })
            .collect::<Vec<_>>();
        for (field_path, origins) in entries {
            let destination_key = self
                .returned_borrow_local_wrapper_field_storage_key(destination.local, &field_path);
            self.remember_persisted_returned_borrow_at_storage_key(destination_key, origins);
        }
    }

    fn record_returned_borrow_local_wrapper_reference_origin(
        &mut self,
        destination_local: Local,
        source: &Place<'tcx>,
    ) {
        if !source.projection.is_empty() || source.local.index() <= self.body.arg_count {
            return;
        }
        let source_prefix =
            self.returned_borrow_local_wrapper_field_storage_key_prefix(source.local);
        if self
            .returned_borrow_storage_origins
            .keys()
            .any(|storage_key| storage_key.starts_with(&source_prefix))
        {
            self.returned_borrow_local_wrapper_reference_origins
                .insert(destination_local, source.local);
        }
    }

    fn propagate_returned_borrow_local_wrapper_reference_origin(
        &mut self,
        destination_local: Local,
        source: &Place<'tcx>,
    ) {
        if !source.projection.is_empty() {
            return;
        }
        if let Some(source_local) = self
            .returned_borrow_local_wrapper_reference_origins
            .get(&source.local)
            .copied()
        {
            self.returned_borrow_local_wrapper_reference_origins
                .insert(destination_local, source_local);
            return;
        }
        self.record_returned_borrow_local_wrapper_reference_origin(destination_local, source);
    }

    fn forget_returned_borrow_local_wrapper_field_origins(&mut self, local: Local) {
        let prefix = self.returned_borrow_local_wrapper_field_storage_key_prefix(local);
        self.returned_borrow_storage_origins
            .retain(|storage_key, _| !storage_key.starts_with(&prefix));
        self.returned_borrow_invalidated_storage_keys
            .retain(|storage_key| !storage_key.starts_with(&prefix));
    }

    fn record_returned_borrow_indexed_iterator_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
    ) {
        if !destination.projection.is_empty() {
            return;
        }
        self.returned_borrow_indexed_iterator_storage_origins
            .remove(&destination.local);
        let origin = match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                operand.place().and_then(|place| {
                    self.returned_borrow_indexed_iterator_storage_origin_from_place(&place)
                })
            }
            Rvalue::Ref(_, _, source_place) => {
                self.returned_borrow_indexed_iterator_storage_origin_from_place(source_place)
            }
            _ => None,
        };
        if origin.is_some() {
            self.returned_borrow_indexed_iterator_storage_origins
                .insert(destination.local, origin);
        }
    }

    fn record_returned_borrow_slice_storage_assignment(
        &mut self,
        destination: &Place<'tcx>,
        rvalue: &Rvalue<'tcx>,
    ) {
        if !destination.projection.is_empty() {
            return;
        }
        self.returned_borrow_slice_storage_origins
            .remove(&destination.local);
        let origin = match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => operand
                .place()
                .and_then(|place| self.returned_borrow_slice_storage_origin_from_place(&place)),
            Rvalue::Ref(_, _, source_place) => {
                self.returned_borrow_slice_storage_origin_from_place(source_place)
            }
            _ => None,
        };
        if let Some(origin) = origin {
            self.returned_borrow_slice_storage_origins
                .insert(destination.local, origin);
        }
    }

    fn record_returned_borrow_range_slice_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
    ) {
        if !destination.projection.is_empty()
            || method_name(callee_def_path).as_deref() != Some("get")
        {
            return;
        }
        self.returned_borrow_slice_storage_origins
            .remove(&destination.local);
        let Some(first_arg) = args.first() else {
            return;
        };
        let storage_type_name = first_arg
            .node
            .ty(&self.body.local_decls, self.tcx)
            .to_string();
        if !returned_borrow_indexed_sequence_storage_type(&storage_type_name) {
            return;
        }
        let Some(range) = args
            .get(1)
            .and_then(|arg| self.stable_range_bounds_from_operand(&arg.node))
        else {
            return;
        };
        if range.end.is_some_and(|end| range.start >= end) {
            return;
        }
        let Some(storage_key) = first_arg
            .node
            .place()
            .and_then(|place| self.returned_borrow_storage_key(&place))
        else {
            return;
        };
        self.returned_borrow_slice_storage_origins.insert(
            destination.local,
            ReturnedBorrowSliceStorageOrigin {
                storage_key,
                start_offset: range.start,
                end_offset: range.end,
            },
        );
    }

    fn propagate_returned_borrow_storage_origins(
        &mut self,
        destination: &Place<'tcx>,
        origins: Vec<PersistedReturnedBorrowObservation>,
    ) {
        if origins.is_empty() {
            return;
        }
        let Some(storage_key) = self.returned_borrow_storage_key(destination) else {
            return;
        };
        self.remember_persisted_returned_borrow_at_storage_key(storage_key, origins);
    }

    fn remember_persisted_returned_borrow_at_storage_key(
        &mut self,
        storage_key: String,
        origins: Vec<PersistedReturnedBorrowObservation>,
    ) {
        if self
            .returned_borrow_invalidated_storage_keys
            .contains(&storage_key)
        {
            return;
        }
        for mut origin in origins {
            if origin.storage_key.as_deref() == Some(storage_key.as_str()) {
                continue;
            }
            origin.storage_key = Some(storage_key.clone());
            self.remember_persisted_returned_borrow(origin);
        }
    }

    fn unique_returned_borrow_storage_origins_from_operands<'operand>(
        &self,
        operands: impl IntoIterator<Item = &'operand Operand<'tcx>>,
    ) -> Vec<PersistedReturnedBorrowObservation>
    where
        'tcx: 'operand,
    {
        let mut origins = Vec::new();
        for operand in operands {
            for origin in self.returned_borrow_storage_origins_from_operand(operand) {
                if !origins.contains(&origin) {
                    origins.push(origin);
                }
            }
        }
        origins
    }

    fn returned_borrow_storage_origins_from_operand(
        &self,
        operand: &Operand<'tcx>,
    ) -> Vec<PersistedReturnedBorrowObservation> {
        let Some(place) = operand.place() else {
            return Vec::new();
        };
        self.returned_borrow_storage_origins_from_place(&place)
    }

    fn returned_borrow_storage_origins_from_place(
        &self,
        place: &Place<'tcx>,
    ) -> Vec<PersistedReturnedBorrowObservation> {
        let mut origins = Vec::new();
        if let Some(storage_key) = self.returned_borrow_storage_key(place)
            && let Some(keyed) = self.returned_borrow_storage_origins.get(&storage_key)
        {
            origins.extend(keyed.iter().cloned());
        }
        let local_key = self.returned_borrow_local_storage_key(place.local);
        if let Some(local_origins) = self.returned_borrow_storage_origins.get(&local_key) {
            for origin in local_origins {
                if !origins.contains(origin) {
                    origins.push(origin.clone());
                }
            }
        }
        origins
    }

    fn returned_borrow_storage_key(&self, place: &Place<'tcx>) -> Option<String> {
        if let Some(unique_key) = self.unique_owned_storage_key_from_place(place) {
            return self.live_returned_borrow_storage_key(unique_key);
        }
        if let Some(slice_origin) = self.returned_borrow_slice_storage_origin_from_place(place) {
            return self.live_returned_borrow_storage_key(indexed_returned_borrow_storage_key(
                &slice_origin.storage_key,
                &slice_origin.start_offset.to_string(),
            ));
        }
        if let Some(storage_key) = self.option_some_field_storage_key(place) {
            return self.live_returned_borrow_storage_key(storage_key);
        }
        let projection = storage_projection_key(self.body, place)?;
        if let Some(storage_key) = self.closure_storage_capture_key(place, &projection) {
            return self.live_returned_borrow_storage_key(storage_key);
        }
        if !projection.is_empty() && place.local.index() > self.body.arg_count {
            let local_wrapper_field_key =
                self.returned_borrow_local_wrapper_field_storage_key(place.local, &projection);
            if self
                .returned_borrow_storage_origins
                .contains_key(&local_wrapper_field_key)
            {
                return self.live_returned_borrow_storage_key(local_wrapper_field_key);
            }
        }
        if projection.is_empty() {
            if let Some(storage_key) = self
                .returned_borrow_storage_reference_origins
                .get(&place.local)
                .cloned()
                .flatten()
            {
                return self.live_returned_borrow_storage_key(storage_key);
            }
            return self.live_returned_borrow_storage_key(
                self.returned_borrow_local_storage_key(place.local),
            );
        }
        let owner_family = lifecycle_receiver_family(&self.owner_def_path)?;
        self.live_returned_borrow_storage_key(field_storage_key(&owner_family, &projection))
    }

    fn returned_borrow_slice_storage_origin_from_place(
        &self,
        place: &Place<'tcx>,
    ) -> Option<ReturnedBorrowSliceStorageOrigin> {
        if place.projection.is_empty() {
            return self
                .returned_borrow_slice_storage_origins
                .get(&place.local)
                .cloned();
        }
        if place.projection.len() == 2
            && matches!(place.projection[0], ProjectionElem::Downcast(..))
            && matches!(place.projection[1], ProjectionElem::Field(field, _) if field.index() == 0)
        {
            return self
                .returned_borrow_slice_storage_origins
                .get(&place.local)
                .cloned();
        }
        None
    }

    fn unique_returned_borrow_slice_storage_origin_from_operands<'operand>(
        &self,
        operands: impl IntoIterator<Item = &'operand Operand<'tcx>>,
    ) -> Option<ReturnedBorrowSliceStorageOrigin>
    where
        'tcx: 'operand,
    {
        let mut unique: Option<ReturnedBorrowSliceStorageOrigin> = None;
        for operand in operands {
            let Some(origin) = operand
                .place()
                .and_then(|place| self.returned_borrow_slice_storage_origin_from_place(&place))
            else {
                continue;
            };
            if unique.as_ref().is_some_and(|existing| existing != &origin) {
                return None;
            }
            unique = Some(origin);
        }
        unique
    }

    fn option_some_field_storage_key(&self, place: &Place<'tcx>) -> Option<String> {
        if place.projection.len() != 2 {
            return None;
        }
        let base_type_name = self.body.local_decls[place.local].ty.to_string();
        if !base_type_name.to_ascii_lowercase().contains("option<") {
            return None;
        }
        match (place.projection[0], place.projection[1]) {
            (ProjectionElem::Downcast(..), ProjectionElem::Field(field, _))
                if field.index() == 0 =>
            {
                self.returned_borrow_storage_reference_origins
                    .get(&place.local)
                    .cloned()
                    .flatten()
            }
            _ => None,
        }
    }

    fn live_returned_borrow_storage_key(&self, storage_key: String) -> Option<String> {
        if self
            .returned_borrow_invalidated_storage_keys
            .contains(&storage_key)
        {
            return None;
        }
        Some(storage_key)
    }

    fn unique_owned_storage_key_from_source_place(&self, place: &Place<'tcx>) -> Option<String> {
        self.unique_owned_storage_key_from_place(place).or_else(|| {
            let place_ty = place.ty(&self.body.local_decls, self.tcx).ty;
            if !is_box_storage_owner_ty(place_ty) {
                return None;
            }
            let projection = storage_projection_key(self.body, place)?;
            if projection.is_empty() {
                return self
                    .returned_borrow_storage_reference_origins
                    .get(&place.local)
                    .cloned()
                    .flatten();
            }
            let owner_family = lifecycle_receiver_family(&self.owner_def_path)?;
            Some(field_storage_key(&owner_family, &projection))
        })
    }

    fn unique_owned_storage_key_from_place(&self, place: &Place<'tcx>) -> Option<String> {
        let base_key = self
            .returned_borrow_unique_storage_origins
            .get(&place.local)
            .cloned()?;
        if place.projection.is_empty()
            || unique_owned_storage_projection_passthrough(self.body, place)
        {
            return Some(base_key);
        }
        None
    }

    fn closure_storage_capture_key(
        &self,
        place: &Place<'tcx>,
        projection: &[String],
    ) -> Option<String> {
        if place.local.index() != 1 || projection.is_empty() {
            return None;
        }
        self.closure_storage_capture_summaries
            .get(&self.owner_def_path)
            .and_then(|captures| captures.get(projection))
            .cloned()
            .flatten()
    }

    fn closure_returned_borrow_capture_origin(
        &self,
        place: &Place<'tcx>,
        projection: &[String],
    ) -> Option<ReturnedBorrowOrigin> {
        if place.local.index() != 1 || projection.is_empty() {
            return None;
        }
        self.closure_returned_borrow_capture_summaries
            .get(&self.owner_def_path)
            .and_then(|captures| captures.get(projection))
            .cloned()
            .flatten()
    }

    fn returned_borrow_local_storage_key(&self, local: Local) -> String {
        format!("local:{}:{}", self.owner_def_path, local.index())
    }

    fn returned_borrow_local_wrapper_field_storage_key(
        &self,
        local: Local,
        field_path: &[String],
    ) -> String {
        local_wrapper_field_storage_key(&self.owner_def_path, local, field_path)
    }

    fn returned_borrow_local_wrapper_field_storage_key_prefix(&self, local: Local) -> String {
        local_wrapper_field_storage_key_prefix(&self.owner_def_path, local)
    }

    fn borrow_reference_from_rvalue(
        &self,
        rvalue: &Rvalue<'tcx>,
        span: Span,
        location: Location,
    ) -> Option<BorrowReference> {
        match rvalue {
            Rvalue::Use(operand, _) => self.borrow_reference_from_operand(operand, span, location),
            Rvalue::Ref(_, _, place) => self.borrow_reference_from_place(place, span, location),
            Rvalue::Aggregate(kind, operands) if matches!(**kind, AggregateKind::Adt(..)) => {
                self.unique_borrow_reference_from_operands(operands, span, location)
            }
            _ => None,
        }
    }

    fn unique_borrow_reference_from_operands<'operand>(
        &self,
        operands: impl IntoIterator<Item = &'operand Operand<'tcx>>,
        span: Span,
        location: Location,
    ) -> Option<BorrowReference>
    where
        'tcx: 'operand,
    {
        let mut source = None;
        for operand in operands {
            let Some(candidate) = self.borrow_reference_from_operand(operand, span, location)
            else {
                continue;
            };
            if let Some(existing) = &source
                && existing != &candidate
            {
                return None;
            }
            source = Some(candidate);
        }
        source
    }

    fn borrow_reference_from_operand(
        &self,
        operand: &Operand<'tcx>,
        span: Span,
        location: Location,
    ) -> Option<BorrowReference> {
        let place = operand.place()?;
        self.borrow_reference_from_place(&place, span, location)
    }

    fn returned_borrow_origin_from_rvalue(
        &self,
        rvalue: &Rvalue<'tcx>,
        span: Span,
        location: Location,
    ) -> Option<ReturnedBorrowOrigin> {
        match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                self.returned_borrow_origin_from_operand(operand, span, location)
            }
            Rvalue::Aggregate(kind, operands) if matches!(**kind, AggregateKind::Adt(..)) => {
                self.unique_returned_borrow_origin_from_operands(operands, span, location)
            }
            _ => None,
        }
    }

    fn unique_returned_borrow_origin_from_operands<'operand>(
        &self,
        operands: impl IntoIterator<Item = &'operand Operand<'tcx>>,
        span: Span,
        location: Location,
    ) -> Option<ReturnedBorrowOrigin>
    where
        'tcx: 'operand,
    {
        let mut source = None;
        for operand in operands {
            let candidate = self.returned_borrow_origin_from_operand(operand, span, location)?;
            if let Some(existing) = &source
                && existing != &candidate
            {
                return None;
            }
            source = Some(candidate);
        }
        source
    }

    fn returned_borrow_origin_from_operand(
        &self,
        operand: &Operand<'tcx>,
        _span: Span,
        _location: Location,
    ) -> Option<ReturnedBorrowOrigin> {
        let place = operand.place()?;
        self.returned_borrow_origin_from_place(&place)
    }

    fn returned_borrow_origin_from_place(
        &self,
        place: &Place<'tcx>,
    ) -> Option<ReturnedBorrowOrigin> {
        if let Some(projection) = storage_projection_key(self.body, place)
            && let Some(origin) = self.closure_returned_borrow_capture_origin(place, &projection)
        {
            return Some(origin);
        }
        self.returned_borrow_origins
            .get(&place.local)
            .cloned()
            .flatten()
    }

    fn borrow_reference_from_place(
        &self,
        place: &Place<'tcx>,
        span: Span,
        location: Location,
    ) -> Option<BorrowReference> {
        if let Some(origin) = self.borrow_origins.get(&place.local).cloned().flatten() {
            return Some(origin);
        }
        let local_index = place.local.index();
        if local_index == 0 || local_index > self.body.arg_count {
            return None;
        }
        let local_ty = self.body.local_decls[place.local].ty;
        if !matches!(local_ty.kind(), ty::Ref(..)) {
            return None;
        }
        Some(BorrowReference {
            owner_def_path: self.owner_def_path.clone(),
            source_path: source_path(self.tcx, span).ok()?,
            span: stable_span(self.tcx, span).ok()?,
            mir_location: format!("{location:?}"),
            type_name: local_ty.to_string(),
        })
    }

    fn record_returned_borrow_call(
        &mut self,
        callee_def_id: DefId,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        if !destination.projection.is_empty()
            || !ty_contains_ref(destination.ty(&self.body.local_decls, self.tcx).ty)
        {
            return;
        }
        let destination_type_name = destination
            .ty(&self.body.local_decls, self.tcx)
            .ty
            .to_string();
        let local_callee_requires_summary = !root_returned_borrow_view_call(callee_def_path)
            && callee_def_path != self.owner_def_path
            && callee_def_id.as_local().is_some();
        let propagated_origin = (!local_callee_requires_summary)
            .then(|| {
                args.first().and_then(|arg| {
                    self.returned_borrow_origin_from_operand(&arg.node, arg.span, location)
                })
            })
            .flatten();
        let summarized_origin = if local_callee_requires_summary {
            summarize_returned_borrow_callable(self.tcx, self.current_crate_name, callee_def_id)
        } else {
            None
        };
        let source = if let Some(origin) = propagated_origin.as_ref().or(summarized_origin.as_ref())
        {
            Some(origin.source.clone())
        } else if root_returned_borrow_view_call(callee_def_path) {
            self.borrow_reference_at(span, location, destination_type_name.clone())
        } else if callee_def_id.as_local().is_none() {
            args.first()
                .and_then(|arg| self.borrow_reference_from_operand(&arg.node, arg.span, location))
        } else {
            None
        };
        let Some(source) = source else {
            return;
        };
        let origin = ReturnedBorrowOrigin {
            source: source.clone(),
            api_id: propagated_origin
                .or(summarized_origin)
                .map(|origin| origin.api_id)
                .unwrap_or_else(|| callee_def_path.to_owned()),
            returned_type_name: destination_type_name,
        };
        self.borrow_origins.insert(destination.local, Some(source));
        if destination.local == Local::new(0) {
            self.returned_borrow_return_origins
                .push(ReturnedBorrowReturnAssignment {
                    write: KeyedMapEntryBranchWrite::Returned(origin.clone()),
                    location,
                });
        }
        self.returned_borrow_origins
            .insert(destination.local, Some(origin));
    }

    fn observe_persisted_returned_borrow_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        if !persisted_returned_borrow_storage_call(callee_def_path) {
            return;
        }
        let storage_type_name = args
            .first()
            .and_then(|arg| arg.node.place())
            .map(|place| place.ty(&self.body.local_decls, self.tcx).ty.to_string())
            .unwrap_or_else(|| callee_def_path.to_owned());
        let storage_key = args
            .first()
            .and_then(|arg| arg.node.place())
            .and_then(|place| self.returned_borrow_storage_key(&place))
            .and_then(|storage_key| {
                returned_borrow_persisted_collection_storage_key(
                    callee_def_path,
                    args,
                    &storage_type_name,
                    storage_key,
                    &self.returned_borrow_sequence_lengths,
                    &self.stable_constant_origins,
                    &self.scoped_key_origins,
                    &self.dynamic_key_generations,
                    &self.owner_def_path,
                )
            });
        for arg in args.iter().skip(1) {
            let Some(origin) =
                self.returned_borrow_origin_from_operand(&arg.node, arg.span, location)
            else {
                continue;
            };
            self.record_keyed_map_key_contract_gap_if_needed(
                callee_def_path,
                args,
                &storage_type_name,
                span,
                location,
                "key_contract",
            );
            self.push_persisted_returned_borrow(
                origin,
                storage_type_name.clone(),
                span,
                location,
                storage_key.clone(),
            );
            break;
        }
    }

    fn record_returned_borrow_storage_passthrough_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
    ) {
        if !returned_borrow_storage_passthrough_call(callee_def_path) {
            return;
        }
        let origins = self
            .unique_returned_borrow_storage_origins_from_operands(args.iter().map(|arg| &arg.node));
        self.propagate_returned_borrow_storage_origins(destination, origins);
        if destination.projection.is_empty() {
            self.returned_borrow_slice_storage_origins
                .remove(&destination.local);
            if let Some(origin) = self.unique_returned_borrow_slice_storage_origin_from_operands(
                args.iter().map(|arg| &arg.node),
            ) {
                self.returned_borrow_slice_storage_origins
                    .insert(destination.local, origin);
            }
        }
    }

    fn record_shared_owner_returned_borrow_storage_passthrough_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
    ) {
        let destination_ty = destination.ty(&self.body.local_decls, self.tcx).ty;
        let Some(destination_family) = shared_owner_family_token(&destination_ty.to_string())
        else {
            return;
        };
        let Some(first_arg) = args.first() else {
            return;
        };
        if shared_owner_constructor_call(callee_def_path) {
            if destination.projection.is_empty()
                && let Some(source_key) = first_arg
                    .node
                    .place()
                    .and_then(|place| self.returned_borrow_storage_key(&place))
            {
                self.returned_borrow_storage_reference_origins
                    .insert(destination.local, Some(source_key));
            }
            let origins = self.returned_borrow_storage_origins_from_operand(&first_arg.node);
            self.propagate_returned_borrow_storage_origins(destination, origins);
            return;
        }
        if !shared_owner_clone_call(callee_def_path) {
            return;
        }
        let Some(source_place) = first_arg.node.place() else {
            return;
        };
        let source_ty = source_place.ty(&self.body.local_decls, self.tcx).ty;
        if shared_owner_family_token(&source_ty.to_string()) != Some(destination_family) {
            return;
        }
        if destination.projection.is_empty()
            && let Some(source_key) = self.returned_borrow_storage_key(&source_place)
        {
            self.returned_borrow_storage_reference_origins
                .insert(destination.local, Some(source_key));
        }
        let origins = self.returned_borrow_storage_origins_from_place(&source_place);
        self.propagate_returned_borrow_storage_origins(destination, origins);
    }

    fn observe_shared_owner_make_mut_storage_barrier(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    ) {
        if !shared_owner_make_mut_call(callee_def_path) {
            return;
        }
        let Some(storage_key) = args
            .first()
            .and_then(|arg| arg.node.place())
            .and_then(|place| self.returned_borrow_storage_key(&place))
        else {
            return;
        };
        self.forget_returned_borrow_storage_key(&storage_key);
    }

    fn record_interior_mutability_returned_borrow_storage_passthrough_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
    ) {
        let Some(first_arg) = args.first() else {
            return;
        };
        if interior_mutability_constructor_call(callee_def_path) {
            if destination.projection.is_empty()
                && let Some(source_key) = first_arg
                    .node
                    .place()
                    .and_then(|place| self.returned_borrow_storage_key(&place))
            {
                self.returned_borrow_storage_reference_origins
                    .insert(destination.local, Some(source_key));
            }
            let origins = self.returned_borrow_storage_origins_from_operand(&first_arg.node);
            self.propagate_returned_borrow_storage_origins(destination, origins);
            return;
        }
        if !interior_mutability_read_guard_call(callee_def_path) {
            return;
        }
        if destination.projection.is_empty()
            && let Some(source_key) = first_arg
                .node
                .place()
                .and_then(|place| self.returned_borrow_storage_key(&place))
        {
            self.returned_borrow_storage_reference_origins
                .insert(destination.local, Some(source_key));
        }
        let origins = self.returned_borrow_storage_origins_from_operand(&first_arg.node);
        self.propagate_returned_borrow_storage_origins(destination, origins);
    }

    fn observe_interior_mutability_storage_barrier(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    ) {
        if !interior_mutability_mutation_barrier_call(callee_def_path) {
            return;
        }
        let Some(storage_key) = args
            .first()
            .and_then(|arg| arg.node.place())
            .and_then(|place| self.returned_borrow_storage_key(&place))
        else {
            return;
        };
        self.forget_returned_borrow_storage_key(&storage_key);
    }

    fn forget_returned_borrow_storage_key(&mut self, storage_key: &str) {
        self.returned_borrow_invalidated_storage_keys
            .insert(storage_key.to_owned());
        self.returned_borrow_keyed_map_known_empty
            .remove(storage_key);
        self.remove_keyed_map_known_occupied_for_storage_prefix(
            &keyed_map_returned_borrow_storage_prefix(storage_key),
        );
        self.returned_borrow_storage_origins.remove(storage_key);
        self.returned_borrow_storage_reference_origins
            .retain(|_, origin| origin.as_deref() != Some(storage_key));
        self.returned_borrow_entry_value_reference_origins
            .retain(|_, origin| origin.storage_key != storage_key);
        self.returned_borrow_indexed_iterator_storage_origins
            .retain(|_, origin| {
                origin
                    .as_ref()
                    .is_none_or(|origin| origin.storage_key != storage_key)
            });
        self.returned_borrow_slice_storage_origins
            .retain(|_, origin| origin.storage_key != storage_key);
        self.returned_borrow_unique_storage_origins
            .retain(|_, origin| origin != storage_key);
    }

    fn record_returned_borrow_storage_reference_passthrough_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
    ) {
        if !destination.projection.is_empty() {
            return;
        }
        let Some(first_arg) = args.first() else {
            return;
        };
        let source_type_name = first_arg
            .node
            .ty(&self.body.local_decls, self.tcx)
            .to_string();
        let is_passthrough = returned_borrow_storage_reference_passthrough_call(callee_def_path)
            || returned_borrow_option_reference_storage_passthrough_call(
                callee_def_path,
                &source_type_name,
            )
            || returned_borrow_indexed_sequence_reference_passthrough_call(
                callee_def_path,
                &source_type_name,
            );
        if !is_passthrough {
            return;
        }
        let Some(source_key) = first_arg
            .node
            .place()
            .and_then(|place| self.returned_borrow_storage_key(&place))
        else {
            return;
        };
        self.returned_borrow_storage_reference_origins
            .insert(destination.local, Some(source_key.clone()));
        self.returned_borrow_unique_storage_origins
            .insert(destination.local, source_key);
    }

    fn record_local_method_call(&mut self, callee_def_path: &str, span: Span, location: Location) {
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.local_method_calls.push(LocalMethodCall {
            owner_def_path: self.owner_def_path.clone(),
            callee_def_path: callee_def_path.to_owned(),
            source_path,
            span: stable_span,
            mir_location: format!("{location:?}"),
            order_key: mir_order_key(location),
        });
    }

    fn observe_returned_borrow_invalidation_call(
        &mut self,
        callee_def_path: &str,
        span: Span,
        location: Location,
    ) {
        if !returned_borrow_invalidation_call(callee_def_path) {
            return;
        }
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.returned_borrow_invalidations
            .push(ReturnedBorrowInvalidationCall {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}"),
                order_key: mir_order_key(location),
                api_id: callee_def_path.to_owned(),
            });
    }

    fn observe_returned_borrow_collection_mutation_barrier_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        let Some(method) = method_name(callee_def_path) else {
            return;
        };
        if !matches!(method.as_str(), "insert" | "remove" | "clear") {
            return;
        }
        let Some(first_arg) = args.first() else {
            return;
        };
        let storage_type_name = first_arg
            .node
            .ty(&self.body.local_decls, self.tcx)
            .to_string();
        if !returned_borrow_keyed_map_storage_type(&storage_type_name) {
            return;
        }
        let Some(base_storage_key) = first_arg
            .node
            .place()
            .and_then(|place| self.returned_borrow_storage_key(&place))
        else {
            return;
        };

        let mut storage_keys = BTreeSet::new();
        let mut storage_prefixes = BTreeSet::new();
        match method.as_str() {
            "insert" | "remove" => {
                if method == "insert" {
                    self.returned_borrow_keyed_map_known_empty
                        .remove(&base_storage_key);
                }
                if let Some(key) = returned_borrow_keyed_map_argument_key(
                    args,
                    &self.stable_constant_origins,
                    &self.scoped_key_origins,
                    &self.dynamic_key_generations,
                    &self.owner_def_path,
                ) {
                    let keyed_storage_key =
                        keyed_map_returned_borrow_storage_key(&base_storage_key, &key);
                    self.remove_returned_borrow_origins_for_storage_key(&keyed_storage_key);
                    if method == "insert" {
                        self.returned_borrow_keyed_map_known_occupied
                            .insert(keyed_storage_key.clone());
                    } else {
                        self.returned_borrow_keyed_map_known_occupied
                            .remove(&keyed_storage_key);
                    }
                    storage_keys.insert(keyed_storage_key);
                } else {
                    let prefix = keyed_map_returned_borrow_storage_prefix(&base_storage_key);
                    self.remove_returned_borrow_origins_for_storage_prefix(&prefix);
                    self.remove_keyed_map_known_occupied_for_storage_prefix(&prefix);
                    storage_prefixes.insert(prefix);
                }
            }
            "clear" => {
                let prefix = keyed_map_returned_borrow_storage_prefix(&base_storage_key);
                self.remove_returned_borrow_origins_for_storage_prefix(&prefix);
                self.remove_keyed_map_known_occupied_for_storage_prefix(&prefix);
                storage_prefixes.insert(prefix);
                self.returned_borrow_keyed_map_known_empty
                    .insert(base_storage_key);
            }
            _ => return,
        }
        if storage_keys.is_empty() && storage_prefixes.is_empty() {
            return;
        }
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.returned_borrow_storage_mutation_barriers
            .push(ReturnedBorrowStorageMutationBarrier {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}"),
                order_key: mir_order_key(location),
                storage_keys,
                storage_prefixes,
            });
    }

    fn returned_borrow_keyed_map_mutation_call(
        &self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    ) -> bool {
        let Some(method) = method_name(callee_def_path) else {
            return false;
        };
        if !matches!(method.as_str(), "insert" | "remove" | "clear") {
            return false;
        }
        args.first().is_some_and(|arg| {
            returned_borrow_keyed_map_storage_type(
                &arg.node.ty(&self.body.local_decls, self.tcx).to_string(),
            )
        })
    }

    fn observe_returned_borrow_indexed_sequence_mutation_barrier_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    ) {
        let Some(method) = method_name(callee_def_path) else {
            return;
        };
        if !matches!(method.as_str(), "insert" | "clear") {
            return;
        }
        let Some(first_arg) = args.first() else {
            return;
        };
        let storage_type_name = first_arg
            .node
            .ty(&self.body.local_decls, self.tcx)
            .to_string();
        if !returned_borrow_indexed_sequence_storage_type(&storage_type_name) {
            return;
        }
        let Some(storage_key) = first_arg
            .node
            .place()
            .and_then(|place| self.returned_borrow_storage_key(&place))
        else {
            return;
        };
        self.remove_returned_borrow_origins_for_storage_prefix(
            &indexed_sequence_returned_borrow_storage_prefix(&storage_key),
        );
        if method == "clear" {
            self.returned_borrow_sequence_lengths.insert(storage_key, 0);
        } else {
            self.returned_borrow_sequence_lengths.remove(&storage_key);
        }
    }

    fn observe_returned_borrow_collection_mutation_summary_call(
        &mut self,
        callee_def_id: DefId,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        let Some(summary) =
            summarize_returned_borrow_collection_mutation_callable(self.tcx, callee_def_id)
        else {
            return;
        };
        let Some(base_storage_key) = args
            .get(summary.storage_arg_index)
            .and_then(|arg| arg.node.place())
            .and_then(|place| self.returned_borrow_storage_key(&place))
        else {
            return;
        };
        self.returned_borrow_keyed_map_known_empty
            .remove(&base_storage_key);

        let mut storage_keys = BTreeSet::new();
        let mut storage_prefixes = BTreeSet::new();
        if let Some(key_arg_index) = summary.key_arg_index
            && let Some(key) = args.get(key_arg_index).and_then(|arg| {
                scoped_key_operand_key(
                    &arg.node,
                    &self.stable_constant_origins,
                    &self.scoped_key_origins,
                    &self.dynamic_key_generations,
                    &self.owner_def_path,
                )
            })
        {
            let keyed_storage_key = keyed_map_returned_borrow_storage_key(&base_storage_key, &key);
            self.remove_returned_borrow_origins_for_storage_key(&keyed_storage_key);
            self.returned_borrow_keyed_map_known_occupied
                .remove(&keyed_storage_key);
            storage_keys.insert(keyed_storage_key);
        } else {
            let prefix = keyed_map_returned_borrow_storage_prefix(&base_storage_key);
            self.remove_returned_borrow_origins_for_storage_prefix(&prefix);
            self.remove_keyed_map_known_occupied_for_storage_prefix(&prefix);
            storage_prefixes.insert(prefix);
        }

        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.returned_borrow_storage_mutation_barriers
            .push(ReturnedBorrowStorageMutationBarrier {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:summary"),
                order_key: mir_order_key(location),
                storage_keys,
                storage_prefixes,
            });
    }

    fn record_returned_borrow_indexed_sequence_constructor_call(
        &mut self,
        callee_def_path: &str,
        destination: &Place<'tcx>,
    ) {
        let destination_type_name = destination
            .ty(&self.body.local_decls, self.tcx)
            .ty
            .to_string();
        if !returned_borrow_indexed_sequence_empty_constructor_call(
            callee_def_path,
            &destination_type_name,
        ) {
            return;
        }
        let Some(storage_key) = self.returned_borrow_storage_key(destination) else {
            return;
        };
        self.remove_returned_borrow_origins_for_storage_prefix(
            &indexed_sequence_returned_borrow_storage_prefix(&storage_key),
        );
        self.returned_borrow_sequence_lengths.insert(storage_key, 0);
    }

    fn record_returned_borrow_keyed_map_constructor_call(
        &mut self,
        callee_def_path: &str,
        destination: &Place<'tcx>,
    ) {
        let destination_type_name = destination
            .ty(&self.body.local_decls, self.tcx)
            .ty
            .to_string();
        if !returned_borrow_keyed_map_empty_constructor_call(
            callee_def_path,
            &destination_type_name,
        ) {
            return;
        }
        let Some(storage_key) = self.returned_borrow_storage_key(destination) else {
            return;
        };
        self.remove_returned_borrow_origins_for_storage_prefix(
            &keyed_map_returned_borrow_storage_prefix(&storage_key),
        );
        self.remove_keyed_map_known_occupied_for_storage_prefix(
            &keyed_map_returned_borrow_storage_prefix(&storage_key),
        );
        self.returned_borrow_keyed_map_known_empty
            .insert(storage_key);
    }

    fn record_returned_borrow_indexed_sequence_length_mutation_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    ) {
        let Some(first_arg) = args.first() else {
            return;
        };
        let storage_type_name = first_arg
            .node
            .ty(&self.body.local_decls, self.tcx)
            .to_string();
        if !returned_borrow_indexed_sequence_storage_type(&storage_type_name) {
            return;
        }
        let Some(storage_key) = first_arg
            .node
            .place()
            .and_then(|place| self.returned_borrow_storage_key(&place))
        else {
            return;
        };
        let Some(method) = method_name(callee_def_path) else {
            return;
        };
        match method.as_str() {
            "push" | "push_back" => {
                if let Some(length) = self.returned_borrow_sequence_lengths.get_mut(&storage_key) {
                    *length = length.saturating_add(1);
                }
            }
            "insert" => {
                if let Some(index) = returned_borrow_collection_insert_index(
                    callee_def_path,
                    args,
                    &self.stable_constant_origins,
                ) && let Some(length) =
                    self.returned_borrow_sequence_lengths.get_mut(&storage_key)
                    && index
                        .parse::<usize>()
                        .ok()
                        .is_some_and(|index| index <= *length)
                {
                    *length = length.saturating_add(1);
                } else {
                    self.returned_borrow_sequence_lengths.remove(&storage_key);
                }
            }
            "clear" => {
                self.returned_borrow_sequence_lengths.insert(storage_key, 0);
            }
            _ => {}
        }
    }

    fn observe_returned_borrow_collection_persist_summary_call(
        &mut self,
        callee_def_id: DefId,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        let Some(analysis) = summarize_returned_borrow_collection_persist_callable(
            self.tcx,
            self.current_crate_name,
            callee_def_id,
        ) else {
            return;
        };
        for gap in analysis.binding_gaps {
            if args
                .get(gap.storage_arg_index)
                .and_then(|arg| arg.node.place())
                .and_then(|place| self.returned_borrow_storage_key(&place))
                .is_some()
            {
                self.record_object_binding_gap_at_callsite(
                    gap.gap_kind,
                    Some(gap.adapter),
                    span,
                    location,
                    "summary_entry_value_wrapper",
                );
            }
        }
        let Some(summary) = analysis.summary else {
            return;
        };
        let Some(storage_arg) = args.get(summary.storage_arg_index) else {
            return;
        };
        let Some(base_storage_key) = storage_arg
            .node
            .place()
            .and_then(|place| self.returned_borrow_storage_key(&place))
        else {
            return;
        };
        let Some(key) = args.get(summary.key_arg_index).and_then(|arg| {
            scoped_key_operand_key(
                &arg.node,
                &self.stable_constant_origins,
                &self.scoped_key_origins,
                &self.dynamic_key_generations,
                &self.owner_def_path,
            )
        }) else {
            return;
        };
        let storage_key = keyed_map_returned_borrow_storage_key(&base_storage_key, &key);
        let storage_type_name = storage_arg
            .node
            .ty(&self.body.local_decls, self.tcx)
            .to_string();
        self.push_persisted_returned_borrow(
            summary.origin,
            storage_type_name,
            span,
            location,
            Some(storage_key),
        );
    }

    fn remove_returned_borrow_origins_for_storage_key(&mut self, storage_key: &str) {
        self.returned_borrow_storage_origins.remove(storage_key);
    }

    fn record_returned_borrow_storage_mutation_barrier_for_key(
        &mut self,
        storage_key: String,
        span: Span,
        location: Location,
        location_suffix: &str,
    ) {
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.returned_borrow_storage_mutation_barriers
            .push(ReturnedBorrowStorageMutationBarrier {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:{location_suffix}"),
                order_key: mir_order_key(location),
                storage_keys: BTreeSet::from([storage_key]),
                storage_prefixes: BTreeSet::new(),
            });
    }

    fn remove_returned_borrow_origins_for_storage_prefix(&mut self, storage_prefix: &str) {
        self.returned_borrow_storage_origins
            .retain(|storage_key, _| !storage_key.starts_with(storage_prefix));
    }

    fn remove_keyed_map_known_occupied_for_storage_prefix(&mut self, storage_prefix: &str) {
        self.returned_borrow_keyed_map_known_occupied
            .retain(|storage_key| !storage_key.starts_with(storage_prefix));
    }

    fn clear_returned_borrow_storage_key(&mut self, storage_key: &str) {
        self.returned_borrow_invalidated_storage_keys
            .remove(storage_key);
        self.returned_borrow_keyed_map_known_empty
            .remove(storage_key);
        self.remove_keyed_map_known_occupied_for_storage_prefix(
            &keyed_map_returned_borrow_storage_prefix(storage_key),
        );
        self.returned_borrow_storage_origins.remove(storage_key);
        self.returned_borrow_storage_reference_origins
            .retain(|_, origin| origin.as_deref() != Some(storage_key));
        self.returned_borrow_indexed_iterator_storage_origins
            .retain(|_, origin| {
                origin
                    .as_ref()
                    .is_none_or(|origin| origin.storage_key != storage_key)
            });
        self.returned_borrow_slice_storage_origins
            .retain(|_, origin| origin.storage_key != storage_key);
        self.returned_borrow_unique_storage_origins
            .retain(|_, origin| origin != storage_key);
    }

    fn record_keyed_map_remove_returned_borrow_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        if method_name(callee_def_path).as_deref() != Some("remove")
            || !destination.projection.is_empty()
            || !ty_contains_ref(destination.ty(&self.body.local_decls, self.tcx).ty)
        {
            return;
        }
        let Some(first_arg) = args.first() else {
            return;
        };
        let storage_type_name = first_arg
            .node
            .ty(&self.body.local_decls, self.tcx)
            .to_string();
        if !returned_borrow_keyed_map_storage_type(&storage_type_name) {
            return;
        }
        let Some(base_storage_key) = first_arg
            .node
            .place()
            .and_then(|place| self.returned_borrow_storage_key(&place))
        else {
            return;
        };
        let Some(key) = returned_borrow_keyed_map_argument_key(
            args,
            &self.stable_constant_origins,
            &self.scoped_key_origins,
            &self.dynamic_key_generations,
            &self.owner_def_path,
        ) else {
            return;
        };
        let keyed_storage_key = keyed_map_returned_borrow_storage_key(&base_storage_key, &key);
        let Some(origins) = self.returned_borrow_storage_origins.get(&keyed_storage_key) else {
            return;
        };
        let Some(origin) = unique_returned_borrow_origin_from_persisted_observations(origins)
        else {
            return;
        };
        self.returned_borrow_origins
            .insert(destination.local, Some(origin.clone()));
        let destination_type_name = destination
            .ty(&self.body.local_decls, self.tcx)
            .ty
            .to_string();
        let local_storage_key = self.returned_borrow_local_storage_key(destination.local);
        self.push_persisted_returned_borrow(
            origin,
            destination_type_name,
            span,
            location,
            Some(local_storage_key),
        );
    }

    fn record_keyed_map_remove_returned_borrow_summary_call(
        &mut self,
        callee_def_id: DefId,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        if !destination.projection.is_empty()
            || !ty_contains_ref(destination.ty(&self.body.local_decls, self.tcx).ty)
        {
            return;
        }
        let Some(summary) =
            summarize_returned_borrow_collection_remove_return_callable(self.tcx, callee_def_id)
        else {
            return;
        };
        let Some(base_storage_key) = args
            .get(summary.storage_arg_index)
            .and_then(|arg| arg.node.place())
            .and_then(|place| self.returned_borrow_storage_key(&place))
        else {
            return;
        };
        let Some(key) = args.get(summary.key_arg_index).and_then(|arg| {
            scoped_key_operand_key(
                &arg.node,
                &self.stable_constant_origins,
                &self.scoped_key_origins,
                &self.dynamic_key_generations,
                &self.owner_def_path,
            )
        }) else {
            return;
        };
        let keyed_storage_key = keyed_map_returned_borrow_storage_key(&base_storage_key, &key);
        let Some(origins) = self.returned_borrow_storage_origins.get(&keyed_storage_key) else {
            return;
        };
        let Some(origin) = unique_returned_borrow_origin_from_persisted_observations(origins)
        else {
            return;
        };
        self.returned_borrow_origins
            .insert(destination.local, Some(origin.clone()));
        let destination_type_name = destination
            .ty(&self.body.local_decls, self.tcx)
            .ty
            .to_string();
        let local_storage_key = self.returned_borrow_local_storage_key(destination.local);
        self.push_persisted_returned_borrow(
            origin,
            destination_type_name,
            span,
            location,
            Some(local_storage_key),
        );
    }

    fn observe_returned_borrow_storage_use_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        if !returned_borrow_storage_use_call(callee_def_path)
            || !args.iter().any(|arg| {
                returned_borrow_storage_use_type(arg.node.ty(&self.body.local_decls, self.tcx))
            })
        {
            return;
        }
        let mut storage_keys = BTreeSet::new();
        for arg in args {
            if !returned_borrow_storage_use_type(arg.node.ty(&self.body.local_decls, self.tcx)) {
                continue;
            }
            let storage_type_name = arg.node.ty(&self.body.local_decls, self.tcx).to_string();
            let indexed_sequence_use =
                returned_borrow_indexed_sequence_use_call(callee_def_path, &storage_type_name);
            let keyed_map_use =
                returned_borrow_keyed_map_use_call(callee_def_path, &storage_type_name);
            let map_key = keyed_map_use
                .then(|| {
                    returned_borrow_keyed_map_use_key(
                        callee_def_path,
                        args,
                        &self.stable_constant_origins,
                        &self.scoped_key_origins,
                        &self.dynamic_key_generations,
                        &self.owner_def_path,
                    )
                })
                .flatten();
            if keyed_map_use {
                self.record_keyed_map_key_contract_gap_if_needed(
                    callee_def_path,
                    args,
                    &storage_type_name,
                    span,
                    location,
                    "key_contract",
                );
            }
            let slice_origin = arg
                .node
                .place()
                .and_then(|place| self.returned_borrow_slice_storage_origin_from_place(&place));
            let Some(storage_key) = arg
                .node
                .place()
                .and_then(|place| self.returned_borrow_storage_key(&place))
            else {
                continue;
            };
            let base_storage_key = slice_origin
                .as_ref()
                .map(|origin| origin.storage_key.clone())
                .unwrap_or_else(|| storage_key.clone());
            let collection_index = indexed_sequence_use
                .then(|| {
                    if let Some(origin) = &slice_origin {
                        returned_borrow_slice_collection_use_index_for_storage(
                            callee_def_path,
                            args,
                            origin,
                            &base_storage_key,
                            &self.returned_borrow_sequence_lengths,
                            &self.stable_constant_origins,
                        )
                    } else {
                        returned_borrow_collection_use_index_for_storage(
                            callee_def_path,
                            args,
                            &base_storage_key,
                            &self.returned_borrow_sequence_lengths,
                            &self.stable_constant_origins,
                        )
                    }
                })
                .flatten();
            if let Some(index) = &collection_index {
                storage_keys.insert(indexed_returned_borrow_storage_key(
                    &base_storage_key,
                    index,
                ));
            } else if indexed_sequence_use
                && let Some(gap_kind) =
                    self.indexed_sequence_collection_use_gap(callee_def_path, args, &storage_key)
            {
                self.record_object_binding_gap_at_callsite(
                    gap_kind,
                    method_name(callee_def_path),
                    span,
                    location,
                    "collection_use",
                );
            }
            if let Some(key) = &map_key {
                storage_keys.insert(keyed_map_returned_borrow_storage_key(&storage_key, key));
            }
            if !keyed_map_use && (!indexed_sequence_use || collection_index.is_some()) {
                storage_keys.insert(storage_key);
            }
        }
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.returned_borrow_storage_uses
            .push(ReturnedBorrowStorageUse {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}"),
                order_key: mir_order_key(location),
                storage_keys,
            });
    }

    fn observe_returned_borrow_value_argument_use_call(
        &mut self,
        callee_def_id: DefId,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        if callee_def_path == self.owner_def_path
            || returned_borrow_storage_use_call(callee_def_path)
        {
            return;
        }
        let Some(summary) = summarize_returned_borrow_value_use_callable(self.tcx, callee_def_id)
        else {
            return;
        };
        let Some(arg) = args.get(summary.value_arg_index) else {
            return;
        };
        let arg_ty = arg.node.ty(&self.body.local_decls, self.tcx);
        if !returned_borrow_value_argument_use_type(arg_ty) {
            return;
        }
        let Some(place) = arg.node.place() else {
            return;
        };
        let storage_keys = self.returned_borrow_value_use_storage_keys_from_place(&place);
        if storage_keys.is_empty() {
            return;
        }
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.returned_borrow_storage_uses
            .push(ReturnedBorrowStorageUse {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:argument_use"),
                order_key: mir_order_key(location),
                storage_keys,
            });
    }

    fn returned_borrow_value_use_storage_keys_from_place(
        &self,
        place: &Place<'tcx>,
    ) -> BTreeSet<String> {
        let mut storage_keys = BTreeSet::new();
        if let Some(storage_key) = self.returned_borrow_storage_key(place)
            && self
                .returned_borrow_storage_origins
                .contains_key(&storage_key)
        {
            storage_keys.insert(storage_key);
        }
        for origin in self.returned_borrow_storage_origins_from_place(place) {
            if let Some(storage_key) = origin.storage_key {
                storage_keys.insert(storage_key);
            }
        }
        storage_keys
    }

    fn observe_returned_borrow_wrapper_destructure_call(
        &mut self,
        callee_def_id: DefId,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: Option<&Place<'tcx>>,
        span: Span,
        location: Location,
    ) {
        let Some(summary) =
            summarize_returned_borrow_wrapper_destructure_callable(self.tcx, callee_def_id)
        else {
            return;
        };
        let Some(arg_place) = args
            .get(summary.wrapper_arg_index)
            .and_then(|arg| arg.node.place())
        else {
            return;
        };
        let Some(wrapper_local) = self.returned_borrow_local_wrapper_source_local(&arg_place)
        else {
            return;
        };
        let storage_key = self
            .returned_borrow_local_wrapper_field_storage_key(wrapper_local, &summary.field_path);
        let Some(origins) = self
            .returned_borrow_storage_origins
            .get(&storage_key)
            .cloned()
        else {
            return;
        };
        if origins.is_empty() {
            return;
        }
        if let Some(destination) = destination
            && destination.projection.is_empty()
        {
            self.propagate_returned_borrow_storage_origins(destination, origins);
        }
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.returned_borrow_storage_uses
            .push(ReturnedBorrowStorageUse {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:wrapper_destructure"),
                order_key: mir_order_key(location),
                storage_keys: BTreeSet::from([storage_key.clone()]),
            });
        if summary.clears_source {
            self.clear_returned_borrow_storage_key(&storage_key);
        }
    }

    fn observe_returned_borrow_return_terminator_use(&mut self, span: Span, location: Location) {
        let return_local = Local::new(0);
        if !ty_contains_ref(self.body.local_decls[return_local].ty) {
            return;
        }
        let return_order = mir_order_key(location);
        let Some(last_invalidation_order) = self
            .returned_borrow_invalidations
            .iter()
            .filter(|invalidation| {
                invalidation.owner_def_path == self.owner_def_path
                    && invalidation.order_key < return_order
            })
            .map(|invalidation| invalidation.order_key)
            .max()
        else {
            return;
        };
        if self.returned_borrow_storage_uses.iter().any(|use_site| {
            use_site.owner_def_path == self.owner_def_path
                && last_invalidation_order < use_site.order_key
                && use_site.order_key < return_order
        }) {
            return;
        }
        let storage_key = self.returned_borrow_local_storage_key(return_local);
        if !self
            .returned_borrow_storage_origins
            .get(&storage_key)
            .is_some_and(|origins| !origins.is_empty())
        {
            return;
        }
        self.record_returned_borrow_storage_use_for_keys(
            BTreeSet::from([storage_key]),
            span,
            location,
            "return_value_use",
        );
    }

    fn returned_borrow_local_wrapper_source_local(&self, place: &Place<'tcx>) -> Option<Local> {
        if !place.projection.is_empty() {
            return None;
        }
        if place.local.index() > self.body.arg_count {
            let prefix = self.returned_borrow_local_wrapper_field_storage_key_prefix(place.local);
            if self
                .returned_borrow_storage_origins
                .keys()
                .any(|storage_key| storage_key.starts_with(&prefix))
            {
                return Some(place.local);
            }
        }
        self.returned_borrow_local_wrapper_reference_origins
            .get(&place.local)
            .copied()
    }

    fn observe_returned_borrow_option_take_replace_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: Option<&Place<'tcx>>,
        span: Span,
        location: Location,
    ) {
        let Some(first_arg) = args.first() else {
            return;
        };
        let storage_arg_type_name = first_arg
            .node
            .ty(&self.body.local_decls, self.tcx)
            .to_string();
        if !returned_borrow_option_take_or_replace_call(
            callee_def_path,
            args,
            &storage_arg_type_name,
        ) {
            return;
        }
        let Some(source_key) = first_arg
            .node
            .place()
            .and_then(|place| self.returned_borrow_storage_key(&place))
        else {
            return;
        };
        let Some(origins) = self
            .returned_borrow_storage_origins
            .get(&source_key)
            .cloned()
        else {
            return;
        };
        if origins.is_empty() {
            return;
        }

        if let Some(destination) = destination
            && destination.projection.is_empty()
        {
            self.propagate_returned_borrow_storage_origins(destination, origins.clone());
        }
        self.record_returned_borrow_storage_use_for_keys(
            BTreeSet::from([source_key.clone()]),
            span,
            location,
            "option_take_replace",
        );
        self.clear_returned_borrow_storage_key(&source_key);

        if returned_borrow_replace_call(callee_def_path) {
            self.record_returned_borrow_replacement_origin_at_storage_key(
                args.get(1).map(|arg| &arg.node),
                first_arg,
                &source_key,
                span,
                location,
            );
        }
    }

    fn record_returned_borrow_replacement_origin_at_storage_key(
        &mut self,
        replacement: Option<&Operand<'tcx>>,
        storage_arg: &super::rustc_span::Spanned<Operand<'tcx>>,
        storage_key: &str,
        span: Span,
        location: Location,
    ) {
        let Some(replacement) = replacement else {
            return;
        };
        if let Some(origin) = self.returned_borrow_origin_from_operand(replacement, span, location)
        {
            self.push_persisted_returned_borrow(
                origin,
                storage_arg
                    .node
                    .ty(&self.body.local_decls, self.tcx)
                    .to_string(),
                span,
                location,
                Some(storage_key.to_owned()),
            );
            return;
        }
        let origins = self.returned_borrow_storage_origins_from_operand(replacement);
        if !origins.is_empty() {
            self.remember_persisted_returned_borrow_at_storage_key(storage_key.to_owned(), origins);
        }
    }

    fn record_returned_borrow_storage_use_for_keys(
        &mut self,
        storage_keys: BTreeSet<String>,
        span: Span,
        location: Location,
        suffix: &str,
    ) {
        if storage_keys.is_empty() {
            return;
        }
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.returned_borrow_storage_uses
            .push(ReturnedBorrowStorageUse {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:{suffix}"),
                order_key: mir_order_key(location),
                storage_keys,
            });
    }

    fn observe_returned_borrow_storage_use_summary_call(
        &mut self,
        callee_def_id: DefId,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        let Some(analysis) =
            summarize_returned_borrow_collection_use_callable(self.tcx, callee_def_id)
        else {
            return;
        };
        for gap in analysis.binding_gaps {
            if args
                .get(gap.storage_arg_index)
                .and_then(|arg| arg.node.place())
                .and_then(|place| self.returned_borrow_storage_key(&place))
                .is_some()
            {
                self.record_object_binding_gap_at_callsite(
                    gap.gap_kind,
                    Some(gap.adapter),
                    span,
                    location,
                    "summary_adapter",
                );
            }
        }
        let Some(summary) = analysis.summary else {
            return;
        };
        let Some(storage_arg_place) = args
            .get(summary.storage_arg_index)
            .and_then(|arg| arg.node.place())
        else {
            return;
        };
        let storage_arg_type_name = args
            .get(summary.storage_arg_index)
            .map(|arg| {
                arg.node
                    .ty(&self.body.local_decls, self.tcx)
                    .to_string()
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        let storage_arg_is_option_slice = storage_arg_type_name.contains("option<&[")
            || storage_arg_type_name.contains("option<&mut [");
        let slice_origin = self.returned_borrow_slice_storage_origin_from_place(&storage_arg_place);
        let Some(storage_key) = self.returned_borrow_storage_key(&storage_arg_place) else {
            return;
        };
        let base_storage_key = slice_origin
            .as_ref()
            .map(|origin| origin.storage_key.clone())
            .unwrap_or_else(|| storage_key.clone());
        if let Some(min_sequence_len) = summary.min_sequence_len {
            let Some(length) = self.returned_borrow_sequence_lengths.get(&base_storage_key) else {
                self.record_object_binding_gap_at_callsite(
                    ObjectBindingGapKind::SequenceLengthUnknown,
                    Some(
                        if summary.index_from_tail {
                            "tail_read"
                        } else {
                            "sequence_length"
                        }
                        .to_owned(),
                    ),
                    span,
                    location,
                    "summary_adapter",
                );
                return;
            };
            if *length < min_sequence_len {
                return;
            }
        }
        let storage_key = if let Some(key_arg_index) = summary.key_arg_index {
            let Some(key) = args.get(key_arg_index).and_then(|arg| {
                scoped_key_operand_key(
                    &arg.node,
                    &self.stable_constant_origins,
                    &self.scoped_key_origins,
                    &self.dynamic_key_generations,
                    &self.owner_def_path,
                )
            }) else {
                return;
            };
            keyed_map_returned_borrow_storage_key(&base_storage_key, &key)
        } else if summary.index_from_tail {
            let tail_offset = match summary.index_key.as_deref() {
                Some(index_key) => match index_key.parse::<usize>() {
                    Ok(offset) => offset,
                    Err(_) => return,
                },
                None => 0,
            };
            let Some(index) = self
                .returned_borrow_sequence_lengths
                .get(&base_storage_key)
                .and_then(|length| length.checked_sub(1))
                .and_then(|last_index| last_index.checked_sub(tail_offset))
            else {
                self.record_object_binding_gap_at_callsite(
                    ObjectBindingGapKind::SequenceLengthUnknown,
                    Some("tail_read".to_owned()),
                    span,
                    location,
                    "summary_adapter",
                );
                return;
            };
            indexed_returned_borrow_storage_key(&base_storage_key, &index.to_string())
        } else if let Some(index) = summary.index_key {
            if let Some(origin) = slice_origin.as_ref() {
                let Some(index) = slice_origin_adjusted_index(origin, &index) else {
                    return;
                };
                indexed_returned_borrow_storage_key(&base_storage_key, &index)
            } else if storage_arg_is_option_slice {
                storage_key
            } else {
                indexed_returned_borrow_storage_key(&base_storage_key, &index)
            }
        } else {
            storage_key
        };
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.returned_borrow_storage_uses
            .push(ReturnedBorrowStorageUse {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:summary"),
                order_key: mir_order_key(location),
                storage_keys: BTreeSet::from([storage_key]),
            });
    }

    fn observe_cross_crate_returned_borrow_collection_lookup_contract(
        &mut self,
        callee_def_id: DefId,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: Option<&Place<'tcx>>,
        span: Span,
        location: Location,
    ) -> bool {
        if callee_def_id.as_local().is_some() || returned_borrow_storage_use_call(callee_def_path) {
            return false;
        }
        if self.returned_borrow_keyed_map_mutation_call(callee_def_path, args) {
            return false;
        }
        let Some(destination) = destination else {
            return false;
        };
        if !ty_contains_ref(destination.ty(&self.body.local_decls, self.tcx).ty) {
            return false;
        }
        let Some(contract) = self
            .collection_lookup_contracts
            .iter()
            .find(|contract| audited_collection_lookup_contract(contract, callee_def_path))
        else {
            return false;
        };
        let Some(storage_arg) = args.get(contract.storage_arg_index) else {
            return false;
        };
        let storage_type_name = storage_arg
            .node
            .ty(&self.body.local_decls, self.tcx)
            .to_string();
        if !returned_borrow_keyed_map_storage_type(&storage_type_name) {
            return false;
        }
        let Some(storage_arg_place) = storage_arg.node.place() else {
            return false;
        };
        let Some(base_storage_key) = self.returned_borrow_storage_key(&storage_arg_place) else {
            return false;
        };
        let Some(key_arg) = args.get(contract.key_arg_index) else {
            return false;
        };
        if !returned_borrow_collection_lookup_key_arg_type(
            &key_arg
                .node
                .ty(&self.body.local_decls, self.tcx)
                .to_string(),
        ) {
            return false;
        }
        let Some(key) = scoped_key_operand_key(
            &key_arg.node,
            &self.stable_constant_origins,
            &self.scoped_key_origins,
            &self.dynamic_key_generations,
            &self.owner_def_path,
        ) else {
            return false;
        };
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return false;
        };
        self.returned_borrow_storage_uses
            .push(ReturnedBorrowStorageUse {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:cross_crate_collection_lookup_contract"),
                order_key: mir_order_key(location),
                storage_keys: BTreeSet::from([keyed_map_returned_borrow_storage_key(
                    &base_storage_key,
                    &key,
                )]),
            });
        true
    }

    fn observe_cross_crate_returned_borrow_collection_lookup_gap(
        &mut self,
        callee_def_id: DefId,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: Option<&Place<'tcx>>,
        span: Span,
        location: Location,
    ) {
        if callee_def_id.as_local().is_some() || returned_borrow_storage_use_call(callee_def_path) {
            return;
        }
        if self.returned_borrow_keyed_map_mutation_call(callee_def_path, args) {
            return;
        }
        let Some(destination) = destination else {
            return;
        };
        if !ty_contains_ref(destination.ty(&self.body.local_decls, self.tcx).ty) {
            return;
        }
        let has_key_arg = args.iter().any(|arg| {
            returned_borrow_collection_lookup_key_arg_type(
                &arg.node.ty(&self.body.local_decls, self.tcx).to_string(),
            )
        });
        if !has_key_arg {
            return;
        }
        let has_keyed_storage_arg = args.iter().any(|arg| {
            let storage_type_name = arg.node.ty(&self.body.local_decls, self.tcx).to_string();
            returned_borrow_keyed_map_storage_type(&storage_type_name)
                && arg
                    .node
                    .place()
                    .and_then(|place| self.returned_borrow_storage_key(&place))
                    .is_some()
        });
        if !has_keyed_storage_arg {
            return;
        }
        self.record_object_binding_gap_at_callsite(
            ObjectBindingGapKind::KeyContract,
            Some("cross_crate_collection_lookup".to_owned()),
            span,
            location,
            "cross_crate_collection_lookup",
        );
    }

    fn observe_returned_borrow_indexed_iterator_next_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        let Some(method) = method_name(callee_def_path) else {
            return;
        };
        if !matches!(method.as_str(), "next" | "nth" | "last") {
            return;
        };
        let Some(origin) = args.first().and_then(|arg| {
            self.returned_borrow_indexed_iterator_storage_origin_from_operand(&arg.node)
        }) else {
            return;
        };
        let index = match method.as_str() {
            "next" => returned_borrow_iterator_directional_index(
                &origin,
                &self.returned_borrow_sequence_lengths,
                0,
            ),
            "nth" => returned_borrow_iterator_nth_index(
                callee_def_path,
                args,
                &self.stable_constant_origins,
            )
            .and_then(|offset| {
                returned_borrow_iterator_directional_index(
                    &origin,
                    &self.returned_borrow_sequence_lengths,
                    offset,
                )
            }),
            "last" => {
                returned_borrow_iterator_last_index(&origin, &self.returned_borrow_sequence_lengths)
            }
            _ => None,
        };
        let Some(index) = index else {
            if let Some(gap_kind) =
                self.indexed_iterator_use_gap(method.as_str(), callee_def_path, args, &origin)
            {
                self.record_object_binding_gap_at_callsite(
                    gap_kind,
                    Some(method),
                    span,
                    location,
                    "iterator_use",
                );
            }
            return;
        };
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.returned_borrow_storage_uses
            .push(ReturnedBorrowStorageUse {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:iter_next"),
                order_key: mir_order_key(location),
                storage_keys: BTreeSet::from([indexed_returned_borrow_storage_key(
                    &origin.storage_key,
                    &index.to_string(),
                )]),
            });
        self.returned_borrow_indexed_iterator_storage_origins
            .retain(|_, candidate| {
                candidate
                    .as_ref()
                    .is_none_or(|candidate| candidate.storage_key != origin.storage_key)
            });
    }

    fn record_returned_borrow_iterator_adapter_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
    ) {
        if destination.projection.is_empty() {
            let origin =
                self.returned_borrow_iterator_origin_from_adapter_call(callee_def_path, args);
            self.returned_borrow_iterator_origins
                .insert(destination.local, origin);
        }
    }

    fn returned_borrow_iterator_origin_from_adapter_call(
        &self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    ) -> Option<ReturnedBorrowOrigin> {
        if returned_borrow_iterator_adapter_call(callee_def_path) {
            return self
                .unique_returned_borrow_callable_origin_from_args(args)
                .or_else(|| self.returned_borrow_passthrough_arg_origin(args));
        }
        if returned_borrow_iterator_passthrough_call(callee_def_path) {
            return self.returned_borrow_passthrough_arg_origin(args);
        }
        None
    }

    fn unique_returned_borrow_callable_origin_from_args(
        &self,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    ) -> Option<ReturnedBorrowOrigin> {
        let mut origin = None;
        for arg in args.iter().skip(1) {
            let Some(def_id) =
                callback_def_id_from_ty(arg.node.ty(&self.body.local_decls, self.tcx))
            else {
                continue;
            };
            let Some(candidate) =
                summarize_returned_borrow_callable(self.tcx, self.current_crate_name, def_id)
            else {
                continue;
            };
            if let Some(existing) = &origin
                && existing != &candidate
            {
                return None;
            }
            origin = Some(candidate);
        }
        origin
    }

    fn returned_borrow_passthrough_arg_origin(
        &self,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    ) -> Option<ReturnedBorrowOrigin> {
        args.first()
            .and_then(|arg| self.returned_borrow_iterator_origin_from_operand(&arg.node))
    }

    fn returned_borrow_iterator_origin_from_operand(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<ReturnedBorrowOrigin> {
        let place = operand.place()?;
        if !place.projection.is_empty() {
            return None;
        }
        self.returned_borrow_iterator_origins
            .get(&place.local)
            .cloned()
            .flatten()
    }

    fn record_returned_borrow_indexed_sequence_iterator_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
    ) {
        if !destination.projection.is_empty() {
            return;
        }
        let Some(first_arg) = args.first() else {
            return;
        };
        let source_type_name = first_arg
            .node
            .ty(&self.body.local_decls, self.tcx)
            .to_string();
        if !returned_borrow_indexed_sequence_iterator_call(callee_def_path, &source_type_name) {
            return;
        }
        let slice_origin = first_arg
            .node
            .place()
            .and_then(|place| self.returned_borrow_slice_storage_origin_from_place(&place));
        let storage_key = if let Some(slice_origin) = slice_origin {
            Some(IndexedIteratorStorageOrigin {
                storage_key: slice_origin.storage_key,
                front_offset: slice_origin.start_offset,
                back_offset: 0,
                take_limit: slice_origin
                    .end_offset
                    .and_then(|end_offset| end_offset.checked_sub(slice_origin.start_offset)),
                take_from_back: slice_origin.end_offset.map(|_| false),
                from_back: false,
                allow_forward_without_sequence_length: true,
            })
        } else {
            first_arg
                .node
                .place()
                .and_then(|place| self.returned_borrow_storage_key(&place))
                .map(|storage_key| IndexedIteratorStorageOrigin {
                    storage_key,
                    front_offset: 0,
                    back_offset: 0,
                    take_limit: None,
                    take_from_back: None,
                    from_back: false,
                    allow_forward_without_sequence_length: false,
                })
        };
        self.returned_borrow_indexed_iterator_storage_origins
            .insert(destination.local, storage_key);
    }

    fn record_returned_borrow_indexed_iterator_offset_adapter_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        if !destination.projection.is_empty() {
            return;
        }
        let Some(origin) = args.first().and_then(|arg| {
            self.returned_borrow_indexed_iterator_storage_origin_from_operand(&arg.node)
        }) else {
            return;
        };
        let Some(method) = method_name(callee_def_path) else {
            return;
        };
        let origin = match method.as_str() {
            "skip" => {
                let Some(offset) = returned_borrow_iterator_skip_index(
                    callee_def_path,
                    args,
                    &self.stable_constant_origins,
                ) else {
                    self.record_object_binding_gap_at_callsite(
                        ObjectBindingGapKind::DynamicIndex,
                        Some(method),
                        span,
                        location,
                        "iterator_adapter",
                    );
                    return;
                };
                if origin.from_back {
                    let Some((take_limit, take_from_back)) =
                        returned_borrow_iterator_take_after_skip(
                            origin.take_limit,
                            origin.take_from_back,
                            origin.from_back,
                            offset,
                        )
                    else {
                        return;
                    };
                    origin.back_offset.checked_add(offset).map(|back_offset| {
                        IndexedIteratorStorageOrigin {
                            storage_key: origin.storage_key,
                            front_offset: origin.front_offset,
                            back_offset,
                            take_limit,
                            take_from_back,
                            from_back: origin.from_back,
                            allow_forward_without_sequence_length: origin
                                .allow_forward_without_sequence_length,
                        }
                    })
                } else {
                    let Some((take_limit, take_from_back)) =
                        returned_borrow_iterator_take_after_skip(
                            origin.take_limit,
                            origin.take_from_back,
                            origin.from_back,
                            offset,
                        )
                    else {
                        return;
                    };
                    origin.front_offset.checked_add(offset).map(|front_offset| {
                        IndexedIteratorStorageOrigin {
                            storage_key: origin.storage_key,
                            front_offset,
                            back_offset: origin.back_offset,
                            take_limit,
                            take_from_back,
                            from_back: origin.from_back,
                            allow_forward_without_sequence_length: origin
                                .allow_forward_without_sequence_length,
                        }
                    })
                }
            }
            "rev" => Some(IndexedIteratorStorageOrigin {
                storage_key: origin.storage_key,
                front_offset: origin.front_offset,
                back_offset: origin.back_offset,
                take_limit: origin.take_limit,
                take_from_back: origin.take_from_back,
                from_back: !origin.from_back,
                allow_forward_without_sequence_length: origin.allow_forward_without_sequence_length,
            }),
            "take" => {
                let Some(limit) = returned_borrow_iterator_take_limit(
                    callee_def_path,
                    args,
                    &self.stable_constant_origins,
                ) else {
                    self.record_object_binding_gap_at_callsite(
                        ObjectBindingGapKind::DynamicIndex,
                        Some(method),
                        span,
                        location,
                        "iterator_adapter",
                    );
                    return;
                };
                let Some((take_limit, take_from_back)) = returned_borrow_iterator_take_after_take(
                    origin.take_limit,
                    origin.take_from_back,
                    origin.from_back,
                    limit,
                ) else {
                    return;
                };
                Some(IndexedIteratorStorageOrigin {
                    storage_key: origin.storage_key,
                    front_offset: origin.front_offset,
                    back_offset: origin.back_offset,
                    take_limit: Some(take_limit),
                    take_from_back: Some(take_from_back),
                    from_back: origin.from_back,
                    allow_forward_without_sequence_length: origin
                        .allow_forward_without_sequence_length,
                })
            }
            "copied" | "cloned" | "enumerate" => Some(origin),
            "map" if iterator_map_identity_preserving_arg(self.tcx, self.body, args) => {
                Some(origin)
            }
            "filter" if iterator_filter_always_true_arg(self.tcx, self.body, args) => Some(origin),
            "filter_map"
                if iterator_filter_map_identity_preserving_arg(self.tcx, self.body, args) =>
            {
                Some(origin)
            }
            "chain" | "filter" | "filter_map" | "flat_map" | "map" | "zip" => {
                self.record_iterator_object_binding_gap(method.as_str(), span, location);
                None
            }
            _ => return,
        };
        self.returned_borrow_indexed_iterator_storage_origins
            .insert(destination.local, origin);
    }

    fn record_iterator_object_binding_gap(&mut self, method: &str, span: Span, location: Location) {
        let Some(gap_kind) = iterator_adapter_gap_kind(method) else {
            return;
        };
        self.record_object_binding_gap_at_callsite(
            gap_kind,
            Some(method.to_owned()),
            span,
            location,
            "iterator_adapter",
        );
    }

    fn indexed_sequence_collection_use_gap(
        &self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        storage_key: &str,
    ) -> Option<ObjectBindingGapKind> {
        match method_name(callee_def_path).as_deref()? {
            "get" => {
                let index_arg = args.get(1)?;
                if usize_constant_operand_key_with_origins(
                    &index_arg.node,
                    &self.stable_constant_origins,
                )
                .is_some()
                {
                    return None;
                }
                let index_type_name = index_arg
                    .node
                    .ty(&self.body.local_decls, self.tcx)
                    .to_string();
                if range_or_slice_index_type(&index_type_name) {
                    Some(ObjectBindingGapKind::RangeOrSlice)
                } else {
                    Some(ObjectBindingGapKind::DynamicIndex)
                }
            }
            "last" | "back"
                if !self
                    .returned_borrow_sequence_lengths
                    .contains_key(storage_key) =>
            {
                Some(ObjectBindingGapKind::SequenceLengthUnknown)
            }
            _ => None,
        }
    }

    fn indexed_iterator_use_gap(
        &self,
        method: &str,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        origin: &IndexedIteratorStorageOrigin,
    ) -> Option<ObjectBindingGapKind> {
        match method {
            "nth" => {
                let Some(offset) = returned_borrow_iterator_nth_index(
                    callee_def_path,
                    args,
                    &self.stable_constant_origins,
                ) else {
                    return Some(ObjectBindingGapKind::DynamicIndex);
                };
                if !returned_borrow_iterator_take_limit_allows(origin.take_limit, offset) {
                    return None;
                }
                origin
                    .from_back
                    .then_some(ObjectBindingGapKind::SequenceLengthUnknown)
            }
            "next" if origin.from_back => Some(ObjectBindingGapKind::SequenceLengthUnknown),
            "last"
                if !self
                    .returned_borrow_sequence_lengths
                    .contains_key(&origin.storage_key) =>
            {
                Some(ObjectBindingGapKind::SequenceLengthUnknown)
            }
            _ => None,
        }
    }

    fn record_object_binding_gap_at_callsite(
        &mut self,
        gap_kind: ObjectBindingGapKind,
        adapter: Option<String>,
        span: Span,
        location: Location,
        location_suffix: &str,
    ) {
        self.record_object_binding_gap_with_bindings(
            gap_kind,
            adapter,
            span,
            location,
            location_suffix,
            None,
            None,
        );
    }

    fn record_object_binding_gap_with_bindings(
        &mut self,
        gap_kind: ObjectBindingGapKind,
        adapter: Option<String>,
        span: Span,
        location: Location,
        location_suffix: &str,
        field_path: Option<String>,
        container_type_name: Option<String>,
    ) {
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.observations
            .object_binding_gaps
            .push(ObjectBindingGapObservation {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}:{location_suffix}"),
                api_id: self.owner_def_path.clone(),
                gap_kind,
                field_path,
                container_type_name,
                adapter,
            });
    }

    fn returned_borrow_indexed_iterator_storage_origin_from_operand(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<IndexedIteratorStorageOrigin> {
        let place = operand.place()?;
        self.returned_borrow_indexed_iterator_storage_origin_from_place(&place)
    }

    fn returned_borrow_indexed_iterator_storage_origin_from_place(
        &self,
        place: &Place<'tcx>,
    ) -> Option<IndexedIteratorStorageOrigin> {
        self.returned_borrow_indexed_iterator_storage_origins
            .get(&place.local)
            .cloned()
            .flatten()
    }

    fn observe_persisted_returned_borrow_collect_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        if !persisted_returned_borrow_collect_call(callee_def_path)
            || !destination.projection.is_empty()
        {
            return;
        }
        let Some(origin) = self.returned_borrow_passthrough_arg_origin(args) else {
            return;
        };
        let storage_type_name = destination
            .ty(&self.body.local_decls, self.tcx)
            .ty
            .to_string();
        let storage_key = self.returned_borrow_storage_key(destination);
        self.push_persisted_returned_borrow(origin, storage_type_name, span, location, storage_key);
    }

    fn record_foreign_borrowed_pointer_return(
        &mut self,
        callee_def_path: &str,
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        if !foreign_borrowed_pointer_return_call(callee_def_path)
            || !matches!(
                destination.ty(&self.body.local_decls, self.tcx).ty.kind(),
                ty::RawPtr(..)
            )
        {
            return;
        }
        let Some(key) = raw_pointer_place_key(destination) else {
            return;
        };
        let source = self.borrow_reference_at(
            span,
            location,
            destination
                .ty(&self.body.local_decls, self.tcx)
                .ty
                .to_string(),
        );
        self.merge_borrowed_foreign_pointer_origin(key, source);
    }

    fn record_borrowed_view_from_foreign_pointer(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        if !borrowed_view_from_raw_pointer_call(callee_def_path)
            || !destination.projection.is_empty()
            || !matches!(
                destination.ty(&self.body.local_decls, self.tcx).ty.kind(),
                ty::Ref(..)
            )
        {
            return;
        }
        let Some(source) = args
            .first()
            .and_then(|arg| self.borrowed_foreign_pointer_reference_from_operand(&arg.node))
        else {
            self.borrow_origins.insert(destination.local, None);
            return;
        };
        self.borrow_origins
            .insert(destination.local, Some(source.clone()));
        if destination.local == Local::new(0)
            && ty_contains_ref(self.body.local_decls[Local::new(0)].ty)
        {
            self.push_returned_borrow_relation(source, span, location);
        }
    }

    fn borrow_reference_at(
        &self,
        span: Span,
        location: Location,
        type_name: String,
    ) -> Option<BorrowReference> {
        Some(BorrowReference {
            owner_def_path: self.owner_def_path.clone(),
            source_path: source_path(self.tcx, span).ok()?,
            span: stable_span(self.tcx, span).ok()?,
            mir_location: format!("{location:?}"),
            type_name,
        })
    }

    fn borrowed_foreign_pointer_reference_from_operand(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<BorrowReference> {
        let place = operand.place()?;
        let key = raw_pointer_place_key(&place)?;
        self.borrowed_foreign_pointer_origins
            .get(&key)
            .cloned()
            .flatten()
    }

    fn merge_borrowed_foreign_pointer_origin(
        &mut self,
        key: RawPointerPlaceKey,
        source: Option<BorrowReference>,
    ) {
        match self.borrowed_foreign_pointer_origins.get_mut(&key) {
            Some(existing)
                if existing
                    .as_ref()
                    .zip(source.as_ref())
                    .is_some_and(|(left, right)| left != right) =>
            {
                *existing = None;
            }
            Some(existing) if existing.is_none() || source.is_none() => {
                *existing = None;
            }
            Some(_) => {}
            None => {
                self.borrowed_foreign_pointer_origins.insert(key, source);
            }
        }
    }

    fn unique_reference_argument(&self, span: Span, location: Location) -> Option<BorrowReference> {
        let mut references = (1..=self.body.arg_count)
            .filter_map(|index| {
                let local = Local::new(index);
                let local_ty = self.body.local_decls[local].ty;
                matches!(local_ty.kind(), ty::Ref(..)).then_some(BorrowReference {
                    owner_def_path: self.owner_def_path.clone(),
                    source_path: source_path(self.tcx, span).ok()?,
                    span: stable_span(self.tcx, span).ok()?,
                    mir_location: format!("{location:?}"),
                    type_name: local_ty.to_string(),
                })
            })
            .collect::<Vec<_>>();
        (references.len() == 1).then(|| references.remove(0))
    }

    fn observe_external_buffer_binding(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        let return_ty = self.body.local_decls[Local::new(0)].ty;
        if foreign_selector_output_buffer_call(callee_def_path) && ty_contains_ref(return_ty) {
            let Some(source) = self.borrow_reference_at(
                span,
                location,
                "foreign selector output pointer from input buffers".to_owned(),
            ) else {
                return;
            };
            let key = format!(
                "{}:{}:{}",
                self.owner_def_path, source.mir_location, callee_def_path
            );
            if !self.external_buffer_binding_keys.insert(key) {
                return;
            }
            self.push_external_buffer_binding(source, return_ty.to_string(), span, location);
            return;
        }

        if let Some(buffer_type_name) = external_buffer_creation_call(callee_def_path) {
            let Some(source) = args.get(1).and_then(|arg| {
                self.external_buffer_source_reference_from_operand(&arg.node, arg.span, location)
            }) else {
                return;
            };
            self.push_external_buffer_binding(source, buffer_type_name.to_owned(), span, location);
            return;
        }

        if !callee_def_path.ends_with("::as_ptr") || !is_external_buffer_return_ty(return_ty) {
            return;
        }
        let Some(source) = args
            .first()
            .and_then(|arg| self.borrow_reference_from_operand(&arg.node, arg.span, location))
            .or_else(|| self.unique_reference_argument(span, location))
        else {
            return;
        };
        let key = format!(
            "{}:{}:{}",
            self.owner_def_path, source.mir_location, source.type_name
        );
        if !self.external_buffer_binding_keys.insert(key) {
            return;
        }
        self.push_external_buffer_binding(source, return_ty.to_string(), span, location);
    }

    fn push_external_buffer_binding(
        &mut self,
        source: BorrowReference,
        buffer_type_name: String,
        span: Span,
        location: Location,
    ) {
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.observations
            .external_buffer_bindings
            .push(ExternalBufferBindingObservation {
                owner_def_path: self.owner_def_path.clone(),
                source_path,
                span: stable_span,
                mir_location: format!("{location:?}"),
                api_id: self.owner_def_path.clone(),
                source,
                buffer_type_name,
            });
    }

    fn external_buffer_source_reference_from_operand(
        &self,
        operand: &Operand<'tcx>,
        span: Span,
        location: Location,
    ) -> Option<BorrowReference> {
        self.borrow_reference_from_operand(operand, span, location)
            .or_else(|| self.object_source_reference_from_operand(operand, span, location))
    }

    fn object_source_reference_from_operand(
        &self,
        operand: &Operand<'tcx>,
        span: Span,
        location: Location,
    ) -> Option<BorrowReference> {
        let place = operand.place()?;
        if place.local.index() == 0 {
            return None;
        }
        let type_name = place.ty(&self.body.local_decls, self.tcx).ty.to_string();
        Some(BorrowReference {
            owner_def_path: self.owner_def_path.clone(),
            source_path: source_path(self.tcx, span).ok()?,
            span: stable_span(self.tcx, span).ok()?,
            mir_location: format!("{location:?}"),
            type_name,
        })
    }

    fn record_previous_user_data_return(
        &mut self,
        api_id: &str,
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        if !registration_call_returns_previous_user_data(api_id)
            || !matches!(
                destination.ty(&self.body.local_decls, self.tcx).ty.kind(),
                ty::RawPtr(..)
            )
        {
            return;
        }
        let type_name = format!(
            "previous_user_data:{}",
            destination.ty(&self.body.local_decls, self.tcx).ty
        );
        let Some(user_data) = self.raw_pointer_reference_at(span, location, type_name) else {
            return;
        };
        self.record_raw_pointer_destination(destination, user_data);
        let Some(key) = raw_pointer_place_key(destination) else {
            return;
        };
        let Some(hook_family) = hook_family_from_api_id(api_id) else {
            return;
        };
        update_optional_origin(
            &mut self.previous_user_data_origins,
            key,
            Some(PreviousUserDataReturn {
                hook_family: hook_family.to_owned(),
            }),
        );
    }

    fn assignment_span(&self, location: Location) -> Span {
        self.body.source_info(location).span
    }

    fn raw_pointer_passthrough_call_reference(
        &self,
        callee_def_id: DefId,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    ) -> Option<RawPointerReference> {
        let arg_index = raw_pointer_passthrough_arg_index(self.tcx, callee_def_id)?;
        let arg = args.get(arg_index)?;
        matches!(
            arg.node.ty(&self.body.local_decls, self.tcx).kind(),
            ty::RawPtr(..)
        )
        .then(|| self.raw_pointer_reference_from_operand(&arg.node))
        .flatten()
    }

    fn raw_pointer_release_call_reference(
        &self,
        callee_def_id: DefId,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    ) -> Option<RawPointerReleaseCallReference> {
        let arg_key =
            raw_pointer_release_arg_place_key(self.tcx, callee_def_id, false).or_else(|| {
                raw_pointer_shared_owner_release_arg_place_key_on_any_path(self.tcx, callee_def_id)
            })?;
        let arg = args.get(arg_key.arg_index)?;
        let user_data = self
            .raw_pointer_reference_from_operand_with_projection(&arg.node, &arg_key.projection)?;
        Some(RawPointerReleaseCallReference {
            user_data,
            arg_index: arg_key.arg_index,
            projection: arg_key.projection,
            arg_type_name: arg.node.ty(&self.body.local_decls, self.tcx).to_string(),
        })
    }

    fn observe_raw_pointer_passthrough_object_flow(
        &mut self,
        callee_def_path: &str,
        destination: &Place<'tcx>,
        user_data: RawPointerReference,
        span: Span,
        location: Location,
    ) {
        let type_name = destination
            .ty(&self.body.local_decls, self.tcx)
            .ty
            .to_string();
        let Some(wrapper_site) =
            self.object_flow_static_site_endpoint_at(span, location, "wrapper_move", type_name)
        else {
            return;
        };
        let flow_source_path = object_flow_endpoint_source_path(&wrapper_site).to_path_buf();
        let flow_span = object_flow_endpoint_span(&wrapper_site).to_owned();
        self.observations.object_flows.push(object_flow_observation(
            &self.owner_def_path,
            &flow_source_path,
            &flow_span,
            &format!("{location:?}:wrapper_move"),
            callee_def_path,
            ObjectFlowEndpointObservation::UserData(user_data),
            ObjectFlowObjectKind::UserData,
            wrapper_site,
            ObjectFlowObjectKind::OpaqueHandle,
            ObjectFlowKind::WrapperMove,
            None,
            None,
        ));
    }

    fn record_raw_pointer_return_field_call(
        &mut self,
        callee_def_id: DefId,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        let Some(field_mappings) = raw_pointer_return_field_arg_mappings(self.tcx, callee_def_id)
        else {
            return;
        };
        let Some(destination_key) = raw_pointer_place_key(destination) else {
            return;
        };
        self.forget_raw_pointer_origin_prefix(&destination_key);
        for (field_path, arg_key) in field_mappings {
            let Some(arg) = args.get(arg_key.arg_index) else {
                continue;
            };
            let mut field_key = destination_key.clone();
            field_key.projection.extend(field_path.iter().cloned());
            let Some(user_data) = self
                .raw_pointer_reference_from_operand_with_projection(&arg.node, &arg_key.projection)
            else {
                continue;
            };
            self.record_raw_pointer_origin_key(field_key, Some(user_data.clone()));
            self.observe_raw_pointer_return_field_object_flow(
                callee_def_path,
                user_data,
                span,
                location,
                &field_path,
                arg.node.ty(&self.body.local_decls, self.tcx).to_string(),
            );
        }
    }

    fn record_raw_pointer_non_null_constructor_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        if !raw_pointer_non_null_constructor_call(callee_def_path)
            || !non_null_storage_ty(destination.ty(&self.body.local_decls, self.tcx).ty)
        {
            return;
        }
        let Some(destination_key) = raw_pointer_place_key(destination) else {
            return;
        };
        let Some(user_data) = args
            .first()
            .and_then(|arg| self.raw_pointer_reference_from_operand(&arg.node))
        else {
            return;
        };
        self.forget_raw_pointer_origin_prefix(&destination_key);
        let mut field_key = destination_key;
        field_key.projection.push("field:0".to_owned());
        self.record_raw_pointer_origin_key(field_key.clone(), Some(user_data.clone()));
        self.observe_raw_pointer_storage_field_store_object_flow(
            callee_def_path,
            user_data,
            span,
            location,
            &field_key.projection,
            destination
                .ty(&self.body.local_decls, self.tcx)
                .ty
                .to_string(),
            "nonnull_field_store",
        );
    }

    fn record_raw_pointer_non_null_as_ptr_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        if !raw_pointer_non_null_as_ptr_call(callee_def_path)
            || !matches!(
                destination.ty(&self.body.local_decls, self.tcx).ty.kind(),
                ty::RawPtr(..)
            )
        {
            return;
        }
        let Some(arg) = args.first() else {
            return;
        };
        if !non_null_storage_ty(arg.node.ty(&self.body.local_decls, self.tcx)) {
            return;
        }
        let Some((field_key, user_data)) =
            self.raw_pointer_origin_from_operand_storage_prefix(&arg.node)
        else {
            return;
        };
        self.record_raw_pointer_destination(destination, user_data.clone());
        self.observe_raw_pointer_storage_field_load_object_flow(
            callee_def_path,
            user_data,
            span,
            location,
            &field_key.projection,
            arg.node.ty(&self.body.local_decls, self.tcx).to_string(),
            "nonnull_field_load",
        );
    }

    fn record_raw_pointer_unique_owner_constructor_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        if !raw_pointer_deref_owner_constructor_call(callee_def_path) {
            return;
        }
        let Some(destination_key) = raw_pointer_place_key(destination) else {
            return;
        };
        if !destination_key.projection.is_empty() {
            return;
        }
        let Some(source_place) = args.first().and_then(|arg| arg.node.place()) else {
            return;
        };
        let Some(source_key) = raw_pointer_place_key(&source_place) else {
            return;
        };
        self.forget_raw_pointer_origin_prefix(&destination_key);
        let mappings = self
            .raw_pointer_origins
            .iter()
            .filter_map(|(key, origin)| {
                if key.local != source_key.local
                    || !key.projection.starts_with(&source_key.projection)
                {
                    return None;
                }
                let mut projection = vec!["deref".to_owned()];
                projection.extend_from_slice(&key.projection[source_key.projection.len()..]);
                Some((projection, origin.clone()))
            })
            .collect::<Vec<_>>();
        for (projection, origin) in mappings {
            let Some(user_data) = origin else {
                continue;
            };
            let field_key = RawPointerPlaceKey {
                local: destination_key.local,
                projection: projection.clone(),
            };
            self.record_raw_pointer_origin_key(field_key, Some(user_data.clone()));
            self.observe_raw_pointer_unique_owner_field_store_object_flow(
                callee_def_path,
                user_data,
                span,
                location,
                &projection,
                source_place
                    .ty(&self.body.local_decls, self.tcx)
                    .ty
                    .to_string(),
            );
        }
    }

    fn observe_raw_pointer_storage_field_store_object_flow(
        &mut self,
        callee_def_path: &str,
        user_data: RawPointerReference,
        span: Span,
        location: Location,
        field_path: &[String],
        type_name: String,
        role: &str,
    ) {
        let field_path = field_path.join(".");
        if field_path.is_empty() {
            return;
        }
        let Some(storage_site) = self.object_flow_static_site_endpoint_for_field_key(
            span,
            location,
            role,
            &field_path,
            type_name,
        ) else {
            return;
        };
        let flow_source_path = object_flow_endpoint_source_path(&storage_site).to_path_buf();
        let flow_span = object_flow_endpoint_span(&storage_site).to_owned();
        self.observations.object_flows.push(object_flow_observation(
            &self.owner_def_path,
            &flow_source_path,
            &flow_span,
            &format!("{location:?}:{role}:{field_path}"),
            callee_def_path,
            ObjectFlowEndpointObservation::UserData(user_data),
            ObjectFlowObjectKind::UserData,
            storage_site,
            ObjectFlowObjectKind::Storage,
            ObjectFlowKind::FieldStore,
            Some(field_path),
            None,
        ));
    }

    fn observe_raw_pointer_storage_field_load_object_flow(
        &mut self,
        callee_def_path: &str,
        user_data: RawPointerReference,
        span: Span,
        location: Location,
        field_path: &[String],
        type_name: String,
        role: &str,
    ) {
        let field_path = field_path.join(".");
        if field_path.is_empty() {
            return;
        }
        let Some(storage_site) = self.object_flow_static_site_endpoint_for_field_key(
            span,
            location,
            role,
            &field_path,
            type_name,
        ) else {
            return;
        };
        let flow_source_path = object_flow_endpoint_source_path(&storage_site).to_path_buf();
        let flow_span = object_flow_endpoint_span(&storage_site).to_owned();
        self.observations.object_flows.push(object_flow_observation(
            &self.owner_def_path,
            &flow_source_path,
            &flow_span,
            &format!("{location:?}:{role}:{field_path}"),
            callee_def_path,
            storage_site,
            ObjectFlowObjectKind::Storage,
            ObjectFlowEndpointObservation::UserData(user_data),
            ObjectFlowObjectKind::UserData,
            ObjectFlowKind::FieldLoad,
            Some(field_path),
            None,
        ));
    }

    fn record_raw_pointer_deref_reference_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
    ) {
        if !shared_owner_deref_call(callee_def_path) || !destination.projection.is_empty() {
            return;
        }
        if !matches!(
            destination.ty(&self.body.local_decls, self.tcx).ty.kind(),
            ty::Ref(..)
        ) {
            return;
        }
        let Some(arg) = args.first() else {
            return;
        };
        if shared_owner_family_token(&arg.node.ty(&self.body.local_decls, self.tcx).to_string())
            .is_none()
        {
            return;
        }
        let Some(arg_place) = arg.node.place() else {
            return;
        };
        if !arg_place.projection.is_empty() {
            return;
        }
        let Some(mut borrowed_key) = self
            .raw_pointer_borrow_origins
            .get(&arg_place.local)
            .cloned()
            .flatten()
        else {
            return;
        };
        borrowed_key.projection.push("deref".to_owned());
        update_optional_origin(
            &mut self.raw_pointer_borrow_origins,
            destination.local,
            Some(borrowed_key),
        );
    }

    fn observe_raw_pointer_unique_owner_field_store_object_flow(
        &mut self,
        callee_def_path: &str,
        user_data: RawPointerReference,
        span: Span,
        location: Location,
        field_path: &[String],
        type_name: String,
    ) {
        let field_path = field_path.join(".");
        let Some(storage_site) = self.object_flow_static_site_endpoint_for_field_key(
            span,
            location,
            "unique_owner_field_store",
            &field_path,
            type_name,
        ) else {
            return;
        };
        let flow_source_path = object_flow_endpoint_source_path(&storage_site).to_path_buf();
        let flow_span = object_flow_endpoint_span(&storage_site).to_owned();
        self.observations.object_flows.push(object_flow_observation(
            &self.owner_def_path,
            &flow_source_path,
            &flow_span,
            &format!("{location:?}:unique_owner_field_store:{field_path}"),
            callee_def_path,
            ObjectFlowEndpointObservation::UserData(user_data),
            ObjectFlowObjectKind::UserData,
            storage_site,
            ObjectFlowObjectKind::Storage,
            ObjectFlowKind::FieldStore,
            Some(field_path),
            None,
        ));
    }

    fn observe_raw_pointer_return_field_object_flow(
        &mut self,
        callee_def_path: &str,
        user_data: RawPointerReference,
        span: Span,
        location: Location,
        field_path: &[String],
        type_name: String,
    ) {
        let field_path = field_path.join(".");
        let Some(storage_site) = self.object_flow_static_site_endpoint_for_field_key(
            span,
            location,
            "return_field_store",
            &field_path,
            type_name,
        ) else {
            return;
        };
        let flow_source_path = object_flow_endpoint_source_path(&storage_site).to_path_buf();
        let flow_span = object_flow_endpoint_span(&storage_site).to_owned();
        self.observations.object_flows.push(object_flow_observation(
            &self.owner_def_path,
            &flow_source_path,
            &flow_span,
            &format!("{location:?}:return_field_store:{field_path}"),
            callee_def_path,
            ObjectFlowEndpointObservation::UserData(user_data),
            ObjectFlowObjectKind::UserData,
            storage_site,
            ObjectFlowObjectKind::Storage,
            ObjectFlowKind::FieldStore,
            Some(field_path),
            None,
        ));
    }

    fn observe_raw_pointer_release_call(
        &mut self,
        release_ref: RawPointerReleaseCallReference,
        callee_def_path: &str,
        span: Span,
        location: Location,
    ) {
        let user_data = release_ref.user_data.clone();
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        let release = RawPointerTransferObservation {
            owner_def_path: self.owner_def_path.clone(),
            source_path: source_path.clone(),
            span: stable_span.clone(),
            mir_location: format!("{location:?}"),
            basic_block: location.block.index(),
            statement_index: location.statement_index,
            kind: RawPointerTransferKind::FromRaw,
            user_data: user_data.clone(),
        };
        self.observations
            .raw_pointer_transfers
            .push(release.clone());
        let wrapper_type_name = if release_ref.projection.is_empty() {
            release_ref.arg_type_name
        } else {
            format!(
                "{}:arg{}:{}",
                release_ref.arg_type_name,
                release_ref.arg_index,
                release_ref.projection.join(".")
            )
        };
        let Some(wrapper_site) = self.object_flow_static_site_endpoint_at(
            span,
            location,
            "wrapper_release",
            wrapper_type_name,
        ) else {
            return;
        };
        self.observations.object_flows.push(object_flow_observation(
            &self.owner_def_path,
            &source_path,
            &stable_span,
            &format!("{location:?}:wrapper_move"),
            callee_def_path,
            ObjectFlowEndpointObservation::UserData(user_data.clone()),
            ObjectFlowObjectKind::UserData,
            wrapper_site.clone(),
            ObjectFlowObjectKind::OpaqueHandle,
            ObjectFlowKind::WrapperMove,
            (!release_ref.projection.is_empty()).then(|| release_ref.projection.join(".")),
            None,
        ));
        self.observations.object_flows.push(object_flow_observation(
            &self.owner_def_path,
            &source_path,
            &stable_span,
            &format!("{location:?}:wrapper_destructure"),
            callee_def_path,
            wrapper_site,
            ObjectFlowObjectKind::OpaqueHandle,
            ObjectFlowEndpointObservation::UserData(user_data),
            ObjectFlowObjectKind::UserData,
            ObjectFlowKind::WrapperDestructure,
            (!release_ref.projection.is_empty()).then(|| release_ref.projection.join(".")),
            None,
        ));
    }

    fn observe_drop_impl_release(&mut self, place: &Place<'tcx>, span: Span, location: Location) {
        let object_ty = place.ty(&self.body.local_decls, self.tcx).ty;
        let ty::Adt(adt_def, _) = object_ty.kind() else {
            return;
        };
        let Some(destructor) = adt_def.destructor(self.tcx) else {
            return;
        };
        let Some(release_arg) = raw_pointer_release_arg_place_key(self.tcx, destructor.did, false)
        else {
            return;
        };
        if release_arg.arg_index != 0 || release_arg.projection.is_empty() {
            return;
        }
        let Some(user_data) =
            self.raw_pointer_reference_from_place_with_projection(place, &release_arg.projection)
        else {
            return;
        };
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        let projection = release_arg.projection.join(".");
        let release = RawPointerTransferObservation {
            owner_def_path: self.owner_def_path.clone(),
            source_path: source_path.clone(),
            span: stable_span.clone(),
            mir_location: format!("{location:?}:drop_impl_release:{projection}"),
            basic_block: location.block.index(),
            statement_index: location.statement_index,
            kind: RawPointerTransferKind::FromRaw,
            user_data: user_data.clone(),
        };
        self.observations
            .raw_pointer_transfers
            .push(release.clone());
        let Some(wrapper_site) = self.object_flow_static_site_endpoint_at(
            span,
            location,
            "drop_impl_release",
            format!("{}:{projection}", object_ty),
        ) else {
            return;
        };
        self.observations.object_flows.push(object_flow_observation(
            &self.owner_def_path,
            &source_path,
            &stable_span,
            &format!("{location:?}:drop_impl_wrapper_move:{projection}"),
            &self.tcx.def_path_str(destructor.did),
            ObjectFlowEndpointObservation::UserData(user_data.clone()),
            ObjectFlowObjectKind::UserData,
            wrapper_site.clone(),
            ObjectFlowObjectKind::OpaqueHandle,
            ObjectFlowKind::WrapperMove,
            Some(projection.clone()),
            None,
        ));
        self.observations.object_flows.push(object_flow_observation(
            &self.owner_def_path,
            &source_path,
            &stable_span,
            &format!("{location:?}:drop_impl_wrapper_destructure:{projection}"),
            &self.tcx.def_path_str(destructor.did),
            wrapper_site,
            ObjectFlowObjectKind::OpaqueHandle,
            ObjectFlowEndpointObservation::UserData(user_data),
            ObjectFlowObjectKind::UserData,
            ObjectFlowKind::WrapperDestructure,
            Some(projection),
            None,
        ));
    }

    fn record_openssl_ex_data_new_index_call(
        &mut self,
        callee_def_id: DefId,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        span: Span,
        location: Location,
    ) {
        let Some(api_id) = openssl_ex_data_new_index_api_id(callee_def_path) else {
            return;
        };
        if !matches!(
            destination.ty(&self.body.local_decls, self.tcx).ty.kind(),
            ty::Int(_) | ty::Uint(_)
        ) {
            return;
        }
        let Some(free_arg) = args
            .first()
            .and_then(|arg| self.openssl_ex_data_free_callback_arg(&arg.node))
        else {
            return;
        };
        if free_arg.arg_index != 1 || !free_arg.projection.is_empty() {
            return;
        }
        let Some(destination_key) = raw_pointer_place_key(destination) else {
            return;
        };
        let Some(slot_key) = openssl_ex_data_slot_key_for_new_index(
            api_id,
            &self.owner_def_path,
            &format!("{location:?}"),
        ) else {
            return;
        };
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        let contract = OpenSslExDataFreeContract {
            api_id: api_id.to_owned(),
            owner_def_path: self.owner_def_path.clone(),
            source_path,
            span: stable_span,
            mir_location: format!("{location:?}:openssl_ex_data_new_index_free_callback"),
        };
        self.openssl_ex_data_slot_free_contracts
            .insert(slot_key.clone(), contract.clone());
        if self.current_crate_name == "openssl"
            && openssl_ex_data_new_index_contract_owner(&self.owner_def_path, api_id, callee_def_id)
        {
            self.openssl_ex_data_free_contracts
                .insert(api_id.to_owned(), contract);
        }
        update_optional_origin(
            &mut self.openssl_ex_data_slot_origins,
            destination_key,
            Some(slot_key),
        );
    }

    fn openssl_ex_data_free_callback_arg(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<RawPointerArgPlaceKey> {
        let free_def_id = self
            .fn_def_from_operand(operand)
            .or_else(|| self.option_fn_def_from_operand(operand))?;
        raw_pointer_release_arg_place_key(self.tcx, free_def_id, false).or_else(|| {
            let free_def_path = self.tcx.def_path_str(free_def_id);
            openssl_ex_data_free_data_box_path(&free_def_path).then(|| {
                raw_pointer_release_arg_place_key_on_any_path(self.tcx, free_def_id, false)
            })?
        })
    }

    fn observe_openssl_ex_data_registration_summary_call(
        &mut self,
        callee_def_id: DefId,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        let Some(summary) = summarize_openssl_ex_data_registration_callable(
            self.tcx,
            self.current_crate_name,
            callee_def_id,
        ) else {
            return;
        };
        let Some(owner_family) = lifecycle_receiver_family(&self.owner_def_path) else {
            return;
        };
        let Some(handle_key) =
            self.openssl_ex_data_handle_key_from_summary_arg(args, &summary.handle_arg)
        else {
            return;
        };
        let Some(slot_key) =
            self.openssl_ex_data_slot_key_from_summary_arg(args, &summary.slot_arg)
        else {
            return;
        };
        let slot_uses_index_argument = summary.slot_arg.projection.is_empty()
            && self.openssl_ex_data_slot_uses_index_argument(args, summary.slot_arg.arg_index);
        let Some(user_data) = args.get(summary.user_data_arg.arg_index).and_then(|arg| {
            self.raw_pointer_reference_from_operand_with_projection(
                &arg.node,
                &summary.user_data_arg.projection,
            )
        }) else {
            return;
        };
        let slot_free_contract = self
            .openssl_ex_data_slot_free_contracts
            .get(&slot_key)
            .cloned();
        if let Ok(observation) = self.registration_observation(
            summary.api_id,
            bw_model::RegistrationRole::Register,
            None,
            Some(user_data),
            span,
            location,
        ) {
            self.openssl_ex_data_registrations
                .push(OpenSslExDataRegistration {
                    owner_family,
                    handle_key,
                    slot_key,
                    slot_uses_index_argument,
                    slot_free_contract,
                    registration: observation.clone(),
                });
            if !self
                .observations
                .registrations
                .iter()
                .any(|existing| existing == &observation)
            {
                self.observations.registrations.push(observation);
            }
        }
    }

    fn record_openssl_ex_data_get_summary_call(
        &mut self,
        callee_def_id: DefId,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        _span: Span,
        _location: Location,
    ) {
        if !destination.projection.is_empty()
            || !matches!(
                destination.ty(&self.body.local_decls, self.tcx).ty.kind(),
                ty::RawPtr(..)
            )
        {
            return;
        }
        let Some(summary) = summarize_openssl_ex_data_get_callable(
            self.tcx,
            self.current_crate_name,
            callee_def_id,
        ) else {
            return;
        };
        let Some(owner_family) = lifecycle_receiver_family(&self.owner_def_path) else {
            return;
        };
        let Some(handle_key) =
            self.openssl_ex_data_handle_key_from_summary_arg(args, &summary.handle_arg)
        else {
            return;
        };
        let Some(slot_key) =
            self.openssl_ex_data_slot_key_from_summary_arg(args, &summary.slot_arg)
        else {
            return;
        };
        let Some(destination_key) = raw_pointer_place_key(destination) else {
            return;
        };
        update_optional_origin(
            &mut self.openssl_ex_data_get_origins,
            destination_key,
            Some(OpenSslExDataGetOrigin {
                owner_family,
                api_id: summary.api_id,
                handle_key,
                slot_key,
            }),
        );
    }

    fn openssl_ex_data_handle_key_from_summary_arg(
        &self,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        arg_key: &RawPointerArgPlaceKey,
    ) -> Option<String> {
        if arg_key.projection.is_empty() {
            return self.openssl_ex_data_handle_key(args, arg_key.arg_index);
        }
        let arg = args.get(arg_key.arg_index)?;
        let place = arg.node.place()?;
        let mut place_key = raw_pointer_place_key(&place)?;
        place_key.projection.extend_from_slice(&arg_key.projection);
        self.openssl_ex_data_handle_origins
            .get(&place_key)
            .cloned()
            .flatten()
    }

    fn openssl_ex_data_slot_key_from_summary_arg(
        &self,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        arg_key: &OpenSslExDataSlotArgKey,
    ) -> Option<String> {
        if arg_key.projection.is_empty() {
            return self.openssl_ex_data_slot_key(args, arg_key.arg_index);
        }
        let arg = args.get(arg_key.arg_index)?;
        let place = arg.node.place()?;
        let mut place_key = raw_pointer_place_key(&place)?;
        place_key.projection.extend_from_slice(&arg_key.projection);
        self.openssl_ex_data_slot_origins
            .get(&place_key)
            .cloned()
            .flatten()
    }

    fn record_openssl_ex_data_get_call(
        &mut self,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        destination: &Place<'tcx>,
        _span: Span,
        _location: Location,
    ) {
        let call_context = CallContext {
            current_crate_name: self.current_crate_name,
            owner_def_path: Some(&self.owner_def_path),
        };
        let Some(contract) = registration::opaque_handle_contract(callee_def_path, call_context)
        else {
            return;
        };
        if contract.role != bw_model::OpaqueHandleApiRole::Get {
            return;
        }
        if !destination.projection.is_empty()
            || !matches!(
                destination.ty(&self.body.local_decls, self.tcx).ty.kind(),
                ty::RawPtr(..)
            )
        {
            return;
        }
        let Some(owner_family) = lifecycle_receiver_family(&self.owner_def_path) else {
            return;
        };
        let Some(handle_key) = self.openssl_ex_data_handle_key(args, contract.handle_arg_index)
        else {
            return;
        };
        let Some(slot_key) = self.openssl_ex_data_slot_key(args, contract.key_arg_index) else {
            return;
        };
        let Some(destination_key) = raw_pointer_place_key(destination) else {
            return;
        };
        update_optional_origin(
            &mut self.openssl_ex_data_get_origins,
            destination_key,
            Some(OpenSslExDataGetOrigin {
                owner_family,
                api_id: contract.binding_api_id,
                handle_key,
                slot_key,
            }),
        );
    }

    fn observe_openssl_ex_data_release_call(
        &mut self,
        callee_def_id: DefId,
        callee_def_path: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        let arg_key =
            raw_pointer_release_arg_place_key(self.tcx, callee_def_id, false).or_else(|| {
                (raw_pointer_transfer_kind(callee_def_path)
                    == Some(RawPointerTransferKind::FromRaw))
                .then_some(RawPointerArgPlaceKey {
                    arg_index: 0,
                    projection: Vec::new(),
                })
            });
        let Some(arg_key) = arg_key else { return };
        let Some(arg) = args.get(arg_key.arg_index) else {
            return;
        };
        let Some(origin) = self.openssl_ex_data_get_origin_from_operand_with_projection(
            &arg.node,
            &arg_key.projection,
        ) else {
            return;
        };
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.openssl_ex_data_releases.push(OpenSslExDataRelease {
            owner_family: origin.owner_family,
            owner_def_path: self.owner_def_path.clone(),
            api_id: origin.api_id,
            handle_key: origin.handle_key,
            slot_key: origin.slot_key,
            source_path,
            span: stable_span,
            mir_location: format!("{location:?}"),
            basic_block: location.block.index(),
            statement_index: location.statement_index,
            postdominates_entry: release_postdominates_entry(self.body, location.block.index()),
        });
    }

    fn observe_openssl_ex_data_box_from_raw_call(
        &mut self,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        span: Span,
        location: Location,
    ) {
        let Ok(snippet) = self.tcx.sess.source_map().span_to_snippet(span) else {
            return;
        };
        if !snippet.contains("Box::from_raw") {
            return;
        }
        let Some(arg) = args.first() else {
            return;
        };
        let Some(origin) =
            self.openssl_ex_data_get_origin_from_operand_with_projection(&arg.node, &[])
        else {
            return;
        };
        let (Ok(source_path), Ok(stable_span)) =
            (source_path(self.tcx, span), stable_span(self.tcx, span))
        else {
            return;
        };
        self.openssl_ex_data_releases.push(OpenSslExDataRelease {
            owner_family: origin.owner_family,
            owner_def_path: self.owner_def_path.clone(),
            api_id: origin.api_id,
            handle_key: origin.handle_key,
            slot_key: origin.slot_key,
            source_path,
            span: stable_span,
            mir_location: format!("{location:?}"),
            basic_block: location.block.index(),
            statement_index: location.statement_index,
            postdominates_entry: release_postdominates_entry(self.body, location.block.index()),
        });
    }

    fn record_openssl_ex_data_registration(
        &mut self,
        api_id: &str,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        registration: &RegistrationObservation,
    ) {
        let Some(contract) = registration::opaque_handle_contract_for_api_id(api_id) else {
            return;
        };
        if contract.role != bw_model::OpaqueHandleApiRole::Set
            || !openssl_ex_data_register_api(&contract.binding_api_id)
            || registration.role != bw_model::RegistrationRole::Register
            || registration.user_data.is_none()
        {
            return;
        }
        let Some(owner_family) = lifecycle_receiver_family(&self.owner_def_path) else {
            return;
        };
        let Some(handle_key) = self.openssl_ex_data_handle_key(args, contract.handle_arg_index)
        else {
            return;
        };
        let Some(slot_key) = self.openssl_ex_data_slot_key(args, contract.key_arg_index) else {
            return;
        };
        let slot_uses_index_argument =
            self.openssl_ex_data_slot_uses_index_argument(args, contract.key_arg_index);
        let slot_free_contract = self
            .openssl_ex_data_slot_free_contracts
            .get(&slot_key)
            .cloned();
        self.openssl_ex_data_registrations
            .push(OpenSslExDataRegistration {
                owner_family,
                handle_key,
                slot_key,
                slot_uses_index_argument,
                slot_free_contract,
                registration: registration.clone(),
            });
    }

    fn openssl_ex_data_handle_key(
        &self,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        index: usize,
    ) -> Option<String> {
        let arg = args.get(index)?;
        if let Some(exact) = self.openssl_ex_data_exact_handle_key_from_operand(&arg.node) {
            return exact;
        }
        self.tcx
            .sess
            .source_map()
            .span_to_snippet(arg.span)
            .ok()
            .and_then(|snippet| normalize_openssl_ex_data_handle_snippet(&snippet))
            .or_else(|| normalize_openssl_ex_data_handle_snippet(&format!("{:?}", arg.node)))
    }

    fn openssl_ex_data_slot_key(
        &self,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        index: usize,
    ) -> Option<String> {
        let arg = args.get(index)?;
        self.openssl_ex_data_slot_key_from_operand(&arg.node)
            .or_else(|| {
                self.tcx
                    .sess
                    .source_map()
                    .span_to_snippet(arg.span)
                    .ok()
                    .and_then(|snippet| normalize_openssl_ex_data_slot_snippet(&snippet))
            })
            .or_else(|| normalize_openssl_ex_data_slot_snippet(&format!("{:?}", arg.node)))
    }

    fn openssl_ex_data_slot_key_from_rvalue(&self, rvalue: &Rvalue<'tcx>) -> Option<String> {
        match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                self.openssl_ex_data_slot_key_from_operand(operand)
            }
            _ => normalize_openssl_ex_data_slot_snippet(&format!("{rvalue:?}")),
        }
    }

    fn openssl_ex_data_slot_key_from_operand(&self, operand: &Operand<'tcx>) -> Option<String> {
        match operand {
            Operand::Copy(place) | Operand::Move(place) => raw_pointer_place_key(place)
                .and_then(|key| {
                    self.openssl_ex_data_slot_origins
                        .get(&key)
                        .cloned()
                        .flatten()
                })
                .or_else(|| normalize_openssl_ex_data_slot_snippet(&format!("{operand:?}"))),
            Operand::Constant(_) => normalize_openssl_ex_data_slot_snippet(&format!("{operand:?}")),
            _ => None,
        }
    }

    fn openssl_ex_data_slot_uses_index_argument(
        &self,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        index: usize,
    ) -> bool {
        args.get(index)
            .and_then(|arg| self.tcx.sess.source_map().span_to_snippet(arg.span).ok())
            .is_some_and(|snippet| {
                let snippet = snippet.split_whitespace().collect::<String>();
                snippet.ends_with(".as_raw()")
                    || snippet.contains("Index<")
                    || snippet.contains("Index::from_raw")
            })
    }

    fn openssl_ex_data_get_origin_from_rvalue(
        &self,
        rvalue: &Rvalue<'tcx>,
    ) -> Option<OpenSslExDataGetOrigin> {
        match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                self.openssl_ex_data_get_origin_from_operand_with_projection(operand, &[])
            }
            _ => None,
        }
    }

    fn openssl_ex_data_get_origin_from_operand_with_projection(
        &self,
        operand: &Operand<'tcx>,
        projection: &[String],
    ) -> Option<OpenSslExDataGetOrigin> {
        let place = operand.place()?;
        let mut key = raw_pointer_place_key(&place)?;
        key.projection.extend_from_slice(projection);
        self.openssl_ex_data_get_origins
            .get(&key)
            .cloned()
            .flatten()
    }

    fn raw_pointer_reference_from_args(
        &self,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        indices: &[usize],
    ) -> Option<RawPointerReference> {
        let mut user_data = None;
        for arg in indexed_args(args, indices) {
            if !matches!(
                arg.node.ty(&self.body.local_decls, self.tcx).kind(),
                ty::RawPtr(..)
            ) {
                continue;
            }
            let Some(candidate) = self.raw_pointer_reference_from_operand(&arg.node) else {
                continue;
            };
            if let Some(existing) = &user_data
                && existing != &candidate
            {
                return None;
            }
            user_data = Some(candidate);
        }
        user_data
    }

    fn raw_pointer_reference_from_operand(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<RawPointerReference> {
        self.raw_pointer_reference_from_operand_with_projection(operand, &[])
    }

    fn raw_pointer_reference_from_operand_with_projection(
        &self,
        operand: &Operand<'tcx>,
        projection: &[String],
    ) -> Option<RawPointerReference> {
        let place = operand.place()?;
        let mut key = self.raw_pointer_storage_field_key_from_place(&place)?;
        key.projection.extend_from_slice(projection);
        self.raw_pointer_origins
            .get(&key)
            .cloned()
            .flatten()
            .or_else(|| {
                if !place.projection.is_empty()
                    || !matches!(
                        place.ty(&self.body.local_decls, self.tcx).ty.kind(),
                        ty::Ref(..)
                    )
                {
                    return None;
                }
                let mut borrowed_key = self
                    .raw_pointer_borrow_origins
                    .get(&place.local)
                    .cloned()
                    .flatten()?;
                borrowed_key.projection.extend_from_slice(projection);
                self.raw_pointer_origins
                    .get(&borrowed_key)
                    .cloned()
                    .flatten()
            })
    }

    fn raw_pointer_origin_from_operand_storage_prefix(
        &self,
        operand: &Operand<'tcx>,
    ) -> Option<(RawPointerPlaceKey, RawPointerReference)> {
        let place = operand.place()?;
        let source_key = self.raw_pointer_storage_field_key_from_place(&place)?;
        let mut found = None;
        for (key, origin) in &self.raw_pointer_origins {
            if key.local != source_key.local || !key.projection.starts_with(&source_key.projection)
            {
                continue;
            }
            let Some(origin) = origin.clone() else {
                return None;
            };
            if let Some((_, existing)) = &found
                && existing != &origin
            {
                return None;
            }
            found = Some((key.clone(), origin));
        }
        found
    }

    fn raw_pointer_reference_from_place_with_projection(
        &self,
        place: &Place<'tcx>,
        projection: &[String],
    ) -> Option<RawPointerReference> {
        let mut key = self.raw_pointer_storage_field_key_from_place(place)?;
        key.projection.extend_from_slice(projection);
        self.raw_pointer_origins.get(&key).cloned().flatten()
    }

    fn callback_reference_from_ty(&self, ty: Ty<'tcx>) -> Option<CallbackReference> {
        self.callback_reference_from_def_id(callback_def_id_from_ty(ty)?)
    }

    fn callback_argument_is_explicit_none(
        &self,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        indices: &[usize],
    ) -> bool {
        indexed_args(args, indices).any(|arg| {
            self.tcx
                .sess
                .source_map()
                .span_to_snippet(arg.span)
                .ok()
                .is_some_and(|snippet| {
                    let snippet = snippet.trim_start();
                    snippet == "None" || snippet.starts_with("None::<")
                })
        })
    }

    fn callback_argument_is_explicit_some(
        &self,
        args: &[super::rustc_span::Spanned<Operand<'tcx>>],
        indices: &[usize],
    ) -> bool {
        indexed_args(args, indices).any(|arg| {
            self.tcx
                .sess
                .source_map()
                .span_to_snippet(arg.span)
                .ok()
                .is_some_and(|snippet| {
                    let snippet = snippet.trim_start();
                    snippet.starts_with("Some(") || snippet.starts_with("Some::<")
                })
        })
    }

    fn callback_reference_from_def_id(&self, callback_def_id: DefId) -> Option<CallbackReference> {
        let span = self.tcx.def_span(callback_def_id);
        Some(CallbackReference {
            def_path: self.tcx.def_path_str(callback_def_id),
            source_path: source_path(self.tcx, span).ok()?,
            span: stable_span(self.tcx, span).ok()?,
        })
    }

    fn external_call_observation(
        &self,
        api_id: String,
        role: bw_model::ExternalCallRole,
        span: Span,
        location: Location,
    ) -> Result<ExternalCallObservation, MirExtractionError> {
        Ok(ExternalCallObservation {
            owner_def_path: self.owner_def_path.clone(),
            source_path: source_path(self.tcx, span)?,
            span: stable_span(self.tcx, span)?,
            mir_location: format!("{location:?}"),
            api_id,
            role,
        })
    }
}

fn release_postdominates_registration(
    body: &Body<'_>,
    registration_block: usize,
    release_block: usize,
) -> bool {
    if registration_block == release_block {
        return false;
    }
    let registration_block = BasicBlock::new(registration_block);
    let release_block = BasicBlock::new(release_block);
    !path_to_exit_avoiding_release(
        body,
        registration_block,
        release_block,
        &mut BTreeSet::new(),
    )
}

fn state_machine_write_postdominates_registration(
    body: &Body<'_>,
    registration_block: usize,
    write_block: usize,
) -> bool {
    if registration_block == write_block {
        return false;
    }
    let registration_block = BasicBlock::new(registration_block);
    let write_block = BasicBlock::new(write_block);
    !path_to_exit_avoiding_release_ignoring_unreachable(
        body,
        registration_block,
        write_block,
        &mut BTreeSet::new(),
    )
}

fn entry_value_assignment_postdominates_reference(
    body: &Body<'_>,
    reference_order_key: MirOrderKey,
    assignment_order_key: MirOrderKey,
) -> bool {
    if reference_order_key.basic_block == assignment_order_key.basic_block {
        return reference_order_key.statement_index <= assignment_order_key.statement_index;
    }
    state_machine_write_postdominates_registration(
        body,
        reference_order_key.basic_block,
        assignment_order_key.basic_block,
    )
}

fn release_postdominates_entry(body: &Body<'_>, release_block: usize) -> bool {
    let release_block = BasicBlock::new(release_block);
    !path_to_exit_avoiding_release(
        body,
        BasicBlock::new(0),
        release_block,
        &mut BTreeSet::new(),
    )
}

fn blocks_cover_all_entry_to_exit_paths(
    body: &Body<'_>,
    covered_blocks: &BTreeSet<BasicBlock>,
) -> bool {
    !covered_blocks.is_empty()
        && !path_to_exit_avoiding_covered_blocks(
            body,
            BasicBlock::new(0),
            covered_blocks,
            &mut BTreeSet::new(),
        )
}

fn path_to_exit_avoiding_release(
    body: &Body<'_>,
    block: BasicBlock,
    release_block: BasicBlock,
    visiting: &mut BTreeSet<BasicBlock>,
) -> bool {
    if block == release_block {
        return false;
    }
    // A reachable cycle that avoids the release endpoint has an execution path for which
    // completion of the local release action cannot be established.
    if !visiting.insert(block) {
        return true;
    }
    let successors = body.basic_blocks[block]
        .terminator()
        .successors()
        .collect::<Vec<_>>();
    let reaches_exit = successors.is_empty()
        || successors.into_iter().any(|successor| {
            path_to_exit_avoiding_release(body, successor, release_block, visiting)
        });
    visiting.remove(&block);
    reaches_exit
}

fn path_to_exit_avoiding_covered_blocks(
    body: &Body<'_>,
    block: BasicBlock,
    covered_blocks: &BTreeSet<BasicBlock>,
    visiting: &mut BTreeSet<BasicBlock>,
) -> bool {
    if covered_blocks.contains(&block) {
        return false;
    }
    // A reachable cycle that avoids every covered endpoint is an execution path for which
    // completion of the local same-origin write/return set cannot be established.
    if !visiting.insert(block) {
        return true;
    }
    let successors = body.basic_blocks[block]
        .terminator()
        .successors()
        .collect::<Vec<_>>();
    let reaches_exit = successors.is_empty()
        || successors.into_iter().any(|successor| {
            path_to_exit_avoiding_covered_blocks(body, successor, covered_blocks, visiting)
        });
    visiting.remove(&block);
    reaches_exit
}

fn path_to_exit_avoiding_release_ignoring_unreachable(
    body: &Body<'_>,
    block: BasicBlock,
    release_block: BasicBlock,
    visiting: &mut BTreeSet<BasicBlock>,
) -> bool {
    if block == release_block {
        return false;
    }
    if body.basic_blocks[block].is_cleanup {
        return false;
    }
    if !visiting.insert(block) {
        return true;
    }
    let terminator = body.basic_blocks[block].terminator();
    if matches!(terminator.kind, TerminatorKind::Unreachable) {
        visiting.remove(&block);
        return false;
    }
    let successors = terminator.successors().collect::<Vec<_>>();
    let reaches_exit = successors.is_empty()
        || successors.into_iter().any(|successor| {
            path_to_exit_avoiding_release_ignoring_unreachable(
                body,
                successor,
                release_block,
                visiting,
            )
        });
    visiting.remove(&block);
    reaches_exit
}

fn indexed_args<'a, 'tcx>(
    args: &'a [super::rustc_span::Spanned<Operand<'tcx>>],
    indices: &'a [usize],
) -> impl Iterator<Item = &'a super::rustc_span::Spanned<Operand<'tcx>>> {
    indices.iter().filter_map(|index| args.get(*index))
}

fn update_optional_origin<K: Ord, T: Eq>(
    origins: &mut BTreeMap<K, Option<T>>,
    key: K,
    origin: Option<T>,
) {
    match origins.get_mut(&key) {
        Some(existing)
            if existing
                .as_ref()
                .zip(origin.as_ref())
                .is_some_and(|(left, right)| left != right) =>
        {
            *existing = None;
        }
        Some(existing) if existing.is_none() || origin.is_none() => {
            *existing = None;
        }
        Some(_) => {}
        None => {
            origins.insert(key, origin);
        }
    }
}

fn is_fn_pointer_ty(ty: Ty<'_>) -> bool {
    matches!(ty.kind(), ty::FnPtr(..))
}

fn is_option_fn_pointer_ty(ty: Ty<'_>) -> bool {
    let ty = ty.to_string();
    (ty.starts_with("std::option::Option<") || ty.starts_with("core::option::Option<"))
        && ty.contains("unsafe")
        && ty.contains("fn")
}

fn foreign_destructor_arg_index(api_id: &str, callee_def_path: &str) -> Option<usize> {
    (api_id == "api:rusqlite:create_scalar_function:register"
        && callee_def_path.starts_with("libsqlite3_sys::")
        && callee_def_path.ends_with("::sqlite3_create_function_v2"))
    .then_some(8)
    .or_else(|| {
        (api_id == "api:diesel:sqlite3_create_function_v2:register"
            && diesel_sqlite3_create_function_v2_ffi_path(callee_def_path))
        .then_some(8)
    })
    .or_else(|| {
        (api_id == "api:pyo3:pycapsule_new:register"
            && pyo3_pycapsule_new_ffi_path(callee_def_path))
        .then_some(2)
    })
}

fn foreign_destructor_allows_capsule_get_pointer(api_id: &str) -> bool {
    api_id == "api:pyo3:pycapsule_new:register"
}

fn pyo3_pycapsule_new_ffi_path(canonical_def_path: &str) -> bool {
    (canonical_def_path == "pyo3_ffi::PyCapsule_New"
        || canonical_def_path.starts_with("pyo3_ffi::"))
        && canonical_def_path.ends_with("::PyCapsule_New")
}

fn diesel_sqlite3_create_function_v2_ffi_path(canonical_def_path: &str) -> bool {
    canonical_def_path == "sqlite::connection::raw::ffi::sqlite3_create_function_v2"
        || canonical_def_path == "sqlite::connection::ffi::sqlite3_create_function_v2"
        || canonical_def_path == "sqlite3_create_function_v2"
}

fn pyo3_pycapsule_get_pointer_ffi_path(canonical_def_path: &str) -> bool {
    (canonical_def_path == "pyo3_ffi::PyCapsule_GetPointer"
        || canonical_def_path.starts_with("pyo3_ffi::"))
        && canonical_def_path.ends_with("::PyCapsule_GetPointer")
}

fn registration_call_returns_previous_user_data(api_id: &str) -> bool {
    matches!(
        api_id,
        "api:rusqlite:update_hook:register"
            | "api:rusqlite:update_hook:unregister"
            | "api:rusqlite:commit_hook:register"
            | "api:rusqlite:commit_hook:unregister"
            | "api:rusqlite:rollback_hook:register"
            | "api:rusqlite:rollback_hook:unregister"
    )
}

fn hook_family_from_api_id(api_id: &str) -> Option<&'static str> {
    if matches!(
        api_id,
        "api:rusqlite:update_hook:register" | "api:rusqlite:update_hook:unregister"
    ) {
        return Some("rusqlite:update_hook");
    }
    if matches!(
        api_id,
        "api:rusqlite:commit_hook:register" | "api:rusqlite:commit_hook:unregister"
    ) {
        return Some("rusqlite:commit_hook");
    }
    if matches!(
        api_id,
        "api:rusqlite:rollback_hook:register" | "api:rusqlite:rollback_hook:unregister"
    ) {
        return Some("rusqlite:rollback_hook");
    }
    None
}

fn summarize_registration_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    current_crate_name: &str,
    def_id: DefId,
) -> Option<RegistrationCallSummary> {
    let mut visited = BTreeSet::new();
    summarize_registration_callable_inner(tcx, current_crate_name, def_id, &mut visited)
}

fn summarize_registration_callable_inner<'tcx>(
    tcx: TyCtxt<'tcx>,
    current_crate_name: &str,
    def_id: DefId,
    visited: &mut BTreeSet<String>,
) -> Option<RegistrationCallSummary> {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);
    let owner_def_path = tcx.def_path_str(def_id);
    if !visited.insert(owner_def_path.clone()) {
        return None;
    }

    let mut callback_origins = BTreeMap::<Local, Option<usize>>::new();
    let mut raw_pointer_origins = BTreeMap::<Local, Option<usize>>::new();
    for (arg_index, local) in body.args_iter().enumerate() {
        let ty = body.local_decls[local].ty;
        if registration_callback_summary_type(ty) {
            callback_origins.insert(local, Some(arg_index));
        }
        if matches!(ty.kind(), ty::RawPtr(..)) {
            raw_pointer_origins.insert(local, Some(arg_index));
        }
    }
    if callback_origins.is_empty() || raw_pointer_origins.is_empty() {
        return None;
    }

    let mut unique_summary = None;
    for (block_index, block) in body.basic_blocks.iter().enumerate() {
        for statement in &block.statements {
            let StatementKind::Assign(assignment) = &statement.kind else {
                continue;
            };
            let (place, rvalue) = &**assignment;
            record_registration_callback_summary_assignment(
                body,
                &mut callback_origins,
                place,
                rvalue,
            );
            record_registration_raw_pointer_summary_assignment(
                body,
                &mut raw_pointer_origins,
                place,
                rvalue,
            );
        }

        if let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &block.terminator().kind
        {
            let Some((callee_def_id, _)) = func.const_fn_def() else {
                record_registration_summary_unknown_destination(
                    body,
                    &mut callback_origins,
                    &mut raw_pointer_origins,
                    destination,
                );
                continue;
            };
            let callee_def_path = tcx.def_path_str(callee_def_id);
            let direct_summary = registration_summary_from_direct_call(
                &callee_def_path,
                args,
                current_crate_name,
                &owner_def_path,
                &callback_origins,
                &raw_pointer_origins,
            );
            let nested_summary = direct_summary.or_else(|| {
                let mut nested_visited = visited.clone();
                summarize_registration_callable_inner(
                    tcx,
                    current_crate_name,
                    callee_def_id,
                    &mut nested_visited,
                )
                .and_then(|summary| {
                    registration_summary_from_nested_summary(
                        summary,
                        args,
                        &callback_origins,
                        &raw_pointer_origins,
                    )
                })
            });
            if let Some(summary) = nested_summary {
                if !release_postdominates_entry(body, block_index) {
                    return None;
                }
                unique_summary = merge_registration_call_summary(unique_summary, summary)?;
            }
            record_registration_summary_unknown_destination(
                body,
                &mut callback_origins,
                &mut raw_pointer_origins,
                destination,
            );
        }
    }

    unique_summary
}

fn summarize_openssl_ex_data_registration_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    current_crate_name: &str,
    def_id: DefId,
) -> Option<OpenSslExDataRegistrationCallSummary> {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);
    let owner_def_path = tcx.def_path_str(def_id);
    let predecessors = raw_pointer_basic_block_predecessors(body);
    let mut raw_pointer_exit_origins = vec![None; body.basic_blocks.len()];
    let mut slot_exit_origins = vec![None; body.basic_blocks.len()];
    let mut unique_summary = None;
    for (block_index, block) in body.basic_blocks.iter().enumerate() {
        let mut raw_pointer_arg_origins =
            incoming_raw_pointer_arg_origins(&predecessors, &raw_pointer_exit_origins, block_index);
        let mut slot_arg_origins = incoming_openssl_ex_data_slot_arg_origins(
            &predecessors,
            &slot_exit_origins,
            block_index,
        );
        for statement in &block.statements {
            record_callee_raw_pointer_arg_assignment_with_aggregates(
                body,
                tcx,
                statement,
                &mut raw_pointer_arg_origins,
            );
            record_openssl_ex_data_slot_arg_assignment(body, tcx, statement, &mut slot_arg_origins);
        }

        let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &block.terminator().kind
        else {
            raw_pointer_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            slot_exit_origins[block_index] = Some(slot_arg_origins);
            continue;
        };
        let Some((callee_def_id, _)) = func.const_fn_def() else {
            record_callee_raw_pointer_arg_call_destination(
                body,
                tcx,
                destination,
                None,
                &mut raw_pointer_arg_origins,
            );
            record_openssl_ex_data_slot_arg_call_destination(
                body,
                tcx,
                destination,
                None,
                &mut slot_arg_origins,
            );
            raw_pointer_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            slot_exit_origins[block_index] = Some(slot_arg_origins);
            continue;
        };
        let callee_def_path = tcx.def_path_str(callee_def_id);
        let call_context = CallContext {
            current_crate_name,
            owner_def_path: Some(&owner_def_path),
        };
        if let Some(contract) = registration::opaque_handle_contract(&callee_def_path, call_context)
            && contract.role == bw_model::OpaqueHandleApiRole::Set
            && openssl_ex_data_register_api(&contract.binding_api_id)
        {
            let handle_arg = args.get(contract.handle_arg_index).and_then(|arg| {
                callee_raw_pointer_arg_key_from_operand(
                    body,
                    tcx,
                    &arg.node,
                    &raw_pointer_arg_origins,
                )
            })?;
            let slot_arg = args.get(contract.key_arg_index).and_then(|arg| {
                openssl_ex_data_slot_arg_key_from_operand(body, tcx, &arg.node, &slot_arg_origins)
            })?;
            let payload_arg_index = contract.payload_arg_index?;
            let user_data_arg = args.get(payload_arg_index).and_then(|arg| {
                callee_raw_pointer_arg_key_from_operand(
                    body,
                    tcx,
                    &arg.node,
                    &raw_pointer_arg_origins,
                )
            })?;
            if !release_postdominates_entry(body, block_index) {
                return None;
            }
            let candidate = OpenSslExDataRegistrationCallSummary {
                api_id: contract.binding_api_id,
                handle_arg,
                slot_arg,
                user_data_arg,
            };
            if unique_summary
                .as_ref()
                .is_some_and(|existing| existing != &candidate)
            {
                return None;
            }
            unique_summary = Some(candidate);
        }
        record_callee_raw_pointer_arg_call_destination(
            body,
            tcx,
            destination,
            None,
            &mut raw_pointer_arg_origins,
        );
        record_openssl_ex_data_slot_arg_call_destination(
            body,
            tcx,
            destination,
            None,
            &mut slot_arg_origins,
        );
        raw_pointer_exit_origins[block_index] = Some(raw_pointer_arg_origins);
        slot_exit_origins[block_index] = Some(slot_arg_origins);
    }
    unique_summary
}

fn summarize_openssl_ex_data_get_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    current_crate_name: &str,
    def_id: DefId,
) -> Option<OpenSslExDataGetCallSummary> {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);
    let owner_def_path = tcx.def_path_str(def_id);
    let predecessors = raw_pointer_basic_block_predecessors(body);
    let mut raw_pointer_exit_origins = vec![None; body.basic_blocks.len()];
    let mut slot_exit_origins = vec![None; body.basic_blocks.len()];
    let mut unique_summary = None;
    for (block_index, block) in body.basic_blocks.iter().enumerate() {
        let mut raw_pointer_arg_origins =
            incoming_raw_pointer_arg_origins(&predecessors, &raw_pointer_exit_origins, block_index);
        let mut slot_arg_origins = incoming_openssl_ex_data_slot_arg_origins(
            &predecessors,
            &slot_exit_origins,
            block_index,
        );
        for statement in &block.statements {
            record_callee_raw_pointer_arg_assignment_with_aggregates(
                body,
                tcx,
                statement,
                &mut raw_pointer_arg_origins,
            );
            record_openssl_ex_data_slot_arg_assignment(body, tcx, statement, &mut slot_arg_origins);
        }

        let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &block.terminator().kind
        else {
            raw_pointer_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            slot_exit_origins[block_index] = Some(slot_arg_origins);
            continue;
        };
        let Some((callee_def_id, _)) = func.const_fn_def() else {
            record_callee_raw_pointer_arg_call_destination(
                body,
                tcx,
                destination,
                None,
                &mut raw_pointer_arg_origins,
            );
            record_openssl_ex_data_slot_arg_call_destination(
                body,
                tcx,
                destination,
                None,
                &mut slot_arg_origins,
            );
            raw_pointer_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            slot_exit_origins[block_index] = Some(slot_arg_origins);
            continue;
        };
        let callee_def_path = tcx.def_path_str(callee_def_id);
        let call_context = CallContext {
            current_crate_name,
            owner_def_path: Some(&owner_def_path),
        };
        if let Some(contract) = registration::opaque_handle_contract(&callee_def_path, call_context)
            && contract.role == bw_model::OpaqueHandleApiRole::Get
        {
            if destination.local != Local::new(0) || !destination.projection.is_empty() {
                return None;
            }
            let handle_arg = args.get(contract.handle_arg_index).and_then(|arg| {
                callee_raw_pointer_arg_key_from_operand(
                    body,
                    tcx,
                    &arg.node,
                    &raw_pointer_arg_origins,
                )
            })?;
            let slot_arg = args.get(contract.key_arg_index).and_then(|arg| {
                openssl_ex_data_slot_arg_key_from_operand(body, tcx, &arg.node, &slot_arg_origins)
            })?;
            if !release_postdominates_entry(body, block_index) {
                return None;
            }
            let candidate = OpenSslExDataGetCallSummary {
                api_id: contract.binding_api_id,
                handle_arg,
                slot_arg,
            };
            if unique_summary
                .as_ref()
                .is_some_and(|existing| existing != &candidate)
            {
                return None;
            }
            unique_summary = Some(candidate);
        }
        record_callee_raw_pointer_arg_call_destination(
            body,
            tcx,
            destination,
            None,
            &mut raw_pointer_arg_origins,
        );
        record_openssl_ex_data_slot_arg_call_destination(
            body,
            tcx,
            destination,
            None,
            &mut slot_arg_origins,
        );
        raw_pointer_exit_origins[block_index] = Some(raw_pointer_arg_origins);
        slot_exit_origins[block_index] = Some(slot_arg_origins);
    }
    unique_summary
}

fn summarize_callback_user_data_invocation_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
) -> Option<CallbackUserDataInvocationSummary> {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);

    if body.arg_count == 0 {
        return None;
    }

    let mut unique_summary = None;
    let predecessors = raw_pointer_basic_block_predecessors(body);
    let mut callback_exit_origins = vec![None; body.basic_blocks.len()];
    let mut raw_pointer_exit_origins = vec![None; body.basic_blocks.len()];
    for (block_index, block) in body.basic_blocks.iter().enumerate() {
        let mut block_callback_origins =
            incoming_raw_pointer_arg_origins(&predecessors, &callback_exit_origins, block_index);
        let mut block_raw_pointer_origins =
            incoming_raw_pointer_arg_origins(&predecessors, &raw_pointer_exit_origins, block_index);
        for statement in &block.statements {
            record_callback_user_data_invocation_callback_assignment(
                body,
                tcx,
                statement,
                &mut block_callback_origins,
            );
            record_callee_raw_pointer_arg_assignment_with_aggregates(
                body,
                tcx,
                statement,
                &mut block_raw_pointer_origins,
            );
        }

        let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &block.terminator().kind
        else {
            callback_exit_origins[block_index] = Some(block_callback_origins);
            raw_pointer_exit_origins[block_index] = Some(block_raw_pointer_origins);
            continue;
        };
        let Some(callback_arg) =
            callback_user_data_invocation_callback_arg(func, body, tcx, &block_callback_origins)
        else {
            record_callback_user_data_invocation_unknown_destination(
                body,
                tcx,
                &mut block_callback_origins,
                &mut block_raw_pointer_origins,
                destination,
            );
            callback_exit_origins[block_index] = Some(block_callback_origins);
            raw_pointer_exit_origins[block_index] = Some(block_raw_pointer_origins);
            continue;
        };
        let Some(user_data_arg) = callback_user_data_invocation_raw_pointer_arg(
            body,
            tcx,
            args,
            &block_raw_pointer_origins,
        ) else {
            return None;
        };
        if !release_postdominates_entry(body, block_index) {
            return None;
        }
        let candidate = CallbackUserDataInvocationSummary {
            callback_arg,
            user_data_arg,
        };
        if unique_summary
            .as_ref()
            .is_some_and(|existing| existing != &candidate)
        {
            return None;
        }
        unique_summary = Some(candidate);
        record_callback_user_data_invocation_unknown_destination(
            body,
            tcx,
            &mut block_callback_origins,
            &mut block_raw_pointer_origins,
            destination,
        );
        callback_exit_origins[block_index] = Some(block_callback_origins);
        raw_pointer_exit_origins[block_index] = Some(block_raw_pointer_origins);
    }
    unique_summary
}

fn callback_user_data_invocation_callback_type(ty: Ty<'_>) -> bool {
    if !is_fn_pointer_ty(ty) {
        return false;
    }
    let ty = ty.to_string();
    ty.contains("extern \"C\"") && ty.contains("*mut")
}

fn callback_user_data_invocation_callback_arg<'tcx>(
    func: &Operand<'tcx>,
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    origins: &BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) -> Option<RawPointerArgPlaceKey> {
    callback_user_data_invocation_callback_arg_from_operand(body, tcx, func, origins)
}

fn callback_user_data_invocation_raw_pointer_arg<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    origins: &BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) -> Option<RawPointerArgPlaceKey> {
    let mut unique = None;
    for origin in args
        .iter()
        .filter_map(|arg| callee_raw_pointer_arg_key_from_operand(body, tcx, &arg.node, origins))
    {
        if unique.as_ref().is_some_and(|existing| existing != &origin) {
            return None;
        }
        unique = Some(origin);
    }
    unique
}

fn callback_user_data_invocation_callback_arg_from_operand<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    operand: &Operand<'tcx>,
    origins: &BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) -> Option<RawPointerArgPlaceKey> {
    if !callback_user_data_invocation_callback_type(operand.ty(&body.local_decls, tcx)) {
        return None;
    }
    let place = operand.place()?;
    callback_user_data_invocation_callback_arg_from_place(body, &place).or_else(|| {
        fn_pointer_place_key(body, &place).and_then(|key| origins.get(&key).cloned().flatten())
    })
}

fn callback_user_data_invocation_callback_arg_from_place(
    body: &Body<'_>,
    place: &Place<'_>,
) -> Option<RawPointerArgPlaceKey> {
    let arg_index = place.local.index().checked_sub(1)?;
    if arg_index >= body.arg_count {
        return None;
    }
    Some(RawPointerArgPlaceKey {
        arg_index,
        projection: fn_pointer_projection_key(body, place, false)?,
    })
}

fn record_callback_user_data_invocation_callback_assignment<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    statement: &super::rustc_middle::mir::Statement<'tcx>,
    origins: &mut BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) {
    let StatementKind::Assign(assignment) = &statement.kind else {
        return;
    };
    let (destination, rvalue) = &**assignment;
    let Some(destination_key) = fn_pointer_place_key(body, destination) else {
        return;
    };
    if callback_user_data_invocation_callback_type(destination.ty(&body.local_decls, tcx).ty) {
        let origin = match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                callback_user_data_invocation_callback_arg_from_operand(body, tcx, operand, origins)
            }
            _ => None,
        };
        update_optional_origin(origins, destination_key, origin);
        return;
    }

    match rvalue {
        Rvalue::Aggregate(kind, operands) if raw_pointer_aggregate_kind_tracks_fields(kind) => {
            forget_callback_user_data_invocation_callback_origin_prefix(origins, &destination_key);
            for (field_index, operand) in operands.iter().enumerate() {
                for (field_key, origin) in
                    callback_user_data_invocation_callback_aggregate_operand_origins(
                        body,
                        tcx,
                        &destination_key,
                        field_index,
                        operand,
                        origins,
                    )
                {
                    update_optional_origin(origins, field_key, origin);
                }
            }
        }
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            record_callback_user_data_invocation_callback_place_alias(
                body,
                tcx,
                destination,
                operand,
                origins,
            );
        }
        _ => {
            forget_callback_user_data_invocation_callback_origin_prefix(origins, &destination_key);
        }
    }
}

fn callback_user_data_invocation_callback_aggregate_operand_origins<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    destination_key: &RawPointerPlaceKey,
    field_index: usize,
    operand: &Operand<'tcx>,
    origins: &BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) -> Vec<(RawPointerPlaceKey, Option<RawPointerArgPlaceKey>)> {
    let mut field_prefix = destination_key.clone();
    field_prefix.projection.push(format!("field:{field_index}"));
    if callback_user_data_invocation_callback_type(operand.ty(&body.local_decls, tcx)) {
        return vec![(
            field_prefix,
            callback_user_data_invocation_callback_arg_from_operand(body, tcx, operand, origins),
        )];
    }

    let Some(source_place) = operand.place() else {
        return Vec::new();
    };
    let Some(source_key) = fn_pointer_place_key(body, &source_place) else {
        return Vec::new();
    };
    origins
        .iter()
        .filter_map(|(key, value)| {
            if key.local != source_key.local || !key.projection.starts_with(&source_key.projection)
            {
                return None;
            }
            let mut projection = field_prefix.projection.clone();
            projection.extend_from_slice(&key.projection[source_key.projection.len()..]);
            Some((
                RawPointerPlaceKey {
                    local: field_prefix.local,
                    projection,
                },
                value.clone(),
            ))
        })
        .collect()
}

fn record_callback_user_data_invocation_callback_place_alias<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    destination: &Place<'tcx>,
    source: &Operand<'tcx>,
    origins: &mut BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) {
    let Some(destination_key) = fn_pointer_place_key(body, destination) else {
        return;
    };
    forget_callback_user_data_invocation_callback_origin_prefix(origins, &destination_key);
    let Some(source_place) = source.place() else {
        return;
    };
    if callback_user_data_invocation_callback_type(source.ty(&body.local_decls, tcx)) {
        return;
    }
    let Some(source_key) = fn_pointer_place_key(body, &source_place) else {
        return;
    };
    let aliases = origins
        .iter()
        .filter_map(|(key, value)| {
            if key.local != source_key.local || !key.projection.starts_with(&source_key.projection)
            {
                return None;
            }
            let mut projection = destination_key.projection.clone();
            projection.extend_from_slice(&key.projection[source_key.projection.len()..]);
            Some((
                RawPointerPlaceKey {
                    local: destination_key.local,
                    projection,
                },
                value.clone(),
            ))
        })
        .collect::<Vec<_>>();
    for (key, value) in aliases {
        update_optional_origin(origins, key, value);
    }
}

fn record_callback_user_data_invocation_unknown_destination<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    callback_origins: &mut BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
    raw_pointer_origins: &mut BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
    destination: &Place<'tcx>,
) {
    if let Some(key) = fn_pointer_place_key(body, destination) {
        forget_callback_user_data_invocation_callback_origin_prefix(callback_origins, &key);
        if callback_user_data_invocation_callback_type(destination.ty(&body.local_decls, tcx).ty) {
            update_optional_origin(callback_origins, key, None);
        }
    }
    if let Some(key) = raw_pointer_place_key(destination) {
        forget_callee_raw_pointer_arg_origin_prefix(raw_pointer_origins, &key);
        if matches!(
            destination.ty(&body.local_decls, tcx).ty.kind(),
            ty::RawPtr(..)
        ) {
            update_optional_origin(raw_pointer_origins, key, None);
        }
    }
}

fn forget_callback_user_data_invocation_callback_origin_prefix(
    origins: &mut BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
    prefix: &RawPointerPlaceKey,
) {
    origins.retain(|key, _| {
        key.local != prefix.local || !key.projection.starts_with(&prefix.projection)
    });
}

fn registration_callback_summary_type(ty: Ty<'_>) -> bool {
    is_fn_pointer_ty(ty) || is_option_fn_pointer_ty(ty) || callback_def_id_from_ty(ty).is_some()
}

fn record_registration_callback_summary_assignment<'tcx>(
    body: &Body<'tcx>,
    origins: &mut BTreeMap<Local, Option<usize>>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let origin = match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            registration_callback_summary_operand_origin(operand, origins)
        }
        Rvalue::Aggregate(_, operands) => {
            registration_callback_summary_origin_from_operands(operands, origins)
        }
        _ => None,
    };
    if registration_callback_summary_type(body.local_decls[destination.local].ty)
        || origins.contains_key(&destination.local)
        || origin.is_some()
    {
        update_optional_origin(origins, destination.local, origin);
    }
}

fn record_registration_raw_pointer_summary_assignment<'tcx>(
    body: &Body<'tcx>,
    origins: &mut BTreeMap<Local, Option<usize>>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let origin = match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            registration_raw_pointer_summary_operand_origin(operand, origins)
        }
        _ => None,
    };
    if matches!(
        body.local_decls[destination.local].ty.kind(),
        ty::RawPtr(..)
    ) || origins.contains_key(&destination.local)
        || origin.is_some()
    {
        update_optional_origin(origins, destination.local, origin);
    }
}

fn registration_callback_summary_origin_from_operands<'a, 'tcx>(
    operands: impl IntoIterator<Item = &'a Operand<'tcx>>,
    origins: &BTreeMap<Local, Option<usize>>,
) -> Option<usize>
where
    'tcx: 'a,
{
    let mut unique = None;
    let mut operand_count = 0usize;
    for operand in operands {
        operand_count += 1;
        let Some(origin) = registration_callback_summary_operand_origin(operand, origins) else {
            return None;
        };
        if unique.is_some_and(|existing| existing != origin) {
            return None;
        }
        unique = Some(origin);
    }
    (operand_count == 1).then_some(unique).flatten()
}

fn registration_callback_summary_operand_origin(
    operand: &Operand<'_>,
    origins: &BTreeMap<Local, Option<usize>>,
) -> Option<usize> {
    operand.place().and_then(|place| {
        place
            .projection
            .is_empty()
            .then(|| origins.get(&place.local).copied().flatten())
            .flatten()
    })
}

fn registration_raw_pointer_summary_operand_origin(
    operand: &Operand<'_>,
    origins: &BTreeMap<Local, Option<usize>>,
) -> Option<usize> {
    operand.place().and_then(|place| {
        place
            .projection
            .is_empty()
            .then(|| origins.get(&place.local).copied().flatten())
            .flatten()
    })
}

fn registration_summary_from_direct_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    current_crate_name: &str,
    owner_def_path: &str,
    callback_origins: &BTreeMap<Local, Option<usize>>,
    raw_pointer_origins: &BTreeMap<Local, Option<usize>>,
) -> Option<RegistrationCallSummary> {
    let call_context = CallContext {
        current_crate_name,
        owner_def_path: Some(owner_def_path),
    };
    let callback_arg_indices =
        registration::callback_argument_indices(callee_def_path, call_context);
    let callback_arg_index =
        unique_registration_callback_arg_index(args, &callback_arg_indices, callback_origins);
    let callback_argument_kind = if callback_arg_index.is_some() {
        RegistrationArgumentKind::CallbackPresent
    } else {
        RegistrationArgumentKind::Unknown
    };
    let Some(CallClassification::Registration { api_id, role }) =
        registration::classify_call(callee_def_path, callback_argument_kind, call_context)
    else {
        return None;
    };
    if role != bw_model::RegistrationRole::Register {
        return None;
    }
    let user_data_arg_indices = registration::user_data_argument_indices(&api_id);
    let user_data_arg_index = unique_registration_raw_pointer_arg_index(
        args,
        &user_data_arg_indices,
        raw_pointer_origins,
    );
    if callback_arg_index.is_none() || user_data_arg_index.is_none() {
        return None;
    }
    Some(RegistrationCallSummary {
        api_id,
        role,
        callback_arg_index,
        user_data_arg_index,
    })
}

fn registration_summary_from_nested_summary<'tcx>(
    summary: RegistrationCallSummary,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    callback_origins: &BTreeMap<Local, Option<usize>>,
    raw_pointer_origins: &BTreeMap<Local, Option<usize>>,
) -> Option<RegistrationCallSummary> {
    Some(RegistrationCallSummary {
        api_id: summary.api_id,
        role: summary.role,
        callback_arg_index: summary.callback_arg_index.and_then(|index| {
            args.get(index).and_then(|arg| {
                registration_callback_summary_operand_origin(&arg.node, callback_origins)
            })
        }),
        user_data_arg_index: summary.user_data_arg_index.and_then(|index| {
            args.get(index).and_then(|arg| {
                registration_raw_pointer_summary_operand_origin(&arg.node, raw_pointer_origins)
            })
        }),
    })
    .filter(|summary| summary.callback_arg_index.is_some() && summary.user_data_arg_index.is_some())
}

fn unique_registration_callback_arg_index<'tcx>(
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    indices: &[usize],
    origins: &BTreeMap<Local, Option<usize>>,
) -> Option<usize> {
    let mut unique = None;
    for origin in indexed_args(args, indices)
        .filter_map(|arg| registration_callback_summary_operand_origin(&arg.node, origins))
    {
        if unique.is_some_and(|existing| existing != origin) {
            return None;
        }
        unique = Some(origin);
    }
    unique
}

fn unique_registration_raw_pointer_arg_index<'tcx>(
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    indices: &[usize],
    origins: &BTreeMap<Local, Option<usize>>,
) -> Option<usize> {
    let mut unique = None;
    for origin in indexed_args(args, indices)
        .filter_map(|arg| registration_raw_pointer_summary_operand_origin(&arg.node, origins))
    {
        if unique.is_some_and(|existing| existing != origin) {
            return None;
        }
        unique = Some(origin);
    }
    unique
}

fn record_registration_summary_unknown_destination<'tcx>(
    body: &Body<'tcx>,
    callback_origins: &mut BTreeMap<Local, Option<usize>>,
    raw_pointer_origins: &mut BTreeMap<Local, Option<usize>>,
    destination: &Place<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let ty = body.local_decls[destination.local].ty;
    if registration_callback_summary_type(ty) || callback_origins.contains_key(&destination.local) {
        update_optional_origin(callback_origins, destination.local, None);
    }
    if matches!(ty.kind(), ty::RawPtr(..)) || raw_pointer_origins.contains_key(&destination.local) {
        update_optional_origin(raw_pointer_origins, destination.local, None);
    }
}

fn openssl_ex_data_string_origin_prefixed_aliases(
    origins: &BTreeMap<RawPointerPlaceKey, Option<String>>,
    field_prefix: &RawPointerPlaceKey,
    operand: &Operand<'_>,
) -> Vec<(RawPointerPlaceKey, Option<String>)> {
    let Some(source_place) = operand.place() else {
        return Vec::new();
    };
    let Some(source_key) = raw_pointer_place_key(&source_place) else {
        return Vec::new();
    };
    origins
        .iter()
        .filter_map(|(key, value)| {
            if key.local != source_key.local || !key.projection.starts_with(&source_key.projection)
            {
                return None;
            }
            let mut projection = field_prefix.projection.clone();
            projection.extend_from_slice(&key.projection[source_key.projection.len()..]);
            Some((
                RawPointerPlaceKey {
                    local: field_prefix.local,
                    projection,
                },
                value.clone(),
            ))
        })
        .collect()
}

fn copy_openssl_ex_data_string_origin_alias(
    destination_key: &RawPointerPlaceKey,
    source: &Operand<'_>,
    origins: &mut BTreeMap<RawPointerPlaceKey, Option<String>>,
) {
    let aliases = openssl_ex_data_string_origin_prefixed_aliases(origins, destination_key, source);
    forget_openssl_ex_data_string_origin_prefix(origins, destination_key);
    for (key, value) in aliases {
        update_optional_origin(origins, key, value);
    }
}

fn forget_openssl_ex_data_string_origin_prefix(
    origins: &mut BTreeMap<RawPointerPlaceKey, Option<String>>,
    prefix: &RawPointerPlaceKey,
) {
    origins.retain(|key, _| {
        key.local != prefix.local || !key.projection.starts_with(&prefix.projection)
    });
}

fn merge_registration_call_summary(
    existing: Option<RegistrationCallSummary>,
    candidate: RegistrationCallSummary,
) -> Option<Option<RegistrationCallSummary>> {
    if existing
        .as_ref()
        .is_some_and(|existing| existing != &candidate)
    {
        return None;
    }
    Some(Some(candidate))
}

fn summarize_returned_borrow_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    current_crate_name: &str,
    def_id: DefId,
) -> Option<ReturnedBorrowOrigin> {
    let closure_returned_borrow_capture_summaries = ClosureReturnedBorrowCaptureSummaries::new();
    summarize_returned_borrow_callable_with_captures(
        tcx,
        current_crate_name,
        def_id,
        &closure_returned_borrow_capture_summaries,
    )
}

fn summarize_returned_borrow_callable_with_captures<'tcx>(
    tcx: TyCtxt<'tcx>,
    current_crate_name: &str,
    def_id: DefId,
    closure_returned_borrow_capture_summaries: &ClosureReturnedBorrowCaptureSummaries,
) -> Option<ReturnedBorrowOrigin> {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);
    let return_local = Local::new(0);
    if !ty_contains_ref(body.local_decls[return_local].ty) {
        return None;
    }
    let owner_def_path = tcx.def_path_str(def_id);
    let mut visitor = MirSiteVisitor {
        tcx,
        body,
        current_crate_name,
        collection_lookup_contracts: &[],
        owner_def_path,
        owner_is_foreign_callback: false,
        observations: MirSiteObservations::default(),
        raw_pointer_origins: BTreeMap::new(),
        raw_pointer_borrow_origins: BTreeMap::new(),
        closure_upvar_sources: BTreeMap::new(),
        receiver_borrow_locals: BTreeMap::new(),
        borrowed_foreign_pointer_origins: BTreeMap::new(),
        returned_borrow_origins: BTreeMap::new(),
        returned_borrow_return_origins: Vec::new(),
        returned_borrow_slot_assignment_origins: Vec::new(),
        returned_borrow_iterator_origins: BTreeMap::new(),
        fn_pointer_origins: BTreeMap::new(),
        option_fn_pointer_origins: BTreeMap::new(),
        fn_pointer_source_origins: BTreeMap::new(),
        option_fn_pointer_source_origins: BTreeMap::new(),
        option_fn_pointer_release_origins: BTreeMap::new(),
        previous_user_data_origins: BTreeMap::new(),
        hook_release_field_writes: Vec::new(),
        hook_previous_release_candidates: Vec::new(),
        borrow_origins: BTreeMap::new(),
        returned_borrow_storage_origins: BTreeMap::new(),
        returned_borrow_storage_reference_origins: BTreeMap::new(),
        returned_borrow_entry_value_reference_origins: BTreeMap::new(),
        pending_returned_borrow_entry_value_assignments: Vec::new(),
        returned_borrow_indexed_iterator_storage_origins: BTreeMap::new(),
        returned_borrow_slice_storage_origins: BTreeMap::new(),
        returned_borrow_unique_storage_origins: BTreeMap::new(),
        returned_borrow_local_wrapper_reference_origins: BTreeMap::new(),
        returned_borrow_invalidated_storage_keys: BTreeSet::new(),
        returned_borrow_sequence_lengths: BTreeMap::new(),
        returned_borrow_keyed_map_entry_origins: BTreeMap::new(),
        returned_borrow_keyed_map_entry_branch_writes: BTreeMap::new(),
        returned_borrow_keyed_map_split_entry_branch_writes: BTreeMap::new(),
        returned_borrow_keyed_map_known_empty: BTreeSet::new(),
        returned_borrow_keyed_map_known_occupied: BTreeSet::new(),
        stable_constant_origins: BTreeMap::new(),
        stable_range_origins: BTreeMap::new(),
        scoped_key_origins: BTreeMap::new(),
        unsupported_key_wrapper_origins: BTreeMap::new(),
        dynamic_key_generations: BTreeMap::new(),
        closure_storage_capture_summaries: BTreeMap::new(),
        discovered_closure_storage_captures: BTreeMap::new(),
        closure_returned_borrow_capture_summaries: closure_returned_borrow_capture_summaries
            .clone(),
        discovered_closure_returned_borrow_captures: BTreeMap::new(),
        closure_capture_use_summaries: BTreeMap::new(),
        atomic_ordering_origins: BTreeMap::new(),
        external_buffer_binding_keys: BTreeSet::new(),
        returned_borrow_invalidations: Vec::new(),
        returned_borrow_storage_uses: Vec::new(),
        returned_borrow_storage_mutation_barriers: Vec::new(),
        local_method_calls: Vec::new(),
        callback_user_data_invocations: Vec::new(),
        openssl_ex_data_get_origins: BTreeMap::new(),
        openssl_ex_data_handle_origins: BTreeMap::new(),
        openssl_ex_data_slot_origins: BTreeMap::new(),
        openssl_ex_data_slot_free_contracts: BTreeMap::new(),
        openssl_ex_data_free_contracts: BTreeMap::new(),
        openssl_ex_data_registrations: Vec::new(),
        openssl_ex_data_releases: Vec::new(),
    };
    visitor.visit_body(body);
    if !visitor.returned_borrow_return_origins.is_empty() {
        return unique_unconditional_returned_borrow_return_assignment_origin(
            body,
            visitor.returned_borrow_return_origins,
        );
    }
    let candidates = visitor
        .observations
        .returned_borrow_relations
        .iter()
        .map(|relation| ReturnedBorrowOrigin {
            source: relation.source.clone(),
            api_id: relation.api_id.clone(),
            returned_type_name: relation.returned_type_name.clone(),
        })
        .collect::<Vec<_>>();
    if !candidates.is_empty() {
        return unique_returned_borrow_origin(candidates);
    }
    visitor
        .returned_borrow_origins
        .get(&return_local)
        .cloned()
        .flatten()
}

fn summarize_returned_borrow_slot_assignment_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    current_crate_name: &str,
    def_id: DefId,
    closure_returned_borrow_capture_summaries: &ClosureReturnedBorrowCaptureSummaries,
) -> Option<ReturnedBorrowOrigin> {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);
    let owner_def_path = tcx.def_path_str(def_id);
    let mut visitor = MirSiteVisitor {
        tcx,
        body,
        current_crate_name,
        collection_lookup_contracts: &[],
        owner_def_path,
        owner_is_foreign_callback: false,
        observations: MirSiteObservations::default(),
        raw_pointer_origins: BTreeMap::new(),
        raw_pointer_borrow_origins: BTreeMap::new(),
        closure_upvar_sources: BTreeMap::new(),
        receiver_borrow_locals: BTreeMap::new(),
        borrowed_foreign_pointer_origins: BTreeMap::new(),
        returned_borrow_origins: BTreeMap::new(),
        returned_borrow_return_origins: Vec::new(),
        returned_borrow_slot_assignment_origins: Vec::new(),
        returned_borrow_iterator_origins: BTreeMap::new(),
        fn_pointer_origins: BTreeMap::new(),
        option_fn_pointer_origins: BTreeMap::new(),
        fn_pointer_source_origins: BTreeMap::new(),
        option_fn_pointer_source_origins: BTreeMap::new(),
        option_fn_pointer_release_origins: BTreeMap::new(),
        previous_user_data_origins: BTreeMap::new(),
        hook_release_field_writes: Vec::new(),
        hook_previous_release_candidates: Vec::new(),
        borrow_origins: BTreeMap::new(),
        returned_borrow_storage_origins: BTreeMap::new(),
        returned_borrow_storage_reference_origins: BTreeMap::new(),
        returned_borrow_entry_value_reference_origins: BTreeMap::new(),
        pending_returned_borrow_entry_value_assignments: Vec::new(),
        returned_borrow_indexed_iterator_storage_origins: BTreeMap::new(),
        returned_borrow_slice_storage_origins: BTreeMap::new(),
        returned_borrow_unique_storage_origins: BTreeMap::new(),
        returned_borrow_local_wrapper_reference_origins: BTreeMap::new(),
        returned_borrow_invalidated_storage_keys: BTreeSet::new(),
        returned_borrow_sequence_lengths: BTreeMap::new(),
        returned_borrow_keyed_map_entry_origins: BTreeMap::new(),
        returned_borrow_keyed_map_entry_branch_writes: BTreeMap::new(),
        returned_borrow_keyed_map_split_entry_branch_writes: BTreeMap::new(),
        returned_borrow_keyed_map_known_empty: BTreeSet::new(),
        returned_borrow_keyed_map_known_occupied: BTreeSet::new(),
        stable_constant_origins: BTreeMap::new(),
        stable_range_origins: BTreeMap::new(),
        scoped_key_origins: BTreeMap::new(),
        unsupported_key_wrapper_origins: BTreeMap::new(),
        dynamic_key_generations: BTreeMap::new(),
        closure_storage_capture_summaries: BTreeMap::new(),
        discovered_closure_storage_captures: BTreeMap::new(),
        closure_returned_borrow_capture_summaries: closure_returned_borrow_capture_summaries
            .clone(),
        discovered_closure_returned_borrow_captures: BTreeMap::new(),
        closure_capture_use_summaries: BTreeMap::new(),
        atomic_ordering_origins: BTreeMap::new(),
        external_buffer_binding_keys: BTreeSet::new(),
        returned_borrow_invalidations: Vec::new(),
        returned_borrow_storage_uses: Vec::new(),
        returned_borrow_storage_mutation_barriers: Vec::new(),
        local_method_calls: Vec::new(),
        callback_user_data_invocations: Vec::new(),
        openssl_ex_data_get_origins: BTreeMap::new(),
        openssl_ex_data_handle_origins: BTreeMap::new(),
        openssl_ex_data_slot_origins: BTreeMap::new(),
        openssl_ex_data_slot_free_contracts: BTreeMap::new(),
        openssl_ex_data_free_contracts: BTreeMap::new(),
        openssl_ex_data_registrations: Vec::new(),
        openssl_ex_data_releases: Vec::new(),
    };
    visitor.visit_body(body);
    unique_unconditional_returned_borrow_slot_assignment_origin(
        body,
        visitor.returned_borrow_slot_assignment_origins,
    )
}

fn unique_returned_borrow_origin(
    origins: impl IntoIterator<Item = ReturnedBorrowOrigin>,
) -> Option<ReturnedBorrowOrigin> {
    let mut unique = None;
    for origin in origins {
        if let Some(existing) = &unique
            && existing != &origin
        {
            return None;
        }
        unique = Some(origin);
    }
    unique
}

fn unique_unconditional_returned_borrow_slot_assignment_origin(
    body: &Body<'_>,
    assignments: impl IntoIterator<Item = ReturnedBorrowSlotAssignment>,
) -> Option<ReturnedBorrowOrigin> {
    let mut unique = None;
    let mut has_postdominating_assignment = false;
    let mut covered_blocks = BTreeSet::new();
    for assignment in assignments {
        let KeyedMapEntryBranchWrite::Returned(origin) = assignment.write else {
            return None;
        };
        if let Some(existing) = &unique
            && existing != &origin
        {
            return None;
        }
        if release_postdominates_entry(body, assignment.location.block.index()) {
            has_postdominating_assignment = true;
        }
        covered_blocks.insert(assignment.location.block);
        unique = Some(origin);
    }
    let covers_all_paths = has_postdominating_assignment
        || blocks_cover_all_entry_to_exit_paths(body, &covered_blocks);
    covers_all_paths.then_some(unique).flatten()
}

fn unique_unconditional_returned_borrow_return_assignment_origin(
    body: &Body<'_>,
    assignments: impl IntoIterator<Item = ReturnedBorrowReturnAssignment>,
) -> Option<ReturnedBorrowOrigin> {
    let mut unique = None;
    let mut has_postdominating_return_assignment = false;
    let mut covered_blocks = BTreeSet::new();
    for assignment in assignments {
        let KeyedMapEntryBranchWrite::Returned(origin) = assignment.write else {
            return None;
        };
        if let Some(existing) = &unique
            && existing != &origin
        {
            return None;
        }
        if release_postdominates_entry(body, assignment.location.block.index()) {
            has_postdominating_return_assignment = true;
        }
        covered_blocks.insert(assignment.location.block);
        unique = Some(origin);
    }
    let covers_all_paths = has_postdominating_return_assignment
        || blocks_cover_all_entry_to_exit_paths(body, &covered_blocks);
    covers_all_paths.then_some(unique).flatten()
}

fn summarize_string_key_return_callable<'tcx>(tcx: TyCtxt<'tcx>, def_id: DefId) -> Option<usize> {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);
    let return_local = Local::new(0);
    let return_type = body.local_decls[return_local].ty;
    let return_type_name = return_type.to_string();
    let return_is_string_key =
        owned_string_key_type(&return_type_name) || string_like_key_type(&return_type_name);
    let return_is_audited_key_wrapper =
        !return_is_string_key && key_wrapper_return_type_has_local_derive_hash_eq(tcx, return_type);
    if !return_is_string_key && !return_is_audited_key_wrapper {
        return None;
    }

    let mut origins = BTreeMap::<Local, Option<usize>>::new();
    for (arg_index, local) in body.args_iter().enumerate() {
        if string_like_key_type(&body.local_decls[local].ty.to_string()) {
            origins.insert(local, Some(arg_index));
        }
    }
    if origins.is_empty() {
        return None;
    }

    for block in body.basic_blocks.iter() {
        for statement in &block.statements {
            let StatementKind::Assign(assignment) = &statement.kind else {
                continue;
            };
            let (place, rvalue) = &**assignment;
            record_string_key_summary_assignment(body, &mut origins, place, rvalue);
        }
        if let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &block.terminator().kind
        {
            let Some((callee_def_id, _)) = func.const_fn_def() else {
                record_string_key_summary_unknown_destination(body, &mut origins, destination);
                continue;
            };
            let callee_def_path = tcx.def_path_str(callee_def_id);
            record_string_key_summary_call(
                tcx,
                body,
                &mut origins,
                callee_def_id,
                &callee_def_path,
                args,
                destination,
            );
        }
    }

    origins.get(&return_local).copied().flatten()
}

fn key_wrapper_return_type_has_local_derive_hash_eq<'tcx>(
    tcx: TyCtxt<'tcx>,
    return_type: Ty<'tcx>,
) -> bool {
    let ty::Adt(adt_def, _) = return_type.kind() else {
        return false;
    };
    let def_id = adt_def.did();
    if def_id.as_local().is_none() {
        return false;
    }
    let span = tcx.def_span(def_id);
    let Ok(path) = source_path(tcx, span) else {
        return false;
    };
    let (_, line_start, _, _, _) = tcx.sess.source_map().span_to_location_info(span);
    if line_start <= 1 {
        return false;
    }
    let Ok(source) = fs::read_to_string(path) else {
        return false;
    };
    let lines = source.lines().collect::<Vec<_>>();
    let mut index = line_start.saturating_sub(2);
    let mut derive_lines = Vec::new();
    while index < lines.len() && derive_lines.len() < 8 {
        let trimmed = lines[index].trim();
        if trimmed.is_empty() {
            break;
        }
        derive_lines.push(trimmed);
        if trimmed.starts_with("#[") {
            break;
        }
        if index == 0 {
            break;
        }
        index -= 1;
    }
    derive_lines.reverse();
    let derive_attr = derive_lines.join(" ");
    if !derive_attr.contains("#[derive") {
        return false;
    }
    ["Hash", "Eq", "PartialEq"]
        .iter()
        .all(|required| derive_attr_has_token(&derive_attr, required))
}

fn derive_attr_has_token(attribute: &str, token: &str) -> bool {
    attribute
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|part| part == token)
}

fn string_key_summary_origin_from_aggregate<'a, 'tcx>(
    operands: impl IntoIterator<Item = &'a Operand<'tcx>>,
    origins: &BTreeMap<Local, Option<usize>>,
) -> Option<usize>
where
    'tcx: 'a,
{
    let mut unique = None;
    let mut operand_count = 0usize;
    for operand in operands {
        operand_count += 1;
        let Some(origin) = string_key_summary_operand_origin(operand, origins) else {
            return None;
        };
        if unique.is_some_and(|existing| existing != origin) {
            return None;
        }
        unique = Some(origin);
    }
    (operand_count == 1).then_some(unique).flatten()
}

fn record_string_key_summary_assignment<'tcx>(
    body: &Body<'tcx>,
    origins: &mut BTreeMap<Local, Option<usize>>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let origin = match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            string_key_summary_operand_origin(operand, origins)
        }
        Rvalue::Ref(_, _, place) => string_key_summary_place_origin(place, origins),
        Rvalue::Aggregate(_, operands) => {
            string_key_summary_origin_from_aggregate(operands, origins)
        }
        _ => None,
    };
    if owned_string_key_type(&body.local_decls[destination.local].ty.to_string())
        || string_like_key_type(&body.local_decls[destination.local].ty.to_string())
        || origins.contains_key(&destination.local)
        || (matches!(rvalue, Rvalue::Aggregate(..)) && origin.is_some())
    {
        update_optional_origin(origins, destination.local, origin);
    }
}

fn record_string_key_summary_call<'tcx>(
    tcx: TyCtxt<'tcx>,
    body: &Body<'tcx>,
    origins: &mut BTreeMap<Local, Option<usize>>,
    callee_def_id: DefId,
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    destination: &Place<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let origin = if string_key_passthrough_call(callee_def_path) {
        args.first()
            .and_then(|arg| string_key_summary_operand_origin(&arg.node, origins))
    } else {
        summarize_string_key_return_callable(tcx, callee_def_id).and_then(|arg_index| {
            args.get(arg_index)
                .and_then(|arg| string_key_summary_operand_origin(&arg.node, origins))
        })
    };
    if owned_string_key_type(&body.local_decls[destination.local].ty.to_string())
        || string_like_key_type(&body.local_decls[destination.local].ty.to_string())
        || origins.contains_key(&destination.local)
        || origin.is_some()
    {
        update_optional_origin(origins, destination.local, origin);
    }
}

fn record_string_key_summary_unknown_destination<'tcx>(
    body: &Body<'tcx>,
    origins: &mut BTreeMap<Local, Option<usize>>,
    destination: &Place<'tcx>,
) {
    if destination.projection.is_empty()
        && (owned_string_key_type(&body.local_decls[destination.local].ty.to_string())
            || string_like_key_type(&body.local_decls[destination.local].ty.to_string())
            || origins.contains_key(&destination.local))
    {
        update_optional_origin(origins, destination.local, None);
    }
}

fn string_key_summary_operand_origin(
    operand: &Operand<'_>,
    origins: &BTreeMap<Local, Option<usize>>,
) -> Option<usize> {
    operand
        .place()
        .and_then(|place| string_key_summary_place_origin(&place, origins))
}

fn string_key_summary_place_origin(
    place: &Place<'_>,
    origins: &BTreeMap<Local, Option<usize>>,
) -> Option<usize> {
    if !place.projection.is_empty() {
        return None;
    }
    origins.get(&place.local).copied().flatten()
}

fn summarize_returned_borrow_collection_use_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
) -> Option<ReturnedBorrowCollectionUseAnalysis> {
    let mut visited = BTreeSet::new();
    summarize_returned_borrow_collection_use_callable_inner(tcx, def_id, &mut visited)
}

fn summarize_returned_borrow_collection_use_callable_inner<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
    visited: &mut BTreeSet<String>,
) -> Option<ReturnedBorrowCollectionUseAnalysis> {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);
    let owner_def_path = tcx.def_path_str(def_id);
    if !visited.insert(owner_def_path) {
        return None;
    }
    if !ty_contains_ref(body.local_decls[Local::new(0)].ty) {
        return None;
    }

    let mut storage_origins = BTreeMap::<Local, Option<usize>>::new();
    let mut key_origins = BTreeMap::<Local, Option<usize>>::new();
    let mut stable_constant_origins = BTreeMap::<Local, String>::new();
    let mut stable_range_origins = BTreeMap::<Local, ConstRangeBounds>::new();
    let mut slice_origins = BTreeMap::<Local, Option<IndexedIteratorArgOrigin>>::new();
    let mut iterator_origins = BTreeMap::<Local, Option<IndexedIteratorArgOrigin>>::new();
    let mut callable_origins = BTreeMap::<Local, DefId>::new();
    for (arg_index, local) in body.args_iter().enumerate() {
        let type_name = body.local_decls[local].ty.to_string();
        if returned_borrow_collection_storage_type(&type_name) {
            storage_origins.insert(local, Some(arg_index));
        }
        if string_like_key_type(&type_name) {
            key_origins.insert(local, Some(arg_index));
        }
    }
    if storage_origins.is_empty() {
        return None;
    }

    let mut unique_summary = None;
    let mut binding_gaps = Vec::<ReturnedBorrowCollectionBindingGapSummary>::new();
    for block in body.basic_blocks.iter() {
        for statement in &block.statements {
            let StatementKind::Assign(assignment) = &statement.kind else {
                continue;
            };
            let (place, rvalue) = &**assignment;
            record_collection_storage_summary_assignment(&mut storage_origins, place, rvalue);
            record_stable_constant_summary_assignment(&mut stable_constant_origins, place, rvalue);
            record_stable_range_summary_assignment(
                &mut stable_range_origins,
                &stable_constant_origins,
                body,
                tcx,
                place,
                rvalue,
            );
            record_collection_summary_slice_assignment(&mut slice_origins, place, rvalue);
            record_string_key_summary_assignment(body, &mut key_origins, place, rvalue);
            record_collection_summary_indexed_iterator_assignment(
                &mut iterator_origins,
                place,
                rvalue,
            );
            record_collection_summary_callable_assignment(
                &mut callable_origins,
                body,
                tcx,
                place,
                rvalue,
            );
        }
        if let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &block.terminator().kind
        {
            record_collection_summary_indexed_iterator_unknown_destination(
                &mut iterator_origins,
                destination,
            );
            record_collection_summary_slice_unknown_destination(&mut slice_origins, destination);
            if destination.projection.is_empty() {
                stable_range_origins.remove(&destination.local);
            }
            let Some((callee_def_id, _)) = func.const_fn_def() else {
                record_collection_storage_summary_unknown_destination(
                    body,
                    &mut storage_origins,
                    destination,
                );
                record_string_key_summary_unknown_destination(body, &mut key_origins, destination);
                continue;
            };
            let callee_def_path = tcx.def_path_str(callee_def_id);
            if returned_borrow_collection_mutating_call_in_summary(
                &callee_def_path,
                args,
                &storage_origins,
            ) {
                return None;
            }
            record_stable_range_summary_constructor_call(
                &mut stable_range_origins,
                &stable_constant_origins,
                &callee_def_path,
                args,
                body,
                tcx,
                destination,
            );
            let range_slice_origin_recorded = record_collection_summary_range_slice_call(
                &mut slice_origins,
                &callee_def_path,
                args,
                body,
                tcx,
                destination,
                &storage_origins,
                &stable_range_origins,
            );
            let mut call_binding_gaps = Vec::new();
            let direct_summary = if let Some(analysis) =
                returned_borrow_option_and_then_collection_use_analysis_from_call(
                    &callee_def_path,
                    args,
                    body,
                    tcx,
                    &storage_origins,
                    &callable_origins,
                ) {
                call_binding_gaps.extend(analysis.binding_gaps);
                analysis.summary
            } else {
                returned_borrow_collection_iterator_use_summary_from_call(
                    &callee_def_path,
                    args,
                    &iterator_origins,
                    &stable_constant_origins,
                )
                .or_else(|| {
                    returned_borrow_collection_use_summary_from_call(
                        &callee_def_path,
                        args,
                        body,
                        tcx,
                        &storage_origins,
                        &key_origins,
                        &slice_origins,
                        &stable_constant_origins,
                    )
                })
            };
            let nested_analysis = {
                let mut nested_visited = visited.clone();
                summarize_returned_borrow_collection_use_callable_inner(
                    tcx,
                    callee_def_id,
                    &mut nested_visited,
                )
            };
            let nested_summary = nested_analysis.as_ref().and_then(|analysis| {
                returned_borrow_collection_use_summary_from_nested_analysis(
                    analysis,
                    args,
                    &storage_origins,
                    &key_origins,
                )
            });
            if let Some(analysis) = &nested_analysis {
                call_binding_gaps.extend(
                    collection_use_binding_gap_summaries_from_nested_analysis(
                        analysis,
                        args,
                        &storage_origins,
                    ),
                );
            }
            let mut emitted_summary = false;
            for summary in [direct_summary, nested_summary].into_iter().flatten() {
                if let Some(existing) = unique_summary
                    && existing != summary
                {
                    return None;
                }
                unique_summary = Some(summary);
                emitted_summary = true;
            }
            if !emitted_summary {
                if call_binding_gaps.is_empty() {
                    if let Some(gap) = returned_borrow_collection_iterator_use_binding_gap_from_call(
                        &callee_def_path,
                        args,
                        &iterator_origins,
                        &stable_constant_origins,
                    ) {
                        binding_gaps.push(gap);
                    }
                    if let Some(gap) = returned_borrow_collection_use_binding_gap_from_call(
                        &callee_def_path,
                        args,
                        body,
                        tcx,
                        &storage_origins,
                        &stable_constant_origins,
                    )
                    .filter(|_| !range_slice_origin_recorded)
                    {
                        binding_gaps.push(gap);
                    }
                }
            }
            binding_gaps.extend(call_binding_gaps);
            consume_collection_summary_indexed_iterator_use(
                &callee_def_path,
                args,
                &mut iterator_origins,
            );
            record_string_key_summary_call(
                tcx,
                body,
                &mut key_origins,
                callee_def_id,
                &callee_def_path,
                args,
                destination,
            );
            let storage_reference_passthrough =
                record_collection_storage_summary_reference_passthrough_call(
                    &callee_def_path,
                    args,
                    body,
                    tcx,
                    destination,
                    &mut storage_origins,
                );
            record_collection_summary_slice_passthrough_call(
                &callee_def_path,
                args,
                destination,
                &mut slice_origins,
            );
            if !storage_reference_passthrough {
                record_collection_storage_summary_unknown_destination(
                    body,
                    &mut storage_origins,
                    destination,
                );
            }
            record_collection_summary_indexed_iterator_call(
                &callee_def_path,
                args,
                body,
                tcx,
                destination,
                &storage_origins,
                &slice_origins,
                &mut iterator_origins,
                &stable_constant_origins,
            )
            .into_iter()
            .for_each(|gap| binding_gaps.push(gap));
        }
    }

    (unique_summary.is_some() || !binding_gaps.is_empty()).then_some(
        ReturnedBorrowCollectionUseAnalysis {
            summary: unique_summary,
            binding_gaps,
        },
    )
}

fn summarize_returned_borrow_value_use_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
) -> Option<ReturnedBorrowValueUseSummary> {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);
    if !returned_borrow_value_argument_use_type(body.local_decls[Local::new(0)].ty) {
        return None;
    }

    let mut value_origins = BTreeMap::<Local, Option<usize>>::new();
    for (arg_index, local) in body.args_iter().enumerate() {
        if returned_borrow_value_argument_use_type(body.local_decls[local].ty) {
            value_origins.insert(local, Some(arg_index));
        }
    }
    if value_origins.is_empty() {
        return None;
    }

    let mut returned_arg_index = None;
    for block in body.basic_blocks.iter() {
        for statement in &block.statements {
            let StatementKind::Assign(assignment) = &statement.kind else {
                continue;
            };
            let (place, rvalue) = &**assignment;
            if !place.projection.is_empty() {
                if place.local == Local::new(0) {
                    return None;
                }
                continue;
            }
            let origin = returned_borrow_value_summary_origin_from_rvalue(rvalue, &value_origins);
            if let Some(origin) = origin {
                value_origins.insert(place.local, origin);
            } else {
                value_origins.remove(&place.local);
            }
            if place.local == Local::new(0) {
                let Some(arg_index) = origin.flatten() else {
                    return None;
                };
                if returned_arg_index.is_some_and(|existing| existing != arg_index) {
                    return None;
                }
                returned_arg_index = Some(arg_index);
            }
        }
        if let TerminatorKind::Call { destination, .. } = &block.terminator().kind
            && destination.projection.is_empty()
        {
            if destination.local == Local::new(0) {
                return None;
            }
            value_origins.remove(&destination.local);
        }
    }

    returned_arg_index.map(|value_arg_index| ReturnedBorrowValueUseSummary { value_arg_index })
}

fn returned_borrow_value_summary_origin_from_rvalue(
    rvalue: &Rvalue<'_>,
    value_origins: &BTreeMap<Local, Option<usize>>,
) -> Option<Option<usize>> {
    match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            returned_borrow_value_summary_origin_from_operand(operand, value_origins)
        }
        _ => None,
    }
}

fn returned_borrow_value_summary_origin_from_operand(
    operand: &Operand<'_>,
    value_origins: &BTreeMap<Local, Option<usize>>,
) -> Option<Option<usize>> {
    let place = operand.place()?;
    if place.projection.is_empty() {
        value_origins.get(&place.local).copied()
    } else {
        None
    }
}

fn summarize_returned_borrow_wrapper_destructure_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
) -> Option<ReturnedBorrowWrapperDestructureSummary> {
    if !matches!(tcx.def_kind(def_id), DefKind::AssocFn | DefKind::Fn)
        || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);
    if !returned_borrow_value_argument_use_type(body.local_decls[Local::new(0)].ty) {
        return None;
    }
    let arg_locals = body
        .args_iter()
        .enumerate()
        .map(|(arg_index, local)| (local, arg_index))
        .collect::<BTreeMap<_, _>>();
    let mut local_origins =
        BTreeMap::<Local, Option<ReturnedBorrowWrapperDestructureSummary>>::new();
    let mut summary = None;
    for block in body.basic_blocks.iter() {
        for statement in &block.statements {
            let StatementKind::Assign(assignment) = &statement.kind else {
                continue;
            };
            let (place, rvalue) = &**assignment;
            if place.local != Local::new(0) || !place.projection.is_empty() {
                if place.projection.is_empty() {
                    let origin = returned_borrow_wrapper_destructure_summary_from_rvalue(
                        body,
                        rvalue,
                        &arg_locals,
                        &local_origins,
                    );
                    update_optional_origin(&mut local_origins, place.local, origin);
                } else if place.local == Local::new(0) {
                    return None;
                }
                continue;
            }
            let candidate = returned_borrow_wrapper_destructure_summary_from_rvalue(
                body,
                rvalue,
                &arg_locals,
                &local_origins,
            )?;
            merge_returned_borrow_wrapper_destructure_summary(&mut summary, candidate)?;
        }
        if let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &block.terminator().kind
            && destination.projection.is_empty()
        {
            let candidate = func
                .const_fn_def()
                .map(|(callee_def_id, _)| tcx.def_path_str(callee_def_id))
                .and_then(|callee_def_path| {
                    returned_borrow_wrapper_destructure_summary_from_take_replace_call(
                        &callee_def_path,
                        args,
                        body,
                        tcx,
                        &arg_locals,
                        &local_origins,
                    )
                });
            if destination.local == Local::new(0) {
                let candidate = candidate?;
                merge_returned_borrow_wrapper_destructure_summary(&mut summary, candidate)?;
            } else {
                update_optional_origin(&mut local_origins, destination.local, candidate);
            }
        }
    }
    summary
}

fn returned_borrow_wrapper_destructure_summary_from_rvalue<'tcx>(
    body: &Body<'tcx>,
    rvalue: &Rvalue<'tcx>,
    arg_locals: &BTreeMap<Local, usize>,
    local_origins: &BTreeMap<Local, Option<ReturnedBorrowWrapperDestructureSummary>>,
) -> Option<ReturnedBorrowWrapperDestructureSummary> {
    let source_place = returned_borrow_storage_use_source_place(rvalue)?;
    returned_borrow_wrapper_destructure_summary_from_place(
        body,
        &source_place,
        arg_locals,
        local_origins,
        false,
    )
}

fn returned_borrow_wrapper_destructure_summary_from_take_replace_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    arg_locals: &BTreeMap<Local, usize>,
    local_origins: &BTreeMap<Local, Option<ReturnedBorrowWrapperDestructureSummary>>,
) -> Option<ReturnedBorrowWrapperDestructureSummary> {
    let first_arg = args.first()?;
    let storage_arg_type_name = first_arg.node.ty(&body.local_decls, tcx).to_string();
    if !returned_borrow_option_take_or_replace_call(callee_def_path, args, &storage_arg_type_name) {
        return None;
    }
    let source_place = first_arg.node.place()?;
    returned_borrow_wrapper_destructure_summary_from_place(
        body,
        &source_place,
        arg_locals,
        local_origins,
        true,
    )
}

fn returned_borrow_wrapper_destructure_summary_from_place<'tcx>(
    body: &Body<'tcx>,
    source_place: &Place<'tcx>,
    arg_locals: &BTreeMap<Local, usize>,
    local_origins: &BTreeMap<Local, Option<ReturnedBorrowWrapperDestructureSummary>>,
    clears_source: bool,
) -> Option<ReturnedBorrowWrapperDestructureSummary> {
    if source_place.projection.is_empty() {
        let mut summary = local_origins.get(&source_place.local).cloned().flatten()?;
        summary.clears_source |= clears_source;
        return Some(summary);
    }
    let wrapper_arg_index = *arg_locals.get(&source_place.local)?;
    let field_path = storage_projection_key(body, &source_place)?;
    if field_path.is_empty() {
        return None;
    }
    Some(ReturnedBorrowWrapperDestructureSummary {
        wrapper_arg_index,
        field_path,
        clears_source,
    })
}

fn merge_returned_borrow_wrapper_destructure_summary(
    summary: &mut Option<ReturnedBorrowWrapperDestructureSummary>,
    candidate: ReturnedBorrowWrapperDestructureSummary,
) -> Option<()> {
    if summary
        .as_ref()
        .is_some_and(|existing| existing != &candidate)
    {
        return None;
    }
    *summary = Some(candidate);
    Some(())
}

fn summarize_returned_borrow_collection_mutation_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
) -> Option<ReturnedBorrowCollectionMutationSummary> {
    let mut visited = BTreeSet::new();
    summarize_returned_borrow_collection_mutation_callable_inner(tcx, def_id, &mut visited)
}

fn summarize_returned_borrow_collection_mutation_callable_inner<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
    visited: &mut BTreeSet<String>,
) -> Option<ReturnedBorrowCollectionMutationSummary> {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);
    let owner_def_path = tcx.def_path_str(def_id);
    if !visited.insert(owner_def_path) {
        return None;
    }

    let mut storage_origins = BTreeMap::<Local, Option<usize>>::new();
    let mut key_origins = BTreeMap::<Local, Option<usize>>::new();
    let mut entry_origins =
        BTreeMap::<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>::new();
    for (arg_index, local) in body.args_iter().enumerate() {
        let type_name = body.local_decls[local].ty.to_string();
        if returned_borrow_keyed_map_storage_type(&type_name) {
            storage_origins.insert(local, Some(arg_index));
        }
        if string_like_key_type(&type_name) {
            key_origins.insert(local, Some(arg_index));
        }
    }
    if storage_origins.is_empty() {
        return None;
    }

    let mut unique_summary = None;
    for (block_index, block) in body.basic_blocks.iter().enumerate() {
        let basic_block = BasicBlock::new(block_index);
        for statement in &block.statements {
            let StatementKind::Assign(assignment) = &statement.kind else {
                continue;
            };
            let (place, rvalue) = &**assignment;
            record_collection_storage_summary_assignment(&mut storage_origins, place, rvalue);
            record_string_key_summary_assignment(body, &mut key_origins, place, rvalue);
            record_collection_entry_summary_assignment(&mut entry_origins, place, rvalue);
        }
        if let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &block.terminator().kind
        {
            let location = Location {
                block: basic_block,
                statement_index: block.statements.len(),
            };
            let Some((callee_def_id, _)) = func.const_fn_def() else {
                record_collection_storage_summary_unknown_destination(
                    body,
                    &mut storage_origins,
                    destination,
                );
                record_string_key_summary_unknown_destination(body, &mut key_origins, destination);
                continue;
            };
            let callee_def_path = tcx.def_path_str(callee_def_id);
            if let Some(summary) = returned_borrow_collection_mutation_summary_from_call(
                &callee_def_path,
                args,
                body,
                tcx,
                &storage_origins,
                &key_origins,
                &entry_origins,
            ) {
                unique_summary =
                    merge_returned_borrow_collection_mutation_summary(unique_summary, summary)?;
            }
            let nested_summary = {
                let mut nested_visited = visited.clone();
                summarize_returned_borrow_collection_mutation_callable_inner(
                    tcx,
                    callee_def_id,
                    &mut nested_visited,
                )
            }
            .and_then(|summary| {
                returned_borrow_collection_mutation_summary_from_nested_summary(
                    summary,
                    args,
                    &storage_origins,
                    &key_origins,
                )
            });
            if let Some(summary) = nested_summary {
                unique_summary =
                    merge_returned_borrow_collection_mutation_summary(unique_summary, summary)?;
            }
            record_string_key_summary_call(
                tcx,
                body,
                &mut key_origins,
                callee_def_id,
                &callee_def_path,
                args,
                destination,
            );
            record_collection_entry_summary_call(
                body,
                tcx,
                &mut entry_origins,
                callee_def_id,
                &callee_def_path,
                args,
                destination,
                &storage_origins,
                &key_origins,
                location,
                visited,
            );
            record_collection_storage_summary_unknown_destination(
                body,
                &mut storage_origins,
                destination,
            );
        }
    }

    unique_summary
}

fn summarize_returned_borrow_collection_remove_return_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
) -> Option<ReturnedBorrowCollectionRemoveReturnSummary> {
    let mut visited = BTreeSet::new();
    summarize_returned_borrow_collection_remove_return_callable_inner(tcx, def_id, &mut visited)
}

fn summarize_returned_borrow_collection_remove_return_callable_inner<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
    visited: &mut BTreeSet<String>,
) -> Option<ReturnedBorrowCollectionRemoveReturnSummary> {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);
    let owner_def_path = tcx.def_path_str(def_id);
    if !visited.insert(owner_def_path) {
        return None;
    }
    let return_local = Local::new(0);
    if !ty_contains_ref(body.local_decls[return_local].ty) {
        return None;
    }

    let mut storage_origins = BTreeMap::<Local, Option<usize>>::new();
    let mut key_origins = BTreeMap::<Local, Option<usize>>::new();
    for (arg_index, local) in body.args_iter().enumerate() {
        let type_name = body.local_decls[local].ty.to_string();
        if returned_borrow_keyed_map_storage_type(&type_name) {
            storage_origins.insert(local, Some(arg_index));
        }
        if string_like_key_type(&type_name) {
            key_origins.insert(local, Some(arg_index));
        }
    }
    if storage_origins.is_empty() || key_origins.is_empty() {
        return None;
    }

    let mut remove_return_origins =
        BTreeMap::<Local, Option<ReturnedBorrowCollectionRemoveReturnSummary>>::new();
    let mut unique_summary = None;
    for block in body.basic_blocks.iter() {
        for statement in &block.statements {
            let StatementKind::Assign(assignment) = &statement.kind else {
                continue;
            };
            let (place, rvalue) = &**assignment;
            record_collection_storage_summary_assignment(&mut storage_origins, place, rvalue);
            record_string_key_summary_assignment(body, &mut key_origins, place, rvalue);
            record_collection_remove_return_summary_assignment(
                &mut remove_return_origins,
                place,
                rvalue,
            );
            if place.local == return_local && place.projection.is_empty() {
                let summary = remove_return_origins
                    .get(&return_local)
                    .cloned()
                    .flatten()?;
                unique_summary = merge_returned_borrow_collection_remove_return_summary(
                    unique_summary,
                    summary,
                )?;
            }
        }

        if let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &block.terminator().kind
        {
            let Some((callee_def_id, _)) = func.const_fn_def() else {
                record_collection_storage_summary_unknown_destination(
                    body,
                    &mut storage_origins,
                    destination,
                );
                record_string_key_summary_unknown_destination(body, &mut key_origins, destination);
                record_collection_remove_return_summary_unknown_destination(
                    &mut remove_return_origins,
                    destination,
                );
                if destination.local == return_local && destination.projection.is_empty() {
                    return None;
                }
                continue;
            };
            let callee_def_path = tcx.def_path_str(callee_def_id);
            let direct_summary = returned_borrow_collection_remove_return_summary_from_call(
                &callee_def_path,
                args,
                body,
                tcx,
                &storage_origins,
                &key_origins,
                destination,
            );
            let nested_summary = direct_summary.or_else(|| {
                let mut nested_visited = visited.clone();
                summarize_returned_borrow_collection_remove_return_callable_inner(
                    tcx,
                    callee_def_id,
                    &mut nested_visited,
                )
                .and_then(|summary| {
                    returned_borrow_collection_remove_return_summary_from_nested_summary(
                        summary,
                        args,
                        &storage_origins,
                        &key_origins,
                    )
                })
            });
            if destination.projection.is_empty() {
                if let Some(summary) = nested_summary {
                    update_optional_origin(
                        &mut remove_return_origins,
                        destination.local,
                        Some(summary),
                    );
                    if destination.local == return_local {
                        unique_summary = merge_returned_borrow_collection_remove_return_summary(
                            unique_summary,
                            summary,
                        )?;
                    }
                } else {
                    record_collection_remove_return_summary_unknown_destination(
                        &mut remove_return_origins,
                        destination,
                    );
                    if destination.local == return_local {
                        return None;
                    }
                }
            }
            record_string_key_summary_call(
                tcx,
                body,
                &mut key_origins,
                callee_def_id,
                &callee_def_path,
                args,
                destination,
            );
            record_collection_storage_summary_unknown_destination(
                body,
                &mut storage_origins,
                destination,
            );
        }
    }

    unique_summary
}

fn summarize_returned_borrow_collection_persist_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    current_crate_name: &str,
    def_id: DefId,
) -> Option<ReturnedBorrowCollectionPersistAnalysis> {
    let mut visited = BTreeSet::new();
    summarize_returned_borrow_collection_persist_callable_inner(
        tcx,
        current_crate_name,
        def_id,
        &mut visited,
    )
}

fn summarize_returned_borrow_collection_entry_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
) -> Option<ReturnedBorrowCollectionEntryReturnSummary> {
    let mut visited = BTreeSet::new();
    summarize_returned_borrow_collection_entry_callable_inner(tcx, def_id, &mut visited)
}

fn summarize_returned_borrow_collection_entry_callable_inner<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
    visited: &mut BTreeSet<String>,
) -> Option<ReturnedBorrowCollectionEntryReturnSummary> {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);
    let owner_def_path = tcx.def_path_str(def_id);
    if !visited.insert(owner_def_path) {
        return None;
    }
    let return_local = Local::new(0);
    let return_type_name = body.local_decls[return_local]
        .ty
        .to_string()
        .to_ascii_lowercase();
    if !return_type_name.contains("entry<") {
        return None;
    }

    let mut storage_origins = BTreeMap::<Local, Option<usize>>::new();
    let mut key_origins = BTreeMap::<Local, Option<usize>>::new();
    for (arg_index, local) in body.args_iter().enumerate() {
        let type_name = body.local_decls[local].ty.to_string();
        if returned_borrow_keyed_map_storage_type(&type_name) {
            storage_origins.insert(local, Some(arg_index));
        }
        if string_like_key_type(&type_name) {
            key_origins.insert(local, Some(arg_index));
        }
    }
    if storage_origins.is_empty() || key_origins.is_empty() {
        return None;
    }

    let mut entry_origins =
        BTreeMap::<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>::new();
    let mut unique_summary = None;
    for (block_index, block) in body.basic_blocks.iter().enumerate() {
        let basic_block = BasicBlock::new(block_index);
        for (statement_index, statement) in block.statements.iter().enumerate() {
            let location = Location {
                block: basic_block,
                statement_index,
            };
            let StatementKind::Assign(assignment) = &statement.kind else {
                continue;
            };
            let (place, rvalue) = &**assignment;
            record_collection_storage_summary_assignment(&mut storage_origins, place, rvalue);
            record_string_key_summary_assignment(body, &mut key_origins, place, rvalue);
            record_collection_entry_summary_assignment(&mut entry_origins, place, rvalue);
            if place.local == return_local && place.projection.is_empty() {
                let origin = collection_entry_summary_place_origin(place, &entry_origins)?;
                if !entry_value_assignment_postdominates_reference(
                    body,
                    origin.entry_site_id,
                    mir_order_key(location),
                ) {
                    return None;
                }
                let summary = ReturnedBorrowCollectionEntryReturnSummary {
                    storage_arg_index: origin.storage_arg_index,
                    key_arg_index: origin.key_arg_index?,
                };
                unique_summary =
                    merge_returned_borrow_collection_entry_return_summary(unique_summary, summary)?;
            }
        }

        let terminator = block.terminator();
        let location = Location {
            block: basic_block,
            statement_index: block.statements.len(),
        };
        if let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &terminator.kind
        {
            let Some((callee_def_id, _)) = func.const_fn_def() else {
                record_collection_storage_summary_unknown_destination(
                    body,
                    &mut storage_origins,
                    destination,
                );
                record_string_key_summary_unknown_destination(body, &mut key_origins, destination);
                record_collection_entry_summary_unknown_destination(
                    body,
                    &mut entry_origins,
                    destination,
                );
                if destination.local == return_local && destination.projection.is_empty() {
                    return None;
                }
                continue;
            };
            let callee_def_path = tcx.def_path_str(callee_def_id);
            let origin = returned_borrow_collection_entry_summary_origin_from_call(
                &callee_def_path,
                args,
                body,
                tcx,
                &storage_origins,
                &key_origins,
                &entry_origins,
                location,
            )
            .or_else(|| {
                returned_borrow_collection_entry_summary_origin_from_nested_return_summary(
                    tcx,
                    callee_def_id,
                    args,
                    &storage_origins,
                    &key_origins,
                    location,
                    visited,
                )
            });
            if let Some(origin) = origin {
                update_optional_origin(&mut entry_origins, destination.local, Some(origin));
            } else {
                record_collection_entry_summary_unknown_destination(
                    body,
                    &mut entry_origins,
                    destination,
                );
            }
            if destination.local == return_local && destination.projection.is_empty() {
                let origin = entry_origins.get(&return_local).cloned().flatten()?;
                let summary = ReturnedBorrowCollectionEntryReturnSummary {
                    storage_arg_index: origin.storage_arg_index,
                    key_arg_index: origin.key_arg_index?,
                };
                unique_summary =
                    merge_returned_borrow_collection_entry_return_summary(unique_summary, summary)?;
            }
            record_string_key_summary_call(
                tcx,
                body,
                &mut key_origins,
                callee_def_id,
                &callee_def_path,
                args,
                destination,
            );
            record_collection_storage_summary_unknown_destination(
                body,
                &mut storage_origins,
                destination,
            );
        }
    }

    unique_summary
}

fn merge_returned_borrow_collection_entry_return_summary(
    existing: Option<ReturnedBorrowCollectionEntryReturnSummary>,
    candidate: ReturnedBorrowCollectionEntryReturnSummary,
) -> Option<Option<ReturnedBorrowCollectionEntryReturnSummary>> {
    if existing.is_some_and(|existing| existing != candidate) {
        return None;
    }
    Some(Some(candidate))
}

fn summarize_returned_borrow_collection_entry_value_reference_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    current_crate_name: &str,
    def_id: DefId,
) -> Option<ReturnedBorrowCollectionEntryValueReferenceReturnSummary> {
    let mut visited = BTreeSet::new();
    summarize_returned_borrow_collection_entry_value_reference_callable_inner(
        tcx,
        current_crate_name,
        def_id,
        &mut visited,
    )
}

fn summarize_returned_borrow_collection_entry_value_reference_callable_inner<'tcx>(
    tcx: TyCtxt<'tcx>,
    current_crate_name: &str,
    def_id: DefId,
    visited: &mut BTreeSet<String>,
) -> Option<ReturnedBorrowCollectionEntryValueReferenceReturnSummary> {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);
    let owner_def_path = tcx.def_path_str(def_id);
    if !visited.insert(owner_def_path) {
        return None;
    }
    let return_local = Local::new(0);
    if !ty_contains_ref(body.local_decls[return_local].ty) {
        return None;
    }

    let mut storage_origins = BTreeMap::<Local, Option<usize>>::new();
    let mut key_origins = BTreeMap::<Local, Option<usize>>::new();
    for (arg_index, local) in body.args_iter().enumerate() {
        let type_name = body.local_decls[local].ty.to_string();
        if returned_borrow_keyed_map_storage_type(&type_name) {
            storage_origins.insert(local, Some(arg_index));
        }
        if string_like_key_type(&type_name) {
            key_origins.insert(local, Some(arg_index));
        }
    }
    if storage_origins.is_empty() || key_origins.is_empty() {
        return None;
    }

    let mut entry_origins =
        BTreeMap::<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>::new();
    let mut entry_value_reference_origins =
        BTreeMap::<Local, Option<ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin>>::new();
    let mut unique_summary = None;
    for (block_index, block) in body.basic_blocks.iter().enumerate() {
        let basic_block = BasicBlock::new(block_index);
        for (statement_index, statement) in block.statements.iter().enumerate() {
            let location = Location {
                block: basic_block,
                statement_index,
            };
            let StatementKind::Assign(assignment) = &statement.kind else {
                continue;
            };
            let (place, rvalue) = &**assignment;
            record_collection_storage_summary_assignment(&mut storage_origins, place, rvalue);
            record_string_key_summary_assignment(body, &mut key_origins, place, rvalue);
            record_collection_entry_summary_assignment(&mut entry_origins, place, rvalue);
            record_collection_entry_value_reference_summary_assignment(
                &mut entry_value_reference_origins,
                place,
                rvalue,
            );
            if place.local == return_local && place.projection.is_empty() {
                let summary =
                    returned_borrow_collection_entry_value_reference_return_summary_from_origin(
                        body,
                        entry_value_reference_origins
                            .get(&return_local)
                            .cloned()
                            .flatten()?,
                        location,
                    )?;
                unique_summary =
                    merge_returned_borrow_collection_entry_value_reference_return_summary(
                        unique_summary,
                        summary,
                    )?;
            }
        }

        let terminator = block.terminator();
        let location = Location {
            block: basic_block,
            statement_index: block.statements.len(),
        };
        if let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &terminator.kind
        {
            let Some((callee_def_id, _)) = func.const_fn_def() else {
                record_collection_storage_summary_unknown_destination(
                    body,
                    &mut storage_origins,
                    destination,
                );
                record_string_key_summary_unknown_destination(body, &mut key_origins, destination);
                record_collection_entry_summary_unknown_destination(
                    body,
                    &mut entry_origins,
                    destination,
                );
                record_collection_entry_value_reference_summary_unknown_destination(
                    body,
                    &mut entry_value_reference_origins,
                    destination,
                );
                if destination.local == return_local && destination.projection.is_empty() {
                    return None;
                }
                continue;
            };
            let callee_def_path = tcx.def_path_str(callee_def_id);
            let mut recorded_entry_value_reference =
                record_collection_entry_value_reference_summary_call(
                    body,
                    &mut entry_value_reference_origins,
                    &callee_def_path,
                    args,
                    destination,
                    &entry_origins,
                    location,
                    false,
                );
            if !recorded_entry_value_reference
                && let Some(origin) =
                    returned_borrow_collection_entry_value_reference_summary_origin_from_nested_return_summary(
                        tcx,
                        current_crate_name,
                        callee_def_id,
                        args,
                        &storage_origins,
                        &key_origins,
                        location,
                        visited,
                    )
            {
                update_collection_entry_value_reference_summary_origin(
                    &mut entry_value_reference_origins,
                    destination.local,
                    origin,
                );
                recorded_entry_value_reference = true;
            }
            if !recorded_entry_value_reference {
                record_collection_entry_value_reference_summary_unknown_destination(
                    body,
                    &mut entry_value_reference_origins,
                    destination,
                );
            }
            if destination.local == return_local && destination.projection.is_empty() {
                let summary =
                    returned_borrow_collection_entry_value_reference_return_summary_from_origin(
                        body,
                        entry_value_reference_origins
                            .get(&return_local)
                            .cloned()
                            .flatten()?,
                        location,
                    )?;
                unique_summary =
                    merge_returned_borrow_collection_entry_value_reference_return_summary(
                        unique_summary,
                        summary,
                    )?;
            }
            record_string_key_summary_call(
                tcx,
                body,
                &mut key_origins,
                callee_def_id,
                &callee_def_path,
                args,
                destination,
            );
            record_collection_entry_summary_call(
                body,
                tcx,
                &mut entry_origins,
                callee_def_id,
                &callee_def_path,
                args,
                destination,
                &storage_origins,
                &key_origins,
                location,
                visited,
            );
            record_collection_storage_summary_unknown_destination(
                body,
                &mut storage_origins,
                destination,
            );
        }
    }

    unique_summary
}

fn summarize_returned_borrow_collection_persist_callable_inner<'tcx>(
    tcx: TyCtxt<'tcx>,
    current_crate_name: &str,
    def_id: DefId,
    visited: &mut BTreeSet<String>,
) -> Option<ReturnedBorrowCollectionPersistAnalysis> {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return None;
    }
    let body = tcx.optimized_mir(def_id);
    let owner_def_path = tcx.def_path_str(def_id);
    if !visited.insert(owner_def_path.clone()) {
        return None;
    }

    let mut storage_origins = BTreeMap::<Local, Option<usize>>::new();
    let mut key_origins = BTreeMap::<Local, Option<usize>>::new();
    for (arg_index, local) in body.args_iter().enumerate() {
        let type_name = body.local_decls[local].ty.to_string();
        if returned_borrow_keyed_map_storage_type(&type_name) {
            storage_origins.insert(local, Some(arg_index));
        }
        if string_like_key_type(&type_name) {
            key_origins.insert(local, Some(arg_index));
        }
    }
    if storage_origins.is_empty() || key_origins.is_empty() {
        return None;
    }

    let mut visitor = MirSiteVisitor {
        tcx,
        body,
        current_crate_name,
        collection_lookup_contracts: &[],
        owner_def_path,
        owner_is_foreign_callback: false,
        observations: MirSiteObservations::default(),
        raw_pointer_origins: BTreeMap::new(),
        raw_pointer_borrow_origins: BTreeMap::new(),
        closure_upvar_sources: BTreeMap::new(),
        receiver_borrow_locals: BTreeMap::new(),
        borrowed_foreign_pointer_origins: BTreeMap::new(),
        returned_borrow_origins: BTreeMap::new(),
        returned_borrow_return_origins: Vec::new(),
        returned_borrow_slot_assignment_origins: Vec::new(),
        returned_borrow_iterator_origins: BTreeMap::new(),
        fn_pointer_origins: BTreeMap::new(),
        option_fn_pointer_origins: BTreeMap::new(),
        fn_pointer_source_origins: BTreeMap::new(),
        option_fn_pointer_source_origins: BTreeMap::new(),
        option_fn_pointer_release_origins: BTreeMap::new(),
        previous_user_data_origins: BTreeMap::new(),
        hook_release_field_writes: Vec::new(),
        hook_previous_release_candidates: Vec::new(),
        borrow_origins: BTreeMap::new(),
        returned_borrow_storage_origins: BTreeMap::new(),
        returned_borrow_storage_reference_origins: BTreeMap::new(),
        returned_borrow_entry_value_reference_origins: BTreeMap::new(),
        pending_returned_borrow_entry_value_assignments: Vec::new(),
        returned_borrow_indexed_iterator_storage_origins: BTreeMap::new(),
        returned_borrow_slice_storage_origins: BTreeMap::new(),
        returned_borrow_unique_storage_origins: BTreeMap::new(),
        returned_borrow_local_wrapper_reference_origins: BTreeMap::new(),
        returned_borrow_invalidated_storage_keys: BTreeSet::new(),
        returned_borrow_sequence_lengths: BTreeMap::new(),
        returned_borrow_keyed_map_entry_origins: BTreeMap::new(),
        returned_borrow_keyed_map_entry_branch_writes: BTreeMap::new(),
        returned_borrow_keyed_map_split_entry_branch_writes: BTreeMap::new(),
        returned_borrow_keyed_map_known_empty: BTreeSet::new(),
        returned_borrow_keyed_map_known_occupied: BTreeSet::new(),
        stable_constant_origins: BTreeMap::new(),
        stable_range_origins: BTreeMap::new(),
        scoped_key_origins: BTreeMap::new(),
        unsupported_key_wrapper_origins: BTreeMap::new(),
        dynamic_key_generations: BTreeMap::new(),
        closure_storage_capture_summaries: BTreeMap::new(),
        discovered_closure_storage_captures: BTreeMap::new(),
        closure_returned_borrow_capture_summaries: BTreeMap::new(),
        discovered_closure_returned_borrow_captures: BTreeMap::new(),
        closure_capture_use_summaries: BTreeMap::new(),
        atomic_ordering_origins: BTreeMap::new(),
        external_buffer_binding_keys: BTreeSet::new(),
        returned_borrow_invalidations: Vec::new(),
        returned_borrow_storage_uses: Vec::new(),
        returned_borrow_storage_mutation_barriers: Vec::new(),
        local_method_calls: Vec::new(),
        callback_user_data_invocations: Vec::new(),
        openssl_ex_data_get_origins: BTreeMap::new(),
        openssl_ex_data_handle_origins: BTreeMap::new(),
        openssl_ex_data_slot_origins: BTreeMap::new(),
        openssl_ex_data_slot_free_contracts: BTreeMap::new(),
        openssl_ex_data_free_contracts: BTreeMap::new(),
        openssl_ex_data_registrations: Vec::new(),
        openssl_ex_data_releases: Vec::new(),
    };

    let mut unique_summary = None;
    let mut poisoned = false;
    let mut helper_binding_gaps = Vec::<ReturnedBorrowCollectionBindingGapSummary>::new();
    let mut entry_origins =
        BTreeMap::<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>::new();
    let mut entry_value_reference_origins =
        BTreeMap::<Local, Option<ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin>>::new();
    let mut pending_entry_value_assignments =
        Vec::<PendingReturnedBorrowCollectionEntryValueAssignmentSummary>::new();
    let mut entry_branch_writes = BTreeMap::<
        (usize, usize, MirOrderKey),
        ReturnedBorrowCollectionEntrySummaryBranchWrites,
    >::new();
    let mut split_entry_branch_writes =
        BTreeMap::<(usize, usize), ReturnedBorrowCollectionSplitEntrySummaryBranchWrites>::new();
    let mut pending_blocked_entry_mutations = BTreeSet::<(usize, usize)>::new();
    for (block_index, block) in body.basic_blocks.iter().enumerate() {
        let basic_block = BasicBlock::new(block_index);
        for (statement_index, statement) in block.statements.iter().enumerate() {
            let location = Location {
                block: basic_block,
                statement_index,
            };
            visitor.visit_statement(statement, location);
            let StatementKind::Assign(assignment) = &statement.kind else {
                continue;
            };
            let (place, rvalue) = &**assignment;
            record_collection_storage_summary_assignment(&mut storage_origins, place, rvalue);
            record_string_key_summary_assignment(body, &mut key_origins, place, rvalue);
            record_collection_entry_summary_assignment(&mut entry_origins, place, rvalue);
            record_collection_entry_value_reference_summary_assignment(
                &mut entry_value_reference_origins,
                place,
                rvalue,
            );
            for summary in drain_pending_returned_borrow_collection_entry_value_assignments(
                body,
                place.local,
                &entry_value_reference_origins,
                &mut pending_entry_value_assignments,
            ) {
                pending_blocked_entry_mutations
                    .remove(&(summary.storage_arg_index, summary.key_arg_index));
                if let Some(existing) = &unique_summary
                    && existing != &summary
                {
                    poisoned = true;
                } else {
                    unique_summary = Some(summary);
                }
            }
            if let Some(summary) =
                returned_borrow_collection_entry_value_assignment_summary_from_assignment(
                    body,
                    place,
                    rvalue,
                    &entry_value_reference_origins,
                    &visitor,
                    statement.source_info.span,
                    location,
                )
            {
                if let Some(existing) = &unique_summary
                    && existing != &summary
                {
                    poisoned = true;
                } else {
                    unique_summary = Some(summary);
                }
            } else if let Some(pending) =
                pending_returned_borrow_collection_entry_value_assignment_from_assignment(
                    place,
                    rvalue,
                    &visitor,
                    statement.source_info.span,
                    location,
                )
                && !pending_entry_value_assignments.contains(&pending)
            {
                pending_entry_value_assignments.push(pending);
            }
        }

        let terminator = block.terminator();
        let location = Location {
            block: basic_block,
            statement_index: block.statements.len(),
        };
        visitor.visit_terminator(terminator, location);
        if let TerminatorKind::Call {
            func,
            args,
            destination,
            fn_span,
            ..
        } = &terminator.kind
        {
            let Some((callee_def_id, _)) = func.const_fn_def() else {
                record_collection_storage_summary_unknown_destination(
                    body,
                    &mut storage_origins,
                    destination,
                );
                record_string_key_summary_unknown_destination(body, &mut key_origins, destination);
                record_collection_entry_summary_unknown_destination(
                    body,
                    &mut entry_origins,
                    destination,
                );
                record_collection_entry_value_reference_summary_unknown_destination(
                    body,
                    &mut entry_value_reference_origins,
                    destination,
                );
                continue;
            };
            let callee_def_path = tcx.def_path_str(callee_def_id);
            let summary = returned_borrow_collection_persist_summary_from_call(
                &callee_def_path,
                args,
                body,
                tcx,
                &storage_origins,
                &key_origins,
                &entry_origins,
                &visitor,
                *fn_span,
                location,
            );
            let nested_analysis = {
                let mut nested_visited = visited.clone();
                summarize_returned_borrow_collection_persist_callable_inner(
                    tcx,
                    current_crate_name,
                    callee_def_id,
                    &mut nested_visited,
                )
            };
            let nested_summary = nested_analysis.as_ref().and_then(|analysis| {
                returned_borrow_collection_persist_summary_from_nested_analysis(
                    analysis,
                    args,
                    &storage_origins,
                    &key_origins,
                )
            });
            if let Some(analysis) = &nested_analysis {
                for gap in collection_persist_binding_gap_summaries_from_nested_analysis(
                    analysis,
                    args,
                    &storage_origins,
                ) {
                    if !helper_binding_gaps.contains(&gap) {
                        helper_binding_gaps.push(gap);
                    }
                }
            }
            let mut recorded_entry_value_reference =
                record_collection_entry_value_reference_summary_call(
                    body,
                    &mut entry_value_reference_origins,
                    &callee_def_path,
                    args,
                    destination,
                    &entry_origins,
                    location,
                    false,
                );
            if !recorded_entry_value_reference
                && let Some(origin) =
                    returned_borrow_collection_entry_value_reference_summary_origin_from_nested_return_summary(
                        tcx,
                        current_crate_name,
                        callee_def_id,
                        args,
                        &storage_origins,
                        &key_origins,
                        location,
                        visited,
                    )
            {
                update_collection_entry_value_reference_summary_origin(
                    &mut entry_value_reference_origins,
                    destination.local,
                    origin,
                );
                recorded_entry_value_reference = true;
            }
            if !recorded_entry_value_reference {
                record_collection_entry_value_reference_summary_unknown_destination(
                    body,
                    &mut entry_value_reference_origins,
                    destination,
                );
            }
            if recorded_entry_value_reference {
                for summary in drain_pending_returned_borrow_collection_entry_value_assignments(
                    body,
                    destination.local,
                    &entry_value_reference_origins,
                    &mut pending_entry_value_assignments,
                ) {
                    pending_blocked_entry_mutations
                        .remove(&(summary.storage_arg_index, summary.key_arg_index));
                    if let Some(existing) = &unique_summary
                        && existing != &summary
                    {
                        poisoned = true;
                    } else {
                        unique_summary = Some(summary);
                    }
                }
            }
            let branch_outcome = returned_borrow_collection_entry_branch_persist_summary_from_call(
                &callee_def_path,
                args,
                &entry_origins,
                &visitor,
                &mut entry_branch_writes,
                &mut split_entry_branch_writes,
                location,
            );
            let tracked_entry_handle_key =
                collection_entry_handle_return_key_from_insert_entry_call(
                    &callee_def_path,
                    args,
                    body,
                    destination,
                    &entry_origins,
                );
            let mut had_call_summary = summary.is_some() || nested_summary.is_some();
            match branch_outcome {
                CollectionEntryBranchPersistOutcome::Complete(branch_summary) => {
                    had_call_summary = true;
                    pending_blocked_entry_mutations.remove(&(
                        branch_summary.storage_arg_index,
                        branch_summary.key_arg_index,
                    ));
                    if let Some(existing) = &unique_summary
                        && existing != &branch_summary
                    {
                        return None;
                    }
                    unique_summary = Some(branch_summary);
                }
                CollectionEntryBranchPersistOutcome::Poison if !recorded_entry_value_reference => {
                    if let Some(key) = tracked_entry_handle_key {
                        pending_blocked_entry_mutations.insert(key);
                    } else {
                        poisoned = true;
                    }
                }
                CollectionEntryBranchPersistOutcome::Poison => {}
                CollectionEntryBranchPersistOutcome::Irrelevant
                | CollectionEntryBranchPersistOutcome::Pending => {}
            }
            for summary in [summary, nested_summary].into_iter().flatten() {
                pending_blocked_entry_mutations
                    .remove(&(summary.storage_arg_index, summary.key_arg_index));
                if let Some(existing) = &unique_summary
                    && existing != &summary
                {
                    poisoned = true;
                    continue;
                }
                unique_summary = Some(summary);
            }
            if !had_call_summary
                && !recorded_entry_value_reference
                && returned_borrow_collection_mutating_call_in_summary(
                    &callee_def_path,
                    args,
                    &storage_origins,
                )
            {
                poisoned = true;
                continue;
            }
            record_string_key_summary_call(
                tcx,
                body,
                &mut key_origins,
                callee_def_id,
                &callee_def_path,
                args,
                destination,
            );
            record_collection_entry_summary_call(
                body,
                tcx,
                &mut entry_origins,
                callee_def_id,
                &callee_def_path,
                args,
                destination,
                &storage_origins,
                &key_origins,
                location,
                visited,
            );
            record_collection_storage_summary_unknown_destination(
                body,
                &mut storage_origins,
                destination,
            );
        }
    }

    let binding_gaps = collection_persist_binding_gap_summaries_from_observations(
        &visitor.observations.object_binding_gaps,
        &storage_origins,
    );
    let mut binding_gaps = binding_gaps;
    for gap in helper_binding_gaps {
        if !binding_gaps.contains(&gap) {
            binding_gaps.push(gap);
        }
    }
    if poisoned {
        unique_summary = None;
    }
    if !pending_blocked_entry_mutations.is_empty() {
        unique_summary = None;
    }
    (unique_summary.is_some() || !binding_gaps.is_empty()).then_some(
        ReturnedBorrowCollectionPersistAnalysis {
            summary: unique_summary,
            binding_gaps,
        },
    )
}

fn collection_persist_binding_gap_summaries_from_observations(
    gaps: &[ObjectBindingGapObservation],
    storage_origins: &BTreeMap<Local, Option<usize>>,
) -> Vec<ReturnedBorrowCollectionBindingGapSummary> {
    let mut storage_arg_index = None;
    for origin in storage_origins.values().copied().flatten() {
        if storage_arg_index.is_some_and(|existing| existing != origin) {
            return Vec::new();
        }
        storage_arg_index = Some(origin);
    }
    let Some(storage_arg_index) = storage_arg_index else {
        return Vec::new();
    };
    let mut summaries = Vec::new();
    for gap in gaps {
        if gap.gap_kind != ObjectBindingGapKind::MappedValue
            || gap.adapter.as_deref() != Some("entry_value_wrapper")
        {
            continue;
        }
        let summary = ReturnedBorrowCollectionBindingGapSummary {
            storage_arg_index,
            gap_kind: gap.gap_kind,
            adapter: "entry_value_wrapper".to_owned(),
        };
        if !summaries.contains(&summary) {
            summaries.push(summary);
        }
    }
    summaries
}

fn record_collection_storage_summary_assignment<'tcx>(
    origins: &mut BTreeMap<Local, Option<usize>>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let origin = match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            collection_storage_summary_operand_origin(operand, origins)
        }
        Rvalue::Ref(_, _, place) => collection_storage_summary_place_origin(place, origins),
        _ => None,
    };
    if origin.is_some() || origins.contains_key(&destination.local) {
        update_optional_origin(origins, destination.local, origin);
    }
}

fn record_collection_storage_summary_unknown_destination<'tcx>(
    body: &Body<'tcx>,
    origins: &mut BTreeMap<Local, Option<usize>>,
    destination: &Place<'tcx>,
) {
    if destination.projection.is_empty()
        && returned_borrow_collection_storage_type(
            &body.local_decls[destination.local].ty.to_string(),
        )
    {
        update_optional_origin(origins, destination.local, None);
    }
}

fn record_collection_entry_summary_assignment<'tcx>(
    origins: &mut BTreeMap<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let origin = match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            collection_entry_summary_operand_origin(operand, origins)
        }
        Rvalue::Ref(_, _, place) => collection_entry_summary_place_origin(place, origins),
        _ => None,
    };
    if origin.is_some() || origins.contains_key(&destination.local) {
        update_collection_entry_summary_origin(origins, destination.local, origin);
    }
}

fn record_collection_entry_summary_call<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    origins: &mut BTreeMap<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>,
    callee_def_id: DefId,
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    destination: &Place<'tcx>,
    storage_origins: &BTreeMap<Local, Option<usize>>,
    key_origins: &BTreeMap<Local, Option<usize>>,
    location: Location,
    visited: &BTreeSet<String>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let origin = returned_borrow_collection_entry_summary_origin_from_call(
        callee_def_path,
        args,
        body,
        tcx,
        storage_origins,
        key_origins,
        origins,
        location,
    )
    .or_else(|| {
        returned_borrow_collection_entry_summary_origin_from_nested_return_summary(
            tcx,
            callee_def_id,
            args,
            storage_origins,
            key_origins,
            location,
            visited,
        )
    });
    if origin.is_some() {
        update_collection_entry_summary_origin(origins, destination.local, origin);
    } else {
        record_collection_entry_summary_unknown_destination(body, origins, destination);
    }
}

fn record_collection_entry_summary_unknown_destination<'tcx>(
    body: &Body<'tcx>,
    origins: &mut BTreeMap<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>,
    destination: &Place<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let destination_type_name = body.local_decls[destination.local]
        .ty
        .to_string()
        .to_ascii_lowercase();
    if origins.contains_key(&destination.local)
        || destination_type_name.contains("entry<")
        || destination_type_name.contains("occupiedentry<")
        || destination_type_name.contains("vacantentry<")
    {
        update_collection_entry_summary_origin(origins, destination.local, None);
    }
}

fn update_collection_entry_summary_origin(
    origins: &mut BTreeMap<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>,
    local: Local,
    origin: Option<ReturnedBorrowCollectionEntrySummaryOrigin>,
) {
    match (origins.get_mut(&local), origin) {
        (Some(existing), Some(origin)) => {
            *existing = existing
                .and_then(|existing| merge_collection_entry_summary_origins(existing, origin));
        }
        (Some(existing), None) => {
            *existing = None;
        }
        (None, origin) => {
            origins.insert(local, origin);
        }
    }
}

fn merge_collection_entry_summary_origins(
    existing: ReturnedBorrowCollectionEntrySummaryOrigin,
    incoming: ReturnedBorrowCollectionEntrySummaryOrigin,
) -> Option<ReturnedBorrowCollectionEntrySummaryOrigin> {
    if existing.storage_arg_index != incoming.storage_arg_index
        || existing.key_arg_index != incoming.key_arg_index
        || existing.entry_site_id != incoming.entry_site_id
    {
        return None;
    }
    let projection_kind = match (existing.projection_kind, incoming.projection_kind) {
        (left, right) if left == right => left,
        (None, Some(KeyedMapEntryProjectionKind::Occupied))
        | (Some(KeyedMapEntryProjectionKind::Occupied), None) => None,
        _ => return None,
    };
    Some(ReturnedBorrowCollectionEntrySummaryOrigin {
        projection_kind,
        ..existing
    })
}

fn record_collection_entry_value_reference_summary_assignment<'tcx>(
    origins: &mut BTreeMap<Local, Option<ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin>>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let origin = match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            operand.place().and_then(|place| {
                collection_entry_value_reference_summary_place_origin(&place, origins)
            })
        }
        Rvalue::Ref(_, _, place) => {
            collection_entry_value_reference_summary_place_origin(place, origins)
        }
        _ => None,
    };
    if let Some(origin) = origin {
        update_collection_entry_value_reference_summary_origin(origins, destination.local, origin);
    } else if origins.contains_key(&destination.local) {
        origins.insert(destination.local, None);
    }
}

fn record_collection_entry_value_reference_summary_call<'tcx>(
    body: &Body<'tcx>,
    origins: &mut BTreeMap<Local, Option<ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin>>,
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    destination: &Place<'tcx>,
    entry_origins: &BTreeMap<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>,
    location: Location,
    record_unknown: bool,
) -> bool {
    if !destination.projection.is_empty() {
        return false;
    }
    let Some(method) = method_name(callee_def_path) else {
        if record_unknown {
            record_collection_entry_value_reference_summary_unknown_destination(
                body,
                origins,
                destination,
            );
        }
        return false;
    };
    if !matches!(
        method.as_str(),
        "or_insert" | "or_insert_with" | "or_insert_with_key" | "get_mut" | "into_mut" | "insert"
    ) {
        if record_unknown {
            record_collection_entry_value_reference_summary_unknown_destination(
                body,
                origins,
                destination,
            );
        }
        return false;
    }
    let origin = args
        .first()
        .and_then(|arg| collection_entry_summary_operand_origin(&arg.node, entry_origins))
        .and_then(|entry| {
            let allowed_entry_value_reference = match method.as_str() {
                "or_insert" | "or_insert_with" | "or_insert_with_key" => true,
                "get_mut" | "into_mut" => {
                    entry.projection_kind.is_none()
                        || entry.projection_kind == Some(KeyedMapEntryProjectionKind::Occupied)
                }
                "insert" => entry.projection_kind == Some(KeyedMapEntryProjectionKind::Vacant),
                _ => false,
            };
            if !allowed_entry_value_reference {
                return None;
            }
            entry.key_arg_index.map(
                |_| ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin {
                    entry,
                    reference_order_keys: BTreeSet::from([mir_order_key(location)]),
                },
            )
        });
    if let Some(origin) = origin {
        update_collection_entry_value_reference_summary_origin(origins, destination.local, origin);
        true
    } else {
        if record_unknown {
            record_collection_entry_value_reference_summary_unknown_destination(
                body,
                origins,
                destination,
            );
        }
        false
    }
}

fn update_collection_entry_value_reference_summary_origin(
    origins: &mut BTreeMap<Local, Option<ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin>>,
    local: Local,
    origin: ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin,
) {
    match origins.get_mut(&local) {
        Some(Some(existing))
            if collection_entry_value_reference_origins_match(&existing.entry, &origin.entry) =>
        {
            existing
                .reference_order_keys
                .extend(origin.reference_order_keys);
        }
        Some(Some(_)) | Some(None) => {
            origins.insert(local, None);
        }
        None => {
            origins.insert(local, Some(origin));
        }
    }
}

fn collection_entry_value_reference_origins_match(
    left: &ReturnedBorrowCollectionEntrySummaryOrigin,
    right: &ReturnedBorrowCollectionEntrySummaryOrigin,
) -> bool {
    left.storage_arg_index == right.storage_arg_index
        && left.key_arg_index == right.key_arg_index
        && left.entry_site_id == right.entry_site_id
}

fn record_collection_entry_value_reference_summary_unknown_destination<'tcx>(
    body: &Body<'tcx>,
    origins: &mut BTreeMap<Local, Option<ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin>>,
    destination: &Place<'tcx>,
) {
    if destination.projection.is_empty()
        && (origins.contains_key(&destination.local)
            || matches!(body.local_decls[destination.local].ty.kind(), ty::Ref(..)))
    {
        update_optional_origin(origins, destination.local, None);
    }
}

fn collection_entry_value_reference_summary_place_origin(
    place: &Place<'_>,
    origins: &BTreeMap<Local, Option<ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin>>,
) -> Option<ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin> {
    if !place.projection.is_empty() {
        return None;
    }
    origins.get(&place.local).cloned().flatten()
}

fn returned_borrow_collection_entry_value_reference_return_summary_from_origin(
    body: &Body<'_>,
    origin: ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin,
    location: Location,
) -> Option<ReturnedBorrowCollectionEntryValueReferenceReturnSummary> {
    if !origin
        .reference_order_keys
        .iter()
        .all(|reference_order_key| {
            entry_value_assignment_postdominates_reference(
                body,
                *reference_order_key,
                mir_order_key(location),
            )
        })
    {
        return None;
    }
    Some(ReturnedBorrowCollectionEntryValueReferenceReturnSummary {
        storage_arg_index: origin.entry.storage_arg_index,
        key_arg_index: origin.entry.key_arg_index?,
    })
}

fn merge_returned_borrow_collection_entry_value_reference_return_summary(
    existing: Option<ReturnedBorrowCollectionEntryValueReferenceReturnSummary>,
    candidate: ReturnedBorrowCollectionEntryValueReferenceReturnSummary,
) -> Option<Option<ReturnedBorrowCollectionEntryValueReferenceReturnSummary>> {
    if existing.is_some_and(|existing| existing != candidate) {
        return None;
    }
    Some(Some(candidate))
}

fn returned_borrow_collection_entry_value_reference_summary_origin_from_nested_return_summary<
    'tcx,
>(
    tcx: TyCtxt<'tcx>,
    current_crate_name: &str,
    callee_def_id: DefId,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    storage_origins: &BTreeMap<Local, Option<usize>>,
    key_origins: &BTreeMap<Local, Option<usize>>,
    location: Location,
    visited: &BTreeSet<String>,
) -> Option<ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin> {
    let mut nested_visited = visited.clone();
    let summary = summarize_returned_borrow_collection_entry_value_reference_callable_inner(
        tcx,
        current_crate_name,
        callee_def_id,
        &mut nested_visited,
    )?;
    let storage_arg_index = args
        .get(summary.storage_arg_index)
        .and_then(|arg| collection_storage_summary_operand_origin(&arg.node, storage_origins))?;
    let key_arg_index = args
        .get(summary.key_arg_index)
        .and_then(|arg| string_key_summary_operand_origin(&arg.node, key_origins))?;
    Some(ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin {
        entry: ReturnedBorrowCollectionEntrySummaryOrigin {
            storage_arg_index,
            key_arg_index: Some(key_arg_index),
            entry_site_id: mir_order_key(location),
            projection_kind: None,
        },
        reference_order_keys: BTreeSet::from([mir_order_key(location)]),
    })
}

fn returned_borrow_collection_entry_value_assignment_summary_from_assignment<'tcx>(
    body: &Body<'tcx>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
    origins: &BTreeMap<Local, Option<ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin>>,
    visitor: &MirSiteVisitor<'_, 'tcx>,
    span: Span,
    location: Location,
) -> Option<ReturnedBorrowCollectionPersistSummary> {
    if !destination
        .projection
        .iter()
        .any(|projection| matches!(projection, ProjectionElem::Deref))
    {
        return None;
    }
    let reference_origin = origins.get(&destination.local).cloned().flatten()?;
    if !reference_origin
        .reference_order_keys
        .iter()
        .all(|reference_order_key| {
            entry_value_assignment_postdominates_reference(
                body,
                *reference_order_key,
                mir_order_key(location),
            )
        })
    {
        return None;
    }
    let entry_origin = reference_origin.entry;
    let key_arg_index = entry_origin.key_arg_index?;
    let origin = visitor.returned_borrow_origin_from_rvalue(rvalue, span, location)?;
    Some(ReturnedBorrowCollectionPersistSummary {
        storage_arg_index: entry_origin.storage_arg_index,
        key_arg_index,
        origin,
    })
}

fn pending_returned_borrow_collection_entry_value_assignment_from_assignment<'tcx>(
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
    visitor: &MirSiteVisitor<'_, 'tcx>,
    span: Span,
    location: Location,
) -> Option<PendingReturnedBorrowCollectionEntryValueAssignmentSummary> {
    if !destination
        .projection
        .iter()
        .any(|projection| matches!(projection, ProjectionElem::Deref))
    {
        return None;
    }
    let origin = visitor.returned_borrow_origin_from_rvalue(rvalue, span, location)?;
    Some(PendingReturnedBorrowCollectionEntryValueAssignmentSummary {
        local: destination.local,
        origin,
        assignment_order_key: mir_order_key(location),
    })
}

fn drain_pending_returned_borrow_collection_entry_value_assignments(
    body: &Body<'_>,
    local: Local,
    origins: &BTreeMap<Local, Option<ReturnedBorrowCollectionEntryValueReferenceSummaryOrigin>>,
    pending: &mut Vec<PendingReturnedBorrowCollectionEntryValueAssignmentSummary>,
) -> Vec<ReturnedBorrowCollectionPersistSummary> {
    let Some(reference_origin) = origins.get(&local).cloned().flatten() else {
        return Vec::new();
    };
    let Some(key_arg_index) = reference_origin.entry.key_arg_index else {
        return Vec::new();
    };
    let mut summaries = Vec::new();
    let mut remaining = Vec::new();
    for assignment in std::mem::take(pending) {
        if assignment.local != local {
            remaining.push(assignment);
            continue;
        }
        if !reference_origin
            .reference_order_keys
            .iter()
            .all(|reference_order_key| {
                entry_value_assignment_postdominates_reference(
                    body,
                    *reference_order_key,
                    assignment.assignment_order_key,
                )
            })
        {
            remaining.push(assignment);
            continue;
        }
        summaries.push(ReturnedBorrowCollectionPersistSummary {
            storage_arg_index: reference_origin.entry.storage_arg_index,
            key_arg_index,
            origin: assignment.origin,
        });
    }
    *pending = remaining;
    summaries
}

fn returned_borrow_collection_entry_summary_origin_from_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    storage_origins: &BTreeMap<Local, Option<usize>>,
    key_origins: &BTreeMap<Local, Option<usize>>,
    entry_origins: &BTreeMap<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>,
    location: Location,
) -> Option<ReturnedBorrowCollectionEntrySummaryOrigin> {
    let method = method_name(callee_def_path)?;
    if method == "and_modify" {
        return args
            .first()
            .and_then(|arg| collection_entry_summary_operand_origin(&arg.node, entry_origins));
    }
    if method == "insert_entry" {
        return args
            .first()
            .and_then(|arg| collection_entry_summary_operand_origin(&arg.node, entry_origins))
            .map(|origin| ReturnedBorrowCollectionEntrySummaryOrigin {
                projection_kind: None,
                ..origin
            });
    }
    if method != "entry" {
        return None;
    }
    let first_arg = args.first()?;
    let storage_type_name = first_arg.node.ty(&body.local_decls, tcx).to_string();
    if !returned_borrow_keyed_map_storage_type(&storage_type_name) {
        return None;
    }
    let storage_arg_index =
        collection_storage_summary_operand_origin(&first_arg.node, storage_origins);
    let key_arg_index = args
        .get(1)
        .and_then(|arg| string_key_summary_operand_origin(&arg.node, key_origins));
    let storage_arg_index = storage_arg_index?;
    Some(ReturnedBorrowCollectionEntrySummaryOrigin {
        storage_arg_index,
        key_arg_index,
        entry_site_id: mir_order_key(location),
        projection_kind: None,
    })
}

fn returned_borrow_collection_entry_summary_origin_from_nested_return_summary<'tcx>(
    tcx: TyCtxt<'tcx>,
    callee_def_id: DefId,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    storage_origins: &BTreeMap<Local, Option<usize>>,
    key_origins: &BTreeMap<Local, Option<usize>>,
    location: Location,
    visited: &BTreeSet<String>,
) -> Option<ReturnedBorrowCollectionEntrySummaryOrigin> {
    let mut nested_visited = visited.clone();
    let summary = summarize_returned_borrow_collection_entry_callable_inner(
        tcx,
        callee_def_id,
        &mut nested_visited,
    )?;
    let storage_arg_index = args
        .get(summary.storage_arg_index)
        .and_then(|arg| collection_storage_summary_operand_origin(&arg.node, storage_origins))?;
    let key_arg_index = args
        .get(summary.key_arg_index)
        .and_then(|arg| string_key_summary_operand_origin(&arg.node, key_origins))?;
    Some(ReturnedBorrowCollectionEntrySummaryOrigin {
        storage_arg_index,
        key_arg_index: Some(key_arg_index),
        entry_site_id: mir_order_key(location),
        projection_kind: None,
    })
}

fn record_stable_constant_summary_assignment<'tcx>(
    origins: &mut BTreeMap<Local, String>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let key = match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            stable_constant_operand_key_with_origins(operand, origins)
        }
        _ => None,
    };
    if let Some(key) = key {
        origins.insert(destination.local, key);
    } else {
        origins.remove(&destination.local);
    }
}

fn record_stable_range_summary_assignment<'tcx>(
    range_origins: &mut BTreeMap<Local, ConstRangeBounds>,
    stable_constant_origins: &BTreeMap<Local, String>,
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let type_name = destination.ty(&body.local_decls, tcx).ty.to_string();
    let Some(range_kind) = slice_range_kind(&type_name) else {
        range_origins.remove(&destination.local);
        return;
    };
    let bounds = match rvalue {
        Rvalue::Aggregate(_, operands) => const_range_bounds_from_summary_operands(
            range_kind,
            operands.iter().collect::<Vec<_>>().as_slice(),
            stable_constant_origins,
        ),
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            stable_range_summary_bounds_from_operand(operand, body, tcx, range_origins)
        }
        _ => None,
    };
    if let Some(bounds) = bounds {
        range_origins.insert(destination.local, bounds);
    } else {
        range_origins.remove(&destination.local);
    }
}

fn record_stable_range_summary_constructor_call<'tcx>(
    range_origins: &mut BTreeMap<Local, ConstRangeBounds>,
    stable_constant_origins: &BTreeMap<Local, String>,
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    destination: &Place<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let type_name = destination.ty(&body.local_decls, tcx).ty.to_string();
    let Some(range_kind) = slice_range_kind(&type_name) else {
        return;
    };
    if range_kind != SliceRangeKind::RangeInclusive
        || method_name(callee_def_path).as_deref() != Some("new")
        || !callee_def_path.contains("RangeInclusive")
    {
        return;
    }
    let operands = args.iter().map(|arg| &arg.node).collect::<Vec<_>>();
    if let Some(bounds) = const_range_bounds_from_summary_operands(
        range_kind,
        operands.as_slice(),
        stable_constant_origins,
    ) {
        range_origins.insert(destination.local, bounds);
    }
}

fn stable_range_summary_bounds_from_operand<'tcx>(
    operand: &Operand<'tcx>,
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    range_origins: &BTreeMap<Local, ConstRangeBounds>,
) -> Option<ConstRangeBounds> {
    if let Some(place) = operand.place() {
        if !place.projection.is_empty() {
            return None;
        }
        if let Some(bounds) = range_origins.get(&place.local).copied() {
            return Some(bounds);
        }
    }
    let type_name = operand.ty(&body.local_decls, tcx).to_string();
    let range_kind = slice_range_kind(&type_name)?;
    let snippet = format!("{operand:?}");
    match range_kind {
        SliceRangeKind::Range => {
            let start = debug_usize_field(&snippet, "start")?;
            let end = debug_usize_field(&snippet, "end")?;
            Some(ConstRangeBounds {
                start,
                end: Some(end),
            })
        }
        SliceRangeKind::RangeInclusive => {
            let start = debug_usize_field(&snippet, "start")?;
            let end = debug_usize_field(&snippet, "end")?.checked_add(1)?;
            Some(ConstRangeBounds {
                start,
                end: Some(end),
            })
        }
        SliceRangeKind::RangeFrom => {
            let start = debug_usize_field(&snippet, "start")?;
            Some(ConstRangeBounds { start, end: None })
        }
        SliceRangeKind::RangeTo => {
            let end = debug_usize_field(&snippet, "end")?;
            Some(ConstRangeBounds {
                start: 0,
                end: Some(end),
            })
        }
        SliceRangeKind::RangeToInclusive => {
            let end = debug_usize_field(&snippet, "end")?.checked_add(1)?;
            Some(ConstRangeBounds {
                start: 0,
                end: Some(end),
            })
        }
        SliceRangeKind::RangeFull => Some(ConstRangeBounds {
            start: 0,
            end: None,
        }),
    }
}

fn const_range_bounds_from_summary_operands<'tcx>(
    range_kind: SliceRangeKind,
    operands: &[&Operand<'tcx>],
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<ConstRangeBounds> {
    match range_kind {
        SliceRangeKind::Range if operands.len() == 2 => {
            let start =
                usize_constant_operand_key_with_origins(operands[0], stable_constant_origins)?
                    .parse::<usize>()
                    .ok()?;
            let end =
                usize_constant_operand_key_with_origins(operands[1], stable_constant_origins)?
                    .parse::<usize>()
                    .ok()?;
            Some(ConstRangeBounds {
                start,
                end: Some(end),
            })
        }
        SliceRangeKind::RangeInclusive if operands.len() >= 2 => {
            let start =
                usize_constant_operand_key_with_origins(operands[0], stable_constant_origins)?
                    .parse::<usize>()
                    .ok()?;
            let end =
                usize_constant_operand_key_with_origins(operands[1], stable_constant_origins)?
                    .parse::<usize>()
                    .ok()?
                    .checked_add(1)?;
            Some(ConstRangeBounds {
                start,
                end: Some(end),
            })
        }
        SliceRangeKind::RangeFrom if operands.len() == 1 => {
            let start =
                usize_constant_operand_key_with_origins(operands[0], stable_constant_origins)?
                    .parse::<usize>()
                    .ok()?;
            Some(ConstRangeBounds { start, end: None })
        }
        SliceRangeKind::RangeTo if operands.len() == 1 => {
            let end =
                usize_constant_operand_key_with_origins(operands[0], stable_constant_origins)?
                    .parse::<usize>()
                    .ok()?;
            Some(ConstRangeBounds {
                start: 0,
                end: Some(end),
            })
        }
        SliceRangeKind::RangeToInclusive if operands.len() == 1 => {
            let end =
                usize_constant_operand_key_with_origins(operands[0], stable_constant_origins)?
                    .parse::<usize>()
                    .ok()?
                    .checked_add(1)?;
            Some(ConstRangeBounds {
                start: 0,
                end: Some(end),
            })
        }
        SliceRangeKind::RangeFull if operands.is_empty() => Some(ConstRangeBounds {
            start: 0,
            end: None,
        }),
        _ => None,
    }
}

fn record_collection_summary_callable_assignment<'tcx>(
    origins: &mut BTreeMap<Local, DefId>,
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let origin = match rvalue {
        Rvalue::Aggregate(kind, _) => closure_def_id_from_aggregate_kind(kind),
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            collection_summary_callable_def_from_operand(operand, body, tcx, origins)
        }
        _ => None,
    };
    if let Some(origin) = origin {
        origins.insert(destination.local, origin);
    } else {
        origins.remove(&destination.local);
    }
}

fn record_collection_storage_summary_reference_passthrough_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    destination: &Place<'tcx>,
    origins: &mut BTreeMap<Local, Option<usize>>,
) -> bool {
    let is_deref = method_name(callee_def_path)
        .as_deref()
        .is_some_and(|method| matches!(method, "deref" | "deref_mut"));
    let is_indexed_sequence_passthrough = args.first().is_some_and(|arg| {
        let source_type_name = arg.node.ty(&body.local_decls, tcx).to_string();
        returned_borrow_indexed_sequence_reference_passthrough_call(
            callee_def_path,
            &source_type_name,
        )
    });
    let is_option_reference_passthrough = args.first().is_some_and(|arg| {
        let source_type_name = arg.node.ty(&body.local_decls, tcx).to_string();
        returned_borrow_option_reference_storage_passthrough_call(
            callee_def_path,
            &source_type_name,
        )
    });
    if !destination.projection.is_empty()
        || !(is_deref
            || returned_borrow_storage_reference_passthrough_call(callee_def_path)
            || is_option_reference_passthrough
            || is_indexed_sequence_passthrough)
    {
        return false;
    }
    let origin = args
        .first()
        .and_then(|arg| collection_storage_summary_operand_origin(&arg.node, origins));
    update_optional_origin(origins, destination.local, origin);
    true
}

fn record_collection_summary_slice_assignment<'tcx>(
    origins: &mut BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    origins.remove(&destination.local);
    let origin = match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            collection_summary_slice_origin_from_operand(operand, origins)
        }
        Rvalue::Ref(_, _, source_place) => {
            collection_summary_slice_origin_from_place(source_place, origins)
        }
        _ => None,
    };
    if origin.is_some() {
        origins.insert(destination.local, origin);
    }
}

fn record_collection_summary_slice_unknown_destination<'tcx>(
    origins: &mut BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
    destination: &Place<'tcx>,
) {
    if destination.projection.is_empty() {
        origins.remove(&destination.local);
    }
}

fn record_collection_summary_range_slice_call<'tcx>(
    origins: &mut BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    destination: &Place<'tcx>,
    storage_origins: &BTreeMap<Local, Option<usize>>,
    range_origins: &BTreeMap<Local, ConstRangeBounds>,
) -> bool {
    if !destination.projection.is_empty() || method_name(callee_def_path).as_deref() != Some("get")
    {
        return false;
    }
    let Some(first_arg) = args.first() else {
        return false;
    };
    let storage_type_name = first_arg.node.ty(&body.local_decls, tcx).to_string();
    if !returned_borrow_indexed_sequence_storage_type(&storage_type_name) {
        return false;
    }
    let Some(storage_arg_index) =
        collection_storage_summary_operand_origin(&first_arg.node, storage_origins)
    else {
        return false;
    };
    let Some(range) = args.get(1).and_then(|arg| {
        stable_range_summary_bounds_from_operand(&arg.node, body, tcx, range_origins)
    }) else {
        return false;
    };
    if range.end.is_some_and(|end| range.start >= end) {
        return false;
    }
    origins.insert(
        destination.local,
        Some(IndexedIteratorArgOrigin {
            storage_arg_index,
            front_offset: range.start,
            back_offset: 0,
            take_limit: range.end.and_then(|end| end.checked_sub(range.start)),
            take_from_back: range.end.map(|_| false),
            from_back: false,
        }),
    );
    true
}

fn record_collection_summary_slice_passthrough_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    destination: &Place<'tcx>,
    origins: &mut BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
) {
    if !destination.projection.is_empty()
        || !returned_borrow_storage_passthrough_call(callee_def_path)
    {
        return;
    }
    origins.remove(&destination.local);
    let mut unique = None;
    for arg in args {
        let Some(origin) = collection_summary_slice_origin_from_operand(&arg.node, origins) else {
            continue;
        };
        if unique.as_ref().is_some_and(|existing| existing != &origin) {
            origins.insert(destination.local, None);
            return;
        }
        unique = Some(origin);
    }
    if unique.is_some() {
        origins.insert(destination.local, unique);
    }
}

fn record_collection_summary_indexed_iterator_assignment<'tcx>(
    origins: &mut BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    origins.remove(&destination.local);
    let origin = match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            collection_summary_indexed_iterator_origin_from_operand(operand, origins)
        }
        Rvalue::Ref(_, _, source_place) => {
            collection_summary_indexed_iterator_origin_from_place(source_place, origins)
        }
        _ => None,
    };
    if origin.is_some() {
        origins.insert(destination.local, origin);
    }
}

fn record_collection_summary_indexed_iterator_unknown_destination<'tcx>(
    origins: &mut BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
    destination: &Place<'tcx>,
) {
    if destination.projection.is_empty() {
        origins.remove(&destination.local);
    }
}

fn record_collection_summary_indexed_iterator_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    destination: &Place<'tcx>,
    storage_origins: &BTreeMap<Local, Option<usize>>,
    slice_origins: &BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
    iterator_origins: &mut BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<ReturnedBorrowCollectionBindingGapSummary> {
    if !destination.projection.is_empty() {
        return None;
    }
    if let Some(origin) = args.first().and_then(|arg| {
        let storage_type_name = arg.node.ty(&body.local_decls, tcx).to_string();
        returned_borrow_indexed_sequence_iterator_call(callee_def_path, &storage_type_name)
            .then(|| {
                collection_summary_slice_origin_from_operand(&arg.node, slice_origins).or_else(
                    || {
                        collection_storage_summary_operand_origin(&arg.node, storage_origins).map(
                            |storage_arg_index| IndexedIteratorArgOrigin {
                                storage_arg_index,
                                front_offset: 0,
                                back_offset: 0,
                                take_limit: None,
                                take_from_back: None,
                                from_back: false,
                            },
                        )
                    },
                )
            })
            .flatten()
    }) {
        iterator_origins.insert(destination.local, Some(origin));
        return None;
    }
    let Some(origin) = args.first().and_then(|arg| {
        collection_summary_indexed_iterator_origin_from_operand(&arg.node, iterator_origins)
    }) else {
        return None;
    };
    let Some(method) = method_name(callee_def_path) else {
        return None;
    };
    let mut binding_gap = None;
    let origin = match method.as_str() {
        "skip" => {
            if let Some(offset) =
                returned_borrow_iterator_skip_index(callee_def_path, args, stable_constant_origins)
            {
                if origin.from_back {
                    let Some((take_limit, take_from_back)) =
                        returned_borrow_iterator_take_after_skip(
                            origin.take_limit,
                            origin.take_from_back,
                            origin.from_back,
                            offset,
                        )
                    else {
                        return None;
                    };
                    origin.back_offset.checked_add(offset).map(|back_offset| {
                        IndexedIteratorArgOrigin {
                            storage_arg_index: origin.storage_arg_index,
                            front_offset: origin.front_offset,
                            back_offset,
                            take_limit,
                            take_from_back,
                            from_back: origin.from_back,
                        }
                    })
                } else {
                    let Some((take_limit, take_from_back)) =
                        returned_borrow_iterator_take_after_skip(
                            origin.take_limit,
                            origin.take_from_back,
                            origin.from_back,
                            offset,
                        )
                    else {
                        return None;
                    };
                    origin.front_offset.checked_add(offset).map(|front_offset| {
                        IndexedIteratorArgOrigin {
                            storage_arg_index: origin.storage_arg_index,
                            front_offset,
                            back_offset: origin.back_offset,
                            take_limit,
                            take_from_back,
                            from_back: origin.from_back,
                        }
                    })
                }
            } else {
                binding_gap = Some(ReturnedBorrowCollectionBindingGapSummary {
                    storage_arg_index: origin.storage_arg_index,
                    gap_kind: ObjectBindingGapKind::DynamicIndex,
                    adapter: method.clone(),
                });
                None
            }
        }
        "rev" => Some(IndexedIteratorArgOrigin {
            storage_arg_index: origin.storage_arg_index,
            front_offset: origin.front_offset,
            back_offset: origin.back_offset,
            take_limit: origin.take_limit,
            take_from_back: origin.take_from_back,
            from_back: !origin.from_back,
        }),
        "take" => {
            if let Some(limit) =
                returned_borrow_iterator_take_limit(callee_def_path, args, stable_constant_origins)
            {
                let Some((take_limit, take_from_back)) = returned_borrow_iterator_take_after_take(
                    origin.take_limit,
                    origin.take_from_back,
                    origin.from_back,
                    limit,
                ) else {
                    return None;
                };
                Some(IndexedIteratorArgOrigin {
                    storage_arg_index: origin.storage_arg_index,
                    front_offset: origin.front_offset,
                    back_offset: origin.back_offset,
                    take_limit: Some(take_limit),
                    take_from_back: Some(take_from_back),
                    from_back: origin.from_back,
                })
            } else {
                binding_gap = Some(ReturnedBorrowCollectionBindingGapSummary {
                    storage_arg_index: origin.storage_arg_index,
                    gap_kind: ObjectBindingGapKind::DynamicIndex,
                    adapter: method.clone(),
                });
                None
            }
        }
        "copied" | "cloned" | "enumerate" => Some(origin),
        "map" if iterator_map_identity_preserving_arg(tcx, body, args) => Some(origin),
        "filter" if iterator_filter_always_true_arg(tcx, body, args) => Some(origin),
        "filter_map" if iterator_filter_map_identity_preserving_arg(tcx, body, args) => {
            Some(origin)
        }
        "chain" | "filter" | "filter_map" | "flat_map" | "map" | "zip" => {
            binding_gap = iterator_adapter_gap_kind(method.as_str()).map(|gap_kind| {
                ReturnedBorrowCollectionBindingGapSummary {
                    storage_arg_index: origin.storage_arg_index,
                    gap_kind,
                    adapter: method.clone(),
                }
            });
            None
        }
        _ => return None,
    };
    iterator_origins.insert(destination.local, origin);
    binding_gap
}

fn returned_borrow_option_and_then_collection_use_analysis_from_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    storage_origins: &BTreeMap<Local, Option<usize>>,
    callable_origins: &BTreeMap<Local, DefId>,
) -> Option<ReturnedBorrowCollectionUseAnalysis> {
    if method_name(callee_def_path).as_deref() != Some("and_then") {
        return None;
    }
    let first_arg = args.first()?;
    let source_type_name = first_arg.node.ty(&body.local_decls, tcx).to_string();
    let normalized_source_type = source_type_name.to_ascii_lowercase();
    if !normalized_source_type.contains("option<")
        || !returned_borrow_storage_use_type(first_arg.node.ty(&body.local_decls, tcx))
    {
        return None;
    }
    let storage_arg_index =
        collection_storage_summary_operand_origin(&first_arg.node, storage_origins)?;
    let callable_def_id = args.get(1).and_then(|arg| {
        collection_summary_callable_def_from_operand(&arg.node, body, tcx, callable_origins)
    })?;
    let analysis = summarize_returned_borrow_collection_use_callable(tcx, callable_def_id)?;
    let summary = analysis.summary.and_then(|summary| {
        if summary.storage_arg_index != 1 {
            return None;
        }
        Some(ReturnedBorrowCollectionUseSummary {
            storage_arg_index,
            key_arg_index: None,
            index_key: None,
            index_from_tail: false,
            min_sequence_len: None,
        })
    });
    let binding_gaps = analysis
        .binding_gaps
        .into_iter()
        .filter(|gap| gap.storage_arg_index == 1)
        .map(|gap| ReturnedBorrowCollectionBindingGapSummary {
            storage_arg_index,
            gap_kind: gap.gap_kind,
            adapter: gap.adapter,
        })
        .collect::<Vec<_>>();
    (summary.is_some() || !binding_gaps.is_empty()).then_some(ReturnedBorrowCollectionUseAnalysis {
        summary,
        binding_gaps,
    })
}

fn iterator_map_identity_preserving_arg<'tcx>(
    tcx: TyCtxt<'tcx>,
    body: &Body<'tcx>,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
) -> bool {
    args.get(1)
        .and_then(|arg| callback_def_id_from_ty(arg.node.ty(&body.local_decls, tcx)))
        .is_some_and(|def_id| summarize_identity_preserving_iterator_map_callable(tcx, def_id))
}

fn iterator_filter_map_identity_preserving_arg<'tcx>(
    tcx: TyCtxt<'tcx>,
    body: &Body<'tcx>,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
) -> bool {
    args.get(1)
        .and_then(|arg| callback_def_id_from_ty(arg.node.ty(&body.local_decls, tcx)))
        .is_some_and(|def_id| {
            summarize_identity_preserving_iterator_filter_map_callable(tcx, def_id)
        })
}

fn iterator_filter_always_true_arg<'tcx>(
    tcx: TyCtxt<'tcx>,
    body: &Body<'tcx>,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
) -> bool {
    args.get(1)
        .and_then(|arg| callback_def_id_from_ty(arg.node.ty(&body.local_decls, tcx)))
        .is_some_and(|def_id| summarize_always_true_iterator_filter_callable(tcx, def_id))
}

fn summarize_identity_preserving_iterator_map_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
) -> bool {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return false;
    }
    let Some(local_def_id) = def_id.as_local() else {
        return false;
    };
    let body = tcx.optimized_mir(local_def_id);
    let return_local = Local::new(0);
    if !ty_contains_ref(body.local_decls[return_local].ty) {
        return false;
    }
    let expected_arg_index = match tcx.def_kind(def_id) {
        DefKind::Closure => 1,
        _ => 0,
    };
    let mut origins = BTreeMap::<Local, Option<usize>>::new();
    for (arg_index, local) in body.args_iter().enumerate() {
        origins.insert(local, Some(arg_index));
    }
    for block in body.basic_blocks.iter() {
        for statement in &block.statements {
            let StatementKind::Assign(assignment) = &statement.kind else {
                continue;
            };
            let (place, rvalue) = &**assignment;
            record_identity_iterator_map_summary_assignment(&mut origins, place, rvalue);
        }
        if let TerminatorKind::Call { destination, .. } = &block.terminator().kind
            && destination.projection.is_empty()
        {
            origins.insert(destination.local, None);
        }
    }
    origins
        .get(&return_local)
        .copied()
        .flatten()
        .is_some_and(|arg_index| arg_index == expected_arg_index)
}

fn summarize_identity_preserving_iterator_filter_map_callable<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
) -> bool {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return false;
    }
    let Some(local_def_id) = def_id.as_local() else {
        return false;
    };
    let body = tcx.optimized_mir(local_def_id);
    let return_local = Local::new(0);
    let return_type = body.local_decls[return_local].ty.to_string();
    if !ty_contains_ref(body.local_decls[return_local].ty)
        || !return_type.to_ascii_lowercase().contains("option<")
    {
        return false;
    }
    let expected_arg_index = match tcx.def_kind(def_id) {
        DefKind::Closure => 1,
        _ => 0,
    };
    let mut item_origins = BTreeMap::<Local, Option<usize>>::new();
    let mut option_origins = BTreeMap::<Local, Option<usize>>::new();
    for (arg_index, local) in body.args_iter().enumerate() {
        item_origins.insert(local, Some(arg_index));
    }
    for block in body.basic_blocks.iter() {
        for statement in &block.statements {
            let StatementKind::Assign(assignment) = &statement.kind else {
                continue;
            };
            let (place, rvalue) = &**assignment;
            record_identity_iterator_map_summary_assignment(&mut item_origins, place, rvalue);
            record_identity_iterator_filter_map_summary_assignment(
                &mut option_origins,
                &item_origins,
                body,
                place,
                rvalue,
            );
        }
        if let TerminatorKind::Call { destination, .. } = &block.terminator().kind
            && destination.projection.is_empty()
        {
            item_origins.insert(destination.local, None);
            option_origins.insert(destination.local, None);
        }
    }
    option_origins
        .get(&return_local)
        .copied()
        .flatten()
        .is_some_and(|arg_index| arg_index == expected_arg_index)
}

fn summarize_always_true_iterator_filter_callable<'tcx>(tcx: TyCtxt<'tcx>, def_id: DefId) -> bool {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return false;
    }
    let Some(local_def_id) = def_id.as_local() else {
        return false;
    };
    let body = tcx.optimized_mir(local_def_id);
    let return_local = Local::new(0);
    if body.local_decls[return_local].ty.to_string() != "bool" {
        return false;
    }
    let mut saw_true_return = false;
    for block in body.basic_blocks.iter() {
        for statement in &block.statements {
            let StatementKind::Assign(assignment) = &statement.kind else {
                continue;
            };
            let (place, rvalue) = &**assignment;
            if place.local != return_local || !place.projection.is_empty() {
                continue;
            }
            let Some(value) = bool_constant_rvalue(rvalue) else {
                return false;
            };
            if !value {
                return false;
            }
            saw_true_return = true;
        }
        if let TerminatorKind::Call { destination, .. } = &block.terminator().kind
            && destination.local == return_local
        {
            return false;
        }
    }
    saw_true_return
}

fn bool_constant_rvalue(rvalue: &Rvalue<'_>) -> Option<bool> {
    match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => bool_constant_operand(operand),
        _ => None,
    }
}

fn bool_constant_operand(operand: &Operand<'_>) -> Option<bool> {
    let snippet = format!("{operand:?}");
    bool_constant_debug_snippet(&snippet)
}

fn bool_constant_debug_snippet(snippet: &str) -> Option<bool> {
    let after_const = snippet
        .find("const")
        .map(|index| &snippet[index + "const".len()..])?;
    let after_const = after_const.trim_start();
    if after_const.starts_with("true")
        && after_const.get("true".len()..).is_none_or(|tail| {
            tail.chars()
                .next()
                .is_none_or(|ch| !ch.is_ascii_alphanumeric())
        })
    {
        Some(true)
    } else if after_const.starts_with("false")
        && after_const.get("false".len()..).is_none_or(|tail| {
            tail.chars()
                .next()
                .is_none_or(|ch| !ch.is_ascii_alphanumeric())
        })
    {
        Some(false)
    } else {
        None
    }
}

fn record_identity_iterator_map_summary_assignment<'tcx>(
    origins: &mut BTreeMap<Local, Option<usize>>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let origin = match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            identity_iterator_map_summary_operand_origin(operand, origins)
        }
        Rvalue::Ref(_, _, place) => identity_iterator_map_summary_place_origin(place, origins),
        _ => None,
    };
    update_optional_origin(origins, destination.local, origin);
}

fn record_identity_iterator_filter_map_summary_assignment<'tcx>(
    option_origins: &mut BTreeMap<Local, Option<usize>>,
    item_origins: &BTreeMap<Local, Option<usize>>,
    body: &Body<'tcx>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let destination_type = body.local_decls[destination.local].ty.to_string();
    if !destination_type.to_ascii_lowercase().contains("option<") {
        return;
    }
    let origin = match rvalue {
        Rvalue::Aggregate(_, operands) if operands.len() == 1 => {
            operands.iter().next().and_then(|operand| {
                identity_iterator_map_summary_operand_origin(operand, item_origins)
            })
        }
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            operand.place().and_then(|place| {
                identity_iterator_filter_map_summary_option_place_origin(&place, option_origins)
            })
        }
        _ => None,
    };
    update_optional_origin(option_origins, destination.local, origin);
}

fn identity_iterator_filter_map_summary_option_place_origin(
    place: &Place<'_>,
    origins: &BTreeMap<Local, Option<usize>>,
) -> Option<usize> {
    if place.projection.is_empty()
        || (place.projection.len() == 2
            && matches!(place.projection[0], ProjectionElem::Downcast(..))
            && matches!(place.projection[1], ProjectionElem::Field(field, _) if field.index() == 0))
    {
        return origins.get(&place.local).copied().flatten();
    }
    None
}

fn identity_iterator_map_summary_operand_origin(
    operand: &Operand<'_>,
    origins: &BTreeMap<Local, Option<usize>>,
) -> Option<usize> {
    operand
        .place()
        .and_then(|place| identity_iterator_map_summary_place_origin(&place, origins))
}

fn identity_iterator_map_summary_place_origin(
    place: &Place<'_>,
    origins: &BTreeMap<Local, Option<usize>>,
) -> Option<usize> {
    if place
        .projection
        .iter()
        .all(|elem| matches!(elem, ProjectionElem::Deref))
    {
        return origins.get(&place.local).copied().flatten();
    }
    None
}

fn collection_summary_callable_def_from_operand<'tcx>(
    operand: &Operand<'tcx>,
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    origins: &BTreeMap<Local, DefId>,
) -> Option<DefId> {
    if let Some((def_id, _)) = operand.const_fn_def() {
        return Some(def_id);
    }
    if let ty::Closure(def_id, _) = operand.ty(&body.local_decls, tcx).kind() {
        return Some(*def_id);
    }
    let place = operand.place()?;
    if !place.projection.is_empty() {
        return None;
    }
    origins.get(&place.local).copied()
}

fn returned_borrow_collection_iterator_use_summary_from_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    iterator_origins: &BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<ReturnedBorrowCollectionUseSummary> {
    let method = method_name(callee_def_path)?;
    if !matches!(method.as_str(), "next" | "nth" | "last") {
        return None;
    }
    let origin = args.first().and_then(|arg| {
        collection_summary_indexed_iterator_origin_from_operand(&arg.node, iterator_origins)
    })?;
    match method.as_str() {
        "next" => {
            let (index_key, index_from_tail, min_sequence_len) =
                returned_borrow_iterator_summary_selection(&origin, 0)?;
            Some(ReturnedBorrowCollectionUseSummary {
                storage_arg_index: origin.storage_arg_index,
                key_arg_index: None,
                index_key,
                index_from_tail,
                min_sequence_len,
            })
        }
        "nth" => {
            let offset =
                returned_borrow_iterator_nth_index(callee_def_path, args, stable_constant_origins)?;
            let (index_key, index_from_tail, min_sequence_len) =
                returned_borrow_iterator_summary_selection(&origin, offset)?;
            Some(ReturnedBorrowCollectionUseSummary {
                storage_arg_index: origin.storage_arg_index,
                key_arg_index: None,
                index_key,
                index_from_tail,
                min_sequence_len,
            })
        }
        "last" if !origin.from_back => {
            let (index_key, index_from_tail, min_sequence_len) =
                returned_borrow_iterator_summary_last_selection(&origin)?;
            Some(ReturnedBorrowCollectionUseSummary {
                storage_arg_index: origin.storage_arg_index,
                key_arg_index: None,
                index_key,
                index_from_tail,
                min_sequence_len,
            })
        }
        "last" if origin.from_back => {
            let (index_key, index_from_tail, min_sequence_len) =
                returned_borrow_iterator_summary_last_selection(&origin)?;
            Some(ReturnedBorrowCollectionUseSummary {
                storage_arg_index: origin.storage_arg_index,
                key_arg_index: None,
                index_key,
                index_from_tail,
                min_sequence_len,
            })
        }
        _ => None,
    }
}

fn returned_borrow_collection_iterator_use_binding_gap_from_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    iterator_origins: &BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<ReturnedBorrowCollectionBindingGapSummary> {
    let method = method_name(callee_def_path)?;
    if method.as_str() != "nth"
        || returned_borrow_iterator_nth_index(callee_def_path, args, stable_constant_origins)
            .is_some()
    {
        return None;
    }
    let origin = args.first().and_then(|arg| {
        collection_summary_indexed_iterator_origin_from_operand(&arg.node, iterator_origins)
    })?;
    Some(ReturnedBorrowCollectionBindingGapSummary {
        storage_arg_index: origin.storage_arg_index,
        gap_kind: ObjectBindingGapKind::DynamicIndex,
        adapter: method,
    })
}

fn returned_borrow_indexed_sequence_use_summary_from_origin(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'_>>],
    origin: IndexedIteratorArgOrigin,
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<ReturnedBorrowCollectionUseSummary> {
    let method = method_name(callee_def_path)?;
    let (index_key, index_from_tail, min_sequence_len) = match method.as_str() {
        "get" => {
            let offset = args
                .get(1)
                .and_then(|arg| {
                    usize_constant_operand_key_with_origins(&arg.node, stable_constant_origins)
                })
                .and_then(|index| index.parse::<usize>().ok())?;
            returned_borrow_iterator_summary_selection(&origin, offset)?
        }
        "first" | "front" => returned_borrow_iterator_summary_selection(&origin, 0)?,
        "last" | "back" => returned_borrow_iterator_summary_last_selection(&origin)?,
        _ => return None,
    };
    Some(ReturnedBorrowCollectionUseSummary {
        storage_arg_index: origin.storage_arg_index,
        key_arg_index: None,
        index_key,
        index_from_tail,
        min_sequence_len,
    })
}

fn returned_borrow_collection_use_binding_gap_from_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    storage_origins: &BTreeMap<Local, Option<usize>>,
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<ReturnedBorrowCollectionBindingGapSummary> {
    let first_arg = args.first()?;
    let storage_type_name = first_arg.node.ty(&body.local_decls, tcx).to_string();
    if !returned_borrow_indexed_sequence_use_call(callee_def_path, &storage_type_name) {
        return None;
    }
    let storage_arg_index =
        collection_storage_summary_operand_origin(&first_arg.node, storage_origins)?;
    match method_name(callee_def_path).as_deref()? {
        "get" => {
            let index_arg = args.get(1)?;
            if usize_constant_operand_key_with_origins(&index_arg.node, stable_constant_origins)
                .is_some()
            {
                return None;
            }
            let index_type_name = index_arg.node.ty(&body.local_decls, tcx).to_string();
            Some(ReturnedBorrowCollectionBindingGapSummary {
                storage_arg_index,
                gap_kind: if range_or_slice_index_type(&index_type_name) {
                    ObjectBindingGapKind::RangeOrSlice
                } else {
                    ObjectBindingGapKind::DynamicIndex
                },
                adapter: "get".to_owned(),
            })
        }
        _ => None,
    }
}

fn returned_borrow_iterator_summary_selection(
    origin: &IndexedIteratorArgOrigin,
    offset: usize,
) -> Option<(Option<String>, bool, Option<usize>)> {
    match (origin.take_limit, origin.take_from_back) {
        (Some(limit), Some(false)) => {
            if offset >= limit {
                return None;
            }
            let min_sequence_len = origin.front_offset.checked_add(limit);
            if origin.from_back {
                let index = origin
                    .front_offset
                    .checked_add(limit.checked_sub(1)?.checked_sub(offset)?)?;
                Some((Some(index.to_string()), false, min_sequence_len))
            } else {
                let index = origin.front_offset.checked_add(offset)?;
                Some((Some(index.to_string()), false, min_sequence_len))
            }
        }
        (Some(limit), Some(true)) => {
            if offset >= limit {
                return None;
            }
            let min_sequence_len = origin.back_offset.checked_add(limit);
            if origin.from_back {
                let tail_offset = origin.back_offset.checked_add(offset)?;
                Some((
                    (tail_offset > 0).then(|| tail_offset.to_string()),
                    true,
                    min_sequence_len,
                ))
            } else {
                let tail_offset = origin
                    .back_offset
                    .checked_add(limit.checked_sub(1)?.checked_sub(offset)?)?;
                Some((
                    (tail_offset > 0).then(|| tail_offset.to_string()),
                    true,
                    min_sequence_len,
                ))
            }
        }
        (Some(_), None) => None,
        (None, _) if origin.from_back => {
            let tail_offset = origin.back_offset.checked_add(offset)?;
            Some((
                (tail_offset > 0).then(|| tail_offset.to_string()),
                true,
                (origin.front_offset > 0)
                    .then(|| {
                        returned_borrow_iterator_min_sequence_len(
                            origin.front_offset,
                            origin.back_offset,
                            offset,
                        )
                    })
                    .flatten(),
            ))
        }
        (None, _) => {
            let index = origin.front_offset.checked_add(offset)?;
            Some((
                Some(index.to_string()),
                false,
                (origin.back_offset > 0)
                    .then(|| {
                        returned_borrow_iterator_min_sequence_len(
                            origin.front_offset,
                            origin.back_offset,
                            offset,
                        )
                    })
                    .flatten(),
            ))
        }
    }
}

fn returned_borrow_iterator_summary_last_selection(
    origin: &IndexedIteratorArgOrigin,
) -> Option<(Option<String>, bool, Option<usize>)> {
    match (origin.take_limit, origin.take_from_back) {
        (Some(0), _) => None,
        (Some(limit), Some(false)) if origin.from_back => Some((
            Some(origin.front_offset.to_string()),
            false,
            origin.front_offset.checked_add(limit),
        )),
        (Some(limit), Some(false)) => {
            let index = origin.front_offset.checked_add(limit.checked_sub(1)?)?;
            Some((
                Some(index.to_string()),
                false,
                origin.front_offset.checked_add(limit),
            ))
        }
        (Some(limit), Some(true)) if origin.from_back => {
            let tail_offset = origin.back_offset.checked_add(limit.checked_sub(1)?)?;
            Some((
                (tail_offset > 0).then(|| tail_offset.to_string()),
                true,
                origin.back_offset.checked_add(limit),
            ))
        }
        (Some(limit), Some(true)) => Some((
            (origin.back_offset > 0).then(|| origin.back_offset.to_string()),
            true,
            origin.back_offset.checked_add(limit),
        )),
        (Some(_), None) => None,
        (None, _) if origin.from_back => Some((
            Some(origin.front_offset.to_string()),
            false,
            (origin.front_offset > 0 || origin.back_offset > 0)
                .then(|| {
                    returned_borrow_iterator_min_sequence_len(
                        origin.front_offset,
                        origin.back_offset,
                        0,
                    )
                })
                .flatten(),
        )),
        (None, _) => Some((
            (origin.back_offset > 0).then(|| origin.back_offset.to_string()),
            true,
            (origin.front_offset > 0)
                .then(|| {
                    returned_borrow_iterator_min_sequence_len(
                        origin.front_offset,
                        origin.back_offset,
                        0,
                    )
                })
                .flatten(),
        )),
    }
}

fn consume_collection_summary_indexed_iterator_use<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    iterator_origins: &mut BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
) {
    if !method_name(callee_def_path)
        .as_deref()
        .is_some_and(|method| matches!(method, "next" | "nth" | "last"))
    {
        return;
    }
    let Some(origin) = args.first().and_then(|arg| {
        collection_summary_indexed_iterator_origin_from_operand(&arg.node, iterator_origins)
    }) else {
        return;
    };
    iterator_origins.retain(|_, candidate| {
        candidate
            .as_ref()
            .is_none_or(|candidate| candidate.storage_arg_index != origin.storage_arg_index)
    });
}

fn collection_summary_indexed_iterator_origin_from_operand(
    operand: &Operand<'_>,
    origins: &BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
) -> Option<IndexedIteratorArgOrigin> {
    let place = operand.place()?;
    collection_summary_indexed_iterator_origin_from_place(&place, origins)
}

fn collection_summary_indexed_iterator_origin_from_place(
    place: &Place<'_>,
    origins: &BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
) -> Option<IndexedIteratorArgOrigin> {
    if !place.projection.is_empty() {
        return None;
    }
    origins.get(&place.local).cloned().flatten()
}

fn returned_borrow_collection_use_summary_from_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    storage_origins: &BTreeMap<Local, Option<usize>>,
    key_origins: &BTreeMap<Local, Option<usize>>,
    slice_origins: &BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<ReturnedBorrowCollectionUseSummary> {
    let first_arg = args.first()?;
    let storage_type_name = first_arg.node.ty(&body.local_decls, tcx).to_string();
    if returned_borrow_keyed_map_use_call(callee_def_path, &storage_type_name) {
        let storage_arg_index =
            collection_storage_summary_operand_origin(&first_arg.node, storage_origins)?;
        let key_arg_index = args
            .get(1)
            .and_then(|arg| string_key_summary_operand_origin(&arg.node, key_origins))?;
        return Some(ReturnedBorrowCollectionUseSummary {
            storage_arg_index,
            key_arg_index: Some(key_arg_index),
            index_key: None,
            index_from_tail: false,
            min_sequence_len: None,
        });
    }
    if returned_borrow_indexed_sequence_use_call(callee_def_path, &storage_type_name) {
        if let Some(origin) =
            collection_summary_slice_origin_from_operand(&first_arg.node, slice_origins)
        {
            return returned_borrow_indexed_sequence_use_summary_from_origin(
                callee_def_path,
                args,
                origin,
                stable_constant_origins,
            );
        }
        let storage_arg_index =
            collection_storage_summary_operand_origin(&first_arg.node, storage_origins)?;
        let index_from_tail = returned_borrow_collection_tail_use(callee_def_path);
        let index_key = if index_from_tail {
            None
        } else {
            Some(returned_borrow_collection_use_index(
                callee_def_path,
                args,
                stable_constant_origins,
            )?)
        };
        return Some(ReturnedBorrowCollectionUseSummary {
            storage_arg_index,
            key_arg_index: None,
            index_key,
            index_from_tail,
            min_sequence_len: None,
        });
    }
    None
}

fn returned_borrow_collection_use_summary_from_nested_analysis<'tcx>(
    analysis: &ReturnedBorrowCollectionUseAnalysis,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    storage_origins: &BTreeMap<Local, Option<usize>>,
    key_origins: &BTreeMap<Local, Option<usize>>,
) -> Option<ReturnedBorrowCollectionUseSummary> {
    let summary = analysis.summary.as_ref()?;
    let storage_arg_index = args
        .get(summary.storage_arg_index)
        .and_then(|arg| collection_storage_summary_operand_origin(&arg.node, storage_origins))?;
    let key_arg_index = match summary.key_arg_index {
        Some(key_arg_index) => Some(
            args.get(key_arg_index)
                .and_then(|arg| string_key_summary_operand_origin(&arg.node, key_origins))?,
        ),
        None => None,
    };
    Some(ReturnedBorrowCollectionUseSummary {
        storage_arg_index,
        key_arg_index,
        index_key: summary.index_key.clone(),
        index_from_tail: summary.index_from_tail,
        min_sequence_len: summary.min_sequence_len,
    })
}

fn collection_use_binding_gap_summaries_from_nested_analysis<'tcx>(
    analysis: &ReturnedBorrowCollectionUseAnalysis,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    storage_origins: &BTreeMap<Local, Option<usize>>,
) -> Vec<ReturnedBorrowCollectionBindingGapSummary> {
    let mut summaries = Vec::new();
    for gap in &analysis.binding_gaps {
        let Some(storage_arg_index) = args
            .get(gap.storage_arg_index)
            .and_then(|arg| collection_storage_summary_operand_origin(&arg.node, storage_origins))
        else {
            continue;
        };
        let summary = ReturnedBorrowCollectionBindingGapSummary {
            storage_arg_index,
            gap_kind: gap.gap_kind,
            adapter: gap.adapter.clone(),
        };
        if !summaries.contains(&summary) {
            summaries.push(summary);
        }
    }
    summaries
}

fn returned_borrow_collection_mutation_summary_from_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    storage_origins: &BTreeMap<Local, Option<usize>>,
    key_origins: &BTreeMap<Local, Option<usize>>,
    entry_origins: &BTreeMap<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>,
) -> Option<ReturnedBorrowCollectionMutationSummary> {
    let method = method_name(callee_def_path)?;
    if matches!(method.as_str(), "and_modify" | "insert_entry" | "insert")
        && let Some(entry_origin) = args
            .first()
            .and_then(|arg| collection_entry_summary_operand_origin(&arg.node, entry_origins))
    {
        return Some(ReturnedBorrowCollectionMutationSummary {
            storage_arg_index: entry_origin.storage_arg_index,
            key_arg_index: entry_origin.key_arg_index,
        });
    }
    if !matches!(method.as_str(), "insert" | "remove" | "clear") {
        return None;
    }
    let first_arg = args.first()?;
    let storage_type_name = first_arg.node.ty(&body.local_decls, tcx).to_string();
    if !returned_borrow_keyed_map_storage_type(&storage_type_name) {
        return None;
    }
    let storage_arg_index =
        collection_storage_summary_operand_origin(&first_arg.node, storage_origins)?;
    let key_arg_index = match method.as_str() {
        "insert" | "remove" => args
            .get(1)
            .and_then(|arg| string_key_summary_operand_origin(&arg.node, key_origins)),
        "clear" => None,
        _ => None,
    };
    Some(ReturnedBorrowCollectionMutationSummary {
        storage_arg_index,
        key_arg_index,
    })
}

fn returned_borrow_collection_mutation_summary_from_nested_summary<'tcx>(
    summary: ReturnedBorrowCollectionMutationSummary,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    storage_origins: &BTreeMap<Local, Option<usize>>,
    key_origins: &BTreeMap<Local, Option<usize>>,
) -> Option<ReturnedBorrowCollectionMutationSummary> {
    let storage_arg_index = args
        .get(summary.storage_arg_index)
        .and_then(|arg| collection_storage_summary_operand_origin(&arg.node, storage_origins))?;
    let key_arg_index = match summary.key_arg_index {
        Some(key_arg_index) => args
            .get(key_arg_index)
            .and_then(|arg| string_key_summary_operand_origin(&arg.node, key_origins)),
        None => None,
    };
    Some(ReturnedBorrowCollectionMutationSummary {
        storage_arg_index,
        key_arg_index,
    })
}

fn record_collection_remove_return_summary_assignment<'tcx>(
    origins: &mut BTreeMap<Local, Option<ReturnedBorrowCollectionRemoveReturnSummary>>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) {
    if !destination.projection.is_empty() {
        return;
    }
    let origin = match rvalue {
        Rvalue::Use(operand, _) => operand.place().and_then(|place| {
            place
                .projection
                .is_empty()
                .then(|| origins.get(&place.local).cloned().flatten())
                .flatten()
        }),
        _ => None,
    };
    update_optional_origin(origins, destination.local, origin);
}

fn record_collection_remove_return_summary_unknown_destination<'tcx>(
    origins: &mut BTreeMap<Local, Option<ReturnedBorrowCollectionRemoveReturnSummary>>,
    destination: &Place<'tcx>,
) {
    if destination.projection.is_empty() {
        origins.remove(&destination.local);
    }
}

fn returned_borrow_collection_remove_return_summary_from_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    storage_origins: &BTreeMap<Local, Option<usize>>,
    key_origins: &BTreeMap<Local, Option<usize>>,
    destination: &Place<'tcx>,
) -> Option<ReturnedBorrowCollectionRemoveReturnSummary> {
    if method_name(callee_def_path).as_deref() != Some("remove")
        || !destination.projection.is_empty()
        || !ty_contains_ref(destination.ty(&body.local_decls, tcx).ty)
    {
        return None;
    }
    let first_arg = args.first()?;
    let storage_type_name = first_arg.node.ty(&body.local_decls, tcx).to_string();
    if !returned_borrow_keyed_map_storage_type(&storage_type_name) {
        return None;
    }
    let storage_arg_index =
        collection_storage_summary_operand_origin(&first_arg.node, storage_origins)?;
    let key_arg_index = args
        .get(1)
        .and_then(|arg| string_key_summary_operand_origin(&arg.node, key_origins))?;
    Some(ReturnedBorrowCollectionRemoveReturnSummary {
        storage_arg_index,
        key_arg_index,
    })
}

fn returned_borrow_collection_remove_return_summary_from_nested_summary<'tcx>(
    summary: ReturnedBorrowCollectionRemoveReturnSummary,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    storage_origins: &BTreeMap<Local, Option<usize>>,
    key_origins: &BTreeMap<Local, Option<usize>>,
) -> Option<ReturnedBorrowCollectionRemoveReturnSummary> {
    let storage_arg_index = args
        .get(summary.storage_arg_index)
        .and_then(|arg| collection_storage_summary_operand_origin(&arg.node, storage_origins))?;
    let key_arg_index = args
        .get(summary.key_arg_index)
        .and_then(|arg| string_key_summary_operand_origin(&arg.node, key_origins))?;
    Some(ReturnedBorrowCollectionRemoveReturnSummary {
        storage_arg_index,
        key_arg_index,
    })
}

fn merge_returned_borrow_collection_remove_return_summary(
    existing: Option<ReturnedBorrowCollectionRemoveReturnSummary>,
    candidate: ReturnedBorrowCollectionRemoveReturnSummary,
) -> Option<Option<ReturnedBorrowCollectionRemoveReturnSummary>> {
    if existing.is_some_and(|existing| existing != candidate) {
        return None;
    }
    Some(Some(candidate))
}

fn returned_borrow_collection_persist_summary_from_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    storage_origins: &BTreeMap<Local, Option<usize>>,
    key_origins: &BTreeMap<Local, Option<usize>>,
    entry_origins: &BTreeMap<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>,
    visitor: &MirSiteVisitor<'_, 'tcx>,
    span: Span,
    location: Location,
) -> Option<ReturnedBorrowCollectionPersistSummary> {
    let method = method_name(callee_def_path)?;
    if matches!(method.as_str(), "insert_entry" | "insert")
        && let Some(entry_origin) = args
            .first()
            .and_then(|arg| collection_entry_summary_operand_origin(&arg.node, entry_origins))
    {
        if entry_origin.projection_kind.is_some() {
            return None;
        }
        let key_arg_index = entry_origin.key_arg_index?;
        let origin = args.get(1).and_then(|arg| {
            visitor.returned_borrow_origin_from_operand(&arg.node, arg.span, location)
        })?;
        return Some(ReturnedBorrowCollectionPersistSummary {
            storage_arg_index: entry_origin.storage_arg_index,
            key_arg_index,
            origin,
        });
    }
    if method != "insert" {
        return None;
    }
    let first_arg = args.first()?;
    let storage_type_name = first_arg.node.ty(&body.local_decls, tcx).to_string();
    if !returned_borrow_keyed_map_insert_call(callee_def_path, &storage_type_name) {
        return None;
    }
    let storage_arg_index =
        collection_storage_summary_operand_origin(&first_arg.node, storage_origins)?;
    let key_arg_index = args
        .get(1)
        .and_then(|arg| string_key_summary_operand_origin(&arg.node, key_origins))?;
    let origin = args
        .get(2)
        .and_then(|arg| visitor.returned_borrow_origin_from_operand(&arg.node, span, location))?;
    Some(ReturnedBorrowCollectionPersistSummary {
        storage_arg_index,
        key_arg_index,
        origin,
    })
}

fn returned_borrow_collection_persist_summary_from_nested_analysis<'tcx>(
    analysis: &ReturnedBorrowCollectionPersistAnalysis,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    storage_origins: &BTreeMap<Local, Option<usize>>,
    key_origins: &BTreeMap<Local, Option<usize>>,
) -> Option<ReturnedBorrowCollectionPersistSummary> {
    let summary = analysis.summary.as_ref()?;
    let storage_arg_index = args
        .get(summary.storage_arg_index)
        .and_then(|arg| collection_storage_summary_operand_origin(&arg.node, storage_origins))?;
    let key_arg_index = args
        .get(summary.key_arg_index)
        .and_then(|arg| string_key_summary_operand_origin(&arg.node, key_origins))?;
    Some(ReturnedBorrowCollectionPersistSummary {
        storage_arg_index,
        key_arg_index,
        origin: summary.origin.clone(),
    })
}

fn collection_persist_binding_gap_summaries_from_nested_analysis<'tcx>(
    analysis: &ReturnedBorrowCollectionPersistAnalysis,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    storage_origins: &BTreeMap<Local, Option<usize>>,
) -> Vec<ReturnedBorrowCollectionBindingGapSummary> {
    let mut summaries = Vec::new();
    for gap in &analysis.binding_gaps {
        let Some(storage_arg_index) = args
            .get(gap.storage_arg_index)
            .and_then(|arg| collection_storage_summary_operand_origin(&arg.node, storage_origins))
        else {
            continue;
        };
        let summary = ReturnedBorrowCollectionBindingGapSummary {
            storage_arg_index,
            gap_kind: gap.gap_kind,
            adapter: gap.adapter.clone(),
        };
        if !summaries.contains(&summary) {
            summaries.push(summary);
        }
    }
    summaries
}

fn returned_borrow_collection_entry_branch_persist_summary_from_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    entry_origins: &BTreeMap<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>,
    visitor: &MirSiteVisitor<'_, 'tcx>,
    branch_writes: &mut BTreeMap<
        (usize, usize, MirOrderKey),
        ReturnedBorrowCollectionEntrySummaryBranchWrites,
    >,
    split_branch_writes: &mut BTreeMap<
        (usize, usize),
        ReturnedBorrowCollectionSplitEntrySummaryBranchWrites,
    >,
    location: Location,
) -> CollectionEntryBranchPersistOutcome {
    let Some(method) = method_name(callee_def_path) else {
        return CollectionEntryBranchPersistOutcome::Irrelevant;
    };
    if !matches!(
        method.as_str(),
        "and_modify"
            | "or_insert"
            | "or_insert_with"
            | "or_insert_with_key"
            | "insert"
            | "insert_entry"
    ) {
        return CollectionEntryBranchPersistOutcome::Irrelevant;
    }
    let Some(entry_origin) = args
        .first()
        .and_then(|arg| collection_entry_summary_operand_origin(&arg.node, entry_origins))
    else {
        return CollectionEntryBranchPersistOutcome::Irrelevant;
    };
    let Some(key_arg_index) = entry_origin.key_arg_index else {
        return CollectionEntryBranchPersistOutcome::Poison;
    };
    let Some(branch_kind) = (match method.as_str() {
        "and_modify" => Some(KeyedMapEntryProjectionKind::Occupied),
        "or_insert" | "or_insert_with" | "or_insert_with_key" => {
            Some(KeyedMapEntryProjectionKind::Vacant)
        }
        "insert" | "insert_entry" => entry_origin.projection_kind,
        _ => None,
    }) else {
        return CollectionEntryBranchPersistOutcome::Irrelevant;
    };
    let branch_write = match method.as_str() {
        "and_modify" => args
            .get(1)
            .and_then(|arg| {
                callback_def_id_from_ty(arg.node.ty(&visitor.body.local_decls, visitor.tcx))
            })
            .and_then(|def_id| {
                summarize_returned_borrow_slot_assignment_callable(
                    visitor.tcx,
                    visitor.current_crate_name,
                    def_id,
                    &visitor.closure_returned_borrow_capture_summaries,
                )
            })
            .map(KeyedMapEntryBranchWrite::Returned)
            .unwrap_or(KeyedMapEntryBranchWrite::Blocked),
        "or_insert" => args
            .get(1)
            .and_then(|arg| {
                visitor.returned_borrow_origin_from_operand(&arg.node, arg.span, location)
            })
            .map(KeyedMapEntryBranchWrite::Returned)
            .unwrap_or(KeyedMapEntryBranchWrite::Blocked),
        "or_insert_with" | "or_insert_with_key" => args
            .get(1)
            .and_then(|arg| {
                callback_def_id_from_ty(arg.node.ty(&visitor.body.local_decls, visitor.tcx))
            })
            .and_then(|def_id| {
                (!returned_borrow_callable_returns_ref_container(visitor.tcx, def_id))
                    .then(|| {
                        summarize_returned_borrow_callable_with_captures(
                            visitor.tcx,
                            visitor.current_crate_name,
                            def_id,
                            &visitor.closure_returned_borrow_capture_summaries,
                        )
                    })
                    .flatten()
            })
            .map(KeyedMapEntryBranchWrite::Returned)
            .unwrap_or(KeyedMapEntryBranchWrite::Blocked),
        "insert" | "insert_entry" => args
            .get(1)
            .and_then(|arg| {
                visitor.returned_borrow_origin_from_operand(&arg.node, arg.span, location)
            })
            .map(KeyedMapEntryBranchWrite::Returned)
            .unwrap_or(KeyedMapEntryBranchWrite::Blocked),
        _ => return CollectionEntryBranchPersistOutcome::Irrelevant,
    };
    let exact_branch_key = (
        entry_origin.storage_arg_index,
        key_arg_index,
        entry_origin.entry_site_id,
    );
    let writes = branch_writes.entry(exact_branch_key).or_insert_with(|| {
        ReturnedBorrowCollectionEntrySummaryBranchWrites {
            storage_arg_index: entry_origin.storage_arg_index,
            key_arg_index,
            entry_site_id: entry_origin.entry_site_id,
            occupied: KeyedMapEntryBranchWrite::Unseen,
            vacant: KeyedMapEntryBranchWrite::Unseen,
            merged: false,
        }
    });
    debug_assert_eq!(writes.entry_site_id, entry_origin.entry_site_id);
    if writes.merged {
        return CollectionEntryBranchPersistOutcome::Poison;
    }
    match branch_kind {
        KeyedMapEntryProjectionKind::Occupied => {
            merge_keyed_map_entry_branch_write(&mut writes.occupied, branch_write.clone())
        }
        KeyedMapEntryProjectionKind::Vacant => {
            merge_keyed_map_entry_branch_write(&mut writes.vacant, branch_write.clone())
        }
    }
    if matches!(
        (&writes.occupied, &writes.vacant),
        (KeyedMapEntryBranchWrite::Ambiguous, _)
            | (_, KeyedMapEntryBranchWrite::Ambiguous)
            | (KeyedMapEntryBranchWrite::Blocked, _)
            | (_, KeyedMapEntryBranchWrite::Blocked)
    ) {
        return CollectionEntryBranchPersistOutcome::Poison;
    }
    let merged_origin = match (&writes.occupied, &writes.vacant) {
        (
            KeyedMapEntryBranchWrite::Returned(occupied),
            KeyedMapEntryBranchWrite::Returned(vacant),
        ) if occupied == vacant => Some(occupied.clone()),
        _ => None,
    };
    if let Some(origin) = merged_origin {
        writes.merged = true;
        return CollectionEntryBranchPersistOutcome::Complete(
            ReturnedBorrowCollectionPersistSummary {
                storage_arg_index: writes.storage_arg_index,
                key_arg_index: writes.key_arg_index,
                origin,
            },
        );
    }
    if matches!(
        (&writes.occupied, &writes.vacant),
        (
            KeyedMapEntryBranchWrite::Returned(_),
            KeyedMapEntryBranchWrite::Returned(_)
        )
    ) {
        return CollectionEntryBranchPersistOutcome::Poison;
    }
    let split_branch_key = (entry_origin.storage_arg_index, key_arg_index);
    let split_writes = split_branch_writes
        .entry(split_branch_key)
        .or_insert_with(|| ReturnedBorrowCollectionSplitEntrySummaryBranchWrites {
            storage_arg_index: entry_origin.storage_arg_index,
            key_arg_index,
            occupied_entry_site_id: None,
            vacant_entry_site_id: None,
            occupied: KeyedMapEntryBranchWrite::Unseen,
            vacant: KeyedMapEntryBranchWrite::Unseen,
            merged: false,
        });
    if split_writes.merged {
        return CollectionEntryBranchPersistOutcome::Poison;
    }
    match branch_kind {
        KeyedMapEntryProjectionKind::Occupied => {
            let incoming = if split_writes
                .occupied_entry_site_id
                .is_some_and(|site| site != entry_origin.entry_site_id)
            {
                KeyedMapEntryBranchWrite::Ambiguous
            } else {
                split_writes.occupied_entry_site_id = Some(entry_origin.entry_site_id);
                branch_write
            };
            merge_keyed_map_entry_branch_write(&mut split_writes.occupied, incoming);
        }
        KeyedMapEntryProjectionKind::Vacant => {
            let incoming = if split_writes
                .vacant_entry_site_id
                .is_some_and(|site| site != entry_origin.entry_site_id)
            {
                KeyedMapEntryBranchWrite::Ambiguous
            } else {
                split_writes.vacant_entry_site_id = Some(entry_origin.entry_site_id);
                branch_write
            };
            merge_keyed_map_entry_branch_write(&mut split_writes.vacant, incoming);
        }
    }
    if matches!(
        (&split_writes.occupied, &split_writes.vacant),
        (KeyedMapEntryBranchWrite::Ambiguous, _)
            | (_, KeyedMapEntryBranchWrite::Ambiguous)
            | (KeyedMapEntryBranchWrite::Blocked, _)
            | (_, KeyedMapEntryBranchWrite::Blocked)
    ) {
        return CollectionEntryBranchPersistOutcome::Poison;
    }
    let split_merged_origin = match (
        split_writes.occupied_entry_site_id,
        split_writes.vacant_entry_site_id,
        &split_writes.occupied,
        &split_writes.vacant,
    ) {
        (
            Some(occupied_site),
            Some(vacant_site),
            KeyedMapEntryBranchWrite::Returned(occupied),
            KeyedMapEntryBranchWrite::Returned(vacant),
        ) if occupied_site != vacant_site && occupied == vacant => Some(occupied.clone()),
        _ => None,
    };
    if let Some(origin) = split_merged_origin {
        split_writes.merged = true;
        return CollectionEntryBranchPersistOutcome::Complete(
            ReturnedBorrowCollectionPersistSummary {
                storage_arg_index: split_writes.storage_arg_index,
                key_arg_index: split_writes.key_arg_index,
                origin,
            },
        );
    }
    if matches!(
        (&split_writes.occupied, &split_writes.vacant),
        (
            KeyedMapEntryBranchWrite::Returned(_),
            KeyedMapEntryBranchWrite::Returned(_)
        )
    ) {
        return CollectionEntryBranchPersistOutcome::Poison;
    }
    CollectionEntryBranchPersistOutcome::Pending
}

fn collection_entry_handle_return_key_from_insert_entry_call<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    body: &Body<'tcx>,
    destination: &Place<'tcx>,
    entry_origins: &BTreeMap<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>,
) -> Option<(usize, usize)> {
    if method_name(callee_def_path).as_deref() != Some("insert_entry")
        || !destination.projection.is_empty()
    {
        return None;
    }
    let destination_type_name = body.local_decls[destination.local]
        .ty
        .to_string()
        .to_ascii_lowercase();
    if !destination_type_name.contains("occupiedentry<")
        && !destination_type_name.contains("entry<")
    {
        return None;
    }
    let entry_origin = args
        .first()
        .and_then(|arg| collection_entry_summary_operand_origin(&arg.node, entry_origins))?;
    Some((entry_origin.storage_arg_index, entry_origin.key_arg_index?))
}

fn merge_returned_borrow_collection_mutation_summary(
    existing: Option<ReturnedBorrowCollectionMutationSummary>,
    candidate: ReturnedBorrowCollectionMutationSummary,
) -> Option<Option<ReturnedBorrowCollectionMutationSummary>> {
    let Some(existing) = existing else {
        return Some(Some(candidate));
    };
    if existing.storage_arg_index != candidate.storage_arg_index {
        return None;
    }
    if existing.key_arg_index == candidate.key_arg_index {
        return Some(Some(existing));
    }
    Some(Some(ReturnedBorrowCollectionMutationSummary {
        storage_arg_index: existing.storage_arg_index,
        key_arg_index: None,
    }))
}

fn returned_borrow_collection_mutating_call_in_summary<'tcx>(
    callee_def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'tcx>>],
    storage_origins: &BTreeMap<Local, Option<usize>>,
) -> bool {
    let Some(method) = method_name(callee_def_path) else {
        return false;
    };
    if !matches!(method.as_str(), "insert" | "remove" | "clear") {
        return false;
    }
    args.first().is_some_and(|arg| {
        collection_storage_summary_operand_origin(&arg.node, storage_origins).is_some()
    })
}

fn collection_storage_summary_operand_origin(
    operand: &Operand<'_>,
    origins: &BTreeMap<Local, Option<usize>>,
) -> Option<usize> {
    operand
        .place()
        .and_then(|place| collection_storage_summary_place_origin(&place, origins))
}

fn collection_storage_summary_place_origin(
    place: &Place<'_>,
    origins: &BTreeMap<Local, Option<usize>>,
) -> Option<usize> {
    if !place.projection.is_empty() {
        return None;
    }
    origins.get(&place.local).copied().flatten()
}

fn collection_entry_summary_operand_origin(
    operand: &Operand<'_>,
    origins: &BTreeMap<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>,
) -> Option<ReturnedBorrowCollectionEntrySummaryOrigin> {
    operand
        .place()
        .and_then(|place| collection_entry_summary_place_origin(&place, origins))
}

fn collection_entry_summary_place_origin(
    place: &Place<'_>,
    origins: &BTreeMap<Local, Option<ReturnedBorrowCollectionEntrySummaryOrigin>>,
) -> Option<ReturnedBorrowCollectionEntrySummaryOrigin> {
    if place.projection.is_empty() {
        return origins.get(&place.local).copied().flatten();
    }
    let origin = origins.get(&place.local).copied().flatten()?;
    keyed_map_entry_projection_kind(place).map(|projection_kind| {
        ReturnedBorrowCollectionEntrySummaryOrigin {
            projection_kind: Some(projection_kind),
            ..origin
        }
    })
}

fn collection_summary_slice_origin_from_operand(
    operand: &Operand<'_>,
    origins: &BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
) -> Option<IndexedIteratorArgOrigin> {
    operand
        .place()
        .and_then(|place| collection_summary_slice_origin_from_place(&place, origins))
}

fn collection_summary_slice_origin_from_place(
    place: &Place<'_>,
    origins: &BTreeMap<Local, Option<IndexedIteratorArgOrigin>>,
) -> Option<IndexedIteratorArgOrigin> {
    if place.projection.is_empty()
        || (place.projection.len() == 2
            && matches!(place.projection[0], ProjectionElem::Downcast(..))
            && matches!(place.projection[1], ProjectionElem::Field(field, _) if field.index() == 0))
    {
        return origins.get(&place.local).cloned().flatten();
    }
    None
}

fn raw_pointer_passthrough_arg_index<'tcx>(
    tcx: TyCtxt<'tcx>,
    callee_def_id: DefId,
) -> Option<usize> {
    if raw_pointer_cast_passthrough_path(&tcx.def_path_str(callee_def_id)) {
        return Some(0);
    }
    if !tcx.is_mir_available(callee_def_id) {
        return None;
    }
    let body = tcx.optimized_mir(callee_def_id);
    if body.basic_blocks.len() != 1 {
        return None;
    }
    let return_local = Local::new(0);
    if !matches!(body.local_decls[return_local].ty.kind(), ty::RawPtr(..)) {
        return None;
    }

    let block = &body.basic_blocks[BasicBlock::new(0)];
    if !matches!(
        block.terminator().kind,
        TerminatorKind::Return | TerminatorKind::UnwindResume
    ) {
        return None;
    }

    let mut returned_arg_index = None;
    for statement in &block.statements {
        let StatementKind::Assign(assignment) = &statement.kind else {
            continue;
        };
        let (place, rvalue) = &**assignment;
        if place.local != return_local || !place.projection.is_empty() {
            continue;
        }
        let source_local = match rvalue {
            Rvalue::Use(operand, _) => operand_raw_pointer_local(operand)?,
            _ => return None,
        };
        if !matches!(body.local_decls[source_local].ty.kind(), ty::RawPtr(..)) {
            return None;
        }
        let arg_index = source_local.index().checked_sub(1)?;
        if arg_index >= body.arg_count {
            return None;
        }
        if returned_arg_index
            .replace(arg_index)
            .is_some_and(|existing| existing != arg_index)
        {
            return None;
        }
    }
    returned_arg_index
}

fn raw_pointer_return_field_arg_mappings<'tcx>(
    tcx: TyCtxt<'tcx>,
    callee_def_id: DefId,
) -> Option<BTreeMap<Vec<String>, RawPointerArgPlaceKey>> {
    if !tcx.is_mir_available(callee_def_id) {
        return None;
    }
    let body = tcx.optimized_mir(callee_def_id);
    if body.basic_blocks.len() != 1 {
        return None;
    }
    let return_local = Local::new(0);
    if matches!(body.local_decls[return_local].ty.kind(), ty::RawPtr(..)) {
        return None;
    }

    let block = &body.basic_blocks[BasicBlock::new(0)];
    if !matches!(block.terminator().kind, TerminatorKind::Return) {
        return None;
    }

    let mut raw_pointer_arg_origins = BTreeMap::new();
    for statement in &block.statements {
        record_callee_raw_pointer_arg_assignment_with_aggregates(
            body,
            tcx,
            statement,
            &mut raw_pointer_arg_origins,
        );
    }

    let mut mappings = BTreeMap::new();
    for (key, origin) in raw_pointer_arg_origins {
        if key.local != return_local.index() || key.projection.is_empty() {
            continue;
        }
        let Some(origin) = origin else {
            continue;
        };
        if mappings
            .insert(key.projection, origin.clone())
            .is_some_and(|existing| existing != origin)
        {
            return None;
        }
    }
    (!mappings.is_empty()).then_some(mappings)
}

fn raw_pointer_cast_passthrough_path(def_path: &str) -> bool {
    def_path.ends_with("::cast") && (def_path.contains("ptr") || def_path.contains("*mut"))
}

fn raw_pointer_release_arg_place_key<'tcx>(
    tcx: TyCtxt<'tcx>,
    callee_def_id: DefId,
    allow_capsule_get_pointer: bool,
) -> Option<RawPointerArgPlaceKey> {
    if !tcx.is_mir_available(callee_def_id) {
        return None;
    }
    let body = tcx.optimized_mir(callee_def_id);
    let mut released_arg_key = None;
    let predecessors = raw_pointer_basic_block_predecessors(body);
    let mut block_exit_origins = vec![None; body.basic_blocks.len()];
    for (block_index, block) in body.basic_blocks.iter().enumerate() {
        let mut raw_pointer_arg_origins =
            incoming_raw_pointer_arg_origins(&predecessors, &block_exit_origins, block_index);
        for statement in &block.statements {
            record_callee_raw_pointer_arg_assignment(
                body,
                tcx,
                statement,
                &mut raw_pointer_arg_origins,
            );
        }
        let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &block.terminator().kind
        else {
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        };
        let Some((release_def_id, _)) = func.const_fn_def() else {
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        };
        let release_def_path = tcx.def_path_str(release_def_id);
        if record_callee_raw_pointer_shared_owner_deref_call_destination(
            body,
            tcx,
            &release_def_path,
            destination,
            args.first().map(|arg| &arg.node),
            &mut raw_pointer_arg_origins,
        ) {
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        }
        if record_callee_raw_pointer_non_null_as_ptr_call_destination(
            body,
            tcx,
            &release_def_path,
            destination,
            args.first().map(|arg| &arg.node),
            &mut raw_pointer_arg_origins,
        ) {
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        }
        if allow_capsule_get_pointer && pyo3_pycapsule_get_pointer_ffi_path(&release_def_path) {
            record_callee_raw_pointer_arg_call_destination(
                body,
                tcx,
                destination,
                args.first().map(|arg| &arg.node),
                &mut raw_pointer_arg_origins,
            );
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        }
        if let Some(arg_index) = raw_pointer_passthrough_arg_index(tcx, release_def_id) {
            record_callee_raw_pointer_arg_call_destination(
                body,
                tcx,
                destination,
                args.get(arg_index).map(|arg| &arg.node),
                &mut raw_pointer_arg_origins,
            );
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        }
        if raw_pointer_transfer_kind(&release_def_path) != Some(RawPointerTransferKind::FromRaw) {
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        }
        let arg_key = args.first().and_then(|arg| {
            callee_raw_pointer_arg_key_from_operand(body, tcx, &arg.node, &raw_pointer_arg_origins)
        })?;
        if arg_key.arg_index >= body.arg_count || !release_postdominates_entry(body, block_index) {
            return None;
        }
        if released_arg_key
            .replace(arg_key.clone())
            .is_some_and(|existing| existing != arg_key)
        {
            return None;
        }
        block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
    }
    released_arg_key
}

fn raw_pointer_release_arg_place_key_on_any_path<'tcx>(
    tcx: TyCtxt<'tcx>,
    callee_def_id: DefId,
    allow_capsule_get_pointer: bool,
) -> Option<RawPointerArgPlaceKey> {
    if !tcx.is_mir_available(callee_def_id) {
        return None;
    }
    let body = tcx.optimized_mir(callee_def_id);
    let mut released_arg_key = None;
    let predecessors = raw_pointer_basic_block_predecessors(body);
    let mut block_exit_origins = vec![None; body.basic_blocks.len()];
    for (block_index, block) in body.basic_blocks.iter().enumerate() {
        let mut raw_pointer_arg_origins =
            incoming_raw_pointer_arg_origins(&predecessors, &block_exit_origins, block_index);
        for statement in &block.statements {
            record_callee_raw_pointer_arg_assignment(
                body,
                tcx,
                statement,
                &mut raw_pointer_arg_origins,
            );
        }
        let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &block.terminator().kind
        else {
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        };
        let Some((release_def_id, _)) = func.const_fn_def() else {
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        };
        let release_def_path = tcx.def_path_str(release_def_id);
        if record_callee_raw_pointer_shared_owner_deref_call_destination(
            body,
            tcx,
            &release_def_path,
            destination,
            args.first().map(|arg| &arg.node),
            &mut raw_pointer_arg_origins,
        ) {
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        }
        if record_callee_raw_pointer_non_null_as_ptr_call_destination(
            body,
            tcx,
            &release_def_path,
            destination,
            args.first().map(|arg| &arg.node),
            &mut raw_pointer_arg_origins,
        ) {
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        }
        if allow_capsule_get_pointer && pyo3_pycapsule_get_pointer_ffi_path(&release_def_path) {
            record_callee_raw_pointer_arg_call_destination(
                body,
                tcx,
                destination,
                args.first().map(|arg| &arg.node),
                &mut raw_pointer_arg_origins,
            );
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        }
        if let Some(arg_index) = raw_pointer_passthrough_arg_index(tcx, release_def_id) {
            record_callee_raw_pointer_arg_call_destination(
                body,
                tcx,
                destination,
                args.get(arg_index).map(|arg| &arg.node),
                &mut raw_pointer_arg_origins,
            );
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        }
        if raw_pointer_transfer_kind(&release_def_path) != Some(RawPointerTransferKind::FromRaw) {
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        }
        let arg_key = args.first().and_then(|arg| {
            callee_raw_pointer_arg_key_from_operand(body, tcx, &arg.node, &raw_pointer_arg_origins)
        })?;
        if arg_key.arg_index >= body.arg_count {
            return None;
        }
        if released_arg_key
            .replace(arg_key.clone())
            .is_some_and(|existing| existing != arg_key)
        {
            return None;
        }
        block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
    }
    released_arg_key
}

fn raw_pointer_shared_owner_release_arg_place_key_on_any_path<'tcx>(
    tcx: TyCtxt<'tcx>,
    callee_def_id: DefId,
) -> Option<RawPointerArgPlaceKey> {
    if !tcx.is_mir_available(callee_def_id) {
        return None;
    }
    let body = tcx.optimized_mir(callee_def_id);
    let mut released_arg_key = None;
    let predecessors = raw_pointer_basic_block_predecessors(body);
    let mut block_exit_origins = vec![None; body.basic_blocks.len()];
    for (block_index, block) in body.basic_blocks.iter().enumerate() {
        let mut raw_pointer_arg_origins =
            incoming_raw_pointer_arg_origins(&predecessors, &block_exit_origins, block_index);
        for statement in &block.statements {
            record_callee_raw_pointer_arg_assignment(
                body,
                tcx,
                statement,
                &mut raw_pointer_arg_origins,
            );
        }
        let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &block.terminator().kind
        else {
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        };
        let Some((release_def_id, _)) = func.const_fn_def() else {
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        };
        let release_def_path = tcx.def_path_str(release_def_id);
        if record_callee_raw_pointer_shared_owner_deref_call_destination(
            body,
            tcx,
            &release_def_path,
            destination,
            args.first().map(|arg| &arg.node),
            &mut raw_pointer_arg_origins,
        ) {
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        }
        if raw_pointer_transfer_kind(&release_def_path) != Some(RawPointerTransferKind::FromRaw) {
            block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
            continue;
        }
        let arg_key = args.first().and_then(|arg| {
            callee_raw_pointer_arg_key_from_operand(body, tcx, &arg.node, &raw_pointer_arg_origins)
        })?;
        let arg_local = Local::new(arg_key.arg_index.checked_add(1)?);
        if arg_key.arg_index >= body.arg_count
            || !arg_key
                .projection
                .first()
                .is_some_and(|item| item == "deref")
            || shared_owner_family_token(&body.local_decls[arg_local].ty.to_string()).is_none()
        {
            return None;
        }
        if released_arg_key
            .replace(arg_key.clone())
            .is_some_and(|existing| existing != arg_key)
        {
            return None;
        }
        block_exit_origins[block_index] = Some(raw_pointer_arg_origins);
    }
    released_arg_key
}

fn raw_pointer_basic_block_predecessors(body: &Body<'_>) -> Vec<Vec<usize>> {
    let mut predecessors = vec![Vec::new(); body.basic_blocks.len()];
    for (block_index, block) in body.basic_blocks.iter().enumerate() {
        for successor in block.terminator().successors() {
            predecessors[successor.index()].push(block_index);
        }
    }
    predecessors
}

fn incoming_raw_pointer_arg_origins(
    predecessors: &[Vec<usize>],
    block_exit_origins: &[Option<BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>>],
    block_index: usize,
) -> BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>> {
    let Some(block_predecessors) = predecessors.get(block_index) else {
        return BTreeMap::new();
    };
    let mut incoming = block_predecessors
        .iter()
        .filter_map(|predecessor| block_exit_origins.get(*predecessor)?.as_ref());
    let Some(first) = incoming.next() else {
        return BTreeMap::new();
    };
    if incoming.all(|candidate| candidate == first) {
        first.clone()
    } else {
        BTreeMap::new()
    }
}

fn incoming_openssl_ex_data_slot_arg_origins(
    predecessors: &[Vec<usize>],
    block_exit_origins: &[Option<BTreeMap<RawPointerPlaceKey, Option<OpenSslExDataSlotArgKey>>>],
    block_index: usize,
) -> BTreeMap<RawPointerPlaceKey, Option<OpenSslExDataSlotArgKey>> {
    let Some(block_predecessors) = predecessors.get(block_index) else {
        return BTreeMap::new();
    };
    let mut incoming = block_predecessors
        .iter()
        .filter_map(|predecessor| block_exit_origins.get(*predecessor)?.as_ref());
    let Some(first) = incoming.next() else {
        return BTreeMap::new();
    };
    if incoming.all(|candidate| candidate == first) {
        first.clone()
    } else {
        BTreeMap::new()
    }
}

fn operand_raw_pointer_local(operand: &Operand<'_>) -> Option<Local> {
    let place = operand.place()?;
    place.projection.is_empty().then_some(place.local)
}

fn closure_def_path_from_aggregate_kind<'tcx>(
    tcx: TyCtxt<'tcx>,
    kind: &AggregateKind<'tcx>,
) -> Option<String> {
    closure_def_id_from_aggregate_kind(kind).map(|def_id| tcx.def_path_str(def_id))
}

fn closure_def_id_from_aggregate_kind<'tcx>(kind: &AggregateKind<'tcx>) -> Option<DefId> {
    match kind {
        AggregateKind::Closure(def_id, _) => Some(*def_id),
        _ => None,
    }
}

fn record_callee_raw_pointer_arg_call_destination<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    destination: &Place<'tcx>,
    source: Option<&Operand<'tcx>>,
    raw_pointer_arg_origins: &mut BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) {
    let Some(key) = raw_pointer_place_key(destination) else {
        return;
    };
    if !matches!(
        destination.ty(&body.local_decls, tcx).ty.kind(),
        ty::RawPtr(..)
    ) {
        return;
    }
    let user_data = source.and_then(|operand| {
        callee_raw_pointer_arg_key_from_operand(body, tcx, operand, raw_pointer_arg_origins)
    });
    update_optional_origin(raw_pointer_arg_origins, key, user_data);
}

fn record_openssl_ex_data_slot_arg_call_destination<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    destination: &Place<'tcx>,
    source: Option<&Operand<'tcx>>,
    slot_arg_origins: &mut BTreeMap<RawPointerPlaceKey, Option<OpenSslExDataSlotArgKey>>,
) {
    let Some(key) = raw_pointer_place_key(destination) else {
        return;
    };
    if !matches!(
        destination.ty(&body.local_decls, tcx).ty.kind(),
        ty::Int(_) | ty::Uint(_)
    ) {
        return;
    }
    let slot = source.and_then(|operand| {
        openssl_ex_data_slot_arg_key_from_operand(body, tcx, operand, slot_arg_origins)
    });
    update_optional_origin(slot_arg_origins, key, slot);
}

fn record_callee_raw_pointer_shared_owner_deref_call_destination<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    callee_def_path: &str,
    destination: &Place<'tcx>,
    source: Option<&Operand<'tcx>>,
    raw_pointer_arg_origins: &mut BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) -> bool {
    if !shared_owner_deref_call(callee_def_path) || !destination.projection.is_empty() {
        return false;
    }
    if !matches!(
        destination.ty(&body.local_decls, tcx).ty.kind(),
        ty::Ref(..)
    ) {
        return false;
    }
    let Some(source) = source else {
        return false;
    };
    let Some(source_place) = source.place() else {
        return false;
    };
    let Some(source_key) = raw_pointer_place_key(&source_place) else {
        return false;
    };
    let Some(destination_key) = raw_pointer_place_key(destination) else {
        return false;
    };
    let Some(mut origin) = raw_pointer_arg_origins.get(&source_key).cloned().flatten() else {
        return false;
    };
    origin.projection.push("deref".to_owned());
    update_optional_origin(raw_pointer_arg_origins, destination_key, Some(origin));
    true
}

fn record_callee_raw_pointer_non_null_as_ptr_call_destination<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    callee_def_path: &str,
    destination: &Place<'tcx>,
    source: Option<&Operand<'tcx>>,
    raw_pointer_arg_origins: &mut BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) -> bool {
    if !raw_pointer_non_null_as_ptr_call(callee_def_path) {
        return false;
    }
    let Some(destination_key) = raw_pointer_place_key(destination) else {
        return false;
    };
    if !matches!(
        destination.ty(&body.local_decls, tcx).ty.kind(),
        ty::RawPtr(..)
    ) {
        return false;
    }
    let Some(source) = source else {
        return false;
    };
    let Some(origin) = callee_raw_pointer_arg_key_from_non_null_operand(
        body,
        tcx,
        source,
        raw_pointer_arg_origins,
    ) else {
        return false;
    };
    update_optional_origin(raw_pointer_arg_origins, destination_key, Some(origin));
    true
}

fn record_callee_raw_pointer_arg_assignment<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    statement: &super::rustc_middle::mir::Statement<'tcx>,
    raw_pointer_arg_origins: &mut BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) {
    let StatementKind::Assign(assignment) = &statement.kind else {
        return;
    };
    let (place, rvalue) = &**assignment;
    let Some(key) = raw_pointer_place_key(place) else {
        return;
    };
    if record_callee_raw_pointer_deref_owner_borrow_assignment(
        body,
        place,
        rvalue,
        raw_pointer_arg_origins,
    ) {
        return;
    }
    if record_callee_raw_pointer_non_null_assignment(
        body,
        tcx,
        place,
        rvalue,
        raw_pointer_arg_origins,
    ) {
        return;
    }
    if !matches!(place.ty(&body.local_decls, tcx).ty.kind(), ty::RawPtr(..)) {
        return;
    }
    let user_data = match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            callee_raw_pointer_arg_key_from_operand(body, tcx, operand, raw_pointer_arg_origins)
        }
        _ => None,
    }
    .or_else(|| callee_raw_pointer_unique_owner_storage_arg_key_from_rvalue(body, rvalue));
    match raw_pointer_arg_origins.get_mut(&key) {
        Some(existing)
            if existing
                .as_ref()
                .is_some_and(|item| Some(item) != user_data.as_ref()) =>
        {
            *existing = None;
        }
        Some(_) => {}
        None => {
            raw_pointer_arg_origins.insert(key, user_data);
        }
    }
}

fn record_callee_raw_pointer_deref_owner_borrow_assignment<'tcx>(
    body: &Body<'tcx>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
    raw_pointer_arg_origins: &mut BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) -> bool {
    if !destination.projection.is_empty()
        || !matches!(body.local_decls[destination.local].ty.kind(), ty::Ref(..))
    {
        return false;
    }
    let Some(destination_key) = raw_pointer_place_key(destination) else {
        return false;
    };
    let origin = match rvalue {
        Rvalue::Ref(_, _, source_place)
            if source_place.projection.is_empty()
                && is_raw_pointer_deref_owner_ty(body.local_decls[source_place.local].ty) =>
        {
            source_place
                .local
                .index()
                .checked_sub(1)
                .filter(|arg_index| *arg_index < body.arg_count)
                .map(|arg_index| RawPointerArgPlaceKey {
                    arg_index,
                    projection: Vec::new(),
                })
        }
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => operand
            .place()
            .and_then(|source_place| raw_pointer_place_key(&source_place))
            .and_then(|source_key| raw_pointer_arg_origins.get(&source_key).cloned().flatten()),
        _ => None,
    };
    update_optional_origin(raw_pointer_arg_origins, destination_key, origin);
    true
}

fn record_callee_raw_pointer_non_null_assignment<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    destination: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
    raw_pointer_arg_origins: &mut BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) -> bool {
    if !non_null_storage_ty(destination.ty(&body.local_decls, tcx).ty) {
        return false;
    }
    let Some(mut destination_key) = raw_pointer_place_key(destination) else {
        return false;
    };
    destination_key.projection.push("field:0".to_owned());
    let origin = match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            callee_raw_pointer_arg_key_from_non_null_operand(
                body,
                tcx,
                operand,
                raw_pointer_arg_origins,
            )
        }
        _ => None,
    };
    update_optional_origin(raw_pointer_arg_origins, destination_key, origin);
    true
}

fn record_callee_raw_pointer_arg_assignment_with_aggregates<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    statement: &super::rustc_middle::mir::Statement<'tcx>,
    raw_pointer_arg_origins: &mut BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) {
    let StatementKind::Assign(assignment) = &statement.kind else {
        return;
    };
    let (place, rvalue) = &**assignment;
    let Some(key) = raw_pointer_place_key(place) else {
        return;
    };
    if matches!(place.ty(&body.local_decls, tcx).ty.kind(), ty::RawPtr(..)) {
        let user_data = match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                callee_raw_pointer_arg_key_from_operand(body, tcx, operand, raw_pointer_arg_origins)
            }
            _ => None,
        }
        .or_else(|| callee_raw_pointer_unique_owner_storage_arg_key_from_rvalue(body, rvalue));
        update_optional_origin(raw_pointer_arg_origins, key, user_data);
        return;
    }

    match rvalue {
        Rvalue::Aggregate(kind, operands) if raw_pointer_aggregate_kind_tracks_fields(kind) => {
            forget_callee_raw_pointer_arg_origin_prefix(raw_pointer_arg_origins, &key);
            for (field_index, operand) in operands.iter().enumerate() {
                for (field_key, user_data) in callee_raw_pointer_arg_aggregate_operand_origins(
                    body,
                    tcx,
                    &key,
                    field_index,
                    operand,
                    raw_pointer_arg_origins,
                ) {
                    update_optional_origin(raw_pointer_arg_origins, field_key, user_data);
                }
            }
        }
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            record_callee_raw_pointer_arg_place_alias(
                body,
                tcx,
                place,
                operand,
                raw_pointer_arg_origins,
            );
        }
        _ => {
            forget_callee_raw_pointer_arg_origin_prefix(raw_pointer_arg_origins, &key);
        }
    }
}

fn record_openssl_ex_data_slot_arg_assignment<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    statement: &super::rustc_middle::mir::Statement<'tcx>,
    slot_arg_origins: &mut BTreeMap<RawPointerPlaceKey, Option<OpenSslExDataSlotArgKey>>,
) {
    let StatementKind::Assign(assignment) = &statement.kind else {
        return;
    };
    let (place, rvalue) = &**assignment;
    let Some(destination_key) = raw_pointer_place_key(place) else {
        return;
    };
    if matches!(
        place.ty(&body.local_decls, tcx).ty.kind(),
        ty::Int(_) | ty::Uint(_)
    ) {
        let slot = match rvalue {
            Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
                openssl_ex_data_slot_arg_key_from_operand(body, tcx, operand, slot_arg_origins)
            }
            _ => None,
        };
        update_optional_origin(slot_arg_origins, destination_key, slot);
        return;
    }

    match rvalue {
        Rvalue::Aggregate(kind, operands) if raw_pointer_aggregate_kind_tracks_fields(kind) => {
            forget_openssl_ex_data_slot_arg_origin_prefix(slot_arg_origins, &destination_key);
            for (field_index, operand) in operands.iter().enumerate() {
                for (field_key, slot) in openssl_ex_data_slot_arg_aggregate_operand_origins(
                    body,
                    tcx,
                    &destination_key,
                    field_index,
                    operand,
                    slot_arg_origins,
                ) {
                    update_optional_origin(slot_arg_origins, field_key, slot);
                }
            }
        }
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => {
            record_openssl_ex_data_slot_arg_place_alias(place, operand, slot_arg_origins);
        }
        _ => {
            forget_openssl_ex_data_slot_arg_origin_prefix(slot_arg_origins, &destination_key);
        }
    }
}

fn openssl_ex_data_slot_arg_aggregate_operand_origins<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    destination_key: &RawPointerPlaceKey,
    field_index: usize,
    operand: &Operand<'tcx>,
    slot_arg_origins: &BTreeMap<RawPointerPlaceKey, Option<OpenSslExDataSlotArgKey>>,
) -> Vec<(RawPointerPlaceKey, Option<OpenSslExDataSlotArgKey>)> {
    let mut field_prefix = destination_key.clone();
    field_prefix.projection.push(format!("field:{field_index}"));
    if matches!(
        operand.ty(&body.local_decls, tcx).kind(),
        ty::Int(_) | ty::Uint(_)
    ) {
        return vec![(
            field_prefix,
            openssl_ex_data_slot_arg_key_from_operand(body, tcx, operand, slot_arg_origins),
        )];
    }

    let Some(source_place) = operand.place() else {
        return Vec::new();
    };
    let Some(source_key) = raw_pointer_place_key(&source_place) else {
        return Vec::new();
    };
    slot_arg_origins
        .iter()
        .filter_map(|(key, value)| {
            if key.local != source_key.local || !key.projection.starts_with(&source_key.projection)
            {
                return None;
            }
            let mut projection = field_prefix.projection.clone();
            projection.extend_from_slice(&key.projection[source_key.projection.len()..]);
            Some((
                RawPointerPlaceKey {
                    local: field_prefix.local,
                    projection,
                },
                value.clone(),
            ))
        })
        .collect()
}

fn record_openssl_ex_data_slot_arg_place_alias(
    destination: &Place<'_>,
    source: &Operand<'_>,
    slot_arg_origins: &mut BTreeMap<RawPointerPlaceKey, Option<OpenSslExDataSlotArgKey>>,
) {
    let Some(destination_key) = raw_pointer_place_key(destination) else {
        return;
    };
    forget_openssl_ex_data_slot_arg_origin_prefix(slot_arg_origins, &destination_key);
    let Some(source_place) = source.place() else {
        return;
    };
    let Some(source_key) = raw_pointer_place_key(&source_place) else {
        return;
    };
    let aliases = slot_arg_origins
        .iter()
        .filter_map(|(key, value)| {
            if key.local != source_key.local || !key.projection.starts_with(&source_key.projection)
            {
                return None;
            }
            let mut projection = destination_key.projection.clone();
            projection.extend_from_slice(&key.projection[source_key.projection.len()..]);
            Some((
                RawPointerPlaceKey {
                    local: destination_key.local,
                    projection,
                },
                value.clone(),
            ))
        })
        .collect::<Vec<_>>();
    for (key, value) in aliases {
        update_optional_origin(slot_arg_origins, key, value);
    }
}

fn forget_openssl_ex_data_slot_arg_origin_prefix(
    slot_arg_origins: &mut BTreeMap<RawPointerPlaceKey, Option<OpenSslExDataSlotArgKey>>,
    prefix: &RawPointerPlaceKey,
) {
    slot_arg_origins.retain(|key, _| {
        key.local != prefix.local || !key.projection.starts_with(&prefix.projection)
    });
}

fn record_callee_raw_pointer_arg_place_alias<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    destination: &Place<'tcx>,
    source: &Operand<'tcx>,
    raw_pointer_arg_origins: &mut BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) {
    let Some(destination_key) = raw_pointer_place_key(destination) else {
        return;
    };
    forget_callee_raw_pointer_arg_origin_prefix(raw_pointer_arg_origins, &destination_key);
    let Some(source_place) = source.place() else {
        return;
    };
    if matches!(
        source_place.ty(&body.local_decls, tcx).ty.kind(),
        ty::RawPtr(..)
    ) {
        return;
    }
    let Some(source_key) = raw_pointer_place_key(&source_place) else {
        return;
    };
    let aliases = raw_pointer_arg_origins
        .iter()
        .filter_map(|(key, value)| {
            if key.local != source_key.local || !key.projection.starts_with(&source_key.projection)
            {
                return None;
            }
            let mut projection = destination_key.projection.clone();
            projection.extend_from_slice(&key.projection[source_key.projection.len()..]);
            Some((
                RawPointerPlaceKey {
                    local: destination_key.local,
                    projection,
                },
                value.clone(),
            ))
        })
        .collect::<Vec<_>>();
    for (key, value) in aliases {
        update_optional_origin(raw_pointer_arg_origins, key, value);
    }
}

fn callee_raw_pointer_arg_aggregate_operand_origins<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    destination_key: &RawPointerPlaceKey,
    field_index: usize,
    operand: &Operand<'tcx>,
    raw_pointer_arg_origins: &BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) -> Vec<(RawPointerPlaceKey, Option<RawPointerArgPlaceKey>)> {
    let mut field_prefix = destination_key.clone();
    field_prefix.projection.push(format!("field:{field_index}"));
    if matches!(operand.ty(&body.local_decls, tcx).kind(), ty::RawPtr(..)) {
        return vec![(
            field_prefix,
            callee_raw_pointer_arg_key_from_operand(body, tcx, operand, raw_pointer_arg_origins),
        )];
    }

    let Some(source_place) = operand.place() else {
        return Vec::new();
    };
    let Some(source_key) = raw_pointer_place_key(&source_place) else {
        return Vec::new();
    };
    raw_pointer_arg_origins
        .iter()
        .filter_map(|(key, value)| {
            if key.local != source_key.local || !key.projection.starts_with(&source_key.projection)
            {
                return None;
            }
            let mut projection = field_prefix.projection.clone();
            projection.extend_from_slice(&key.projection[source_key.projection.len()..]);
            Some((
                RawPointerPlaceKey {
                    local: field_prefix.local,
                    projection,
                },
                value.clone(),
            ))
        })
        .collect()
}

fn forget_callee_raw_pointer_arg_origin_prefix(
    raw_pointer_arg_origins: &mut BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
    prefix: &RawPointerPlaceKey,
) {
    raw_pointer_arg_origins.retain(|key, _| {
        key.local != prefix.local || !key.projection.starts_with(&prefix.projection)
    });
}

fn callee_raw_pointer_arg_key_from_operand<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    operand: &Operand<'tcx>,
    raw_pointer_arg_origins: &BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) -> Option<RawPointerArgPlaceKey> {
    let place = operand.place()?;
    if !matches!(place.ty(&body.local_decls, tcx).ty.kind(), ty::RawPtr(..)) {
        return None;
    }
    callee_raw_pointer_arg_key_from_place(body, &place).or_else(|| {
        raw_pointer_place_key(&place)
            .and_then(|key| raw_pointer_arg_origins.get(&key).cloned().flatten())
            .or_else(|| {
                callee_raw_pointer_arg_key_from_storage_pointer_place(
                    &place,
                    raw_pointer_arg_origins,
                )
            })
    })
}

fn openssl_ex_data_slot_arg_key_from_operand<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    operand: &Operand<'tcx>,
    slot_arg_origins: &BTreeMap<RawPointerPlaceKey, Option<OpenSslExDataSlotArgKey>>,
) -> Option<OpenSslExDataSlotArgKey> {
    let place = operand.place()?;
    if !matches!(
        place.ty(&body.local_decls, tcx).ty.kind(),
        ty::Int(_) | ty::Uint(_)
    ) {
        return None;
    }
    openssl_ex_data_slot_arg_key_from_place(body, &place).or_else(|| {
        raw_pointer_place_key(&place).and_then(|key| slot_arg_origins.get(&key).cloned().flatten())
    })
}

fn openssl_ex_data_slot_arg_key_from_place(
    body: &Body<'_>,
    place: &Place<'_>,
) -> Option<OpenSslExDataSlotArgKey> {
    let arg_index = place.local.index().checked_sub(1)?;
    if arg_index >= body.arg_count {
        return None;
    }
    Some(OpenSslExDataSlotArgKey {
        arg_index,
        projection: raw_pointer_arg_projection_key(body, place)?,
    })
}

fn callee_raw_pointer_arg_key_from_non_null_operand<'tcx>(
    body: &Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    operand: &Operand<'tcx>,
    raw_pointer_arg_origins: &BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) -> Option<RawPointerArgPlaceKey> {
    if !non_null_storage_ty(operand.ty(&body.local_decls, tcx)) {
        return None;
    }
    let place = operand.place()?;
    if let Some(mut arg_key) = callee_raw_pointer_arg_key_from_place(body, &place) {
        arg_key.projection.push("field:0".to_owned());
        return Some(arg_key);
    }
    let source_key = raw_pointer_place_key(&place)?;
    let mut found = None;
    for (key, origin) in raw_pointer_arg_origins {
        if key.local != source_key.local || !key.projection.starts_with(&source_key.projection) {
            continue;
        }
        let Some(origin) = origin.clone() else {
            return None;
        };
        if let Some(existing) = &found
            && existing != &origin
        {
            return None;
        }
        found = Some(origin);
    }
    found
}

fn callee_raw_pointer_arg_key_from_storage_pointer_place(
    place: &Place<'_>,
    raw_pointer_arg_origins: &BTreeMap<RawPointerPlaceKey, Option<RawPointerArgPlaceKey>>,
) -> Option<RawPointerArgPlaceKey> {
    let mut projection = Vec::new();
    let mut elements = place.projection.iter();
    if !matches!(elements.next(), Some(ProjectionElem::Deref)) {
        return None;
    }
    for elem in elements {
        match elem {
            ProjectionElem::Field(field, _) => projection.push(format!("field:{}", field.index())),
            _ => return None,
        }
    }
    let base_key = RawPointerPlaceKey {
        local: place.local.index(),
        projection: Vec::new(),
    };
    let mut origin = raw_pointer_arg_origins.get(&base_key).cloned().flatten()?;
    origin.projection.extend(projection);
    Some(origin)
}

fn callee_raw_pointer_unique_owner_storage_arg_key_from_rvalue(
    body: &Body<'_>,
    rvalue: &Rvalue<'_>,
) -> Option<RawPointerArgPlaceKey> {
    let operand = match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => operand,
        _ => return None,
    };
    let place = operand.place()?;
    let arg_index = place.local.index().checked_sub(1)?;
    if arg_index >= body.arg_count || !is_box_storage_owner_ty(body.local_decls[place.local].ty) {
        return None;
    }
    let mut field_count = 0usize;
    for elem in place.projection {
        match elem {
            ProjectionElem::Field(field, _) if field.index() == 0 => {
                field_count += 1;
            }
            _ => return None,
        }
    }
    (field_count >= 2).then_some(RawPointerArgPlaceKey {
        arg_index,
        projection: vec!["deref".to_owned()],
    })
}

fn callee_raw_pointer_arg_key_from_place(
    body: &Body<'_>,
    place: &Place<'_>,
) -> Option<RawPointerArgPlaceKey> {
    let arg_index = place.local.index().checked_sub(1)?;
    if arg_index >= body.arg_count {
        return None;
    }
    Some(RawPointerArgPlaceKey {
        arg_index,
        projection: raw_pointer_arg_projection_key(body, place)?,
    })
}

fn raw_pointer_place_key(place: &Place<'_>) -> Option<RawPointerPlaceKey> {
    Some(RawPointerPlaceKey {
        local: place.local.index(),
        projection: raw_pointer_projection_key(place)?,
    })
}

fn raw_pointer_option_some_field_key_from_place(
    body: &Body<'_>,
    place: &Place<'_>,
) -> Option<RawPointerPlaceKey> {
    if place.projection.len() != 2 {
        return None;
    }
    if !body.local_decls[place.local]
        .ty
        .to_string()
        .to_ascii_lowercase()
        .contains("option<")
    {
        return None;
    }
    match (place.projection[0], place.projection[1]) {
        (ProjectionElem::Downcast(..), ProjectionElem::Field(field, _)) if field.index() == 0 => {
            Some(RawPointerPlaceKey {
                local: place.local.index(),
                projection: vec!["field:0".to_owned()],
            })
        }
        _ => None,
    }
}

fn raw_pointer_result_ok_field_key_from_place(
    body: &Body<'_>,
    place: &Place<'_>,
) -> Option<RawPointerPlaceKey> {
    if place.projection.len() != 2 {
        return None;
    }
    if !body.local_decls[place.local]
        .ty
        .to_string()
        .to_ascii_lowercase()
        .contains("result<")
    {
        return None;
    }
    match (place.projection[0], place.projection[1]) {
        (ProjectionElem::Downcast(Some(variant_name), _), ProjectionElem::Field(field, _))
            if variant_name.as_str() == "Ok" && field.index() == 0 =>
        {
            Some(RawPointerPlaceKey {
                local: place.local.index(),
                projection: vec!["field:0".to_owned()],
            })
        }
        _ => None,
    }
}

fn raw_pointer_unique_owner_field_key_from_place(
    body: &Body<'_>,
    place: &Place<'_>,
) -> Option<RawPointerPlaceKey> {
    if place.projection.is_empty()
        || !is_raw_pointer_deref_owner_ty(body.local_decls[place.local].ty)
    {
        return None;
    }
    let mut projection = Vec::new();
    let mut followed_unique_owner_deref = false;
    for elem in place.projection {
        match elem {
            ProjectionElem::Deref if !followed_unique_owner_deref => {
                followed_unique_owner_deref = true;
                projection.push("deref".to_owned());
            }
            ProjectionElem::Field(field, _) if followed_unique_owner_deref => {
                projection.push(format!("field:{}", field.index()));
            }
            _ => return None,
        }
    }
    followed_unique_owner_deref.then_some(RawPointerPlaceKey {
        local: place.local.index(),
        projection,
    })
}

fn raw_pointer_unique_owner_storage_pointer_key_from_place(
    body: &Body<'_>,
    place: &Place<'_>,
) -> Option<RawPointerPlaceKey> {
    if !is_box_storage_owner_ty(body.local_decls[place.local].ty) {
        return None;
    }
    let mut field_count = 0usize;
    for elem in place.projection {
        match elem {
            ProjectionElem::Field(field, _) if field.index() == 0 => {
                field_count += 1;
            }
            _ => return None,
        }
    }
    (field_count >= 2).then_some(RawPointerPlaceKey {
        local: place.local.index(),
        projection: vec!["deref".to_owned()],
    })
}

fn raw_pointer_storage_pointer_field_key_from_place(
    body: &Body<'_>,
    place: &Place<'_>,
) -> Option<RawPointerPlaceKey> {
    if place.projection.is_empty()
        || !matches!(body.local_decls[place.local].ty.kind(), ty::RawPtr(..))
    {
        return None;
    }
    let mut projection = Vec::new();
    let mut elements = place.projection.iter();
    if !matches!(elements.next(), Some(ProjectionElem::Deref)) {
        return None;
    }
    for elem in elements {
        match elem {
            ProjectionElem::Field(field, _) => projection.push(format!("field:{}", field.index())),
            _ => return None,
        }
    }
    (!projection.is_empty()).then_some(RawPointerPlaceKey {
        local: place.local.index(),
        projection,
    })
}

fn fn_pointer_place_key(body: &Body<'_>, place: &Place<'_>) -> Option<RawPointerPlaceKey> {
    Some(RawPointerPlaceKey {
        local: place.local.index(),
        projection: fn_pointer_projection_key(body, place, false)?,
    })
}

fn option_fn_pointer_key_from_unwrapped_place(
    body: &Body<'_>,
    place: &Place<'_>,
) -> Option<RawPointerPlaceKey> {
    Some(RawPointerPlaceKey {
        local: place.local.index(),
        projection: fn_pointer_projection_key(body, place, true)?,
    })
}

fn is_receiver_field_key(body: &Body<'_>, key: &RawPointerPlaceKey) -> bool {
    key.local == 1
        && body.arg_count >= 1
        && !key.projection.is_empty()
        && matches!(body.local_decls[Local::new(1)].ty.kind(), ty::Ref(..))
}

fn mir_order_key(location: Location) -> MirOrderKey {
    MirOrderKey {
        basic_block: location.block.index(),
        statement_index: location.statement_index,
    }
}

fn mir_order_graph(body: &Body<'_>) -> MirOrderGraph {
    let mut reachable_blocks = BTreeMap::<usize, BTreeSet<usize>>::new();
    for block_index in 0..body.basic_blocks.len() {
        let mut seen = BTreeSet::<usize>::new();
        let mut stack = body.basic_blocks[BasicBlock::new(block_index)]
            .terminator()
            .successors()
            .map(|successor| successor.index())
            .collect::<Vec<_>>();
        while let Some(successor) = stack.pop() {
            if !seen.insert(successor) {
                continue;
            }
            stack.extend(
                body.basic_blocks[BasicBlock::new(successor)]
                    .terminator()
                    .successors()
                    .map(|next| next.index()),
            );
        }
        reachable_blocks.insert(block_index, seen);
    }
    MirOrderGraph { reachable_blocks }
}

fn mir_order_before(
    mir_order_graphs: &BTreeMap<String, MirOrderGraph>,
    owner_def_path: &str,
    left: MirOrderKey,
    right: MirOrderKey,
) -> bool {
    if left.basic_block == right.basic_block {
        return left.statement_index < right.statement_index;
    }
    let Some(graph) = mir_order_graphs.get(owner_def_path) else {
        return left < right;
    };
    let left_reaches_right = graph
        .reachable_blocks
        .get(&left.basic_block)
        .is_some_and(|reachable| reachable.contains(&right.basic_block));
    if !left_reaches_right {
        return false;
    }
    let right_reaches_left = graph
        .reachable_blocks
        .get(&right.basic_block)
        .is_some_and(|reachable| reachable.contains(&left.basic_block));
    !right_reaches_left
}

fn infer_returned_borrow_invalidation_orders(
    persisted_borrows: &[PersistedReturnedBorrowObservation],
    invalidations: &[ReturnedBorrowInvalidationCall],
    storage_uses: &[ReturnedBorrowStorageUse],
    storage_mutation_barriers: &[ReturnedBorrowStorageMutationBarrier],
    local_method_calls: &[LocalMethodCall],
    mir_order_graphs: &BTreeMap<String, MirOrderGraph>,
) -> Vec<ReturnedBorrowInvalidationOrderObservation> {
    let mut observations = Vec::new();
    for persisted in persisted_borrows {
        for use_site in storage_uses.iter().filter(|use_site| {
            returned_borrow_same_order_scope(
                &persisted.owner_def_path,
                returned_borrow_order_owner(&use_site.owner_def_path),
            ) && returned_borrow_storage_matches(persisted, use_site)
        }) {
            let use_order_owner = returned_borrow_order_owner(&use_site.owner_def_path);
            let mut invalidation_candidates = invalidations
                .iter()
                .filter(|invalidation| {
                    invalidation.owner_def_path == use_order_owner
                        && invalidation.source_path == use_site.source_path
                        && (use_order_owner != use_site.owner_def_path
                            || mir_order_before(
                                mir_order_graphs,
                                use_order_owner,
                                invalidation.order_key,
                                use_site.order_key,
                            ))
                })
                .collect::<Vec<_>>();
            if invalidation_candidates.is_empty() {
                continue;
            }
            invalidation_candidates.sort_by_key(|invalidation| invalidation.order_key);
            for invalidation in invalidation_candidates {
                if returned_borrow_storage_blocked_by_mutation(
                    persisted,
                    use_site,
                    &use_order_owner,
                    storage_mutation_barriers,
                    local_method_calls,
                    mir_order_graphs,
                ) {
                    continue;
                }

                if persisted.owner_def_path == use_order_owner
                    && persisted.source_path == use_site.source_path
                    && mir_order_before(
                        mir_order_graphs,
                        use_order_owner,
                        persisted_returned_borrow_order_key(persisted),
                        invalidation.order_key,
                    )
                    && mir_order_before(
                        mir_order_graphs,
                        use_order_owner,
                        invalidation.order_key,
                        use_site.order_key,
                    )
                {
                    observations.push(returned_borrow_invalidation_order_observation(
                        persisted,
                        invalidation,
                        use_site,
                        ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse,
                    ));
                    break;
                }

                if returned_borrow_constructor_persistence(persisted)
                    && !local_method_calls.iter().any(|call| {
                        call.owner_def_path == use_order_owner
                            && call.callee_def_path == persisted.owner_def_path
                    })
                {
                    observations.push(returned_borrow_invalidation_order_observation(
                        persisted,
                        invalidation,
                        use_site,
                        ReturnedBorrowInvalidationOrdering::PersistenceBeforeInvalidationUse,
                    ));
                    break;
                }

                if local_method_calls.iter().any(|call| {
                    call.owner_def_path == use_order_owner
                        && call.source_path == use_site.source_path
                        && returned_borrow_same_method_effect(
                            &call.callee_def_path,
                            &persisted.owner_def_path,
                        )
                        && mir_order_before(
                            mir_order_graphs,
                            use_order_owner,
                            invalidation.order_key,
                            call.order_key,
                        )
                        && (use_order_owner != use_site.owner_def_path
                            || mir_order_before(
                                mir_order_graphs,
                                use_order_owner,
                                call.order_key,
                                use_site.order_key,
                            ))
                }) {
                    observations.push(returned_borrow_invalidation_order_observation(
                        persisted,
                        invalidation,
                        use_site,
                        ReturnedBorrowInvalidationOrdering::InvalidationBeforePersistenceUse,
                    ));
                    break;
                }
            }
        }
    }
    observations.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
            .then(left.api_id.cmp(&right.api_id))
            .then(left.invalidation_api_id.cmp(&right.invalidation_api_id))
    });
    observations.dedup_by(|left, right| {
        left.owner_def_path == right.owner_def_path
            && left.mir_location == right.mir_location
            && left.api_id == right.api_id
            && left.invalidation_api_id == right.invalidation_api_id
            && left.ordering == right.ordering
    });
    observations
}

fn object_binding_gaps_from_storage_mutation_barriers(
    storage_mutation_barriers: &[ReturnedBorrowStorageMutationBarrier],
) -> Vec<ObjectBindingGapObservation> {
    let mut gaps = Vec::new();
    for barrier in storage_mutation_barriers {
        for storage_key in &barrier.storage_keys {
            gaps.push(ObjectBindingGapObservation {
                owner_def_path: barrier.owner_def_path.clone(),
                source_path: barrier.source_path.clone(),
                span: barrier.span.clone(),
                mir_location: format!(
                    "{}:object_binding_gap:{}",
                    barrier.mir_location,
                    short_digest(storage_key)
                ),
                api_id: barrier.owner_def_path.clone(),
                gap_kind: ObjectBindingGapKind::MutationBarrier,
                field_path: returned_borrow_object_flow_field_path_from_storage_key(storage_key),
                container_type_name: None,
                adapter: Some("returned_borrow_storage_mutation".to_owned()),
            });
        }
        for storage_prefix in &barrier.storage_prefixes {
            gaps.push(ObjectBindingGapObservation {
                owner_def_path: barrier.owner_def_path.clone(),
                source_path: barrier.source_path.clone(),
                span: barrier.span.clone(),
                mir_location: format!(
                    "{}:object_binding_gap_prefix:{}",
                    barrier.mir_location,
                    short_digest(storage_prefix)
                ),
                api_id: barrier.owner_def_path.clone(),
                gap_kind: ObjectBindingGapKind::MutationBarrier,
                field_path: Some(storage_prefix.clone()),
                container_type_name: None,
                adapter: Some(format!(
                    "returned_borrow_storage_prefix_mutation:{}",
                    short_digest(storage_prefix)
                )),
            });
        }
    }
    gaps.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
            .then(left.field_path.cmp(&right.field_path))
            .then(left.adapter.cmp(&right.adapter))
    });
    gaps.dedup();
    gaps
}

fn persisted_returned_borrow_order_key(
    persisted: &PersistedReturnedBorrowObservation,
) -> MirOrderKey {
    MirOrderKey {
        basic_block: persisted.mir_order_block,
        statement_index: persisted.mir_statement_index,
    }
}

fn infer_object_flows(observations: &MirSiteObservations) -> Vec<ObjectFlowObservation> {
    let mut flows = Vec::new();
    for registration in observations.registrations.iter().filter(|registration| {
        registration.role == bw_model::RegistrationRole::Register
            && registration.user_data.is_some()
    }) {
        let Some(user_data) = registration.user_data.as_ref() else {
            continue;
        };
        for transfer in observations
            .raw_pointer_transfers
            .iter()
            .filter(|transfer| &transfer.user_data == user_data)
        {
            match transfer.kind {
                RawPointerTransferKind::IntoRaw => {
                    flows.push(object_flow_observation(
                        &transfer.owner_def_path,
                        &transfer.source_path,
                        &transfer.span,
                        &format!("{}:into_raw_return", transfer.mir_location),
                        &registration.api_id,
                        ObjectFlowEndpointObservation::RawPointerTransferSite(transfer.clone()),
                        ObjectFlowObjectKind::StaticSite,
                        ObjectFlowEndpointObservation::UserData(user_data.clone()),
                        ObjectFlowObjectKind::UserData,
                        ObjectFlowKind::ReturnValue,
                        None,
                        None,
                    ));
                }
                RawPointerTransferKind::FromRaw | RawPointerTransferKind::FromRawParts => {
                    flows.push(object_flow_observation(
                        &transfer.owner_def_path,
                        &transfer.source_path,
                        &transfer.span,
                        &format!("{}:from_raw_argument", transfer.mir_location),
                        &registration.api_id,
                        ObjectFlowEndpointObservation::UserData(user_data.clone()),
                        ObjectFlowObjectKind::UserData,
                        ObjectFlowEndpointObservation::RawPointerTransferSite(transfer.clone()),
                        ObjectFlowObjectKind::StaticSite,
                        ObjectFlowKind::Argument,
                        None,
                        None,
                    ));
                }
            }
        }
        flows.push(object_flow_observation(
            &registration.owner_def_path,
            &registration.source_path,
            &registration.span,
            &format!("{}:registration_argument", registration.mir_location),
            &registration.api_id,
            ObjectFlowEndpointObservation::UserData(user_data.clone()),
            ObjectFlowObjectKind::UserData,
            ObjectFlowEndpointObservation::RegistrationSite(registration.clone()),
            ObjectFlowObjectKind::StaticSite,
            ObjectFlowKind::Argument,
            None,
            None,
        ));
    }

    for proof in &observations.release_path_proofs {
        let Some(registration_user_data) = proof.registration.user_data.as_ref() else {
            continue;
        };
        if registration_user_data != &proof.release.user_data {
            continue;
        }
        flows.push(object_flow_observation(
            &proof.registration.owner_def_path,
            &proof.registration.source_path,
            &proof.registration.span,
            &format!(
                "{}:release_path_registration_field_store",
                proof.registration.mir_location
            ),
            &proof.registration.api_id,
            ObjectFlowEndpointObservation::UserData(registration_user_data.clone()),
            ObjectFlowObjectKind::UserData,
            ObjectFlowEndpointObservation::RegistrationSite(proof.registration.clone()),
            ObjectFlowObjectKind::StaticSite,
            ObjectFlowKind::FieldStore,
            Some("registration:user_data".to_owned()),
            None,
        ));
        flows.push(object_flow_observation(
            &proof.owner_def_path,
            &proof.source_path,
            &proof.span,
            &format!("{}:release_path_field_load", proof.mir_location),
            &proof.registration.api_id,
            ObjectFlowEndpointObservation::RegistrationSite(proof.registration.clone()),
            ObjectFlowObjectKind::StaticSite,
            ObjectFlowEndpointObservation::RawPointerTransferSite(proof.release.clone()),
            ObjectFlowObjectKind::StaticSite,
            ObjectFlowKind::FieldLoad,
            Some("registration:user_data".to_owned()),
            None,
        ));
    }

    for persisted in &observations.persisted_returned_borrows {
        let flow_kind = returned_borrow_persisted_store_flow_kind(persisted);
        let flow_label = returned_borrow_persisted_store_flow_label(flow_kind);
        flows.push(object_flow_observation(
            &persisted.owner_def_path,
            &persisted.source_path,
            &persisted.span,
            &format!("{}:{flow_label}", persisted.mir_location),
            &persisted.api_id,
            ObjectFlowEndpointObservation::ReturnedBorrow(persisted.clone()),
            ObjectFlowObjectKind::ReturnedRef,
            ObjectFlowEndpointObservation::Storage(persisted.clone()),
            ObjectFlowObjectKind::Storage,
            flow_kind,
            returned_borrow_persisted_object_flow_field_path(persisted),
            Some(persisted.storage_type_name.clone()),
        ));
    }

    for order in &observations.returned_borrow_invalidation_orders {
        let flow_kind = returned_borrow_persisted_load_flow_kind(&order.persisted);
        let flow_label = returned_borrow_persisted_load_flow_label(flow_kind);
        flows.push(object_flow_observation(
            &order.owner_def_path,
            &order.source_path,
            &order.span,
            &format!("{}:{flow_label}", order.mir_location),
            &order.api_id,
            ObjectFlowEndpointObservation::Storage(order.persisted.clone()),
            ObjectFlowObjectKind::Storage,
            ObjectFlowEndpointObservation::ReturnedBorrowUse(order.clone()),
            ObjectFlowObjectKind::StaticSite,
            flow_kind,
            returned_borrow_persisted_object_flow_field_path(&order.persisted),
            Some(order.persisted.storage_type_name.clone()),
        ));
    }

    flows.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
            .then(left.api_id.cmp(&right.api_id))
    });
    flows.dedup();
    flows
}

#[allow(clippy::too_many_arguments)]
fn object_flow_observation(
    owner_def_path: &str,
    source_path: &std::path::Path,
    span: &str,
    mir_location: &str,
    api_id: &str,
    from: ObjectFlowEndpointObservation,
    from_object_kind: ObjectFlowObjectKind,
    to: ObjectFlowEndpointObservation,
    to_object_kind: ObjectFlowObjectKind,
    flow_kind: ObjectFlowKind,
    field_path: Option<String>,
    container_type_name: Option<String>,
) -> ObjectFlowObservation {
    ObjectFlowObservation {
        owner_def_path: owner_def_path.to_owned(),
        source_path: source_path.to_path_buf(),
        span: span.to_owned(),
        mir_location: mir_location.to_owned(),
        api_id: api_id.to_owned(),
        from,
        from_object_kind,
        to,
        to_object_kind,
        flow_kind,
        field_path,
        container_type_name,
    }
}

fn returned_borrow_persisted_store_flow_kind(
    persisted: &PersistedReturnedBorrowObservation,
) -> ObjectFlowKind {
    if returned_borrow_persisted_storage_is_local_wrapper_field(persisted) {
        ObjectFlowKind::WrapperMove
    } else if returned_borrow_persisted_storage_is_exact_field(persisted) {
        ObjectFlowKind::FieldStore
    } else {
        ObjectFlowKind::CollectionStore
    }
}

fn returned_borrow_persisted_load_flow_kind(
    persisted: &PersistedReturnedBorrowObservation,
) -> ObjectFlowKind {
    if returned_borrow_persisted_storage_is_local_wrapper_field(persisted) {
        ObjectFlowKind::WrapperDestructure
    } else if returned_borrow_persisted_storage_is_exact_field(persisted) {
        ObjectFlowKind::FieldLoad
    } else {
        ObjectFlowKind::CollectionLoad
    }
}

fn returned_borrow_persisted_store_flow_label(flow_kind: ObjectFlowKind) -> &'static str {
    match flow_kind {
        ObjectFlowKind::FieldStore => "returned_ref_field_store",
        ObjectFlowKind::WrapperMove => "returned_ref_wrapper_move",
        _ => "returned_ref_collection_store",
    }
}

fn returned_borrow_persisted_load_flow_label(flow_kind: ObjectFlowKind) -> &'static str {
    match flow_kind {
        ObjectFlowKind::FieldLoad => "returned_ref_field_load",
        ObjectFlowKind::WrapperDestructure => "returned_ref_wrapper_destructure",
        _ => "returned_ref_collection_load",
    }
}

fn returned_borrow_persisted_storage_is_local_wrapper_field(
    persisted: &PersistedReturnedBorrowObservation,
) -> bool {
    persisted
        .storage_key
        .as_deref()
        .is_some_and(|storage_key| storage_key.starts_with("local_wrapper_field:"))
}

fn returned_borrow_persisted_object_flow_field_path(
    persisted: &PersistedReturnedBorrowObservation,
) -> Option<String> {
    persisted
        .storage_key
        .as_deref()
        .and_then(returned_borrow_object_flow_field_path_from_storage_key)
}

fn returned_borrow_object_flow_field_path_from_storage_key(storage_key: &str) -> Option<String> {
    local_wrapper_field_path_from_storage_key(storage_key)
        .or_else(|| (!storage_key.is_empty()).then(|| storage_key.to_owned()))
}

fn returned_borrow_persisted_storage_is_exact_field(
    persisted: &PersistedReturnedBorrowObservation,
) -> bool {
    persisted
        .storage_key
        .as_deref()
        .is_some_and(|storage_key| storage_key.starts_with("field:"))
        && !returned_borrow_collection_storage_type(&persisted.storage_type_name)
}

fn object_flow_endpoint_source_path(endpoint: &ObjectFlowEndpointObservation) -> &std::path::Path {
    match endpoint {
        ObjectFlowEndpointObservation::UserData(user_data) => &user_data.source_path,
        ObjectFlowEndpointObservation::CallbackSite(callback) => &callback.source_path,
        ObjectFlowEndpointObservation::RegistrationSite(registration) => &registration.source_path,
        ObjectFlowEndpointObservation::RawPointerTransferSite(transfer) => &transfer.source_path,
        ObjectFlowEndpointObservation::ReturnedBorrow(persisted)
        | ObjectFlowEndpointObservation::Storage(persisted) => &persisted.source_path,
        ObjectFlowEndpointObservation::ReturnedBorrowUse(order) => &order.source_path,
        ObjectFlowEndpointObservation::StaticSite(site) => &site.source_path,
    }
}

fn object_flow_endpoint_span(endpoint: &ObjectFlowEndpointObservation) -> &str {
    match endpoint {
        ObjectFlowEndpointObservation::UserData(user_data) => &user_data.span,
        ObjectFlowEndpointObservation::CallbackSite(callback) => &callback.span,
        ObjectFlowEndpointObservation::RegistrationSite(registration) => &registration.span,
        ObjectFlowEndpointObservation::RawPointerTransferSite(transfer) => &transfer.span,
        ObjectFlowEndpointObservation::ReturnedBorrow(persisted)
        | ObjectFlowEndpointObservation::Storage(persisted) => &persisted.span,
        ObjectFlowEndpointObservation::ReturnedBorrowUse(order) => &order.span,
        ObjectFlowEndpointObservation::StaticSite(site) => &site.span,
    }
}

fn returned_borrow_order_owner(owner_def_path: &str) -> &str {
    owner_def_path
        .split_once("::{closure#")
        .map(|(owner, _)| owner)
        .unwrap_or(owner_def_path)
}

fn infer_openssl_ex_data_release_path_proofs(
    registrations: &[OpenSslExDataRegistration],
    releases: &[OpenSslExDataRelease],
) -> (
    Vec<RawPointerTransferObservation>,
    Vec<ReleasePathProofObservation>,
) {
    let mut transfers = Vec::new();
    let mut proofs = Vec::new();
    for registration in registrations {
        let Some(user_data) = registration.registration.user_data.clone() else {
            continue;
        };
        for release in releases.iter().filter(|release| {
            release.owner_family == registration.owner_family
                && release.api_id == registration.registration.api_id
                && release.handle_key == registration.handle_key
                && release.slot_key == registration.slot_key
        }) {
            let transfer =
                openssl_ex_data_release_transfer(registration, release, user_data.clone());
            if release.postdominates_entry {
                proofs.push(ReleasePathProofObservation {
                    owner_def_path: registration.registration.owner_def_path.clone(),
                    source_path: transfer.source_path.clone(),
                    span: transfer.span.clone(),
                    mir_location: transfer.mir_location.clone(),
                    registration: registration.registration.clone(),
                    release: transfer.clone(),
                });
            }
            transfers.push(transfer);
        }
    }
    transfers.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
    });
    transfers.dedup_by(|left, right| {
        left.owner_def_path == right.owner_def_path
            && left.mir_location == right.mir_location
            && left.user_data == right.user_data
    });
    proofs.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
    });
    proofs.dedup_by(|left, right| {
        left.owner_def_path == right.owner_def_path
            && left.mir_location == right.mir_location
            && left.registration == right.registration
            && left.release == right.release
    });
    (transfers, proofs)
}

fn infer_openssl_ex_data_object_flows(
    registrations: &[OpenSslExDataRegistration],
    releases: &[OpenSslExDataRelease],
    free_contracts: &BTreeMap<String, OpenSslExDataFreeContract>,
) -> Vec<ObjectFlowObservation> {
    let mut flows = Vec::new();
    for registration in registrations {
        let Some(user_data) = registration.registration.user_data.clone() else {
            continue;
        };
        let Some(binding_key) = openssl_ex_data_object_flow_binding_key(registration) else {
            continue;
        };
        let store_site = openssl_ex_data_object_flow_static_site_from_registration(
            registration,
            "store",
            &binding_key,
        );
        flows.push(object_flow_observation(
            &registration.registration.owner_def_path,
            &registration.registration.source_path,
            &registration.registration.span,
            &format!(
                "{}:openssl_ex_data_field_store:{}",
                registration.registration.mir_location,
                short_digest(&binding_key)
            ),
            &registration.registration.api_id,
            ObjectFlowEndpointObservation::UserData(user_data.clone()),
            ObjectFlowObjectKind::UserData,
            store_site,
            ObjectFlowObjectKind::OpaqueHandle,
            ObjectFlowKind::FieldStore,
            Some(binding_key.clone()),
            None,
        ));

        for release in releases.iter().filter(|release| {
            release.owner_family == registration.owner_family
                && release.api_id == registration.registration.api_id
                && release.handle_key == registration.handle_key
                && release.slot_key == registration.slot_key
        }) {
            let transfer =
                openssl_ex_data_release_transfer(registration, release, user_data.clone());
            let load_site =
                openssl_ex_data_object_flow_static_site_from_release(release, "load", &binding_key);
            flows.push(object_flow_observation(
                &registration.registration.owner_def_path,
                &release.source_path,
                &release.span,
                &format!(
                    "{}:openssl_ex_data_field_load:{}",
                    release.mir_location,
                    short_digest(&binding_key)
                ),
                &registration.registration.api_id,
                load_site,
                ObjectFlowObjectKind::OpaqueHandle,
                ObjectFlowEndpointObservation::RawPointerTransferSite(transfer),
                ObjectFlowObjectKind::StaticSite,
                ObjectFlowKind::FieldLoad,
                Some(binding_key.clone()),
                None,
            ));
        }

        let Some(contract) =
            openssl_ex_data_free_callback_contract_for_registration(registration, free_contracts)
        else {
            continue;
        };
        let transfer =
            openssl_ex_data_free_callback_transfer(registration, contract, user_data.clone());
        let load_site = openssl_ex_data_object_flow_static_site_from_contract(
            registration,
            contract,
            "free_callback_load",
            &binding_key,
        );
        flows.push(object_flow_observation(
            &registration.registration.owner_def_path,
            &contract.source_path,
            &contract.span,
            &format!(
                "{}:openssl_ex_data_free_callback_field_load:{}",
                contract.mir_location,
                short_digest(&binding_key)
            ),
            &registration.registration.api_id,
            load_site,
            ObjectFlowObjectKind::OpaqueHandle,
            ObjectFlowEndpointObservation::RawPointerTransferSite(transfer),
            ObjectFlowObjectKind::StaticSite,
            ObjectFlowKind::FieldLoad,
            Some(binding_key),
            None,
        ));
    }
    flows.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
            .then(left.api_id.cmp(&right.api_id))
            .then(left.field_path.cmp(&right.field_path))
    });
    flows.dedup();
    flows
}

fn infer_callback_user_data_object_flows(
    registrations: &[RegistrationObservation],
    reconstructions: &[CallbackUserDataReconstructionObservation],
) -> Vec<ObjectFlowObservation> {
    let mut registration_counts = BTreeMap::<(String, String), usize>::new();
    for registration in registrations.iter().filter(|registration| {
        registration.role == bw_model::RegistrationRole::Register
            && registration.callback.is_some()
            && registration.user_data.is_some()
    }) {
        let Some(callback) = registration.callback.as_ref() else {
            continue;
        };
        *registration_counts
            .entry((registration.api_id.clone(), callback.def_path.clone()))
            .or_default() += 1;
    }

    let mut reconstructions_by_callback =
        BTreeMap::<String, Vec<&CallbackUserDataReconstructionObservation>>::new();
    for reconstruction in reconstructions {
        reconstructions_by_callback
            .entry(reconstruction.owner_def_path.clone())
            .or_default()
            .push(reconstruction);
    }

    let mut flows = Vec::new();
    for registration in registrations.iter().filter(|registration| {
        registration.role == bw_model::RegistrationRole::Register
            && registration.callback.is_some()
            && registration.user_data.is_some()
    }) {
        let Some(callback) = registration.callback.as_ref() else {
            continue;
        };
        let Some(user_data) = registration.user_data.as_ref() else {
            continue;
        };
        let registration_key = (registration.api_id.clone(), callback.def_path.clone());
        if registration_counts
            .get(&registration_key)
            .copied()
            .unwrap_or_default()
            != 1
        {
            continue;
        }
        let Some(callback_reconstructions) = reconstructions_by_callback.get(&callback.def_path)
        else {
            continue;
        };
        if callback_reconstructions.len() != 1 {
            continue;
        }
        let reconstruction = callback_reconstructions[0];
        let binding_key =
            callback_user_data_object_flow_binding_key(&registration.api_id, &callback.def_path);

        flows.push(object_flow_observation(
            &registration.owner_def_path,
            &registration.source_path,
            &registration.span,
            &format!(
                "{}:callback_user_data_field_store:{}",
                registration.mir_location,
                short_digest(&binding_key)
            ),
            &registration.api_id,
            ObjectFlowEndpointObservation::UserData(user_data.clone()),
            ObjectFlowObjectKind::UserData,
            ObjectFlowEndpointObservation::RegistrationSite(registration.clone()),
            ObjectFlowObjectKind::OpaqueHandle,
            ObjectFlowKind::FieldStore,
            Some(binding_key.clone()),
            None,
        ));
        flows.push(object_flow_observation(
            &reconstruction.owner_def_path,
            &reconstruction.source_path,
            &reconstruction.span,
            &format!(
                "{}:callback_user_data_field_load:{}",
                reconstruction.mir_location,
                short_digest(&binding_key)
            ),
            &registration.api_id,
            ObjectFlowEndpointObservation::RegistrationSite(registration.clone()),
            ObjectFlowObjectKind::OpaqueHandle,
            ObjectFlowEndpointObservation::UserData(reconstruction.user_data.clone()),
            ObjectFlowObjectKind::UserData,
            ObjectFlowKind::FieldLoad,
            Some(binding_key),
            None,
        ));
    }
    flows.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
            .then(left.api_id.cmp(&right.api_id))
            .then(left.field_path.cmp(&right.field_path))
    });
    flows.dedup();
    flows
}

fn callback_user_data_object_flow_binding_key(api_id: &str, callback_def_path: &str) -> String {
    format!(
        "callback_user_data:{api_id}:{}",
        short_digest(callback_def_path)
    )
}

fn infer_callback_release_use_orders(
    release_path_proofs: &[ReleasePathProofObservation],
    reconstructions: &[CallbackUserDataReconstructionObservation],
    invocations: &[CallbackUserDataInvocation],
    mir_order_graphs: &BTreeMap<String, MirOrderGraph>,
) -> Vec<CallbackReleaseUseOrderObservation> {
    let mut reconstructions_by_callback =
        BTreeMap::<String, Vec<&CallbackUserDataReconstructionObservation>>::new();
    for reconstruction in reconstructions {
        reconstructions_by_callback
            .entry(reconstruction.owner_def_path.clone())
            .or_default()
            .push(reconstruction);
    }

    let mut orders = Vec::new();
    for proof in release_path_proofs {
        let Some(callback) = proof.registration.callback.as_ref() else {
            continue;
        };
        let Some(registration_user_data) = proof.registration.user_data.as_ref() else {
            continue;
        };
        if registration_user_data != &proof.release.user_data {
            continue;
        }
        let Some(callback_reconstructions) = reconstructions_by_callback.get(&callback.def_path)
        else {
            continue;
        };
        if callback_reconstructions.len() != 1 {
            continue;
        }
        let reconstruction = callback_reconstructions[0];
        let release_order = MirOrderKey {
            basic_block: proof.release.basic_block,
            statement_index: proof.release.statement_index,
        };
        for invocation in invocations.iter().filter(|invocation| {
            invocation.owner_def_path == proof.owner_def_path
                && invocation.callback_def_path == callback.def_path
                && invocation.user_data == *registration_user_data
        }) {
            let ordering = if mir_order_before(
                mir_order_graphs,
                &proof.owner_def_path,
                release_order,
                invocation.order_key,
            ) {
                CallbackReleaseUseOrdering::ReleaseBeforeCallbackUse
            } else if mir_order_before(
                mir_order_graphs,
                &proof.owner_def_path,
                invocation.order_key,
                release_order,
            ) {
                CallbackReleaseUseOrdering::CallbackUseBeforeRelease
            } else {
                // CFG 无法为 release 与 callback use 定序：两个位置互相可达（同处循环）
                // 或互不可达（位于互斥分支）。此前这里直接 continue，观测被静默丢弃，
                // 使"顺序无法证明"和"根本没有 callback use"在下游无法区分。改为记录
                // 缺证事实；消费方按 unknown_ordering token 拒绝点亮证明层。
                CallbackReleaseUseOrdering::UnknownOrdering
            };
            orders.push(CallbackReleaseUseOrderObservation {
                owner_def_path: invocation.owner_def_path.clone(),
                source_path: invocation.source_path.clone(),
                span: invocation.span.clone(),
                mir_location: invocation.mir_location.clone(),
                registration: proof.registration.clone(),
                release: proof.release.clone(),
                reconstruction: reconstruction.clone(),
                ordering,
            });
        }
    }
    orders.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
            .then(
                left.registration
                    .mir_location
                    .cmp(&right.registration.mir_location),
            )
    });
    orders.dedup();
    orders
}

fn infer_openssl_ex_data_free_callback_release_path_proofs(
    registrations: &[OpenSslExDataRegistration],
    free_contracts: &BTreeMap<String, OpenSslExDataFreeContract>,
) -> (
    Vec<RawPointerTransferObservation>,
    Vec<ReleasePathProofObservation>,
) {
    let mut transfers = Vec::new();
    let mut proofs = Vec::new();
    for registration in registrations {
        let Some(user_data) = registration.registration.user_data.clone() else {
            continue;
        };
        let contract =
            openssl_ex_data_free_callback_contract_for_registration(registration, free_contracts);
        let Some(contract) = contract else { continue };
        if contract.api_id != registration.registration.api_id {
            continue;
        }
        let transfer = openssl_ex_data_free_callback_transfer(registration, contract, user_data);
        proofs.push(ReleasePathProofObservation {
            owner_def_path: registration.registration.owner_def_path.clone(),
            source_path: transfer.source_path.clone(),
            span: transfer.span.clone(),
            mir_location: transfer.mir_location.clone(),
            registration: registration.registration.clone(),
            release: transfer.clone(),
        });
        transfers.push(transfer);
    }
    transfers.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
    });
    transfers.dedup_by(|left, right| {
        left.owner_def_path == right.owner_def_path
            && left.mir_location == right.mir_location
            && left.user_data == right.user_data
    });
    proofs.sort_by(|left, right| {
        left.owner_def_path
            .cmp(&right.owner_def_path)
            .then(left.mir_location.cmp(&right.mir_location))
    });
    proofs.dedup_by(|left, right| {
        left.owner_def_path == right.owner_def_path
            && left.mir_location == right.mir_location
            && left.registration == right.registration
            && left.release == right.release
    });
    (transfers, proofs)
}

fn openssl_ex_data_release_transfer(
    registration: &OpenSslExDataRegistration,
    release: &OpenSslExDataRelease,
    user_data: RawPointerReference,
) -> RawPointerTransferObservation {
    RawPointerTransferObservation {
        owner_def_path: registration.registration.owner_def_path.clone(),
        source_path: release.source_path.clone(),
        span: release.span.clone(),
        mir_location: format!("{}:openssl_ex_data_drop_release", release.mir_location),
        basic_block: release.basic_block,
        statement_index: release.statement_index,
        kind: RawPointerTransferKind::FromRaw,
        user_data,
    }
}

fn openssl_ex_data_free_callback_transfer(
    registration: &OpenSslExDataRegistration,
    contract: &OpenSslExDataFreeContract,
    user_data: RawPointerReference,
) -> RawPointerTransferObservation {
    RawPointerTransferObservation {
        owner_def_path: registration.registration.owner_def_path.clone(),
        source_path: registration.registration.source_path.clone(),
        span: registration.registration.span.clone(),
        mir_location: format!(
            "{}:openssl_ex_data_free_callback_contract:{}",
            registration.registration.mir_location, contract.mir_location
        ),
        basic_block: registration.registration.basic_block,
        statement_index: registration.registration.statement_index,
        kind: RawPointerTransferKind::FromRaw,
        user_data,
    }
}

fn openssl_ex_data_free_callback_contract_for_registration<'a>(
    registration: &'a OpenSslExDataRegistration,
    free_contracts: &'a BTreeMap<String, OpenSslExDataFreeContract>,
) -> Option<&'a OpenSslExDataFreeContract> {
    registration.slot_free_contract.as_ref().or_else(|| {
        registration
            .slot_uses_index_argument
            .then(|| free_contracts.get(&registration.registration.api_id))
            .flatten()
    })
}

fn openssl_ex_data_object_flow_binding_key(
    registration: &OpenSslExDataRegistration,
) -> Option<String> {
    if !openssl_ex_data_exact_handle_key(&registration.handle_key)
        || !openssl_ex_data_exact_slot_key(&registration.slot_key)
    {
        return None;
    }
    Some(format!(
        "openssl_ex_data:{}:{}:{}",
        registration.registration.api_id, registration.handle_key, registration.slot_key
    ))
}

fn openssl_ex_data_exact_handle_key(handle_key: &str) -> bool {
    handle_key.starts_with("arg:")
}

fn openssl_ex_data_exact_slot_key(slot_key: &str) -> bool {
    slot_key.starts_with("const:")
        || slot_key.starts_with("free_callback_slot:")
        || slot_key.starts_with("expr:Self::")
        || slot_key.starts_with("expr:const")
}

fn openssl_ex_data_object_flow_static_site_from_registration(
    registration: &OpenSslExDataRegistration,
    role: &str,
    binding_key: &str,
) -> ObjectFlowEndpointObservation {
    ObjectFlowEndpointObservation::StaticSite(ObjectFlowStaticSiteObservation {
        owner_def_path: registration.registration.owner_def_path.clone(),
        source_path: registration.registration.source_path.clone(),
        span: registration.registration.span.clone(),
        mir_location: format!(
            "{}:openssl_ex_data_{role}:{}",
            registration.registration.mir_location,
            short_digest(binding_key)
        ),
        type_name: format!("openssl_ex_data_slot:{}", registration.registration.api_id),
    })
}

fn openssl_ex_data_object_flow_static_site_from_release(
    release: &OpenSslExDataRelease,
    role: &str,
    binding_key: &str,
) -> ObjectFlowEndpointObservation {
    ObjectFlowEndpointObservation::StaticSite(ObjectFlowStaticSiteObservation {
        owner_def_path: release.owner_def_path.clone(),
        source_path: release.source_path.clone(),
        span: release.span.clone(),
        mir_location: format!(
            "{}:openssl_ex_data_{role}:{}",
            release.mir_location,
            short_digest(binding_key)
        ),
        type_name: format!("openssl_ex_data_slot:{}", release.api_id),
    })
}

fn openssl_ex_data_object_flow_static_site_from_contract(
    registration: &OpenSslExDataRegistration,
    contract: &OpenSslExDataFreeContract,
    role: &str,
    binding_key: &str,
) -> ObjectFlowEndpointObservation {
    ObjectFlowEndpointObservation::StaticSite(ObjectFlowStaticSiteObservation {
        owner_def_path: registration.registration.owner_def_path.clone(),
        source_path: contract.source_path.clone(),
        span: contract.span.clone(),
        mir_location: format!(
            "{}:openssl_ex_data_{role}:{}",
            contract.mir_location,
            short_digest(binding_key)
        ),
        type_name: format!("openssl_ex_data_slot:{}", registration.registration.api_id),
    })
}

fn returned_borrow_invalidation_order_observation(
    persisted: &PersistedReturnedBorrowObservation,
    invalidation: &ReturnedBorrowInvalidationCall,
    use_site: &ReturnedBorrowStorageUse,
    ordering: ReturnedBorrowInvalidationOrdering,
) -> ReturnedBorrowInvalidationOrderObservation {
    ReturnedBorrowInvalidationOrderObservation {
        owner_def_path: use_site.owner_def_path.clone(),
        source_path: use_site.source_path.clone(),
        span: use_site.span.clone(),
        mir_location: use_site.mir_location.clone(),
        persisted: persisted.clone(),
        invalidation_owner_def_path: invalidation.owner_def_path.clone(),
        invalidation_source_path: invalidation.source_path.clone(),
        invalidation_span: invalidation.span.clone(),
        invalidation_mir_location: invalidation.mir_location.clone(),
        use_owner_def_path: use_site.owner_def_path.clone(),
        use_source_path: use_site.source_path.clone(),
        use_span: use_site.span.clone(),
        use_mir_location: use_site.mir_location.clone(),
        api_id: persisted.api_id.clone(),
        invalidation_api_id: invalidation.api_id.clone(),
        ordering,
    }
}

fn returned_borrow_constructor_persistence(persisted: &PersistedReturnedBorrowObservation) -> bool {
    method_name(&persisted.owner_def_path)
        .is_some_and(|method| matches!(method.as_str(), "new" | "default" | "from"))
}

fn returned_borrow_storage_matches(
    persisted: &PersistedReturnedBorrowObservation,
    use_site: &ReturnedBorrowStorageUse,
) -> bool {
    match (&persisted.storage_key, use_site.storage_keys.is_empty()) {
        (Some(storage_key), false) => use_site.storage_keys.contains(storage_key),
        (Some(_), true) | (None, _) => false,
    }
}

fn unique_returned_borrow_origin_from_persisted_observations(
    origins: &[PersistedReturnedBorrowObservation],
) -> Option<ReturnedBorrowOrigin> {
    let mut unique = None;
    for persisted in origins {
        let candidate = ReturnedBorrowOrigin {
            source: persisted.source.clone(),
            api_id: persisted.api_id.clone(),
            returned_type_name: persisted.returned_type_name.clone(),
        };
        if let Some(existing) = &unique
            && existing != &candidate
        {
            return None;
        }
        unique = Some(candidate);
    }
    unique
}

fn returned_borrow_storage_blocked_by_mutation(
    persisted: &PersistedReturnedBorrowObservation,
    use_site: &ReturnedBorrowStorageUse,
    use_order_owner: &str,
    storage_mutation_barriers: &[ReturnedBorrowStorageMutationBarrier],
    local_method_calls: &[LocalMethodCall],
    mir_order_graphs: &BTreeMap<String, MirOrderGraph>,
) -> bool {
    let Some(persisted_storage_key) = persisted.storage_key.as_deref() else {
        return false;
    };
    storage_mutation_barriers.iter().any(|barrier| {
        barrier.owner_def_path == use_order_owner
            && barrier.source_path == use_site.source_path
            && mir_order_before(
                mir_order_graphs,
                use_order_owner,
                barrier.order_key,
                use_site.order_key,
            )
            && mutation_barrier_matches_storage_key(barrier, persisted_storage_key)
            && persisted_before_mutation_barrier(
                persisted,
                barrier,
                use_order_owner,
                local_method_calls,
                mir_order_graphs,
            )
    })
}

fn mutation_barrier_matches_storage_key(
    barrier: &ReturnedBorrowStorageMutationBarrier,
    storage_key: &str,
) -> bool {
    barrier.storage_keys.contains(storage_key)
        || barrier
            .storage_prefixes
            .iter()
            .any(|prefix| storage_key.starts_with(prefix))
}

fn persisted_before_mutation_barrier(
    persisted: &PersistedReturnedBorrowObservation,
    barrier: &ReturnedBorrowStorageMutationBarrier,
    use_order_owner: &str,
    local_method_calls: &[LocalMethodCall],
    mir_order_graphs: &BTreeMap<String, MirOrderGraph>,
) -> bool {
    if persisted.owner_def_path == use_order_owner && persisted.source_path == barrier.source_path {
        return mir_order_before(
            mir_order_graphs,
            use_order_owner,
            persisted_returned_borrow_order_key(persisted),
            barrier.order_key,
        );
    }
    if returned_borrow_constructor_persistence(persisted) {
        return true;
    }
    local_method_calls.iter().any(|call| {
        call.owner_def_path == use_order_owner
            && call.source_path == barrier.source_path
            && returned_borrow_same_method_effect(&call.callee_def_path, &persisted.owner_def_path)
            && mir_order_before(
                mir_order_graphs,
                use_order_owner,
                call.order_key,
                barrier.order_key,
            )
    })
}

fn returned_borrow_same_order_scope(left: &str, right: &str) -> bool {
    let Some(left_family) = lifecycle_receiver_family(left) else {
        return false;
    };
    let Some(right_family) = lifecycle_receiver_family(right) else {
        return false;
    };
    left_family == right_family
}

fn returned_borrow_same_method_effect(left: &str, right: &str) -> bool {
    owner_family_prefix(left) == owner_family_prefix(right)
        && method_name(left) == method_name(right)
}

fn lifecycle_receiver_family(def_path: &str) -> Option<String> {
    if let Some(stripped) = def_path.strip_prefix('<') {
        let receiver = stripped
            .split_once(" as ")
            .map(|(receiver, _)| receiver)
            .unwrap_or(stripped);
        let family = strip_def_path_generics(receiver)
            .trim_end_matches('>')
            .trim()
            .to_owned();
        return (!family.is_empty()).then_some(family);
    }
    owner_family_prefix(def_path)
}

fn owner_family_prefix(def_path: &str) -> Option<String> {
    let normalized = if let Some(stripped) = def_path.strip_prefix('<') {
        stripped
            .split_once(" as ")
            .map(|(receiver, _)| receiver)
            .unwrap_or(stripped)
    } else {
        def_path
    };
    let normalized = strip_def_path_generics(normalized);
    normalized
        .rsplit_once("::")
        .map(|(prefix, _)| prefix.trim_end_matches("::").to_owned())
}

fn method_name(def_path: &str) -> Option<String> {
    let normalized = strip_def_path_generics(def_path);
    normalized
        .rsplit("::")
        .find(|method| !method.is_empty())
        .map(ToOwned::to_owned)
}

fn strip_def_path_generics(def_path: &str) -> String {
    let mut output = String::with_capacity(def_path.len());
    let mut depth = 0_u32;
    for ch in def_path.chars() {
        match ch {
            '<' => depth = depth.saturating_add(1),
            '>' if depth > 0 => depth -= 1,
            _ if depth == 0 => output.push(ch),
            _ => {}
        }
    }
    output
}

fn is_atomic_load_call(callee_def_path: &str) -> bool {
    let lower = callee_def_path.to_ascii_lowercase();
    lower.ends_with("::load") && lower.contains("sync::atomic") && lower.contains("atomic")
}

fn is_pointer_like_atomic_type(type_name: &str) -> bool {
    let lower = type_name.to_ascii_lowercase();
    lower.contains("atomicptr")
        || lower.contains("atomic_ptr")
        || lower.contains("atomic<*")
        || lower.contains("*mut ")
        || lower.contains("*const ")
}

fn owner_is_atomic_lifecycle_scope(owner_def_path: &str) -> bool {
    let lower = owner_def_path.to_ascii_lowercase();
    lower.contains("iterator")
        || lower.contains("intoiter")
        || lower.contains("rawiter")
        || lower.contains("thread_local")
        || lower.contains("get_or_try")
        || lower.ends_with("::next")
        || lower.contains("::next::")
        || matches!(
            method_name(owner_def_path).as_deref(),
            Some("next" | "next_back" | "get_or_try" | "into_iter")
        )
}

fn atomic_ordering_from_text(text: &str) -> Option<AtomicOrderingKind> {
    let lower = text.to_ascii_lowercase();
    let compact = lower
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>();
    if lower.contains("acqrel")
        || lower.contains("acq_rel")
        || compact.contains("orderingacqrel")
        || compact.contains("orderingacq_rel")
    {
        Some(AtomicOrderingKind::AcqRel)
    } else if lower.contains("seqcst")
        || lower.contains("seq_cst")
        || compact.contains("orderingseqcst")
        || compact.contains("orderingseq_cst")
    {
        Some(AtomicOrderingKind::SeqCst)
    } else if lower.contains("relaxed") || compact.contains("orderingrelaxed") {
        Some(AtomicOrderingKind::Relaxed)
    } else if lower.contains("acquire") || compact.contains("orderingacquire") {
        Some(AtomicOrderingKind::Acquire)
    } else if lower.contains("release") || compact.contains("orderingrelease") {
        Some(AtomicOrderingKind::Release)
    } else {
        None
    }
}

fn raw_pointer_projection_key(place: &Place<'_>) -> Option<Vec<String>> {
    let mut projection = Vec::new();
    for elem in place.projection {
        match elem {
            ProjectionElem::Field(field, _) => {
                projection.push(format!("field:{}", field.index()));
            }
            _ => return None,
        }
    }
    Some(projection)
}

fn raw_pointer_field_path_from_key(key: &RawPointerPlaceKey) -> Option<String> {
    (!key.projection.is_empty()).then(|| key.projection.join("."))
}

fn hook_release_slot_field_path(hook_family: &str, key: &RawPointerPlaceKey) -> Option<String> {
    raw_pointer_field_path_from_key(key)
        .map(|field_path| format!("hook_release_slot:{hook_family}:{field_path}"))
}

fn hook_release_slot_static_site<'tcx>(
    tcx: TyCtxt<'tcx>,
    owner_def_path: &str,
    span: Span,
    location: Location,
    role: &str,
    hook_family: &str,
) -> Option<ObjectFlowEndpointObservation> {
    Some(ObjectFlowEndpointObservation::StaticSite(
        ObjectFlowStaticSiteObservation {
            owner_def_path: owner_def_path.to_owned(),
            source_path: source_path(tcx, span).ok()?,
            span: stable_span(tcx, span).ok()?,
            mir_location: format!("{location:?}:{role}:{hook_family}"),
            type_name: format!("hook_release_slot:{hook_family}"),
        },
    ))
}

fn raw_pointer_aggregate_kind_tracks_fields(kind: &AggregateKind<'_>) -> bool {
    matches!(kind, AggregateKind::Adt(..) | AggregateKind::Tuple)
}

fn fn_pointer_projection_key(
    body: &Body<'_>,
    place: &Place<'_>,
    stop_at_downcast: bool,
) -> Option<Vec<String>> {
    let mut projection = Vec::new();
    let mut skipped_receiver_deref = false;
    let is_ref_local = matches!(body.local_decls[place.local].ty.kind(), ty::Ref(..));
    for elem in place.projection {
        if is_ref_local && !skipped_receiver_deref && matches!(elem, ProjectionElem::Deref) {
            skipped_receiver_deref = true;
            continue;
        }
        match elem {
            ProjectionElem::Field(field, _) => {
                projection.push(format!("field:{}", field.index()));
            }
            ProjectionElem::Downcast(..) if stop_at_downcast => return Some(projection),
            _ => return None,
        }
    }
    (!stop_at_downcast).then_some(projection)
}

fn storage_projection_key<'tcx>(body: &Body<'tcx>, place: &Place<'tcx>) -> Option<Vec<String>> {
    let mut projection = Vec::new();
    let mut current_ty = body.local_decls[place.local].ty;
    let mut skipped_receiver_deref = false;
    let mut followed_unique_owner_deref = false;
    let is_ref_local = matches!(current_ty.kind(), ty::Ref(..));
    for elem in place.projection {
        match elem {
            ProjectionElem::Deref if is_ref_local && !skipped_receiver_deref => {
                skipped_receiver_deref = true;
                if let ty::Ref(_, inner, _) = current_ty.kind() {
                    current_ty = *inner;
                }
            }
            ProjectionElem::Deref
                if !followed_unique_owner_deref && is_box_storage_owner_ty(current_ty) =>
            {
                followed_unique_owner_deref = true;
                projection.push("deref".to_owned());
            }
            ProjectionElem::Field(field, field_ty) => {
                followed_unique_owner_deref = false;
                projection.push(format!("field:{}", field.index()));
                current_ty = field_ty;
            }
            ProjectionElem::Downcast(..)
            | ProjectionElem::Index(_)
            | ProjectionElem::ConstantIndex { .. }
            | ProjectionElem::Subslice { .. }
            | ProjectionElem::OpaqueCast(_) => return None,
            _ => return None,
        }
    }
    Some(projection)
}

fn unique_owned_storage_projection_passthrough<'tcx>(
    body: &Body<'tcx>,
    place: &Place<'tcx>,
) -> bool {
    let mut current_ty = body.local_decls[place.local].ty;
    for elem in place.projection {
        match elem {
            ProjectionElem::Deref => {
                if matches!(current_ty.kind(), ty::RawPtr(..) | ty::Ref(..))
                    || is_box_storage_owner_ty(current_ty)
                {
                    if let ty::Ref(_, inner, _) = current_ty.kind() {
                        current_ty = *inner;
                    }
                    continue;
                }
                return false;
            }
            ProjectionElem::Field(_, field_ty) => {
                let lower = current_ty.to_string().to_ascii_lowercase();
                if is_box_storage_owner_ty(current_ty)
                    || lower.contains("ptr::unique<")
                    || lower.contains("ptr::non_null<")
                {
                    current_ty = field_ty;
                    continue;
                }
                return false;
            }
            ProjectionElem::OpaqueCast(_)
            | ProjectionElem::Downcast(..)
            | ProjectionElem::Index(_)
            | ProjectionElem::ConstantIndex { .. }
            | ProjectionElem::Subslice { .. } => return false,
            _ => return false,
        }
    }
    true
}

fn field_storage_key(owner_family: &str, projection: &[String]) -> String {
    format!("field:{owner_family}:{}", projection.join("."))
}

fn local_wrapper_field_storage_key(
    owner_def_path: &str,
    local: Local,
    field_path: &[String],
) -> String {
    format!(
        "local_wrapper_field:{}:l{}:{}",
        short_digest(owner_def_path),
        local.index(),
        field_path.join(".")
    )
}

fn local_wrapper_field_storage_key_prefix(owner_def_path: &str, local: Local) -> String {
    format!(
        "local_wrapper_field:{}:l{}:",
        short_digest(owner_def_path),
        local.index()
    )
}

fn local_wrapper_field_path_from_storage_key(storage_key: &str) -> Option<String> {
    let rest = storage_key.strip_prefix("local_wrapper_field:")?;
    let mut parts = rest.splitn(3, ':');
    let _owner_digest = parts.next()?;
    let _local = parts.next()?;
    parts
        .next()
        .map(ToOwned::to_owned)
        .filter(|field_path| !field_path.is_empty())
}

fn is_box_storage_owner_ty(ty: Ty<'_>) -> bool {
    let lower = ty.to_string().to_ascii_lowercase();
    lower.starts_with("box<")
        || lower.contains("::boxed::box<")
        || lower.contains("alloc::boxed::box<")
        || lower.contains("std::boxed::box<")
}

fn is_raw_pointer_deref_owner_ty(ty: Ty<'_>) -> bool {
    is_box_storage_owner_ty(ty) || shared_owner_family_token(&ty.to_string()).is_some()
}

fn non_null_storage_ty(ty: Ty<'_>) -> bool {
    let lower = ty.to_string().to_ascii_lowercase();
    lower.starts_with("std::ptr::nonnull<")
        || lower.starts_with("core::ptr::nonnull<")
        || lower.starts_with("ptr::nonnull<")
        || lower.starts_with("std::ptr::non_null::nonnull<")
        || lower.starts_with("core::ptr::non_null::nonnull<")
        || lower.starts_with("ptr::non_null::nonnull<")
        || lower.starts_with("nonnull<")
}

fn raw_pointer_unique_owner_constructor_call(def_path: &str) -> bool {
    method_name(def_path).as_deref() == Some("new")
        && def_path.to_ascii_lowercase().contains("boxed::box")
}

fn raw_pointer_non_null_constructor_call(def_path: &str) -> bool {
    method_name(def_path).as_deref() == Some("new_unchecked")
}

fn raw_pointer_non_null_as_ptr_call(def_path: &str) -> bool {
    method_name(def_path).as_deref() == Some("as_ptr")
}

fn raw_pointer_deref_owner_constructor_call(def_path: &str) -> bool {
    raw_pointer_unique_owner_constructor_call(def_path) || shared_owner_constructor_call(def_path)
}

fn shared_owner_clone_call(def_path: &str) -> bool {
    def_path.ends_with("::clone")
}

fn shared_owner_constructor_call(def_path: &str) -> bool {
    method_name(def_path).as_deref() == Some("new")
        && shared_owner_path_mentions_family(def_path).is_some()
}

fn shared_owner_deref_call(def_path: &str) -> bool {
    method_name(def_path)
        .as_deref()
        .is_some_and(|method| matches!(method, "deref" | "deref_mut"))
}

fn shared_owner_make_mut_call(def_path: &str) -> bool {
    method_name(def_path).as_deref() == Some("make_mut")
        && shared_owner_path_mentions_family(def_path).is_some()
}

fn interior_mutability_constructor_call(def_path: &str) -> bool {
    method_name(def_path).as_deref() == Some("new")
        && interior_mutability_path_mentions_family(def_path).is_some()
}

fn interior_mutability_read_guard_call(def_path: &str) -> bool {
    let Some(method) = method_name(def_path) else {
        return false;
    };
    match interior_mutability_path_mentions_family(def_path) {
        Some("refcell") => method == "borrow",
        Some("rwlock") => method == "read",
        _ => false,
    }
}

fn interior_mutability_mutation_barrier_call(def_path: &str) -> bool {
    let Some(method) = method_name(def_path) else {
        return false;
    };
    match interior_mutability_path_mentions_family(def_path) {
        Some("refcell") => matches!(
            method.as_str(),
            "borrow_mut" | "get_mut" | "replace" | "replace_with" | "take" | "swap"
        ),
        Some("cell") => matches!(
            method.as_str(),
            "set" | "replace" | "take" | "swap" | "get_mut"
        ),
        Some("mutex") => matches!(method.as_str(), "lock" | "get_mut"),
        Some("rwlock") => matches!(method.as_str(), "write" | "get_mut"),
        _ => false,
    }
}

fn shared_owner_type_name(ty: Ty<'_>) -> Option<String> {
    let type_name = ty.to_string();
    shared_owner_family_token(&type_name).map(|_| type_name)
}

fn shared_owner_path_mentions_family(def_path: &str) -> Option<&'static str> {
    let lower = def_path.to_ascii_lowercase();
    if lower.contains("sync::arc") {
        Some("arc")
    } else if lower.contains("rc::rc") {
        Some("rc")
    } else {
        None
    }
}

fn interior_mutability_path_mentions_family(def_path: &str) -> Option<&'static str> {
    let lower = def_path.to_ascii_lowercase();
    if lower.contains("cell::refcell") {
        Some("refcell")
    } else if lower.contains("cell::cell") {
        Some("cell")
    } else if lower.contains("sync::mutex") {
        Some("mutex")
    } else if lower.contains("sync::rwlock") {
        Some("rwlock")
    } else {
        None
    }
}

fn shared_owner_family_token(type_name: &str) -> Option<&'static str> {
    let lower = strip_reference_prefix(type_name).to_ascii_lowercase();
    if lower.starts_with("std::sync::arc<")
        || lower.starts_with("alloc::sync::arc<")
        || lower.starts_with("sync::arc<")
        || lower.starts_with("arc<")
    {
        Some("arc")
    } else if lower.starts_with("std::rc::rc<")
        || lower.starts_with("alloc::rc::rc<")
        || lower.starts_with("rc::rc<")
        || lower.starts_with("rc<")
    {
        Some("rc")
    } else {
        None
    }
}

fn strip_reference_prefix(type_name: &str) -> &str {
    let mut normalized = type_name.trim();
    while let Some(stripped) = normalized.strip_prefix('&') {
        normalized = stripped.trim_start();
        if let Some(stripped) = normalized.strip_prefix("mut ") {
            normalized = stripped.trim_start();
        }
    }
    normalized
}

fn raw_pointer_arg_projection_key(body: &Body<'_>, place: &Place<'_>) -> Option<Vec<String>> {
    let mut projection = Vec::new();
    let mut skipped_receiver_deref = false;
    let is_ref_arg = matches!(body.local_decls[place.local].ty.kind(), ty::Ref(..));
    if !is_ref_arg
        && (raw_pointer_option_some_field_key_from_place(body, place).is_some()
            || raw_pointer_result_ok_field_key_from_place(body, place).is_some())
    {
        return Some(vec!["field:0".to_owned()]);
    }
    if !is_ref_arg && let Some(key) = raw_pointer_unique_owner_field_key_from_place(body, place) {
        return Some(key.projection);
    }
    for elem in place.projection {
        if is_ref_arg && !skipped_receiver_deref {
            if !matches!(elem, ProjectionElem::Deref) {
                return None;
            }
            skipped_receiver_deref = true;
            continue;
        }
        match elem {
            ProjectionElem::Field(field, _) => {
                projection.push(format!("field:{}", field.index()));
            }
            _ => return None,
        }
    }
    if is_ref_arg && !skipped_receiver_deref {
        return None;
    }
    Some(projection)
}

/// callee 是否把接收者的一部分借出去作为返回值，例如 `fn get(&self) -> &T { &self.value }`。
///
/// 这是完全健全的普通写法，`ReturnedBorrowRelation` 那套（针对未约束生命周期）不会触发；
/// 但对留存分析它很关键：闭包捕获的是这个借用，而被销毁的是接收者。
///
/// 判据保持窄：返回值必须直接由对第 0 个参数（接收者）的借用赋值而来。看不出来就返回
/// false —— 宁可漏掉一条别名，也不要凭猜测把两个无关对象连在一起。
fn callable_returns_receiver_borrow<'tcx>(tcx: TyCtxt<'tcx>, def_id: DefId) -> bool {
    if !matches!(tcx.def_kind(def_id), DefKind::Fn | DefKind::AssocFn)
        || !tcx.is_mir_available(def_id)
    {
        return false;
    }
    let body = tcx.optimized_mir(def_id);
    let Some(receiver) = body.args_iter().next() else {
        return false;
    };
    if !matches!(
        body.local_decls[receiver].ty.kind(),
        ty::Ref(..) | ty::RawPtr(..)
    ) {
        return false;
    }
    body.basic_blocks.iter().any(|block| {
        block.statements.iter().any(|statement| {
            let StatementKind::Assign(assignment) = &statement.kind else {
                return false;
            };
            let (place, rvalue) = &**assignment;
            // 只认直接写进返回位置 `_0` 的赋值。
            if place.local != RETURN_PLACE || !place.projection.is_empty() {
                return false;
            }
            let Rvalue::Ref(_, _, borrowed) = rvalue else {
                return false;
            };
            borrowed.local == receiver
        })
    })
}

fn is_lifecycle_owner_ty(ty: Ty<'_>) -> bool {
    matches!(ty.kind(), ty::Adt(..) | ty::Closure(..))
}

fn is_external_buffer_return_ty(ty: Ty<'_>) -> bool {
    matches!(ty.kind(), ty::Adt(..)) && ty.to_string().to_ascii_lowercase().contains("buffer")
}

fn external_buffer_creation_call(def_path: &str) -> Option<&'static str> {
    if def_path.ends_with("::buffer::new_external") {
        Some("external_buffer")
    } else if def_path.ends_with("::arraybuffer::new_external") {
        Some("external_arraybuffer")
    } else {
        None
    }
}

fn foreign_selector_output_buffer_call(def_path: &str) -> bool {
    def_path == "openssl_sys::SSL_select_next_proto"
        || def_path.ends_with("::openssl_sys::SSL_select_next_proto")
}

fn foreign_borrowed_pointer_return_call(def_path: &str) -> bool {
    def_path == "sqlite3_column_name"
        || def_path == "sqlite3_column_name16"
        || def_path.ends_with("::sqlite3_column_name")
        || def_path.ends_with("::sqlite3_column_name16")
}

fn borrowed_view_from_raw_pointer_call(def_path: &str) -> bool {
    def_path.ends_with("::CStr::from_ptr")
        || def_path.ends_with("::OsStr::from_encoded_bytes_unchecked")
}

fn openssl_ex_data_register_api(api_id: &str) -> bool {
    matches!(
        api_id,
        "api:openssl:ssl_set_ex_data:register" | "api:openssl:ssl_ctx_set_ex_data:register"
    )
}

fn openssl_ex_data_new_index_api_id(def_path: &str) -> Option<&'static str> {
    let method = method_name(def_path)?;
    match method.as_str() {
        "get_new_ssl_idx" => Some("api:openssl:ssl_set_ex_data:register"),
        "get_new_idx" => Some("api:openssl:ssl_ctx_set_ex_data:register"),
        _ => None,
    }
}

fn openssl_ex_data_new_index_contract_owner(
    owner_def_path: &str,
    api_id: &str,
    _callee_def_id: DefId,
) -> bool {
    match api_id {
        "api:openssl:ssl_set_ex_data:register" => owner_def_path.ends_with("::Ssl::new_ex_index"),
        "api:openssl:ssl_ctx_set_ex_data:register" => {
            owner_def_path.ends_with("::SslContext::new_ex_index")
        }
        _ => false,
    }
}

fn openssl_ex_data_slot_key_for_new_index(
    api_id: &str,
    owner_def_path: &str,
    mir_location: &str,
) -> Option<String> {
    if !openssl_ex_data_register_api(api_id) {
        return None;
    }
    Some(format!(
        "free_callback_slot:{api_id}:{}:{mir_location}",
        strip_def_path_generics(owner_def_path)
    ))
}

fn openssl_ex_data_free_data_box_path(def_path: &str) -> bool {
    method_name(def_path)
        .as_deref()
        .is_some_and(|method| method.contains("free_data_box"))
}

fn normalize_openssl_ex_data_handle_snippet(snippet: &str) -> Option<String> {
    let normalized = snippet.split_whitespace().collect::<String>();
    (!normalized.is_empty()).then(|| format!("handle:{normalized}"))
}

fn normalize_openssl_ex_data_slot_snippet(snippet: &str) -> Option<String> {
    let normalized = snippet.split_whitespace().collect::<String>();
    if normalized.is_empty() {
        return None;
    }
    if let Some(integer) = openssl_slot_integer_token(snippet) {
        return Some(format!("const:{integer}"));
    }
    Some(format!("expr:{normalized}"))
}

fn openssl_slot_integer_token(snippet: &str) -> Option<String> {
    let trimmed = snippet.trim();
    if let Some(integer) = leading_integer_token(trimmed) {
        return Some(integer);
    }
    if let Some(after_const) = snippet.find("const").map(|index| &snippet[index + 5..]) {
        let after_const = after_const.trim_start_matches(|ch: char| {
            ch.is_whitespace() || matches!(ch, '(' | '{' | '[' | ':')
        });
        if let Some(integer) = leading_integer_token(after_const) {
            return Some(integer);
        }
    }
    let compact = snippet.split_whitespace().collect::<String>();
    compact.find("const").and_then(|index| {
        let after_const = &compact[index + 5..];
        leading_integer_token(
            after_const.trim_start_matches(|ch: char| matches!(ch, '(' | '{' | '[' | ':')),
        )
    })
}

fn leading_integer_token(text: &str) -> Option<String> {
    let mut chars = text.char_indices();
    let Some((_, first)) = chars.next() else {
        return None;
    };
    let mut end = if first == '-' {
        let Some((offset, next)) = chars.next() else {
            return None;
        };
        if !next.is_ascii_digit() {
            return None;
        }
        offset + next.len_utf8()
    } else if first.is_ascii_digit() {
        first.len_utf8()
    } else {
        return None;
    };
    let tail_start = end;
    for (offset, ch) in text[tail_start..].char_indices() {
        if !ch.is_ascii_digit() {
            break;
        }
        end = tail_start + offset + ch.len_utf8();
    }
    Some(text[..end].to_owned())
}

fn root_returned_borrow_view_call(def_path: &str) -> bool {
    def_path.ends_with("::field_name")
}

fn returned_borrow_callable_returns_ref_container<'tcx>(tcx: TyCtxt<'tcx>, def_id: DefId) -> bool {
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn | DefKind::AssocFn | DefKind::Closure
    ) || !tcx.is_mir_available(def_id)
    {
        return false;
    }
    let Some(local_def_id) = def_id.as_local() else {
        return false;
    };
    let body = tcx.optimized_mir(local_def_id);
    let return_ty = body.local_decls[Local::new(0)].ty;
    ty_contains_ref(return_ty) && !matches!(return_ty.kind(), ty::Ref(..))
}

fn persisted_returned_borrow_storage_call(def_path: &str) -> bool {
    def_path.ends_with("::insert")
        || def_path.ends_with("::push")
        || def_path.ends_with("::push_back")
        || def_path.ends_with("::extend")
}

fn returned_borrow_storage_passthrough_call(def_path: &str) -> bool {
    let normalized = strip_def_path_generics(def_path);
    normalized == "std::ops::Try::branch"
        || normalized == "core::ops::Try::branch"
        || normalized == "std::ops::try_trait::Try::branch"
        || normalized == "core::ops::try_trait::Try::branch"
        || normalized.ends_with(" as std::ops::Try>::branch")
        || normalized.ends_with(" as core::ops::Try>::branch")
        || normalized.ends_with(" as std::ops::try_trait::Try>::branch")
        || normalized.ends_with(" as core::ops::try_trait::Try>::branch")
}

fn returned_borrow_storage_reference_passthrough_call(def_path: &str) -> bool {
    let normalized = strip_def_path_generics(def_path);
    let lower = normalized.to_ascii_lowercase();
    (lower.ends_with("::deref") || lower.ends_with("::deref_mut"))
        && (lower.contains("::ops::deref")
            || lower.contains(" as std::ops::deref")
            || lower.contains(" as core::ops::deref"))
}

fn returned_borrow_option_reference_storage_passthrough_call(
    def_path: &str,
    storage_type_name: &str,
) -> bool {
    method_name(def_path)
        .as_deref()
        .is_some_and(|method| matches!(method, "as_ref" | "as_deref" | "as_deref_mut"))
        && storage_type_name.to_ascii_lowercase().contains("option<")
        && returned_borrow_collection_storage_type(storage_type_name)
}

fn returned_borrow_indexed_sequence_reference_passthrough_call(
    def_path: &str,
    storage_type_name: &str,
) -> bool {
    method_name(def_path).as_deref() == Some("as_slice")
        && returned_borrow_indexed_sequence_storage_type(storage_type_name)
}

fn returned_borrow_indexed_sequence_iterator_call(def_path: &str, storage_type_name: &str) -> bool {
    method_name(def_path).as_deref() == Some("iter")
        && returned_borrow_indexed_sequence_storage_type(storage_type_name)
}

fn returned_borrow_iterator_adapter_call(def_path: &str) -> bool {
    def_path.ends_with("::filter_map") || def_path.ends_with("::map")
}

fn returned_borrow_iterator_passthrough_call(def_path: &str) -> bool {
    def_path.ends_with("::enumerate")
        || def_path.ends_with("::filter")
        || def_path.ends_with("::inspect")
        || def_path.ends_with("::peekable")
        || def_path.ends_with("::skip")
        || def_path.ends_with("::take")
}

fn persisted_returned_borrow_collect_call(def_path: &str) -> bool {
    def_path.ends_with("::collect")
}

fn returned_borrow_invalidation_call(def_path: &str) -> bool {
    def_path.ends_with("::step")
        || def_path.ends_with("::reset")
        || def_path.ends_with("::clear")
        || def_path.ends_with("::advance")
        || def_path.ends_with("::next")
}

fn returned_borrow_storage_use_call(def_path: &str) -> bool {
    def_path.ends_with("::get")
        || def_path.ends_with("::first")
        || def_path.ends_with("::front")
        || def_path.ends_with("::last")
        || def_path.ends_with("::back")
        || def_path.ends_with("::into_named")
        || def_path.ends_with("::and_then")
        || def_path.ends_with("::as_ref")
}

fn audited_collection_lookup_contract(
    contract: &CollectionLookupContract,
    callee_def_path: &str,
) -> bool {
    contract.callee == callee_def_path
        && contract.returns_identity_preserving_borrow
        && !contract.mutates_storage
}

fn returned_borrow_collection_lookup_key_arg_type(type_name: &str) -> bool {
    !returned_borrow_collection_storage_type(type_name) && string_like_key_type(type_name)
}

fn returned_borrow_option_take_or_replace_call(
    def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'_>>],
    storage_arg_type_name: &str,
) -> bool {
    if args.is_empty() || !type_name_mentions_option(storage_arg_type_name) {
        return false;
    }
    returned_borrow_option_take_call(def_path) || returned_borrow_replace_call(def_path)
}

fn returned_borrow_option_take_call(def_path: &str) -> bool {
    let Some(method) = method_name(def_path) else {
        return false;
    };
    if method != "take" {
        return false;
    }
    let normalized = strip_def_path_generics(def_path).to_ascii_lowercase();
    normalized.contains("option::option") || normalized.contains("::mem::take")
}

fn returned_borrow_replace_call(def_path: &str) -> bool {
    let Some(method) = method_name(def_path) else {
        return false;
    };
    if method != "replace" {
        return false;
    }
    let normalized = strip_def_path_generics(def_path).to_ascii_lowercase();
    normalized.contains("option::option") || normalized.contains("::mem::replace")
}

fn type_name_mentions_option(type_name: &str) -> bool {
    type_name.to_ascii_lowercase().contains("option<")
}

fn returned_borrow_collection_insert_index(
    def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'_>>],
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<String> {
    if method_name(def_path).as_deref() != Some("insert") {
        return None;
    }
    args.get(1)
        .and_then(|arg| usize_constant_operand_key_with_origins(&arg.node, stable_constant_origins))
}

fn returned_borrow_persisted_collection_storage_key(
    def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'_>>],
    storage_type_name: &str,
    storage_key: String,
    indexed_sequence_lengths: &BTreeMap<String, usize>,
    stable_constant_origins: &BTreeMap<Local, String>,
    scoped_key_origins: &BTreeMap<Local, String>,
    dynamic_key_generations: &BTreeMap<Local, u32>,
    owner_def_path: &str,
) -> Option<String> {
    if !returned_borrow_indexed_sequence_insert_call(def_path, storage_type_name) {
        if returned_borrow_indexed_sequence_append_call(def_path, storage_type_name) {
            return indexed_sequence_lengths.get(&storage_key).map(|length| {
                indexed_returned_borrow_storage_key(&storage_key, &length.to_string())
            });
        }
        if returned_borrow_keyed_map_insert_call(def_path, storage_type_name) {
            return returned_borrow_keyed_map_insert_key(
                def_path,
                args,
                stable_constant_origins,
                scoped_key_origins,
                dynamic_key_generations,
                owner_def_path,
            )
            .map(|key| keyed_map_returned_borrow_storage_key(&storage_key, &key));
        }
        return Some(storage_key);
    }
    returned_borrow_collection_insert_index(def_path, args, stable_constant_origins)
        .map(|index| indexed_returned_borrow_storage_key(&storage_key, &index))
}

fn returned_borrow_collection_use_index(
    def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'_>>],
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<String> {
    match method_name(def_path).as_deref()? {
        "get" => args.get(1).and_then(|arg| {
            usize_constant_operand_key_with_origins(&arg.node, stable_constant_origins)
        }),
        "first" | "front" => Some("0".to_owned()),
        _ => None,
    }
}

fn range_or_slice_index_type(type_name: &str) -> bool {
    type_name.contains("std::ops::Range")
        || type_name.contains("core::ops::Range")
        || type_name.contains("RangeFrom<")
        || type_name.contains("RangeInclusive<")
        || type_name.contains("RangeTo<")
        || type_name.contains("RangeToInclusive<")
        || type_name.contains("RangeFull")
}

fn slice_range_kind(type_name: &str) -> Option<SliceRangeKind> {
    let normalized = type_name.split_whitespace().collect::<String>();
    match normalized.as_str() {
        "std::ops::Range<usize>" | "core::ops::Range<usize>" | "Range<usize>" => {
            Some(SliceRangeKind::Range)
        }
        "std::ops::RangeInclusive<usize>"
        | "core::ops::RangeInclusive<usize>"
        | "RangeInclusive<usize>" => Some(SliceRangeKind::RangeInclusive),
        "std::ops::RangeFrom<usize>" | "core::ops::RangeFrom<usize>" | "RangeFrom<usize>" => {
            Some(SliceRangeKind::RangeFrom)
        }
        "std::ops::RangeTo<usize>" | "core::ops::RangeTo<usize>" | "RangeTo<usize>" => {
            Some(SliceRangeKind::RangeTo)
        }
        "std::ops::RangeToInclusive<usize>"
        | "core::ops::RangeToInclusive<usize>"
        | "RangeToInclusive<usize>" => Some(SliceRangeKind::RangeToInclusive),
        "std::ops::RangeFull" | "core::ops::RangeFull" | "RangeFull" => {
            Some(SliceRangeKind::RangeFull)
        }
        _ => None,
    }
}

fn slice_origin_adjusted_index(
    origin: &ReturnedBorrowSliceStorageOrigin,
    inner_index: &str,
) -> Option<String> {
    let inner_index = inner_index.parse::<usize>().ok()?;
    let absolute = origin.start_offset.checked_add(inner_index)?;
    origin
        .end_offset
        .is_none_or(|end_offset| absolute < end_offset)
        .then(|| absolute.to_string())
}

fn returned_borrow_collection_tail_use(def_path: &str) -> bool {
    method_name(def_path)
        .as_deref()
        .is_some_and(|method| matches!(method, "last" | "back"))
}

fn returned_borrow_collection_use_index_for_storage(
    def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'_>>],
    storage_key: &str,
    indexed_sequence_lengths: &BTreeMap<String, usize>,
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<String> {
    match method_name(def_path).as_deref()? {
        "last" | "back" => indexed_sequence_lengths
            .get(storage_key)
            .and_then(|length| length.checked_sub(1))
            .map(|index| index.to_string()),
        _ => returned_borrow_collection_use_index(def_path, args, stable_constant_origins),
    }
}

fn returned_borrow_slice_collection_use_index_for_storage(
    def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'_>>],
    origin: &ReturnedBorrowSliceStorageOrigin,
    base_storage_key: &str,
    indexed_sequence_lengths: &BTreeMap<String, usize>,
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<String> {
    match method_name(def_path).as_deref()? {
        "last" | "back" => {
            let absolute = if let Some(end_offset) = origin.end_offset {
                end_offset.checked_sub(1)?
            } else {
                indexed_sequence_lengths
                    .get(base_storage_key)
                    .and_then(|length| length.checked_sub(1))?
            };
            (absolute >= origin.start_offset).then(|| absolute.to_string())
        }
        _ => returned_borrow_collection_use_index(def_path, args, stable_constant_origins)
            .and_then(|index| slice_origin_adjusted_index(origin, &index)),
    }
}

fn returned_borrow_iterator_nth_index(
    def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'_>>],
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<usize> {
    if method_name(def_path).as_deref() != Some("nth") {
        return None;
    }
    args.get(1)
        .and_then(|arg| usize_constant_operand_key_with_origins(&arg.node, stable_constant_origins))
        .and_then(|index| index.parse::<usize>().ok())
}

fn returned_borrow_iterator_skip_index(
    def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'_>>],
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<usize> {
    if method_name(def_path).as_deref() != Some("skip") {
        return None;
    }
    args.get(1)
        .and_then(|arg| usize_constant_operand_key_with_origins(&arg.node, stable_constant_origins))
        .and_then(|index| index.parse::<usize>().ok())
}

fn returned_borrow_iterator_take_limit(
    def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'_>>],
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<usize> {
    if method_name(def_path).as_deref() != Some("take") {
        return None;
    }
    args.get(1)
        .and_then(|arg| usize_constant_operand_key_with_origins(&arg.node, stable_constant_origins))
        .and_then(|limit| limit.parse::<usize>().ok())
}

fn returned_borrow_iterator_take_after_skip(
    existing: Option<usize>,
    existing_from_back: Option<bool>,
    skip_from_back: bool,
    consumed: usize,
) -> Option<(Option<usize>, Option<bool>)> {
    let Some(existing) = existing else {
        return Some((None, None));
    };
    if existing_from_back != Some(skip_from_back) {
        return None;
    }
    Some((Some(existing.saturating_sub(consumed)), existing_from_back))
}

fn returned_borrow_iterator_take_after_take(
    existing: Option<usize>,
    existing_from_back: Option<bool>,
    take_from_back: bool,
    limit: usize,
) -> Option<(usize, bool)> {
    let Some(existing) = existing else {
        return Some((limit, take_from_back));
    };
    if existing_from_back != Some(take_from_back) {
        return None;
    }
    Some((existing.min(limit), take_from_back))
}

fn iterator_adapter_gap_kind(method: &str) -> Option<ObjectBindingGapKind> {
    match method {
        "filter" => Some(ObjectBindingGapKind::SelectionPredicate),
        "map" | "filter_map" => Some(ObjectBindingGapKind::MappedValue),
        "chain" => Some(ObjectBindingGapKind::MergedSources),
        "zip" => Some(ObjectBindingGapKind::TupleProjection),
        "flat_map" => Some(ObjectBindingGapKind::CardinalityTransform),
        _ => None,
    }
}

fn returned_borrow_iterator_take_limit_allows(limit: Option<usize>, offset: usize) -> bool {
    limit.is_none_or(|limit| offset < limit)
}

fn returned_borrow_iterator_last_index(
    origin: &IndexedIteratorStorageOrigin,
    indexed_sequence_lengths: &BTreeMap<String, usize>,
) -> Option<usize> {
    let (front_index, back_index) =
        returned_borrow_iterator_selectable_range(origin, indexed_sequence_lengths)?;
    if origin.from_back {
        return Some(front_index);
    }
    Some(back_index)
}

fn returned_borrow_iterator_directional_index(
    origin: &IndexedIteratorStorageOrigin,
    indexed_sequence_lengths: &BTreeMap<String, usize>,
    offset: usize,
) -> Option<usize> {
    if !returned_borrow_iterator_take_limit_allows(origin.take_limit, offset) {
        return None;
    }
    if origin.allow_forward_without_sequence_length && !origin.from_back {
        return origin.front_offset.checked_add(offset);
    }
    let (front_index, back_index) =
        returned_borrow_iterator_selectable_range(origin, indexed_sequence_lengths)?;
    if origin.from_back {
        return back_index
            .checked_sub(offset)
            .filter(|index| *index >= front_index);
    }
    front_index
        .checked_add(offset)
        .filter(|index| *index <= back_index)
}

fn returned_borrow_iterator_selectable_range(
    origin: &IndexedIteratorStorageOrigin,
    indexed_sequence_lengths: &BTreeMap<String, usize>,
) -> Option<(usize, usize)> {
    let last_index = indexed_sequence_lengths
        .get(&origin.storage_key)
        .and_then(|length| length.checked_sub(1))?;
    let back_index = last_index.checked_sub(origin.back_offset)?;
    let (front_index, back_index) = match (origin.take_limit, origin.take_from_back) {
        (Some(0), _) => return None,
        (Some(limit), Some(false)) => {
            let bounded_back = origin
                .front_offset
                .checked_add(limit.checked_sub(1)?)?
                .min(back_index);
            (origin.front_offset, bounded_back)
        }
        (Some(limit), Some(true)) => {
            let bounded_front = back_index
                .checked_sub(limit.checked_sub(1)?)
                .map_or(origin.front_offset, |index| index.max(origin.front_offset));
            (bounded_front, back_index)
        }
        (Some(_), None) => return None,
        (None, _) => (origin.front_offset, back_index),
    };
    (front_index <= back_index).then_some((front_index, back_index))
}

fn returned_borrow_iterator_min_sequence_len(
    front_offset: usize,
    back_offset: usize,
    extra_offset: usize,
) -> Option<usize> {
    front_offset
        .checked_add(back_offset)?
        .checked_add(extra_offset)?
        .checked_add(1)
}

fn returned_borrow_keyed_map_insert_key(
    def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'_>>],
    stable_constant_origins: &BTreeMap<Local, String>,
    scoped_key_origins: &BTreeMap<Local, String>,
    dynamic_key_generations: &BTreeMap<Local, u32>,
    owner_def_path: &str,
) -> Option<String> {
    if method_name(def_path).as_deref() != Some("insert") {
        return None;
    }
    args.get(1).and_then(|arg| {
        scoped_key_operand_key(
            &arg.node,
            stable_constant_origins,
            scoped_key_origins,
            dynamic_key_generations,
            owner_def_path,
        )
    })
}

fn returned_borrow_keyed_map_use_key(
    def_path: &str,
    args: &[super::rustc_span::Spanned<Operand<'_>>],
    stable_constant_origins: &BTreeMap<Local, String>,
    scoped_key_origins: &BTreeMap<Local, String>,
    dynamic_key_generations: &BTreeMap<Local, u32>,
    owner_def_path: &str,
) -> Option<String> {
    if method_name(def_path).as_deref() != Some("get") {
        return None;
    }
    args.get(1).and_then(|arg| {
        scoped_key_operand_key(
            &arg.node,
            stable_constant_origins,
            scoped_key_origins,
            dynamic_key_generations,
            owner_def_path,
        )
    })
}

fn returned_borrow_keyed_map_argument_key(
    args: &[super::rustc_span::Spanned<Operand<'_>>],
    stable_constant_origins: &BTreeMap<Local, String>,
    scoped_key_origins: &BTreeMap<Local, String>,
    dynamic_key_generations: &BTreeMap<Local, u32>,
    owner_def_path: &str,
) -> Option<String> {
    args.get(1).and_then(|arg| {
        scoped_key_operand_key(
            &arg.node,
            stable_constant_origins,
            scoped_key_origins,
            dynamic_key_generations,
            owner_def_path,
        )
    })
}

fn returned_borrow_indexed_sequence_insert_call(def_path: &str, storage_type_name: &str) -> bool {
    method_name(def_path).as_deref() == Some("insert")
        && returned_borrow_indexed_sequence_storage_type(storage_type_name)
}

fn returned_borrow_indexed_sequence_use_call(def_path: &str, storage_type_name: &str) -> bool {
    method_name(def_path)
        .as_deref()
        .is_some_and(|method| matches!(method, "get" | "first" | "front" | "last" | "back"))
        && returned_borrow_indexed_sequence_storage_type(storage_type_name)
}

fn returned_borrow_keyed_map_use_call(def_path: &str, storage_type_name: &str) -> bool {
    method_name(def_path).as_deref() == Some("get")
        && returned_borrow_keyed_map_storage_type(storage_type_name)
}

fn returned_borrow_indexed_sequence_append_call(def_path: &str, storage_type_name: &str) -> bool {
    method_name(def_path)
        .as_deref()
        .is_some_and(|method| matches!(method, "push" | "push_back"))
        && returned_borrow_indexed_sequence_storage_type(storage_type_name)
}

fn returned_borrow_indexed_sequence_empty_constructor_call(
    def_path: &str,
    storage_type_name: &str,
) -> bool {
    method_name(def_path)
        .as_deref()
        .is_some_and(|method| matches!(method, "new" | "default"))
        && returned_borrow_indexed_sequence_storage_type(storage_type_name)
}

fn returned_borrow_keyed_map_empty_constructor_call(
    def_path: &str,
    storage_type_name: &str,
) -> bool {
    method_name(def_path)
        .as_deref()
        .is_some_and(|method| matches!(method, "new" | "default"))
        && returned_borrow_keyed_map_storage_type(storage_type_name)
}

fn returned_borrow_keyed_map_insert_call(def_path: &str, storage_type_name: &str) -> bool {
    method_name(def_path).as_deref() == Some("insert")
        && returned_borrow_keyed_map_storage_type(storage_type_name)
}

fn returned_borrow_collection_storage_type(storage_type_name: &str) -> bool {
    returned_borrow_keyed_map_storage_type(storage_type_name)
        || returned_borrow_indexed_sequence_storage_type(storage_type_name)
}

fn returned_borrow_keyed_map_storage_type(storage_type_name: &str) -> bool {
    let type_name = storage_type_name.to_ascii_lowercase();
    ["hashmap<", "btreemap<", "indexmap<"]
        .iter()
        .any(|token| type_name.contains(token))
}

fn returned_borrow_indexed_sequence_storage_type(storage_type_name: &str) -> bool {
    let type_name = storage_type_name.to_ascii_lowercase();
    [
        "vec<",
        "vecdeque<",
        "smallvec<",
        "[&",
        "[std::option::option<&",
        "[core::option::option<&",
    ]
    .iter()
    .any(|token| type_name.contains(token))
}

fn indexed_returned_borrow_storage_key(storage_key: &str, index: &str) -> String {
    format!("{storage_key}:element_index:{index}")
}

fn indexed_sequence_returned_borrow_storage_prefix(storage_key: &str) -> String {
    format!("{storage_key}:element_index:")
}

fn keyed_map_returned_borrow_storage_key(storage_key: &str, key: &str) -> String {
    format!("{storage_key}:map_key:{key}")
}

fn keyed_map_returned_borrow_storage_prefix(storage_key: &str) -> String {
    format!("{storage_key}:map_key:")
}

fn keyed_map_entry_origin_with_projection(
    origin: &KeyedMapEntryOrigin,
    projection_kind: KeyedMapEntryProjectionKind,
    projection_order_key: Option<MirOrderKey>,
) -> KeyedMapEntryOrigin {
    let mut origin = origin.clone();
    origin.projection_kind = Some(projection_kind);
    if let Some(projection_order_key) = projection_order_key {
        origin.projection_order_key = Some(projection_order_key);
    }
    origin
}

fn keyed_map_entry_branch_tracking_key(origin: &KeyedMapEntryOrigin, storage_key: &str) -> String {
    format!("{}:{storage_key}", origin.entry_site_id)
}

fn merge_keyed_map_entry_branch_write(
    slot: &mut KeyedMapEntryBranchWrite,
    incoming: KeyedMapEntryBranchWrite,
) {
    let current = std::mem::replace(slot, KeyedMapEntryBranchWrite::Unseen);
    *slot = match (current, incoming) {
        (KeyedMapEntryBranchWrite::Unseen, incoming) => incoming,
        (current, KeyedMapEntryBranchWrite::Unseen) => current,
        (KeyedMapEntryBranchWrite::Ambiguous, _) | (_, KeyedMapEntryBranchWrite::Ambiguous) => {
            KeyedMapEntryBranchWrite::Ambiguous
        }
        (KeyedMapEntryBranchWrite::Blocked, KeyedMapEntryBranchWrite::Blocked) => {
            KeyedMapEntryBranchWrite::Blocked
        }
        (KeyedMapEntryBranchWrite::Returned(left), KeyedMapEntryBranchWrite::Returned(right))
            if left == right =>
        {
            KeyedMapEntryBranchWrite::Returned(left)
        }
        _ => KeyedMapEntryBranchWrite::Ambiguous,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyedMapEntryProjectionKind {
    Occupied,
    Vacant,
}

fn keyed_map_entry_projection_kind(place: &Place<'_>) -> Option<KeyedMapEntryProjectionKind> {
    if place.projection.len() != 2 || !matches!(place.projection[0], ProjectionElem::Downcast(..)) {
        return None;
    }
    let ProjectionElem::Field(field, field_ty) = place.projection[1] else {
        return None;
    };
    if field.index() != 0 {
        return None;
    }
    let field_ty = field_ty.to_string().to_ascii_lowercase();
    if field_ty.contains("occupiedentry<") {
        Some(KeyedMapEntryProjectionKind::Occupied)
    } else if field_ty.contains("vacantentry<") {
        Some(KeyedMapEntryProjectionKind::Vacant)
    } else {
        None
    }
}

fn returned_borrow_storage_use_source_place<'tcx>(rvalue: &Rvalue<'tcx>) -> Option<Place<'tcx>> {
    match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => operand.place(),
        Rvalue::Ref(_, _, source_place) => Some(*source_place),
        _ => None,
    }
}

fn closure_capture_use_source_place<'tcx>(rvalue: &Rvalue<'tcx>) -> Option<Place<'tcx>> {
    match rvalue {
        Rvalue::Use(operand, _) | Rvalue::Cast(_, operand, _) => operand.place(),
        Rvalue::Ref(_, _, source_place) => Some(*source_place),
        _ => None,
    }
}

fn stable_constant_operand_key(operand: &Operand<'_>) -> Option<String> {
    string_constant_operand_key(operand)
        .map(|key| format!("str:{key}"))
        .or_else(|| usize_constant_operand_key(operand).map(|key| format!("usize:{key}")))
}

fn stable_constant_operand_key_with_origins(
    operand: &Operand<'_>,
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<String> {
    stable_constant_operand_key(operand).or_else(|| {
        let place = operand.place()?;
        place
            .projection
            .is_empty()
            .then(|| stable_constant_origins.get(&place.local).cloned())
            .flatten()
    })
}

fn usize_constant_operand_key_with_origins(
    operand: &Operand<'_>,
    stable_constant_origins: &BTreeMap<Local, String>,
) -> Option<String> {
    usize_constant_operand_key(operand).or_else(|| {
        stable_constant_operand_key_with_origins(operand, stable_constant_origins)
            .and_then(|key| key.strip_prefix("usize:").map(ToOwned::to_owned))
    })
}

fn scoped_key_operand_key(
    operand: &Operand<'_>,
    stable_constant_origins: &BTreeMap<Local, String>,
    scoped_key_origins: &BTreeMap<Local, String>,
    dynamic_key_generations: &BTreeMap<Local, u32>,
    owner_def_path: &str,
) -> Option<String> {
    stable_constant_operand_key_with_origins(operand, stable_constant_origins)
        .or_else(|| scoped_key_origin_from_operand(operand, scoped_key_origins))
        .or_else(|| {
            scoped_dynamic_key_from_operand(operand, dynamic_key_generations, owner_def_path)
        })
}

fn scoped_key_origin_from_operand(
    operand: &Operand<'_>,
    scoped_key_origins: &BTreeMap<Local, String>,
) -> Option<String> {
    let place = operand.place()?;
    place
        .projection
        .is_empty()
        .then(|| scoped_key_origins.get(&place.local).cloned())
        .flatten()
}

fn scoped_dynamic_key_from_operand(
    operand: &Operand<'_>,
    dynamic_key_generations: &BTreeMap<Local, u32>,
    owner_def_path: &str,
) -> Option<String> {
    let place = operand.place()?;
    if !place.projection.is_empty() {
        return None;
    }
    let generation = dynamic_key_generations
        .get(&place.local)
        .copied()
        .unwrap_or(0);
    Some(format!(
        "dynamic_local:{}:l{}:g{}",
        short_digest(owner_def_path),
        place.local.index(),
        generation
    ))
}

fn string_key_passthrough_call(def_path: &str) -> bool {
    let Some(method) = method_name(def_path) else {
        return false;
    };
    matches!(method.as_str(), "to_owned" | "to_string" | "from" | "clone")
}

fn owned_string_key_type(type_name: &str) -> bool {
    let type_name = type_name.to_ascii_lowercase();
    type_name == "string" || type_name.ends_with("::string") || type_name.contains("string::string")
}

fn string_like_key_type(type_name: &str) -> bool {
    let type_name = type_name.to_ascii_lowercase();
    type_name.contains("str") || owned_string_key_type(&type_name)
}

fn short_digest(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn string_constant_operand_key(operand: &Operand<'_>) -> Option<String> {
    let snippet = format!("{operand:?}");
    quoted_debug_string_tokens(&snippet)
        .into_iter()
        .next()
        .map(|token| sanitize_storage_key_token(&token))
}

fn quoted_debug_string_tokens(snippet: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = snippet.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut token = String::new();
        let mut escaped = false;
        for (_, inner) in chars.by_ref() {
            if escaped {
                token.push(inner);
                escaped = false;
                continue;
            }
            if inner == '\\' {
                escaped = true;
                continue;
            }
            if inner == '"' {
                break;
            }
            token.push(inner);
        }
        if !token.is_empty() {
            tokens.push(token);
        }
    }
    tokens
}

fn sanitize_storage_key_token(token: &str) -> String {
    token
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn usize_constant_operand_key(operand: &Operand<'_>) -> Option<String> {
    let snippet = format!("{operand:?}");
    let after_const = snippet
        .find("const")
        .map(|index| &snippet[index + "const".len()..])?;
    let mut digits = String::new();
    let mut started = false;
    for ch in after_const.chars() {
        if ch.is_ascii_digit() {
            started = true;
            digits.push(ch);
            continue;
        }
        if started {
            break;
        }
        if !ch.is_whitespace() && ch != '_' {
            return None;
        }
    }
    (!digits.is_empty()).then_some(digits)
}

fn debug_usize_field(snippet: &str, field: &str) -> Option<usize> {
    let needle = format!("{field}:");
    let after_field = snippet
        .find(&needle)
        .map(|index| &snippet[index + needle.len()..])?;
    let mut digits = String::new();
    let mut started = false;
    for ch in after_field.chars() {
        if ch.is_ascii_digit() {
            started = true;
            digits.push(ch);
            continue;
        }
        if started {
            break;
        }
        if !ch.is_whitespace() && ch != '_' {
            return None;
        }
    }
    (!digits.is_empty())
        .then(|| digits.parse::<usize>().ok())
        .flatten()
}

fn returned_borrow_storage_use_type(ty: Ty<'_>) -> bool {
    let type_name = ty.to_string().to_ascii_lowercase();
    let collection_with_borrow = [
        "hashmap<",
        "btreemap<",
        "indexmap<",
        "vec<",
        "vecdeque<",
        "smallvec<",
    ]
    .iter()
    .any(|token| type_name.contains(token))
        || type_name.contains("std::option::option<&")
        || type_name.contains("core::option::option<&")
        || type_name.contains("option<&")
        || type_name.contains("[&")
        || type_name.contains("[std::option::option<&")
        || type_name.contains("[core::option::option<&")
        || type_name.contains("[option<&");
    collection_with_borrow && type_name.contains('&')
}

fn returned_borrow_value_argument_use_type(ty: Ty<'_>) -> bool {
    let type_name = ty.to_string().to_ascii_lowercase();
    if type_name.contains("&mut") || returned_borrow_collection_storage_type(&type_name) {
        return false;
    }
    type_name.contains("option<&") || type_name.trim_start().starts_with('&')
}

fn unconstrained_return_lifetime_relation<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: LocalDefId,
    owner_def_path: &str,
) -> Option<ReturnedBorrowRelationObservation> {
    let node = tcx.hir_node_by_def_id(def_id);
    let sig = node.fn_sig()?;
    if !matches!(
        sig.decl.implicit_self(),
        hir::ImplicitSelfKind::RefImm | hir::ImplicitSelfKind::RefMut
    ) || !sig
        .decl
        .inputs
        .first()
        .is_some_and(hir_ty_contains_reference)
    {
        return None;
    }

    let hir::FnRetTy::Return(output_ty) = sig.decl.output else {
        return None;
    };
    let declared_lifetimes = function_declared_lifetime_params(node.generics()?);
    if declared_lifetimes.is_empty() {
        return None;
    }
    let mut input_lifetimes = BTreeSet::<usize>::new();
    for input in sig.decl.inputs {
        collect_hir_lifetime_params_from_ty(input, &mut input_lifetimes);
    }
    let mut output_lifetimes = BTreeSet::<usize>::new();
    collect_hir_lifetime_params_from_ty(output_ty, &mut output_lifetimes);
    if !output_lifetimes.iter().any(|lifetime| {
        declared_lifetimes.contains(lifetime) && !input_lifetimes.contains(lifetime)
    }) {
        return None;
    }

    let source_path = source_path(tcx, sig.span).ok()?;
    let stable_span = stable_span(tcx, sig.span).ok()?;
    let returned_type_name = tcx
        .fn_sig(def_id.to_def_id())
        .instantiate_identity()
        .skip_binder()
        .output()
        .to_string();
    let receiver_type_name = sig
        .decl
        .inputs
        .first()
        .and_then(|input| tcx.sess.source_map().span_to_snippet(input.span).ok())
        .unwrap_or_else(|| "signature_receiver".to_owned());
    Some(ReturnedBorrowRelationObservation {
        owner_def_path: owner_def_path.to_owned(),
        source_path: source_path.clone(),
        span: stable_span.clone(),
        mir_location: "hir_signature:unconstrained_return_lifetime".to_owned(),
        api_id: owner_def_path.to_owned(),
        relation_kind: Some(ReturnedBorrowRelationKind::UnconstrainedReturnLifetime),
        source: BorrowReference {
            owner_def_path: owner_def_path.to_owned(),
            source_path,
            span: stable_span,
            mir_location: "hir_signature:receiver".to_owned(),
            type_name: receiver_type_name,
        },
        returned_type_name,
    })
}

fn arena_into_iter_unconstrained_lifetime_relation<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: LocalDefId,
    owner_def_path: &str,
) -> Option<ReturnedBorrowRelationObservation> {
    let owner_identity = owner_def_path.to_ascii_lowercase();
    if !owner_identity.ends_with("::into_iter") || !owner_identity.contains("intoiterator") {
        return None;
    }
    if !owner_def_path.contains('\'')
        || !(owner_identity.contains("arena") || owner_identity.contains("bump"))
    {
        return None;
    }

    let node = tcx.hir_node_by_def_id(def_id);
    let sig = node.fn_sig()?;
    let hir::FnRetTy::Return(output_ty) = sig.decl.output else {
        return None;
    };

    let output_type_name = tcx
        .fn_sig(def_id.to_def_id())
        .instantiate_identity()
        .skip_binder()
        .output()
        .to_string();
    let output_snippet = tcx
        .sess
        .source_map()
        .span_to_snippet(output_ty.span)
        .unwrap_or_default();
    let output_identity = format!("{output_snippet} {output_type_name}").to_ascii_lowercase();
    if !(output_identity.contains("intoiter") || output_identity.contains("into_iter")) {
        return None;
    }

    let mut output_lifetimes = BTreeSet::<usize>::new();
    collect_hir_lifetime_params_from_ty(output_ty, &mut output_lifetimes);
    if !output_lifetimes.is_empty() {
        return None;
    }

    let source_path = source_path(tcx, output_ty.span).ok()?;
    let stable_span = stable_span(tcx, output_ty.span).ok()?;
    let receiver_type_name = sig
        .decl
        .inputs
        .first()
        .and_then(|input| tcx.sess.source_map().span_to_snippet(input.span).ok())
        .unwrap_or_else(|| owner_def_path.to_owned());
    Some(ReturnedBorrowRelationObservation {
        owner_def_path: owner_def_path.to_owned(),
        source_path: source_path.clone(),
        span: stable_span.clone(),
        mir_location: "hir_signature:arena_into_iter_unconstrained_lifetime".to_owned(),
        api_id: owner_def_path.to_owned(),
        relation_kind: Some(ReturnedBorrowRelationKind::UnconstrainedReturnLifetime),
        source: BorrowReference {
            owner_def_path: owner_def_path.to_owned(),
            source_path,
            span: stable_span,
            mir_location: "hir_signature:arena_into_iter_receiver".to_owned(),
            type_name: receiver_type_name,
        },
        returned_type_name: output_type_name,
    })
}

/// 从 HIR 签名读出每个回调泛型参数的生命周期 bound。
///
/// 形状（`rusqlite` 0.26.1 `hooks.rs`）：
///
/// ```ignore
/// fn update_hook<'c, F>(&'c mut self, hook: Option<F>)
/// where F: FnMut(..) + Send + 'c,        // ← 'c 来自 receiver，不是 'static
/// { .. ffi::sqlite3_update_hook(.., Some(trampoline::<F>), boxed as *mut c_void) }
/// ```
///
/// 0.26.2 把这里改成 `+ 'static` 就修好了，所以判据必须是"bound 指向本函数声明的某个
/// lifetime 参数"，而不是"存在 lifetime bound"——`'static` 不是声明的参数，因此
/// [`hir_lifetime_param_index`] 对它返回 `None`，收紧后的版本自然落到
/// [`CallbackLifetimeBoundScope::StaticLifetime`]。
///
/// 与 [`unconstrained_return_lifetime_relation`] 是同一族分析：都只读 HIR 签名，不需要
/// 任何调用代码。区别在于那个看**返回值**的 lifetime 是否被输入约束，这个看**回调参数**
/// 的存活期是否短于外部持有期。**不要把它并进 `ReturnedBorrowRelationKind`**——那是
/// "返回借用"家族，混进去就是又一次"读了相邻属性"。
///
/// 健全的两种 scope 也照样产出事实：缺证（没有事实）与"已检查且健全"必须可区分，这正是
/// `callback_bound_scope` 的 `Undecided` 存在的同一个理由。
fn callback_lifetime_bounds<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: LocalDefId,
    owner_def_path: &str,
) -> Vec<CallbackLifetimeBoundObservation> {
    let node = tcx.hir_node_by_def_id(def_id);
    let Some(sig) = node.fn_sig() else {
        return Vec::new();
    };
    let Some(generics) = node.generics() else {
        return Vec::new();
    };
    let Ok(source_path) = source_path(tcx, sig.span) else {
        return Vec::new();
    };
    let Ok(stable_span) = stable_span(tcx, sig.span) else {
        return Vec::new();
    };

    let declared_lifetimes = function_declared_lifetime_params(generics);
    // receiver 上出现的 lifetime。回调 bound 落在其中之一时，它的存活期就被绑在一次
    // 借用上，而外部持有方并不受那次借用约束。
    let mut receiver_lifetimes = BTreeSet::<usize>::new();
    if let Some(receiver) = sig.decl.inputs.first() {
        collect_hir_lifetime_params_from_ty(receiver, &mut receiver_lifetimes);
    }

    // 同一个泛型参数的 bound 可能散在多条 predicate 里：`where F: FnMut(), F: 'c` 是
    // 合法写法，rustc 也会把内联 bound 和 where 子句降成各自的 predicate。逐条判定会
    // 让前一条读成 `NoLifetimeBound`——一个看起来完全正常的结果，正是这类缺陷最难发现
    // 的失败方式。所以先按参数名把 bound 全部聚起来，再判一次。
    let mut bounds_by_param = BTreeMap::<String, Vec<&hir::GenericBound<'_>>>::new();
    for predicate in generics.predicates {
        let hir::WherePredicateKind::BoundPredicate(bound_predicate) = predicate.kind else {
            continue;
        };
        let Some(param_name) = declared_type_param_name(generics, bound_predicate.bounded_ty)
        else {
            continue;
        };
        bounds_by_param
            .entry(param_name)
            .or_default()
            .extend(bound_predicate.bounds);
    }

    let mut observations = bounds_by_param
        .into_iter()
        // 判据是"回调参数"，不是"任何被约束的泛型参数"：没有 `Fn` 家族 bound 的一律不出
        // 事实，否则 `T: Clone + 'c` 也会被当成回调。
        .filter(|(_, bounds)| {
            bounds
                .iter()
                .any(|bound| hir_bound_is_callable_trait(bound))
        })
        .map(|(callback_param, bounds)| {
            let (bound_lifetime, bound_scope) =
                callback_bound_scope_from_bounds(&bounds, &declared_lifetimes, &receiver_lifetimes);
            CallbackLifetimeBoundObservation {
                owner_def_path: owner_def_path.to_owned(),
                source_path: source_path.clone(),
                span: stable_span.clone(),
                mir_location: format!("hir_signature:callback_lifetime_bound:{callback_param}"),
                api_id: owner_def_path.to_owned(),
                callback_param,
                bound_lifetime,
                bound_scope,
            }
        })
        .collect::<Vec<_>>();

    // trait object 形式的回调（`Box<dyn FnMut()>`、`&'c mut dyn FnMut()`）不出现在
    // `generics.predicates` 里——它们是**参数类型**，不是被约束的泛型参数。上面那段
    // 完全看不到它们，实测确认过：`boxed_dyn_default` 一条事实都不产出。
    //
    // 这是漏报而不是误报，所以更难发现：扫描退出成功、结果看起来正常，只是少了一整类
    // 交出点。
    for (index, input) in sig.decl.inputs.iter().enumerate() {
        let Some(resolved) =
            callback_trait_object_lifetime(input, ObjectLifetimeContext::Unknown)
        else {
            continue;
        };
        let (bound_lifetime, bound_scope) =
            trait_object_callback_scope(&resolved, &declared_lifetimes, &receiver_lifetimes);
        let callback_param = format!("arg{index}");
        observations.push(CallbackLifetimeBoundObservation {
            owner_def_path: owner_def_path.to_owned(),
            source_path: source_path.clone(),
            span: stable_span.clone(),
            mir_location: format!("hir_signature:callback_lifetime_bound:{callback_param}"),
            api_id: owner_def_path.to_owned(),
            callback_param,
            bound_lifetime,
            bound_scope,
        });
    }

    observations
}

/// registration guard：安全 API 是否返回一个把注册存活绑到被捕对象上的值。
///
/// 判据来自 `docs/roadmap/implementation-plan.md` 的 PG-1，三条同时成立才算 guard：
///
/// 1. 返回类型带**本函数声明的** lifetime 参数；
/// 2. 该 lifetime 与回调 bound 指向**同一个**声明——绑到别的 lifetime 上，约束的就不是
///    这个回调捕获的东西；
/// 3. 返回类型的 `Drop` impl 里有一次指向外部函数的调用。
///
/// # 第 3 条为什么不查 API map 的注销角色
///
/// 计划原文写的是"指向注销角色 API 的调用"，而角色分类目前只能来自人工 API map
/// （`registration.rs` 的 `classify_call`）。用它做必要条件有两个后果：guard 检测只能在
/// 有清单的 crate 上工作，规模化的猎物探针拿不到这个事实；而且它把人工标注的语义当成了
/// Rust 侧观察。
///
/// 更重要的是，**"Rust 只能看到 `Drop` 调了某个外部函数、判断不了它是否真的清空槽位"
/// 正是要外部侧证据的那条论证本身**（research thesis §2.6）。所以这里只判"调了外部
/// 函数"这个 Rust 侧看得见的形状，是否真的注销由 Q4′ 回答。有 API map 时角色信息仍在
/// `RegistrationSiteFact` 里，可作为交叉验证，不作必要条件。
///
/// # 不产出 `OwnerDropUnregisters`
///
/// 那一取值的判据是 owner 类型 drop 路径的证明，与 `ReleasePathProofFact` 同源，不是
/// 返回值形状。PG-1 不覆盖它。
fn registration_guards<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: LocalDefId,
    owner_def_path: &str,
) -> Vec<RegistrationGuardObservation> {
    let node = tcx.hir_node_by_def_id(def_id);
    let Some(sig) = node.fn_sig() else {
        return Vec::new();
    };
    let Some(generics) = node.generics() else {
        return Vec::new();
    };
    let Ok(source_path) = source_path(tcx, sig.span) else {
        return Vec::new();
    };
    let Ok(stable_span) = stable_span(tcx, sig.span) else {
        return Vec::new();
    };

    let declared_lifetimes = function_declared_lifetime_params(generics);
    let callback_params = callback_param_bound_lifetimes(generics, &declared_lifetimes);
    if callback_params.is_empty() {
        return Vec::new();
    }

    // 返回类型上出现的、本函数声明的 lifetime。空集意味着返回值没有把任何东西绑住。
    let mut return_lifetimes = BTreeSet::<usize>::new();
    let return_ty = match sig.decl.output {
        hir::FnRetTy::Return(ty) => {
            collect_hir_lifetime_params_from_ty(ty, &mut return_lifetimes);
            Some(ty)
        }
        hir::FnRetTy::DefaultReturn(_) => None,
    };
    return_lifetimes.retain(|index| declared_lifetimes.contains(index));

    let guard_adt = return_ty.and_then(|ty| return_type_adt(tcx, ty));
    let drop_evidence = guard_adt.map(|adt| adt_drop_foreign_call(tcx, adt));

    callback_params
        .into_iter()
        .map(|(callback_param, bound_lifetimes)| {
            let ties_to_callback_bound = bound_lifetimes
                .iter()
                .any(|index| return_lifetimes.contains(index));
            let (guard, foreign_release_callee) = if return_lifetimes.is_empty() {
                // 返回值不携带任何声明 lifetime：注册的存活没有被绑到调用方的任何东西上。
                (RegistrationGuard::None, None)
            } else if !ties_to_callback_bound {
                if bound_lifetimes.is_empty() {
                    // 回调没有显式 outlives bound，返回值却带 lifetime。形状像 guard，但
                    // 类型层没有写下"注册活得不比被捕对象久"这句话。**不猜。**
                    (RegistrationGuard::Unresolved, None)
                } else {
                    // 绑在另一个声明 lifetime 上——约束的不是这个回调捕获的对象。
                    (RegistrationGuard::None, None)
                }
            } else {
                match &drop_evidence {
                    // 解析不到 ADT（`impl Trait`、类型别名、投影……），说不出它 drop 时做什么。
                    None => (RegistrationGuard::Unresolved, None),
                    Some(DropForeignCall::Foreign(callee)) => {
                        (RegistrationGuard::TiesSlotToSubject, Some(callee.clone()))
                    }
                    // 没有 `Drop` impl：guard 消失时不注销任何东西，与没有 guard 等价。
                    Some(DropForeignCall::NoDestructor) => (RegistrationGuard::None, None),
                    // drop 里一次调用都没有，同样不可能注销。
                    Some(DropForeignCall::NoCalls) => (RegistrationGuard::None, None),
                    // 只调了 Rust 函数：外部调用可能藏在被调方里，有界分析看不到。
                    Some(DropForeignCall::OnlyRustCalls) => (RegistrationGuard::Unresolved, None),
                    // 跨 crate 的 ADT 拿不到 drop 的 MIR。
                    Some(DropForeignCall::MirUnavailable) => (RegistrationGuard::Unresolved, None),
                }
            };
            RegistrationGuardObservation {
                owner_def_path: owner_def_path.to_owned(),
                source_path: source_path.clone(),
                span: stable_span.clone(),
                mir_location: format!("hir_signature:registration_guard:{callback_param}"),
                api_id: owner_def_path.to_owned(),
                callback_param,
                guard_type: guard_adt.map(|adt| tcx.def_path_str(adt)),
                foreign_release_callee,
                guard,
            }
        })
        .collect()
}

/// 回调分配交出之后由谁负责释放（PG-2）。
///
/// 判据只用本函数体内的 raw pointer 转移事实：
///
/// - 同一分配上既有 `into_raw` 又有配对的 `from_raw` → Rust 侧仍有回收路径；
/// - 只有 `into_raw`、没有任何回收 → 交出后本体内不再回收；
/// - 其余一律缺证。
///
/// **配对靠的是 `user_data` 引用本身，不是位置相邻。** `raw_pointer_reference_from_operand`
/// 会把 `from_raw(boxed)` 的实参解析回产生 `boxed` 的那次 `into_raw`，因此同一分配的
/// 两次转移携带**同一个** [`RawPointerReference`]。已实测确认。
///
/// # 取值方向不对称
///
/// [`AllocationOwnership::ForeignOwnedUntilUnregister`] 会**否定**分离可能性、把判定推
/// 向相容，因此它是"漏报方向"的取值，只在能确证本体内没有回收路径时才给。
/// [`AllocationOwnership::RustRetainsAndMayFreeEarly`] 是"误报方向"，需要配对证据。
/// 两者都证不出来时落 [`AllocationOwnership::Unresolved`]。
///
/// # 已知覆盖缺口
///
/// - **一个函数里有多个回调参数**：本体级的转移事实无法归属到具体哪一个，全部落缺证；
/// - **分配发生在别的函数里**（helper 里 box、这里只收 raw pointer）：看不到 `into_raw`，
///   落缺证；
/// - **指针逃逸后由别处回收**：本体内没有 `from_raw` 不等于没有别的 Rust 代码会回收它。
///   这一条是首期片段的明确 limitation，见 `docs/roadmap/execution-plan.md` 阶段 1.1。
fn allocation_ownerships(
    tcx: TyCtxt<'_>,
    def_id: LocalDefId,
    owner_def_path: &str,
    transfers: &[RawPointerTransferObservation],
) -> Vec<AllocationOwnershipObservation> {
    let node = tcx.hir_node_by_def_id(def_id);
    let Some(sig) = node.fn_sig() else {
        return Vec::new();
    };
    let Some(generics) = node.generics() else {
        return Vec::new();
    };
    let Ok(source_path) = source_path(tcx, sig.span) else {
        return Vec::new();
    };
    let Ok(stable_span) = stable_span(tcx, sig.span) else {
        return Vec::new();
    };

    let declared_lifetimes = function_declared_lifetime_params(generics);
    let callback_params = callback_param_bound_lifetimes(generics, &declared_lifetimes);
    if callback_params.is_empty() {
        return Vec::new();
    }
    // 多个回调参数时，本体级的转移事实归属不到具体哪一个。**不猜。**
    let attributable = callback_params.len() == 1;

    let into_raws = transfers
        .iter()
        .filter(|transfer| transfer.kind == RawPointerTransferKind::IntoRaw)
        .collect::<Vec<_>>();
    let reclaims = transfers
        .iter()
        .filter(|transfer| {
            matches!(
                transfer.kind,
                RawPointerTransferKind::FromRaw | RawPointerTransferKind::FromRawParts
            )
        })
        .collect::<Vec<_>>();

    // 同一分配上的 into_raw / 回收配对。
    let paired = into_raws.iter().find_map(|into_raw| {
        reclaims
            .iter()
            .find(|reclaim| reclaim.user_data == into_raw.user_data)
            .map(|reclaim| (*into_raw, *reclaim))
    });

    let (ownership, into_raw_mir_location, reclaim_mir_location) = if !attributable {
        (AllocationOwnership::Unresolved, None, None)
    } else if let Some((into_raw, reclaim)) = paired {
        (
            AllocationOwnership::RustRetainsAndMayFreeEarly,
            Some(into_raw.mir_location.clone()),
            Some(reclaim.mir_location.clone()),
        )
    } else if let Some(into_raw) = into_raws.first() {
        if reclaims.is_empty() {
            // 本体内没有任何回收：交出之后这段代码不再碰它。
            (
                AllocationOwnership::ForeignOwnedUntilUnregister,
                Some(into_raw.mir_location.clone()),
                None,
            )
        } else {
            // 有回收，但配不上这次交出——可能是另一个对象，也可能是解析不出同一性。
            (
                AllocationOwnership::Unresolved,
                Some(into_raw.mir_location.clone()),
                None,
            )
        }
    } else {
        // 看不到分配交出点：分配可能发生在别的函数里。
        (AllocationOwnership::Unresolved, None, None)
    };

    callback_params
        .into_iter()
        .map(|(callback_param, _)| AllocationOwnershipObservation {
            owner_def_path: owner_def_path.to_owned(),
            source_path: source_path.clone(),
            span: stable_span.clone(),
            mir_location: format!("hir_signature:allocation_ownership:{callback_param}"),
            api_id: owner_def_path.to_owned(),
            callback_param,
            into_raw_mir_location: into_raw_mir_location.clone(),
            reclaim_mir_location: reclaim_mir_location.clone(),
            ownership,
        })
        .collect()
}

/// 每个回调泛型参数，以及约束它的、本函数声明的 lifetime 参数集合。
///
/// 与 [`callback_lifetime_bounds`] 用同一个"什么算回调参数"的判据（有 `Fn` 家族 bound），
/// 两处必须一致：guard 事实要能按 `callback_param` 与 bound 事实配对。
fn callback_param_bound_lifetimes(
    generics: &hir::Generics<'_>,
    declared_lifetimes: &BTreeSet<usize>,
) -> Vec<(String, BTreeSet<usize>)> {
    let mut bounds_by_param = BTreeMap::<String, Vec<&hir::GenericBound<'_>>>::new();
    for predicate in generics.predicates {
        let hir::WherePredicateKind::BoundPredicate(bound_predicate) = predicate.kind else {
            continue;
        };
        let Some(param_name) = declared_type_param_name(generics, bound_predicate.bounded_ty)
        else {
            continue;
        };
        bounds_by_param
            .entry(param_name)
            .or_default()
            .extend(bound_predicate.bounds);
    }

    bounds_by_param
        .into_iter()
        .filter(|(_, bounds)| {
            bounds
                .iter()
                .any(|bound| hir_bound_is_callable_trait(bound))
        })
        .map(|(param_name, bounds)| {
            let mut lifetimes = BTreeSet::<usize>::new();
            for bound in bounds {
                if let hir::GenericBound::Outlives(lifetime) = bound {
                    collect_hir_lifetime_param(lifetime, &mut lifetimes);
                }
            }
            lifetimes.retain(|index| declared_lifetimes.contains(index));
            (param_name, lifetimes)
        })
        .collect()
}

/// 返回类型直接解析到的 ADT。
///
/// 只认直接写在返回位置上的具名类型；`Result<Registration<'a>, E>` 这类包一层的形状
/// 当前不展开，会落到 [`RegistrationGuard::Unresolved`]，是已知的覆盖缺口而不是判"无 guard"。
fn return_type_adt<'tcx>(tcx: TyCtxt<'tcx>, ty: &hir::Ty<'_>) -> Option<DefId> {
    let hir::TyKind::Path(hir::QPath::Resolved(None, path)) = ty.kind else {
        return None;
    };
    let def_id = match path.res {
        hir::def::Res::Def(DefKind::Struct | DefKind::Enum | DefKind::Union, def_id) => def_id,
        _ => return None,
    };
    // ADT 必须真的是 ADT：`def_kind` 已经保证了，这里只是把 `tcx` 用上以便未来扩展。
    let _ = tcx.def_kind(def_id);
    Some(def_id)
}

/// guard 类型 `Drop` impl 里能观察到什么。每一格都是一个可测量的区别，不是一句"不确定"。
#[derive(Clone, Debug, Eq, PartialEq)]
enum DropForeignCall {
    /// `Drop::drop` 调用了一个外部函数。def path 仅作诊断。
    Foreign(String),
    /// `Drop::drop` 里有调用，但都指向 Rust 函数。
    OnlyRustCalls,
    /// `Drop::drop` 里一次调用都没有。
    NoCalls,
    /// 该类型没有 `Drop` impl。
    NoDestructor,
    /// 有 `Drop` impl，但拿不到它的 MIR（跨 crate 等）。
    MirUnavailable,
}

fn adt_drop_foreign_call<'tcx>(tcx: TyCtxt<'tcx>, adt_def_id: DefId) -> DropForeignCall {
    let Some(destructor) = tcx.adt_destructor(adt_def_id) else {
        return DropForeignCall::NoDestructor;
    };
    let drop_def_id = destructor.did;
    if !tcx.is_mir_available(drop_def_id) {
        return DropForeignCall::MirUnavailable;
    }
    let body = tcx.optimized_mir(drop_def_id);
    let mut saw_call = false;
    for block in body.basic_blocks.iter() {
        let Some(terminator) = &block.terminator else {
            continue;
        };
        let TerminatorKind::Call { func, .. } = &terminator.kind else {
            continue;
        };
        let Some((callee, _)) = func.const_fn_def() else {
            // 间接调用：被调方未知，不能据此判定。
            saw_call = true;
            continue;
        };
        saw_call = true;
        if callee_is_foreign(tcx, callee) {
            return DropForeignCall::Foreign(tcx.def_path_str(callee));
        }
    }
    if saw_call {
        DropForeignCall::OnlyRustCalls
    } else {
        DropForeignCall::NoCalls
    }
}

/// 被调方是否位于边界另一侧。
///
/// `extern {}` 块里的声明是外部项；本地定义但标了 `extern "C"` 的函数不是——它的函数体
/// 仍在本 crate 里，Rust 侧看得见。
fn callee_is_foreign<'tcx>(tcx: TyCtxt<'tcx>, callee: DefId) -> bool {
    tcx.is_foreign_item(callee)
}

/// 省略的 trait object lifetime 默认成什么，取决于它外层是什么。
///
/// `Box<dyn Fn()>` 默认 `'static`、`&'a dyn Fn()` 默认 `'a`——**两者在 HIR 里的
/// `LifetimeKind` 完全相同（都是 `ImplicitObjectLifetimeDefault`）**，只能靠外层容器区分。
/// 已实测确认过这一点；按 lifetime kind 直接分类会把其中一半判反。
#[derive(Clone, Copy)]
enum ObjectLifetimeContext<'hir> {
    /// 直接位于 `&'a` / `&'a mut` 之下：省略的 object lifetime 默认为 `'a`。
    Reference(&'hir hir::Lifetime),
    /// 位于 `Box` / `Rc` / `Arc` 之下：省略的 object lifetime 默认为 `'static`。
    StaticContainer,
    /// 其余位置。**不猜。**
    Unknown,
}

/// trait object 形式回调的 object lifetime 解析结果。
enum TraitObjectCallbackLifetime<'hir> {
    /// 显式写出的、或由外层引用默认得到的一个 lifetime。
    Lifetime(&'hir hir::Lifetime),
    /// 由容器默认到 `'static`。
    StaticByContainerDefault,
    /// 识别出回调 trait object，但解析不出它的 object lifetime。
    Unresolved,
}

/// 外层容器是否让省略的 object lifetime 默认到 `'static`。
///
/// 只认标准库那几个已知的智能指针。用户自定义容器可能带自己的 lifetime bound，
/// 猜错方向就会把不健全判成健全，所以一律落到 [`ObjectLifetimeContext::Unknown`]。
fn is_static_defaulting_container(name: &str) -> bool {
    matches!(name, "Box" | "Rc" | "Arc")
}

/// 在参数类型里找 `dyn Fn` 家族的 trait object，并解析它的 object lifetime。
fn callback_trait_object_lifetime<'hir>(
    ty: &'hir hir::Ty<'hir>,
    context: ObjectLifetimeContext<'hir>,
) -> Option<TraitObjectCallbackLifetime<'hir>> {
    match &ty.kind {
        hir::TyKind::TraitObject(bounds, lifetime) => {
            if !bounds.iter().any(hir_poly_trait_ref_is_callable) {
                return None;
            }
            let lifetime: &hir::Lifetime = &**lifetime;
            Some(match lifetime.kind {
                hir::LifetimeKind::Param(_) | hir::LifetimeKind::Static => {
                    TraitObjectCallbackLifetime::Lifetime(lifetime)
                }
                hir::LifetimeKind::ImplicitObjectLifetimeDefault => match context {
                    ObjectLifetimeContext::Reference(outer) => {
                        TraitObjectCallbackLifetime::Lifetime(outer)
                    }
                    ObjectLifetimeContext::StaticContainer => {
                        TraitObjectCallbackLifetime::StaticByContainerDefault
                    }
                    ObjectLifetimeContext::Unknown => TraitObjectCallbackLifetime::Unresolved,
                },
                _ => TraitObjectCallbackLifetime::Unresolved,
            })
        }
        hir::TyKind::Ref(lifetime, mut_ty) => {
            callback_trait_object_lifetime(mut_ty.ty, ObjectLifetimeContext::Reference(lifetime))
        }
        hir::TyKind::Ptr(mut_ty) => {
            callback_trait_object_lifetime(mut_ty.ty, ObjectLifetimeContext::Unknown)
        }
        hir::TyKind::Slice(inner) | hir::TyKind::Array(inner, _) => {
            callback_trait_object_lifetime(inner, ObjectLifetimeContext::Unknown)
        }
        hir::TyKind::Tup(types) => types
            .iter()
            .find_map(|inner| callback_trait_object_lifetime(inner, ObjectLifetimeContext::Unknown)),
        hir::TyKind::Path(hir::QPath::Resolved(_, path)) => {
            let inner_context = path
                .segments
                .last()
                .filter(|segment| is_static_defaulting_container(segment.ident.name.as_str()))
                .map_or(ObjectLifetimeContext::Unknown, |_| {
                    ObjectLifetimeContext::StaticContainer
                });
            path.segments
                .iter()
                .filter_map(|segment| segment.args)
                .flat_map(|args| args.args.iter())
                .find_map(|arg| match arg {
                    hir::GenericArg::Type(inner) => {
                        callback_trait_object_lifetime(inner.as_unambig_ty(), inner_context)
                    }
                    _ => None,
                })
        }
        _ => None,
    }
}

fn hir_poly_trait_ref_is_callable(poly_trait_ref: &hir::PolyTraitRef<'_>) -> bool {
    poly_trait_ref
        .trait_ref
        .path
        .segments
        .last()
        .is_some_and(|segment| {
            matches!(
                segment.ident.name.as_str(),
                "Fn" | "FnMut" | "FnOnce" | "AsyncFn" | "AsyncFnMut" | "AsyncFnOnce"
            )
        })
}

/// 把 trait object 的 object lifetime 归到一个 scope。
fn trait_object_callback_scope(
    resolved: &TraitObjectCallbackLifetime<'_>,
    declared_lifetimes: &BTreeSet<usize>,
    receiver_lifetimes: &BTreeSet<usize>,
) -> (Option<String>, CallbackLifetimeBoundScope) {
    match resolved {
        TraitObjectCallbackLifetime::StaticByContainerDefault => (
            Some("'static".to_owned()),
            CallbackLifetimeBoundScope::StaticLifetime,
        ),
        TraitObjectCallbackLifetime::Unresolved => {
            (None, CallbackLifetimeBoundScope::UnresolvedLifetime)
        }
        TraitObjectCallbackLifetime::Lifetime(lifetime) => {
            if hir_lifetime_is_static(lifetime) {
                return (
                    Some(lifetime.ident.name.to_string()),
                    CallbackLifetimeBoundScope::StaticLifetime,
                );
            }
            match hir_lifetime_param_index(lifetime) {
                Some(index) if declared_lifetimes.contains(&index) => {
                    let scope = if receiver_lifetimes.contains(&index) {
                        CallbackLifetimeBoundScope::DeclaredReceiverLifetime
                    } else {
                        CallbackLifetimeBoundScope::DeclaredFreeLifetime
                    };
                    (Some(lifetime.ident.name.to_string()), scope)
                }
                _ => (None, CallbackLifetimeBoundScope::UnresolvedLifetime),
            }
        }
    }
}

/// 被约束的类型是不是本函数声明的一个泛型类型参数。
///
/// 只认 `F` 这种裸参数路径，`Vec<F>` 或关联类型都不算——那些的 bound 约束的不是回调
/// 本身。
fn declared_type_param_name(
    generics: &hir::Generics<'_>,
    bounded_ty: &hir::Ty<'_>,
) -> Option<String> {
    let hir::TyKind::Path(hir::QPath::Resolved(None, path)) = bounded_ty.kind else {
        return None;
    };
    let [segment] = path.segments else {
        return None;
    };
    if !generics.params.iter().any(|param| {
        matches!(param.kind, hir::GenericParamKind::Type { .. })
            && param.name.ident().name == segment.ident.name
    }) {
        return None;
    }
    Some(segment.ident.name.to_string())
}

/// 把一组 bound 归到四个 scope 之一。
///
/// 顺序有意义：先找本函数声明的 lifetime（不健全的那两种），再看 `'static`。反过来写会
/// 让 `F: FnMut(..) + 'c + 'static` 这种被判成健全。
fn callback_bound_scope_from_bounds(
    bounds: &[&hir::GenericBound<'_>],
    declared_lifetimes: &BTreeSet<usize>,
    receiver_lifetimes: &BTreeSet<usize>,
) -> (Option<String>, CallbackLifetimeBoundScope) {
    let outlives = bounds
        .iter()
        .filter_map(|bound| match bound {
            hir::GenericBound::Outlives(lifetime) => Some(*lifetime),
            _ => None,
        })
        .collect::<Vec<_>>();

    for lifetime in &outlives {
        let Some(index) = hir_lifetime_param_index(lifetime) else {
            continue;
        };
        if !declared_lifetimes.contains(&index) {
            continue;
        }
        let scope = if receiver_lifetimes.contains(&index) {
            CallbackLifetimeBoundScope::DeclaredReceiverLifetime
        } else {
            CallbackLifetimeBoundScope::DeclaredFreeLifetime
        };
        return (Some(lifetime.ident.name.to_string()), scope);
    }
    for lifetime in &outlives {
        if hir_lifetime_is_static(lifetime) {
            return (
                Some(lifetime.ident.name.to_string()),
                CallbackLifetimeBoundScope::StaticLifetime,
            );
        }
    }
    (None, CallbackLifetimeBoundScope::NoLifetimeBound)
}

/// bound 是否是 `Fn` / `FnMut` / `FnOnce`。用来把回调参数和普通泛型参数分开。
fn hir_bound_is_callable_trait(bound: &hir::GenericBound<'_>) -> bool {
    let hir::GenericBound::Trait(poly_trait_ref) = bound else {
        return false;
    };
    poly_trait_ref
        .trait_ref
        .path
        .segments
        .last()
        .is_some_and(|segment| {
            matches!(
                segment.ident.name.as_str(),
                "Fn" | "FnMut" | "FnOnce" | "AsyncFn" | "AsyncFnMut" | "AsyncFnOnce"
            )
        })
}

fn function_declared_lifetime_params(generics: &hir::Generics<'_>) -> BTreeSet<usize> {
    generics
        .params
        .iter()
        .filter(|param| {
            matches!(
                param.kind,
                hir::GenericParamKind::Lifetime { kind }
                    if !matches!(kind, hir::LifetimeParamKind::Elided(_))
            )
        })
        .map(|param| param.def_id.index())
        .collect()
}

fn collect_hir_lifetime_params_from_ty(ty: &hir::Ty<'_>, lifetimes: &mut BTreeSet<usize>) {
    match &ty.kind {
        hir::TyKind::Slice(inner) => collect_hir_lifetime_params_from_ty(inner, lifetimes),
        hir::TyKind::Array(inner, _) => collect_hir_lifetime_params_from_ty(inner, lifetimes),
        hir::TyKind::Ptr(mut_ty) => collect_hir_lifetime_params_from_ty(mut_ty.ty, lifetimes),
        hir::TyKind::Ref(lifetime, mut_ty) => {
            collect_hir_lifetime_param(lifetime, lifetimes);
            collect_hir_lifetime_params_from_ty(mut_ty.ty, lifetimes);
        }
        hir::TyKind::FnPtr(fn_ptr) => {
            for input in fn_ptr.decl.inputs {
                collect_hir_lifetime_params_from_ty(input, lifetimes);
            }
            if let hir::FnRetTy::Return(output) = fn_ptr.decl.output {
                collect_hir_lifetime_params_from_ty(output, lifetimes);
            }
        }
        hir::TyKind::UnsafeBinder(unsafe_binder) => {
            collect_hir_lifetime_params_from_ty(unsafe_binder.inner_ty, lifetimes);
        }
        hir::TyKind::Tup(types) => {
            for inner in *types {
                collect_hir_lifetime_params_from_ty(inner, lifetimes);
            }
        }
        hir::TyKind::Path(path) => collect_hir_lifetime_params_from_qpath(path, lifetimes),
        hir::TyKind::OpaqueDef(opaque) => {
            for bound in opaque.bounds {
                collect_hir_lifetime_params_from_param_bound(bound, lifetimes);
            }
        }
        hir::TyKind::TraitObject(bounds, lifetime) => {
            for bound in *bounds {
                collect_hir_lifetime_params_from_poly_trait_ref(bound, lifetimes);
            }
            collect_hir_lifetime_param(lifetime, lifetimes);
        }
        hir::TyKind::InferDelegation(_)
        | hir::TyKind::Never
        | hir::TyKind::TraitAscription(_)
        | hir::TyKind::Err(_)
        | hir::TyKind::Pat(_, _)
        | hir::TyKind::FieldOf(_, _)
        | hir::TyKind::Infer(()) => {}
    }
}

fn collect_hir_lifetime_params_from_qpath(qpath: &hir::QPath<'_>, lifetimes: &mut BTreeSet<usize>) {
    match qpath {
        hir::QPath::Resolved(self_ty, path) => {
            if let Some(self_ty) = self_ty {
                collect_hir_lifetime_params_from_ty(self_ty, lifetimes);
            }
            for segment in path.segments {
                collect_hir_lifetime_params_from_generic_args(segment.args(), lifetimes);
            }
        }
        hir::QPath::TypeRelative(self_ty, segment) => {
            collect_hir_lifetime_params_from_ty(self_ty, lifetimes);
            collect_hir_lifetime_params_from_generic_args(segment.args(), lifetimes);
        }
    }
}

fn collect_hir_lifetime_params_from_generic_args(
    args: &hir::GenericArgs<'_>,
    lifetimes: &mut BTreeSet<usize>,
) {
    for arg in args.args {
        match arg {
            hir::GenericArg::Lifetime(lifetime) => {
                collect_hir_lifetime_param(lifetime, lifetimes);
            }
            hir::GenericArg::Type(ty) => {
                collect_hir_lifetime_params_from_ty(ty.as_unambig_ty(), lifetimes);
            }
            hir::GenericArg::Const(_) | hir::GenericArg::Infer(_) => {}
        }
    }
    if let Some((inputs, output)) = args.paren_sugar_inputs_output() {
        for input in inputs {
            collect_hir_lifetime_params_from_ty(input, lifetimes);
        }
        collect_hir_lifetime_params_from_ty(output, lifetimes);
    }
    for constraint in args.constraints {
        collect_hir_lifetime_params_from_generic_args(constraint.gen_args, lifetimes);
        if let Some(ty) = (*constraint).ty() {
            collect_hir_lifetime_params_from_ty(ty, lifetimes);
        }
        if let hir::AssocItemConstraintKind::Bound { bounds } = constraint.kind {
            for bound in bounds {
                collect_hir_lifetime_params_from_param_bound(bound, lifetimes);
            }
        }
    }
}

fn collect_hir_lifetime_params_from_param_bound(
    bound: &hir::GenericBound<'_>,
    lifetimes: &mut BTreeSet<usize>,
) {
    match bound {
        hir::GenericBound::Trait(trait_ref) => {
            collect_hir_lifetime_params_from_poly_trait_ref(trait_ref, lifetimes);
        }
        hir::GenericBound::Outlives(lifetime) => collect_hir_lifetime_param(lifetime, lifetimes),
        hir::GenericBound::Use(args, _) => {
            for arg in *args {
                if let hir::PreciseCapturingArg::Lifetime(lifetime) = arg {
                    collect_hir_lifetime_param(lifetime, lifetimes);
                }
            }
        }
    }
}

fn collect_hir_lifetime_params_from_poly_trait_ref(
    trait_ref: &hir::PolyTraitRef<'_>,
    lifetimes: &mut BTreeSet<usize>,
) {
    for segment in trait_ref.trait_ref.path.segments {
        collect_hir_lifetime_params_from_generic_args(segment.args(), lifetimes);
    }
}

fn collect_hir_lifetime_param(lifetime: &hir::Lifetime, lifetimes: &mut BTreeSet<usize>) {
    if let Some(index) = hir_lifetime_param_index(lifetime) {
        lifetimes.insert(index);
    }
}

/// 具名 lifetime 参数的 def index。`'static` 与被擦除的 lifetime 返回 `None`——它们不是
/// 本函数声明的参数，这个区别正是回调 bound 判定的全部依据。
fn hir_lifetime_param_index(lifetime: &hir::Lifetime) -> Option<usize> {
    match lifetime.kind {
        hir::LifetimeKind::Param(def_id) => Some(def_id.index()),
        _ => None,
    }
}

fn hir_lifetime_is_static(lifetime: &hir::Lifetime) -> bool {
    matches!(lifetime.kind, hir::LifetimeKind::Static)
}

fn hir_ty_contains_reference(ty: &hir::Ty<'_>) -> bool {
    match &ty.kind {
        hir::TyKind::Ref(..) => true,
        hir::TyKind::Slice(inner) => hir_ty_contains_reference(inner),
        hir::TyKind::Array(inner, _) => hir_ty_contains_reference(inner),
        hir::TyKind::Ptr(mut_ty) => hir_ty_contains_reference(mut_ty.ty),
        hir::TyKind::Tup(types) => types.iter().any(hir_ty_contains_reference),
        hir::TyKind::Path(path) => hir_qpath_contains_reference(path),
        _ => false,
    }
}

fn hir_qpath_contains_reference(qpath: &hir::QPath<'_>) -> bool {
    match qpath {
        hir::QPath::Resolved(self_ty, path) => {
            self_ty.is_some_and(hir_ty_contains_reference)
                || path.segments.iter().any(|segment| {
                    segment.args().args.iter().any(|arg| match arg {
                        hir::GenericArg::Type(ty) => hir_ty_contains_reference(ty.as_unambig_ty()),
                        _ => false,
                    })
                })
        }
        hir::QPath::TypeRelative(self_ty, segment) => {
            hir_ty_contains_reference(self_ty)
                || segment.args().args.iter().any(|arg| match arg {
                    hir::GenericArg::Type(ty) => hir_ty_contains_reference(ty.as_unambig_ty()),
                    _ => false,
                })
        }
    }
}

fn ty_contains_ref<'tcx>(ty: Ty<'tcx>) -> bool {
    struct RefTyVisitor {
        found: bool,
    }

    impl<'tcx> TypeVisitor<TyCtxt<'tcx>> for RefTyVisitor {
        type Result = ControlFlow<()>;

        fn visit_ty(&mut self, ty: Ty<'tcx>) -> Self::Result {
            if matches!(ty.kind(), ty::Ref(..)) {
                self.found = true;
                return ControlFlow::Break(());
            }
            ty.super_visit_with(self)
        }
    }

    let mut visitor = RefTyVisitor { found: false };
    let _ = ty.visit_with(&mut visitor);
    visitor.found
}

fn callback_def_id_from_ty<'tcx>(ty: Ty<'tcx>) -> Option<DefId> {
    struct CallbackDefIdVisitor {
        found: Option<DefId>,
    }

    impl<'tcx> TypeVisitor<TyCtxt<'tcx>> for CallbackDefIdVisitor {
        type Result = ControlFlow<()>;

        fn visit_ty(&mut self, ty: Ty<'tcx>) -> Self::Result {
            match ty.kind() {
                ty::Closure(def_id, _) | ty::FnDef(def_id, _) => {
                    self.found = Some(*def_id);
                    ControlFlow::Break(())
                }
                _ => ty.super_visit_with(self),
            }
        }
    }

    let mut visitor = CallbackDefIdVisitor { found: None };
    let _ = ty.visit_with(&mut visitor);
    visitor.found
}

fn is_explicit_drop_call(def_path: &str) -> bool {
    def_path == "std::mem::drop" || def_path == "core::mem::drop"
}

fn is_mem_forget_call(def_path: &str) -> bool {
    def_path == "std::mem::forget" || def_path == "core::mem::forget"
}

fn owner_is_foreign_callback<'tcx>(tcx: TyCtxt<'tcx>, def_id: DefId) -> bool {
    if !matches!(tcx.def_kind(def_id), DefKind::Fn | DefKind::AssocFn) {
        return false;
    }
    let sig = tcx.fn_sig(def_id).instantiate_identity().skip_binder();
    let abi = format!("{:?}", sig.abi());
    abi.contains('C') && !abi.contains("Rust")
}

fn is_transmute_call(def_path: &str) -> bool {
    def_path == "std::mem::transmute"
        || def_path == "core::mem::transmute"
        || def_path.ends_with("::transmute")
}

fn is_box_leak_call(def_path: &str) -> bool {
    def_path.contains("boxed::Box") && def_path.ends_with("::leak")
}

fn raw_pointer_transfer_kind(def_path: &str) -> Option<RawPointerTransferKind> {
    if vec_from_raw_parts_transfer_call(def_path) {
        return Some(RawPointerTransferKind::FromRawParts);
    }
    let supports_raw_transfer = def_path.contains("boxed::Box")
        || def_path.contains("sync::Arc")
        || def_path.contains("rc::Rc");
    if !supports_raw_transfer {
        return None;
    }
    if def_path.ends_with("::into_raw") {
        Some(RawPointerTransferKind::IntoRaw)
    } else if def_path.ends_with("::from_raw") {
        Some(RawPointerTransferKind::FromRaw)
    } else {
        None
    }
}

fn vec_from_raw_parts_transfer_call(def_path: &str) -> bool {
    def_path.ends_with("::from_raw_parts") && def_path.contains("vec::Vec")
}

fn source_path<'tcx>(tcx: TyCtxt<'tcx>, span: Span) -> Result<PathBuf, MirExtractionError> {
    match tcx.sess.source_map().span_to_filename(span) {
        FileName::Real(name) => Ok(name
            .path(RemapPathScopeComponents::DIAGNOSTICS)
            .to_path_buf()),
        filename => Err(MirExtractionError::NonRealSourceFile {
            filename: format!("{filename:?}"),
        }),
    }
}

fn stable_span<'tcx>(tcx: TyCtxt<'tcx>, span: Span) -> Result<String, MirExtractionError> {
    let (source_file, lo_line, lo_col, hi_line, hi_col) =
        tcx.sess.source_map().span_to_location_info(span);
    if source_file.is_none() {
        return Err(MirExtractionError::MissingSpanLocation);
    }
    Ok(format!("{lo_line}:{lo_col}-{hi_line}:{hi_col}"))
}

#[derive(Debug)]
pub enum MirExtractionError {
    NonRealSourceFile { filename: String },
    MissingSpanLocation,
}

impl fmt::Display for MirExtractionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonRealSourceFile { filename } => {
                write!(
                    formatter,
                    "MIR span does not point to a real source file: {filename}"
                )
            }
            Self::MissingSpanLocation => formatter.write_str("MIR span has no source location"),
        }
    }
}

impl std::error::Error for MirExtractionError {}
