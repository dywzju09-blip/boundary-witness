use std::collections::BTreeMap;

use bw_model::{
    CaptureMode, InstanceId, ObjectKind, RuntimeEvent, RuntimeEventEnvelope, SiteId, StaticFact,
    StaticFactEnvelope,
};

use crate::{ContractFeedbackState, FeedbackStateSnapshot, ObserverError, StableRuleContext};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectLifecycle {
    Live,
    Ended,
    Freed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectState {
    site_id: SiteId,
    kind: ObjectKind,
    lifecycle: ObjectLifecycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallbackLifecycle {
    Retained,
    Released,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CallbackState {
    owner_instance_id: InstanceId,
    lifecycle: CallbackLifecycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureLifecycle {
    Active,
    Ended,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CaptureState {
    capture_mode: CaptureMode,
    lifecycle: CaptureLifecycle,
}

/// D2 observer that translates generic lifecycle transitions into fuzz feedback states.
#[derive(Clone, Debug)]
pub struct ContractStateObserver {
    capture_modes: BTreeMap<(SiteId, SiteId), CaptureMode>,
    objects: BTreeMap<InstanceId, ObjectState>,
    callbacks: BTreeMap<InstanceId, CallbackState>,
    captures: BTreeMap<(InstanceId, InstanceId), CaptureState>,
    snapshot: FeedbackStateSnapshot,
}

impl ContractStateObserver {
    pub fn from_static_facts(
        facts: impl IntoIterator<Item = StaticFactEnvelope>,
    ) -> Result<Self, ObserverError> {
        let mut capture_modes = BTreeMap::new();
        for fact in facts {
            if let StaticFact::CallbackCapture(capture) = fact.payload {
                let key = (capture.callback_site_id, capture.object_site_id);
                if capture_modes.insert(key, capture.capture_mode).is_some() {
                    return Err(ObserverError::new(
                        "BW-OBSERVER-STATIC-CAPTURE-DUPLICATE",
                        "同一 callback/object site 出现重复 capture 摘要",
                    ));
                }
            }
        }
        Ok(Self {
            capture_modes,
            objects: BTreeMap::new(),
            callbacks: BTreeMap::new(),
            captures: BTreeMap::new(),
            snapshot: FeedbackStateSnapshot::default(),
        })
    }

    pub fn observe_all(
        mut self,
        events: impl IntoIterator<Item = RuntimeEventEnvelope>,
    ) -> Result<FeedbackStateSnapshot, ObserverError> {
        for event in events {
            self.observe(&event)?;
        }
        Ok(self.snapshot)
    }

    pub fn observe(
        &mut self,
        event: &RuntimeEventEnvelope,
    ) -> Result<&FeedbackStateSnapshot, ObserverError> {
        match &event.payload {
            RuntimeEvent::TraceStart(_)
            | RuntimeEvent::ObjectUse(_)
            | RuntimeEvent::Checkpoint(_)
            | RuntimeEvent::TraceEnd(_) => {}
            RuntimeEvent::ObjectCreate(created) => {
                self.objects.insert(
                    created.instance_id.clone(),
                    ObjectState {
                        site_id: created.site_id.clone(),
                        kind: created.object_kind,
                        lifecycle: ObjectLifecycle::Live,
                    },
                );
            }
            RuntimeEvent::CallbackRegister(registered) => {
                self.callbacks.insert(
                    registered.callback_instance_id.clone(),
                    CallbackState {
                        owner_instance_id: registered.owner_instance_id.clone(),
                        lifecycle: CallbackLifecycle::Retained,
                    },
                );
            }
            RuntimeEvent::CaptureBind(binding) => {
                let Some(capture_mode) = self
                    .capture_modes
                    .get(&(
                        binding.callback_site_id.clone(),
                        binding.object_site_id.clone(),
                    ))
                    .copied()
                else {
                    return Ok(&self.snapshot);
                };
                self.captures.insert(
                    (
                        binding.callback_instance_id.clone(),
                        binding.object_instance_id.clone(),
                    ),
                    CaptureState {
                        capture_mode,
                        lifecycle: CaptureLifecycle::Active,
                    },
                );
                if capture_mode == CaptureMode::Borrowed
                    && self.callback_is_retained(&binding.callback_instance_id)
                {
                    self.snapshot.record(
                        ContractFeedbackState::BorrowedRetained,
                        &event.record_id,
                        StableRuleContext::BorrowedCaptureRetainedCallback,
                    );
                }
            }
            RuntimeEvent::CallbackUnregister(unregistered) => {
                let callback_id = &unregistered.callback_instance_id;
                if self.callback_is_retained(callback_id) {
                    let captured_live_object = self
                        .captures
                        .iter()
                        .filter(|((captured_callback, _), capture)| {
                            captured_callback == callback_id
                                && capture.capture_mode == CaptureMode::Borrowed
                                && capture.lifecycle == CaptureLifecycle::Active
                        })
                        .any(|((_, object_id), _)| {
                            self.objects
                                .get(object_id)
                                .is_some_and(|object| object.lifecycle == ObjectLifecycle::Live)
                        });
                    if captured_live_object {
                        self.snapshot.record(
                            ContractFeedbackState::ReleasedBeforeEnd,
                            &event.record_id,
                            StableRuleContext::CallbackReleasedBeforeBorrowEnd,
                        );
                    }
                }
                if let Some(callback) = self.callbacks.get_mut(callback_id) {
                    callback.lifecycle = CallbackLifecycle::Released;
                }
            }
            RuntimeEvent::CallbackInvoke(invoked) => {
                if self.callback_is_retained(&invoked.callback_instance_id) {
                    let invoked_after_end = self
                        .captures
                        .iter()
                        .filter(|((captured_callback, _), capture)| {
                            captured_callback == &invoked.callback_instance_id
                                && capture.capture_mode == CaptureMode::Borrowed
                                && capture.lifecycle == CaptureLifecycle::Ended
                        })
                        .any(|_| true);
                    if invoked_after_end {
                        self.snapshot.record(
                            ContractFeedbackState::InvokedAfterEnd,
                            &event.record_id,
                            StableRuleContext::CallbackInvokedAfterBorrowEnd,
                        );
                    }
                }
            }
            RuntimeEvent::ObjectDrop(dropped) => {
                self.end_object(&dropped.instance_id, ObjectLifecycle::Ended, event)?;
            }
            RuntimeEvent::ObjectFree(freed) => {
                self.end_object(&freed.instance_id, ObjectLifecycle::Freed, event)?;
            }
        }
        Ok(&self.snapshot)
    }

    #[must_use]
    pub fn snapshot(&self) -> &FeedbackStateSnapshot {
        &self.snapshot
    }

    fn end_object(
        &mut self,
        object_id: &InstanceId,
        lifecycle: ObjectLifecycle,
        event: &RuntimeEventEnvelope,
    ) -> Result<(), ObserverError> {
        let Some(object) = self.objects.get_mut(object_id) else {
            return Ok(());
        };
        object.lifecycle = lifecycle;
        let object_kind = object.kind;
        self.end_borrowed_captures(object_id, event);
        if object_kind == ObjectKind::ExternalOwner {
            self.record_owner_close_feedback(object_id, event);
            for callback in self
                .callbacks
                .values_mut()
                .filter(|callback| callback.owner_instance_id == *object_id)
            {
                callback.lifecycle = CallbackLifecycle::Released;
            }
        }
        Ok(())
    }

    fn end_borrowed_captures(&mut self, object_id: &InstanceId, event: &RuntimeEventEnvelope) {
        let retained_callbacks = self.callbacks.clone();
        for ((callback_id, _), capture) in
            self.captures
                .iter_mut()
                .filter(|((_, captured_object_id), capture)| {
                    captured_object_id == object_id
                        && capture.capture_mode == CaptureMode::Borrowed
                        && capture.lifecycle == CaptureLifecycle::Active
                })
        {
            capture.lifecycle = CaptureLifecycle::Ended;
            if retained_callbacks
                .get(callback_id)
                .is_some_and(|callback| callback.lifecycle == CallbackLifecycle::Retained)
            {
                self.snapshot.record(
                    ContractFeedbackState::BorrowEndedRetained,
                    &event.record_id,
                    StableRuleContext::BorrowEndedRetainedCallback,
                );
            }
        }
    }

    fn record_owner_close_feedback(&mut self, owner_id: &InstanceId, event: &RuntimeEventEnvelope) {
        if self.callbacks.values().any(|callback| {
            callback.owner_instance_id == *owner_id
                && callback.lifecycle == CallbackLifecycle::Retained
        }) {
            self.snapshot.record(
                ContractFeedbackState::ClosedOwnerWithRetainedCallback,
                &event.record_id,
                StableRuleContext::OwnerClosedBeforeCallbackRelease,
            );
        }
    }

    fn callback_is_retained(&self, callback_id: &InstanceId) -> bool {
        self.callbacks
            .get(callback_id)
            .is_some_and(|callback| callback.lifecycle == CallbackLifecycle::Retained)
    }
}
