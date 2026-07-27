use std::collections::BTreeMap;

use bw_model::{CaptureMode, FindingStateSnapshot, InstanceId, ObjectKind, RecordId, SiteId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectLifecycle {
    Live,
    Ended,
    Freed,
}

impl ObjectLifecycle {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Ended => "ended",
            Self::Freed => "freed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectState {
    pub site_id: SiteId,
    pub object_kind: ObjectKind,
    pub lifecycle: ObjectLifecycle,
    pub created_record: RecordId,
    pub end_record: Option<RecordId>,
    pub first_free_record: Option<RecordId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureLifecycle {
    Active,
    Ended,
}

impl CaptureLifecycle {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Ended => "ended",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureState {
    pub capture_mode: CaptureMode,
    pub lifecycle: CaptureLifecycle,
    pub static_fact_record: RecordId,
    pub bind_record: RecordId,
    pub end_record: Option<RecordId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackLifecycle {
    Created,
    Retained,
    Released,
}

impl CallbackLifecycle {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Retained => "retained",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackState {
    pub site_id: SiteId,
    pub owner_instance_id: InstanceId,
    pub api_id: String,
    pub lifecycle: CallbackLifecycle,
    pub register_record: RecordId,
    pub release_record: Option<RecordId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalOwnerLifecycle {
    Open,
    Closed,
}

impl ExternalOwnerLifecycle {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalOwnerState {
    pub lifecycle: ExternalOwnerLifecycle,
    pub close_record: Option<RecordId>,
}

/// 生命周期四张正交状态表。
#[derive(Clone, Debug, Default)]
pub struct OracleState {
    pub objects: BTreeMap<InstanceId, ObjectState>,
    pub captures: BTreeMap<(InstanceId, InstanceId), CaptureState>,
    pub callbacks: BTreeMap<InstanceId, CallbackState>,
    pub owners: BTreeMap<InstanceId, ExternalOwnerState>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct SubjectKey {
    pub object: Option<InstanceId>,
    pub callback: Option<InstanceId>,
}

impl OracleState {
    pub(crate) fn subjects_for_event(&self, event: &bw_model::RuntimeEvent) -> Vec<SubjectKey> {
        let mut subjects = Vec::new();
        match event {
            bw_model::RuntimeEvent::ObjectDrop(event) => {
                self.push_object_subjects(&event.instance_id, &mut subjects);
            }
            bw_model::RuntimeEvent::ObjectFree(event) => {
                self.push_object_subjects(&event.instance_id, &mut subjects);
            }
            bw_model::RuntimeEvent::ObjectUse(event) => {
                self.push_object_subjects(&event.instance_id, &mut subjects);
            }
            bw_model::RuntimeEvent::CallbackInvoke(event) => {
                for ((callback_id, object_id), _) in self
                    .captures
                    .iter()
                    .filter(|((callback_id, _), _)| callback_id == &event.callback_instance_id)
                {
                    subjects.push(SubjectKey {
                        object: Some(object_id.clone()),
                        callback: Some(callback_id.clone()),
                    });
                }
                subjects.push(SubjectKey {
                    object: None,
                    callback: Some(event.callback_instance_id.clone()),
                });
            }
            _ => {}
        }
        subjects.sort();
        subjects.dedup();
        subjects
    }

    fn push_object_subjects(&self, object_id: &InstanceId, subjects: &mut Vec<SubjectKey>) {
        subjects.push(SubjectKey {
            object: Some(object_id.clone()),
            callback: None,
        });
        for ((callback_id, captured_object_id), _) in self
            .captures
            .iter()
            .filter(|((_, captured_object_id), _)| captured_object_id == object_id)
        {
            subjects.push(SubjectKey {
                object: Some(captured_object_id.clone()),
                callback: Some(callback_id.clone()),
            });
        }
    }

    pub(crate) fn snapshot(&self, subject: &SubjectKey) -> FindingStateSnapshot {
        let object_state = subject
            .object
            .as_ref()
            .and_then(|id| self.objects.get(id))
            .map(|state| state.lifecycle.as_str().to_owned());
        let capture_state = match (&subject.callback, &subject.object) {
            (Some(callback), Some(object)) => self
                .captures
                .get(&(callback.clone(), object.clone()))
                .map(|state| state.lifecycle.as_str().to_owned()),
            _ => None,
        };
        let callback = subject
            .callback
            .as_ref()
            .and_then(|id| self.callbacks.get(id));
        let callback_state = callback.map(|state| state.lifecycle.as_str().to_owned());
        let owner_state = callback
            .and_then(|state| self.owners.get(&state.owner_instance_id))
            .or_else(|| subject.object.as_ref().and_then(|id| self.owners.get(id)))
            .map(|state| state.lifecycle.as_str().to_owned());
        FindingStateSnapshot {
            object_state,
            capture_state,
            callback_state,
            owner_state,
        }
    }
}
