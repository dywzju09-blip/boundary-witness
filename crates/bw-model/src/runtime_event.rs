use serde::{Deserialize, Serialize};

use crate::{
    BuildId, InstanceId, ModelError, RecordId, RunId, SiteId, TRACE_SCHEMA_V01, TraceId,
    schema::{deserialize_trace_schema, require_schema_version},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceStartEvent {
    pub build_id: BuildId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Tracked,
    ExternalOwner,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectCreateEvent {
    pub instance_id: InstanceId,
    pub site_id: SiteId,
    pub object_kind: ObjectKind,
    pub epoch: u64,
    pub address_diag: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureBindEvent {
    pub callback_instance_id: InstanceId,
    pub callback_site_id: SiteId,
    pub object_instance_id: InstanceId,
    pub object_site_id: SiteId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackRegisterEvent {
    pub callback_instance_id: InstanceId,
    pub callback_site_id: SiteId,
    pub owner_instance_id: InstanceId,
    pub registration_site_id: SiteId,
    pub api_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackReleaseReason {
    Explicit,
    Replacement,
    OwnerDrop,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackUnregisterEvent {
    pub callback_instance_id: InstanceId,
    pub owner_instance_id: InstanceId,
    pub unregister_site_id: SiteId,
    pub api_id: String,
    pub reason: CallbackReleaseReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackInvokeEvent {
    pub callback_instance_id: InstanceId,
    pub invoke_site_id: SiteId,
    pub api_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectDropEvent {
    pub instance_id: InstanceId,
    pub drop_site_id: SiteId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectUseKind {
    Read,
    Write,
    Borrow,
    External,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectUseEvent {
    pub instance_id: InstanceId,
    pub use_site_id: SiteId,
    pub use_kind: ObjectUseKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectFreeEvent {
    pub instance_id: InstanceId,
    pub free_site_id: SiteId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointKind {
    Registered,
    OwnerEndedOrReleased,
    LaterCallbackPhase,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointEvent {
    pub checkpoint: CheckpointKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceEndEvent {
    pub event_count: u64,
}

/// `bw.trace/0.1` 支持的运行事实种类。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuntimeEvent {
    TraceStart(TraceStartEvent),
    ObjectCreate(ObjectCreateEvent),
    CaptureBind(CaptureBindEvent),
    CallbackRegister(CallbackRegisterEvent),
    CallbackUnregister(CallbackUnregisterEvent),
    CallbackInvoke(CallbackInvokeEvent),
    ObjectDrop(ObjectDropEvent),
    ObjectUse(ObjectUseEvent),
    ObjectFree(ObjectFreeEvent),
    Checkpoint(CheckpointEvent),
    TraceEnd(TraceEndEvent),
}

/// 每条运行事件的版本化公共信封。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEventEnvelope {
    #[serde(deserialize_with = "deserialize_trace_schema")]
    pub schema_version: String,
    pub record_id: RecordId,
    pub run_id: RunId,
    pub trace_id: TraceId,
    pub seq: u64,
    pub thread_id: String,
    pub source: String,
    pub payload: RuntimeEvent,
}

impl RuntimeEventEnvelope {
    /// 解析并精确校验 `bw.trace/0.1`。
    pub fn from_json_str(input: &str) -> Result<Self, ModelError> {
        require_schema_version(input, TRACE_SCHEMA_V01)?;
        Ok(serde_json::from_str(input)?)
    }
}
