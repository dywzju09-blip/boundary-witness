use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use crate::{
    BuildId, InstanceId, JsonlReader, Located, ModelError, ObjectKind, RecordId, RunId,
    RuntimeEvent, RuntimeEventEnvelope, SiteId, TraceId,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectRecord {
    site_id: SiteId,
    object_kind: ObjectKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CallbackRecord {
    site_id: SiteId,
    owner_instance_id: InstanceId,
}

#[derive(Debug)]
struct TraceValidationState {
    run_id: RunId,
    last_seq: u64,
    ended: bool,
    event_count: u64,
    objects: BTreeMap<InstanceId, ObjectRecord>,
    callbacks: BTreeMap<InstanceId, CallbackRecord>,
    last_path: PathBuf,
    last_line: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeValidationSummary {
    pub record_count: u64,
    pub trace_count: u64,
    pub object_count: u64,
    pub callback_count: u64,
}

/// 打开普通 JSONL 或 `.zst` 压缩 JSONL，并进行流式结构校验。
pub fn validate_runtime_path(
    path: impl AsRef<Path>,
    max_line_bytes: usize,
) -> Result<RuntimeValidationSummary, ModelError> {
    let path = path.as_ref().to_path_buf();
    let reader = open_runtime_path(&path)?;
    validate_runtime_stream(JsonlReader::new(reader, path, max_line_bytes))
}

/// 校验 record、trace sequence、对象引用和 callback 引用的结构完整性。
pub fn validate_runtime_stream<I>(events: I) -> Result<RuntimeValidationSummary, ModelError>
where
    I: IntoIterator<Item = Result<Located<RuntimeEventEnvelope>, ModelError>>,
{
    let mut record_ids = BTreeSet::<RecordId>::new();
    let mut traces = BTreeMap::<TraceId, TraceValidationState>::new();
    let mut run_id: Option<RunId> = None;
    let mut build_id: Option<BuildId> = None;
    let mut summary = RuntimeValidationSummary::default();

    for located in events {
        let located = located?;
        let event = &located.value;

        if !record_ids.insert(event.record_id.clone()) {
            return Err(at(
                &located,
                "BW-TRACE-RECORD-DUPLICATE",
                format!("record_id {} 重复", event.record_id),
            ));
        }
        if let Some(expected) = &run_id {
            if expected != &event.run_id {
                return Err(at(
                    &located,
                    "BW-TRACE-RUN-MISMATCH",
                    format!("同一输入出现 run_id {} 和 {}", expected, event.run_id),
                ));
            }
        } else {
            run_id = Some(event.run_id.clone());
        }

        if !traces.contains_key(&event.trace_id) {
            let RuntimeEvent::TraceStart(start) = &event.payload else {
                return Err(at(
                    &located,
                    "BW-TRACE-START-MISSING",
                    format!("trace {} 的首条事件不是 trace_start", event.trace_id),
                ));
            };
            if event.seq != 0 {
                return Err(at(
                    &located,
                    "BW-TRACE-SEQ-START",
                    format!("trace {} 的首个 seq 必须为 0", event.trace_id),
                ));
            }
            if let Some(expected) = &build_id {
                if expected != &start.build_id {
                    return Err(at(
                        &located,
                        "BW-TRACE-BUILD-MISMATCH",
                        format!("同一输入出现 build_id {} 和 {}", expected, start.build_id),
                    ));
                }
            } else {
                build_id = Some(start.build_id.clone());
            }
            traces.insert(
                event.trace_id.clone(),
                TraceValidationState {
                    run_id: event.run_id.clone(),
                    last_seq: event.seq,
                    ended: false,
                    event_count: 1,
                    objects: BTreeMap::new(),
                    callbacks: BTreeMap::new(),
                    last_path: located.path.clone(),
                    last_line: located.line,
                },
            );
            summary.record_count += 1;
            continue;
        }

        let state = traces
            .get_mut(&event.trace_id)
            .expect("trace existence was checked");
        validate_trace_header(&located, state)?;
        validate_payload(&located, state, &mut summary)?;
        state.last_seq = event.seq;
        state.event_count += 1;
        state.last_path = located.path.clone();
        state.last_line = located.line;
        summary.record_count += 1;
    }

    for (trace_id, state) in &traces {
        if !state.ended {
            return Err(ModelError::validation(
                "BW-TRACE-END-MISSING",
                format!("trace {trace_id} 缺少 trace_end"),
            )
            .at_line(state.last_path.clone(), state.last_line));
        }
    }

    summary.trace_count = traces.len() as u64;
    Ok(summary)
}

fn open_runtime_path(path: &Path) -> Result<Box<dyn BufRead>, ModelError> {
    let file = File::open(path)
        .map_err(|error| ModelError::io("打开运行轨迹", error).at_path(path.to_path_buf()))?;
    if path.extension().is_some_and(|extension| extension == "zst") {
        let decoder = zstd::stream::read::Decoder::new(file).map_err(|error| {
            ModelError::io("打开 zstd 运行轨迹", error).at_path(path.to_path_buf())
        })?;
        Ok(Box::new(BufReader::new(decoder)))
    } else {
        Ok(Box::new(BufReader::new(file)))
    }
}

fn validate_trace_header(
    located: &Located<RuntimeEventEnvelope>,
    state: &TraceValidationState,
) -> Result<(), ModelError> {
    let event = &located.value;
    if state.ended {
        return Err(at(
            located,
            "BW-TRACE-AFTER-END",
            format!("trace {} 在 trace_end 后仍有事件", event.trace_id),
        ));
    }
    if state.run_id != event.run_id {
        return Err(at(
            located,
            "BW-TRACE-RUN-MISMATCH",
            format!("trace {} 的 run_id 发生变化", event.trace_id),
        ));
    }
    if event.seq == state.last_seq {
        return Err(at(
            located,
            "BW-TRACE-SEQ-DUPLICATE",
            format!("trace {} 的 seq {} 重复", event.trace_id, event.seq),
        ));
    }
    if event.seq < state.last_seq {
        return Err(at(
            located,
            "BW-TRACE-SEQ-ORDER",
            format!(
                "trace {} 的 seq {} 小于上一序号 {}",
                event.trace_id, event.seq, state.last_seq
            ),
        ));
    }
    Ok(())
}

fn validate_payload(
    located: &Located<RuntimeEventEnvelope>,
    state: &mut TraceValidationState,
    summary: &mut RuntimeValidationSummary,
) -> Result<(), ModelError> {
    let event = &located.value;
    match &event.payload {
        RuntimeEvent::TraceStart(_) => Err(at(
            located,
            "BW-TRACE-START-DUPLICATE",
            format!("trace {} 出现第二个 trace_start", event.trace_id),
        )),
        RuntimeEvent::ObjectCreate(created) => {
            if state.objects.contains_key(&created.instance_id) {
                return Err(at(
                    located,
                    "BW-TRACE-OBJECT-DUPLICATE",
                    format!("对象实例 {} 被重复创建", created.instance_id),
                ));
            }
            state.objects.insert(
                created.instance_id.clone(),
                ObjectRecord {
                    site_id: created.site_id.clone(),
                    object_kind: created.object_kind,
                },
            );
            summary.object_count += 1;
            Ok(())
        }
        RuntimeEvent::CaptureBind(binding) => {
            let callback = require_callback(located, state, &binding.callback_instance_id)?;
            if callback.site_id != binding.callback_site_id {
                return Err(at(
                    located,
                    "BW-TRACE-CALLBACK-SITE-MISMATCH",
                    format!(
                        "callback {} 的 site_id 不一致",
                        binding.callback_instance_id
                    ),
                ));
            }
            let object = require_object(located, state, &binding.object_instance_id)?;
            if object.site_id != binding.object_site_id {
                return Err(at(
                    located,
                    "BW-TRACE-OBJECT-SITE-MISMATCH",
                    format!("对象 {} 的 site_id 不一致", binding.object_instance_id),
                ));
            }
            Ok(())
        }
        RuntimeEvent::CallbackRegister(registered) => {
            let owner = require_object(located, state, &registered.owner_instance_id)?;
            if owner.object_kind != ObjectKind::ExternalOwner {
                return Err(at(
                    located,
                    "BW-TRACE-OWNER-KIND",
                    format!("对象 {} 不是 external_owner", registered.owner_instance_id),
                ));
            }
            if state
                .callbacks
                .contains_key(&registered.callback_instance_id)
            {
                return Err(at(
                    located,
                    "BW-TRACE-CALLBACK-DUPLICATE",
                    format!("callback {} 被重复注册", registered.callback_instance_id),
                ));
            }
            state.callbacks.insert(
                registered.callback_instance_id.clone(),
                CallbackRecord {
                    site_id: registered.callback_site_id.clone(),
                    owner_instance_id: registered.owner_instance_id.clone(),
                },
            );
            summary.callback_count += 1;
            Ok(())
        }
        RuntimeEvent::CallbackUnregister(unregistered) => {
            let callback = require_callback(located, state, &unregistered.callback_instance_id)?;
            if callback.owner_instance_id != unregistered.owner_instance_id {
                return Err(at(
                    located,
                    "BW-TRACE-OWNER-MISMATCH",
                    format!(
                        "callback {} 的 owner 实例不一致",
                        unregistered.callback_instance_id
                    ),
                ));
            }
            Ok(())
        }
        RuntimeEvent::CallbackInvoke(invoked) => {
            require_callback(located, state, &invoked.callback_instance_id)?;
            Ok(())
        }
        RuntimeEvent::ObjectDrop(dropped) => {
            require_object(located, state, &dropped.instance_id)?;
            Ok(())
        }
        RuntimeEvent::ObjectUse(used) => {
            require_object(located, state, &used.instance_id)?;
            Ok(())
        }
        RuntimeEvent::ObjectFree(freed) => {
            require_object(located, state, &freed.instance_id)?;
            Ok(())
        }
        RuntimeEvent::Checkpoint(_) => Ok(()),
        RuntimeEvent::TraceEnd(ended) => {
            let observed_count = state.event_count + 1;
            if ended.event_count != observed_count {
                return Err(at(
                    located,
                    "BW-TRACE-COUNT-MISMATCH",
                    format!(
                        "trace {} 声明 {} 条事件，实际为 {}",
                        event.trace_id, ended.event_count, observed_count
                    ),
                ));
            }
            state.ended = true;
            Ok(())
        }
    }
}

fn require_object<'a>(
    located: &Located<RuntimeEventEnvelope>,
    state: &'a TraceValidationState,
    instance_id: &InstanceId,
) -> Result<&'a ObjectRecord, ModelError> {
    state.objects.get(instance_id).ok_or_else(|| {
        at(
            located,
            "BW-TRACE-OBJECT-MISSING",
            format!("引用了尚未创建的对象 {instance_id}"),
        )
    })
}

fn require_callback<'a>(
    located: &Located<RuntimeEventEnvelope>,
    state: &'a TraceValidationState,
    instance_id: &InstanceId,
) -> Result<&'a CallbackRecord, ModelError> {
    state.callbacks.get(instance_id).ok_or_else(|| {
        at(
            located,
            "BW-TRACE-CALLBACK-MISSING",
            format!("引用了尚未注册的 callback {instance_id}"),
        )
    })
}

fn at(
    located: &Located<RuntimeEventEnvelope>,
    code: &'static str,
    message: impl Into<String>,
) -> ModelError {
    ModelError::validation(code, message).at_line(located.path.clone(), located.line)
}
