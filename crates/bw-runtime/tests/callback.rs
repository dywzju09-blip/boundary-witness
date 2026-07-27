use std::sync::{Arc, Mutex};

use bw_model::{CallbackReleaseReason, InstanceId, RuntimeEvent, RuntimeEventEnvelope, SiteId};
use bw_runtime::{CallbackToken, EventSink, RuntimeContext, RuntimeError};

#[test]
fn callback_token_emits_register_bind_invoke_and_release_facts() {
    let (runtime, sink) = test_runtime();
    let owner = InstanceId::from("run:callback:owner:1");
    let object = InstanceId::from("run:callback:object:1");
    let token = CallbackToken::register(
        runtime,
        site("callback-site"),
        owner.clone(),
        "api:rusqlite:update_hook",
    )
    .unwrap();

    token.bind_object(&object, &site("object-site")).unwrap();
    token.invoke(site("invoke-site")).unwrap();
    token.release(site("unregister-site")).unwrap();

    let events = sink.events();
    assert_eq!(
        event_kinds(&events),
        [
            "callback_register",
            "capture_bind",
            "callback_invoke",
            "callback_unregister"
        ]
    );
    assert_eq!(token.id().0, "run:callback:callback:1");
    assert_eq!(
        match &events[0].payload {
            RuntimeEvent::CallbackRegister(event) => (
                &event.callback_instance_id,
                &event.callback_site_id,
                &event.owner_instance_id,
                event.api_id.as_str(),
            ),
            _ => unreachable!(),
        },
        (
            &token.id().clone(),
            &site("callback-site"),
            &owner,
            "api:rusqlite:update_hook"
        )
    );
    assert_eq!(
        match &events[1].payload {
            RuntimeEvent::CaptureBind(event) => (
                &event.callback_instance_id,
                &event.object_instance_id,
                &event.object_site_id,
            ),
            _ => unreachable!(),
        },
        (&token.id().clone(), &object, &site("object-site"))
    );
}

#[test]
fn released_callback_cannot_emit_a_valid_invoke() {
    let (runtime, sink) = test_runtime();
    let token = CallbackToken::register(
        runtime,
        site("callback-site"),
        InstanceId::from("run:callback:owner:1"),
        "api:rusqlite:update_hook",
    )
    .unwrap();

    token.release(site("unregister-site")).unwrap();
    let error = token.invoke(site("invoke-site")).unwrap_err();

    assert_eq!(error.code(), "BW-RUNTIME-CALLBACK-RELEASED");
    assert_eq!(
        event_kinds(&sink.events()),
        ["callback_register", "callback_unregister"]
    );
}

#[test]
fn release_is_idempotent_and_does_not_emit_duplicate_unregister() {
    let (runtime, sink) = test_runtime();
    let token = CallbackToken::register(
        runtime,
        site("callback-site"),
        InstanceId::from("run:callback:owner:1"),
        "api:rusqlite:update_hook",
    )
    .unwrap();

    token.release(site("unregister-site")).unwrap();
    token.release(site("unregister-site")).unwrap();

    let unregisters = sink
        .events()
        .into_iter()
        .filter(|event| matches!(event.payload, RuntimeEvent::CallbackUnregister(_)))
        .count();
    assert_eq!(unregisters, 1);
}

#[test]
fn release_with_reason_records_non_explicit_release_reason() {
    let (runtime, sink) = test_runtime();
    let token = CallbackToken::register(
        runtime,
        site("callback-site"),
        InstanceId::from("run:callback:owner:1"),
        "api:rusqlite:update_hook",
    )
    .unwrap();

    token
        .release_with_reason(site("owner-drop-site"), CallbackReleaseReason::OwnerDrop)
        .unwrap();

    let events = sink.events();
    let RuntimeEvent::CallbackUnregister(unregister) = &events[1].payload else {
        panic!("second event should be callback_unregister");
    };
    assert_eq!(unregister.reason, CallbackReleaseReason::OwnerDrop);
    assert_eq!(unregister.unregister_site_id, site("owner-drop-site"));
}

fn test_runtime() -> (RuntimeContext, Arc<TestSink>) {
    let sink = Arc::new(TestSink::default());
    let runtime = RuntimeContext::new("run:callback".into(), "trace:callback".into(), sink.clone());
    (runtime, sink)
}

fn site(id: &str) -> SiteId {
    id.into()
}

#[derive(Default)]
struct TestSink {
    events: Mutex<Vec<RuntimeEventEnvelope>>,
}

impl TestSink {
    fn events(&self) -> Vec<RuntimeEventEnvelope> {
        self.events.lock().unwrap().clone()
    }
}

impl EventSink for TestSink {
    fn emit(&self, event: RuntimeEventEnvelope) -> Result<(), RuntimeError> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }

    fn flush(&self) -> Result<(), RuntimeError> {
        Ok(())
    }
}

fn event_kinds(events: &[RuntimeEventEnvelope]) -> Vec<&'static str> {
    events
        .iter()
        .map(|event| match event.payload {
            RuntimeEvent::CallbackRegister(_) => "callback_register",
            RuntimeEvent::CaptureBind(_) => "capture_bind",
            RuntimeEvent::CallbackInvoke(_) => "callback_invoke",
            RuntimeEvent::CallbackUnregister(_) => "callback_unregister",
            _ => "other",
        })
        .collect()
}
