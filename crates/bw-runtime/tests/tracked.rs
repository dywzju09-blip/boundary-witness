use std::sync::{Arc, Mutex};

use bw_model::{ObjectUseKind, RuntimeEvent, RuntimeEventEnvelope, SiteId};
use bw_runtime::{AddressEpochs, EventSink, RuntimeContext, RuntimeError, Tracked};

#[test]
fn tracked_value_emits_create_use_drop_in_order() {
    let (runtime, sink) = test_runtime();
    {
        let value = Tracked::new(runtime.clone(), site("object-site"), String::from("x"));
        assert_eq!(value.id().0, "run:tracked:object:1");
        assert_eq!(value.get(), "x");
    }

    let events = sink.events();
    assert_eq!(
        event_kinds(&events),
        ["object_create", "object_use", "object_drop"]
    );
    assert_eq!(
        match &events[0].payload {
            RuntimeEvent::ObjectCreate(event) =>
                (&event.instance_id.0, &event.site_id.0, event.epoch),
            _ => unreachable!(),
        },
        (
            &"run:tracked:object:1".to_owned(),
            &"object-site".to_owned(),
            0
        )
    );
    assert_eq!(
        match &events[1].payload {
            RuntimeEvent::ObjectUse(event) => (&event.instance_id.0, event.use_kind),
            _ => unreachable!(),
        },
        (&"run:tracked:object:1".to_owned(), ObjectUseKind::Read)
    );
}

#[test]
fn tracked_mutable_access_emits_write_use_before_returning_reference() {
    let (runtime, sink) = test_runtime();
    {
        let mut value = Tracked::new(runtime, site("object-site"), String::from("x"));
        value.get_mut().push('y');
        assert_eq!(value.get(), "xy");
    }

    let events = sink.events();
    assert_eq!(
        event_kinds(&events),
        ["object_create", "object_use", "object_use", "object_drop"]
    );
    assert_eq!(
        match &events[1].payload {
            RuntimeEvent::ObjectUse(event) => event.use_kind,
            _ => unreachable!(),
        },
        ObjectUseKind::Write
    );
}

#[test]
fn epoch_allocator_is_context_independent_from_logical_ids() {
    let mut epochs = AddressEpochs::default();
    assert_eq!(epochs.next_epoch(0x1000), 1);
    assert_eq!(epochs.next_epoch(0x1000), 2);
    assert_eq!(epochs.next_epoch(0x2000), 1);

    let (runtime, _sink) = test_runtime();
    assert_eq!(runtime.next_epoch_for_address(0x1000), 1);
    assert_eq!(runtime.next_epoch_for_address(0x1000), 2);
    assert_eq!(runtime.next_object_id().0, "run:tracked:object:1");
}

fn test_runtime() -> (RuntimeContext, Arc<TestSink>) {
    let sink = Arc::new(TestSink::default());
    let runtime = RuntimeContext::new("run:tracked".into(), "trace:tracked".into(), sink.clone());
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
            RuntimeEvent::ObjectCreate(_) => "object_create",
            RuntimeEvent::ObjectUse(_) => "object_use",
            RuntimeEvent::ObjectDrop(_) => "object_drop",
            _ => "other",
        })
        .collect()
}
