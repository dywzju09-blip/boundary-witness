use std::sync::Arc;

use bw_model::{CheckpointKind, ObjectUseEvent, ObjectUseKind, RuntimeEvent, SiteId};
use bw_runtime::Tracked;
use rusqlite::{hooks::Action, Connection};
use rusqlite_lab_shared::{
    runtime::{benchmark_build_id, benchmark_runtime},
    update_hook::UpdateHookConnection,
    BorrowedCounter,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = benchmark_runtime("run:update:0261-borrowed", "trace:update:0261-borrowed")?;
    runtime.emit_trace_start(benchmark_build_id("build:update:0261-borrowed"))?;

    let connection = Connection::open_in_memory()?;
    connection.execute("CREATE TABLE item(id INTEGER PRIMARY KEY)", [])?;

    let observed = UpdateHookConnection::open(runtime.clone(), site("site:update:connection"))?;
    let counter_site = site("site:update:object");
    let counter = Tracked::new(
        runtime.clone(),
        counter_site.clone(),
        BorrowedCounter::new(),
    );
    let token = observed.register(site("site:update:callback"))?;
    token.bind_object(counter.id(), &site("site:update:object"))?;
    runtime.emit_checkpoint(CheckpointKind::Registered)?;

    let callback_token = Arc::clone(&token);
    let callback_runtime = runtime.clone();
    let callback_counter_id = counter.id().clone();
    let callback_counter_site = counter_site.clone();
    let callback_counter = counter.get();
    connection.update_hook(Some(
        move |action: Action, database: &str, table: &str, rowid: i64| {
            let _ = (action, database, table);
            let _ = callback_token.invoke(site("site:update:invoke"));
            callback_runtime.emit_deferred(RuntimeEvent::ObjectUse(ObjectUseEvent {
                instance_id: callback_counter_id.clone(),
                use_site_id: callback_counter_site.clone(),
                use_kind: ObjectUseKind::Read,
            }));
            callback_counter.record(rowid);
        },
    ));

    drop(counter);
    runtime.emit_checkpoint(CheckpointKind::LaterCallbackPhase)?;
    connection.execute("INSERT INTO item DEFAULT VALUES", [])?;
    observed.close(site("site:update:connection-drop"))?;
    runtime.emit_trace_end()?;
    runtime.finish()?;
    Ok(())
}

fn site(value: &'static str) -> SiteId {
    SiteId::from(value)
}
