use std::sync::Arc;

use bw_model::{CheckpointKind, SiteId};
use bw_runtime::Tracked;
use rusqlite::{hooks::Action, Connection};
use rusqlite_lab_shared::{
    runtime::{benchmark_build_id, benchmark_runtime},
    update_hook::UpdateHookConnection,
    OwnedCounter,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = benchmark_runtime("run:update:0262-owned", "trace:update:0262-owned")?;
    runtime.emit_trace_start(benchmark_build_id("build:update:0262-owned"))?;

    let connection = Connection::open_in_memory()?;
    connection.execute("CREATE TABLE item(id INTEGER PRIMARY KEY)", [])?;

    let observed = UpdateHookConnection::open(runtime.clone(), site("site:update:connection"))?;
    let counter = Tracked::new(
        runtime.clone(),
        site("site:update:object"),
        OwnedCounter::new(),
    );
    let callback_counter = counter.get().clone();
    let token = observed.register(site("site:update:callback"))?;
    token.bind_object(counter.id(), &site("site:update:object"))?;
    runtime.emit_checkpoint(CheckpointKind::Registered)?;

    let callback_token = Arc::clone(&token);
    connection.update_hook(Some(
        move |action: Action, database: &str, table: &str, rowid: i64| {
            let _ = (action, database, table);
            let _ = callback_token.invoke(site("site:update:invoke"));
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
