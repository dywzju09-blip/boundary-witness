use bw_model::{CheckpointKind, SiteId};
use bw_runtime::Tracked;
use rusqlite::{
    functions::{Context, FunctionFlags},
    Connection,
};
use rusqlite_lab_shared::{
    runtime::{benchmark_build_id, benchmark_runtime},
    scalar_function::ScalarFunctionConnection,
    OwnedCounter,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = benchmark_runtime("run:scalar:0262-owned", "trace:scalar:0262-owned")?;
    runtime.emit_trace_start(benchmark_build_id("build:scalar:0262-owned"))?;

    let connection = Connection::open_in_memory()?;
    let observed = ScalarFunctionConnection::open(runtime.clone(), site("site:scalar:connection"))?;
    let counter = Tracked::new(
        runtime.clone(),
        site("site:scalar:object"),
        OwnedCounter::new(),
    );
    let callback_counter = counter.get().clone();
    let token = observed.register("bw_counter", 0, site("site:scalar:callback"))?;
    token.bind_object(counter.id(), &site("site:scalar:object"))?;
    runtime.emit_checkpoint(CheckpointKind::Registered)?;

    let callback_token = token.clone();
    connection.create_scalar_function(
        "bw_counter",
        0,
        FunctionFlags::SQLITE_UTF8,
        move |context: &Context<'_>| {
            let _ = context.len();
            let _ = callback_token.invoke(site("site:scalar:invoke"));
            callback_counter.record(1);
            Ok(callback_counter.hits())
        },
    )?;

    drop(counter);
    runtime.emit_checkpoint(CheckpointKind::LaterCallbackPhase)?;
    let value = connection.query_row("SELECT bw_counter()", [], |row| row.get::<_, i64>(0))?;
    let _ = value;
    observed.close(site("site:scalar:connection-drop"))?;
    runtime.emit_trace_end()?;
    runtime.finish()?;
    Ok(())
}

fn site(value: &'static str) -> SiteId {
    SiteId::from(value)
}
