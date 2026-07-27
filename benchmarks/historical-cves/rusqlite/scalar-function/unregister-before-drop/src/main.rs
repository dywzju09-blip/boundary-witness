use bw_model::{CheckpointKind, SiteId};
use bw_runtime::Tracked;
use rusqlite::{
    functions::{Context, FunctionFlags},
    Connection,
};
use rusqlite_lab_shared::{
    runtime::{benchmark_build_id, benchmark_runtime},
    scalar_function::ScalarFunctionConnection,
    BorrowedCounter,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = benchmark_runtime(
        "run:scalar:0261-unregister-before-drop",
        "trace:scalar:0261-unregister-before-drop",
    )?;
    runtime.emit_trace_start(benchmark_build_id(
        "build:scalar:0261-unregister-before-drop",
    ))?;

    let connection = Connection::open_in_memory()?;
    let observed = ScalarFunctionConnection::open(runtime.clone(), site("site:scalar:connection"))?;
    let counter = Tracked::new(
        runtime.clone(),
        site("site:scalar:object"),
        BorrowedCounter::new(),
    );
    let token = observed.register("bw_counter", 0, site("site:scalar:callback"))?;
    token.bind_object(counter.id(), &site("site:scalar:object"))?;
    runtime.emit_checkpoint(CheckpointKind::Registered)?;

    let callback_token = token.clone();
    let callback_counter = &counter;
    connection.create_scalar_function(
        "bw_counter",
        0,
        FunctionFlags::SQLITE_UTF8,
        move |context: &Context<'_>| {
            let _ = context.len();
            let _ = callback_token.invoke(site("site:scalar:invoke"));
            callback_counter.get().record(1);
            Ok(callback_counter.get().hits())
        },
    )?;

    connection.remove_function("bw_counter", 0)?;
    observed.remove("bw_counter", 0, site("site:scalar:remove"))?;
    runtime.emit_checkpoint(CheckpointKind::OwnerEndedOrReleased)?;
    drop(counter);
    let removed = connection.query_row("SELECT bw_counter()", [], |row| row.get::<_, i64>(0));
    assert!(removed.is_err());
    observed.close(site("site:scalar:connection-drop"))?;
    runtime.emit_trace_end()?;
    runtime.finish()?;
    Ok(())
}

fn site(value: &'static str) -> SiteId {
    SiteId::from(value)
}
