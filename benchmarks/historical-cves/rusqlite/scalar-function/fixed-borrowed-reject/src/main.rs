use rusqlite::{
    functions::{Context, FunctionFlags},
    Connection, Result,
};
use rusqlite_lab_shared::BorrowedCounter;

fn main() -> Result<()> {
    let connection = Connection::open_in_memory()?;
    let counter = BorrowedCounter::new();

    connection.create_scalar_function(
        "bw_counter",
        0,
        FunctionFlags::SQLITE_UTF8,
        |context: &Context<'_>| {
            let _ = context.len();
            counter.record(1);
            Ok(counter.hits())
        },
    )?;

    let value = connection.query_row("SELECT bw_counter()", [], |row| row.get::<_, i64>(0))?;
    let _ = value;
    Ok(())
}
