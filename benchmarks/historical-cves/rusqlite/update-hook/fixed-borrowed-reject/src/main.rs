use rusqlite::{hooks::Action, Connection, Result};
use rusqlite_lab_shared::BorrowedCounter;

fn main() -> Result<()> {
    let connection = Connection::open_in_memory()?;
    let counter = BorrowedCounter::new();

    connection.update_hook(Some(
        |action: Action, database: &str, table: &str, rowid: i64| {
            let _ = (action, database, table);
            counter.record(rowid);
        },
    ));

    connection.execute("CREATE TABLE item(id INTEGER PRIMARY KEY)", [])?;
    connection.execute("INSERT INTO item DEFAULT VALUES", [])?;
    let _ = counter.hits();
    Ok(())
}
