//! 自动 0day 扫描面对的真实形状：被扫的 crate 只是注册 API 的**使用者**。
//!
//! 这个 crate 不叫 `rusqlite`，也没有任何 rusqlite 内部代码，因此所有以
//! "当前编译的 crate 是 rusqlite" 为前提的匹配路径在这里全部不成立。

use rusqlite::{hooks::Action, Connection, Statement};

/// 应当被识别为注册：合约声明的 owner 与方法。
pub fn registers_update_hook() {
    let connection = Connection::open();
    let counter = Counter::new();
    connection.update_hook(Some(
        move |action: Action, database: &str, table: &str, rowid: i64| {
            let _ = (action, database, table);
            counter.record(rowid);
        },
    ));
}

/// 应当被识别为注销：callback 参数是字面 `None`。
pub fn unregisters_update_hook() {
    let connection = Connection::open();
    connection.update_hook(None::<fn(Action, &str, &str, i64)>);
}

/// 不应被识别为注册：方法同名，但 owner 不是合约声明的类型。
pub fn calls_same_name_on_another_type() {
    let statement = Statement::new();
    let counter = Counter::new();
    statement.update_hook(Some(
        move |action: Action, database: &str, table: &str, rowid: i64| {
            let _ = (action, database, table);
            counter.record(rowid);
        },
    ));
}

/// callback 捕获的对象，让注册点有个可追踪的 user data，而不是空闭包。
#[derive(Clone, Copy)]
struct Counter {
    total: i64,
}

impl Counter {
    fn new() -> Self {
        Self { total: 0 }
    }

    fn record(mut self, rowid: i64) {
        self.total += rowid;
    }
}
