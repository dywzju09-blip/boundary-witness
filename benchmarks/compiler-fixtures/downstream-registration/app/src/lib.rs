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

/// 注册包在依赖 crate 的一层封装里：调用点本身不含任何合约 API 的名字。
///
/// 认出它要求看穿 `rusqlite::helpers::install_update_hook` 的函数体，确认第 0 个参数
/// 是 callback、第 1 个是 user data，再把下标映射回这里的实参。callee 在另一个 crate，
/// 所以这条路径同时依赖"不因非本地而放弃"和"依赖带 MIR 编译"。
pub fn registers_through_a_dependency_helper() {
    let counter = Box::new(Counter::new());
    let user_data = Box::into_raw(counter).cast::<std::ffi::c_void>();
    rusqlite::helpers::install_update_hook(Some(on_update), user_data);
}

unsafe extern "C" fn on_update(user_data: *mut std::ffi::c_void) {
    let counter = unsafe { &*(user_data as *const Counter) };
    counter.record(1);
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

    fn record(&self, rowid: i64) {
        let _ = self.total + rowid;
    }
}
