//! 最小的注册 API 提供方，形状照抄真实 rusqlite 的关键之处：`Connection` 在 crate
//! 根可见，而 `update_hook` 的固有实现写在另一个模块 `hooks` 里（真实 rusqlite 亦然）。
//!
//! impl 块本身没有名字，rustc 因此打不出 API map 里那种 `rusqlite::Connection::update_hook`
//! 的可见路径，只能退回 `rusqlite::hooks::<impl rusqlite::Connection>::update_hook`。
//! 换句话说，这个 fixture 复现的是 def path 的形状，不是 SQLite 的行为。

pub mod helpers;
pub mod hooks;

pub struct Connection {
    handle: usize,
}

impl Connection {
    pub fn open() -> Self {
        Self { handle: 0 }
    }
}

/// 同名方法挂在别的类型上：跨 crate 匹配不能只看 crate 和方法名。
pub struct Statement {
    handle: usize,
}

impl Statement {
    pub fn new() -> Self {
        Self { handle: 0 }
    }
}

impl Default for Statement {
    fn default() -> Self {
        Self::new()
    }
}
