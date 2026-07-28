use crate::{Connection, Statement};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Insert,
    Update,
    Delete,
}

impl Connection {
    /// 合约里声明的注册 API：`rusqlite::Connection::update_hook`。
    pub fn update_hook<F>(&self, hook: Option<F>)
    where
        F: FnMut(Action, &str, &str, i64) + Send + 'static,
    {
        let _ = (&self.handle, hook.is_some());
    }
}

impl Statement {
    /// 同名方法，不同 owner。跨 crate 匹配必须区分开。
    pub fn update_hook<F>(&self, hook: Option<F>)
    where
        F: FnMut(Action, &str, &str, i64) + Send + 'static,
    {
        let _ = (&self.handle, hook.is_some());
    }
}
