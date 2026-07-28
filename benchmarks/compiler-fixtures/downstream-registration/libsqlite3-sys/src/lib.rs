//! 合约按 `libsqlite3_sys::*::sqlite3_update_hook` 识别 FFI 层注册。
//!
//! 这里给的是等价签名的桩，不调用真的 SQLite——fixture 要复现的是 def path 与参数
//! 形状，不是数据库行为。

use std::ffi::c_void;

pub mod bindings {
    use std::ffi::c_void;

    /// 参数顺序与真实 `sqlite3_update_hook` 一致：db、callback、user_data。
    pub fn sqlite3_update_hook(
        db: *mut c_void,
        callback: Option<unsafe extern "C" fn(*mut c_void)>,
        user_data: *mut c_void,
    ) -> *mut c_void {
        let _ = (db, callback, user_data);
        std::ptr::null_mut()
    }
}

pub use bindings::sqlite3_update_hook;

/// 让桩里的指针参数不被优化掉。
pub fn touch(pointer: *mut c_void) -> usize {
    pointer as usize
}
