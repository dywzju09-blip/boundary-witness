//! 依赖 crate 里的薄封装：注册被包了一层，调用方的代码里根本不出现合约 API 的名字。
//!
//! 这是真实封装库最常见的形状，也是跨 crate 摘要必须看穿的那一层。要认出调用方那次
//! 调用是注册，得先读到**这个 crate** 的函数体，确认参数 1 是 callback、参数 2 是
//! user data，再把下标映射回调用方的实参。
//!
//! 两个前提缺一不可：分析不能因为 callee 不是本地 crate 就放弃，且依赖必须带着 MIR
//! 编译（`-Zalways-encode-mir`）——rustc 默认不为普通 `pub fn` 编码 MIR。

use std::ffi::c_void;

/// callback 与 user data 原样透传给 FFI 层注册。
pub fn install_update_hook(
    callback: Option<unsafe extern "C" fn(*mut c_void)>,
    user_data: *mut c_void,
) {
    let _previous =
        libsqlite3_sys::bindings::sqlite3_update_hook(std::ptr::null_mut(), callback, user_data);
}
