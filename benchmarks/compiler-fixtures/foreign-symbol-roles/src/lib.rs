//! 阶段 5.2 判据修正的回归 fixture：外部符号绑定里的 userdata 参数角色，
//! 以及 0 跳 safe entry 优先于调用图完整性的 lineage 判定。
//!
//! 三个 extern 形状对应真实 C API 的三种参数排布：
//!
//! - [`fixture_register_with_handle`]：接收者(handle)在 callback 之前——真实 FFI 最
//!   常见（`sqlite3_update_hook(db, cb, ud)`）。userdata 是 callback **之后**第一个
//!   裸指针，判 cb=1、ud=2；
//! - [`fixture_register_ud_first`]：userdata 在 callback **之前**
//!   （`sqlite3_create_function_v2(db, name, n, flags, pApp, xFunc, ..)` 的形状）。
//!   按保守规则 ud=None（缺证，不猜）；
//! - [`fixture_register_plain`]：fixture 原始形状（`cb, ud`），判 cb=0、ud=1。
//!
//! [`dispatch`] 里的函数指针调用让 crate 调用图**不完整**，用来验证 lineage 判据的
//! 顺序：0 跳 public safe entry 不依赖调用图，私有 hand-off 在调用图不完整时降为
//! `Unresolved` 而不是 `NoPublicSafeEntry`（缺证不是否定）。
#![allow(dead_code)]

use std::os::raw::c_void;

unsafe extern "C" fn trampoline<F: FnMut(*mut c_void)>(data: *mut c_void) {
    let callback = unsafe { &mut *data.cast::<F>() };
    callback(data);
}

unsafe extern "C" {
    fn fixture_register_with_handle(
        handle: *mut c_void,
        callback: Option<unsafe extern "C" fn(*mut c_void)>,
        user_data: *mut c_void,
    );
    fn fixture_register_ud_first(
        user_data: *mut c_void,
        callback: Option<unsafe extern "C" fn(*mut c_void)>,
    );
    fn fixture_register_plain(
        callback: Option<unsafe extern "C" fn(*mut c_void)>,
        user_data: *mut c_void,
    );
}

/// handle 在 callback 前：userdata 必须是 callback 后的第一个裸指针（ud=2），
/// 不得把 handle 误判成 userdata（ud=0）。
pub fn register_with_handle<F>(callback: F)
where
    F: FnMut(*mut c_void),
{
    let boxed = Box::into_raw(Box::new(callback));
    unsafe {
        fixture_register_with_handle(
            std::ptr::null_mut(),
            Some(trampoline::<F>),
            boxed.cast::<c_void>(),
        )
    };
}

/// userdata 在 callback 前：缺证不猜，ud=None。
pub fn register_ud_first<F>(callback: F)
where
    F: FnMut(*mut c_void),
{
    let boxed = Box::into_raw(Box::new(callback));
    unsafe {
        fixture_register_ud_first(boxed.cast::<c_void>(), Some(trampoline::<F>));
    }
}

/// 原始形状：cb=0、ud=1。
pub fn register_plain<F>(callback: F)
where
    F: FnMut(*mut c_void),
{
    let boxed = Box::into_raw(Box::new(callback));
    unsafe { fixture_register_plain(Some(trampoline::<F>), boxed.cast::<c_void>()) };
}

/// 私有 hand-off：调用图不完整时必须 Unresolved，不得是 NoPublicSafeEntry。
fn private_register<F>(callback: F)
where
    F: FnMut(*mut c_void),
{
    let boxed = Box::into_raw(Box::new(callback));
    unsafe { fixture_register_plain(Some(trampoline::<F>), boxed.cast::<c_void>()) };
}

/// 0 跳 public safe entry 经私有 wrapper 转发：自身仍是 DirectPublicSafeEntry。
pub fn register_via_private<F>(callback: F)
where
    F: FnMut(*mut c_void),
{
    private_register(callback);
}

/// 函数指针间接调用：让 crate 调用图不完整。
pub fn dispatch(callback: unsafe extern "C" fn(*mut c_void), data: *mut c_void) {
    unsafe { callback(data) }
}

/// 直接 `Box<dyn FnMut + 'a>` 参数形状（portaudio 家族）：回调不是泛型 F，
/// 而是 trait object。扩展后的回调识别必须把它判为回调参数。
pub struct BoxDynHolder<'a> {
    held: Option<Box<dyn FnMut() + 'a>>,
}

impl<'a> BoxDynHolder<'a> {
    pub fn set_boxed_callback(&mut self, callback: Box<dyn FnMut() + 'a>) {
        self.held = Some(callback);
    }
}

/// owner-held 持有形状：注册函数把回调分配存进 receiver 字段（git2 的
/// `set_progress_callback` 同款）。闭包随 owner drop 释放，referent 与 allocation
/// 的分离都不可构造——guard 判据必须识别为 `OwnerHoldsCallback`。
pub struct CallbackHolder<'a> {
    held: Option<Box<dyn FnMut() + 'a>>,
}

impl<'a> CallbackHolder<'a> {
    pub fn set_callback<F>(&mut self, callback: F)
    where
        F: FnMut() + 'a,
    {
        let boxed: Box<dyn FnMut() + 'a> = Box::new(callback);
        self.held = Some(boxed);
    }
}
