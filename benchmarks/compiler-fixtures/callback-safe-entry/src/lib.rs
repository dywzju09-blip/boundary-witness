//! safe-entry lineage 的三组形状。
//!
//! 判定的主张是「**安全** API 允许 UB」。只能从 `unsafe fn` 或只能从 crate 内部私有
//! 路径到达的交出点，不构成该主张的证据——调用它本来就要写 `unsafe`，责任在调用方。
//! 没有这层过滤，候选池会混进大量与论题无关的位置。
//!
//! 四个形状的 Rust 侧回调 bound **完全相同**（都是无 outlives bound 的 `F: FnMut()`），
//! 差别只在「谁能走到它」。这与 Gate R 那组 fixture 的设计意图一致：把要检验的那一个
//! 变量单独隔离出来。
#![allow(dead_code)]

use std::os::raw::c_void;

unsafe extern "C" {
    fn fixture_register(
        callback: Option<unsafe extern "C" fn(*mut c_void)>,
        user_data: *mut c_void,
    );
}

unsafe extern "C" fn trampoline<F: FnMut()>(user_data: *mut c_void) {
    let callback = unsafe { &mut *user_data.cast::<F>() };
    callback();
}

fn hand_off<F: FnMut()>(callback: F) {
    let boxed = Box::into_raw(Box::new(callback));
    unsafe { fixture_register(Some(trampoline::<F>), boxed.cast::<c_void>()) };
}

/// **组 1**：公开的安全 API，自己就是入口 → `DirectPublicSafeEntry`（0 跳）。
pub fn public_safe_register<F>(callback: F)
where
    F: FnMut(),
{
    hand_off(callback);
}

/// **组 2**：公开但是 `unsafe fn`。调用它本来就要写 `unsafe`，**不是安全入口**。
///
/// 本 crate 里没有任何安全的公开函数调用它，因此 → `NoPublicSafeEntry`。
pub unsafe fn public_unsafe_register<F>(callback: F)
where
    F: FnMut(),
{
    hand_off(callback);
}

/// **组 3**：私有 helper，但有一个公开安全 wrapper 调它 → `ReachableFromPublicSafeEntry`。
///
/// 这一组是本 fixture 的重点：交出点自身不可见，安全客户端却确实能通过 wrapper 走到它。
/// 把「不是公开的」直接当成「安全客户端到不了」，就会漏掉整整一类真实的交出点。
fn private_helper_register<F>(callback: F)
where
    F: FnMut(),
{
    hand_off(callback);
}

/// 组 3 的公开安全 wrapper。
pub fn wrapper_over_private_helper<F>(callback: F)
where
    F: FnMut(),
{
    private_helper_register(callback);
}

/// **组 4**：私有 helper，且**没有**任何公开安全路径能到达 → `NoPublicSafeEntry`。
///
/// 与组 3 唯一的差别是没人从安全的公开 API 调它。这是负对照：证明判定看的确实是
/// 可达性，而不是「是不是私有的」。
fn unreachable_private_register<F>(callback: F)
where
    F: FnMut(),
{
    hand_off(callback);
}

/// 只有 `unsafe fn` 调组 4 的 helper。入口不安全，因此组 4 仍然不可达。
pub unsafe fn unsafe_only_caller<F>(callback: F)
where
    F: FnMut(),
{
    unreachable_private_register(callback);
}
