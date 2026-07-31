//! Gate R 的四个 matched fixture：Rust 侧的三种形状。
//!
//! 这些形状与 `foreign/` 下的 C stub 组成四个 fixture，用来验证
//! [`research thesis`] §2.4 的关系确实能分开该分开的情况。对应关系见
//! `foreign/README.md`。
//!
//! **最关键的设计约束**：fixture 2 与 fixture 3 使用**同一个** Rust 形状
//! （[`Registry::register_guarded`]），差别**全部**落在 C stub 的注销是否真的清空槽位。
//! 若判定器能分开这两个，就证明外部侧证据带来了 Rust 侧拿不到的判别力；若分不开，
//! 说明外部侧对这条关系没有净贡献。
//!
//! 这里没有任何调用代码：判定读的是定义点，这正是「扫组件本体」的含义。
//!
//! [`research thesis`]: ../../../../docs/project/research-thesis.md
#![allow(dead_code)]

use std::os::raw::c_void;

unsafe extern "C" {
    /// 把回调与 user data 交给外部组件。外部把它们存进一个跨调用存活的槽位。
    fn fixture_register(
        callback: Option<unsafe extern "C" fn(*mut c_void)>,
        user_data: *mut c_void,
    );

    /// 请求外部清除当前注册。**它是否真的清空槽位，只有外部侧的代码能回答**——
    /// 这正是 Q4′ 要判的东西，也是 fixture 2 与 3 的唯一差别。
    fn fixture_unregister();
}

unsafe extern "C" fn trampoline<F: FnMut()>(user_data: *mut c_void) {
    let callback = unsafe { &mut *user_data.cast::<F>() };
    callback();
}

pub struct Registry;

/// 注册句柄。它的类型把注册的存活期绑在 `'reg` 上，`Drop` 请求注销。
///
/// 这是「guard 形状」：安全客户端**无法**在持有它的期间让被捕对象失效。但这个保护
/// 是否真的成立，取决于 [`fixture_unregister`] 在外部侧是否真的清空了槽位。
pub struct Registration<'reg> {
    marker: std::marker::PhantomData<&'reg ()>,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        unsafe { fixture_unregister() };
    }
}

impl Registry {
    /// **fixture 1 的 Rust 侧**：允许捕获借用，且没有任何 guard。
    ///
    /// `F` 上没有 `'static`，因此安全客户端可以传一个借用了局部变量的闭包；注册之后
    /// 没有任何类型层约束阻止那个局部变量先失效。这是主线缺陷的最直接形状。
    pub fn register_borrowed<F>(&self, callback: F)
    where
        F: FnMut(),
    {
        let boxed = Box::into_raw(Box::new(callback));
        unsafe { fixture_register(Some(trampoline::<F>), boxed.cast::<c_void>()) };
    }

    /// **fixture 2 与 fixture 3 共用的 Rust 侧**：允许捕获借用，但返回 guard。
    ///
    /// 返回值的 lifetime 把注册绑在 `&'reg self` 上，`Drop` 请求注销。**只看 Rust
    /// 这一侧，无法判断这个 API 是否健全**——要看注销在外部侧做了什么。
    pub fn register_guarded<'reg, F>(&'reg self, callback: F) -> Registration<'reg>
    where
        F: FnMut() + 'reg,
    {
        let boxed = Box::into_raw(Box::new(callback));
        unsafe { fixture_register(Some(trampoline::<F>), boxed.cast::<c_void>()) };
        Registration {
            marker: std::marker::PhantomData,
        }
    }

    /// **fixture 4 的 Rust 侧**：`'static` bound，但分配提前释放。
    ///
    /// `F: 'static` 保证闭包没有捕获任何借用——**它对 `Box<F>` 本身的存活不表态**。
    /// 这里 wrapper 在注册之后立刻回收了那块分配，而外部仍持有指向它的指针。
    ///
    /// 按 bound 形状判定的旧 2×2 矩阵会把这个 API 判成「相容」。这是它的漏报。
    pub fn register_static_then_free<F>(&self, callback: F)
    where
        F: FnMut() + 'static,
    {
        let boxed = Box::into_raw(Box::new(callback));
        unsafe { fixture_register(Some(trampoline::<F>), boxed.cast::<c_void>()) };
        // 交出之后立刻回收：外部槽位里的指针从此悬垂。
        drop(unsafe { Box::from_raw(boxed) });
    }

    /// 负对照：`'static` bound，且分配交由外部持有到注销为止。
    ///
    /// 两类生命周期都被约束住，无论外部是否保存并晚调都相容。
    pub fn register_static_owned<F>(&self, callback: F)
    where
        F: FnMut() + 'static,
    {
        let boxed = Box::into_raw(Box::new(callback));
        unsafe { fixture_register(Some(trampoline::<F>), boxed.cast::<c_void>()) };
        // 这里**没有**回收动作：`Box::into_raw` 之后所有权已随注册交给外部，直到
        // 注销才由外部释放。与 `register_static_then_free` 的差别就是少了那一次
        // `Box::from_raw`。
    }
}
