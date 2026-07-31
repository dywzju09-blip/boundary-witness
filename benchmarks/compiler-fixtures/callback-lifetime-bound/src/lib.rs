//! 回调参数生命周期 bound 的四种定义点形状。
//!
//! 每个方法都是一个签名判据的样本，四个 scope 各一个。这里没有任何调用代码：判定只读
//! HIR 签名，这正是"扫组件本体"的含义。
//!
//! `receiver_scoped` 与 `static_scoped` 的差别就是 `rusqlite` 0.26.1 → 0.26.2 那一处
//! 修复的全部内容：`F: FnMut(..) + 'c` 变成 `F: FnMut(..) + 'static`。
#![allow(dead_code)]

use std::os::raw::c_void;

unsafe extern "C" {
    /// 站在 C 侧持有回调的注册函数。它对 Rust 这边的借用一无所知，因此把回调的存活期
    /// 绑在 `&'c mut self` 上是不健全的。
    fn fixture_register_callback(
        handle: *mut c_void,
        callback: Option<unsafe extern "C" fn(*mut c_void)>,
        user_data: *mut c_void,
    );
}

unsafe extern "C" fn trampoline<F: FnMut()>(user_data: *mut c_void) {
    let callback = unsafe { &mut *user_data.cast::<F>() };
    callback();
}

pub struct Handle {
    raw: *mut c_void,
}

pub struct Registry<'owner> {
    handle: &'owner Handle,
}

impl Handle {
    /// `'c` 由 receiver 引入 → `declared_receiver_lifetime`。
    ///
    /// 回调被交给 C 侧长期持有，但签名只要求它活过这一次 `&'c mut self` 借用。这是
    /// `rusqlite` 0.26.1 `update_hook` 的形状。
    pub fn receiver_scoped<'c, F>(&'c mut self, callback: F)
    where
        F: FnMut() + Send + 'c,
    {
        let boxed = Box::into_raw(Box::new(callback));
        unsafe {
            fixture_register_callback(
                self.raw,
                Some(trampoline::<F>),
                boxed.cast::<c_void>(),
            );
        }
    }

    /// `'static` bound → `static_lifetime`。这是 0.26.2 收紧后的形状，健全。
    pub fn static_scoped<F>(&mut self, callback: F)
    where
        F: FnMut() + Send + 'static,
    {
        let boxed = Box::into_raw(Box::new(callback));
        unsafe {
            fixture_register_callback(
                self.raw,
                Some(trampoline::<F>),
                boxed.cast::<c_void>(),
            );
        }
    }

    /// 完全没有 outlives bound → `no_lifetime_bound`。签名本身不表态。
    pub fn unbounded<F>(&mut self, callback: F)
    where
        F: FnMut() + Send,
    {
        let mut callback = callback;
        callback();
    }

    /// 内联写在泛型参数上的 bound。rustc 会把它降到 `generics.predicates`，所以和
    /// where 子句形式必须给出同一个判定——这条是那个假设的样本。
    pub fn receiver_scoped_inline<'c, F: FnMut() + 'c>(&'c mut self, callback: F) {
        let boxed = Box::into_raw(Box::new(callback));
        unsafe {
            fixture_register_callback(
                self.raw,
                Some(trampoline::<F>),
                boxed.cast::<c_void>(),
            );
        }
    }

    /// `Fn` bound 与 outlives bound 拆在两条 where predicate 里。合法写法，语义与
    /// `receiver_scoped` 完全相同，判定也必须相同。
    ///
    /// 逐条 predicate 判定会把第一条读成"有 Fn bound、没有 outlives bound"，给出一个
    /// 看起来完全正常的 `no_lifetime_bound`——缺陷就这样静默漏掉。
    pub fn receiver_scoped_split_predicates<'c, F>(&'c mut self, callback: F)
    where
        F: FnMut(),
        F: 'c,
    {
        let boxed = Box::into_raw(Box::new(callback));
        unsafe {
            fixture_register_callback(self.raw, Some(trampoline::<F>), boxed.cast::<c_void>());
        }
    }

    /// 普通泛型参数，没有 `Fn` 家族 bound，即使 outlives 到声明的 lifetime 也不该产出
    /// 事实。判据是"回调参数"，不是"任何被 lifetime 约束的泛型参数"。
    /// APIT：`impl FnMut()` 在参数位置。语义上等同于一个无 outlives bound 的泛型参数，
    /// 因此**允许捕获借用**。
    pub fn apit_unbounded(&mut self, callback: impl FnMut()) {
        let _ = callback;
    }

    /// APIT 加显式 `'static`。
    pub fn apit_static(&mut self, callback: impl FnMut() + 'static) {
        let _ = callback;
    }

    /// `Box<dyn FnMut()>`：省略的 trait object lifetime **默认到 `'static`**。
    ///
    /// 它与 `unbounded` 在「有没有写 outlives bound」这一点上完全一样，但语义相反：
    /// 这里根本不允许捕获借用。把两者合并成同一个取值就是错的。
    pub fn boxed_dyn_default(&mut self, callback: Box<dyn FnMut()>) {
        let _ = callback;
    }

    /// `Box<dyn FnMut() + 'c>`：显式声明的 lifetime，允许捕获借用。
    pub fn boxed_dyn_declared<'c>(&'c mut self, callback: Box<dyn FnMut() + 'c>) {
        let _ = callback;
    }

    /// `&'c mut dyn FnMut()`：引用形式的 trait object，默认 lifetime 取自引用本身。
    pub fn ref_dyn_default<'c>(&'c mut self, callback: &'c mut dyn FnMut()) {
        let _ = callback;
    }

    /// HRTB：`for<'r> FnMut(&'r u8)` 约束的是**回调参数**的 lifetime，不是捕获环境的。
    /// 它对「能否捕获借用」不表态，不得被读成 `'static`。
    pub fn hrtb_arg_lifetime<F>(&mut self, callback: F)
    where
        F: for<'r> FnMut(&'r u8),
    {
        let _ = callback;
    }

    pub fn not_a_callback<'c, T>(&'c mut self, value: T) -> usize
    where
        T: Clone + 'c,
    {
        let _ = value.clone();
        0
    }
}

impl<'owner> Registry<'owner> {
    /// `'other` 由另一个参数引入，不来自 receiver → `declared_free_lifetime`。
    ///
    /// 仍然短于 `'static`，所以仍然不健全，只是绑的不是 receiver 那次借用。rlua 的
    /// scope 形状属于这一类。
    pub fn free_scoped<'other, F>(&self, anchor: &'other Handle, callback: F)
    where
        F: FnMut() + 'other,
    {
        let boxed = Box::into_raw(Box::new(callback));
        unsafe {
            fixture_register_callback(
                anchor.raw,
                Some(trampoline::<F>),
                boxed.cast::<c_void>(),
            );
        }
    }
}
