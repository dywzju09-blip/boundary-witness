# fltk 1.5.23 app::set_callback 工具全链路出证（0day 候选）

- 日期：2026-08-17
- 候选来源：高置信 0day 候选清单（fltk crate，crates.io 最新 1.5.23，无 RUSTSEC）
- 状态：**工具自动判定 → 自动生成 harness → ASan heap-use-after-free 出证**；
  过程中发现并定位 harness 生成器的 ASan profile 缺失缺陷

## 1. 候选形状

`app::set_callback<F, W>(widget: &mut W, cb: F)` 自由函数（`F: FnMut(&mut dyn WidgetExt)`，
**无 'static**）：

```rust
// fltk-1.5.23 src/app/widget.rs
let a: *mut Box<dyn FnMut(&mut dyn WidgetExt)> = Box::into_raw(Box::new(Box::new(cb)));
Fl_Widget_set_callback(widget.as_widget_ptr(), callback, data);  // 闭包经双层 Box 进 C++ widget
```

- 回调捕获非 'static 引用（RFC 2229 最小捕获，借用在 move 进泛型函数时被类型系统视为结束）；
- `Fl_Widget_do_callback`（C++ 事件回调路径）由 `WidgetExt::do_callback()`（safe）触发，
  shim 解引用存于 C++ 的闭包 → 读已 drop 的 referent → UAF；
- 判定（fltk-1523-contracts）：`guard=none`（返回值不携带注册存活约束）、
  `capture_admission=permits_non_static_capture`、`foreign_symbol=Fl_Widget_set_callback`、
  `registration_generation=multiple_static_sites`。

## 2. ASan 出证

时序：`app::set_callback(&mut w, callback) → drop(witness_referent) → w.do_callback()`

```text
ERROR: AddressSanitizer: heap-use-after-free
  #0 <alloc::vec::Vec<u8>>::len
  #1 <alloc::string::String>::len
  #2 main::{closure#0}  main.rs:21（闭包读 witness_referent.len()）
  #3 fltk::app::widget::set_callback::shim  app/widget.rs:49（catch_unwind）
  ... C++ Fl_Widget_do_callback 路径
SUMMARY: AddressSanitizer: heap-use-after-free in <alloc::vec::Vec<u8>>::len
```

## 3. 负对照（因果矩阵，detect_leaks=0）

| 变体 | 修改 | ASan | 退出 |
| --- | --- | --- | --- |
| vulnerable（正证） | drop referent + do_callback | **heap-use-after-free** | EXIT=1 |
| no-invalidate | 不 drop referent | 干净（0 错误） | EXIT=0 |
| no-trigger | 不调 do_callback | 干净（0 错误） | EXIT=0 |

## 4. 关键发现：生成器不输出 ASan profile 段

**`bw generate-witness-harness` 生成的 Cargo.toml 缺 `[profile.dev]`/`[profile.dev.package]`
rustflags 段**——harness 默认**无 ASan 插桩**。本次调试的完整过程：

1. 新生成 fltk-callback-harness1（无 profile）→ 运行无 UAF、闭包读"成功"
   （len=19、as_ptr=0x0、probe 复用同一地址）；
2. 做了大量误导性实验：最小复现（rustc 直接编译）报 UAF，怀疑 do_callback 中间
   分配复用 referent 块 → decoy 块技巧（8/128 个）无效；
3. **自检实验**（裸指针读 drop 的 Box<String>）在 harness 里也不报 → 判定 ASan 未生效；
   `nm <bin> | grep -c __asan_report` = **0**（ffmpeg/fltk-tree harness = 24）；
4. 对比发现 ffmpeg/fltk-tree harness 的 Cargo.toml 是**之前手动加过 profile 段**的，
   生成器本身不输出；
5. 补上 profile 段后 `nm` = 24 个 `__asan_report` 符号，正证一次通过。

**教训**：无 ASan 插桩时读悬垂堆内存"成功"（值残留），极易误判为"块被 allocator
复用"；**判定 harness 是否真带 ASan 的最快手段是 `nm <bin> | grep __asan_report`**。
生成器重写（5.3）必须输出 profile 段，否则所有新 harness 的 ASan 验证都是空转。

## 5. 证明了什么 / 没证明什么

**证明了**：

- 工具能自动检出「自由函数把非 'static 闭包经双层 Box::into_raw 交给 C++ widget +
  do_callback 晚调」形状：permits_non_static_capture + guard none → harness → ASan 出证；
- fltk set_callback 存在真实的 FFI 回调生命周期 soundness 缺陷（无 RUSTSEC 记录，
  披露判断需用户决定）；
- 负对照证明 invalidate/trigger 均为必要条件。

**没证明**：

- **harness 生成器缺 ASan profile 段**：当前生成物默认无 ASan，出证依赖手动补
  `[profile.dev] rustflags`——这是生成器的功能缺口（5.3 重写范围），本次未修生成器
  代码（避免越过阶段边界），只记录；
- ASan 对 Rust「大数据块（≥4096B）free 后读」漏检（mini-uaf5 实证：Vec/Box 数据块
  读不报、String/Vec 结构体小块报）——harness 的 referent 访问模式依赖小结构体块，
  大块 referent 会漏检，属 ASan+Rust 组合的已知形状，未深挖；
- 外部侧 LLVM IR 未参与（joint verdict 仍是 rust-only，trigger 路径由 ASan 栈给出）；
- fltk WidgetExt::set_callback（trait 方法，'static bound）不是本候选（自由函数无
  'static），未混淆。
