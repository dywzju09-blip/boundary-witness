# fltk 1.5.23 TreeItem::draw_item_content 工具全链路出证（0day 候选）

- 日期：2026-08-17
- 候选来源：高置信 0day 候选清单（fltk crate，crates.io 最新 1.5.23，无 RUSTSEC）
- 状态：**工具自动判定 → 自动生成 harness → ASan heap-use-after-free 出证**；
  cfltk bundled 下载阻塞解除（GitHub 直连可用 + `CFLTK_BUNDLE_DIR` 指向预编译 lib）

## 1. 候选形状

`TreeItem::draw_item_content(&mut self, cb: impl Fn(&mut TreeItem, bool) -> i32)`——
绘制回调注册到 C++ `Fl_Tree_Item`，item 加入 Tree 后由 FLTK 事件循环在绘制时调用：

```rust
item.draw_item_content(callback);   // Rust shim 把闭包包装进 C++ 可调结构
tree.add_item("first", &item);
drop(witness_referent);             // ← 判定推出的 invalidate
win.show();
fltk::app::run();                   // ← 事件循环：绘制树 → C++ 调 shim → 闭包读已释放 referent
```

判定（fltk-1523-contracts）：`guard=receiver_escapes_as_user_data`（receiver 作为
userdata 交给 C++）、`capture_admission=permits_non_static_capture`、
`foreign_symbol=Fl_Tree_Item_draw_item_content`、`registration_generation=
unique_static_site`。

## 2. ASan 出证

```text
ERROR: AddressSanitizer: heap-use-after-free
READ of size 8
  #2 main::{closure#0}  main.rs:20   ← 闭包读 witness_referent.len()
  #3 fltk::tree::TreeItem::draw_item_content::shim  tree.rs:1203（Rust shim）
  #10 TreeItem::draw_item_content::shim（extern C 回调入口）
  #11 Fl_Tree_Item::draw(int, ...)   ← C++
  #13 Fl_Tree::calc_tree()           ← C++
  #14 Fl_Tree::draw()                ← C++
  #15 Widget_Derived<Fl_Tree>::draw()
  #18 Fl_Window::draw()
  #20 Fl_X11_Window_Driver::flush_double()
  #21 Fl::flush()
  #23 Fl::run()                      ← C++ 事件循环
  #25 main  main.rs:30               ← fltk::app::run()
SUMMARY: AddressSanitizer: heap-use-after-free in <alloc::vec::Vec<u8>>::len
```

证据链：**Rust 闭包（捕获 referent 引用）→ 经 draw_item_content shim 注册进 C++
Fl_Tree_Item → 事件循环绘制树（Fl_Tree::calc_tree → Fl_Tree_Item::draw）→ C++ 调
Rust shim → 闭包读已 drop 的 referent 堆 → heap-use-after-free**。

## 3. 负对照（因果矩阵，detect_leaks=0）

| 变体 | 修改 | ASan | 退出 |
| --- | --- | --- | --- |
| vulnerable（正证） | drop referent + 事件循环 | **heap-use-after-free** | EXIT=1 |
| no-invalidate | 不 drop referent（其余同正证） | 干净（0 错误） | EXIT=124（事件循环正常持续，timeout 杀） |
| no-trigger | drop referent + 不跑事件循环 | 干净（0 错误） | EXIT=0 |

invalidate 与 trigger 均为必要条件。

## 4. 构建阻塞解除（基础设施）

- cfltk bundled 之前失败是**临时网络问题**：GitHub release 直连当前可用
  （`lib_x86_64-unknown-linux-gnu.tar.gz` 2.2MB，含 libcfltk.a/libfltk.a 等）；
- `CFLTK_BUNDLE_DIR=<解包后 lib 目录>` 让 fltk-sys build 完全绕过下载
  （bundled.rs 优先读该环境变量）；预编译包已存
  `/mnt/hw/bw-agent/results/cfltk-lib/`；
- 生成器小缺陷：register 片段对 `TreeItem::new` 缺 `mut`（E0596），手动加
  `let mut item` 后编译通过——5.3 harness 生成器重写时参数角色应覆盖
  mutability。

## 5. 证明了什么 / 没证明什么

**证明了**：

- 工具能自动检出「receiver 作为 userdata 交给 C++ + 事件循环触发」形状：
  receiver_escapes_as_user_data 判定 → harness → ASan 出证；
- draw_item_content 的 Rust shim 把捕获非 'static 闭包的调用长期注册给 C++
  Fl_Tree_Item，drop 捕获对象后 C++ 绘制路径再调用 → 真实可构造 UAF；
- cfltk bundled 路径在当前环境可复现（下载 + CFLTK_BUNDLE_DIR 绕过），
  fltk 家族候选（set_callback 等）的 ASan 验证不再被构建阻塞。

**没证明**：

- 该缺陷的披露状态未确认（fltk 1.5.23 无 RUSTSEC 记录，是否已被上游修复、
  是否有 CVE 未知）——披露判断需用户决定；
- 外部侧（LLVM IR）未参与：trigger 路径（Fl_Tree_Item::draw → shim）由 ASan
  栈给出，IR 侧没有独立 retain/调用证据，joint verdict 仍是 rust-only；
- set_callback 候选（WidgetExt trait，几十个实例）判定已 joined，但 harness
  未建（缺 adapter），GUI 事件触发路径（widget 事件 → callback）未出证；
- 变异检查未针对 receiver_escapes 判据重做（该判据在 MOSQ-02 提交已变异验证）；
  bridged 变异（本次 ffmpeg 提交）不影响本候选（guard 不同）。
