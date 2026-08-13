# git2 0.21.0 候选验证：GIT-01 / GIT-02（unseen 0day 候选 × 工具判据）

- 日期：2026-08-13
- 目的：用户提供的两个 git2 0.21.0 候选（Rebase checkout 回调 UAF / Revwalk
  hide_cb UAF）是否是工具能检测的类型；跑真实判定链验证。

## 1. 结论（先看）

**两个候选都是工具要找的类型（R 类：回调持有期 UAF，与 rusqlite 同族），
但工具当前实现都检不到**——各自撞上一个明确可修的判据盲区：

| 候选 | 类型匹配 | Rust 侧 | 外部侧（libgit2 1.9.3 IR） | 工具当前结果 |
| --- | --- | --- | --- | --- |
| **GIT-01** Rebase checkout 回调 | ✅ R 类（`FnMut + 'cb`，PermitsNonStaticCapture） | ❌ `CheckoutBuilder::progress/notify` **GAP**（`foreign_symbol_unresolved`） | —（GIT-01 的 memcpy 形状回调嵌在 `git_rebase_options` 结构体里，role map 无法表达结构体字段回调） | **检不到**（存字段延迟交出盲区） |
| **GIT-02** Revwalk hide_cb | ✅ R 类（`&'cb mut C`，PermitsNonStaticCapture） | ⚠️ 契约有（cb=1, ud=2, symbol=git_revwalk_add_hide_cb），**guard=unresolved**（Result 包装，`guard_bound_lifetime_ab…`） | ✅ **may_retain**（revwalk[13] hide_cb / revwalk[14] payload）+ **may_invoke_after_return** | **判定 joined + insufficient_evidence**，但 witness 层 `decide_invalidate` 对 guard=Unresolved **Refused** → harness 不生成 |

## 2. GIT-02 判定链实测

- `extract-static-facts`（git2 0.21.0，--features vendored-libgit2）：4405 条事实；
- `extract-rust-contracts`：`Revwalk::with_hide_callback` 契约
  `admission=permits_non_static_capture`、`guard=unresolved`、symbol=git_revwalk_add_hide_cb；
- `extract-foreign-facts`（libgit2 1.9.3 IR，修复 #dbg_* 后）：
  `retention=may_retain`、2 槽位、`invocation=may_invoke_after_return`；
- `judge-hand-offs`：**joined**，captured_referent = insufficient_evidence +
  same_slot_invoke_candidate（assumption: registration guard shape unresolved）。

**Witness 层假阴性**：`decide_invalidate` 对 guard=Unresolved 走 Refused
（"guard 把槽位存活绑到被捕对象"）→ 不生成 harness。但 GIT-02 的 guard
（RevwalkWithHideCb<'cb>）是**假的**——`into_inner()` 拆掉 'cb 且
`git_revwalk_reset` 不清 hide_cb、Drop 不注销。guard=Unresolved 是**缺证**，
不是"判定说不能分离"。

## 3. GIT-01 判定链实测

`CheckoutBuilder::progress/notify`：callback_lifetime_bound（'cb）✓、
registration_guard（unresolved，guard_return_type_not_adt）、safe_entry（0 跳）✓，
但 **foreign_symbol_binding = no_foreign_call_within_search_depth** → 装配 GAP。

**盲区机制**：progress 只把闭包 `Box::new(cb)` 存进 `self.progress` 字段，
**当场不调 extern**；真正的交出发生在 `configure()`（`opts.progress_payload =
self`）→ `Repository::rebase(opts)` → `git_rebase_init`（libgit2 memcpy 整个
options）。工具的 foreign_symbol_binding 从"声明回调参数的方法"沿调用图找 extern，
对"存字段 + 延迟经另一 API 交出"的形状找不到 → GAP。

## 4. 顺带修复：`#dbg_declare` 调试指令（clang 14+ 新格式）

libgit2 1.9.3 的 IR 用 **`#dbg_declare`** 指令（opaque pointer + 新 debug 格式），
不是旧 `call @llvm.dbg.declare`。工具把它当 `Other` → 形参落栈 alloca 被
`find_spill_allocas` 判 disqualify → Q1 数据流整条断（store_to_unresolved_pointer）。

修复：新增 `InstKind::DbgIntrinsic`（parse 识别 `#dbg_*` 前缀），operands 为空
（不产生 uses）、find_spill 非逃逸。**变异检查**：改坏识别后新测试转红
（Unresolved 而非 NoRetain——缺证纪律同验）。修复前/后 git2 实测：
store_to_unresolved_pointer → may_retain + 2 槽位。

**rusqlite 为何没触发**：其 IR 是 clang 旧 debug 格式（call @llvm.dbg.declare），
已有 is_non_escaping_intrinsic 处理。git2 的 libgit2-sys build.rs CFLAGS 触发了
新格式。**0day 扫描（最新版 C 库）都会遇到新格式，此修复是前提**。

## 5. 修复方向（后续工作，非本次范围）

1. **GIT-01**：存字段 + 延迟交出的跨方法追踪（回调存进 receiver 字段后，receiver
   作为 userdata 交给外部）——`foreign_symbol_binding` 需支持"字段流"路径；
2. **GIT-02a**：`decide_invalidate` 对 guard=Unresolved 不应直接 Refused——guard
   有效性是外部侧 Q4′ 的事（thesis §2.6），guard 缺证时让 harness 尝试编译
   （编不过 = 负对照，编过 = 候选）；
3. **GIT-02b**：guard 拆除 API 识别（into_inner 返回不带 'cb 的类型）——需要
   "guard 类型的所有方法是否保持绑定"分析；
4. GIT-01 的 role map 表达结构体字段回调（git_rebase_options.checkout_options）。

## 6. 产物（远端 <results-root>/git2-021-*，不进入公开仓库）

- `git2-021-analysis/`、`git2-021-contracts/`、`git2-021-joint*/`
- `git2-021-foreign-ir/`（199 编译单元，libgit2 1.9.3）
- `git2-021-foreign4/`（may_retain + 2 槽位 + 晚调）
