# git2 GIT-01（Rebase checkout 回调 UAF）判定层完成：receiver 桥接检测 + 延迟交出 harness

- 日期：2026-08-13
- 前置：git2-021-git02-detected-2026-08-13.md（GIT-02 已检出）
- 状态：**GIT-01 判定层完成**（guard=owner_holds_callback_bridged → 分离可构造 →
  harness 自动生成 → progress 回调被真实调用）；ASan 出证未完成（晚调触发后
  闭包对象访问的 ASan 报告待调试，如实记录）

## 1. 完成的检测链

`CheckoutBuilder::progress` 的形状：回调 `Box::new(cb)` 存进 receiver 字段（owner-held），
`configure` 把 `self as *mut _`（MIR 里是 `Rvalue::RawPtr`）写进 `libgit2_sys::git_checkout_options`
参数结构体字段，`Repository::rebase` 把整个 options memcpy 给 `git_rebase_init`。

### 新增判据：`receiver_bridged_to_foreign`（compiler/bw-rustc）

- receiver 类型的所有 inherent 方法里，找「receiver 被 cast 成裸指针（`&raw mut
  (*self)` = `Rvalue::RawPtr`，跨 rustc 版本变体不稳定 → 用「place 是裸指针类型 +
  rvalue 操作数引用 receiver/bridged」泛型识别）+ store 进参数结构体字段」；
- 参数结构体 = `raw::`/`ffi`/`sys`/`_sys` crate（bindgen 输出惯例；git2 0.21 的
  `git_checkout_options` 在 `libgit2_sys`）；
- owner-held 检查提前（回调存字段优先于返回值形状——progress 返回 `&mut Self` 带
  'cb，原判据走 guard 类型路径漏掉存字段）；
- 命中 → `RegistrationGuard::OwnerHoldsCallbackBridged` → `decide_invalidate`
  Generated（分离可构造）。

### 装配与生成器

- `RustHandOffKey.foreign_symbol` 改 `Option<String>`（bridged 无符号，非占位）；
- 装配允许 bridged 无符号契约；`callback_arg_index` bridged 时占位 0（不参与
  bridged 的联结/生成，由 adapter 提供）；
- 生成器新增 `register_template`（延迟交出完整注册代码，含 `{callback}`）与
  `invalidate_prelude`（判定允许分离时、drop referent 前释放回调 owner 链）——
  两者是「如何合法调用/释放」的 API 形状；**referent 失效仍由判定推出**。

## 2. 验证

- git2 0.21.0：`CheckoutBuilder::progress/notify` guard = **owner_holds_callback_bridged**；
- 契约装配成功（symbol=None, guard=bridged）；
- harness 自动生成：`cb.progress(callback) → opts.checkout_options(cb) →
  repo.rebase(opts) → drop(opts) → drop(referent) → rebase.next()`；
- 运行：**CALLBACK-INVOKED**（progress 回调被真实调用）；
- 变异检查：RawPtr 识别改坏 → guard 从 bridged 回落 owner_holds_callback ✓；
- 全量测试绿（bw-rustc / bw-foreign-ir / bw-cli）。

## 3. 证明了什么 / 没证明什么

**证明了**：

- 工具能识别「回调存字段 + receiver 桥接到外部 C 结构体」的延迟交出形状
  （GIT-01 判定层）；
- bridged 契约能装配（无符号诚实表达）、生成器能产出延迟交出 harness、回调被
  外部真实调用。

**没证明**：

- **ASan 未出证**：harness 运行 exit=0 无 UAF——rebase.next() 调用了 progress 回调
  但 ASan 未报。可能原因（待调试）：drop(opts) 后闭包 Box 的实际释放路径、
  libgit2 checkout 的 payload 语义、或 ASan 对 libgit2 C 代码调用链的插桩边界。
  **不把「回调被调用但无 ASan 报告」当作候选证伪**（缺证不是否定）；
- 外部侧（git_rebase_init memcpy 保留 + 晚调）未做独立 IR 证明；
- 负对照（owned/no-trigger）未跑。

## 4. 产物（远端 <results-root>/git2-021-*）

- analysis25/（guard=bridged）、contracts8/（bridged 契约装配）
- harness-rebase9/（自动生成 + CALLBACK-INVOKED 验证）
- git2-021-asan-rebase.log（exit=0，无 UAF，待调试）
