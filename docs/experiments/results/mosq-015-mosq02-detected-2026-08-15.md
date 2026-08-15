# mosquitto-client MOSQ-02（Callbacks self 指针 + move 逃逸 UAF）工具全链路出证

- 日期：2026-08-15
- 候选来源：用户 30 候选清单 MOSQ-02（mosquitto-client 0.1.5 `Callbacks` self 指针）
- 前置：rusqlite 7/7 + git2 2 + fluidlite + libsql LSQL-01 出证
- 状态：**工具自动判定 → 自动生成 harness → ASan stack-use-after-scope 出证**；
  判定层扩展「self 方法调用链 + 引用传播」+ decide_invalidate Permits 分支

## 1. 候选形状

`Callbacks::initialize(&mut self)`：
```rust
let pdata: *const Callbacks<T> = &*self;
mosquitto_user_data_set(self.mosq.mosq, pdata as *const Data);
```
- `on_connect`（回调闭包存字段）调用 `initialize()` → receiver 地址作 userdata 交给 C；
- `Callbacks` 非 `!Unpin`，可被 move（`Box::new(mc)` 搬出栈）；
- **move 不是 Drop**：旧栈槽作废但 Drop 不跑，C 仍持旧地址；
- `do_loop` 触发 `mosq_connect_callback` → 读已结束栈帧 → stack-use-after-scope。
- 与 LSQL-01 同属「receiver 地址逃逸」维度，但失效机制是 **move**（非 drop）。

## 2. 判定层扩展（compiler/bw-rustc + bw-cli）

| 扩展 | 位置 | 内容 |
| --- | --- | --- |
| ① owner-held 分支优先检查 receiver 逃逸 | `registration_guards` | 闭包 owner-held 时也先查 `receiver_escapes_as_userdata`——C 持有 receiver 地址比闭包释放更直接构成分离（mosquitto 的 `on_connect` 原本判 OwnerHoldsCallback，漏掉 receiver 逃逸） |
| ② self 方法调用链递归 | `receiver_escapes_as_userdata_inner` | `on_connect` 把 `&mut self` 传给 `initialize()`，真正的逃逸在被调方法里——沿「self 传给本地方法」的边递归（深度 ≤3，防环） |
| ③ self_ptrs 引用传播 | 收集循环 | `&*self as *const as *mut` 的中间是**引用**（Ref 变体），只收裸指针会断链——引用与裸指针都传播 |
| ④ decide_invalidate Permits 分支 | `generate_witness_harness.rs` | `PermitsNonStaticCapture` + `ReceiverEscapesAsUserData` → Generated（此前只 Refused） |

## 3. ASan 出证（harness 由生成器产出，未手工编辑）

时序：`m.callbacks(0i32) → on_connect(callback) → Box::new(mc)（move 出栈，块结束）→ do_loop`

```text
ERROR: AddressSanitizer: stack-use-after-scope
  #0 mosquitto_client::mosq_connect_callback::<i32>  lib.rs:785（读已结束栈帧上的 mc）
  #1-5 libmosquitto（mosquitto_loop → mosquitto_loop_read 调回调）
  #6 Mosquitto::do_loop  lib.rs:544
  #7 main  main.rs:27（harness 的 do_loop）
Address ... is located in stack of thread T0 ... in frame main (line 11)
```

与用户 PoC trace 一致。依赖**真实 broker**（mosquitto 2.0.11，服务器已装，on_connect 在连接建立后触发）。

## 4. 负对照（因果矩阵）

| 变体 | 修改 | ASan（detect_leaks=0） |
| --- | --- | --- |
| vulnerable | 原样（move + do_loop） | **stack-use-after-scope**（EXIT=1） |
| no-trigger | 不 do_loop | 干净（EXIT=0） |
| no-invalidate | 不 move（mc 留栈） | 干净（EXIT=0） |

## 5. 变异检查

改坏 self_ptrs 的 Ref 传播（引用不传播）→ on_connect guard 从
receiver_escapes_as_user_data 回落到 owner_holds_callback → decide_invalidate
Refused → 出证路径断裂；恢复后重新装配。**判据有判别力。**

## 6. 证明了什么 / 没证明什么

**证明了**：

- 工具能自动检出「receiver 地址作 userdata + **move 逃逸**（非 drop）」形状的 FFI UAF：
  self 方法调用链递归（on_connect → initialize）+ 引用传播 → ReceiverEscapesAsUserData
  → harness 自动生成（move 块 + do_loop）→ ASan stack-use-after-scope 出证；
- 失效机制从 drop 扩展到 move：`Box::new(mc)` 搬出栈即构成失效（旧栈槽出 scope）；
- Rust ASan（nightly-2026-07-08）能检测本形状的栈 use-after-scope（工具注释里的
  「栈 UAS 不可靠」在此形状上被推翻——插桩检测到了）；
- 变异检查证明判据有判别力；全量测试绿。

**没证明**：

- judge verdict 仍是 capture 维度（permits + guard 分支）——ReceiverEscapesAsUserData
  的 userdata 维度未进三态 verdict（与 LSQL-01 同一 gap，文档记录）；
- 外部侧（LLVM IR）未做——晚调路径（mosquitto_loop → 回调）由 libmosquitto C
  源码人工确认；
- move 的精确时机（块结束即 scope 结束）依赖 ASan 的栈生命周期插桩——若编译器
  优化改变栈布局可能漏检（本验证 unoptimized + debuginfo，确定性复现）；
- 未测其他回调（on_message/on_publish 等）——与 on_connect 同构（都经 initialize），
  未逐一出证。

## 7. 产物（远端 <results-root>/mosq-015-*）

- analysis/、contracts5/（on_connect guard=receiver_escapes_as_user_data）、
  joint/（rust-only）
- harness1/（vulnerable，ASan 出证）、harness-notrigger/、harness-noinvalidate/
  （对照干净）
- asan1.log（stack-use-after-scope）、control-notrigger.log、control-noinvalidate.log
