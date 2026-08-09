# 阶段 5.3：反证生成器重写（D3）

- 日期：2026-08-10
- 决定依据：[codebase-realignment D3](../../development/codebase-realignment.md)
- 状态：**硬编码模板已重写为声明式 adapter + 判定驱动的生成器**，真实 vulnerable
  harness 生成、编译通过，二进制产出。

## 1. 重写内容

`crates/bw-cli/src/commands/generate_witness_harness.rs` 从 1266 行硬编码模板
（44 处 rusqlite、`SUPPORTED_APIS` 写死四个 API、产物依赖 bw-runtime）重写为
约 600 行的声明式生成器：

| 槽 | 来源 | 生成物中的样子 |
| --- | --- | --- |
| setup | adapter（冻结） | `let conn = Connection::open_in_memory()?;` 等片段原样拼入 |
| register | adapter + 判定给的参数角色 | `let _ = conn.update_hook(Some(callback));`（不写死 `?`，兼容 `()` 与 `Result` 返回） |
| invalidate | **由判定的 `PermitsNonStaticCapture` + guard 结论推出** | `let witness_referent = ...;` + 闭包捕获并访问 + `drop(witness_referent);` |
| trigger | adapter | `conn.execute("INSERT ...", [])?;` |

- 生成物带 `#![forbid(unsafe_code)]`；不依赖 bw-runtime（runtime 降级辅助定位，
  不进证据链顶层）；不用大模型生成（可复现、负对照不失效）。
- `bridge-witness-facts` 拆到独立文件 `commands/bridge_witness_facts.rs`（旧 witness
  链命令保留，生成器不再产出 site-bridge）。

## 2. invalidate 的推导规则

```text
PermitsNonStaticCapture + guard=None        → 生成 invalidate（分离可构造）
RequiresStaticCapture                        → 不生成（类型层排除借用捕获）
ContextDependent / Unresolved                → 不生成（缺证不猜）
guard 把槽位存活绑到 subject                 → 不生成（分离不可构造）
契约缺失                                     → 拒绝生成（contract_missing）
```

**不生成 invalidate 时回调仍引用 referent，而 referent 未声明 → 编译必然失败。**
这正是负对照要的行为：fixed 版在编译期就拒绝该时序，而不是跑出一个「干净」程序。

## 3. 验证

- 6 条单元测试（生成 / RequiresStaticCapture 拒 / guard 拒 / 契约缺失拒 /
  签名解析 / Cargo.toml pin）；
- **变异检查**：把 guard 判定条件改坏（None → TiesSlotToSubject），
  `invalidate_generated_when_capture_permitted_and_no_guard` 与
  `invalidate_refused_when_guard_binds_slot` 两条转红、其余 4 条仍绿，改回后全绿；
- 真实 5.2 产物端到端：`invalidate: generated`、`expected_compile: true`；
- 生成的 harness 用 vendored rusqlite 0.26.1（pinned `=0.26.1` + `[patch.crates-io]`）
  编译通过，二进制产出；无 ASan 下运行退出 0（悬垂读未崩——符合预期，出证需要 ASan，
  见 5.4）；
- bw-cli 全量测试绿（32+31+1+1+80）。

## 4. 过程中修正的三个实现问题

1. **注册调用不能写死 `?`**：rusqlite 0.26.1 的 `update_hook` 返回 `()`，
   `conn.update_hook(Some(callback))?;` 编不过。改为 `let _ = ...;`（对 `()` 与
   `Result` 都成立）。查证了 vendored 0.26.1 源码：`update_hook<'c, F>(&'c self, ...)
   where F: FnMut(Action, &str, &str, i64) + Send + 'c`——4 参数、`'c` bound，
   与 adapter 冻结的签名一致；
2. **adapter 的 target 字段名是 `crate`**（Rust 关键字），serde 需要 rename；
3. **生成物不写 use 行**：setup 片段与回调参数类型都来自 adapter 原文（完整路径），
   use 行反而 unused。

## 5. 这一步证明了什么，没证明什么

**证明了**：

- 从冻结 adapter + 5.2 判定产物可以**自动**生成可编译的 safe-only 反证 harness，
  危险时序（referent 失效）完全由判定推出，adapter 不含任何缺陷信息；
- 「判定说不能分离 → 编不过」的负对照行为由单元测试钉死（fixed 形状
  RequiresStaticCapture 不生成 invalidate），且有变异验证；
- 生成物 `#![forbid(unsafe_code)]`、零 unsafe、零 bw-runtime 依赖、依赖 pin 到
  vendored 0.26.1。

**没证明**：

- **反证真的触发 UAF。** 无 ASan 运行退出 0——悬垂读未崩。是否真发生
  stack-use-after-scope 要 5.4 的 ASan 出证；
- **fixed（0.26.2）的「编不过」只验证到单元测试层**，还没有真实 0.26.2 的契约与
  vendored 源码走一遍（vendor 目录只有 0.26.1；0.26.2 负对照在 5.5）；
- **回调分配（X=A）的 harness 形状**：当前 invalidate 只覆盖 referent 分离
  （X=R）；allocation 提前释放的形状（`'static` + Box 提前 drop）尚未生成；
- **通用性**：adapter schema 只被 update_hook 一个 adapter 实例验证过；
  callback_signature 解析只支持 `FnMut(...)` 扁平列表；
- 生成器选择契约按 api_path 尾段匹配（诊断性选择），两侧证据的联结仍由
  judge-hand-offs 完成，本次没有验证匹配歧义时的行为。
