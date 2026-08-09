# 阶段 5.2：真实目标 source-to-verdict

- 日期：2026-08-10
- 执行计划：[execution plan](../../roadmap/execution-plan.md) 阶段 4 完成条件 + 5.2 验收
- 目标：rusqlite 0.26.1（本体，--all-features，bundled sqlite3）
- 状态：**真实参考目标完成 source-to-verdict。** 联结 1 条、拒绝 0 条，所有 Unknown 都有具体缺证原因。

## 1. 命令链

```
bw extract-static-facts  (重跑：5.0 的 static-facts 不携带本次判据修复后的 lineage)
bw extract-rust-contracts --facts stage5-2/analysis/static-facts.jsonl
    --build-profile x86_64-unknown-linux-gnu/dev
    --rust-artifact rust:rusqlite:lib:01a74a6b8b30b37b
bw extract-foreign-facts  --ir foreign-ir/rusqlite-0.26.1/sqlite3.ll
    --roles adapters/rusqlite/update_hook.foreign-roles.json
    --foreign-artifact sqlite3.c:dce7451f…
    --build-profile x86_64-unknown-linux-gnu/dev   ← 与 Rust 侧同值
bw judge-hand-offs        --rust-contracts …/rust-contracts.jsonl
    --foreign-facts …/foreign-facts.jsonl
```

产物在远端 `<results-root>/stage5-2/`（不进入公开仓库）。

## 2. 数字

| 级 | 数量 |
| --- | --- |
| 静态事实 | 2252（--all-features，含 hooks/functions/session 等 feature 门控代码） |
| hand-off 交出点 | 50 |
| 装配成契约 | 17 |
| gap | 33（foreign_symbol_unresolved ×26、safe_entry_lineage_unresolved ×20；同一记录可带多个原因） |
| 外部事实 | 1（sqlite3_update_hook：MayRetain 2 槽位 / same_slot_invoke_candidate / clear unresolved） |
| 联结 | **1 joined、0 rejected、16 no_foreign_counterpart** |
| 判定 | insufficient_evidence ×2（captured_referent、callback_allocation） |

联结成功的判定细节（`Connection::update_hook` → `sqlite3_update_hook`）：

- **captured_referent**：`InsufficientEvidence` + `same_slot_invoke_candidate` +
  `EstablishLateInvoke` 义务。缺证原因具体到两条：Q3 是降级的（同槽间接调用点不证明晚调可达）；
  `registration_generation = multiple_static_sites`，把运行期注册归属到这一个静态点需要 witness。
- **callback_allocation**：`InsufficientEvidence`，原因 `allocation ownership unresolved`
  （rusqlite 的 `Box<F>` 由 trampoline 内 `from_raw` 回收，本函数体内看不到配对转移，
  PG-2 的已知覆盖缺口，非本次引入）。

## 3. 两个判据缺陷（本次修掉，都有变异验证）

### 3.1 safe-entry lineage：0 跳优先于调用图完整性

**症状**：第一次跑 `extract-rust-contracts`，50 个交出点全部 gap
（`safe_entry_lineage_unresolved`），装配 0 条。

**根因**：`crate_call_graph` 只要 crate 里出现任何解析不出被调方的调用
（函数指针、trait object、闭包间接调用）就置 `complete=false`；rusqlite 的
trampoline/闭包调用普遍存在，于是**整个 crate** 的 lineage 全部降为 Unresolved——
包括交出点自身就是 public safe API 的 0 跳情况。而 0 跳判定只依赖可见性与
`unsafe fn` 标记，不经过任何调用边。

**修复**：先判 `is_public_safe_entry`（0 跳，不依赖调用图），再判调用图完整性。
私有 hand-off 在调用图不完整时仍为 Unresolved（缺证不是否定，不降级为
`NoPublicSafeEntry`）。

**变异验证**：把顺序改回（调用图不完整优先）→ 新测试
`zero_hop_safe_entry_wins_over_incomplete_call_graph` 转红。

### 3.2 userdata 参数角色：只认 callback 之后的第一个裸指针

**症状**：联结 1 条被拒，原因 `user_data_role_mismatch`：Rust 侧
`userdata_arg_index=0`，外部 role map 是 2。

**根因**：`foreign_callback_calls` 把「第一个裸指针参数」当 userdata。真实 C API 的
接收者（sqlite3* 之类 handle）几乎总是 callback 之前的指针参数——rusqlite 的
`self.db()` 传的就是 `*mut sqlite3`，被误判成上下文。

**修复**：userdata 只认 callback **之后**的第一个裸指针；callback 前后都没有裸指针
时 `None`（缺证，不猜）。修复后 `update_hook`/`commit_hook` 等判 cb=1、ud=2，与
role map 一致；`create_scalar_function` 的 userdata 在 callback 之前
（`sqlite3_create_function_v2(db, name, n, flags, pApp, xFunc, …)`），按规则
ud=None——**缺证不猜**，记入已知限制。

**变异验证**：把规则改回「第一个裸指针」→ 新测试
`userdata_role_follows_callback_parameter` 转红（`register_with_handle` 的 ud 变回
0），且 lineage 测试保持绿——判别力定位准确。

## 4. MultipleStaticSites 预判的验证

预判：`Connection::update_hook` 与 `InnerConnection::update_hook` 指向同一符号，
代次会是 `MultipleStaticSites`。

**实际输出确认该预判成立，且行为正确**：`registration_generation =
multiple_static_sites` 被如实记录，并在判定里附加归属假设
（"attributing a runtime registration to this one needs a witness"），联结不被拒绝。
`InnerConnection::update_hook` 自身因 lineage 缺证（私有 + 调用图不完整）不装配，
但它的绑定仍计入符号注册点计数——归属假设因此不是装饰。

## 5. 回归 fixture

新增 `benchmarks/compiler-fixtures/foreign-symbol-roles/` 与
`compiler/bw-rustc/tests/foreign_symbol_roles_golden.rs`，覆盖三种参数排布
（handle 前 / userdata 前 / 原始形状）与 lineage 顺序。bw-rustc、bw-model、
bw-cli 全量测试绿。

## 6. 这一步证明了什么，没证明什么

**证明了**：

- rusqlite 0.26.1 的 `Connection::update_hook` 能从 Rust 源码与真实 sqlite3 IR 一路走到
  三态判定，两侧按符号 + 参数角色精确联结，**source-to-verdict 闭环在真实目标上成立**；
- 装配/联结的每一处缺证都有具体、机器可读的原因（gap reason / unresolved reason /
  obligation / assumption），没有静默丢弃；
- 两个判据缺陷（0 跳 lineage 顺序、userdata 角色）在真实目标上暴露、修复，且有
  变异验证证明测试有判别力；
- MultipleStaticSites 不会把联结变成零判定：归属假设被记录，判定照常产出。

**没证明**：

- **任何 SupportedIncompatibility 判定。** 真实目标上两条 verdict 都是
  `InsufficientEvidence`：Q3 仍是降级的（`EstablishLateInvoke` 义务），Q4′ 在真实库上
  无结论（`clear_only_on_some_paths`，入口参数校验的提前返回，已知未解决问题）。
  静态阶段到此为止**不能**说「这个 API 不相容」；
- **其他 5 条 hook 与 session/functions/collation 系列的判定。** 外部侧只有
  `sqlite3_update_hook` 一条 role map 与事实；其余符号没有 role map，走
  `no_foreign_counterpart`，不是失败但也不是判定；
- **userdata 在 callback 之前的形状**（`create_scalar_function` 等）：按保守规则
  ud=None，本次没有为此类形状提供角色判据——需要 role map 或新的推断规则才能联结；
- **PG-2 分配归属。** `allocation_no_into_raw` ×37、`allocation_multiple_callback_params`
  ×8：rusqlite 的 boxed 分配在 wrapper 层创建、trampoline 内回收，本函数体内的
  转移配对证据看不到（已知覆盖缺口，阶段 1.1 limitation）；
- **单库。** rusqlite 是开发对象，结果不进精度主表；上界 3 跳只在 rusqlite 验证过。
