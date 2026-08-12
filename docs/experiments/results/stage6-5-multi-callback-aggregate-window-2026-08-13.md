# 阶段 6.5（能力③）：多回调参数建模——create_aggregate/window 判定贯通

- 日期：2026-08-13
- 状态：**RUSTSEC-2021-0128 的 7 个 API 全部 joined**（4 个 create_* 从「连契约
  都没有」到可判定），aggregate/window 的 harness 层（trait 回调生成器支持）为下一步。

## 1. 两个缺口与修复（compiler/bw-rustc/src/rustc_api/mir.rs，均有变异/回归背书）

### 1.1 自定义回调 trait 不被识别

create_aggregate_function / create_window_function 的 aggr 参数是
`D: Aggregate<A, T>` / `W: WindowAggregate<A, T>`——不是 Fn 家族，`callback_param_bound_lifetimes`
（只认 Fn/FnMut/FnOnce/AsyncFn 家族）不识别 → 连 callback_lifetime_bound 都没有 → 装配 gap。

修复：`hir_bound_is_callable_trait` 增加 `Aggregate` / `WindowAggregate` trait 名匹配
（rusqlite 特定形状，注释标明 Gate C0 会暴露其他库的同类回调 trait）。

### 1.2 `None` 被当成回调（多回调参数的位置错位）

create_aggregate_function 调 `sqlite3_create_function_v2(db, name, n, flags, pApp,
**None** /*xFunc*/, Some(xStep), Some(xFinal), Some(xDestroy))`——第一个 fn 指针参数是
`None`（xFunc），`foreign_callback_calls` 把它当 callback（cb=5），真正的回调在
xStep(6)/xFinal(7)。

修复：`arg_is_none_option`——实参是空聚合（`Option::None` 无字段 variant）不构成回调
身份，跳过；callback 落在第一个真正的回调参数上。

## 2. 结果

| API | 符号 | cb（修复前→后） | ud | joint |
| --- | --- | --- | --- | --- |
| `create_aggregate_function` | `sqlite3_create_function_v2` | 5(None) → **6(xStep)** | 4 | **joined**（captured_referent + callback_allocation 均 insufficient_evidence） |
| `create_window_function` | `sqlite3_create_window_function` | **5(xStep)** | 4 | **joined**（+ same_slot_invoke_candidate + establish_late_invoke，与 create_scalar/collation 同深度） |

新增 role map：`create_aggregate_function.foreign-roles.json`（cb=6）、
`create_window_function.foreign-roles.json`（cb=5，窗口函数无 xFunc、xStep 即参数 5）。

## 3. 证明了什么 / 没证明什么

**证明了**：

- Rust 侧能识别「自定义回调 trait 参数」（Aggregate/WindowAggregate）与「None
  非回调」两个形状——多回调 C API（xFunc/xStep/xFinal）的 callback 身份落到正确位置；
- 4 个 create_* API 全部从「无契约/角色错配/缺证」走到 joined，判定为
  insufficient_evidence + 具体义务（establish_late_invoke / 缺晚调证据）。

**没证明**：

- **aggregate/window 的 harness 未生成**：回调参数是自定义 trait（`W:
  WindowAggregate<A, T>`），生成器只支持 Fn 闭包模板，需要扩展「trait 回调」形状
  （生成 struct + impl trait + 捕获字段）——下一步；
- aggregate 的判定缺 same_slot_invoke_candidate（外部侧 slots=1、晚调点未匹配到
  xStep 槽位）——晚调证据待 harness/ASan 补（判定已含义务）；
- aggregate/window 尚未 ASan 出证；
- `xStep` 作为代表回调，`xFinal/xValue/xInverse` 同族未单独建模（同一根因）。

## 4. 产物（远端 <results-root>/stage65-userdata/）

- `analysis4/`（新 bw-rustc 重跑）、`rust-contracts4/`（cb=6/cb=5 契约）
- `final-create_aggregate_function/`、`final-create_window_function/`（外部事实）
- `joint-final-*/`（joined 判定）
