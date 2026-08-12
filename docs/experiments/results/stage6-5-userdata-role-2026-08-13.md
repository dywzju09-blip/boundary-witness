# 阶段 6.5（能力①）：Rust 侧 userdata 角色识别——闭包分配形状

- 日期：2026-08-13
- 目标：把 rusqlite 同族 nday（RUSTSEC-2021-0128 覆盖但未出证的 4 个 API）推向 ASan
- 本记录范围：能力①——Rust 侧 userdata 参数角色推断（`sqlite3_create_function_v2` 的 pApp /
  `sqlite3_create_collation_v2` 的 pArg 在 callback 之前，原判据一律漏判）

## 1. 背景

stage6 joint 判定中，`create_scalar_function` / `create_collation` 停在 `rejected`，
原因 `user_data_role_mismatch` + `missing_slot_evidence`。前者的机制：

- Rust 侧 `foreign_callback_calls` 的 userdata 推断只认 **callback 之后**的第一个裸指针
  （5.2 修正：防 handle 误判）；
- rusqlite 把回调闭包本身 `Box::into_raw(Box::new(closure)) as *mut c_void` 作为
  userdata（pApp/pArg）交出，**位置在 callback 之前** → 原规则漏判 → `userdata_arg_index:
  null`，与外部侧人工 role map（ud=3/4）错配。

advisory 全量复核（2026-08-13，最新 advisory-db）：同形状（FFI 回调持有期 R/A 分离）
公开 nday 仍只有 rusqlite 一个；但其公告覆盖 7 个 API，仅 update/commit/rollback hook
3 个出证。剩余 4 个（create_collation / create_scalar_function / create_aggregate_function
/ create_window_function）全部因能力缺口停在 InsufficientEvidence。CVE-2021-45715 单独点名
create_window_function UAF。本阶段即补齐这些能力缺口，把 4 个 API 逐个推到 ASan。

## 2. 改动（compiler/bw-rustc/src/rustc_api/mir.rs）

新增 `userdata_from_closure_allocation`：对 callback **之前**的裸指针实参，沿 MIR 定义链
回溯：

```
裸指针实参 → Use/Cast 透传 → ptr::cast 方法透传 → Box::into_raw / Arc::into_raw
→ Box::new 实参 → 当前函数形参（被 box 的闭包） ⇒ userdata
```

判据刻意**不**放宽成「callback 前第一个裸指针」（那会把 handle 误认成 userdata，
5.2 已踩过）。只认「来源链是闭包 box + into_raw」的参数。

配套函数：`closure_box_into_raw_origin`（回溯主循环）、`box_new_origin`（Box::new/box 语法
实参）、`terminator_call_of`（Terminator Call 产值的定义查找）、`assign_rvalue_of`（Statement
Assign 定义查找）、`is_arg_local`（形参判定，`_0` 是返回槽）、`is_ptr_cast_method`。

## 3. 验证

### 3.1 fixture 回归（benchmarks/compiler-fixtures/foreign-symbol-roles/）

- `register_ud_first`（`Box::into_raw(Box::new(cb))` 作 callback 前 userdata）：`ud=0` ✓
- 新增负例 `register_ud_ptr_before`（callback 前任意裸指针，非闭包分配）：`ud=None` ✓
- 原有形状不回归：`register_with_handle`（cb=1, ud=2）、`register_plain`（cb=0, ud=1）✓
- 全部 compiler 测试绿（含 golden、portaudio 形状、safe-entry lineage 等）

### 3.2 真实目标（rusqlite 0.26.1，--all-features）

| API | 符号 | cb | ud（修复前） | ud（修复后） |
| --- | --- | --- | --- | --- |
| `Connection::create_scalar_function` | `sqlite3_create_function_v2` | 5 | null | **4**（pApp） |
| `Connection::create_collation` | `sqlite3_create_collation_v2` | 4 | null | **3**（pArg） |

judge-hand-offs 重跑：两个 API 的 `user_data_role_mismatch` **消除**，拒绝原因只剩
`missing_slot_evidence`（外部侧堆逃逸追踪，能力②，下一记录）。

### 3.3 变异检查

故意把 `is_arg_local` 改成恒 `false`：`userdata_role_follows_callback_parameter` 断言
`left: None, right: Some(0)` 转红，失败位置在预期那一行。改回后全绿。

## 4. 证明了什么 / 没证明什么

**证明了**：

- Rust 侧能自动识别「回调闭包分配作为 userdata 在 callback 之前交出」的形状
  （`Box::into_raw(Box::new(closure))` 链），不需要人工 role map 补位；
- 判据有判别力：闭包分配 userdata 与任意裸指针 userdata 分开判定（正/负例都有）；
- 修复后两侧 userdata 角色对齐，联结层不再因角色错配拒绝 create_*。

**没证明**：

- **外部侧 `missing_slot_evidence` 仍未解决**：SQLite 把 pApp/userdata 存入
  FuncDef/CollSeq、经 `sqlite3HashInsert` 挂进 db 哈希表的「堆对象插入 caller-owned
  容器」两点传播未被追踪，Q1/Q4′/Q3 仍全部 unresolved。这是能力②，下一步做；
- create_aggregate_function / create_window_function 仍无契约（多回调参数 xStep/xFinal
  形状未建模，能力③）；
- harness 生成与 ASan 出证尚未开始——两个 API 的判定仍不是 `SupportedIncompatibility`；
- `F: 'static` 的 A 类（allocation 提前释放）子问题在本形状上未被触发（rusqlite 用
  xDestroy 外部释放，A 类安全），本阶段只推进了 R 类路径。

## 5. 产物（远端 <results-root>/stage65-userdata/，不进入公开仓库）

- `analysis2/static-facts.jsonl`（新 bw-rustc 重跑）
- `rust-contracts/rust-contracts.jsonl`（ud=3/4 装配成功）
- `joint-cs/`、`joint-cc/`（拒绝原因只剩 missing_slot_evidence）
