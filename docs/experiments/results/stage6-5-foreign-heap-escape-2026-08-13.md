# 阶段 6.5（能力②）：外部侧堆逃逸追踪——容器插入/查找两点传播

- 日期：2026-08-13
- 目标：消除 create_scalar_function / create_collation 的 `missing_slot_evidence`
- 前置：能力①（Rust 侧 userdata 角色）已完成并提交（54d289b）

## 1. 背景与机制

stage6 joint 判定中，create_* 除 `user_data_role_mismatch` 外还停在
`missing_slot_evidence`：SQLite 把 userdata / 回调存进**堆对象字段**（FuncDef /
CollSeq），堆对象经哈希表挂进 db（caller-owned 参数可达的容器）。分析器对
「store 到非 caller-owned 结构体字段」一律记 `SlotNotProvenCallerOwned`（缺证），
Q1 恒 unresolved。

两条传播链（真实 IR 确认）：

| 路径 | 存储 | 挂载 | 取回 |
| --- | --- | --- | --- |
| create_scalar_function | `sqlite3CreateFunc`: store pApp→FuncDef[2]、xFunc→FuncDef[4] | `sqlite3FindFunction` 内 `sqlite3HashInsert(&db->aFunc/*字段75*/, name, FuncDef)` | `sqlite3VdbeExec` 等从 FuncDef 字段 load 后调用 |
| create_collation | `createCollation`: store pUser→CollSeq[2]、xCmp→CollSeq[3] | `findCollSeqEntry` 内 `sqlite3HashInsert(&db->aCollSeq/*字段76*/, ...)`（新建）；替换路径 `sqlite3HashFind` 返回容器已有对象 | 排序时从 CollSeq 字段 load |

## 2. 判据（crates/bw-foreign-ir/src/query.rs）

`trace_param` 的 Store 分支扩展：dest 非 caller-owned 时，先尝试
`store_target_reaches_caller_container`（证明基址是「容器可达堆对象」的字段），
证不出来才记 `SlotNotProvenCallerOwned`（缺证不降级为「没保留」）。

判据四步，全部从 IR 推导（符号名只是候选入口，语义由 IR 验证）：

1. **`source_call_of`**：dest 沿 GEP base / load / cast / alloca 落栈链回溯，
   找到「定义是外部调用返回值」的那一跳（如 sqlite3FindFunction /
   sqlite3FindCollSeq）；
2. **容器可达**：被调函数内找 `*HashInsert*` / `*HashFind*` 调用，容器参数
   （`&db->aFunc` 之类 GEP）可达自 caller-owned 形参或模块全局；
3. **同源**：插入对象参数 / 查找返回值的 alloca trail 与函数返回值 trail 有交集
   （`call:<callee>` 标记让跨函数返回链可相交）；
4. **递归**：容器调用可能隔一层包装（`sqlite3FindCollSeq` →
   `findCollSeqEntry` → `sqlite3HashFind`），沿 ret trail 里的 call 标记递归
   （独立深度上限 3，不占用「交出点包装深度」）。

## 3. 顺带修掉的三个 IR 解析器 bug（都有测试/变异背书）

1. **`Operand::parse` 把类型名当值**：`store %struct.FuncDef* null` 的最后一个
   `%` token 是类型名，值 `null` 不是 `%` token。新增 `parse_trailing_value`
   用于 store 值 / ret 值（值恒在末尾的段）；
2. **ret 尾随元数据**：`ret %struct.FuncDef* %185, !dbg !1` 被解析成
   `Local("185,")`（带逗号）。`parse_return_value` 先截断逗号；
3. **bitcast 目标类型含 `%`**：`bitcast i8* %13 to %struct.CollSeq*` 的目标类型
   含 `%`，`Operand::parse` 优先取最后一个 `%` token 会把目标类型当来源。
   新增 `cast_src_segment`：值在第一个 `to` 之前。

## 4. 验证

### 4.1 fixture（crates/bw-foreign-ir/tests/cross_function.rs，全部含变异）

- `store_to_heap_object_inserted_into_caller_container_is_may_retain`：HashInsert
  形状 → MayRetain + slots 非空；变异 `is_container_insert=false` → 断言转红
  （且 retention 是 Unresolved 不是 NoRetain——缺证纪律同时被验证）；
- `store_to_heap_object_read_from_caller_container_is_may_retain`：HashFind 形状
  （collation 替换路径）→ MayRetain；变异 `is_container_find=false` → 转红；
- `heap_object_without_container_insert_is_not_may_retain`：无容器插入 → 非
  MayRetain 且非 NoRetain（缺证）。

### 4.2 真实目标（rusqlite 0.26.1，--all-features）

| API | slots | retention | 修复前 joint | 修复后 joint |
| --- | --- | --- | --- | --- |
| `Connection::create_scalar_function` | FuncDef[2] pUserData、FuncDef[4] xSFunc | may_retain | rejected（user_data_role_mismatch + missing_slot_evidence） | **joined** |
| `Connection::create_collation` | CollSeq[2] pUser、CollSeq[3] xCmp | may_retain | 同上 | **joined** |

判定内容（与 update_hook 家族同深度）：

- captured_referent：`insufficient_evidence` + `same_slot_invoke_candidate` +
  `establish_late_invoke` 义务（multiple_static_sites 假设 + 晚调可达性待 witness）；
- callback_allocation：`insufficient_evidence` + same_slot_invoke_candidate；
- 外部侧 Q3 找到 3 个同槽间接调用点：`sqlite3VdbeExec` ×2、`valueFromFunction`
  ——正是 SQLite 执行 UDF 时调用 xFunc 的位置。

## 5. 证明了什么 / 没证明什么

**证明了**：

- 外部侧 Q1（跨调用保留）能从真实 LLVM IR 推出**堆对象经容器挂进
  caller-owned 可达对象**的形状——不再只认全局槽位与 caller-owned 对象字段；
- create_scalar_function / create_collation 的联结从 rejected 走到 joined，
  与 hook 家族判定同深度；missing_slot_evidence 消除；
- IR 解析器三处类型名/尾随元数据 bug 的修复有正/负例与变异背书。

**没证明**：

- **Q4′（清槽）语义未分辨**：clear=`may_leave_slot_populated`（clear_sites 两条
  `not_written`）——这是「清槽入口未观察到字段写入」，SQLite 的解除注册机制是
  **删除 FuncDef 对象并调 xDestroy**（functionDestroy），不是「重写字段为空」。
  `not_written` 不能被解读成「guard 被击穿」；把「删除对象型清槽」识别为真清槽
  是 Q4′ 深化项，不在本阶段；
- **Q3 仍是降级**：same-slot 间接调用点不证明晚调可达，晚调真实性是
  `establish_late_invoke` 义务（witness 阶段）；
- harness 生成与 ASan 出证尚未跑——判定仍是 `insufficient_evidence` 不是
  `supported_incompatibility`；
- create_aggregate_function / create_window_function 仍无契约（多回调参数
  xStep/xFinal 未建模，能力③）；
- 容器识别目前靠 `hash+insert` / `hash+find` 符号名模式作候选入口，语义由 IR
  验证；其他库的容器挂载形状（链表、数组、单一指针字段）是 Gate C0 的覆盖项。

## 6. 产物（远端 <results-root>/stage65-userdata/，不进入公开仓库）

- `final-create_scalar_function/`、`final-create_collation/`：外部事实（slots=2）
- `joint-final-*/`：joined 判定
- `rust-contracts/`：能力① 的 Rust 契约（ud=3/4）
