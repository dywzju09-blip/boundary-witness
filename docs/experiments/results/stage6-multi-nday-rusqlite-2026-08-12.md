# 阶段 6 多 nday 检出：RUSTSEC-2021-0128 家族在 rusqlite 0.26.1 上的扩展验证

- 日期：2026-08-12
- 目标：阶段 6（Core Complete）的「组件历史版本检出多个已有 nday」——把
  RUSTSEC-2021-0128 覆盖的 7 个函数逐个过流水线，能检出多少是多少，缺证如实记。
- 绑定 commit：`3493aed`（deepseek）
- 产物：远端 `<results-root>/stage6/`（不进公开仓库）；repo 侧资产：
  `adapters/rusqlite/{commit_hook,rollback_hook}.toml`、
  `adapters/rusqlite/{commit_hook,rollback_hook,create_collation,create_scalar_function}.foreign-roles.json`、
  `crates/bw-foreign-ir` 的两个纪律 bug 修复（phi、is_caller_owned）

## 1. RUSTSEC-2021-0128 的 7 个受影响函数 vs 工具结果

| # | API | Rust 契约（0.26.1） | 外部事实 | 联结 | 反证/ASan | 0.26.2 |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `Connection::update_hook` | permits + guard none | MayRetain 2 槽（stage5-2） | joined | **heap-use-after-free 5/5**（stage5-4） | E0425 拒 |
| 2 | `Connection::commit_hook` | permits + guard none | MayRetain 2 槽 | joined | **heap-use-after-free 3/3** | E0425 拒 |
| 3 | `Connection::rollback_hook` | permits + guard none | MayRetain 2 槽 | joined | **heap-use-after-free 3/3** | E0425 拒 |
| 4 | `Connection::create_collation` | permits + guard none | **Unresolved**（slot_not_proven_caller_owned ×2） | rejected（user_data_role_mismatch + missing_slot_evidence） | 未到达（缺证） | — |
| 5 | `Connection::create_scalar_function` | permits + guard none | **Unresolved**（control_flow_incomplete ×6、escapes_to_unknown_callee ×10、slot_not_proven_caller_owned ×7） | rejected（同上） | 未到达（缺证） | — |
| 6 | `Connection::create_aggregate_function` | **未装配**（多回调参数形状，装配缺口） | — | — | 未到达 | — |
| 7 | `Connection::create_window_function` | **未装配**（同上） | — | — | 未到达 | — |

**3 个已知 nday 完成 source-to-ASan 全链检出，4 个如实停在缺证/缺口，无假阳性、
无假阴性。**

## 2. 两个纪律 bug（缺证当否定）——本次修掉，均有变异验证

create_collation / create_scalar_function 首次跑外部事实时分析器给出 **no_retain**
（零证据零边界）。SQLite 明确保留 collation/function 回调，这是「查不出逃逸 →
输出没保留」的纪律 bug，比漏报更危险。逐层追踪后定位到两个独立缺陷：

### 2.1 phi 节点无模型（`6968cca`）

`sqlite3CreateFunc` 里 xFunc 值流经 `%193 = phi [%189, %188], [%191, %190]`
（判空二选一）再 store 进 FuncDef。分析器没有 `InstKind::Phi`，phi 结果来源被置
Unknown → 别名链断裂 → store 使用点不可见 → 空洞 NoRetain。

修复：新增 `InstKind::Phi`，来源/槽位/caller-owned 沿入边值分支传播（与 select
同规则，块标签剔除）；`trace_param` 把 phi 结果当普通别名继续追。

变异检查：破坏 phi 来源传播 → 恰好两条新 fixture 转红（MayRetain→NoRetain、
Unresolved→NoRetain），其余 cross_function 测试保持绿。

### 2.2 is_caller_owned 漏 origins 检查（`5d7e189`）

phi 修复后仍 NoRetain。调试追踪显示跨函数注入 `caller_owned_params=[]`：
`sqlite3_create_function_v2` → `createFunctionApi` 的实参是**形参落栈后的 load
结果**（`%24 = load %15`），其 origin=Param(5) 但不在 `caller_owned` 集合里；
`is_caller_owned`（pub，供注入用）只查集合、漏 origins，而 `base_is_caller_owned`
（私有）有完整检查——两个谓词语义漂移。注入漏掉 → 被调方全部形参 origin 变
Unknown → 别名链为空 → 空洞 NoRetain。

修复：`is_caller_owned` 合并 origins 检查（全局 / origin=Param / 集合三者其一）。

变异检查：去掉 origins 检查 → 恰好新 fixture
`spilled_load_arg_cross_function_store_to_global_is_may_retain` 转红
（MayRetain→NoRetain），其余保持绿。

修复后 create_collation / create_scalar_function 如实转为 **Unresolved**，边界原因
具体可回查：CollSeq/FuncDef 是堆对象（`sqlite3DbMallocZero`），store 进其字段
「非调用方持有」→ 缺证不猜。这是正确的纪律行为：这两个 API 的保留是经堆逃逸
（哈希表插入）实现的，当前片段模型（首期 global/field slot）证明不了，记
`InsufficientEvidence`，不判 Compatible。

## 3. 联结与判定数字（stage6-joint-2026-08-12）

```
rust_contracts_total: 50   foreign_facts_total: 5
joined: 3  rejected: 2  no_foreign_counterpart: 12
rejection_reasons: user_data_role_mismatch ×2、missing_slot_evidence ×2
verdicts: insufficient_evidence ×6（3 joined × 2 subjects）
obligations: establish_late_invoke ×3
```

三条 joined 判定与 update_hook 完全同型：captured_referent =
InsufficientEvidence + EstablishLateInvoke（witness 路径可走），
callback_allocation = InsufficientEvidence（PG-2 已知覆盖缺口：trampoline 内
from_raw 回收，本函数体看不到配对转移）。

## 4. 反证与对照矩阵（vulnerable 0.26.1 / fixed 0.26.2）

| 运行 | commit_hook | rollback_hook |
| --- | --- | --- |
| ASan（0.26.1 harness，判定生成 invalidate） | **heap-use-after-free**（3/3 重复同型） | **heap-use-after-free**（3/3） |
| fixed（0.26.2 harness） | 编译期拒绝 **E0425**（invalidate refused） | **E0425** |
| owned callback（不捕获借用） | ASan 干净（0 字节） | 干净 |
| unregister-before-drop（`hook(None)` 后失效） | 干净 | 干净 |
| no-trigger（失效但不执行 COMMIT/ROLLBACK） | 干净 | 干净 |

ASan 栈帧完整回查：`main.rs` 生成回调读失效 referent → rusqlite
`call_boxed_closure` trampoline → SQLite C 侧晚调点（commit_hook 的
`sqlite3VdbeHalt` 提交路径 / rollback_hook 的 `sqlite3RollbackAll`，
sqlite3.c 行号可回查）→ 由 harness 的 COMMIT/ROLLBACK 语句触发。
这是 ForeignLateUseEffect 的独立证据链。

## 5. adapter 冻结时点说明（如实记录）

`commit_hook.toml` / `rollback_hook.toml` 冻结于 2026-08-12，晚于该家族的 joint
判定（`p3_verdict_available_at_freeze = true`）。因此这两个目标不构成 Gate 的
「早于判定冻结」证据；内容仍只含公开 API 的合法调用方式（setup/register/trigger），
不含 drop 时机、触发顺序或预期结果——危险动作序列由判定的
PermitsNonStaticCapture + guard 结论推导（D3），生成器不写死。update_hook
adapter（2026-08-04 冻结）不受影响。role map 全部只声明符号与参数位置。

## 6. 这一步证明了什么，没证明什么

**证明了**：

- **rusqlite 0.26.1 上 3 个已知 nday（update/commit/rollback hook）完成
  source-to-ASan 全链检出**：Rust 契约（permits + guard none）→ 外部 IR
  （MayRetain 2 槽位 + 晚调）→ 精确联结 → 判定（EstablishLateInvoke 义务）→
  生成 `#![forbid(unsafe_code)]` harness → ASan heap-use-after-free，3/3 与
  5/5 重复同型，0.26.2 fixed 全部编译期拒绝（E0425），三个客户端安全对照全干净；
- **「多个已知 nday」不再只依赖开发对象 update_hook 单点**：同一历史版本里
  RUSTSEC-2021-0128 家族的三条 hook 路径独立检出，机制同型但触发路径不同
  （INSERT 写触发 / COMMIT 触发 / ROLLBACK 触发），证明工具不是为单个 API
  硬编码的；
- **两个「缺证当否定」纪律 bug 被真实目标暴露并修复**（phi 无模型、
  is_caller_owned 漏 origins），都带 fixture + 变异检查，修复方向都是把错误
  结论（NoRetain）纠正为缺证（Unresolved）；
- create_collation / create_scalar_function 的缺证有**具体、机器可读原因**
  （userdata 角色在 callback 之前是 5.2 的已知设计限制；CollSeq/FuncDef 堆逃逸
  超出首期片段模型），不是套话；
- 反证生成是判定驱动的（0.26.1 生成 invalidate、0.26.2 拒绝），adapter 不含
  缺陷时序，负对照不失效。

**没证明**：

- **create_collation / create_scalar_function 是 nday**——它们停在
  `InsufficientEvidence`（联结层拒绝），不是因为安全而是因为证据不足。要让它们
  走到 ASan 需要两个能力：① Rust 侧 userdata 角色规则扩展（callback 之前的
  into_raw 来源识别，5.2 记为已知限制）；② 外部侧堆逃逸追踪（FuncDef/CollSeq
  经 sqlite3HashInsert 进入 db 哈希表——「堆对象插入 caller-owned 容器」的
  两点传播，首期片段没有）。这两项都不在本次范围，属于后续能力项；
- **create_aggregate_function / create_window_function**——Rust 侧装配缺口
  （多回调参数 xStep/xFinal/xValue 形状未建模），连契约都没有，未过判定；
- **Gate A1 正式判定**——Full vs Rust-only 的探索性比较已有
  （gate-a1-exploratory-2026-08-10），但判据（比较单位/最小效应量/Unknown
  容忍度）未预注册，需要用户给定后才算 Gate A1 通过；
- **Gate B（unseen 目标 safe-only 反证）**——本次三个检出全是开发对象
  （rusqlite），不是 unseen；S1 的 19 个 unseen Tier A-R 候选（git2 11 +
  portaudio 3 + openssl 5）经能力实测分别停在同步形状/guard 绑定/外部缺证，
  尚无一个 unseen 目标走到 ASan。这是阶段 6 剩余的最大缺口；
- **create_scalar_function 的堆逃逸是「真保留」**——方向性事实（SQLite 源码
  语义）支持，但自动化没有证明，本次只记录为缺证；
- **commit_hook / rollback_hook 的 adapter 早于判定冻结**——时点晚于家族判定，
  不构成 Gate 证据（见 §5）。

## 7. 对阶段 6 完成度的影响

Core Complete 判据的六项里，本记录直接推进了「真实 vulnerable/fixed pair 全链」
（从 1 个扩展到 3 个同族 pair）与「fixed + 至少三个负对照」（每个 pair 都有
owned / unregister / no-trigger + 编译期拒绝）。剩余未完成：

1. Gate A1 判据预注册（需用户给定）；
2. Gate B unseen 目标反证（当前样本池无清晰猎物，需扩大候选或补能力项）。

下一步建议（按价值排序）：① 若要把 create_scalar_function 走到 ASan，先做外部
侧堆逃逸追踪（对 git2/curl 家族也有价值）；② Gate A1 判据与验收；③ Gate B 的
unseen 目标扩展（需要用户提供或授权挑选样本口径）。
