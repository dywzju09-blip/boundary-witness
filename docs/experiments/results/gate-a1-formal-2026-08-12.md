# Gate A1 正式判定：Full 与 Rust-only 的判定差异

- 日期：2026-08-12
- 判据：[gate-a1-preregistration-proposal-2026-08-12](./gate-a1-preregistration-proposal-2026-08-12.md)
  （判据在正式运行**之前**写入并提交，commit `7111347`；本记录按该判据执行）
- 绑定 commit：`7111347`（deepseek）
- 结论：**Gate A1 通过**（按预注册判据）

## 1. 判据回顾（预注册）

- 比较单位：hand-off（交出点）
- candidate universe：rusqlite 0.26.1 全部 50 个 hand-off + Gate R fixture 的
  guard 分支（`register_guarded` × clearing/leaky 两个外部 stub）
- 最小效应量：≥ 1 个 hand-off 判定不同，且至少 1 个是 guard 分支（Q4′ 清槽
  结论归属点）
- 差异包括：三态不同、obligation 不同、join vs 拒绝
- 覆盖性差异（Full 缺外部对应）另列，不计入效应量

## 2. 正式运行（当前 commit 重跑）

### 2.1 真实目标 universe（rusqlite 0.26.1）

```
Full:    joined=3（update/commit/rollback hook）、rejected=2（create_collation、
        create_scalar_function）、no_foreign_counterpart=12
Rust-only: joined=17（全部装配契约，无外部证据路径）
```

判定差异 hand-off（role-map 覆盖、有外部对应）：

| hand-off | Full | Rust-only | 差异归因 |
| --- | --- | --- | --- |
| `sqlite3_commit_hook` | IE + **establish_late_invoke** | IE（无义务） | 外部 Q3 同槽晚调候选 |
| `sqlite3_create_collation_v2` | **rejected**（user_data_role_mismatch + missing_slot_evidence） | IE | 外部槽位证据缺失 |
| `sqlite3_create_function_v2` | **rejected**（同上） | IE | 外部槽位证据缺失 |

差异数：**3**（≥1 ✓）。其余 role-map 覆盖符号（update/rollback hook）两侧判定
相同——外部证据不改变它们的方向（都是缺证方向），差异集中在义务与联结状态。

### 2.2 guard 分支（Gate R fixture，`register_guarded`，guard=ties_slot_to_subject）

同一个 Rust 函数、两个只有 `fixture_unregister` 实现不同的外部 stub：

| 变体 | Full | Rust-only |
| --- | --- | --- |
| clearing stub（Q4′: clears_on_all_paths） | **CompatibleWithinAnalyzedFragment** | InsufficientEvidence（无义务） |
| leaky stub（Q4′: may_leave_slot_populated） | **InsufficientEvidence + establish_late_invoke** | InsufficientEvidence（无义务） |

**guard 分支差异成立**（✓）：Full 能分开「注销真清槽」（Compatible）与「注销
没清干净」（IE+晚调义务），Rust-only 对两者给出相同结果（都缺证）。差异可归因
到外部 Q4′ 证据（`clears_on_all_paths` vs `may_leave_slot_populated`，IR 指令级）。

## 3. 覆盖性差异（另列，不计入效应量）

- Full 的 12 个 `no_foreign_counterpart`（role map 未覆盖的符号）在 Rust-only 下
  有判定——这是 role map 覆盖缺口，不是判定逻辑差异；
- Rust-only 对所有 17 个装配契约都给判定（无外部证据 → 大量 IE），Full 只在
  role-map 覆盖的 5 个符号上有外部对应——覆盖范围不同是设计使然（判据 §3.3）。

## 4. 结论与局限

**结论**：按预注册判据，Gate A1 通过——外部侧证据（Q4′ 清槽结论、Q3 晚调候选、
槽位证据）确实携带 Rust 侧拿不到的判别力，最小效应量（≥1，含 guard 分支）达成。
与 thesis §2.6 的预判一致：净贡献落在 Q4′（清槽）上。

**局限**：

- rusqlite 是开发对象，本数字不进论文主表（判据 §3.1 声明）；
- 判据由执行者按「你直接定就行」的授权定稿，维护者可否决；若判据变更，本运行
  作废重跑（预注册纪律：先冻结后运行）；
- 真实目标的 3 个差异中 2 个是 join-vs-reject（缺证拒绝），不是三态翻转——
  机制层面的判别力主要由 guard 分支（§2.2）与义务差异（commit_hook）承担。

## 5. 这一步证明了什么，没证明什么

**证明了**：在当前 commit 上，Full 与 Rust-only 在同一 candidate universe 存在
可归因的判定差异，且 guard 分支（Q4′ 归属点）的判别力在真实 IR 上复现——
外部证据必要性的机制成立，Gate A1 按预注册判据通过。

**没证明**：任何生态级增益数字（n=1 开发对象 + fixture，非正式评估）；Gate B
（unseen 目标正例，单独验收项）；判据的维护者签核（本记录按提案判据执行，
维护者可改判据重跑）。
