# Gate A1 预注册判据（提案，待维护者签核）

- 日期：2026-08-12
- 性质：**判据提案**。正式 Gate A1 判据必须在看到正式运行数据**之前**冻结；
  本提案供维护者确认/修改，签核后成为预注册，再执行正式运行。
- 探索性前置：[gate-a1-exploratory-2026-08-10](./gate-a1-exploratory-2026-08-10.md)
  （机制方向证据，n=1 fixture + 开发对象，**不构成正式通过**；正式运行必须是
  判据冻结后的新执行）

## 1. 问题定义

Gate A1 回答：**外部侧（Q1/Q4′/降级 Q3 的指令级证据）是否在判定上携带
Rust 侧拿不到的净贡献**（thesis §2.6 的预判：贡献落在 Q4′ 清槽结论上）。

## 2. 预注册判据（推荐值，待签核）

| 项 | 推荐判据 | 理由 |
| --- | --- | --- |
| 比较单位 | **hand-off（交出点）**，不是 API 或 crate | 联结与判定都在 hand-off 粒度；两侧半键只在 hand-off 合成 |
| candidate universe | rusqlite 0.26.1 全部 50 个 hand-off（当前 commit 重跑，`--all-features`） | 与 5.2/stage6 同一 universe，全部有 rust 契约；3 条已 join |
| 运行方式 | 同一 universe 分别跑 `judge-hand-offs`（Full）与 `--rust-only`（独立代码路径，`judge_hand_off(rust, None)`） | 两模式共享 Rust 契约输入，只差外部证据 |
| 主要指标 | **判定差异 hand-off 数**：Full 与 Rust-only 静态判定不同的 hand-off 数量 | 净贡献的计数 |
| 最小效应量 | **≥ 1 个 hand-off 判定不同**，且差异可归因到外部证据（Q4′/Q1/Q3 至少一项）；其中至少 1 个是 guard 分支（Q4′ 清槽结论归属点） | 机制性判别力成立即可；n 小是阶段 6 的预期 |
| Unknown 容忍度 | Rust-only 的 `InsufficientEvidence` 比例**无上限**（缺证是预期行为）；Full 的 joined 数 ≥ 1 | 缺证不惩罚；联结覆盖由 role map 决定 |
| 失败动作 | 若 Full 与 Rust-only 在所有 hand-off 上判定完全相同 → Gate A1 **不通过**（外部侧无净贡献，需回查判定链） | 直接对应 A1 的定义 |

## 3. 边界（预注册时声明）

1. rusqlite 是开发对象，本 gate 数字**不进论文主表**，只作为 Core Complete 的
   功能验收；
2. 判定不同包括：三态不同、obligation 不同、join vs 拒绝（Full 的
   `missing_slot_evidence` 拒绝也算差异——Rust-only 对同一 hand-off 会给判定）；
3. 若差异只来自 role map 覆盖缺口（Full 没给某些 hand-off 外部对应）而不来自
   判定逻辑，记录为「覆盖性差异」，不计入效应量，另列。

## 4. 待维护者确认

- [ ] 比较单位、最小效应量、Unknown 容忍度如上
- [ ] 或给出修改后的判据（冻结后不可再改）

签核后执行正式运行：`judge-hand-offs`（Full + `--rust-only`）→ 统计判定差异 →
写 stage6 Gate A1 记录（含证明了什么/没证明什么）。
