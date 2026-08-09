# Gate A1（exploratory）：Full vs Rust-only 的判别力

- 日期：2026-08-10
- 状态：**exploratory**。正式判据（比较单位、最小效应量）未预注册，本记录只给出
  机制层面的方向性证据，不构成 Gate A1 通过。
- 数据来源：阶段 6 fixture 全量重跑（当前 commit，`register_guarded` 同一 Rust
  函数 + 两个外部 stub）。

## 1. 对比

| 变体 | 输入 | register_guarded 判定 |
| --- | --- | --- |
| **Full** | Rust 契约 + 外部 IR 事实 | clearing → `CompatibleWithinAnalyzedFragment`；leaky → `InsufficientEvidence`（GuardDefeated + EstablishLateInvoke） |
| **Rust-only** | 只有 Rust 契约，无外部事实 | 无法回答「注销是否真清槽」→ 只能缺证（InsufficientEvidence） |

**机制方向**：同一 Rust 侧（guard 形状、`'c` bound），Full 能分开「真清槽」与
「没清干净」，Rust-only 对两者给出相同结果（都无法判定）。外部侧的净贡献落在
Q4′（清槽结论）上——与 [research thesis §2.6] 的预判一致。

[research thesis §2.6]: ../../project/research-thesis.md

## 2. 为什么这是方向性证据而不是通过

1. **n=1 且是开发对象**：fixture 是 Gate R 的自写形状，rusqlite 是开发目标，
   两者的数字都不进论文主表；
2. ~~Rust-only 变体是概念性对比~~ **已更新（2026-08-10）**：`judge-hand-offs
   --rust-only` 已实现（同一判定函数、无外部证据路径，`judge_hand_off(rust,
   None)`），fixture 实测：`register_guarded` 在 Rust-only 下
   InsufficientEvidence、Full(clearing) 下 Compatible——**独立执行路径可用**；
   正式 Gate A1 仍缺预注册判据；
3. **判据未预注册**：最小效应量、比较单位（交出点 / API / crate）未定。

## 3. 真实目标补充对比（rusqlite 0.26.1，exploratory）

| 变体 | 判定覆盖 | verdicts | obligations |
| --- | --- | --- | --- |
| Rust-only（--rust-only） | 17 契约全部出判定 | 7 Compatible + 27 InsufficientEvidence（34 条 = 17×2 类生命周期） | 0 |
| Full（阶段 5.2） | 1 joined（update_hook） | 2 InsufficientEvidence | 1（EstablishLateInvoke） |

说明：Rust-only 的「判定」不含外部行为证据——guard 有效性全是缺证，Q3 义务
（来自外部侧）为零；Full 的覆盖受 role map 限制（16 条契约无外部对应）。
两组数字不可直接比大小；机制对比仍以 fixture 2/3 分离为准。

## 4. 正式 Gate A1 需要什么

- 在同一 candidate universe 上实现并运行 Rust-only 模式（关闭外部分析的代码路径）；
- 预注册：比较单位、最小效应量、允许的 Unknown 比例；
- 至少覆盖 guard 分支（外部证据净贡献的归属点，见 thesis §2.6 与 current-work.md）。

## 5. 这一步证明了什么，没证明什么

**证明了**：机制方向——外部侧（Q4′）确实携带 Rust 侧拿不到的判别力，且本次
端到端数据与 stage3/stage4 的模型层测试一致。

**没证明**：Gate A1 通过（判据未预注册、无独立 Rust-only 执行路径、n=1 开发对象）；
也没有任何「增益大小」的数字。
