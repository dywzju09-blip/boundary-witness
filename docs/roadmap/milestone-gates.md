# Milestone gates

本文定义 gate。**研究 gate（R、P、A、B、C、D）决定论题能不能立住；工程 gate（1–6）决定能不能从 V3.2.x 进入 V3.3。两者互不替代**——任何工程 gate 通过都不能推出创新点成立，反之亦然。

方向权威见 [research thesis](../project/research-thesis.md)。本文于 2026-07-30 重写研究 gate 部分，旧的「Gate 0：研究前提」已被 Gate R/P/A/B/C/D 取代。2026-07-31 复审后新增 Gate R 并重做 Gate P 的判据。

---

# 研究 gate

按执行顺序排列。每一道都是研究方向的止损点。

## Gate R：关系正确性

**2026-07-31 复审后新增，排在一切之前。关系错了，后面所有测量都在测错的东西。**

用四个 matched fixture 验证 [research thesis §2.4](../project/research-thesis.md) 的核心关系。**外部侧用手写 C stub，不需要 LLVM IR 流水线**，因此本 gate 与 P1/P2 完全解耦，现在就能做。

| # | Rust 侧 | 外部 C stub | 应判 | 检验什么 |
| --- | --- | --- | --- | --- |
| 1 | 允许捕获借用，无 guard | 保存 + 晚调 | 不相容 | 正对照 |
| 2 | 允许捕获借用，返回 guard | 保存 + 晚调，**注销真的清槽** | 相容 | 不得误报 guard 保护的 API |
| 3 | **与 #2 逐字节相同的 Rust 侧** | 保存 + 晚调，**注销没清干净** | 不相容 | **外部侧是否有判别力** |
| 4 | `'static`，分配提前释放 | 保存 + 晚调 | 不相容 | R / A 分离，不得漏报 |

- **通过**：四条全判对；且 fixture 2 与 3 上 Full 能分开、Rust-only 不能。
- **No-Go**：fixture 2 与 3 分不开。
- **失败动作**：外部侧对 C2 没有判别力，转路线 B。

**fixture 3 是本 gate 的重点。** 它检验 [research thesis §2.6](../project/research-thesis.md) 的推论——外部侧的判别力若真的在 Q4′（清槽）而不在 Q1（是否保存），这一条就必须能分开。**若 Rust-only 也能分开 2 与 3，那是 Gate A 的提前失败信号。**

## Gate P：猎物存在性

在投入外部侧实现之前必须回答：生态里还剩多少个**安全客户端可能形成 lifetime separation 的交出点**。

这一缺陷类在 Rust 社区是公开知识，`'static` 修法众所周知，许多维护者早已收紧 bound。**若猎物池不足以支撑 [research thesis §7.8](../project/research-thesis.md) 的确认集与新发现目标，路线 A 不成立。**

**判据必须同时满足四条方法学要求**，缺一不可：

| 要求 | 内容 |
| --- | --- |
| **语义取值** | 以 `EffectiveCaptureAdmission` 为准，不用语法四态。`fn register<F: Fn()>` 的「无 bound」是**允许捕获借用**，不是「不表态」；`dyn Fn` 的省略 lifetime 默认 `'static`。合并两者会把最强的一类候选记成弱候选 |
| **Tier A** | 回调 / trampoline / userdata 经 dataflow **到达精确的 extern 参数**。仅「同函数内出现 extern 调用」是 Tier B 语法共现，**同时高估和低估**，不得用作 Go/No-Go |
| **L1 可分析** | 候选必须能绑定到精确的外部 LLVM IR。主表须标注 IR acquisition tier——**一个很大的 Rust 侧池可能全部进不了 P1/P2** |
| **置信界判据** | `Pass` = 下置信界仍足以支撑预定确认集；`No-Go` = 上置信界仍不足；`Amber` = 扩大样本或增加人工审计。**「足够」「非平凡」允许事后移动门槛，不得作为 gate 判据** |

**运行前必须完成 family-level sealed split。** 直接查看 300–500 个 crate 的身份与候选数，会按 [research thesis §7.6](../project/research-thesis.md) 把整个前瞻池变成开发集。默认做法是独立 runner 只返回盲化聚合统计。

- **失败动作**：转路线 C（经验研究），不再投入外部侧实现。

执行步骤、抽样预注册与 sealed split 见 [猎物存在性探针 runbook](../experiments/runbooks/prey-existence-probe.md)。前置是 PC（`EffectiveCaptureAdmission`），成本约为外部侧实现的百分之一。

## Gate A：外部证据必要性

- **通过**：matched pair 中 Full 能区分同步与保存、也能区分「注销真清槽」与「注销没清干净」；Rust-only 对两者给出相同结果或必须 abstain；在真实未调优样本上，Full 相对 Rust-only 有可解释的 precision/coverage 增益。
- **No-Go**：关闭外部分析后结果不变；所谓增益主要来自更窄的候选范围；外部行为仍主要由 API map 预先给定。
- **失败动作**：放弃 C2 作为主角，转路线 B（以反证合成为主）。

**注意判别力的来源。** 按 [research thesis §2.6](../project/research-thesis.md)，Q1（是否保存）在候选集合上可能几乎恒为真，恒为真的项没有判别力。本 gate 的增益必须**可归因到 role/slot-sensitive 的外部证据**（主要是 Q4′ 清槽），不能只归因到更窄的候选范围。Gate R 的 fixture 2/3 是这一点的最小检验，**若那里就分不开，不必等到 Gate A**。

与 Yuga / FFIChecker 的同任务同分母精度对照是本 gate 的组成部分，步骤见 [规模化精度对照 runbook](../experiments/runbooks/precision-comparison-at-scale.md)。2026-07-31 的单 crate 对照见 [Gate 0 结果](../experiments/results/gate0-baseline-comparison-2026-07-31.md) 与 [误报归因](../experiments/results/gate0-yuga-precision-triage-2026-07-31.md)——**n=1 且该 crate 参与过开发，不构成证据。**

## Gate B：反证真实性

- **通过**：unseen 候选能自动生成 safe-only harness；外部组件真实晚调回调；回调实际访问失效对象；独立 oracle 在 vulnerable 上产生证据；fixed 与全部负对照干净。
- **No-Go**：只能产生 contract trace；必须手写每个 crate 的专用 harness；结果依赖 synthetic 桥接才成立；无法建立反证与原候选的 identity lineage。
- **失败动作**：C1 降级为 contract-path synthesis，不得称为不健全性确认。

「专用 harness」与「声明式 adapter」的界线是本 gate 的核心判据，定义见 [implementation plan 的 P4](implementation-plan.md#p4-反证合成与执行)：adapter 只描述如何合法使用 API，不得包含任何与缺陷相关的信息，且必须在判定跑出来之前冻结。

## Gate C：跨库泛化

**认证期决定，当前不设下限。**

跨外部库家族的泛化是投稿认证期的问题。**本阶段不对家族数量设置实现约束**——P1/P2 的完成谓词只要求单库端到端打通。取得外部库 LLVM IR 的工程可行性是已知风险，但按当前决定推迟到认证期处理，不构成现在的 gate。

认证期需要报告：外部库家族数、新 API 的接入方式与成本、生成成功率、coverage gap。

## Gate D：确认性评估

- **通过**：冻结后的 unseen corpus；公平 baseline 与全套消融；双人 ground truth；coverage、Unknown、cluster 与置信区间完整；**至少一个有独立外部确认的实际发现**。
- **No-Go**：结论仍来自开发集；100% precision 依赖大量 abstention；指标单位在 alert、API、crate 与 root cause 之间混用；没有新发现。

**在 Gate R、P、A、B、D 全部通过前，不得在任何对外材料中表述跨语言契约不相容判定已达成。**

---

# 工程 gate

从 V3.2.x 进入 V3.3 的条件。任何单项成功都不能替代完整 gate。

## Gate 1：Clean method commit

- 工作树 clean；
- `Cargo.lock`、`rust-toolchain.toml`、Schema、Contract 和 docs 对齐；
- 无 prompt、迁移清单、私有路径、sealed 数据或大型结果；
- PR 必跑测试完成或阻塞项明确记录。

完成谓词：`git status --short` 为空，PR 记录命令、退出码、未运行项和阻塞原因。

## Gate 2：Public regression

- 当前 commit 上运行已揭示公开数据；
- dataset/config/Contract/Schema/run hash 完整；
- negative controls、pair separability、coverage gap 和 failure taxonomy 均记录；
- 历史结果不得升级为当前结果。

完成谓词：新增正式 result 文档，满足 [data-alignment](../experiments/data-alignment.md)，并通过 checksum 和敏感材料扫描。

## Gate 3：ObjectFlow 与 proof-layer 回归

- opaque handle schema/validator 复验；
- returned-borrow exact claimant negative controls 复验；
- graph-v3/ranking-v2/CLI 均按 `verified_layers`/`missing_layers` 消费；
- identity、ordering、complete risk chain 不再被旧 `verified_static_chain` 合并解释。

完成谓词：model、CLI、compiler golden 和 Schema roundtrip 覆盖正负路径。

## Gate 4：Dynamic bridge

- witness plan 可选择或生成最小 harness；
- executor 能驱动 runtime/oracle 或 fuzz/Miri 路线；
- replay receipt、checksum、negative controls 和 failure classification 完整；
- crash、finding、sanitizer 与 method negative 分开。

完成谓词：至少一个公开设计家族在当前 commit 上形成 plan 到 receipt 的可重放闭环。

**注意**：Gate 4 是工程闭环，不等于研究 Gate B。Gate B 额外要求客户端是 safe-only、晚调由外部组件真实触发、证据来自独立 oracle。

## Gate 5：约 100 crate 工程 pilot

- corpus manifest、buildability、boundary、candidate、lifecycle evidence、graph/ranking 和 taxonomy 全链运行；
- unsupported、tool error、timeout、coverage gap 不被改写为安全；
- adapter effort 与 candidate partition 可审计。

完成谓词：pilot result 文档绑定 run ID、hash、失败类和结论上限。

## Gate 6：Freeze 与 sealed holdout

- scanner、Contract、feature profile、ranking policy、threshold、dataset hash 和 ranked output hash 冻结；
- runner/curator 隔离；
- public regression 已通过；
- 使用新的、未 reveal sealed holdout。

完成谓词：公开仓库只保存无身份 freeze record、聚合摘要和不可逆 hash；样本身份、ground truth、逐样本 detail 和结果路径不进入 Git。
