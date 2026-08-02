# 实现路线

本文服从 [research thesis](../project/research-thesis.md)。每个阶段都标注它服务哪条创新点；不服务任何创新点的工作不排进路线。

本文于 2026-07-30 全量重写，2026-07-31 复审后调整关键路径。旧版本的 P0–P7 编号与 N1/N2/N3 创新点编号一律作废。

当前阶段是 **V3.2.x core-effect hardening**。本文是计划，不是已完成能力的声明。

> **本文描述每个阶段是什么，不定义执行顺序。** 顺序、依赖类型与当前位置的唯一权威是 [execution plan](execution-plan.md)；各阶段的技术细节见 [implementation plan](implementation-plan.md)。三份文档表达同一张依赖图，冲突时以 execution plan 为准。

## 关键路径

```text
PF 关系与四 fixture ──（Gate R）── 已完成
PC EffectiveCaptureAdmission ───── 已完成
PG-1 RegistrationGuard ─────────── 已完成
PG-2 AllocationOwnership ───────── 下一步
                                  ↓
                     PP 猎物存在性探针（Gate P）──（决定后续是否投入）──┐
                                                                        │
P0 hand-off 身份与双侧事实模型 ─────────────────────────────────────────┼─→ P3 判定器 ─→ P4 反证合成 ─→ P5 评估
                                                                        │
P1 外部侧 Q1 ─→ Q4′ 清槽 ─→ 降级 Q3 晚调（P2）─────────────────────────┘
```

**执行顺序上最重要的三条：**

1. **PF 排在一切之前。** 关系错了，后面所有测量都在测错的东西。它的外部侧用手写 C stub，与 P1/P2 完全解耦。
2. **PG 是 P3 能吃到真实数据的前提。** 判定关系需要三个 Rust 侧事实，PC 与 PG-1 各完成一个。
3. **PP 排在外部侧实现之前。** 成本约为 P1+P2 的百分之一，却能否定整条路线。**Gate P 通过前不启动 P0 及以后。**

外部侧内部的顺序按判别力排：**Q1（槽位身份）→ Q4′（清槽，真正的判别项）→ 降级 Q3（晚调候选）**，不按查询编号排。

## PF — 核心关系与四个 matched fixture

服务 [Gate R](milestone-gates.md#gate-r关系正确性)。

实现 [research thesis §2.4](../project/research-thesis.md) 的轨迹可行性关系，三类生命周期（referent / allocation / registration）分开建模，用四个 matched fixture 验证。**外部侧用手写 C stub，不需要 LLVM IR 流水线。**

- 风险：低
- 完成谓词：四条 fixture 全判对，且 fixture 2 与 3（Rust 侧逐字节相同、只有 C stub 不同）上 Full 能分开而 Rust-only 不能
- **失败动作**：fixture 2/3 分不开则外部侧对 C2 无判别力，转路线 B

## PC — `EffectiveCaptureAdmission`

服务 PP 的正确性，可与 PF 并行。

把语法四态换成语义取值。`fn register<F: Fn()>` 的「无 bound」是**允许捕获借用**，`dyn Fn` 的省略 lifetime 默认 `'static`——现有实现把这两种语义相反的情况合并了。

- 风险：中
- 完成谓词：`dyn Fn` 与泛型 `F: Fn` 两个 fixture 落到相反取值

## PG — Rust 侧剩余的契约事实

服务 C2。判定关系需要**三个** Rust 侧事实，缺任何一个都会让判定静默落到缺证或产生整类漏报。

| 事实 | 状态 | 缺了会怎样 |
| --- | --- | --- |
| `EffectiveCaptureAdmission` | `Implemented`（PC） | — |
| `RegistrationGuard` | `Implemented`（PG-1） | 「为什么必须看外部侧」的论证落空——它建立在「Rust 看得到 guard、但判断不了它是否有效」上 |
| `AllocationOwnership` | **零行代码**（PG-2） | `'static` 只管住捕获、管不住 `Box<F>` 的存活，这一整类漏报看不见 |

- 风险：低–中
- PG-1 完成谓词：`register_guarded` 判出 `TiesSlotToSubject`（含 guard 类型与外部被调方），其余三个 fixture 函数判 `None`
- PG-2 完成谓词：`register_static_then_free` 判 `RustRetainsAndMayFreeEarly`，只差一次 `Box::from_raw` 的 `register_static_owned` 判 `ForeignOwnedUntilUnregister`

**PG-1 的第三条判据用「`Drop` 里调了外部函数」而不是「调了注销角色 API」**：角色分类只能来自人工清单，用它当必要条件会让 guard 检测无法规模化，也把人工标注当成了 Rust 侧观察。有效性由 Q4′ 回答。

## PP — 猎物存在性探针

服务 [Gate P](milestone-gates.md#gate-p猎物存在性)。前置：PC、PG-2（Tier A-A 判据需要分配归属事实）。

在 300–500 个 FFI crate 上运行 Rust-only 前端，统计 **Tier A** 交出点。仅语法共现的 Tier B 只作探索性筛选，**不得用作 Go/No-Go**。

**Tier A 分成两支，分别统计、分别判定**：`Tier A-R`（referent 类，`PermitsNonStaticCapture`）与 `Tier A-A`（allocation 类，`RequiresStaticCapture` + 分配可提前释放）。**两支的判据互斥**——只统计 R 会把 allocation 这一整类猎物记成零。

- 风险：低
- 完成谓词：候选池表，分列 Tier A-R / Tier A-A / Tier B，标注 IR tier，区分已调优与未调优；按 crate / repository / 外部库家族聚类；判据用置信界
- 运行前必须完成 family-level sealed split，默认只返回盲化聚合统计
- **失败动作**：R 与 A 都不足以支撑确认集则转路线 C，不投入 P1/P2。**不得因 R 的 No-Go 自动放弃 A**

## P0 — hand-off 身份与双侧事实模型

服务 C2 的前提。

拆成三类记录：`RustContractFact`、`ForeignBehaviorFact`、`CompatibilityVerdict`，核心是引入 `HandOffId` 作为两侧连接键。身份必须精确到单态化实例、调用出现次序、参数角色索引、外部符号与构建配置。**源码位置与函数名只能作诊断，不能参与联结。**

- 复用：站点身份描述符、schema 验证器、事实信封
- 风险：低，但必须一次做对，后续每一维都挂在这个键上
- 完成谓词：两侧事实可在不依赖候选切分的前提下联结

**这一层不是创新点**，是任何跨语言分析的基本前提。见 [research thesis §3](../project/research-thesis.md)。

## P1 — 外部侧 Q1：逃逸（前提，非判别项）

服务 C2 的前提。**Q1 是前提不是判别项**——它提供槽位身份，判别力在 Q4′。

判定外部函数的指针形参是否到达「调用返回后仍存活」的存储。只支持外部 C 源码随构建提供的 crate（L1），其余写入 limitation。

- 风险：中
- 纪律：查不出逃逸**不得判定为安全**，必须记 `InsufficientEvidence`
- 完成谓词：单一库上端到端产出指令级可回查证据
- 止损：两三周内看不到端到端结果，贡献结构需重新设计

## P2 — 外部侧 Q4′ 清槽 与降级 Q3 晚调

服务 C2。**全路线风险最高的一段。内部顺序是 Q4′ 先于 Q3**——判别力在清槽，不在晚调候选。

完整 Q3 需要全库可达性加间接调用 callee 解析。**首期降级为「同槽间接调用存在性」**，输出 `StaticVerdict = InsufficientEvidence` + `EvidenceGrade = SameSlotInvokeCandidate` + witness obligation，由 P4 的反证补上真实可达性证明。**不得输出任何第四态。** 降级的确切代价、必须量化的三个指标、以及 F1–F4 分阶段计划，全部记在 [implementation plan 的 P2 一节](implementation-plan.md#p2-外部侧-q4-清槽-与降级-q3-晚调)。

**Q4′（unregister/replace 是否在所有路径上清空槽位）已升为主查询之一。** 按 [research thesis §2.6](../project/research-thesis.md)，Q1 的答案在候选集合上可能恒为真，外部侧的判别力全在 Q4′；guard 是否真的保护也由它判定。

- 风险：高
- Plan B：把范围收为「外部源码随构建提供的 FFI crate」，作为明确 scope 而非失败

## P3 — 关系判定器

服务 C2。

实现 [research thesis §2.4](../project/research-thesis.md) 的轨迹可行性关系（**不是旧的 2×2 矩阵**，那个已因可构造的假阳性与假阴性废除），三个正交维度输出：`StaticVerdict` / `EvidenceGrade` / `WitnessStatus`。外部侧证据来源换成 Q1/Q3/Q4′；人工版本边界保留为交叉验证。

- 风险：低
- 完成谓词：判定来源为外部侧证据；Full / Rust-only / Foreign-only / manual-oracle 四变体作用于同一 candidate universe

## P4 — 反证合成与执行

服务 C1，**首要创新点**。

从判定结果自动合成 `#![forbid(unsafe_code)]` 的最小客户端，链接精确外部构建，由独立 oracle 出证。

**输入不限于 `SupportedIncompatibility`**：也接受 `InsufficientEvidence` + `EstablishLateInvoke` 义务（前提是 Rust 侧分离性、Q1、Q4′ 与身份都已充分）。降级 Q3 永远输出缺证，若只接受不相容判定，首期实现里本阶段将没有合法输入。见 [ADR-0004](../decisions/ADR-0004-joint-trace-verdict-semantics.md)。

**adapter 边界是 Gate B 的判据**：adapter 只描述如何合法使用 API，不得包含任何与缺陷相关的信息；触发序列必须由判定结果自动推导；adapter 必须在判定跑出来之前冻结。

- 复用：runtime、oracle、fuzz observer、现有 harness 设施
- 风险：中高
- 完成谓词：至少一个未参与模板开发的新 crate 可从候选自动到达独立证据

## P5 — 评估

见 [research thesis §7](../project/research-thesis.md)。评估设计不在本文重复。执行顺序见 [implementation plan](implementation-plan.md)。

## 已撤销的阶段

| 旧阶段 | 撤销原因 |
| --- | --- |
| 旧 P1「消除 API 清单」 | 立论已被 Yuga 基线否定。结构化推断仍实现，但作工程属性 |
| 旧 P5「别名与重入维度」 | 持有期一维闭环前不扩维，转 future work |
| 旧 P6「线程维度」 | 同上 |
| 旧 2×2 判定矩阵 | guard 造成假阳性、`'static` 不保证分配存活造成假阴性，由轨迹可行性关系取代 |
| `SupportedIncompatibility (weak)` | 破坏三态模型，由 `EvidenceGrade` + `WitnessStatus` 取代 |

## 明确的非目标

- 不做全程序任意深度 points-to
- 不做外部库的完整语义建模
- 不把静态候选表述为漏洞确认
- 不做可利用性评估或 exploit 生成
- 不因准备 V3.3 设施而声称 V3.3 已通过

## 历史阶段

V2 建立 Contract、静态事实、runtime trace、oracle 与实验基础。V3.1 引入匿名 n-day gate 设施。V3.2 把 corpus intake、buildability、boundary index、candidate partition 与 failure taxonomy 固定为公开 schema。这些阶段的结论不支持泛化，其价值是为本文路线提供可复用设施。
