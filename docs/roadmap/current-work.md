# 当前工作

本文只记录当前所处阶段与下一步，不保存 Agent prompt 或逐日执行过程。阶段定义见 [roadmap](roadmap.md)，方向权威见 [research thesis](../project/research-thesis.md)。状态词含义见 [terminology](../project/terminology.md)。

## 所处位置

**持有期维度的 Rust 侧已闭环，外部侧仍是推断而非证据。研究路线于 2026-07-30 重定向、2026-07-31 复审后修正核心关系，PF/PC/PP/P0/P1/P2 均未开始。**

Rust 侧现在可以走完「从签名读出契约 → 与外部边界事实关联 → 把判定与判定来源写入产物」整条链。但外部侧那一半的证据来自 API 清单分类出的注册与注销事实，不是外部代码本身的行为。因此：

| 创新点 | 状态 |
| --- | --- |
| C1 safe-only 可执行反证合成 | 未开始（roadmap P4） |
| C2 类型契约 × 外部 effect 的精化检查 | 未成立——两侧事实还不是真正的两侧（roadmap P1/P2/P3） |
| C3 生态级度量与新发现 | 未开始 |

## 下一步：PF 核心关系与四个 matched fixture

**这是当前唯一应该做的事。** 它取代了此前「先跑 Gate P」的安排——2026-07-31 的复审证明旧的 2×2 判定矩阵有可构造的假阳性与假阴性，**关系错了，猎物探针数出来的候选也是错的**。

| 字段 | 内容 |
| --- | --- |
| 服务 | [Gate R](milestone-gates.md#gate-r关系正确性) |
| 状态 | `Planned` |
| 前置 | 无。**外部侧用手写 C stub，不需要 LLVM IR 流水线** |
| 要做 | 实现 [research thesis §2.4](../project/research-thesis.md) 的轨迹可行性关系，三类生命周期 R/A/G 分开建模，构造四个 matched fixture |
| 完成谓词 | 四条 fixture 全判对；fixture 2 与 3 的 Rust 侧逐字节相同、只有 C stub 不同，Full 能分开而 Rust-only 不能 |
| 成本 | 小 |
| 失败动作 | fixture 2/3 分不开 → 外部侧对 C2 无判别力，转路线 B |

**fixture 3 是重点。** 它检验一个可能否定 C2 的推论：外部侧的判别力若真在 Q4′（清槽）而不在 Q1（是否保存），这一条就必须能分开。**若 Rust-only 也能分开，那是 Gate A 的提前失败信号——不必等到规模化对照。**

## 并行：PC `EffectiveCaptureAdmission`

| 字段 | 内容 |
| --- | --- |
| 服务 | PP 的正确性，是 Gate P 的前置 |
| 状态 | `Planned` |
| 前置 | 无，可与 PF 并行 |
| 问题 | 现有 `CallbackLifetimeBoundScope` 是语法四态。`fn register<F: Fn()>` 的「无 bound」**恰恰是允许捕获借用**（最强候选），而 `dyn Fn` 的省略 lifetime **默认 `'static`**（不是候选）——两者被合并成同一个 `NoLifetimeBound` |
| 代码入口 | `compiler/bw-rustc/src/rustc_api/mir.rs` 的 `callback_lifetime_bounds`；`crates/bw-model/src/static_fact.rs` |
| 完成谓词 | `dyn Fn` 与泛型 `F: Fn` 两个 fixture 落到**相反**取值 |

**不修这一项就跑 Gate P，会系统性错估猎物池。**

## 之后：PP 猎物存在性探针

仅在 PC 完成后启动。判据已重做，见 [runbook](../experiments/runbooks/prey-existence-probe.md)：以 `EffectiveCaptureAdmission` 语义取值为准；只数 **Tier A**（dataflow 到达精确 extern 参数）；只算 **L1 可分析**；用置信界而非「足够」；**运行前必须完成 family-level sealed split，默认只返回盲化聚合统计**——否则整个前瞻池变成开发集。

## 再之后：P0 与 P1 并行起步

仅在 Gate P 通过后启动。

### P0 hand-off 身份与双侧事实模型

| 字段 | 内容 |
| --- | --- |
| 服务 | C2 的前提 |
| 状态 | `Planned` |
| 代码入口 | `crates/bw-model/src/static_fact.rs`、`crates/bw-model/src/lifecycle_v326.rs`、`crates/bw-model/src/id.rs`、`compiler/bw-rustc/src/site.rs`（`SiteDescriptor` 是现成的可扩展入口）、`compiler/bw-rustc/src/domain.rs` |
| 完成谓词 | 两侧事实可在不依赖候选切分的前提下联结；同一调用含多组 callback/userdata 时仍能区分；判定按 `StaticVerdict` / `EvidenceGrade` / `WitnessStatus` 三个正交维度记录 |
| 风险 | 低，但必须一次做对 |

### P1 外部侧 Q1 逃逸

| 字段 | 内容 |
| --- | --- |
| 服务 | C2 的**前提**，不是判别项 |
| 状态 | `Planned` |
| 范围 | 只支持外部 C 源码随构建提供的 crate（L1） |
| 完成谓词 | 单一库上端到端产出指令级可回查的逃逸证据；查不出逃逸时记 `InsufficientEvidence` 而非判安全 |
| 风险 | 中。**止损**：两三周内看不到端到端结果，贡献结构需重新设计 |

## 已记录的降级

**Q3 晚调查询首期降级为「同槽间接调用存在性」。** 完整 Q3 需要全库可达性加间接调用 callee 解析，代价高一个数量级。降级版输出 `StaticVerdict = InsufficientEvidence` + `EvidenceGrade = SameSlotInvokeCandidate` + witness obligation，由 P4 的反证补上真实可达性证明。**不得输出 `SupportedIncompatibility (weak)` 或任何第四态。**

**即使 F1–F4 全部完成，静态 Q3 也只能称「declared abstraction 内的高精度」，不能称独立确认。**

降级的确切代价、必须量化的三个指标、完整实现的 F1–F4 分阶段计划，见 [implementation plan 的 P2](implementation-plan.md#p2-外部侧-q3-晚调-与-q4-清槽)。

## 代码处置

逐组件的保留 / 冻结 / 重构 / 删除见 [代码库对齐审计](../development/codebase-realignment.md)。结论是**补充优化而非重构**：编译器 Rust 侧在新路线中价值上升，身份模型是可扩展的 builder，外部侧属纯新增。

三条具名决定：

| 编号 | 决定 |
| --- | --- |
| D1 | 冻结 returned-borrow 维度——不删除、不新增投入、不作为贡献陈述 |
| D2 | `HandOffId` + 三态判定 + 外部侧事实合并为**一次** schema 升版 |
| D3 | 重写 `generate_witness_harness.rs` 的产出目标，保留其推导逻辑 |

## 已推迟的决定

**跨外部库家族的数量下限推迟到认证期。** 取得多个外部库 LLVM IR 的工程可行性是已知风险，但按当前决定不构成现阶段的实现约束——P1/P2 只要求单库端到端打通。见 [Gate C](milestone-gates.md#gate-c跨库泛化)。

## 已知未收口项

不阻塞关键路径，但影响评估质量。

| 项 | 影响 |
| --- | --- |
| 排名未把可绑定的注册候选排进默认输出上限 | 默认扫描看不到判定结果，每次都要手动放宽上限 |
| 保护性特征仍依赖源码文本匹配 | 同类候选内部排序不可靠 |
| n-day 度量仪器只接入了单一库 | 召回率数字不具代表性 |
| 跨函数对象流只覆盖有限形状 | 影响未来扩维，当前不阻塞 |
| release/use ordering 中 unregister-before-drop 与 conditional release gap 未分开报告 | 需在 release-proof 层新增事实种类，不能靠扩展 ordering 枚举解决 |

## V3.3

`Blocked`。依赖 clean method commit、公开数据集 manifest、Contract/config hash、pair gate、动态桥接与约 100 crate pilot。判据见 [milestone gates](milestone-gates.md) 的工程 gate 部分与 [public regression runbook](../experiments/runbooks/public-regression.md)。准备 V3.3 设施不改变当前阶段判断，也**不能替代研究 gate**。
