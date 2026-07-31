# 实现路线

本文服从 [research thesis](../project/research-thesis.md)。每个阶段都标注它服务哪条创新点；不服务任何创新点的工作不排进路线。

本文于 2026-07-30 全量重写，取代此前所有版本。旧版本的 P0–P7 编号与 N1/N2/N3 创新点编号一律作废。

当前阶段是 **V3.2.x core-effect hardening**。本文是计划，不是已完成能力的声明。

## 关键路径

```text
PP 猎物存在性探针 ──（决定后续是否投入）──┐
                                          │
P0 hand-off 身份与双侧事实模型 ───────────┼─→ P3 关系判定器 ─→ P4 反证合成 ─→ P5 评估
                                          │
P1 外部侧 Q1 逃逸 ─→ P2 外部侧 Q3 晚调 ───┘
```

**执行顺序上最重要的一条：PP 排在一切之前。** 它成本约为 P1+P2 的百分之一，却能否定整条路线。此前的路线图从设计直接跳到最贵的外部侧实现，没有先问「还有没有东西可找」。

各阶段的可执行细化（数据结构、算法、完成谓词、非空性检查、Q3 降级记录）见 [implementation plan](implementation-plan.md)。

## PP — 猎物存在性探针

服务 [Gate P](milestone-gates.md#gate-p猎物存在性)。

在 300–500 个 FFI crate 上运行已实现的 Rust-only 前端，统计「safe API + 非 `'static` 的 Fn bound + 同函数内 FFI 注册」的位置数量。

- 复用：`callback_lifetime_bounds` 四态判定，已实现且不依赖 API 清单
- 风险：低
- 完成谓词：候选池表，区分已调优与未调优 crate
- **失败动作**：候选池过小则转路线 C（经验研究），不投入 P1/P2

## P0 — hand-off 身份与双侧事实模型

服务 C2 的前提。

拆成三类记录：`RustContractFact`、`ForeignBehaviorFact`、`CompatibilityVerdict`，核心是引入 `HandOffId` 作为两侧连接键。身份必须精确到单态化实例、调用出现次序、参数角色索引、外部符号与构建配置。**源码位置与函数名只能作诊断，不能参与联结。**

- 复用：站点身份描述符、schema 验证器、事实信封
- 风险：低，但必须一次做对，后续每一维都挂在这个键上
- 完成谓词：两侧事实可在不依赖候选切分的前提下联结

**这一层不是创新点**，是任何跨语言分析的基本前提。见 [research thesis §3](../project/research-thesis.md)。

## P1 — 外部侧 Q1：逃逸

服务 C2。

判定外部函数的指针形参是否到达「调用返回后仍存活」的存储。只支持外部 C 源码随构建提供的 crate（L1），其余写入 limitation。

- 风险：中
- 纪律：查不出逃逸**不得判定为安全**，必须记 `InsufficientEvidence`
- 完成谓词：单一库上端到端产出指令级可回查证据
- 止损：两三周内看不到端到端结果，贡献结构需重新设计

## P2 — 外部侧 Q3：晚调

服务 C2 的核心判据。**全路线风险最高的一段。**

完整 Q3 需要全库可达性加间接调用 callee 解析。**首期降级为「同槽间接调用存在性」**，判定产出 `SupportedIncompatibility (weak)`，由 P4 的反证补上真实可达性证明。降级的确切代价、必须量化的三个指标、以及完整实现的 F1–F4 分阶段计划，全部记在 [implementation plan 的 P2 一节](implementation-plan.md#p2-外部侧-q3晚调含降级方案)。

附属查询 Q4′（unregister/replace 是否清空槽位）服务反证的负对照与消融，不作独立创新点。

- 风险：高
- Plan B：把范围收为「外部源码随构建提供的 FFI crate」，作为明确 scope 而非失败

## P3 — 关系判定器

服务 C2。

实现 [research thesis §2.4](../project/research-thesis.md) 的判定矩阵，三态输出。把持有期判定的外部侧证据来源从「注册事实推断」换成 Q1/Q3 证据；人工版本边界保留为交叉验证。

- 风险：低
- 完成谓词：判定来源为外部侧证据；Full / Rust-only / Foreign-only / manual-oracle 四变体作用于同一 candidate universe

## P4 — 反证合成与执行

服务 C1，**首要创新点**。

从一条不相容判定自动合成 `#![forbid(unsafe_code)]` 的最小客户端，链接精确外部构建，由独立 oracle 出证。

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

## 明确的非目标

- 不做全程序任意深度 points-to
- 不做外部库的完整语义建模
- 不把静态候选表述为漏洞确认
- 不做可利用性评估或 exploit 生成
- 不因准备 V3.3 设施而声称 V3.3 已通过

## 历史阶段

V2 建立 Contract、静态事实、runtime trace、oracle 与实验基础。V3.1 引入匿名 n-day gate 设施。V3.2 把 corpus intake、buildability、boundary index、candidate partition 与 failure taxonomy 固定为公开 schema。这些阶段的结论不支持泛化，其价值是为本文路线提供可复用设施。
