# 当前工作

本文只记录当前所处阶段与下一步，不保存 Agent prompt 或逐日执行过程。阶段定义见 [roadmap](roadmap.md)，方向权威见 [research thesis](../project/research-thesis.md)。状态词含义见 [terminology](../project/terminology.md)。

## 所处位置

**持有期维度的 Rust 侧已闭环，外部侧仍是推断而非证据。研究路线于 2026-07-30 重定向，PP/P0/P1/P2 均未开始。**

Rust 侧现在可以走完「从签名读出契约 → 与外部边界事实关联 → 把判定与判定来源写入产物」整条链。但外部侧那一半的证据来自 API 清单分类出的注册与注销事实，不是外部代码本身的行为。因此：

| 创新点 | 状态 |
| --- | --- |
| C1 safe-only 可执行反证合成 | 未开始（roadmap P4） |
| C2 类型契约 × 外部 effect 的精化检查 | 未成立——两侧事实还不是真正的两侧（roadmap P1/P2/P3） |
| C3 生态级度量与新发现 | 未开始 |

## 下一步：PP 猎物存在性探针

**这是当前唯一应该做的事，优先级高于任何代码工作。**

| 字段 | 内容 |
| --- | --- |
| 服务 | [Gate P](milestone-gates.md#gate-p猎物存在性) |
| 状态 | `Planned` |
| 前置 | 无 |
| 所需能力 | 已实现（`compiler/bw-rustc/src/rustc_api/mir.rs` 的 `callback_lifetime_bounds`），不依赖外部侧、不依赖 API 清单 |
| 执行步骤 | [猎物存在性探针 runbook](../experiments/runbooks/prey-existence-probe.md) |
| 完成谓词 | 300–500 个 FFI crate 上的候选池表，强/弱候选分列，已调优 crate 单列 |
| 成本 | 约为 P1+P2 的百分之一 |
| 失败动作 | 候选池过小则转路线 C，不投入外部侧实现 |

**为什么排在最前**：主线缺陷类在 Rust 社区是公开知识，`'static` 修法众所周知，猎物池可能已被维护者清空。若池子只有个位数，[research thesis §7.2](../project/research-thesis.md) 的新发现硬要求无法满足，路线 A 直接死。用最小代价否定最大投入。

## 之后：P0 与 P1 并行起步

仅在 Gate P 通过后启动。

### P0 hand-off 身份与双侧事实模型

| 字段 | 内容 |
| --- | --- |
| 服务 | C2 的前提 |
| 状态 | `Planned` |
| 前置 | 无 |
| 代码入口 | `crates/bw-model/src/static_fact.rs`、`crates/bw-model/src/lifecycle_v326.rs`、`crates/bw-model/src/site.rs`、`compiler/bw-rustc/src/domain.rs` |
| 测试入口 | `crates/bw-model/tests/lifecycle_v326.rs`、`crates/bw-model/tests/schema_roundtrip.rs` |
| 完成谓词 | 两侧事实可在不依赖候选切分的前提下联结；同一调用含多组 callback/userdata 时仍能区分 |
| 风险 | 低，但必须一次做对，后续每一维都挂在这个键上 |

**这一层不是创新点**，是任何跨语言分析的基本前提。

### P1 外部侧 Q1 逃逸

| 字段 | 内容 |
| --- | --- |
| 服务 | C2 |
| 状态 | `Planned` |
| 前置 | 无，可与 P0 并行 |
| 范围 | 只支持外部 C 源码随构建提供的 crate（L1） |
| 完成谓词 | 单一库上端到端产出指令级可回查的逃逸证据；查不出逃逸时记 `InsufficientEvidence` 而非判安全 |
| 风险 | 中。**止损**：两三周内看不到端到端结果，贡献结构需重新设计 |

## 已记录的降级

**Q3 晚调查询首期降级为「同槽间接调用存在性」。** 完整 Q3 需要全库可达性加间接调用 callee 解析，代价高一个数量级。降级版产出 `SupportedIncompatibility (weak)`，由 P4 的反证补上真实可达性证明。

降级的确切代价、必须量化的三个指标、完整实现的 F1–F4 分阶段计划，见 [implementation plan 的 P2](implementation-plan.md#p2-外部侧-q3晚调含降级方案)。

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
