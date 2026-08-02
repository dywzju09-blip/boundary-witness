# ADR-0005: Evidence trust boundary and experiment statistics policy

## Status

Accepted（决定已生效；oracle 矩阵与统计协议的**执行**为 `Planned`）

## Context

三类问题共享同一个根源——**证据的来源等级没有被写成可检查的字段，判据没有被写成可预注册的公式**：

1. 人工 API / Role map 与外部行为事实混在一起。清单声明"这个符号是注销"，系统据此推断存在一个需显式清除的槽位——这个推断合理，但不是证明。若不划边界，正式判定里会混入人工预写的外部行为；
2. Gate 判据用的是"足够""非平凡""可解释的增益"这类事后可移动的措辞。文档自己批评过前两个，却在 Gate A 用了第三个。Gate P 更严重：它要求"下置信界仍足以支撑预定确认集"，但**没有任何公式**把候选数换算成确认发现数；
3. oracle 选型被当成单一问题。referent 失效、allocation 提前释放、清槽失败后仍被调用是三类不同现象，普通 ASan 不覆盖所有 Rust lifetime / provenance UB。

## Decision

**一、RoleMap 与 ForeignEffectFact 的信任边界。**

| 来源 | 允许声明 | 不得声明 |
| --- | --- | --- |
| 人工 Role map | 符号绑定；callback / userdata 参数角色；register / unregister / replace 的**候选**角色；接入所需静态元数据 | 实际是否保留；实际是否晚调；是否所有路径清槽；guard 是否有效 |
| 外部 effect 事实 | 上述全部行为结论 | — |

正式 Full 判定中的外部 effect 必须来自外部 IR 抽取。**手工 foreign oracle 必须带独立的 provenance 与来源等级**，只能用于 fixture、交叉验证与消融，不得伪装成自动分析结果。Gate R 的 C stub 标注即属此类。

**二、Gate 判据必须预注册，且是公式而不是形容词。**

- Gate P：`可用猎物估计 = eligible_pool_lower_bound × conversion_rate_lower_bound`，按 crate / repository / 外部库家族聚类；referent 与 allocation 两条子路线分别判定；
- Gate A：比较单位、最小效应量、置信界下界、允许的 Unknown 比例，全部事先写死；
- Gate B：最小通过线（至少一个真正 unseen 的成功）与投稿竞争线（生成率、编译率、执行率、确认率、重放成功率、adapter 人工成本）分开。

**三、oracle admissibility 按缺陷类分别定义。**

| 缺陷类 | 典型现象 | 可接受 oracle |
| --- | --- | --- |
| referent 失效后被访问 | stack-use-after-scope | 栈对象失效检测，需正负对照 |
| allocation 提前释放 | heap use-after-free | 堆分配器检测，需正负对照 |
| 清槽失败后仍被调用 | callback-after-clear | 语义事件 + 独立执行证据，需正负对照 |

未触发统一记 `Inconclusive`。**本项目自有的 runtime 事件不能单独构成 UB 证据**，否则形成自证循环。

**四、抽样与 feature 策略在所有实验间统一。**

- feature 策略：default、all-features、预注册 bundle、one-feature-at-a-time；跨配置按交出点身份去重。**规模化精度对照不得只用 all-features**，否则与猎物探针的候选全集不一致，工具间比较失去同分母；
- 不得把"无公告"直接当作安全负例；
- vulnerable / fixed 差分只是证据之一，不自动决定 TP / FP；
- 正式确认集需两名独立标注者 + 第三人裁决。资源不足时明确标 `Blocked`，**不得把抽查等价成双人 ground truth**；
- 按 repository、外部库家族与 root cause 聚类；同一 advisory 的多个 API 不得计成多个独立问题。

**五、私有 holdout 与第三方可重放的张力**，用 artifact-evaluation escrow、延迟公开或受控访问解决。**不得一边只提供聚合摘要、一边宣称第三方可完整重放。**

## Consequences

- 外部侧事实模型需要 provenance / source-grade 字段（`Planned`，随一次性 schema 升版落地）；
- Gate P 的统计协议必须在探针运行之前完成预注册，否则结果不可用；
- 精度对照 runbook 的 feature 策略需改为与猎物探针一致；
- 结果文档需按聚类单位报告，不得按 alert 计数。

## References

- [Research thesis §7](../project/research-thesis.md)
- [Milestone gates](../roadmap/milestone-gates.md)
- [Prey existence probe runbook](../experiments/runbooks/prey-existence-probe.md)
- [Precision comparison at scale runbook](../experiments/runbooks/precision-comparison-at-scale.md)
- [Evidence model](../architecture/evidence-model.md)
