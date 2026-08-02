# ADR-0004: Joint-trace verdict semantics

## Status

Accepted（决定已生效；关系层实现为 `Implemented`，联合轨迹与正交证据字段为 **`Planned`**）

## Context

三个问题出现在同一处判定逻辑上：

**一、合取不等于联合可行。** 现有关系是两个 may-property 的合取：`SafeLifetimeSeparationPossible ∧ ForeignLateUsePossible ∧ SameArtifactSlotAndRole`。"存在一条客户端轨迹使 X 失效而注册仍有效"与"存在一条外部路径在返回后调用该槽位"**分别成立，不蕴含存在同一条执行同时满足两者**。而 `SupportedIncompatibility` 这个结论读起来像后者。

**二、外部证据的四个属性被压成一个枚举。** `EvidenceGrade` 同时表达"同槽调用候选""调用点可达""路径支持晚调""guard 被击穿"。前三者是一条可达性阶梯，第四者是清槽结论，两者不可比较。实测后果：guard 被击穿时晚调证据等级被直接覆盖丢失。

**三、降级 Q3 与反证阶段之间存在死锁。** 降级 Q3 的规定输出永远是 `InsufficientEvidence`，永不产出 `SupportedIncompatibility`；而反证合成的输入被描述为"从一条有证据支持的不相容出发"。首期实现里反证阶段没有合法输入。

## Decision

**一、判定要求联合轨迹可行。** 两侧证据必须在同一构建、同一交出点、同一槽位、同一 registration generation 且路径条件相容下能形成联合轨迹：

```text
SupportedIncompatibility(X, Slot)
  ⇐ SeparationCertificate(X, Slot)
  ∧ ForeignLateUseEffect(Slot, X)
  ∧ JointTraceFeasible(...)
```

- `SeparationCertificate` 是**正面证据**。"没有观察到保护机制"不等于"已证明不存在保护机制"，后者才构成证书；
- 静态证不出联合可行性 → `InsufficientEvidence` + `JointTraceObligation`；
- 动态反证可以完成联合轨迹的证明——反证跑起来、外部真的回调进来，就是一条实际发生过的联合轨迹。

**二、三态判定不变，不得引入第四态。** `SupportedIncompatibility` / `CompatibleWithinAnalyzedFragment` / `InsufficientEvidence`。

**三、外部证据拆成四个正交字段**：`RetentionEffect`、`InvokeReachability`、`ClearReplaceStatus`、`PathCompatibility`。可派生报告级总体等级用于展示，**不得丢失原始维度**。

**四、反证阶段接受两类输入**：

1. `SupportedIncompatibility`；
2. `InsufficientEvidence` + `EstablishLateInvoke` 义务，**前提是** Rust 侧分离性、Q1、Q4′ 与身份都已充分，缺的只是晚调可达性。

第 2 类是首期实现的主要输入。动态成功写入 `WitnessStatus = ConfirmedCounterexample`，**不静默改变静态判定的语义**。

**五、反证未触发只能记 `Inconclusive`。** 有限次动态执行不能证伪一个 may-property。

## Consequences

- 关系实现与术语文档需同步引入 certificate / obligation 的正面语义；
- `EvidenceGrade` 的拆分与 `HandOffId` 分层、三态判定合并为一次 schema 升版；
- 首期外部侧实现（降级 Q3）不再是反证阶段的阻塞项，Q3 → P4 的死锁解除；
- 静态可达性证明与动态反证的强度关系写入 limitation：对能生成反证的候选，动态证据强于静态 may-behavior；降级的真正损失落在**不能生成反证的候选**上，必须量化。

## References

- [Research thesis §2](../project/research-thesis.md)
- [Target verifier pipeline](../architecture/target-verifier-pipeline.md)
- [Terminology](../project/terminology.md)
- [Implementation plan](../roadmap/implementation-plan.md)
