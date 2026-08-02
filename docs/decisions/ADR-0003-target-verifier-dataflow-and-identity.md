# ADR-0003: Target verifier dataflow and layered identity

## Status

Accepted（决定已生效；**实现状态 `Planned`**，落地时机受 Gate P 约束）

## Context

当前两侧事实的连接键是函数名，联结实际发生在 candidate 分片这一层。这已经导致两次可复现的错误：

1. 候选按边界切分，把同一函数的两半分到了不同候选；
2. 判定只挂给持有其中一半的候选，另一半读不到结论。

同时，现有设计计划把所有身份概念塞进一个扁平的交出点 ID。该设计缺少两项本项目已经认定重要的区分：

- **registration generation**：同一槽位上"注册 A → 注销 → 注册 B"是不同的注册实例。[research thesis §2.6](../project/research-thesis.md) 把"同一槽位是否被多个 registration instance 共享"列为 Q4′ 的子问题，但身份模型里没有它；
- **safe entry lineage**：研究对象是 public safe API，而现有判据只要求"回调到达 extern 参数"，不要求该交出点能被安全客户端到达。

## Decision

**一、目标数据流单向，candidate 降为下游投影。**

```text
中性事实 → 精确联结 → 判定 → candidate / ranking / 报告
```

candidate 不再充当两侧事实的连接主干，只作展示与调度视图。任何让 candidate 回流进联结或判定的设计一律拒绝。

**二、身份分层，至少五层**：构建产物身份、安全入口身份、静态交出点身份、符号槽位身份、注册实例身份（registration generation）。运行期注册实例若与静态 generation 不一致，单独记录，不合并。

**三、最终判定必须保留 `public safe 入口 → wrapper/helper → 具体 extern 交出点` 的可回查 lineage。** 只证明回调到达 extern 参数不足以证明安全客户端能到达该交出点。

**四、LTO、动态链接、符号解析歧义、`#[link_name]` 不可解析、单态化实例不确定，一律返回 Unknown**，不得用名称近似补齐。

**五、源码位置、span、函数名、API 名、候选 ID 只能作诊断字段**，不参与联结。

## Consequences

- Gate P 的 Tier A 判据必须加入 safe-entry lineage 一条，候选池估计因此收紧；
- 分层身份、三态判定与外部侧事实合并为**一次** schema 升版（见 [codebase realignment](../development/codebase-realignment.md) 的 D2），在阶段 2 与阶段 3 的记录形状定稿之后进行；
- 现有静态事实继续作为底层观察保留，新的契约/行为/判定三层是它们的聚合，不删除既有事实种类；
- 身份字段通过现有站点描述符 builder 的 `with_*` 方法新增，既有调用点不受影响；
- **若 Gate P 判定转路线 C，本 ADR 的实现部分作废**，不得因为文档已写好就照着实现。

## References

- [Target verifier pipeline](../architecture/target-verifier-pipeline.md)
- [Execution plan](../roadmap/execution-plan.md)
- [Research thesis](../project/research-thesis.md)
- [Codebase realignment](../development/codebase-realignment.md)
