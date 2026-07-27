# ADR-0002: Layered object-chain evidence

## Status

Accepted

## Context

早期静态链容易把“对象身份传递”“生命周期顺序”和“完整风险路径”压成单一 `verified_static_chain`。这种表示会让 external buffer、returned borrow、opaque handle 和 callback retention 的不同证据层被误读为同等强度，进而把候选排序写成过强结论。

## Decision

对象链证据分为三层：

1. `identity_transport`：证明同一逻辑对象或传递关系；
2. `lifecycle_ordering`：证明 release、invalidation、use 等事件顺序；
3. `complete_risk_chain`：同对象、危险顺序和风险路径同时闭合。

Graph-v3、ranking 和 CLI 以 `verified_layers`/`missing_layers` 为规范语义。`verified_static_chain` 仅作为兼容字段保留，不能继续承载完整风险链解释。缺少任一层时，候选应保留缺证原因，而不是用 API 名称、源码距离、candidate score 或历史标签补齐。

## Consequences

- external-buffer binding 只能支持 identity transport，不能单独成为完整风险链；
- returned-borrow 需要 relation、persistence 和 invalidation/use ordering；
- release proof、barrier 和 protective facts 可以降低或阻断风险链，但不删除原始证据；
- public report 应区分 candidate、static risk、dynamic witness 和 oracle finding。

## References

- [Lifecycle ObjectFlow and proof layers](../architecture/lifecycle-object-flow.md)
- [Evidence model](../architecture/evidence-model.md)
- [Ranking and reporting](../architecture/ranking-and-reporting.md)
- [Schema index](../reference/schema-index.md)
