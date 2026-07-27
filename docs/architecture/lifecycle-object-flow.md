# 生命周期 ObjectFlow 与证据分层

ObjectFlow 是对象传递事实，不是漏洞结论。BoundaryWitness 对任何强链固定采用以下语义层级：

```text
IdentityTransport
→ LifecycleOrdering
→ CompleteRiskChain
```

后层依赖前层语义，但每层都需要自己的可回查证据；不能因出现后续 API 名称或高分候选而跳层。

## 三层语义

| 层 | 回答的问题 | 典型必要证据 | 仍不能证明 |
| --- | --- | --- | --- |
| `identity_transport` | store/load、capture/use、参数/返回或 set/get 是否属于同一逻辑对象 | matching endpoint、binding key、capture slot、opaque generation key、无相关 barrier 的 `ObjectFlow` | release/use 先后、风险路径、动态触发 |
| `lifecycle_ordering` | release、drop、invalidation 与后续 use 的顺序是否已证明 | release post-dominance、`CallbackReleaseUseOrderFact`、`ReturnedBorrowInvalidationOrderFact`、同对象事件 | 身份本身、完整风险路径、动态影响 |
| `complete_risk_chain` | 同一对象、危险顺序和风险 use 路径是否同时闭合 | identity transport + ordering + callback/returned-view risk fact 的同链 lineage | 真实执行可触发、UB、漏洞或可利用性 |

`V326ObjectChain.verified_layers` 是规范读口，`missing_layers` 说明缺口。`chain_status=verified_static_chain` 只为兼容保留，不能把三层重新压成一个布尔值。

## ObjectFlow 连接规则

当前受支持的中性传递包括：

- closure `capture -> FieldLoad`，slot 由 capture ordinal 与有限 field projection 固定；
- `return_value -> argument`；
- `field_store -> field_load`；
- `wrapper_move -> wrapper_destructure`；
- `collection_store -> collection_load`；
- callback/userdata、opaque handle 与 release endpoint 的受审计连接。

连接要求 endpoint continuity、兼容 object kind、精确 binding key，并且连接区间内不存在匹配的 mutation/reassignment barrier。单边 flow、key 不匹配或端点歧义只能形成 partial/ambiguous chain。

## external-buffer 的上限

单个 `ExternalBufferBindingFact` 只证明 source 与 buffer 的 **identity transport**。graph 应同时把 `lifecycle_ordering` 与 `complete_risk_chain` 放入 `missing_layers`，并保留 `complete_risk_chain_missing` 等原因。只有另有同对象 invalidation/use ordering 和风险路径时，才可逐层晋升；external-buffer binding 本身不得升级为完整链。

## returned-borrow claimant

returned-borrow 的 relation、persistence、invalidation/use 可能由多个 candidate 同时触达。共享 static fact 只有在以下条件同时成立时才可归属：

1. candidate 与事实具有相同的精确 returned-borrow API key；
2. candidate selection 中存在可回查的 `ReturnedBorrowRelation` exact anchor；
3. 在所有竞争 candidate 中，满足前两项的 claimant **恰好一个**。

若 exact-anchor claimant 为零或多于一个，事实不挂入任一竞争 candidate，或在下游保持 ambiguous。严禁用 candidate ID 字典序、rank/score、源码位置接近、同名 tail、候选创建顺序或“最近 span”消歧。实现入口是 [`canonical_returned_borrow_static_fact_claimants`](../../crates/bw-cli/src/commands/extract_lifecycle_evidence.rs) 所在模块。

## Ordering 与反向证据

- 源码行先后不是跨路径 ordering proof；MIR CFG/post-dominance 或专门 ordering fact 才能晋升。
- release-like API 与 registration 同名不足以证明同一对象；`ReleasePathProofFact.object_site_id` 和 supporting ObjectFlow 必须相容。
- owned anchor、drop guard、unregister-before-drop、static lifetime bound、Arc anchor、release coverage 是保护性事实，会降低风险或闭合安全路径，但不删除原始证据。
- mutation/reassignment barrier 是精确 binding 上的反向证据；它阻断相关 transport，不产生“整个 crate 安全”的结论。

## Graph 与 ranking 消费

[`build_v3_2_6_lifecycle_graph_v3`](../../crates/bw-model/src/lifecycle_v326.rs) 先按 candidate/crate 过滤 facts，再仅用 authoritative binding fact 构造对象和边。`summarize_v3_2_6_ranked_object_chains` 分别统计 identity、ordering、complete chain 数量；top chain 优先级也先看 proof layer。ranking 可把层级作为审查信号，但不能自行添加任何层。

## 代码、契约与测试入口

- 代码：[`crates/bw-model/src/lifecycle_v326.rs`](../../crates/bw-model/src/lifecycle_v326.rs)、[`crates/bw-cli/src/commands/extract_lifecycle_evidence.rs`](../../crates/bw-cli/src/commands/extract_lifecycle_evidence.rs)、[`crates/bw-cli/src/commands/build_lifecycle_graph_v3.rs`](../../crates/bw-cli/src/commands/build_lifecycle_graph_v3.rs)。
- Schema/Contract：[`schemas/v3-2-6/lifecycle-graph-v3.schema.json`](../../schemas/v3-2-6/lifecycle-graph-v3.schema.json)、[`schemas/v3-2-6/lifecycle-fact.schema.json`](../../schemas/v3-2-6/lifecycle-fact.schema.json)、[`contracts/callback-retention/openssl-api-map.toml`](../../contracts/callback-retention/openssl-api-map.toml)。
- 测试：[`crates/bw-model/tests/lifecycle_v326.rs`](../../crates/bw-model/tests/lifecycle_v326.rs) 中的 field/collection barrier、closure slot、opaque handle、returned view、external buffer 和 ordering cases；[`crates/bw-cli/tests/lifecycle_v326_cli.rs`](../../crates/bw-cli/tests/lifecycle_v326_cli.rs) 中的 candidate scoping/ambiguous claimant cases；[`crates/bw-model/tests/schema_roundtrip.rs`](../../crates/bw-model/tests/schema_roundtrip.rs) 中的 proof-layer enum/summary fields。

上游事实来源见[编译器分析](compiler-analysis.md)，公开解释规则见[排序与报告](ranking-and-reporting.md)。
