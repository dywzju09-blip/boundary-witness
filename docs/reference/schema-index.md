# Schema index

## 当前使用状态

| 目录 | 状态 | 说明 |
| --- | --- | --- |
| [`schemas/v3-2`](../../schemas/v3-2/) | Active intake / legacy lifecycle | corpus、buildability、boundary、candidate、adapter、taxonomy 仍由当前 CLI 使用；legacy graph/ranking 保留兼容 |
| [`schemas/v3-2-5`](../../schemas/v3-2-5/) | Active evaluation, curator-separated | 已揭示 public regression 的 ground-truth/reveal 格式；不表示新 holdout 已运行 |
| [`schemas/v3-2-6`](../../schemas/v3-2-6/) | Active core-effect | 当前 lifecycle evidence/fact/coverage/contract/graph-v3/ranking/witness 主链 |
| [`schemas/v3-2-7`](../../schemas/v3-2-7/) | Active pair output | `compare-anonymous-pairs` 当前写 candidate-aligned pair delta |
| [`schemas/v3-3`](../../schemas/v3-3/) | Implemented schema, gate Blocked | 只有 scanner freeze record；Schema 存在不表示 V3.3 通过 |

## V3.2

| 文件 | `schema_version` | 角色 |
| --- | --- | --- |
| `corpus-manifest.schema.json` | `v3.2.corpus_manifest.1` | frozen corpus intake ledger |
| `buildability.schema.json` | `v3.2.buildability.1` | per-crate build outcome |
| `boundary-index.schema.json` | `v3.2.boundary_index.1` | supported boundary/negative-summary facts |
| `candidate.schema.json` | `v3.2.candidate.1` | neutral candidate partition |
| `lifecycle-graph.schema.json` | `v3.2.lifecycle_graph.1` | legacy template lifecycle graph |
| `ranked-candidate.schema.json` | `v3.2.ranked_candidate.1` | legacy ranked record |
| `adapter-effort.schema.json` | `v3.2.adapter_effort.1` | dynamic preparation estimate |
| `failure-taxonomy.schema.json` | `v3.2.failure_taxonomy.1` | incomplete/failure accounting |

## V3.2.5

| 文件 | `schema_version` | 角色 |
| --- | --- | --- |
| `private-ground-truth.schema.json` | `v3.2.5.private_ground_truth.1` | curator-only sample expectations; data never enters public artifacts |
| `static-ranking-reveal.schema.json` | `v3.2.5.static_ranking_reveal.1` | aggregate top-k/control/miss summary |

## V3.2.6

| 文件 | `schema_version` | 角色 |
| --- | --- | --- |
| `lifecycle-evidence.schema.json` | `v3.2.6.lifecycle_evidence.1` | candidate-scoped neutral observations |
| `lifecycle-fact.schema.json` | `v3.2.6.lifecycle_fact.1` | provenance-checked lifecycle facts |
| `lifecycle-coverage.schema.json` | `v3.2.6.lifecycle_coverage.1` | per-candidate coverage/gap ledger |
| `lifecycle-contract.schema.json` | `v3.2.6.lifecycle_contract.1` | materialized exact-API lifecycle contract |
| `lifecycle-graph-v2.schema.json` | `v3.2.6.lifecycle_graph_v2.1` | compatibility graph-v2 |
| `lifecycle-graph-v3.schema.json` | `v3.2.6.lifecycle_graph_v3.1` | object-bound graph and proof layers |
| `lifecycle-feature.schema.json` | `v3.2.6.lifecycle_feature.1` | evidence-backed ranking feature |
| `ranked-candidate-v2.schema.json` | `v3.2.6.ranked_candidate_v2.1` | current ranked candidate + chain summary |
| `anonymous-pair.schema.json` | `v3.2.6.anonymous_pair.1` | anonymous left/right pair manifest |
| `pair-delta.schema.json` | `v3.2.6.pair_delta.1` | older crate-level pair comparison |
| `witness-plan.schema.json` | `v3.2.6.witness_plan.1` | controlled witness plan; not execution receipt |

## V3.2.7 与 V3.3

| 文件 | `schema_version` | 角色 |
| --- | --- | --- |
| `v3-2-7/pair-delta.schema.json` | `v3.2.7.pair_delta.1` | candidate-aligned `api_path + pattern_family` comparison |
| `v3-3/scanner-freeze.schema.json` | `v3.3.scanner_freeze.1` | method/input/checksum freeze record |

## 版本规则

JSON Schema `$id` 与 record `schema_version` 都是协议身份，但 validator 以记录版本、strict deserialization、跨记录引用和 lineage 规则为最终约束。语义不兼容变更必须升版；不得静默改变旧字段含义。`verified_static_chain` 仅兼容保留，规范消费者读取 `verified_layers`/`missing_layers`。
