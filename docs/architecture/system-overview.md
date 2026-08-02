# 系统架构总览

BoundaryWitness 是一条面向 Rust–C 生命周期边界的可审计分析链。当前阶段是 **V3.2.x core-effect hardening**；V3.3 gate 未通过。系统先产生中性事实，再把事实组织成候选与静态风险链，最后为受控动态验证提供输入。静态排序、工具退出成功或报告措辞都不等同于漏洞确认。

> **本文描述当前实现。目标形态与它有实质差别**——目标形态里 candidate 降为下游投影、两侧事实按分层身份联结、外部证据来自 IR 抽取而非 API 清单推断。见 [target verifier pipeline](target-verifier-pipeline.md)（全文 `Planned`）。**不要把本文的当前数据流当成目标设计，也不要把目标设计当成已实现能力。**

## 端到端数据流

```text
source / fixture
  -> boundary index + candidate
  -> bw-rustc neutral static facts + MIR coverage
  -> model / Contract / Schema validation
  -> candidate-scoped lifecycle evidence + facts + coverage
  -> ObjectFlow / lifecycle graph v3 / proof layers
  -> feature derivation + ranking + CLI artifacts
  -> witness plan
  -> experiment / runtime events / oracle findings
  -> public report: candidate + evidence + static risk + validation needed
```

| 节点 | 目录与实现入口 | 输入 | 输出 | 失败边界 |
| --- | --- | --- | --- | --- |
| source / fixture | [`benchmarks/`](../../benchmarks/)、[`fixtures/`](../../fixtures/)、[`crates/bw-cli/src/commands/index_boundaries.rs`](../../crates/bw-cli/src/commands/index_boundaries.rs) | 可构建源码、corpus/buildability JSONL、受控 fixture | `v3.2.boundary_index.1` 记录与 negative summary | 不可构建、无受支持边界或 span 不足必须保留为跳过、负结果或覆盖缺口；名称命中不是生命周期证明 |
| candidate | [`emit_candidates.rs`](../../crates/bw-cli/src/commands/emit_candidates.rs)、[`candidate.rs`](../../crates/bw-model/src/candidate.rs) | boundary index，可选 `bw.static/0.2` facts | 分片 `v3.2.candidate.1` JSONL.zst、manifest、统计与 checksum | candidate 只表示待分析位置；不能改名为 finding |
| `bw-rustc` facts | [`compiler/bw-rustc/src/main.rs`](../../compiler/bw-rustc/src/main.rs)、[`rustc_api/mod.rs`](../../compiler/bw-rustc/src/rustc_api/mod.rs)、[`rustc_api/mir.rs`](../../compiler/bw-rustc/src/rustc_api/mir.rs) | Cargo/rustc wrapper 调用、allowlist、API map 与可选 registry | `static-facts.jsonl`、`static-facts.manifest.json`、`mir-coverage.json` | wrapper/config/toolchain/build 失败是工具或构建状态；未观察到事实不能解释为安全 |
| model / Contract / Schema validation | [`crates/bw-model/src/`](../../crates/bw-model/src/)、[`contracts/callback-retention/`](../../contracts/callback-retention/)、[`schemas/`](../../schemas/)、[`validate.rs`](../../crates/bw-cli/src/commands/validate.rs) | 版本化 JSON/JSONL/TOML | 校验通过的 records 或稳定错误码 | schema 版本、未知字段、跨记录 identity、provenance、Contract 引用或 checksum 不符时拒绝；“命令成功”不增加证据层级 |
| candidate-scoped lifecycle facts | [`extract_lifecycle_evidence.rs`](../../crates/bw-cli/src/commands/extract_lifecycle_evidence.rs) | manifest、boundary、candidate、可选 static facts 与 MIR coverage | lifecycle evidence/fact/coverage JSONL.zst 与 checksum | 共享事实只在唯一归属或唯一 exact anchor 下挂接；歧义事实不复制给多个候选 |
| lifecycle graph v3 | [`build_lifecycle_graph_v3.rs`](../../crates/bw-cli/src/commands/build_lifecycle_graph_v3.rs)、[`lifecycle_v326.rs`](../../crates/bw-model/src/lifecycle_v326.rs) | candidate、evidence、facts、已物化 Contract 与 registry manifest | 每候选 graph-v3 JSON、feature JSONL.zst、缺证原因 | graph 只能消费 candidate-scoped authoritative facts；barrier、binding 不匹配、未知 ordering 或 contract 缺失会阻止升级 |
| ranking / CLI | [`rank_lifecycle_v2.rs`](../../crates/bw-cli/src/commands/rank_lifecycle_v2.rs)、[`build_witness_plan.rs`](../../crates/bw-cli/src/commands/build_witness_plan.rs) | features、graph-v3 | ranked candidate、三层 chain summary、witness plan、统计与 checksum | score 只决定审查次序；`verified_static_chain` 是兼容状态，规范消费者读取 `verified_layers`/`missing_layers` |
| experiment / runtime evidence | [`crates/bw-experiment/src/`](../../crates/bw-experiment/src/)、[`crates/bw-runtime/src/`](../../crates/bw-runtime/src/)、[`crates/bw-oracle/src/`](../../crates/bw-oracle/src/) | witness/harness 动作、固定环境、static facts、Contract | trace、finding、ASan/native outcome、replay summary、run manifest/checksum | witness plan 不是 dynamic witness；crash 不是根因；run/build identity 不一致、重复事件、缺少 trace start 或重放不稳定均不得确认 |
| report / reveal | [`reveal_static_ranking.rs`](../../crates/bw-cli/src/commands/reveal_static_ranking.rs)、[`bw-blind-curator`](../../crates/bw-blind-curator/)、[`bw-blind-runner`](../../crates/bw-blind-runner/) | 冻结后的公开结果、隔离 ground truth、运行回执 | 静态 reveal 摘要、blind observation/reveal/receipt | ground truth 只能在运行后核对；公开报告保持“候选、证据、静态风险、需验证”，未完成 gate 不得写成 V3.3 通过 |

## 核心信任边界

1. **编译器与经审计 Contract 提供事实，不提供漏洞答案。** `bw-rustc` 的输出仍需 model validator、artifact identity 和 provenance 检查。
2. **对象身份、生命周期顺序、完整风险必须分层。** 规范顺序是 `identity_transport -> lifecycle_ordering -> complete_risk_chain`，详见[生命周期对象流](lifecycle-object-flow.md)。
3. **静态与动态不互相替代。** graph/ranking 产生静态风险与后续路线；runtime/oracle 处理真实事件；ground truth 只做运行后评估。
4. **派生物保留 lineage。** candidate、fact、chain、finding 通过 `evidence_refs`、`fact_refs`、`record_id`、`run_id`、`build_id` 和 checksum 回到父证据。文件名和自然语言摘要不是 lineage。

## 当前实现边界

已实现的是静态主链、proof-layer split、mutation/reassignment barrier、closure capture slot、opaque generation key、returned-borrow exact claimant，以及 runtime/oracle/fuzz 基础。尚未形成面向任意 candidate 的通用 harness 生成与 executor 闭环；任意深度跨函数/跨 crate、trait/dyn dispatch、async/coroutine、复杂合流、动态 key/index 和任意堆别名也不在通用保证内。正式状态以[当前状态](../project/current-status.md)为准。

## 代码、契约与测试入口

- 代码：[`crates/bw-cli/src/commands/mod.rs`](../../crates/bw-cli/src/commands/mod.rs)、[`compiler/bw-rustc/src/rustc_api/mod.rs`](../../compiler/bw-rustc/src/rustc_api/mod.rs)、[`crates/bw-model/src/lifecycle_v326.rs`](../../crates/bw-model/src/lifecycle_v326.rs)。
- Schema/Contract：[`schemas/v3-2/`](../../schemas/v3-2/)、[`schemas/v3-2-6/`](../../schemas/v3-2-6/)、[`contracts/callback-retention/contract.toml`](../../contracts/callback-retention/contract.toml)。
- 测试：[`crates/bw-cli/tests/lifecycle_v326_cli.rs`](../../crates/bw-cli/tests/lifecycle_v326_cli.rs)、[`crates/bw-model/tests/lifecycle_v326.rs`](../../crates/bw-model/tests/lifecycle_v326.rs)、[`compiler/bw-rustc/tests/mir_sites_golden.rs`](../../compiler/bw-rustc/tests/mir_sites_golden.rs)、[`crates/bw-oracle/tests/properties.rs`](../../crates/bw-oracle/tests/properties.rs)。

相关设计：[证据模型](evidence-model.md)、[编译器分析](compiler-analysis.md)、[Contract 与 Schema](contracts-and-schemas.md)、[排序与报告](ranking-and-reporting.md)、[动态验证](dynamic-validation.md)。
