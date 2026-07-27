# 排序与公开报告

ranking 的职责是按静态证据安排人工审查与动态验证顺序，不是把 candidate 升级为漏洞。公开输出固定保持四类信息：**候选、证据、静态风险、需验证**。

## 静态流水线

1. [`build_lifecycle_graph_v3`](../../crates/bw-cli/src/commands/build_lifecycle_graph_v3.rs) 消费 candidate、evidence、candidate-scoped facts、static facts、lifecycle Contract 与 registry manifest。
2. model 的 [`derive_v3_2_6_lifecycle_features_with_context`](../../crates/bw-model/src/lifecycle_v326.rs) 从实际 evidence/fact/graph 推导风险与保护特征，同时保留 `missing_evidence`。
3. [`rank_lifecycle_v2`](../../crates/bw-cli/src/commands/rank_lifecycle_v2.rs) 计算 score breakdown、稳定排序，并从 graph-v3 汇总 chain layers。
4. [`build_witness_plan`](../../crates/bw-cli/src/commands/build_witness_plan.rs) 当前只对 returned-view 与 external-buffer 做显式分支选择，其余 candidate 一律生成 callback lifecycle 计划。`ManualReviewOnly` 目前只存在于 model 的推荐路由枚举与 summary 推导中，builder 没有独立的 manual-review artifact 分支；因此 model 推荐为 manual review 的候选也会落入 callback 计划，消费者不得把计划类型解释为已实现四路分发。

主要输出为 `graphs-v3/*.json`、`lifecycle-features.jsonl.zst`、`ranked-candidates.jsonl.zst`、`witness-plans.jsonl.zst`、统计和 checksum。

## proof-layer 的严格消费

ranking 与任何 gate 必须读取：

- `identity_transport_chain_count`；
- `lifecycle_ordering_chain_count`；
- `complete_risk_chain_count`；
- `chain_fact_refs` 与 `chain_incomplete_reasons`；
- 每条 chain 的 `verified_layers` 与 `missing_layers`。

不得仅依据 `chain_status=verified_static_chain`、`has_verified_object_chain`、score 或 rank 推断完整风险链。external-buffer binding 只能计入 identity transport；returned-borrow 只有 relation、persistence 和同对象 invalidation/use ordering 闭合时才能计入 complete risk chain。

score 由风险与保护性 feature 共同组成。正分表示审查优先级信号，负分表示 owned anchor、drop guard、release coverage、static bound、Arc anchor 等保护性证据。分数相同可用 candidate ID 提供稳定输出顺序，但这种排序绝不能用来确定事实 claimant 或对象身份。

## 公开报告结构

每条公开候选至少包含：

1. **候选**：candidate ID、crate、boundary/API、pattern family 和 rank；
2. **证据**：source refs、fact/evidence refs、graph path、proof layers、Contract source 和 coverage；
3. **静态风险**：risk/protective features、score breakdown、同对象链状态与缺证原因；
4. **需验证**：recommended witness route、计划动作、所需 observer/oracle assertion、尚无 dynamic witness 的明确说明。

推荐措辞是“静态候选”“静态风险链”“需要动态验证”“当前证据缺少 ordering/identity/contract”。公开报告不得把 candidate/ranking 写成 finding、confirmed vulnerability、0-day 或已复现 UB。

如果已有 oracle finding，报告仍需单列 runtime/contract/static lineage、`run_id`/`build_id`、first violation event、重放次数、fixed/negative control 与 sanitizer/native evidence。单次 finding 或 crash 不自动代表安全影响和根因均已确认。

## reveal 与 blind 输出

[`reveal_static_ranking`](../../crates/bw-cli/src/commands/reveal_static_ranking.rs) 只在 ranked artifact checksum 冻结后加载 private ground truth，输出 reveal summary 与可选 private detail。blind 路径由 [`bw-blind-curator`](../../crates/bw-blind-curator/) 打包/揭示、[`bw-blind-runner`](../../crates/bw-blind-runner/) 隔离执行，并以 public manifest、observation、install/runner receipt 和 checksum 对齐。

ground truth、CVE、补丁、PoC、expected label 不得进入 candidate、ranking、witness search 或公开 seed。揭示结果是效果评估，不是 detector evidence，也不能把已揭示样本再次计为 sealed holdout。

## 失败与负结果

- `partial_chain`、`ambiguous_chain`、`observation_only` 与 `missing_evidence` 必须公开保留；
- tool/build/timeout/unsupported 与 no finding 分开统计；
- fixed、safe move、unregister-before-drop、no-trigger 等负对照与正样本同等报告；
- checksum 不匹配、graph/candidate identity 不匹配或 schema 验证失败时拒绝生成更强结论；
- V3.3 gate、约 100-crate pilot 与新 sealed holdout 尚未完成，报告不得声称已通过。

## 代码、契约与测试入口

- 代码：[`crates/bw-cli/src/commands/build_lifecycle_graph_v3.rs`](../../crates/bw-cli/src/commands/build_lifecycle_graph_v3.rs)、[`crates/bw-cli/src/commands/rank_lifecycle_v2.rs`](../../crates/bw-cli/src/commands/rank_lifecycle_v2.rs)、[`crates/bw-cli/src/commands/build_witness_plan.rs`](../../crates/bw-cli/src/commands/build_witness_plan.rs)、[`crates/bw-cli/src/commands/reveal_static_ranking.rs`](../../crates/bw-cli/src/commands/reveal_static_ranking.rs)。
- Schema/Contract：[`schemas/v3-2-6/ranked-candidate-v2.schema.json`](../../schemas/v3-2-6/ranked-candidate-v2.schema.json)、[`schemas/v3-2-6/witness-plan.schema.json`](../../schemas/v3-2-6/witness-plan.schema.json)、[`schemas/v3-2-5/static-ranking-reveal.schema.json`](../../schemas/v3-2-5/static-ranking-reveal.schema.json)、[`contracts/callback-retention/contract.toml`](../../contracts/callback-retention/contract.toml)。
- 测试：[`crates/bw-cli/tests/cli.rs`](../../crates/bw-cli/tests/cli.rs)、[`crates/bw-cli/tests/lifecycle_v326_cli.rs`](../../crates/bw-cli/tests/lifecycle_v326_cli.rs)、[`crates/bw-model/tests/lifecycle_v326.rs`](../../crates/bw-model/tests/lifecycle_v326.rs)、[`crates/bw-model/tests/static_ranking_reveal.rs`](../../crates/bw-model/tests/static_ranking_reveal.rs)、[`crates/bw-blind-runner/tests/runner.rs`](../../crates/bw-blind-runner/tests/runner.rs)。

动态结论的边界见[动态验证](dynamic-validation.md)。
