# Public regression runbook

## 目的与当前状态

Public regression 使用已揭示、可公开审计的数据检查当前 core-effect hardening 是否退化。**当前目标仓库的最新 gate 未执行**：没有与当前 commit、完整 public dataset manifest、Contract/config hash 和 checksums 对齐的 formal 结果。状态为 **Blocked**，不能沿用历史 smoke 指标标记 `Verified`。

## 输入

- 已公开且已揭示的匿名 corpus manifest 与 materialized sources；
- buildability、boundary、candidate 与 pair manifest；
- 当前 `bw` CLI、`compiler/bw-rustc`、callback-retention Contract/API maps；
- feature profile、ranking policy、dataset/config/Contract hash 与新 `run_id`。

## 禁止输入

不允许 curator 身份映射参与 scanner；不允许以历史 ranked artifact 代替当前运行；不允许修改公开数据后保留旧 dataset hash；不允许将 candidate/rank 解释成 finding。

## 前置检查

1. 当前 commit clean，compiler wrapper 与 `bw --help` 已核对。
2. public corpus 的每个 source_ref 已物化；dataset manifest 与 checksum 可验证。
3. callback-retention Contract/API maps 已 materialize 并审计。
4. `bw-experiment` 全量测试目前因缺少两个 ASan parser fixture 而 Blocked；约 100-crate pilot 和统一 regression orchestrator 也尚未提供。

## 精确命令入口与阻塞边界

当前仓库有可执行的逐阶段 CLI：`build-precheck`、`index-boundaries`、`emit-candidates`、`extract-static-facts`、`extract-lifecycle-evidence`、`materialize-lifecycle-contracts`、`audit-lifecycle-contracts`、`build-lifecycle-graph-v3`、`rank-lifecycle-v2`、`compare-anonymous-pairs`、`reveal-static-ranking`、`verify-run`。参数以 [CLI reference](../../reference/cli.md) 的已核对 `--help` 为准。

仓库**没有**把这些步骤、freeze、checksum、负对照 gate 和回归判定串成一次 formal run 的 `tools/experiment/` 入口。因此完整 public regression 命令为 **Planned/Blocked**；本 runbook 不把一串人工命令伪装成已验收 orchestrator。现有 artifact 的单项检查可使用：

```bash
cargo run -p bw-cli --bin bw --locked -- \
  validate --kind v3-2-6-ranked-candidate \
  "${BW_RANKED_ARTIFACT:?}"

cargo run -p bw-cli --bin bw --locked -- \
  validate --kind v3-2-7-pair-delta \
  "${BW_PAIR_DELTA_ARTIFACT:?}"

cargo run -p bw-cli --bin bw --locked -- \
  verify-run --run-dir "${BW_RUN_DIR:?}"
```

这些命令只验证给定 artifact，不执行最新 gate。

## 输出

完整 gate 未来必须输出 run manifest、static/MIR coverage、contracts audit、graph/ranking/pair delta、聚合 reveal、失败 taxonomy 和 checksums；同时记录 top-k、paired-control clean、separable/insufficient evidence、coverage 缺口和 gate decision。

## 失败分类

`build_failure`、`compiler_coverage_gap`、`contract_gap`、`object_binding_gap`、`ranking_miss`、`control_false_positive`、`pair_insufficient_evidence`、`integrity_failure` 和 `orchestration_blocked` 分开统计。任何一类都不能改写成安全结论。

## 结果归档

只有当前 commit 上的完整 run 通过 checksum、公开敏感标识扫描和预注册 gate 后才能发布新结果；历史记录继续标为 historical，不升级当前状态。

## 清理

删除构建 cache、临时解压源和中间未登记副本；保留失败日志、coverage gap、checksums 和 finalized artifact ID。已揭示数据保持 public regression 身份，不回收为 holdout。
