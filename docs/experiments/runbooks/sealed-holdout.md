# Sealed holdout runbook

## 目的与当前状态

Sealed holdout 用一次性、未参与设计的数据检验冻结方法的泛化。**当前目标仓库的最新 gate 未执行**：public regression 尚未形成当前 commit 的 formal 记录，holdout corpus 也未完成可公开验证的 freeze。状态为 **Blocked**；V3.3 gate 未通过。

数据清单、样本身份映射、ground truth、逐样本 match detail、runner 结果和 reveal 结果均不进入公开仓库。公开仓库只可保存协议、Schema、无身份聚合摘要与不可逆 hash。

## 输入

- curator 持有的未揭示 dataset；
- runner 可见的匿名 pack，只有 case ID、允许公开的 build/source artifact 与 adapter 入口；
- 冻结的 `code_commit`、compiler/toolchain、Contract/API maps、feature/ranking policy、阈值和 dataset manifest hash；
- container isolation、install/runner receipt 和新 `run_id`。

## 禁止输入

scanner/runner 不得接收身份、角色、预期 pattern、advisory、修复差分、PoC 或 reveal 输出。不得在 public regression 未通过时启动 holdout；不得在 reveal 后调参并把同一数据继续称为 holdout。

## 前置检查

1. 当前 commit 的 public regression 已通过全部预注册 gate；当前此条件未满足。
2. scanner freeze 完整绑定 source identity、Cargo.lock、toolchain、Contract/API map、feature profile、threshold、token scan、dataset hash 和 ranked-output 预期 hash。
3. runner 使用受信 container isolation；native smoke receipt 不允许 formal reveal。
4. curator 与 runner 存储、凭据和日志分离；公开仓库中没有 holdout manifest 或结果目录。

## 精确命令入口与阻塞边界

当前 `bw` CLI 只提供 freeze record 校验和已冻结 ranking 的 reveal primitive，没有生成 pack、执行全 pipeline、签署 receipt、freeze、reveal 与 gate decision 的单一 `tools/experiment/` orchestrator。因此完整 gate 命令为 **Planned/Blocked**，不得编造。

公开侧只能验证无身份 freeze record 和 finalized run：

```bash
cargo run -p bw-cli --bin bw --locked -- \
  validate --kind v3-3-scanner-freeze \
  "${BW_FREEZE_RECORD:?}"

cargo run -p bw-cli --bin bw --locked -- \
  verify-run --run-dir "${BW_RUN_DIR:?}"
```

`reveal-static-ranking` 是真实 CLI，但必须由 curator 在隔离环境中调用；公开文档不提供数据位置、receipt key 或逐样本输出命令。其参数定义见 [CLI reference](../../reference/cli.md)。上述校验并不表示 holdout 已运行。

## 输出

curator 侧保留匿名 observations、ranked hash、install/runner receipt、checksums、reveal detail 和 gate decision。可公开部分限于 dataset/ground-truth 不可逆 digest、case 数、聚合 top-k/control/pair 指标、失败类、run/commit/hash 和结论边界。

## 失败分类

`freeze_incomplete`、`identity_leak`、`untrusted_isolation`、`receipt_mismatch`、`checksum_failure`、`build_or_tool_failure`、`ranking_miss`、`control_failure`、`pair_insufficient_evidence` 与 `reveal_policy_failure`。未运行或 incomplete 不计为 negative。

## 结果归档

一次 reveal 后 dataset 永久转为 revealed regression data。公开摘要不得包含数据清单、逐样本身份或结果路径；内部 evidence catalog 用 artifact ID 和 hash 保持 lineage。

## 清理

取消/失败时停止 runner，销毁临时容器、挂载副本和短期 receipt secret，记录 cleanup receipt；保留不可变日志与失败证据。任何可能暴露数据身份的本地临时文件都不进入 Git。
