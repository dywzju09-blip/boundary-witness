# `bw` CLI reference

本页由当前 `cargo run -p bw-cli --bin bw --locked -- --help` 及各子命令 `--help` 核对。统一调用形式：

```bash
cargo run -p bw-cli --bin bw --locked -- COMMAND
```

## 通用退出码

| code | 含义 |
| ---: | --- |
| 0 | 成功且无 error finding |
| 1 | 命令成功完成并产生 finding |
| 2 | 参数、I/O、Schema、Contract 或输入验证错误 |
| 3 | 内部错误 |

错误详情写 stderr，并使用稳定 `BW-*` code；机器输出写 stdout。

## 验证与 oracle

### `validate`

```bash
bw validate --kind KIND [--max-line-bytes BYTES] PATH
```

支持：`static`、`trace`、`contract`、`finding`、全部 V3.2、V3.2.5、V3.2.6、V3.2.7 pair delta 和 V3.3 scanner-freeze kinds。完整 kind 列表以 `bw validate --help` 为准。默认单行上限为 1,048,576 bytes。

### `analyze`

```bash
bw analyze --static STATIC_FACTS --contract CONTRACT --trace TRACE [--output OUTPUT]
```

校验并融合 static facts、callback-retention Contract 和 runtime trace；finding 通过退出码 1 与输出记录表达。

### `diff`

```bash
bw diff \
  --baseline BASELINE_FINDINGS \
  --candidate CANDIDATE_FINDINGS \
  --baseline-trace BASELINE_TRACE \
  --candidate-trace CANDIDATE_TRACE
```

比较规范化 finding 与 trace；不是源码 diff。

## V3.2 intake 与早期流水线

| 命令 | 必需参数 | 主要输出 |
| --- | --- | --- |
| `build-precheck` | `--manifest --output --logs-root --run-id` | buildability JSONL.zst；可选 `--target --cargo --locked --timeout-seconds` |
| `index-boundaries` | `--manifest --buildability --output --logs-root --run-id` | boundary index |
| `emit-candidates` | `--boundary-index --output-dir --run-id` | candidate partitions；可选 `--static-facts --records-per-part` |
| `rank-lifecycle` | `--candidates --output-dir --run-id` | legacy V3.2 lifecycle graph/ranking |
| `account-adapter-effort` | `--ranked-candidates --output-dir --run-id` | planning-only adapter effort |
| `build-failure-taxonomy` | `--buildability --boundary-index --adapter-effort --output-dir --run-id` | incomplete/failure taxonomy |

`rank-lifecycle` 是 legacy V3.2 模板链；新 core-effect 解释使用 graph-v3/ranking-v2。

## V3.2.x core-effect 流水线

| 命令 | 必需参数 | 可选/边界 |
| --- | --- | --- |
| `extract-static-facts` | `--manifest --output-dir --logs-root --run-id --rustc-wrapper` | `--rustc --python --cargo --locked --feature-profile --all-features --no-default-features --features --timeout-seconds` |
| `extract-lifecycle-evidence` | `--manifest --boundary-index --candidates --output-dir --run-id` | `--static-facts --mir-coverage`；source observation 不是自动权威对象绑定 |
| `build-lifecycle-graph-v3` | `--candidates --evidence --output-dir --run-id` | 可加 `--facts --static-facts --contracts --registry-manifest`；权威 provenance 缺失时保留 incomplete |
| `rank-lifecycle-v2` | `--features --output-dir --run-id` | `--graph-dir` 默认 `graphs` |
| `build-witness-plan` | `--ranked-candidates --graphs-dir --output-dir --run-id` | `--limit` 默认 10；只生成 plan，不执行 harness |
| `compare-anonymous-pairs` | `--features --candidates --pair-manifest --output-dir --run-id` | 可加 `--coverage`；当前 producer 写 V3.2.7 candidate-aligned pair delta |

## Contract registry

```bash
bw materialize-lifecycle-contracts \
  --contract-toml contracts/callback-retention/contract.toml \
  --api-map-toml contracts/callback-retention/rusqlite-api-map.toml \
  --run-id "${BW_RUN_ID:?}" \
  --component-id rusqlite \
  --output-dir "${BW_CONTRACT_OUTPUT:?}"

bw audit-lifecycle-contracts \
  --contracts "${BW_CONTRACT_OUTPUT:?}" \
  --output-dir "${BW_CONTRACT_AUDIT_OUTPUT:?}" \
  --run-id "${BW_RUN_ID:?}"
```

`materialize-lifecycle-contracts` 的 `--api-map-toml` 参数可重复；`audit-lifecycle-contracts` 可选 `--registry-manifest`。API map 角色见 [Contract index](contract-index.md)。

## Freeze、reveal 与完整性

### `reveal-static-ranking`

```bash
bw reveal-static-ranking \
  --ranked-candidates "${BW_RANKED_ARTIFACT:?}" \
  --ground-truth "${BW_CURATOR_INPUT:?}" \
  --expected-ranked-sha256 "${BW_RANKED_SHA256:?}" \
  --output-dir "${BW_REVEAL_OUTPUT:?}" \
  --run-id "${BW_RUN_ID:?}"
```

可选 `--buildability`、`--boundary-index`、`--top-k`、`--control-false-positive-min-score` 与 curator-only match detail。该命令必须在 freeze 后由 curator 执行；CLI 存在不表示 gate 已运行。

### `verify-run`

```bash
bw verify-run --run-dir "${BW_RUN_DIR:?}" [--checksums checksums.sha256]
```

它校验相对路径、SHA-256、symlink、漏列和额外文件。不要与 `bw-experiment` 包中的历史 `bw-verify-run FINAL_RUN_DIRECTORY` 混淆。

V3.3 freeze 目前只有 `validate --kind v3-3-scanner-freeze`，没有生成完整 gate 的单一 CLI。当前最新 public regression 与 holdout gate 均未执行。
