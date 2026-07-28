# VPS、GitHub 与本地工作流

本流程把快速远端 smoke 与本地大规模验证分开。VPS 不保存或同步大型数据，只验证分支能在干净环境中构建和执行小入口。

## VPS 拉分支与小测试

1. 从 GitHub 拉取 PR 分支或指定 commit。
2. 确认 `git status --short` 为空，记录 `git rev-parse HEAD`。
3. 安装根 [`rust-toolchain.toml`](../../rust-toolchain.toml) 指定工具链。
4. 运行小测试：

```bash
cargo fmt --all --check
cargo check --workspace --locked
cargo run -p bw-cli --bin bw --locked -- --help
cargo test -p bw-model --locked
```

涉及容器或部署时运行 `tests/containers/`、`tests/deploy/` 下的 smoke 脚本。失败必须按 [error taxonomy](../reference/error-taxonomy.md) 分类。

## 部署归档 profile

[`tools/deploy/create-archive.sh`](../../tools/deploy/create-archive.sh) 只打包当前 commit 的已跟踪文件，并由 [`verify-archive.sh`](../../tools/deploy/verify-archive.sh) 按同一份策略校验。三个 profile 的差异如下。

| profile | 用途 | 额外排除 |
| --- | --- | --- |
| `full-experiment` | 本地或受控环境执行大规模验证 | 无 |
| `staging-builder` | 远端构建与小规模 smoke | `experiments/ground-truth/` |
| `blind-runtime` | sealed holdout runner | `experiments/ground-truth/`、`benchmarks/historical-cves/`、`experiments/schemas/`、`fixtures/`，并执行 forbidden token 扫描 |

所有 profile 一律不打包 `docs/`、`experiments/artifacts/`、`target/`、`runs/` 和 `scratch/`。运行实验的机器不放文档：文档只保留在 Git 仓库与 GitHub 上，失败分类等参考内容在提交结果时对照仓库查阅，不随归档下发。

`schemas/` 会随 `full-experiment` 与 `staging-builder` 下发，因为 `bw-model` 的 Schema 测试在运行时按相对路径读取该目录。

### blind-runtime forbidden token 扫描

`blind-runtime` 归档禁止出现可能泄漏样本身份或答案的路径 token，包括 `vulnerable`、`fixed`、`ground-truth`、`ground_truth`、`cve-`、`ghsa-`、`advisory`、`poc`、`proof-of-concept`、`expected-result` 和 `expected_result`。

**例外：JSON Schema 文件名不参与该扫描。** JSON Schema 只声明记录的字段结构，不含样本身份、标签、逐样本 detail 或预期结果，因此 `schemas/v3-2-5/private-ground-truth.schema.json` 这类文件允许下发。

该例外只豁免**文件名本身**，不豁免所在目录：`experiments/ground-truth/x.schema.json` 仍会被拒绝，因为目录名仍参与扫描。扫描规则在 `create-archive.sh` 与 `verify-archive.sh` 中各实现一次且必须保持一致；[`tests/deploy/archive-policy.sh`](../../tests/deploy/archive-policy.sh) 会用真实仓库同时验证例外生效与答案目录仍被排除。

## VPS 推 PR

VPS 可推送代码、文档、Schema、Contract、小 fixtures 和测试修改。不得推送：

- `target/`、cache、logs、run outputs；
- 大型 corpus、private results、sealed holdout；
- prompt、对话记录、迁移清单或临时 debug 脚本；
- 未披露候选、CVE 提交材料或私有路径。

PR 描述必须包含 commit、命令、结果摘要、未运行项和已知阻塞。

## 本地拉精确 commit 与校验 manifest

本地或受控服务器执行大测试时，应拉取 PR 的精确 commit：

```bash
git fetch origin
git checkout <commit>
git status --short
```

运行前校验 dataset manifest、config hash、Contract/API map hash、Schema version 和 toolchain。正式 run 必须创建新的 `run_id`，不得覆盖历史 artifact。

## 本地大测试

大测试包括完整 public regression、D0/D1/D2 formal、约 100 crate pilot 或 sealed holdout。每次运行保存：

- run manifest、配置和 checksum；
- stdout/stderr、日志、失败分类和 cleanup receipt；
- finalized artifact ID；
- 与当前 commit 对齐的结果摘要。

摘要回写到 PR 或正式结果文档时，只写逻辑 artifact ID、hash、run ID 和结论边界，不写本机或服务器绝对路径。

## 结果回写规则

- 小测试失败：回写命令、退出码、错误类和最小复现步骤。
- 大测试失败：保留失败 artifact，说明是 infrastructure、coverage gap、integrity failure 还是 method negative。
- 大测试通过：只有满足 [data-alignment](../experiments/data-alignment.md) 才能新增正式结果文档。
- sealed holdout：公开仓库只写聚合摘要和不可逆 hash；样本身份、ground truth、逐样本 match detail 和结果路径不进入 Git。
