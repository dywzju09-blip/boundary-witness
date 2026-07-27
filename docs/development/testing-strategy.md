# 测试策略

BoundaryWitness 的测试按风险和运行成本分层。测试通过只能支撑对应层级的 `Implemented` 或运行证据，不能自动升级为 V3.3 或漏洞确认。

## PR 必跑

PR 至少运行与修改范围匹配的快速检查：

```bash
cargo fmt --all --check
cargo test -p bw-model --locked
cargo test -p bw-cli --locked
cargo test -p bw-runtime --locked
cargo test -p bw-oracle --locked
cargo test -p bw-fuzz-observer --locked
```

涉及 compiler wrapper 时增加：

```bash
cargo test --manifest-path compiler/bw-rustc/Cargo.toml --locked
```

涉及 Schema、Contract、CLI 输出或文档时，还要验证对应 fixture、`bw validate`/`--help` 和文档链接。

## VPS smoke

VPS smoke 用于验证部署链，而不是 formal result：

- 拉取 PR 分支或精确 commit；
- 使用仓库锁文件安装工具链和依赖；
- 运行小规模 `cargo check`、CLI help、validator 和容器 smoke；
- 生成简短摘要、commit、命令、退出码和失败类；
- 不同步大型 corpus、sealed holdout 或私有 run artifact。

VPS 结果只能说明目标环境可构建/可执行，不能替代本地或受控环境的大预算运行。

## 本地与受控大规模验证

大规模验证用于形成正式工程或实验结论，必须绑定：

- `code_commit` 与 clean worktree；
- `rust-toolchain.toml`、Cargo.lock、container image digest；
- Contract/API map hash、Schema version、dataset version/hash、config hash；
- `run_id`、manifest、stdout/stderr、checksums 和 cleanup receipt。

public regression、约 100 crate pilot 和 sealed holdout 都属于该层。结果写入 `docs/experiments/results/` 前必须满足 [data-alignment](../experiments/data-alignment.md)。

## 已知测试边界

`bw-experiment` 完整测试当前为 `Blocked`，因为 ASan parser fixture 未进入公开仓库。不得删除测试、跳过测试、放宽 validator 或把该阻塞解释为方法阴性。补齐 fixture 后应重新运行并更新 [current-status](../project/current-status.md)。
