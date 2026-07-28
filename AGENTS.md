# AGENTS.md

本文件给 Agent 和自动化工具提供公开仓库内的工作规则。详细接力流程见 [docs/development/agent-handoff.md](docs/development/agent-handoff.md)。

## 基本规则

- 临时脚本、debug 代码、临时输出和 scratch 文件使用后立即删除。
- 新文件放入职责对应目录，不把工具、文档或数据堆在根目录。
- 存在 `Cargo.lock` 时，Cargo 命令统一使用 `--locked`。
- 不删除测试、不跳过失败测试、不放宽 validator、不降低证据链语义。
- 不提交 prompt、对话记录、迁移清单、大型 run artifact、sealed holdout、私有路径或未披露候选。

## 目录职责

- `crates/`：workspace crate。
- `compiler/bw-rustc/`：compiler wrapper，使用独立工具链和 lockfile。
- `contracts/`：Contract 与 API maps。
- `schemas/`：版本化 JSON Schema。
- `fixtures/`、`benchmarks/`、`experiments/`：小型公开 fixtures、benchmark、safe corpus、配置和 runbook 入口。
- `tools/`、`infra/`、`tests/`：长期脚本、容器和测试。
- `docs/`：正式文档。

## 源代码目录约束

源代码改动应保持模块边界清楚。跨模块接口先固定 Schema、model、Contract 或 CLI，再修改 producer/consumer。compiler、model、CLI、runtime、oracle 和 experiment 的状态边界不得用文档措辞越级。

## 测试要求

根据改动范围运行最小充分测试，并在 PR 中记录命令和结果。常见入口：

```bash
cargo fmt --all --check
cargo test -p bw-model --locked
cargo test -p bw-cli --locked
(cd compiler/bw-rustc && cargo test --locked)
```

`cargo test -p bw-experiment --locked` 只证明公开 fixture 上的组件测试；不要把它写成 D0/D1/D2 formal、public regression 或 V3.3 gate 通过。

## 状态与证据边界

`Implemented` 表示代码和测试存在；`Verified` 需要当前 commit 上与数据、配置、Contract、Schema、checksum 和 run ID 对齐的正式证据。candidate 不是 finding，static risk chain 不是 dynamic witness，历史结果不自动证明当前 commit。

## 文档入口

- [README](README.md)
- [docs README](docs/README.md)
- [current status](docs/project/current-status.md)
- [scope and boundaries](docs/project/scope-and-boundaries.md)
- [testing strategy](docs/development/testing-strategy.md)
- [current work](docs/roadmap/current-work.md)
