# BoundaryWitness

## 项目简介

BoundaryWitness 是面向 Rust-C 生命周期边界的可审计分析与验证工程。它从源码、MIR、Contract 和运行事件中提取中性证据，组织 candidate-scoped 对象链、排序和 witness plan，并为受控动态验证提供可回查输入。

项目当前定位是 **V3.2.x core-effect hardening**。公开仓库用于保存源码、Schema、Contract、小型 fixtures、公开实验配置和正式文档；大型数据、sealed holdout、私有 run 和未披露候选不进入 Git。

## 当前状态

V3.3 gate 未通过。当前工作树中的静态主链、proof-layer split、opaque handle identity、returned-borrow exact claimant、runtime/oracle/fuzz observer 基础均处于 `Implemented` 或局部实现状态；仓库内尚无与当前迁移 commit、完整数据 manifest、Contract/config checksum 和 run receipt 对齐的新增 `Verified` 结论。

最新状态以 [current status](docs/project/current-status.md) 为准；术语含义见 [terminology](docs/project/terminology.md)。

## 能力与非目标

BoundaryWitness 当前能定位 Rust-C 边界，生成生命周期敏感候选，提取 compiler/static facts，构建 graph-v3 proof layers，执行 ranking/pair comparison，并为动态验证生成 witness plan。

它当前不承诺通用 0-day 自动发现、静态候选直接确认漏洞、任意深度全程序 points-to、任意候选自动 harness、可利用性评估或 V3.3 已通过。范围边界见 [scope and boundaries](docs/project/scope-and-boundaries.md)。

## 工作原理

端到端链路：

```text
source / fixture
  -> boundary index + candidate
  -> bw-rustc static facts + MIR coverage
  -> Schema / Contract validation
  -> lifecycle evidence + facts + coverage
  -> ObjectFlow graph-v3 + proof layers
  -> ranking + witness plan
  -> runtime / oracle / experiment evidence
  -> report or reveal summary
```

事实和结论分层解释：candidate 不是 finding，static risk chain 不是 dynamic witness，ground truth 只在运行后 reveal。系统架构见 [system overview](docs/architecture/system-overview.md)。

## 核心组件

| 组件 | 职责 |
| --- | --- |
| `bw-model` | 版本化事实、证据、Contract 与 Schema 数据模型 |
| `bw-oracle` | 生命周期状态机、规则、归一化和 finding diff |
| `bw-runtime` | 运行时事件、对象 epoch、callback token 和 trace sink |
| `bw-cli` | `bw` 命令行入口及静态/实验流水线命令 |
| `bw-experiment` | D0/D1/D2 运行目录、manifest、校验和、runner 和汇总 |
| `bw-fuzz-observer` | D2 contract-state feedback observer |
| `bw-blind-model` | 匿名 N-day public pack、policy、observation 和 receipt 模型 |
| `bw-blind-curator` | curator-only pack、ground truth、reveal 和 gate decision |
| `bw-blind-runner` | 匿名 pack 审计、隔离执行、输出扫描和 provenance |
| `bw-rusqlite-v3-adapter` | rusqlite 匿名 N-day observation adapter |
| `bw-v3-nday-adapter` | 通用 V3 N-day observation adapter |
| `compiler/bw-rustc` | 基于 rustc_private/MIR 的静态事实和 ObjectFlow 提取 |

详细目录职责见 [repository layout](docs/development/repository-layout.md)。

## 仓库结构

| 路径 | 内容 |
| --- | --- |
| `crates/` | 11 个 workspace crate |
| `compiler/bw-rustc/` | rustc_private/MIR compiler wrapper |
| `contracts/` | callback-retention Contract 与 API maps |
| `schemas/` | 版本化 JSON Schema |
| `fixtures/` | 小型 fixtures 与 expected outputs |
| `benchmarks/` | 公开历史样本和 compiler fixtures |
| `experiments/` | 公开实验配置、schema、safe corpus 和工具 |
| `tools/` | 工程、部署和实验脚本 |
| `infra/` | 容器与运行环境定义 |
| `tests/` | 跨 crate、容器和部署 smoke 测试 |
| `docs/` | 项目、架构、实验、开发、路线图和决策文档 |

## 快速开始

```bash
rustup toolchain install 1.97.0 --component clippy --component rustfmt
cargo check --workspace --locked
cargo run -p bw-cli --bin bw --locked -- --help
```

compiler wrapper 使用独立工具链：

```bash
(cd compiler/bw-rustc && cargo check --locked)
```

安装细节见 [setup](docs/development/setup.md)，CLI 见 [CLI reference](docs/reference/cli.md)。

## 测试分层

PR 层运行格式、workspace check、核心 crate 测试和相关 compiler 测试；VPS smoke 验证部署链；本地或受控环境执行 public regression、D0/D1/D2 formal、约 100 crate pilot 和 sealed holdout。

`cargo test -p bw-experiment --locked` 可用公开 fixtures 运行组件测试；这仍不等于当前 commit 上已经完成 D0/D1/D2 formal 或 public regression。测试策略见 [testing strategy](docs/development/testing-strategy.md)。

## 数据与复现

正式结果必须绑定 `code_commit + toolchain + contract_hash + schema_version + dataset_version/hash + config_hash + run_id`。公开文档使用逻辑 artifact ID、dataset ID、run ID 和 SHA-256，不写本机或服务器绝对路径。

数据边界见 [repository and data governance](docs/project/repository-and-data-governance.md)，对齐规则见 [data alignment](docs/experiments/data-alignment.md)。

## 文档导航

完整导航见 [docs README](docs/README.md)。常用入口：

- [project overview](docs/project/overview.md)
- [current status](docs/project/current-status.md)
- [system overview](docs/architecture/system-overview.md)
- [methodology](docs/experiments/methodology.md)
- [current work](docs/roadmap/current-work.md)
- [agent handoff](docs/development/agent-handoff.md)

## 多 Agent 协作

Agent 接手前按固定阅读顺序读取正式文档，先固定接口，再实现生产者和消费者。并行工作需要声明文件所有权；不得提交 prompt、对话记录、迁移清单、临时 debug 输出、大型结果或私有数据。

协作规范见 [agent handoff](docs/development/agent-handoff.md)，仓库内指令见 [AGENTS](AGENTS.md)。

## 安全材料

未披露候选、CVE 提交材料、sealed holdout 和私有 run 不进入公开仓库。安全报告和未公开材料应通过独立安全任务和私有渠道处理，公开仓库只保留通用政策和已公开结果边界。详见 [SECURITY](SECURITY.md)。

## 许可证

BoundaryWitness 使用 `MIT OR Apache-2.0` 双许可证。见 [LICENSE](LICENSE)、[LICENSE-MIT](LICENSE-MIT) 和 [LICENSE-APACHE](LICENSE-APACHE)。
