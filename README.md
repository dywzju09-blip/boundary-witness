# BoundaryWitness

## 项目简介

BoundaryWitness 是面向 Rust-C 生命周期边界的可审计分析与验证工程。它从源码、MIR、Contract 和运行事件中提取中性证据，组织 candidate-scoped 对象链、排序和 witness plan，并为受控动态验证提供可回查输入。

**最终目标是在 Rust 组件中自动发现未知（0-day）生命周期缺陷。** 扫描对象是 Rust 组件（crate + 版本）本身，不是使用该组件的应用——缺陷在于组件的安全 API 允许 UB，与是否已有应用踩中无关；需要具体触发实例时由 witness harness 生成。已知 n-day 在本项目中是**度量检出与证明能力的仪器**，不是交付目标。

项目当前定位是 **V3.2.x core-effect hardening**，处于通往上述目标的第一阶段：先把「已知不健全的组件能否被证明出来」做扎实。公开仓库用于保存源码、Schema、Contract、小型 fixtures、公开实验配置和正式文档；大型数据、sealed holdout、私有 run 和未披露候选不进入 Git。

## 当前状态

V3.3 gate 未通过。当前工作树中的静态主链、proof-layer split、opaque handle identity、returned-borrow exact claimant、runtime/oracle/fuzz observer 基础均处于 `Implemented` 或局部实现状态；仓库内尚无与当前迁移 commit、完整数据 manifest、Contract/config checksum 和 run receipt 对齐的新增 `Verified` 结论。

最新状态以 [current status](docs/project/current-status.md) 为准；术语含义见 [terminology](docs/project/terminology.md)。

## 研究主线

统领主张：**Rust 的全部安全价值建立在「不写 `unsafe` 的代码不可能触发 UB」之上。本项目度量这条保证在 FFI 边界上被打破的频率与形态，并对每一次打破给出只使用 safe Rust 的可执行反证。**

判定的一般形态是逐维契约错配——某一维上 Rust 侧类型允许的比外部侧实际发生的宽。当前只完整实例化**持有期**一维；别名、线程、重入、展开、释放责任、值域、初始化七维是框架的其他实例，属 future work。**八维错配不等价于安全 API 整体健全性。**

三条创新点：C1 safe-only 可执行反证合成、C2 类型契约作为规约与外部 effect 的精化检查、C3 生态级度量与新发现。方向权威是 [research thesis](docs/project/research-thesis.md)，任何实现都必须落到其中一条上。实现阶段见 [roadmap](docs/roadmap/roadmap.md)。

## 能力与非目标

当前能定位 Rust-C 边界、生成生命周期敏感候选、提取 compiler/static facts、构建 graph-v3 proof layers、执行 ranking/pair comparison，并为动态验证生成 witness plan。持有期维度可从 HIR 签名自动读出 Rust 侧契约，无需 API 清单；返回借用寿命不受约束这一类同样如此。

**外部侧行为分析尚未实现**，因此论题声称的跨语言联结尚未成立：持有期维度的外部侧证据目前由 API 清单分类推断而来。接入新组件仍必须先有人手写清单。

当前不承诺跨语言契约不相容判定已达成、通用 0-day 自动发现、静态候选直接确认漏洞、任意深度全程序 points-to、任意候选自动 harness、可利用性评估或 V3.3 已通过。前两项是路线上的目标，其余是范围之外。

以下表述已被实测否定或主动撤销，不得使用：「现有工作检不出这一缺陷类」（2026-07-31 外部基线证明 Yuga 能报 5/7）；「不需要人工 API 清单」作为创新点（同日撤销，结构化推断仍实现但只作工程属性）。逐维覆盖状态与完整的允许/禁止表述清单见 [scope and boundaries](docs/project/scope-and-boundaries.md)。

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
| `bw-v3-nday-adapter` | 匿名 N-day observation adapter；两个 bin 分别是通用形态 `bw-v3-nday-adapter` 与 rusqlite 形态 `bw-rusqlite-v3-adapter`，差别只有一组身份常量 |
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

- [research thesis](docs/project/research-thesis.md)
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
