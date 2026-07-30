# 仓库结构

本文固定公开仓库目录职责。新增文件应落在对应目录下，不把脚本、临时输出、运行结果或迁移过程材料堆在根目录。

## 一级目录

| 路径 | 职责 |
| --- | --- |
| [`crates/`](../../crates/) | Rust workspace crate，覆盖模型、CLI、runtime、oracle、实验和 blind 协议 |
| [`compiler/bw-rustc/`](../../compiler/bw-rustc/) | 基于 `rustc_private`/MIR 的静态事实和 ObjectFlow 提取 |
| [`contracts/`](../../contracts/) | 经审计 API/Contract 语义，不保存漏洞答案 |
| [`schemas/`](../../schemas/) | 公开 JSON Schema 与版本化记录协议 |
| [`fixtures/`](../../fixtures/) | 小型结构化 fixtures 和 expected outputs |
| [`benchmarks/`](../../benchmarks/) | 公开历史样本、compiler fixtures 和小型 benchmark |
| [`experiments/`](../../experiments/) | 公开实验配置、schema、safe corpus 与工具，不保存大型 run 输出 |
| [`tools/`](../../tools/) | 工程脚本、部署脚本和实验入口 |
| [`infra/`](../../infra/) | 容器与运行环境定义 |
| [`tests/`](../../tests/) | 跨 crate、容器和部署 smoke 测试 |
| [`docs/`](../../docs/) | 项目、架构、实验、开发、路线图和决策文档 |

## Workspace crate 职责

| crate | 固定职责 |
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
| `bw-v3-nday-adapter` | 匿名 N-day observation adapter。两个 bin：`bw-v3-nday-adapter`（通用）与 `bw-rusqlite-v3-adapter`（rusqlite）。两者共用同一份实现，差别仅是 `AdapterIdentity` 一组常量（公开签名域、case root 环境变量、witness schema_version）；这三个值进入 checksum 与产物，由 `tests/identity_pinning.rs` 钉死 |
| `compiler/bw-rustc` | 基于 rustc_private/MIR 的静态事实和 ObjectFlow 提取 |

## 目录约束

- 新 Schema 放入对应 `schemas/v*` 目录，并更新 [schema-index](../reference/schema-index.md)。
- 新 Contract 或 API map 放入 `contracts/callback-retention/`，并更新 [contract-index](../reference/contract-index.md)。
- 新实验脚本放入 `tools/experiment/`，并在 runbook 中标明输入、输出、失败分类和清理规则。
- 运行输出、缓存、日志和大型数据放在 Git 外 artifact catalog；公开文档只引用逻辑 artifact ID 和 hash。
