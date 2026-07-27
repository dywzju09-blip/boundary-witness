# Agent 接力规范

本文是新 Agent 接手 BoundaryWitness 的稳定入口。接力必须以当前工作树、代码、测试和正式文档为事实源，不以对话记忆或 prompt 为事实。

## 固定阅读顺序

1. [project overview](../project/overview.md)
2. [current status](../project/current-status.md)
3. [scope and boundaries](../project/scope-and-boundaries.md)
4. [system overview](../architecture/system-overview.md)
5. [lifecycle ObjectFlow](../architecture/lifecycle-object-flow.md)
6. [dynamic validation](../architecture/dynamic-validation.md)
7. [methodology](../experiments/methodology.md)
8. [current work](../roadmap/current-work.md)
9. 本文和 [testing strategy](testing-strategy.md)

## 事实优先级

1. 当前文件内容、git 状态、测试输出和 generated artifact checksum；
2. 正式文档中的阶段、术语和边界；
3. Issue、PR 描述和 ADR；
4. 历史实验结果文档；
5. 口头说明或旧对话。

若事实冲突，以当前工作树和可复现命令为准，并在 PR 中说明冲突。

## Issue 字段

Issue 应包含：

- 背景与目标；
- 影响的代码、Schema、Contract 或文档路径；
- 输入/输出接口；
- 状态边界：`Implemented`、`Verified`、`Planned`、`Blocked` 或 `Deprecated`；
- 测试命令与预期证据；
- 数据边界和禁止材料；
- 完成谓词。

## 分支与文件所有权

分支命名使用 `feat/area-summary`、`fix/area-summary`、`docs/area-summary` 或 `chore/area-summary`。并行 Agent 应声明文件所有权；不同 Agent 不同时编辑同一 Schema、同一 crate 模块或同一结果文档。共享接口先写 Schema、model enum、CLI 参数或 Contract，再实现生产者和消费者。

## 接口先行

涉及跨模块改动时，先固定：

- record `schema_version`、字段、unknown-field 策略和 validator；
- Contract/API map 语义和 checksum；
- CLI 参数、退出码和输出路径；
- fixture 与 expected output；
- 文档中的状态边界。

随后再改 compiler、graph、ranking、runtime 或 experiment。不得为了让测试通过而降低 validator、删除负对照或折叠证据层。

## 测试证据

接力说明必须列出实际运行命令、结果、未运行原因和剩余风险。`cargo test -p bw-experiment --locked` 的当前 ASan fixture 阻塞需要明确写出，不能省略或解释成全仓通过。

## 禁止提交

不得提交 prompt 文档、对话记录、迁移清单、临时脚本、debug 输出、未披露候选、sealed holdout 私有数据、大型 run artifact、本地绝对路径或服务器路径。临时脚本和 debug 代码使用后必须删除；需要长期保留的工具应放在 `tools/` 的合适子目录并写明用途。
