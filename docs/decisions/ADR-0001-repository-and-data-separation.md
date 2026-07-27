# ADR-0001: Repository and data separation

## Status

Accepted

## Context

BoundaryWitness 需要公开源码、Schema、Contract、fixtures、实验方法和历史结果，同时又必须保护大型数据、sealed holdout、私有 run、未披露候选和服务器路径。把这些材料混在一个公开仓库中会破坏 blind gate、泄漏 ground truth，并使结果无法复现到稳定数据身份。

## Decision

公开仓库只保存可公开发布和可长期维护的工程材料：

- Rust 代码、compiler wrapper、CLI、runtime、oracle、实验框架；
- Schema、Contract、API map、小型 fixtures 和公开 safe corpus；
- 正式项目、架构、实验、开发、路线图和决策文档；
- 历史结果的逻辑 run ID、artifact ID、hash 和结论边界。

大型 corpus、private results、sealed holdout、run artifact、服务器副本、迁移清单、prompt 文档和未披露候选保存在 Git 外。公开文档引用逻辑 artifact ID、dataset ID、run ID 和 SHA-256，不引用本机或服务器绝对路径。

## Consequences

- clean clone 可以构建代码、运行小测试并理解项目状态；
- 正式实验必须通过 manifest 和 checksum 对齐，而不是依赖路径；
- sealed holdout 的身份映射和逐样本 reveal 不会因公开仓库发布而泄漏；
- 新 Agent 需要通过 data index 或 artifact catalog 访问大型数据，不能假设仓库内存在完整 run。

## References

- [Repository and data governance](../project/repository-and-data-governance.md)
- [Data alignment](../experiments/data-alignment.md)
- [VPS local workflow](../development/vps-local-workflow.md)
