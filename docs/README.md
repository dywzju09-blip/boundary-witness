# BoundaryWitness 文档导航

本文按角色组织正式文档入口。所有状态以当前工作树、测试输出、run manifest 和正式文档为准。

## 新 Agent

1. [研究主线与创新点](project/research-thesis.md)（方向权威）
1. [项目概览](project/overview.md)
2. [当前状态](project/current-status.md)
3. [范围与边界](project/scope-and-boundaries.md)
4. [系统架构](architecture/system-overview.md)
5. [生命周期 ObjectFlow](architecture/lifecycle-object-flow.md)
6. [实验方法](experiments/methodology.md)
7. [当前工作](roadmap/current-work.md)
8. [Agent 接力规范](development/agent-handoff.md)

## 开发者

1. [安装](development/setup.md)
2. [仓库结构](development/repository-layout.md)
3. [测试策略](development/testing-strategy.md)
4. [CLI 参考](reference/cli.md)
5. [Schema 索引](reference/schema-index.md)
6. [Contract 索引](reference/contract-index.md)
7. [发布与版本](development/release-and-versioning.md)
8. [贡献规范](../CONTRIBUTING.md)

## 实验执行者

1. [实验方法](experiments/methodology.md)
2. [数据对齐](experiments/data-alignment.md)
3. [D0 runbook](experiments/runbooks/d0.md)
4. [D1 runbook](experiments/runbooks/d1.md)
5. [D2 runbook](experiments/runbooks/d2.md)
6. [Public regression runbook](experiments/runbooks/public-regression.md)
7. [Sealed holdout runbook](experiments/runbooks/sealed-holdout.md)
8. [历史结果索引](experiments/results/README.md)
9. [VPS 与本地工作流](development/vps-local-workflow.md)

## 审查者

1. [证据模型](architecture/evidence-model.md)
2. [编译器分析](architecture/compiler-analysis.md)
3. [Contract 与 Schema](architecture/contracts-and-schemas.md)
4. [动态验证](architecture/dynamic-validation.md)
5. [排序与报告](architecture/ranking-and-reporting.md)
6. [错误分类](reference/error-taxonomy.md)
7. [事件格式](reference/event-formats.md)
8. [里程碑 gate](roadmap/milestone-gates.md)
9. [ADR 索引](decisions/README.md)

## 项目与治理

- [仓库与数据治理](project/repository-and-data-governance.md)
- [术语](project/terminology.md)
- [Roadmap](roadmap/roadmap.md)
- [SECURITY](../SECURITY.md)
- [AGENTS](../AGENTS.md)

## 案例

- [案例索引](case-studies/README.md)
- [rusqlite callback lifecycle](case-studies/rusqlite-callback-lifecycle.md)
- [OpenSSL lifetime](case-studies/openssl-lifetime.md)

## 历史结果

- [D1 structured search](experiments/results/d1-structured-search-2026-07-19.md)
- [D2 small comparison](experiments/results/d2-small-comparison-2026-07-20.md)
- [rusqlite M12 blind gate](experiments/results/rusqlite-m12-blind-gate-2026-07-20.md)
- [V3.1 N-day gate](experiments/results/v3-1-nday-gate-2026-07-20.md)
- [V3.2 20-crate pilot](experiments/results/v3-2-20-crate-pilot-2026-07-21.md)
- [V3.2.5 public blind smoke](experiments/results/v3-2-5-nday-blind-smoke-2026-07-21.md)

## 决策记录

- [ADR-0001: Repository and data separation](decisions/ADR-0001-repository-and-data-separation.md)
- [ADR-0002: Layered object-chain evidence](decisions/ADR-0002-layered-object-chain-evidence.md)
