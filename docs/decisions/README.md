# Architecture decision records

本目录记录长期架构决策。ADR 只保存稳定决策、背景、后果和状态，不保存执行 prompt、对话或迁移过程。

| ADR | 状态 | 主题 |
| --- | --- | --- |
| [ADR-0001](ADR-0001-repository-and-data-separation.md) | Accepted | 公开仓库与私有数据分离 |
| [ADR-0002](ADR-0002-layered-object-chain-evidence.md) | Accepted | 对象链证据分层（正式层为三层） |
| [ADR-0003](ADR-0003-target-verifier-dataflow-and-identity.md) | Accepted（实现 `Planned`） | 目标判定数据流与身份分层；candidate 降为下游投影 |
| [ADR-0004](ADR-0004-joint-trace-verdict-semantics.md) | Accepted（部分 `Planned`） | 联合轨迹判定语义、正交外部证据字段、反证义务接口 |
| [ADR-0005](ADR-0005-evidence-trust-and-experiment-statistics.md) | Accepted（执行 `Planned`） | 证据信任边界、oracle admissibility、实验统计政策 |

**ADR-0003 与 ADR-0004 的实现部分受 [Gate P](../roadmap/milestone-gates.md#gate-p猎物存在性) 约束**：Gate P 判定转路线 C 时，其目标架构部分作废。决定本身仍然有效，用于记录"当时为什么这样设计"。

新增 ADR 使用递增编号，至少包含 Status、Context、Decision、Consequences 和 References。
