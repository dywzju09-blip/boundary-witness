# 阶段 6（部分）：重复运行确定性、attrition waterfall 初版与全量回归

- 日期：2026-08-10
- 执行计划：[execution plan](../../roadmap/execution-plan.md) 阶段 6 验收第 3/6 条
- 状态：**阶段 6 未完成**（Gate A1 与 Gate B 最小线需要维护者决策与新目标，见 §4）。
  本文记录已完成的部分验收项。

## 1. 重复运行确定性（验收第 6 条的一部分）

vulnerable harness（rusqlite 0.26.1，ASan 构建）连续运行 5 次：

| run | exit | heap-use-after-free 标记数 |
| --- | --- | --- |
| 1–5 | 全部 1（ASan abort） | 全部 2 |

日志：远端 `<results-root>/stage6/asan-run-1..5.log`。**5/5 全部触发**，缺陷报告
逐次可复现。对照（owned/unregister/no-trigger）同样各 1 次干净（5.5 记录）。

## 2. attrition waterfall 初版（rusqlite 0.26.1 单目标，--all-features）

[research thesis §7.3] 要求的逐级集合，第一次有了真实数字：

| 级 | 数量 | 流失原因 |
| --- | --- | --- |
| eligible hand-off population | 50 | — |
| statically decided | 17 装配成契约 | 33 gap：foreign_symbol_unresolved ×26、safe_entry_lineage_unresolved ×20（可重叠） |
| supported candidates（SupportedIncompatibility） | **0** | Q3 降级 → 全部 InsufficientEvidence + 义务 |
| witness attempted | 1（update_hook，EstablishLateInvoke 义务） | 其余契约无外部 role map |
| witness generated | 1（可编译 safe-only 客户端） | — |
| witness executed | 1 | — |
| independently confirmed | **1**（ASan heap-use-after-free，5/5） | — |

注意：**supported candidates = 0 但 independently confirmed = 1**——反证消费的是
`InsufficientEvidence + EstablishLateInvoke` 义务（thesis §2.7 第二条纪律），不是
只消费不相容判定。这是流水线设计的预期行为，不是数字矛盾。

## 3. 全量回归

bw-model（14 组）、bw-cli、bw-rustc 全部测试通过，无失败。5.2–5.5 的代码改动
（compiler 判据两处、生成器重写、bridge 拆分、fixture 新增）无回归。

## 4. 阶段 6 未完成的部分（需要外部决策，不在本次范围）

| 验收项 | 状态 | 缺什么 |
| --- | --- | --- |
| 四个 matched fixture 全量重跑 | ⬜ | fixture 级端到端（Gate R 验收）未在本次重跑；stage4 已有记录但需当前 commit 对齐 |
| Gate A1（Full vs Rust-only） | ⬜ | 同一 candidate universe 上的消融运行，判据需预注册（维护者） |
| Gate B 最小线（unseen 目标） | ⬜ | 需要一个未参与 adapter 开发的新目标 crate（维护者选定） |
| build mismatch / IR 缺失负向测试 | ⬜ | 人为制造失败的分类验证 |
| receipt 打包 | ⬜ | 正式 receipt 格式与重放脚本 |

## 5. 这一步证明了什么，没证明什么

**证明了**：

- 缺陷触发是确定性的：5/5 次 ASan 报告一致；
- 全量回归在当前 commit 上全绿；
- 真实目标的 attrition waterfall 第一版数字可用，且 supported=0 / confirmed=1 的
  组合是义务消费机制的正常结果。

**没证明**：

- **阶段 6 完成。** Gate A1/B、fixture 全量重跑、负向测试与 receipt 未做；
- **任何精度数字。** waterfall 是单目标、开发对象的数字，不进论文主表；
- **Q4′ / Q3 的缺口没有变。** 判定层仍是 InsufficientEvidence 主导，判别力靠
  反证补齐。
