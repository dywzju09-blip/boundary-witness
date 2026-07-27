# 实验结果索引

本目录只保存六份由运行记录支持的正式历史结果。它们证明对应 historical commit 上发生过什么，不自动证明当前迁移 commit 的行为。当前仓库尚未执行最新 public regression 或独立 holdout gate，因此没有新增与当前 commit 对齐的 `Verified` 结论。

| 日期 | 结果 | 结论边界 |
| --- | --- | --- |
| 2026-07-19 | [D1 structured search](d1-structured-search-2026-07-19.md) | native Linux 上的 30-campaign formal 与第二 API smoke；固定容器未完成 |
| 2026-07-20 | [D2 small comparison](d2-small-comparison-2026-07-20.md) | 三组小规模管线闭环；不支持统计优势 |
| 2026-07-20 | [rusqlite M12 blind gate](rusqlite-m12-blind-gate-2026-07-20.md) | 10-case 设计家族匿名 gate；不是跨项目泛化 |
| 2026-07-20 | [V3.1 N-day gate](v3-1-nday-gate-2026-07-20.md) | 2-case 非 rusqlite 匿名 gate；不公开样本身份 |
| 2026-07-21 | [V3.2 20-crate pilot](v3-2-20-crate-pilot-2026-07-21.md) | 20-crate 工程漏斗；不是约 100-crate 或动态效果结论 |
| 2026-07-21～24 | [V3.2.5 public blind smoke](v3-2-5-nday-blind-smoke-2026-07-21.md) | 已揭示开发语料回归；最新历史记录仍未通过完整 pair gate |

## 解释规则

- `candidate`、top-k、static risk、`adapter_needed` 和 `exposure` 都不是 confirmed finding。
- build/coverage/deferred/integrity failure 必须保留，不能并入 negative。
- 结果中的 artifact 使用逻辑 ID；实际存储位置由 Git 外 catalog 管理。
- 新结果必须满足 [数据对齐规范](../data-alignment.md)，并按 [实验方法](../methodology.md) 区分数据角色、成功等级与证据等级。
