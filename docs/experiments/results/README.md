# 实验结果索引

本目录保存八份由运行记录支持的正式历史结果。**它们证明对应 historical commit 上发生过什么，不自动证明当前 commit 的行为，也不因为路线重写而升级为当前能力。** 当前仓库尚未执行最新 public regression 或独立 holdout gate，因此**没有任何与当前 commit 对齐的 `Verified` 结论**。

前六份产生于 2026-07-30 路线重定向**之前**，服务的是旧的实验分组（见 [methodology](../methodology.md)）；它们的设施可复用，结论不迁移。后两份是 2026-07-31 的外部基线对照。

| 日期 | 结果 | 结论边界 |
| --- | --- | --- |
| 2026-07-19 | [D1 structured search](d1-structured-search-2026-07-19.md) | native Linux 上的 30-campaign formal 与第二 API smoke；固定容器未完成。**旧路线** |
| 2026-07-20 | [D2 small comparison](d2-small-comparison-2026-07-20.md) | 三组小规模管线闭环；不支持统计优势。**旧路线** |
| 2026-07-20 | [rusqlite M12 blind gate](rusqlite-m12-blind-gate-2026-07-20.md) | 10-case 设计家族匿名 gate；不是跨项目泛化。**旧路线** |
| 2026-07-20 | [V3.1 N-day gate](v3-1-nday-gate-2026-07-20.md) | 2-case 非 rusqlite 匿名 gate；不公开样本身份。**旧路线** |
| 2026-07-21 | [V3.2 20-crate pilot](v3-2-20-crate-pilot-2026-07-21.md) | 20-crate 工程漏斗；不是约 100-crate 或动态效果结论。**旧路线** |
| 2026-07-21～24 | [V3.2.5 public blind smoke](v3-2-5-nday-blind-smoke-2026-07-21.md) | 已揭示开发语料回归；仍未通过完整 pair gate。**旧路线** |
| 2026-07-31 | [Gate 0 外部基线对照](gate0-baseline-comparison-2026-07-31.md) | Yuga 与 FFIChecker 在 rusqlite 0.26.1/0.26.2 上的对照。**n=1 且该 crate 参与过开发，不构成精度证据。** 结论是反例：Yuga 能报出主线缺陷类的 5/7，旧 N2 立论因此作废 |
| 2026-07-31 | [Gate 0 Yuga 误报归因](gate0-yuga-precision-triage-2026-07-31.md) | 13 条报告中 8 条不对应公告的逐条归因。**至少四种机制，不得表述为单一根因**；且本系统排除这 8 条只用了 Rust 侧签名形状、没有用外部证据，**不构成"外部侧信息消除了误报"的证据** |

## 解释规则

- `candidate`、top-k、static risk、`adapter_needed` 和 `exposure` 都不是 confirmed finding。
- build/coverage/deferred/integrity failure 必须保留，不能并入 negative。
- 结果中的 artifact 使用逻辑 ID；实际存储位置由 Git 外 catalog 管理。
- 新结果必须满足 [数据对齐规范](../data-alignment.md)，并按 [实验方法](../methodology.md) 区分数据角色、成功等级与证据等级。
