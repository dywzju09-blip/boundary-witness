# 当前工作

本文只记录当前所处阶段与下一步，不保存 Agent prompt 或逐日执行过程。阶段定义见 [roadmap](roadmap.md)，方向权威见 [research thesis](../project/research-thesis.md)。状态词含义见 [terminology](../project/terminology.md)。

## 所处位置

**P3 持有期维度的 Rust 侧已闭环，外部侧仍是推断而非证据。P0 与 P2 均未开始。**

持有期这一维现在可以走完「从签名读出契约 → 与外部边界事实关联 → 把判定与判定来源写入产物」整条链。但外部侧那一半的证据来自 API 清单分类出的注册与注销事实，不是外部代码本身的行为。因此：

- **N1 尚未成立**：两侧事实还不是真正的两侧
- **N2 尚未成立**：清单仍是必需输入，消融实验无法进行
- **N3 尚未开始**

## 下一步

按 [roadmap](roadmap.md) 的关键路径，**P0 与 P2 并行起步**。

### P0 边界事实模型二元化

| 字段 | 内容 |
| --- | --- |
| 服务创新点 | N1 |
| 状态 | `Planned` |
| 前置 | 无 |
| 代码入口 | `crates/bw-model/src/static_fact.rs`、`crates/bw-model/src/lifecycle_v326.rs`、`compiler/bw-rustc/src/domain.rs` |
| 测试入口 | `crates/bw-model/tests/lifecycle_v326.rs`、`crates/bw-model/tests/schema_roundtrip.rs` |
| 完成谓词 | 两侧事实可在不依赖候选切分的前提下联结；`hand_off_id` 取 `(crate, version, foreign_symbol, call_site)` |
| 风险 | 低，但必须一次做对，后续每一维都挂在这个键上 |

### P2 外部侧有界分析

| 字段 | 内容 |
| --- | --- |
| 服务创新点 | N1 的前提 |
| 状态 | `Planned` |
| 前置 | 无，可与 P0 并行 |
| 范围 | 先只支持外部 C 源码随构建提供的 crate；先只做 Q1 逃逸与 Q3 调用/存储 |
| 完成谓词 | 单一库上端到端产出可回查的逃逸证据；查不出逃逸时记缺证而非判安全 |
| 风险 | 高，全路线最大不确定性。若两三周内看不到端到端结果，贡献结构需重新设计 |

## 待决

~~跑 Yuga 作为地基验证~~ **已于 2026-07-31 完成，结论是反例**：Yuga 能报出主线缺陷类的 5/7，原立论被否定，N1 已重定位为「判别」。见 [Gate 0 结果](../experiments/results/gate0-baseline-comparison-2026-07-31.md) 与 [误报归因](../experiments/results/gate0-yuga-precision-triage-2026-07-31.md)。

**现在的待决是规模**：单 crate 数据不构成证据，需扩大到 10–20 个未参与开发的 FFI crate。步骤见 [规模化精度对照 runbook](../experiments/runbooks/precision-comparison-at-scale.md)。**该实验优先级高于任何代码工作**——它决定精度方向是否成立。

## 已知未收口项

不阻塞关键路径，但影响评估质量。

| 项 | 影响 |
| --- | --- |
| 排名未把可绑定的注册候选排进默认输出上限 | 默认扫描看不到判定结果，每次都要手动放宽上限 |
| 保护性特征仍依赖源码文本匹配 | 同类候选内部排序不可靠 |
| n-day 度量仪器只接入了单一库 | 召回率数字不具代表性 |
| 跨函数对象流只覆盖有限形状 | 重入维度（P5）的前置 |
| release/use ordering 中 unregister-before-drop 与 conditional release gap 未分开报告 | 需在 release-proof 层新增事实种类，不能靠扩展 ordering 枚举解决 |

## V3.3

`Blocked`。依赖 clean method commit、公开数据集 manifest、Contract/config hash、pair gate、动态桥接与约 100 crate pilot。判据见 [milestone gates](milestone-gates.md) 与 [public regression runbook](../experiments/runbooks/public-regression.md)。准备 V3.3 设施不改变当前阶段判断。
