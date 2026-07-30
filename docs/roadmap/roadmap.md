# Roadmap

BoundaryWitness 的路线从 V2 的模板化生命周期候选，推进到 V3 的证据分层、ObjectFlow、动态验证和 blind gate。当前阶段固定为 **V3.2.x core-effect hardening**；V3.3 尚未通过。

## 主线

版本号（V2/V3.1/V3.2/V3.3）刻画的是工程成熟度。能力主线是另一条轴，两者不要混读：

```text
最终目标：在 Rust 组件中自动发现未知（0-day）生命周期缺陷
  ↑
阶段 B：定义点分析——不读 API map 也能识别哪些 API 的回调 bound 过松
  ↑
阶段 A（当前）：给定已知不健全的组件，能否把它证明出来
              （生成可编译、可触发的 witness；对已修复版本给出证据驱动的拒绝理由）
  ↑
仪器：n-day 数据集，用于度量阶段 A 的检出率与误报率
```

**阶段 A 与阶段 B 的分界就是 [范围与边界 §2.3](../project/scope-and-boundaries.md) 那张表**：返回借用类已有定义点自动分析，回调 bound 类仍靠人工 API map。阶段 B 的入口是照着已实现的 `unconstrained_return_lifetime_relation` 补一个回调 bound 的定义点检查。

阶段 B 的完成判据只有一条非循环的：**对已有的 n-day 正样本，在不读 API map 的前提下能重新发现其中若干条。** 在此之前，"扫描器"的说法不能用；n-day 上的检出成绩只能表述为验证能力，不能表述为发现能力。

先做扎实 A 再做 B 的理由：如果连已知有洞的组件都证明不出来，自动发现更多可疑 API 只会产出更多证明不了的候选。

## V2：基础候选与运行闭环

V2 建立了 callback-retention Contract、静态事实、runtime trace、oracle finding、D0/D1/D2 实验基础和 rusqlite 设计家族。该阶段证明受控样本上可以形成可审计闭环，但对象身份和静态链解释仍偏模板化。

## V3.1：匿名 N-day gate

V3.1 引入 blind runner/curator、匿名 pack、receipt、reveal 和 gate decision。历史结果显示小规模非 rusqlite blind gate 可以闭环；样本规模和数据角色不支持泛化结论。

## V3.2：工程化 intake 与 pilot

V3.2 把 corpus intake、buildability、boundary index、candidate partition、adapter effort 和 failure taxonomy 固定为公开 Schema。20-crate pilot 证明工程格式能运转，但不等于约 100 crate pilot 或动态效果结论。

## V3.2.x：Core-effect hardening

当前工作集中在：

- candidate-scoped lifecycle facts；
- opaque handle generation key；
- returned-borrow exact claimant；
- mutation/reassignment barrier；
- closure capture slot 与 use-side projection；
- `identity_transport`、`lifecycle_ordering`、`complete_risk_chain` 三层 proof；
- graph-v3、ranking-v2、pair delta 和 witness plan 的分层解释。

该阶段目标是减少技术失真，明确缺证原因，并为 public regression 与 V3.3 gate 准备干净方法 commit。

## V3.3：进入条件

V3.3 不是单个 Schema 目录，也不是 scanner-freeze 文件存在。进入 V3.3 需要同时满足 [milestone gates](milestone-gates.md)：

- clean method commit；
- 完整 public regression；
- ObjectFlow 与 proof-layer 回归；
- 动态 bridge 的可执行最小闭环；
- 约 100 crate 工程 pilot；
- scanner/Contract/feature/config/checksum freeze；
- 新 sealed holdout blind smoke。

未满足这些条件前，路线图允许推进基础设施、fixtures、orchestrator 和诊断运行，但项目状态仍是 V3.2.x。

## 阶段 B：定义点分析

V3.3 gate 是工程成熟度的门槛，阶段 B 是能力上的下一步，两者可以并行准备但不可互相替代。阶段 B 的内容：

1. **（已完成）** 照 [`unconstrained_return_lifetime_relation`](../../compiler/bw-rustc/src/rustc_api/mir.rs) 的形式，新增从 HIR 签名判断「回调参数的生命周期 bound 是否绑在函数声明的 lifetime 而非 `'static`」的检查。产出 `callback_lifetime_bound` 静态事实，四个取值（`declared_receiver_lifetime` / `declared_free_lifetime` / `static_lifetime` / `no_lifetime_bound`）覆盖健全与不健全两侧——缺证与「已检查且健全」必须可区分；
2. **（已完成）** 输出是**候选 API 列表**，不是结论——候选仍需经阶段 A 的证明链才能升级。`declared_receiver_lifetime` 只说明签名允许回调借用有限存活期的数据，要构成缺陷还需要另一半：外部持有期确实更长。`derive_v3_2_6_callback_bound_verdicts` 把这两半按**函数**关联起来（不是按候选——候选是按 boundary 切的，两半会落在不同候选里）。人工写的版本边界 `non_static_callback_max_version` 由此降为兜底与审计对照，两路结论不一致时一起留在产物里；
3. 用现有 n-day 正样本做非循环验证：关掉 API map，看能重新发现几条。**注意第 2 步只降格了版本边界这一个字段**：外部持有期的证据仍是 API map 分类出来的 register / unregister 事实，所以「不读 API map」这一条尚未成立；
4. 只有第 3 步有结果之后，才允许把 API map 整体从「必需输入」降格为「审计加固」。

在阶段 B 交付前，接入任一新组件都仍需先人工编写 API map。
