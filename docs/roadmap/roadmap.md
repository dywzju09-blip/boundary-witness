# Roadmap

BoundaryWitness 的路线从 V2 的模板化生命周期候选，推进到 V3 的证据分层、ObjectFlow、动态验证和 blind gate。当前阶段固定为 **V3.2.x core-effect hardening**；V3.3 尚未通过。

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
