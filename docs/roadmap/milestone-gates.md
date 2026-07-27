# Milestone gates

本文定义从 V3.2.x 进入 V3.3 前必须通过的 gate。任何单项成功都不能替代完整 gate。

## Gate 1：Clean method commit

- 工作树 clean；
- `Cargo.lock`、`rust-toolchain.toml`、Schema、Contract 和 docs 对齐；
- 无 prompt、迁移清单、私有路径、sealed 数据或大型结果；
- PR 必跑测试完成或阻塞项明确记录。

完成谓词：`git status --short` 为空，PR 记录命令、退出码、未运行项和阻塞原因。

## Gate 2：Public regression

- 当前 commit 上运行已揭示公开数据；
- dataset/config/Contract/Schema/run hash 完整；
- negative controls、pair separability、coverage gap 和 failure taxonomy 均记录；
- 历史结果不得升级为当前结果。

完成谓词：新增正式 result 文档，满足 [data-alignment](../experiments/data-alignment.md)，并通过 checksum 和敏感材料扫描。

## Gate 3：ObjectFlow 与 proof-layer 回归

- opaque handle schema/validator 复验；
- returned-borrow exact claimant negative controls 复验；
- graph-v3/ranking-v2/CLI 均按 `verified_layers`/`missing_layers` 消费；
- identity、ordering、complete risk chain 不再被旧 `verified_static_chain` 合并解释。

完成谓词：model、CLI、compiler golden 和 Schema roundtrip 覆盖正负路径。

## Gate 4：Dynamic bridge

- witness plan 可选择或生成最小 harness；
- executor 能驱动 runtime/oracle 或 fuzz/Miri 路线；
- replay receipt、checksum、negative controls 和 failure classification 完整；
- crash、finding、sanitizer 与 method negative 分开。

完成谓词：至少一个公开设计家族在当前 commit 上形成 plan 到 receipt 的可重放闭环。

## Gate 5：约 100 crate 工程 pilot

- corpus manifest、buildability、boundary、candidate、lifecycle evidence、graph/ranking 和 taxonomy 全链运行；
- unsupported、tool error、timeout、coverage gap 不被改写为安全；
- adapter effort 与 candidate partition 可审计。

完成谓词：pilot result 文档绑定 run ID、hash、失败类和结论上限。

## Gate 6：Freeze 与 sealed holdout

- scanner、Contract、feature profile、ranking policy、threshold、dataset hash 和 ranked output hash 冻结；
- runner/curator 隔离；
- public regression 已通过；
- 使用新的、未 reveal sealed holdout。

完成谓词：公开仓库只保存无身份 freeze record、聚合摘要和不可逆 hash；样本身份、ground truth、逐样本 detail 和结果路径不进入 Git。
