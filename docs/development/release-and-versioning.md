# 发布与版本策略

BoundaryWitness 同时管理代码、Schema、Contract、dataset 和 run 五类版本。它们相互引用，但不能互相替代。

## 代码版本

代码版本由 Git commit 固定。正式结果要求 clean worktree；未提交修改只能用于本地诊断。PR 合并后若改变模型、CLI、Schema、Contract 或实验解释，必须更新相应文档和测试。

## Schema 版本

Schema 使用 `schema_version` 与 JSON Schema `$id` 双重标识。兼容扩展必须保持旧消费者语义；语义不兼容时升版，并更新 [schema-index](../reference/schema-index.md)、fixtures 和 validator 测试。禁止静默改变旧字段含义。

## Contract 版本

Contract 与 API map 通过文件内容 hash 和版本字段固定。新增 API family 前需要明确 role、参数位置、opaque generation key 或 callback/user-data 关系，并通过 materialize/audit 测试。Contract 描述 API 语义，不保存 ground truth 或漏洞答案。

## Dataset 版本

dataset 使用逻辑 ID、manifest 和 SHA-256。公开仓库可以保存小型 fixtures、公开 safe corpus 和 manifest；大型数据、sealed holdout、私有结果和服务器副本保存在 Git 外。数据经 materialize、过滤、补锁或重打包后必须产生新版本或新 hash。

## Run 版本

每次执行使用唯一 `run_id`。失败、中止和 timeout run 也保留自己的身份，不覆盖、不改名、不并入成功统计。正式 run 必须绑定 code commit、toolchain、Contract hash、Schema version、dataset hash、config hash、stdout/stderr、checksums 和 cleanup 记录。

## 发布口径

- `Implemented`：代码和测试存在。
- `Verified`：当前 commit 上的对齐运行证据通过。
- `Blocked`：缺失 gate、fixture、orchestrator、数据或环境。

发布说明不得把 historical run 升级为当前 Verified，也不得把 candidate/ranking/finding 直接写成漏洞确认。V3.3 只有在 milestone gate 全部满足后才能发布。
