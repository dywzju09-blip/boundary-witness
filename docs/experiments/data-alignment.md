# 数据对齐规范

实验结果只有在代码、工具链、Contract、Schema、数据、配置和运行身份同时冻结时才可比较。本规范使用以下最小绑定：

```text
code_commit
+ toolchain
+ contract_hash
+ schema_version
+ dataset_version / dataset_hash
+ config_hash
+ run_id
```

## 必填身份

| 字段 | 规范 | 校验边界 |
| --- | --- | --- |
| `code_commit` | 运行源码的完整 Git commit | 工作树有未提交改动时不得形成 formal 结果 |
| `toolchain` | stable/nightly 版本、target triple；涉及 compiler 时同时记录 sysroot/LLVM 可识别版本 | 只写 `stable` 或 `nightly` 不足以复现 |
| `contract_hash` | 实际消费的 Contract 与 API map 逐文件 SHA-256；多文件再计算有序 manifest hash | Contract 文件名不能替代内容 hash |
| `schema_version` | 每种输入/输出记录自己的 `schema_version`；run manifest 记录完整集合 | 目录名或 JSON Schema `$id` 不能替代记录内版本 |
| `dataset_version` | 稳定逻辑 ID，例如 `corpus.v3-2.pilot.20.20260721` | 不使用本机路径作为数据身份 |
| `dataset_hash` | scanner 实际读取的 manifest/pack/corpus manifest SHA-256 | reveal 后的答案文件 hash 单独由 curator 保存 |
| `config_hash` | campaign、objective、feature profile、ranking policy 和 freeze 配置的 SHA-256 集合 | 默认参数也要落入可审计配置或 manifest |
| `run_id` | 全局唯一且不可复用；失败/中止 run 也保留独立 ID | 不覆盖已有目录，不向 finalized records 追加 |

推荐补充 `build_id`、deployment archive hash、container image digest、CPU/内存限制、host class、开始/结束 UTC、seed list、input/output artifact ID 和 `checksums.sha256` hash。

## 逻辑 artifact ID

公开文档只引用稳定身份，不记录操作者机器或服务器路径：

- finalized run：`artifact:run:{run_id}`；
- corpus manifest：`artifact:dataset:{dataset_version}:manifest`；
- ranked output：`artifact:run:{run_id}:ranked-candidates`；
- receipt：`artifact:run:{run_id}:runner-receipt`；
- reveal aggregate：`artifact:run:{run_id}:reveal-summary`。

artifact catalog 可以在 Git 外把这些 ID 映射到实际存储位置。迁移、同步或换服务器不改变 artifact ID；字节变化必须产生新 hash，语义变化必须产生新 dataset/config version。

## Hash 计算

1. 文件统一使用 SHA-256，按原始字节计算。
2. 多文件集合先生成按 UTF-8 路径字节排序的 checksum manifest；manifest 自身再计算 SHA-256。
3. checksum 中只能出现 artifact 根目录下的规范相对路径；拒绝绝对路径、`..`、symlink、重复项、漏列和额外文件。
4. 压缩 artifact 记录压缩文件 hash；需要逐记录验证时，同时记录解压后 canonical stream hash，二者不可混用。
5. dataset manifest、materialized manifest 和运行时可变 corpus 是三个不同对象，必须分别命名和 hash。

## 对齐判定

两个 run 只有在目标比较所需的字段全部相等时才称为 aligned。允许变化的自变量必须预先声明，例如 D2 只允许 feedback strategy 不同；其余预算与输入字段应一致。

出现以下任一情况时，结果只能标为 diagnostic 或 historical：

- 当前代码 revision 与结果 commit 不同；
- 输入 hash 或 Contract/API map hash 缺失；
- Schema 语义已变但仍复用旧版本号；
- 数据经 materialize、过滤或补 lockfile 后未产生新 hash；
- run 目录不完整、checksum 失败或包含未登记文件；
- 只知道同步位置，不知道 runner 实际读取的 artifact；
- reveal 前 freeze 未绑定 ranked output hash。

## 正式运行输入锁

大规模 public regression、pilot、D0/D1/D2 formal 和 sealed holdout 前必须先生成运行输入锁。入口为：

```bash
python3 tools/experiment/verify_run_inputs.py \
  --repository . \
  --dataset-manifest "$DATASET_MANIFEST" \
  --run-config "$RUN_CONFIG" \
  --expected-commit "$EXPECTED_COMMIT" \
  --output-lock "$OUTPUT_LOCK"
```

`run-config` 使用 `boundary-witness/run-input-config/v1`，记录 `run_id`、预期 `rustc --version`、Contract snapshot hash、Schema version 集合、dataset identity/hash、`experiment_config` 的 canonical hash，以及实际实验配置对象。检查器只读输入；任一字段不一致、Git 工作树 dirty、Contract/Schema 内容漂移、dataset manifest hash 不匹配或配置 hash 不匹配时返回非零，并删除 `.partial` 或旧锁文件。

成功锁文件使用 `boundary-witness/run-input-lock/v1`，绑定实际 Git commit、`code_dirty=false`、toolchain、Contract snapshot hash、Schema versions、dataset identity/hash、config hash 和 `run_id`。该锁证明本次运行启动前输入已冻结；它不证明私人服务器副本已对齐，也不证明后续执行事实。副本字节一致性仍由私有数据索引仓库的 manifest compare 证明，执行事实仍依赖 run receipt、日志、checksums 和 finalized artifact。

## 失败与重跑

- `.partial`、abort、timeout 和 integrity failure 保留原 `run_id` 与失败分类，不改名为 negative。
- 修复环境、脚本或 corpus 污染后必须创建新 `run_id`；旧 run 不删除、不并入新统计。
- 同一 frozen dataset 上调参重跑属于公开开发回归，不恢复 holdout 身份。
- 从服务器同步后的本地验证只证明字节完整性，不证明服务器执行事实；执行事实依赖 manifest、receipt、日志和 image/deployment 绑定。

## 发布检查表

正式结果文档应同时给出：日期、`run_id`、完整 `code_commit`、dataset ID/hash、工具入口、关键配置/Contract hash、输出 hash、实际结果、失败说明和结论上限。历史文档缺少某个现代字段时必须明确缺口，不能补造 hash。
