# Error taxonomy

错误分三层：CLI/格式错误、执行 outcome、实验 failure taxonomy。三层不得相互折叠。

## CLI 与格式错误

| family | 代表 code | 含义 |
| --- | --- | --- |
| syntax/encoding | `BW-JSON-INVALID`、`BW-TOML-INVALID`、`BW-JSONL-LINE-TOO-LONG` | 语法、编码或资源上限错误 |
| schema | `BW-SCHEMA-UNSUPPORTED` | 不支持的 record version |
| I/O/integrity | `BW-IO`、`BW-V32-VERIFY-CHECKSUM`、`BW-V32-VERIFY-SYMLINK`、`BW-V32-VERIFY-EXTRA-FILE` | 读取、checksum、路径或文件集错误 |
| trace state | `BW-TRACE-*` | start/end、seq、object/callback/owner 引用不一致 |
| oracle input | `BW-ORACLE-*` | static/trace/build/Contract evidence 不完整或歧义 |
| public boundary | `BW-*-PRIVATE-TOKEN`、`BW-V325-PUBLIC-TOKEN` | public artifact 出现受禁身份 token |
| provenance | `BW-V326-FACT-PROVENANCE`、`BW-V326-GRAPH-V3-*` | fact、object、edge、chain 或 evidence 无法回查 |
| Contract | `BW-CONTRACT-*` | clause/API map/opaque generation key/registry 审计失败 |
| internal | `BW-INTERNAL` | 工具内部错误；退出码 3 |

具体 validator code 是稳定机器接口；文档按 family 汇总，不把 message 文本当稳定 API。

## 执行 outcomes

`bw-experiment` 将一次运行的 primary outcome 分为：

- `contract_finding`；
- `clean_exit`；
- `asan`；
- `native_crash`；
- `panic`；
- `timeout`；
- `invalid_input`；
- `tool_error`。

优先级由 outcome classifier 决定，但报告必须保留各 evidence flag；finding 与 ASan 同时出现时不能丢失交集。D1 campaign 另有 `primary_found`、`no_primary`、`timeout`、`tool_error`，以及 records 中的 crash-without-primary 处理。

## V3.2 failure classes

[`failure_taxonomy.rs`](../../crates/bw-model/src/failure_taxonomy.rs) 定义：

| class | 层 | 是否默认 infrastructure | 解释 |
| --- | --- | --- | --- |
| `requires_system_dependency` | build | 是 | 固定环境缺系统依赖 |
| `cargo_check_failed` | build | 否 | 构建失败，需日志归因 |
| `not_buildable` | build | 否 | 当前配置不可构建 |
| `unsupported_target` | build | 是 | target/toolchain 不支持 |
| `timeout` | build/run | 是 | 预算内未完成 |
| `tool_error` | any | 是 | 工具执行失败 |
| `no_supported_boundary_pattern` | boundary | 否 | 当前 detector 未识别支持模式；不是安全 |
| `deferred_static_only` | dynamic prep | 否 | 优先级/成本推迟；不是动态阴性 |
| `analyzer_unsupported` | analysis | 否 | 当前分析形状不覆盖 |
| `insufficient_evidence` | graph/pair | 否 | 无法闭合要求的 proof |
| `integrity_failure` | archive | 否 | lineage/checksum/receipt 不可信 |

当前 taxonomy builder 强制这些 incomplete records 的 `is_method_negative=false`。只有预注册方法评价明确把可运行、可观察且证据完整的样本计入分母时，才能产生 method negative。

## Gate 语义

- `Blocked`：缺少技术入口、数据、fixture 或前置 gate；不是失败实验，也不是 negative。
- `Planned`：规范/方向存在但没有可执行完整入口。
- `Implemented`：代码与测试存在；不等于 formal run。
- `Verified`：与 commit/toolchain/Contract/Schema/dataset/config/run 对齐的正式证据通过。
- `Deprecated`：兼容字段或旧解释仍可读，但不能用于新结论。

public regression、holdout、buildability 和 dynamic search 的失败必须按原层记录；不得用“无 finding”覆盖 timeout、tool error、coverage gap 或 integrity failure。
