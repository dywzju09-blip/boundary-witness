# Event and record formats

BoundaryWitness 使用版本化 JSON/JSONL/TOML 记录。Rust model 对核心记录启用 unknown-field rejection；`schema_version` 不匹配、跨记录引用悬空或事件顺序错误都属于输入错误。

## `bw.static/0.1` 与 `bw.static/0.2`

static fact envelope 位于 [`static_fact.rs`](../../crates/bw-model/src/static_fact.rs)。两版都可读取；只有 `0.2` 在完整 artifact identity、source span 和 semantic anchor 存在时才可能成为 authoritative lifecycle binding。

`0.2` 信封字段：`schema_version`、`record_id`、`producer`、`build_id`、`artifact {crate_id, package_name, package_version, target}`、`source_ref {path, line_start, line_end, symbol_path}`、`payload`。

payload kinds：

- object/callback/capture：`object_site`、`callback_site`、`callback_capture`；
- lifecycle：`drop_site`、`drop_prevention`、`callback_user_data_reconstruction`；
- boundary：`registration_site`、`external_call_site`、`raw_pointer_transfer`；
- proof/order：`release_path_proof`、`callback_release_use_order`；
- returned view：`returned_borrow_relation`、`persisted_returned_borrow`、`returned_borrow_invalidation_order`；
- other object flow：`external_buffer_binding`、`atomic_ordering`、`object_binding_gap`、`object_flow`。

static fact 是“编译器观察到什么”，不是 finding。source-derived observation 如果不能回查 authoritative static artifact，graph 必须保留 provenance gap。

## `bw.trace/0.1`

runtime JSONL envelope：

| 字段 | 含义 |
| --- | --- |
| `record_id` | run 内唯一记录 ID |
| `run_id` / `trace_id` | 执行与单条 trace 身份 |
| `seq` | 从 0 开始严格递增 |
| `thread_id` / `source` | 诊断来源 |
| `payload.kind` | 事件种类 |

事件种类：`trace_start`、`object_create`、`capture_bind`、`callback_register`、`callback_unregister`、`callback_invoke`、`object_drop`、`object_use`、`object_free`、`checkpoint`、`trace_end`。unregister reason 为 `explicit`、`replacement` 或 `owner_drop`；checkpoint 为 `registered`、`owner_ended_or_released`、`later_callback_phase`。

trace validator 检查 start/end、event count、run/build identity、seq、对象/callback existence、site/owner consistency。地址只允许诊断，不作为稳定对象 ID。

runtime sink 另用 `bw.trace-index/0.1` 索引分段文件；index 不是 oracle event stream。

## `bw.contract/0.1` 与 `bw.api-map/0.1`

Contract TOML 定义 clause 和通用 API role；API map TOML 把 exact Rust/FFI path 映射到 Contract API，并声明 callback/user-data/opaque-handle 参数。详见 [Contract index](contract-index.md)。Contract 描述允许的解释，不证明某次运行发生了相关事件。

## `bw.finding/0.1`

finding 包括 rule ID、`exposure|confirmed_violation` classification、subject object/callback、first violation event、evidence references、context rules、前后 state snapshot、normalized signature、producer/build/run identity 和 message。

每条 evidence 标记来源 `static_fact`、`contract_clause` 或 `runtime_event`。finding 必须能回到输入记录；candidate、score、crash 或报告段落不能代替这一 lineage。

## `bw.run/0.1`

run manifest 记录 `run_id`、`build_id`、Git/deployment/image/config identity、host resource、seed/toolchains 和开始/结束时间。D0/D1 finalized run 还使用 `COMPLETE` 与 `checksums.sha256`；run manifest 本身不证明执行成功。

## 实验记录

`experiments/schemas/` 包含：

- blind pack/observation/install receipt/runner receipt/reveal；
- D1 formal 与 rollup summary；
- D2 comparison 和 feedback-state snapshot；
- deployment、MIR coverage 与 finalized run-integrity。

这些实验 Schema 与 [`schemas/`](../../schemas/) 的 V3.2 pipeline Schema 不同：前者固定实验协议，后者固定 scanner 中间产物。完整版本索引见 [Schema index](schema-index.md)。

## 顺序与公开边界

1. producer 写版本、identity 和中性事实；
2. validator 拒绝结构/引用/provenance 错误；
3. graph/ranking 保留 missing evidence；
4. runtime/oracle 产生 finding；
5. freeze 绑定 ranked hash；
6. curator reveal 产生聚合评估。

逐样本答案、身份映射和 curator match detail 不属于公开 event format。
