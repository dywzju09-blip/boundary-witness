# Contract 与 Schema

Contract 描述 API 的生命周期角色，Schema 固定机器记录的结构与版本。两者都约束解释过程，但都不包含 CVE 标签、样本答案或动态触发结论。

## Contract 层

### callback-retention contract

[`contract.toml`](../../contracts/callback-retention/contract.toml) 使用 `bw.contract/0.1`，定义 retain、unregister/replacement/owner-drop release、retained invoke、borrow outlives retention、no-use-after-end 和 free-at-most-once 等 clause。`CallbackApiEntry` 将通用 `api_id` 绑定到 registration role、release behavior、owner kind 与 invoke role。

### API map

`bw.api-map/0.1` 将具体 Rust path 映射到通用 contract API。当前公开 map 位于 [`contracts/callback-retention/`](../../contracts/callback-retention/)，覆盖 rusqlite、diesel、PyO3 与 OpenSSL 的受审计入口。map 提供 callback/userdata 参数索引、callback family 和可选 opaque metadata。

API map 不是名称规则库：只有经过 parser、validator、checksum/manifest 与 contract ID 对齐的条目才能进入强语义。未审计 API 保持 unknown。

## opaque generation key

`CallbackRetentionApiMapEntry.opaque_generation_key` 是结构化 identity 组成，不是自由文本：

- set role 必须包含 `binding_api_id`、`handle_arg`、`key_arg`、`payload_arg`；
- get role 必须包含 `binding_api_id`、`handle_arg`、`key_arg`，且不得包含 `payload_arg`；
- component 不得重复；handle/key 参数索引必须存在；
- get 的 `opaque_binding_api_id` 必须引用同 family 的 set entry；set 以自身 `api_id` 为 binding ID。

这些约束防止“同 slot 不同 handle”或“同 API 不同 payload generation”被错误合并。validator 在 [`crates/bw-model/src/contract.rs`](../../crates/bw-model/src/contract.rs) 中实现，compiler 内联配置也必须显式调用验证。

## 生命周期 Contract 物化

[`materialize_lifecycle_contracts.rs`](../../crates/bw-cli/src/commands/materialize_lifecycle_contracts.rs) 读取一个 base contract 与一个或多个 API map，输出：

- `lifecycle-contracts.jsonl`，schema 为 `v3.2.6.lifecycle_contract.1`；
- `registry-manifest.json`，记录输入路径、SHA-256、record 数和 registry digest；
- `checksums.sha256`。

[`audit_lifecycle_contracts.rs`](../../crates/bw-cli/src/commands/audit_lifecycle_contracts.rs) 对 registry 输入 checksum、exact API coverage、release coverage 和组件覆盖进行审计。物化成功只说明结构和引用有效，不证明目标程序实际遵守 Contract。

## Schema 族

| 层 | 主要 Schema | 关键约束 |
| --- | --- | --- |
| intake/candidate | [`schemas/v3-2/`](../../schemas/v3-2/) | corpus、buildability、boundary、candidate、旧 graph/ranking 的版本化输入输出 |
| lifecycle evidence | [`lifecycle-evidence.schema.json`](../../schemas/v3-2-6/lifecycle-evidence.schema.json)、[`lifecycle-fact.schema.json`](../../schemas/v3-2-6/lifecycle-fact.schema.json)、[`lifecycle-coverage.schema.json`](../../schemas/v3-2-6/lifecycle-coverage.schema.json) | candidate/crate scope、source ref、confidence、coverage、provenance 与 object/evidence refs |
| graph/ranking | [`lifecycle-graph-v3.schema.json`](../../schemas/v3-2-6/lifecycle-graph-v3.schema.json)、[`ranked-candidate-v2.schema.json`](../../schemas/v3-2-6/ranked-candidate-v2.schema.json) | object/edge/chain、`verified_layers`/`missing_layers`、feature evidence、missing evidence、chain summary |
| validation plan | [`witness-plan.schema.json`](../../schemas/v3-2-6/witness-plan.schema.json) | graph reference、actions、observer/assertion 与 replay refs；plan 不等于 witness |
| reveal/freeze | [`schemas/v3-2-5/`](../../schemas/v3-2-5/)、[`scanner-freeze.schema.json`](../../schemas/v3-3/scanner-freeze.schema.json) | private ground truth/reveal 与 scanner freeze 分离；freeze schema 的存在不表示 V3.3 已通过 |
| dynamic/blind | [`experiments/schemas/`](../../experiments/schemas/) | D1/D2 summary、run integrity、blind public/private/receipt 边界 |

Rust validator 以 `deny_unknown_fields`、精确 `schema_version`、枚举、非空/唯一性、跨记录引用和 lineage 检查补充 JSON Schema。CLI [`validate`](../../crates/bw-cli/src/commands/validate.rs) 覆盖静态、trace、Contract、finding 及版本化 V3.2/V3.2.6/V3.3 record kind。

## 版本演进规则

1. Schema ID 与 `schema_version` 是外部协议；语义不兼容时新增版本或新字段，不静默改义。
2. 新字段先进入 model/validator、Schema 和 roundtrip/negative tests，再由 producer 写出、consumer 读取。
3. 兼容字段可以保留，但必须标出规范替代项。当前 `verified_static_chain` 的宽泛解释已废弃，消费者读取 `verified_layers`/`missing_layers`。
4. checksum/manifest 绑定 Contract、registry、config 和运行；路径或文件名不替代 digest。
5. private ground truth 与公开 detector inputs 使用不同 Schema 和流程；揭示后样本不再具有 sealed 身份。
6. `schemas/v3-3/scanner-freeze.schema.json` 仅定义未来 gate artifact；当前状态仍是 V3.2.x，V3.3 未通过。

## 代码、契约与测试入口

- 代码：[`crates/bw-model/src/contract.rs`](../../crates/bw-model/src/contract.rs)、[`crates/bw-model/src/schema.rs`](../../crates/bw-model/src/schema.rs)、[`crates/bw-model/src/validate.rs`](../../crates/bw-model/src/validate.rs)、[`compiler/bw-rustc/src/config.rs`](../../compiler/bw-rustc/src/config.rs)。
- Schema/Contract：[`contracts/callback-retention/`](../../contracts/callback-retention/)、[`schemas/`](../../schemas/)、[`experiments/schemas/`](../../experiments/schemas/)。
- 测试：[`crates/bw-model/tests/schema_roundtrip.rs`](../../crates/bw-model/tests/schema_roundtrip.rs)、[`crates/bw-model/tests/jsonl_validation.rs`](../../crates/bw-model/tests/jsonl_validation.rs)、[`crates/bw-cli/tests/lifecycle_v326_cli.rs`](../../crates/bw-cli/tests/lifecycle_v326_cli.rs)、[`compiler/bw-rustc/tests/mir_sites_golden.rs`](../../compiler/bw-rustc/tests/mir_sites_golden.rs)。

证据语义见[证据模型](evidence-model.md)，graph 消费规则见[生命周期对象流](lifecycle-object-flow.md)。
