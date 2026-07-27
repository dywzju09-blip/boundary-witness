# 当前工作

本文只记录里程碑级任务，不保存 Agent prompt 或逐日执行过程。状态词含义见 [terminology](../project/terminology.md)。

## 1. 复验当前 opaque handle schema/validator

| 字段 | 内容 |
| --- | --- |
| 状态 | `Implemented`，迁移后 formal regression 未完成 |
| 依赖 | OpenSSL API map、Contract materialize/audit、Schema roundtrip |
| 代码入口 | `crates/bw-model/src/contract.rs`、`contracts/callback-retention/openssl-api-map.toml`、`compiler/bw-rustc/src/rustc_api/mir.rs` |
| 测试入口 | `crates/bw-model/tests/schema_roundtrip.rs`、`crates/bw-model/tests/lifecycle_v326.rs`、`compiler/bw-rustc/tests/mir_sites_golden.rs` |
| 完成谓词 | set/get generation key、handle/key/payload lineage、negative key mismatch 和 audit failure 均有当前 commit 测试证据 |

## 2. 复验 returned-borrow exact claimant negative controls

| 字段 | 内容 |
| --- | --- |
| 状态 | `Implemented`，需完整 public regression 观察总体影响 |
| 依赖 | exact API key、relation anchor、ambiguous claimant 处理 |
| 代码入口 | `crates/bw-cli/src/commands/extract_lifecycle_evidence.rs`、`crates/bw-model/src/lifecycle_v326.rs` |
| 测试入口 | `crates/bw-cli/tests/lifecycle_v326_cli.rs`、`crates/bw-cli/tests/cli.rs`、`crates/bw-model/tests/lifecycle_v326.rs` |
| 完成谓词 | 零 claimant、多 claimant、近邻 span、同名 API 和高分 candidate 都不能错误取得共享事实 |

## 3. 复验 proof-layer-aware graph/ranking/CLI

| 字段 | 内容 |
| --- | --- |
| 状态 | `Implemented`，旧兼容字段解释需持续压降 |
| 依赖 | `verified_layers`、`missing_layers`、ranking summary、Schema index |
| 代码入口 | `crates/bw-model/src/lifecycle_v326.rs`、`crates/bw-cli/src/commands/build_lifecycle_graph_v3.rs`、`crates/bw-cli/src/commands/rank_lifecycle_v2.rs` |
| 测试入口 | `crates/bw-model/tests/lifecycle_v326.rs`、`crates/bw-model/tests/schema_roundtrip.rs`、`crates/bw-cli/tests/cli.rs` |
| 完成谓词 | external buffer 只点亮 identity，returned borrow 需 relation+persistence+ordering，CLI 输出不把 compatibility status 当完整风险链 |

## 4. 补最小跨函数 ObjectFlow

| 字段 | 内容 |
| --- | --- |
| 状态 | `Planned` |
| 依赖 | compiler MIR fact、candidate scoping、binding key continuity、barrier |
| 代码入口 | `compiler/bw-rustc/src/rustc_api/mir.rs`、`compiler/bw-rustc/src/domain.rs`、`crates/bw-model/src/lifecycle_v326.rs` |
| 测试入口 | `compiler/bw-rustc/tests/mir_sites_golden.rs`、`benchmarks/compiler-fixtures/`、`crates/bw-model/tests/lifecycle_v326.rs` |
| 完成谓词 | 至少 same-crate helper 的参数/返回或 field/wrapper 传递可形成 identity transport；unsupported dispatch 保留缺证 |

## 5. 补 release/use ordering

| 字段 | 内容 |
| --- | --- |
| 状态 | `Planned` |
| 依赖 | release proof、MIR CFG/post-dominance、runtime/oracle 对照 |
| 代码入口 | `compiler/bw-rustc/src/rustc_api/mir.rs`、`crates/bw-model/src/lifecycle_v326.rs`、`crates/bw-oracle/src/` |
| 测试入口 | `compiler/bw-rustc/tests/mir_sites_golden.rs`、`crates/bw-model/tests/lifecycle_v326.rs`、`crates/bw-oracle/tests/` |
| 完成谓词 | release-before-use、unregister-before-drop、conditional release gap、unknown ordering 和 negative controls 均被分开报告 |

## 6. 完成 public regression 后再判断 V3.3

| 字段 | 内容 |
| --- | --- |
| 状态 | `Blocked` |
| 依赖 | clean method commit、public dataset manifest、Contract/config hash、pair gate、dynamic bridge、约 100 crate pilot |
| 代码入口 | `crates/bw-cli/src/commands/`、`compiler/bw-rustc/`、`tools/experiment/` |
| 测试入口 | [public regression runbook](../experiments/runbooks/public-regression.md)、[milestone gates](milestone-gates.md) |
| 完成谓词 | 当前 commit 的 formal result 满足 data alignment；controls clean、coverage gap、pair separability 和 failure taxonomy 全部可审计 |
