# rusqlite M12 blind gate（2026-07-20）

## 运行身份

| 字段 | 值 |
| --- | --- |
| 状态 | Historical / formal container gate passed |
| suite | `suite.rusqlite.m12.v3` |
| run_id | `unix1784521354-660c122-baf3275a` |
| method/runner commit | `660c12206d96cc62c3f44284e97b3991cbe69c6b` |
| reveal verifier commit | `6f404152ce3f4d516d9fa13916ab95bbe6ffae2a` |
| dataset ID | `dataset:suite.rusqlite.m12.v3:gate:20260720` |
| isolation | Docker container |
| finalized artifact | `artifact:run:unix1784521354-660c122-baf3275a` |

### Hash 绑定

| 对象 | SHA-256 |
| --- | --- |
| staging-builder archive | `d26fcf9821c8477873ee668f0f5d7f5870ba07124756bd10148aa3949947da25` |
| blind-runtime archive | `daa804859b792713618172f94cba9ee1aef27551d8e7fd0fee430db11d9e8794` |
| public pack archive | `033f2773e35c2c25e152a94dde197408e003f8d7ea0959ebe9e62d28ba10d376` |
| public manifest | `4bb81cd1971e45e32c0838d09572005958f486fa1cbe7eab2be7f6e49415cdd9` |
| policy | `e2cde164fcf4cc8bac9a61d07464febcfe6244c7e60b63ecc85496bbc3f4779f` |
| curator ground-truth digest | `361110d350859ec0d2ba2d3d36e440573d2614c926638c55c03d6121b2056d22` |
| observations | `2d1b1a1b19997097fccb5596340c06aff6b7d32e520da012f631716904e549da` |
| runner evidence digest | `27cd0c4a944471b42293301c806355fb78903d4b83f27fd8d0e6a8d697555e20` |
| checksum manifest | `3b877461fd111492a00c003b62d86c675e770112d3f98034db5b215976de49d9` |
| install receipt | `4022c1293ef20f472dd217c0e61db22a3f469e2a6d1661dbbfd2d38d00a14cdd` |
| runner receipt | `f871d6c3abb115855625309e9745c06ae6e973fba8a7891727ae7d6cb1c5c7ef` |
| reveal report | `2fc8bcb6fa57424559eb532b86fcaa1dad3781c2b202cd9fdd50974b5714c808` |
| gate decision | `09dbd2924ea5aaa121303c7d5a77c9d4d5cb937f4a9182d92ed50725b6b95ca0` |

## 工具入口

历史流程使用当前仓库仍存在的 `bw-blind-audit`、`bw-blind-run`、`bw-verify-run` 和 `bw-blind-reveal` CLI。runner 的真实参数形状可核对为：

```bash
cargo run -p bw-blind-runner --bin bw-blind-run --locked -- --help
cargo run -p bw-blind-curator --bin bw-blind-reveal --locked -- --help
```

出于数据隔离，本文不发布 pack catalog、curator input、receipt secret 或 reveal output 的存储位置。

## 实际结果

- public pack audit：10 cases；manifest hash 与 method commit 匹配。
- runner：10 completed、0 failed；container isolation receipt 有效。
- 2 个 confirmed cases 的 witness 都 replay 20/20。
- finalized run 通过 `bw-verify-run`；receipt 与 checksums 在 reveal 前验证。
- reveal：`gate_passed=true`，`minimum_confirmed_cases=1`，`passed_violation_cases=2`，`control_failures=[]`，`incomplete_cases=[]`。
- 确认模式为 retained-borrowed-callback；这是已知设计家族，不是新缺陷声明。

## 失败与修复记录

两个旧 revision 的 run 均未进入结果：`741cff7` 因 trace-index 元数据兼容问题造成 10/10 tool error；`1b783c5` 因公开 signature 不是 64 位 hex 导致 4 cases 被拒绝。最终 method commit 修复 signature hashing；reveal verifier commit 修复 runner/curator evidence digest 遍历顺序。失败保留为 tool/protocol failure，不计为 negative。

## 结论边界

该 run 证明历史工具链能在 rusqlite M12 设计家族上完成匿名 pack、container runner、receipt/checksum 和事后 reveal 闭环。它不证明跨项目泛化、未知缺陷发现或当前迁移 commit 的效果。
