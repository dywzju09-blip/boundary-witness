# V3.2.5 N-day blind smoke（2026-07-21～24）

本记录是同一已揭示 20-sample 开发语料上的历史回归序列，不是独立 holdout，也不是动态复现。scanner 输出只表示 candidate、证据、静态风险和需要验证。

## 初始 formal smoke

| 字段 | 值 |
| --- | --- |
| suite | `suite.v3-2-5.nday.smoke.001` |
| corpus | `corpus.v3-2.nday.smoke.20` |
| run_id | `v3-2-5-nday-smoke-20-f2a76c8-20260721` |
| method commit | `f2a76c8cf5fc1d12e19293b8174a21f1cb158e4d` |
| public manifest SHA-256 | `bb4161aa22ebe109ffb238c53f80ef475a4dd141af15a0abb7d400e971520512` |
| ranked SHA-256 | `d7cefb41c308a651d9f5ac05df3c907c25937e1b3b7ec59e8c59183a47b90e9a` |
| buildability SHA-256 | `b82bc37f4ac872c67cdffaa46e2339d2a342269b2c6e0b6f91aaa6d5f80ed364` |
| boundary index SHA-256 | `1a925b18098383a36a671761deb2a947b144d4f0997071b2dc4d833ce0e52c71` |
| curator ground-truth digest | `5c0c84f063c69f41cc2f4e7ac33f37bfc22a7da55e11a837a4f2a2042869f776` |

20/20 buildable，43 boundaries/candidates/ranked，6 个无支持边界，max score 45。3 个 historical-positive 都有相关 candidate，但 top1=0、top5=0、top10=2；3 个 paired controls 均出现同类高分信号，`false_positive_control_count=3`、`paired_control_clean_count=0`。因此 `smoke_pass=no`。

## 关键历史回归

| revision/run | 绑定 hash | top1/top5/top10 | controls clean / FP | pair 结果 | gate |
| --- | --- | ---: | ---: | --- | --- |
| `d67e6573538d05862b7dd3b739cb1cad9f4f3fea` / `v3-2-6-regression-v3-2-5-20-d67e6573538d-20260722-r3` | ranked `1ad86e09f815c5762cc409a89178c290eb69ad621c73828fa71ba01ac4a29a64`; checksums `ce4908e24b9c2c2ade88f279b8d6448dc221b33e28e237545399c5135dfec867` | 0/0/2 | 0/3 | 3 insufficient | fail |
| `22ccecaf0fdd2825069d67b825033cf51182db92` / `v3-2-7-regression-v3-2-5-20-22ccecaf0fdd-20260722-r2` | ranked `83eea4859a1a03ad64c55cc7c1edc4983c53e9e0049835d408b08bdd09efbb83`; checksums `ce7563013fcaca0e5e89092fb0fc38b5b365abbc65557e063c96130db267d322` | 0/0/1 | 2/1 | 3 insufficient | fail |
| `361ed1d40042929e7a2182a358a2b9891ea3f03a` / `v3-2-7-regression-v3-2-5-20-361ed1d-20260722-r1` | dataset manifest unchanged | 0/1/1 | 1/2 | 0 separable; 86 insufficient of 108 comparisons | fail |
| `117a330cd5ead2232b3315265b1244b0aef4e3ed` / `v3-2-8-authenticity-v3-2-5-20-117a330-20260723-r1` | ranked `d297143fe00c40d2556c8df73a1260d6c179235a0fde1a206188e5fb28bd4fb5` | 1/1/1 | 2/1 | 0 separable; 89 insufficient | fail |
| static bridge development run | ranked `7b640e2fdc94c66de0885950ca6defd4ca2d59711a970c0c4a782f4f7c765508` | 1/1/1 | 2/1 | 0 separable; 89 insufficient | fail |
| `v3-2-5-20-20260723-static-r17b-lifecycle-r2-source-scoped-proof` | ranked `3a3a88ceb23ea804f845a2df32ada0c11478c4fbad315ebbd0127bbf8eddced7` | 1/2/2 | 3/0 | 3 separable; 119 insufficient | fail |
| `v3-2-5-20-20260723-static-r17b-lifecycle-r3-source-api-unregister` | ranked `74377dcccb07a84f5ccd86ccb61cff898393b65c7648472f7ed00c9d4d1a1d1a` | 1/2/2 | 3/0 | 3 separable; 119 insufficient | fail |
| `v3-2-5-20-20260723-static-r17b-lifecycle-r4-sibling-unregister` | ranked `9e6456300dbbf2da4441a6dd39a32770c195b5d38e6c2056e747fab849da6078` | 1/2/2 | 3/0 | 3 separable; 119 insufficient | fail |
| `v3-2-5-20-20260724-static-r27-openssl-free-callback` | static facts `21207813e86bbfe481e4ac7934089d13b6a73452a9dd9bde42cc8063c0223880`; ranked `f983353304179c07dd9e36ccb34e59e1c136b1e7d30c10ebc616ab62e5ad730b` | 1/2/2 | 3/0 | 6 separable; 104 insufficient | fail |

`v3-2-5-20-20260723-static-r18b-previous-hook-release` 的 static facts hash 为 `db0ac1101d1ab4276319a26b6e5641ebe2582015a64aebc159ca52d8e7c82e7b`，与前一 public static artifact byte-identical，因此未重跑 lifecycle/ranking 指标。

## 工具入口

历史后期链使用当前 `bw` CLI 中仍存在的 `extract-static-facts`、`extract-lifecycle-evidence`、`materialize-lifecycle-contracts`、`build-lifecycle-graph-v3`、`rank-lifecycle-v2`、`compare-anonymous-pairs`、`reveal-static-ranking` 和 `verify-run`。入口通过实际 help 核对：

```bash
cargo run -p bw-cli --bin bw --locked -- extract-static-facts --help
cargo run -p bw-cli --bin bw --locked -- build-lifecycle-graph-v3 --help
cargo run -p bw-cli --bin bw --locked -- compare-anonymous-pairs --help
cargo run -p bw-cli --bin bw --locked -- reveal-static-ranking --help
```

## 动态证据与失败说明

本系列没有 harness、fuzz 或 replay，动态证据等级为 `R0`；所有命中都是静态 ranking/reveal 指标。static bridge 历史记录只分析 17/20，3 个 source extraction `cargo_check_failed`；OpenSSL 回归为 19/20。exact destructor 和 OpenSSL ex_data free-callback proof 能正确降低已证明释放覆盖的候选风险，但 object binding、returned-borrow invalidation/use ordering 和跨函数状态机仍留下大量 `insufficient_evidence`。

## 最新历史结论与当前状态

截至这组来源的最后一次记录，top-k 与 paired controls 已改善，但 pair coverage 仍有 104 条 insufficient evidence，完整 gate 未通过，V3.3 未进入。最后一条 2026-07-24 static 记录保留了 run ID 与 artifact hashes，却没有记录对应 method commit，因此按当前对齐规则仍是 historical diagnostic。该数据已用于多轮开发，不具一次性泛化身份。当前迁移 commit 尚未执行最新 public regression；以上任何 historical run 都不能升级为当前 `Verified`。
