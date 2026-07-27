# D2 small comparison（2026-07-20）

## 运行身份

| 字段 | 值 |
| --- | --- |
| 状态 | Historical / pipeline acceptance |
| code revision | `d35b74ffb3b11a2cd5a206ab4a8b1207b40c29ac` |
| source archive SHA-256 | `317671a2eb449e29a360335d76089eaeaace46218ad1ac9678ec85efdab9fece` |
| config SHA-256 | `9b93a781ffce6cb0e221f3b45989e9f6bc47df766ced806d2973032d966d8232` |
| corpus ID | `dataset:d2-update-hook-safe-fragments:20260720` |
| artifact | `artifact:result:d2-small:d35b74f:20260720` |

原记录没有独立 `run_id`，以执行日期和 code revision 定位；也没有 Contract、dataset 与 schema-set 的完整 hash，故不能视为当前 commit 上的 aligned regression。

## 工具入口

```bash
BW_D2_GENERATE_RECORDS=1 \
BW_D2_RUSTUP_TOOLCHAIN=nightly-2026-07-08 \
tools/experiment/run-d2-small.sh \
  experiments/configs/d2-baselines.toml \
  "${BW_RECORDS_ROOT:?}"

tools/experiment/verify-d2-comparison.sh \
  experiments/configs/d2-baselines.toml \
  "${BW_RECORDS_ROOT:?}"
```

## 实际结果

| group | campaigns | primary | median time-to-first | valid ratio | minimized length | replay successes | progress-state coverage |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `random_action` | 5 | 0 | not run | 0.0066 | not run | not run | 6 |
| `coverage_only` | 5 | 5 | 185 ms | 0.0446 | 6 | 100/100 | 0 |
| `coverage_state` | 5 | 5 | 178 ms | 0.0550 | 6 | 100/100 | 14 |

coverage 两组从 artifact 自动完成 decode、minimize、replay、campaign record 和 comparison summary。每个 group/campaign 使用独立的可变 corpus，避免 libFuzzer 变异跨组污染。

## 失败记录

commit `36b2ed9` 上的一次 partial run 因 coverage 两组共享可变 corpus 被作废；其逻辑记录为 `artifact:abort:d2:36b2ed9:shared-mutable-corpus`，不进入上表。

更重要的统计缺口是：`random_action` 按 `execution_budget=1000` 停止，而 coverage 两组按时间预算运行。0/5 不能解释为“同 CPU-time 下随机策略失败”。每组仅 5 次，coverage-only 与 coverage-state 都是 5/5，不能据 178 ms 对 185 ms 声明显优势。

## 结论边界

本结果证明三组 records、contract-state coverage、artifact 最小化/重放和 summary 管线在历史 revision 上闭环。它不证明 state feedback 统计上优于 coverage-only，不证明 random baseline 同预算，也不证明大规模或未知样本能力。
