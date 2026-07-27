# D1 structured search（2026-07-19）

## 运行身份

| 字段 | 值 |
| --- | --- |
| 状态 | Historical / native Linux formal |
| code revision | `f3fa5edfdaf39bd0a3510fd0593e0033f2e995fb` |
| deployment SHA-256 | `f6c60964724934d3fd089b8994c804d5bb43ce69fb5e8993a45a712df4ea3224` |
| update_hook run_id | `unix1784400047-f3fa5ed-d1formal` |
| scalar run_id | `unix1784400000-f3fa5ed-d1scalar` |
| corpus ID | `dataset:d1-safe-fragments:callback-lifecycle:20260719` |
| environment | `native-linux`（固定容器复跑未完成） |
| artifacts | `artifact:run:unix1784400047-f3fa5ed-d1formal`；`artifact:run:unix1784400000-f3fa5ed-d1scalar` |

原记录没有保存 Contract hash、完整 dataset hash 或 schema-set hash，因此按当前 [对齐规范](../data-alignment.md) 只能作为历史验证，不能与当前 commit 直接合并比较。

## 工具入口

历史运行使用的入口在当前仓库仍存在：

```bash
tools/experiment/run-d1-formal.sh \
  --repo-root . \
  --runs-root "${BW_RUNS_ROOT:?}" \
  --commit f3fa5edfdaf39bd0a3510fd0593e0033f2e995fb \
  --deployment-sha256 f6c60964724934d3fd089b8994c804d5bb43ce69fb5e8993a45a712df4ea3224 \
  --image-digest native-linux \
  --rustup-toolchain nightly-2026-07-08

tools/experiment/verify-d1-formal.sh \
  "${BW_RUNS_ROOT:?}/unix1784400047-f3fa5ed-d1formal"
```

第二 API 使用 `tools/experiment/run-d1-scalar-smoke.sh`；完整性使用 `bw-verify-run`，跨 run 汇总使用 `bw-d1-summary`。

## 实际结果

### update_hook formal

| 指标 | 结果 |
| --- | ---: |
| campaigns | 30 |
| primary success | 30/30（门槛 18/30） |
| timeout / tool error | 0 / 0 |
| executions | 130,940 |
| valid / invalid sequences | 12,235 / 118,705 |
| progress / secondary | 1,159 / 0 |
| replay | 每个 30 个 primary artifact 均 20/20 |
| safe-only | 1,315,014 executions；0 artifact；0 primary |

所有 minimized witness 都保留 register、owner end、later trigger 三阶段。

### create_scalar_function smoke

3/3 campaign 找到 primary；12,916 executions 中 444 条 valid、12,472 条 invalid；3 个代表 artifact 均 replay 20/20。它证明相同 grammar、objective 与 replay/minimize 管线可用于第二 API，但不进入 update_hook formal 的主统计。

### 合并汇总

33/33 campaign 成功，143,856 executions，12,679 valid、131,177 invalid，1,259 progress、0 secondary、660 次 replay 成功。time-to-first primary 为 357 ms / 2,248 ms / 9,766 ms（min/median/max）；minimized length 为 5 / 6 / 8。

## 失败与边界

- 固定 container/image digest gate 未执行；`native-linux` 不是可复现镜像身份。
- 该结果没有证明 D2 feedback 优于 baseline，也没有覆盖任意 Rust FFI callback API。
- 当前迁移工作树的 benchmark lock 尚不能通过脚本内部 `cargo --locked`，因此这份历史记录不能充当当前 CLI 的新运行验证。
- 没有 timeout/tool error 是本次观察，不得外推为工具不会失败。

结论：在绑定的历史 revision 与 native Linux 环境中，D1 从安全 fragments 自动搜索到 rusqlite callback-lifecycle primary witness，并稳定最小化/重放；证据等级为 `R4` historical，而非当前 commit `Verified`。
