# 当前工作

本文只记录当前所处阶段与下一步。阶段定义见 [roadmap](roadmap.md)，方向权威见
[research thesis](../project/research-thesis.md)，执行顺序权威见
[execution plan](execution-plan.md)。

## 所处位置

**阶段 0–4、5.0、5.2、5.3、5.4、5.5 全部完成。** 下一步：**大规模 0day 探针**
（判定→生成→oracle 三层流水线已就绪，规模从小到大）。

| 阶段 | 状态 | 证据 |
| --- | --- | --- |
| 0–4（范围/Rust 侧/外部 IR/联结） | ✅ | [results 索引](../experiments/results/README.md) |
| 5.0 符号解析（rusqlite 6/6） | ✅ | [stage5-0](../experiments/results/stage5-0-symbol-resolution-2026-08-07.md) |
| 5.2 真实 source-to-verdict | ✅ | [stage5-2](../experiments/results/stage5-2-source-to-verdict-2026-08-10.md) |
| 5.3 生成器重写（D3） | ✅ **2026-08-17** | [stage5-3](../experiments/results/stage5-3-witness-generator-rewrite-2026-08-17.md)（硬编码清零 + ASan profile + extra_dependencies；旧 08-10 记录已删） |
| 5.4 ASan 独立 oracle | ✅ **2026-08-17** | [stage5-4-5](../experiments/results/stage5-4-5-asan-oracle-and-negative-control-2026-08-17.md)（`bw run-witness-oracle`） |
| 5.5 rusqlite 0.26.2 负对照 | ✅ **2026-08-17** | 同上（对照矩阵 5/5） |
| 候选验证（0day 候选） | ✅ 5/6 出证 + 1 缺证 | tree-sitter / sqlite-vfs / ffmpeg / fltk×2 ASan 出证；fluidsynth 触发缺证（非证伪）；见 [highconf](../experiments/results/highconf-candidates-2026-08-16.md) |
| **大规模 0day 探针** | ⬜ **下一步** | 用户指示：规模从小到大，先验证有效性；披露判断必须询问用户 |
| 阶段 6–9（论文级验收/holdout） | ⬜ 后置 | execution-plan |

## 当前可复现命令链

```text
# 1) 静态分析（判定层）
bw extract-static-facts --manifest <m> --output-dir <o> --logs-root <l> --run-id <r> --rustc-wrapper <w> [--all-features]
bw extract-rust-contracts --facts <static-facts> --output-dir <o> --run-id <r> --build-profile <bp> --rust-artifact <ra>
# 2) 外部侧（阶段 3 产物，如需）
bw extract-foreign-facts --ir <sqlite3.ll> --roles <roles.json>
bw judge-hand-offs --rust-contracts ... --foreign-facts ...
# 3) witness（5.3 生成器 + 5.4 oracle）
bw generate-witness-harness --adapter <adapter.toml> --contracts ... --verdicts ... --repo-root ... --crate-version <v> --crate-source-dir ...
bw run-witness-oracle --harness-dir <dir> --run-id <id> --toolchain nightly-2026-07-08 --expect triggered|clean|build_failed
```

## 环境（远端服务器）

- 服务器：`ssh -i /Users/dingyanwen/Desktop/RAG/id_rsa_fixed -p 61015 root@10.98.36.107`
- worktree：`/mnt/hw/bw-agent/worktree`（分支 `deepseek`）；results：`/mnt/hw/bw-agent/results/`
- 工具链：`nightly-2026-07-08`；构建需
  `LD_LIBRARY_PATH=/root/.rustup/toolchains/nightly-2026-07-08-x86_64-unknown-linux-gnu/lib`
- 提交前 `bash /mnt/hw/bw-agent/pubcheck.sh`（自动移 target → check_public_tree → 移回）；
  推送 `GIT_SSH_COMMAND="ssh -i /root/.ssh/id_ed25519_dywzju09_blip -o StrictHostKeyChecking=no" git push origin deepseek`
- 环境备注：`/usr/local/lib64` 有 fluidsynth 1.1.10（系统 2.2.5 缺 midi router 符号，
  已备份 `.bak2x`）；`/mnt/hw/bw-agent/results/cfltk-lib/` 有 cfltk 预编译库
  （harness 构建 `CFLTK_BUNDLE_DIR`）；`/tmp/server2.py` 是 ffmpeg harness 慢速
  HTTP 服务器；`/mnt/hw/bw-agent/disk-clean.sh` 磁盘清理（类别规则，dry-run 默认）。

## 已知未解决问题

见 [current-status](../project/current-status.md#已知未解决问题不重复发现)（Q4′
无结论、Q3 降级、rust_def_instance、registration_key、3 跳上界、fluidsynth
触发缺证、setup 片段责任）。
