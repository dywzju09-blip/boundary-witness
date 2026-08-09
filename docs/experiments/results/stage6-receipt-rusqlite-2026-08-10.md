# 阶段 6 receipt：rusqlite vulnerable/fixed 链路的可重放证据绑定

- 日期：2026-08-10
- 绑定 commit：`4d85d0d`（deepseek）
- 性质：**开发集 receipt**（rusqlite 是开发对象，不构成论文正式数字；用途是
  阶段 6 验收的 artifact 绑定与重放）

## 1. artifact hash 表

| 产物 | sha256 | 说明 |
| --- | --- | --- |
| `stage5-2/rust-contracts/rust-contracts.jsonl` | `3523255a…24b89` | 0.26.1 契约（17 装配） |
| `stage5-2/joint/joint-verdicts.jsonl` | `cfec2d0c…53c` | 0.26.1 联结判定（1 joined，InsufficientEvidence ×2） |
| `stage5-3/harness-vulnerable/src/main.rs` | `03f7c4a7…563d2f` | 生成的 safe-only harness（Box referent） |
| `stage5-3/harness-vulnerable/Cargo.toml` | `ed8e29b6…179e` | pinned =0.26.1 + vendored patch |
| `stage5-4/asan-vulnerable-0.26.1.log` | `d950fe27…4b45` | ASan 证据（heap-use-after-free，完整栈帧） |
| `stage6/asan-run-1.log` | `a1fd3d91…500d` | 重复运行 #1（5/5 全部同型报告） |
| `stage5-5/rust-contracts/rust-contracts.jsonl` | `433648ab…24d9` | 0.26.2 契约（requires_static_capture） |
| `stage5-5/harness-fixed-0.26.2/src/main.rs` | `bd03f47f…229e7` | fixed harness（invalidate refused） |
| `stage5-5/harness-fixed-0.26.2/Cargo.toml` | `0c3dcf22…b03a` | pinned =0.26.2 + vendored patch |
| 三个对照 asan 日志（owned/unregister/no-trigger） | `e3b0c442…b855`（空文件） | ASan 干净 = 无输出 |

## 2. 重放步骤

```bash
# 1) 静态判定（0.26.1）
bw extract-static-facts --manifest <corpus>/component-only.jsonl --rustc-wrapper <bw-rustc> --all-features
bw extract-rust-contracts --facts <analysis>/static-facts.jsonl --build-profile x86_64-unknown-linux-gnu/dev \
    --rust-artifact rust:rusqlite:lib:<build_id>
bw extract-foreign-facts --ir <foreign-ir>/sqlite3.ll --roles adapters/rusqlite/update_hook.foreign-roles.json \
    --build-profile x86_64-unknown-linux-gnu/dev
bw judge-hand-offs --rust-contracts <contracts> --foreign-facts <facts> --output-dir <joint>

# 2) 反证生成 + ASan（vulnerable）
bw generate-witness-harness --adapter adapters/rusqlite/update_hook.toml --contracts <contracts> \
    --verdicts <joint> --repo-root <repo> --output-dir <harness-vulnerable>
cd <harness-vulnerable> && RUSTUP_TOOLCHAIN=nightly-2026-07-08 RUSTFLAGS="-Zsanitizer=address" cargo build
./target/debug/bw-witness-adapter_rusqlite_update_hook-0_26_1   # 预期 ASan abort（heap-use-after-free）

# 3) fixed 负对照（0.26.2）
bw extract-static-facts --manifest <corpus>/component-0.26.2.jsonl --rustc-wrapper <bw-rustc> --all-features
bw extract-rust-contracts --facts <analysis-0262>/static-facts.jsonl --build-profile x86_64-unknown-linux-gnu/dev \
    --rust-artifact rust:rusqlite:lib:<build_id-0262>
bw generate-witness-harness --adapter adapters/rusqlite/update_hook.toml --contracts <contracts-0262> \
    --verdicts <joint> --repo-root <repo> --crate-version 0.26.2 --output-dir <harness-fixed>
cd <harness-fixed> && cargo build    # 预期 E0425 编不过（invalidate refused）
```

产物全部在远端 `<results-root>/stage5-2|5-3|5-4|5-5|6/`（不进公开仓库）；
repo 侧资产（adapter、role map、生成器、fixture）在 deepseek `4d85d0d`。

## 3. 结果矩阵

| 运行 | 结果 |
| --- | --- |
| vulnerable 0.26.1（ASan） | heap-use-after-free（5/5 次重复同型） |
| fixed 0.26.2 | 编译期拒绝（E0425） |
| owned callback | ASan 干净（空日志） |
| unregister-before-drop | ASan 干净 |
| no-trigger | ASan 干净 |

## 4. 这一步证明了什么，没证明什么

**证明了**：阶段 6 验收的 artifact 绑定齐备——静态判定、harness、ASan 证据、
fixed 负对照、客户端对照的 hash 全部可回查，重放步骤可执行。

**没证明**：任何正式数字（开发集）；Gate A1/B 通过；receipt 的自动化验证
（`verify_run` 类工具绑定 receipt 格式——本次是文档级 receipt，不是机器可校验的
receipt schema）。
