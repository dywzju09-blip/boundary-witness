# 阶段 6 验收：重复运行重放一致性 + Gate A1

日期：2026-08-23 · run_id：`repeat-run-rusqlite-m12-2026-08-23`、`gate-a1-full-vs-rust-only-2026-08-23`
基线 commit：`99a198c`（vulnerable 树）/ `208f477` 冻结 adapter 不变
状态：**`Implemented`**——命令、产物哈希与本记录存在；D2 正式对齐（受管位置 + Linux 受控环境）完成前不升 `Verified`。

对应 [execution plan 阶段 6 验收清单](../../roadmap/execution-plan.md) 第 6 项（重复运行并比较 artifact、verdict 与 receipt）与第 7 项（Gate A1）。第 8 项 Gate B 的裁定记录见 [current work](../../roadmap/current-work.md) 同日条目。

---

## 一、重复运行重放比较（update_hook 腿，从源码全量重建）

### 方法

把 `/tmp/bw-p6` 中除生成物外的全部输入（组件源码、sqlite3.c、adapter/controls/RoleMap/config）复制到独立树 `/tmp/bw-p6-rerun`，删除全部生成产物后按 [stage6 记录](stage6-checksum-and-rusqlite-e2e-2026-08-23.md) 的复现命令**从零重跑整条链**：wrapper 静态事实 → Rust 契约 → cc-capture 位码 → llvm-dis → 外部行为事实 → 联结 → 计划 → 生成 → 运行 → verify-run。

过程中修掉的两个执行层问题（不影响语义）：`rust-toolchain.toml` 按 CWD 解析导致一次 E0514（改为在 crate 目录内执行）；llvm-dis 需按 capture-manifest 选择 sqlite3.c 对应位码而非通配。

### 结果

| 产物 | 比较 |
| --- | --- |
| `analysis/static-facts.jsonl` | **逐字节一致** |
| `contracts/rust-contracts.jsonl` | **逐字节一致** |
| `foreign/foreign-facts.jsonl` | **逐字节一致**（位码字节不同——内嵌路径不同；抽取事实不变） |
| `joint/joint-verdicts.jsonl` | **逐字节一致** |
| `plans/witness-plans.jsonl` | **逐字节一致** |
| 4 个客户端 `src/main.rs` | **逐字节一致** |
| `run/witness-summary.json` | **逐字节一致** |
| 执行结论 | 重放侧同样 **2 confirmed_counterexample + 2 clean**，verify-run 全过 |

### receipt 字段级归因

对两棵树的全部回执做字段级比较（先做 `/tmp/bw-p6-rerun → /tmp/bw-p6` 路径规范化）：

- **语义字段全部一致**：`outcome`（confirmed/clean）、`run_exit_code`、`build_exit_code`、sanitizer 错误类别（heap-use-after-free）、出错位置（main.rs:17）、`main_rs_sha256`、`foreign_source_sha256`、`toolchain`、`rustc_version`。
- **差异字段全部为路径派生**：`build_argv`/`run_argv`（绝对路径字符串）、`binary_sha256`（二进制内嵌编译路径）、`checksums.sha256`（登记了含路径的 Cargo.toml 的哈希）、个别 `stderr_tail`/`sanitizer_report.summary` 中的**符号元数据散列**（`_RNCNvCs2…` vs `_RNCNvCs9…`——CGU 散列随编译路径变化，错误类别与源位置不受影响）。

### 结论

判定链对相同输入**决定性**；receipt 可稳定重放，差异类别被完整归因为「绝对路径派生」一类且不影响任何语义字段。阶段 6 验收第 6 项通过。

---

## 二、Gate A1：Full vs Rust-only（同一候选域）

### 候选域固定

同一份 fixture Rust 契约（`callback-retention-relation@fixture`，5 条记录 = 4 装配 + 1 缺证，sha256 `7adbd19d…9950`）作为唯一 Rust 侧输入，外部实现取 4 个手写 C stub（`retain_late_invoke` / `_clearing` / `_leaky` / `synchronous_only`，IR 为入库的 `foreign/ir/*.ll`）。

- **Full 模式**：每个 stub 抽取外部行为事实后联结 → 16 条联结记录 × 每条 2 个 subject = **32 条三态判定**（与 stage5 历史 run 完全同构）。
- **Rust-only 模式**：同一契约文件 + **零记录外部事实文件**（sha256 `e3b0c442…b855`，即空）→ 联结器输出：`joined=0`、`no_foreign_counterpart=4`、verdicts 空。工具自身汇总文件确认整个候选域不可达 = **全局 abstain**。

### Full 模式关键区分（captured_referent subject）

| API | clearing（注销真清槽） | leaky（注销没清干净） | retain | synchronous |
| --- | --- | --- | --- | --- |
| `register_guarded` | **compatible_within_analyzed_fragment** | **insufficient_evidence**（进入 witness 义务链） | insufficient_evidence | compatible |
| `register_borrowed` | insufficient_evidence | insufficient_evidence | insufficient_evidence | compatible |
| `register_static_owned` | compatible | compatible | compatible | compatible |
| `register_static_then_free` | compatible（callback_allocation 上 insufficient_evidence，属另一 subject 形状） | 同左 | 同左 | compatible |

- **判据核心**：Full 在 guarded API 上把「注销真清槽」判为相容、「注销没清干净」降级为证据不足——**两者结果不同**。borrowed API 两者的区分按设计落在动态域（stage5 控制矩阵 `fixed_foreign_implementation` 在 clearing stub 上干净），静态三态如实保持相同。
- leaky stub 的额外槽位（`g_cached_callback`/`g_cached_user_data`）直接来自对其 IR 的分析而非任何预给定 API map——外部证据来源等级满足要求。

### 对照 [milestone-gates](../../roadmap/milestone-gates.md) 判据

| 检查 | 结论 |
| --- | --- |
| Full 能区分 clearing 与 leaky | ✅（guarded：compatible vs insufficient_evidence） |
| Rust-only 对两者给出相同结果或必须 abstain | ✅ 全局 abstain（0 联结，汇总文件为证） |
| No-Go：关闭外部分析后结果不变 | ❌ 未触发（16 行 → 0 行） |
| No-Go：增益来自更窄候选范围 | ❌ 未触发（Full 候选域严格包含 Rust-only 所见，后者为零） |
| No-Go：外部行为主要由 API map 预给定 | ❌ 未触发（槽位/保留/晚调证据均抽自真实 IR，RoleMap 只声明参数角色） |

**Gate A1 最小线：通过。**

### 边界

单 fixture 家族（callback-retention-relation）上的机制增益证明；跨库泛化归 Gate C0/C。比较单位为「subject 级三态判定」，全程一致。产物树 `/tmp/bw-a1`（`joint-full-all.jsonl` sha256 `285f1921…59af`）待纳入受管位置后随 D2 对齐升 `Verified`。

## 复现

```bash
# 重复运行重放：复制 /tmp/bw-p6 输入到独立树后按 stage6 记录复现节从零重跑，
# 再对每对产物 cmp -s；receipt 用路径规范化后字段级比较。
# Gate A1：
BW=<repo>; OUT=/tmp/bw-a1; RUN_ID=gate-a1-full-vs-rust-only-2026-08-23
export DYLD_FALLBACK_LIBRARY_PATH="$HOME/.rustup/toolchains/nightly-2026-07-08-aarch64-apple-darwin/lib"
# 1) wrapper 静态事实（allowlist 只含 callback_retention_relation lib；RUSTUP_TOOLCHAIN=nightly-2026-07-08）
cd $BW/benchmarks/compiler-fixtures/callback-retention-relation
RUSTC_WRAPPER=$BW/compiler/bw-rustc/target/debug/bw-rustc BW_RUSTC_CONFIG=$OUT/rustc-config.json \
  RUSTUP_TOOLCHAIN=nightly-2026-07-08 CARGO_TARGET_DIR=$OUT/target cargo check --locked
# 2) 契约
cd $BW && cargo run -p bw-cli --locked -- extract-rust-contracts --facts $OUT/analysis/static-facts.jsonl \
  --output-dir $OUT/contracts --run-id $RUN_ID --build-profile fixture-debug \
  --rust-artifact callback-retention-relation@fixture
# 3) Full：对 4 个 stub 各跑 extract-foreign-facts + judge-hand-offs（roles 见 contracts/callback-retention/）
# 4) Rust-only：judge-hand-offs 配零字节 foreign-facts 文件
# 5) 比较两模式在同一 (api_id, foreign_artifact, subject) 键上的三态
```
