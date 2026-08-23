# 阶段 5（P4）：反证合成端到端——2026-08-08

执行计划阶段 5.0–5.4 的结果记录。上游输入是 [stage4](stage4-joint-closure-2026-08-06.md)
的三态判定；本文回答「判定能不能变成可执行、可复核的反例」。

## 结论

| 判据 | 结果 |
| --- | --- |
| 判定 → 反证计划（5.1） | ✅ 7 计划 / 25 拒绝，全部拒绝带原因 token |
| 计划 → safe-only 客户端（5.2） | ✅ 18 个 `#![forbid(unsafe_code)]` crate，语句↔步骤覆盖有结构断言 |
| 客户端 → 独立 oracle 回执（5.3） | ✅ 7 primary 全部触发 `heap-use-after-free` |
| 控制矩阵（5.4） | ✅ 19 个控制组全部干净，判别对成立 |
| 三态纪律 | ✅ 无一例把 Inconclusive 写成证伪；无第四种状态 |

## 流水线与产物

```text
fixture 源码 ──bw-rustc──→ 44 条静态事实
                ↓ extract-rust-contracts      run_id = p4-fixture-2026-08-08
              4 契约 + 1 gap
C stub ──clang──→ IR ──extract-foreign-facts──→ 每 stub 1 个槽位联结
                ↓ judge-hand-offs ×4 stub     （16 条联结记录，32 条判定）
   合并 joint-verdicts.jsonl
                ↓ plan-witnesses              7 plans / 25 refusals
                ↓ generate-safe-client        18 crates / 0 refusals
                ↓ run-safe-client             26 executions → 7 confirmed / 19 clean
```

新命令（`crates/bw-cli`）：`plan-witnesses`、`generate-safe-client`、`run-safe-client`。
生成引擎在 `commands/safe_client.rs`；模型层规划器在 `crates/bw-model/src/witness.rs`
（schema `bw.witness-plan/0.1`、`bw.safe-client/0.1`、`bw.witness-receipt/0.1`、
`bw.controls/0.1` 已在协议注册表集中登记）。

## 计划分布（7 个）

| API | 形状 | 判定所属外部实现 |
| --- | --- | --- |
| `Registry::register_borrowed` ×3 | `BorrowedCaptureEscapingScope` | retain / clearing / leaky 各一 |
| `Registry::register_guarded` ×1 | `GuardDefeatedBypass` | leaky |
| `Registry::register_static_then_free` ×3 | `AllocationFreedByWrapper` | retain / clearing / leaky 各一 |

输入类别全部是 `EstablishLateInvoke`——降级 Q3 的合法输入形状。这验证了 ADR-0004
的关键约束：P4 的第一道门必须接受「缺证 + 义务」，否则首期实现零输入。

25 条拒绝的构成：24 条 `verdict_compatible_nothing_to_witness`（相容判定本就不需要
反例），1 条 `insufficient_evidence_without_obligation`（plain stub 上 guard 无击穿
证据——该 stub 根本没有注销入口）。**没有一条拒绝被静默吞掉。**

## oracle 结果

26 次执行（7 primary + 19 控制），0 跳过：

| 结果 | 数量 |
| --- | --- |
| `confirmed_counterexample` | 7（每个计划的 primary） |
| `clean` | 19（全部控制组） |
| build 失败 / 执行失败 | 0 |

三个 API 形状的 primary 都产出同一 oracle 类的证据：
`AddressSanitizer: heap-use-after-free`（READ of size 8，落在客户端闭包体，
经组件 trampoline 到达）。

## 控制矩阵与判别力

控制矩阵是判决后产物（[experiments/configs/p4-fixture-controls.toml](../../../experiments/configs/p4-fixture-controls.toml)，
schema `bw.controls/0.1`），声明 role × build_id × client_variant × expectation。
全部按预期通过：

| 控制 | 覆盖 | 含义 |
| --- | --- | --- |
| `fixed_foreign_implementation` | guarded 计划 ×clearing stub | **同一客户端**，注销真的清槽时干净——fixture 2/3 的差别进入动态领域 |
| `owned_callback_client` | allocation 计划 ×3 | 分配归闭包自己所有时干净——缺陷根源确是 wrapper 的提前回收 |
| `unregister_before_drop` | guarded 计划 | 触发早于任何失效动作时干净——时序是必要条件 |
| `no_trigger` | 全部 7 计划 | 省掉触发步即无晚调 |
| `synchronous_foreign_implementation` | 全部 no-trigger 客户端 | 同步 stub（无 trigger 符号、无存储）配机械省略触发的客户端 |

## 过程中修掉的两个真实缺陷

1. **闭包体传引用而非解引用**。首版模板写 `black_box(&*payload)`：只把指针值交给
   不透明函数，已释放堆块从未被读，oracle 全程沉默（4 个 Inconclusive）。改为
   `black_box(*payload)` 后 UAF 立即触发。教训进了单测：生成物必须包含解引用加载，
   否则「合成成功、证据为零」。
2. **primary 聚合按 client_variant 查找**。`fixed_foreign_implementation` 也跑 primary
   变体客户端，字典序又排在前面，guarded 计划被 fixed 控制的 clean 结论顶替成
   Inconclusive。改为按 control_role 查找。教训：聚合键必须用语义角色，不能用变体名。

## 决定性与回执

- `plan-witnesses` 重跑逐字节一致（plans/refusals/summary 三份产物 diff 为空）；
- 每次执行一条回执（`bw.witness-receipt/0.1`）：外部源 sha256、main.rs sha256、
  binary sha256、stderr sha256+尾部、sanitizer 结构化报告、可重放 argv、工具链版本；
- 聚合闸门：任一控制组违反预期，整个计划降级回 `Inconclusive` 并留下显式违规清单。

## 这一步证明了什么，没证明什么

**证明了**：

- 从三态判定到「带收据的可执行反例」整条链一条命令跑通，且输出决定性；
- 反证客户端不含任何 unsafe（`#![forbid(unsafe_code)]`），UB 只能来自被分析组件；
- 降级 Q3 的义务（EstablishLateInvoke）由动态侧补上后，三个形状都能升级为
  `ConfirmedCounterexample`——静态缺证不是终点；
- 控制矩阵能把「反例成立」与「我们对组件行为的理解正确」同时钉住。

**没证明**：

- 单库单 fixture 家族。跨库泛化仍归 [Gate C]；
- `SupportedIncompatibility` 输入类别在本轮 fixture 上没有自然样本（Q3 降级使然），
  该分支只由模型层测试覆盖，端到端未走过；
- Stack-use-after-scope 证据类只有设计，没有样本；
- 真实 rusqlite（非 fixture 组件）的 P4 链路未跑；
- 回执尚未接入 verify-run 的 checksum 清单体系。

## 复现

```bash
# Rust 侧静态事实（wrapper 固定 nightly-2026-07-08；macOS 本机需 DYLD_FALLBACK_LIBRARY_PATH）
export DYLD_FALLBACK_LIBRARY_PATH="$HOME/.rustup/toolchains/nightly-2026-07-08-aarch64-apple-darwin/lib"
RUSTC_WRAPPER=<bw-rustc> BW_RUSTC_CONFIG=<config> cargo check \
  --manifest-path benchmarks/compiler-fixtures/callback-retention-relation/Cargo.toml

cargo run -p bw-cli --locked -- extract-rust-contracts --facts <analysis>/static-facts.jsonl \
  --output-dir <out>/contracts --run-id p4-fixture-2026-08-08 \
  --build-profile fixture-debug --rust-artifact callback-retention-relation@fixture

# 每个 C stub 一次
cargo run -p bw-cli --locked -- extract-foreign-facts --ir foreign/ir/<stub>.ll \
  --roles contracts/callback-retention/callback-retention.foreign-roles.json \
  --output-dir <out>/foreign/<stub> --run-id p4-fixture-2026-08-08 \
  --foreign-artifact callback-retention/<stub> --build-profile fixture-debug

cargo run -p bw-cli --locked -- judge-hand-offs --rust-contracts ... --foreign-facts ... \
  --output-dir <out>/joint/<stub> --run-id p4-fixture-2026-08-08

cat <out>/joint/*/joint-verdicts.jsonl > joint-verdicts-all.jsonl
cargo run -p bw-cli --locked -- plan-witnesses --joint-verdicts joint-verdicts-all.jsonl \
  --rust-contracts ... --output-dir <out>/plans --run-id p4-fixture-2026-08-08
cargo run -p bw-cli --locked -- generate-safe-client --plans <out>/plans/witness-plans.jsonl \
  --adapter adapters/callback-retention-relation.toml --output-dir <out>/clients --repo-root .
cargo run -p bw-cli --locked -- run-safe-client --clients-dir <out>/clients \
  --controls experiments/configs/p4-fixture-controls.toml \
  --toolchain nightly --output-dir <out>/run
```

测试：`cargo test -p bw-cli --locked`（169 项，含 51 项引擎/关联单测与 5 项链路集成测试）、
`cargo test -p bw-model --locked`（28 项）、`(cd compiler/bw-rustc && cargo test --locked)`（70 项）。
