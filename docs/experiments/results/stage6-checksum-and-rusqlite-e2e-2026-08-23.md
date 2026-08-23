# stage6 核心收口：witness 回执接入 checksum 清单 + rusqlite 0.26.1 真实组件端到端复验

日期：2026-08-23。run_id：`rusqlite-m12-e2e-2026-08-23`。
状态：**`Implemented`**——代码、测试与本记录的复现命令存在；正式 D2 对齐（与当前
commit、checksum、run ID 的正式证据链）仍属后续工作。本文不把它写成 `Verified`。

## 本轮做了什么

1. **witness 回执接入 checksum 清单体系**（stage6 收口的第一项）：
   - P3/P4 六条产物命令（`extract-rust-contracts`、`extract-foreign-facts`、
     `judge-hand-offs`、`plan-witnesses`、`generate-safe-client`、`run-safe-client`）
     全部在写出产物后登记 `checksums.sha256`，统一走共享的
     `crate::commands::write_checksums`；
   - `run-safe-client` 新增 `--target-dir`（默认 `<output-dir>-target` 兄弟目录），
     并把客户端 crate **暂存**（stage）到 `<target-dir>/staged-clients/` 再构建：
     cargo 会在 crate 目录写 `Cargo.lock`，直接在被校验的生成目录里构建必然产生
     `BW-V32-VERIFY-EXTRA-FILE`；
   - `verify-run` 对全部六个产物目录零容忍核对通过（2/2/2/3/10/2 个文件）。

2. **真实组件端到端**：RUSTSEC-2021-0128（M12，retained-borrowed-callback）。
   组件 rusqlite **0.26.1**（已 yank，API 直取 + sparse index checksum 校验一致），
   `Connection::update_hook<'c, F>(&'c self, hook: Option<F>) where F: FnMut(Action,
   &str, &str, i64) + Send + 'c`——缺 `'static`，闭包寿命绑到接收者寿命；0.26.2 修复
   为 `+ 'static`。外部实现是 libsqlite3-sys 0.23.2 bundled 的真实 sqlite3.c。

## 复现

```bash
export DYLD_FALLBACK_LIBRARY_PATH="$HOME/.rustup/toolchains/nightly-2026-07-08-aarch64-apple-darwin/lib"
BW=<repo>; OUT=<scratch>            # 本轮 scratch：/tmp/bw-p6
# 0) 组件与外部源
#    rusqlite-0.26.1 解包到 $OUT/src/rusqlite-0.26.1（rust-toolchain.toml 钉
#    nightly-2026-07-08；scratch 项目不自带 lockfile，故不加 --locked）。
#    sqlite3.c 取自 cargo registry 缓存 libsqlite3-sys-0.23.2，
#    sha256 前缀 dce7451fab8d2678，复制到 $OUT/sqlite3/sqlite3.c。
# 1) wrapper 静态事实（allowlist 只含 rusqlite lib）
RUSTC_WRAPPER=$BW/compiler/bw-rustc/target/debug/bw-rustc \
BW_RUSTC_CONFIG=$OUT/rustc-config.json \
CARGO_TARGET_DIR=$OUT/target cargo check --features bundled,hooks \
  --manifest-path $OUT/src/rusqlite-0.26.1/Cargo.toml
# 2) Rust 侧契约（1008 条事实 → 32 交出点 → 10 装配 / 22 缺证）
cargo run -p bw-cli --locked -- extract-rust-contracts --facts $OUT/analysis/static-facts.jsonl \
  --output-dir $OUT/contracts --run-id rusqlite-m12-e2e-2026-08-23 \
  --build-profile rusqlite-0.26.1/bundled/debug --rust-artifact rusqlite@0.26.1
# 3) 外部 IR：CC 换成 cc-capture 构建同一 crate 捕获 bitcode → llvm-dis
CC=$BW/tools/foreign-ir/cc-capture BW_REAL_CC=/opt/homebrew/opt/llvm@12/bin/clang \
BW_FOREIGN_IR_DIR=$OUT/foreign-ir CFLAGS_aarch64_apple_darwin="--sysroot=$(xcrun --show-sdk-path)" \
  <同上 cargo check>
/opt/homebrew/opt/llvm@12/bin/llvm-dis $OUT/foreign-ir/<sha16>.bc -o $OUT/sqlite3.ll   # 782,531 行
# 4) 外部行为事实（4.4 s）
cargo run -p bw-cli --locked -- extract-foreign-facts --ir $OUT/sqlite3.ll \
  --roles adapters/rusqlite/update_hook.foreign-roles.json --output-dir $OUT/foreign \
  --run-id rusqlite-m12-e2e-2026-08-23 \
  --foreign-artifact libsqlite3-sys/bundled-sqlite3@0.23.2 \
  --build-profile rusqlite-0.26.1/bundled/debug
# 5) 联结 → 计划 → 生成 → 运行
cargo run -p bw-cli --locked -- judge-hand-offs --rust-contracts $OUT/contracts/rust-contracts.jsonl \
  --foreign-facts $OUT/foreign/foreign-facts.jsonl --output-dir $OUT/joint \
  --run-id rusqlite-m12-e2e-2026-08-23
cargo run -p bw-cli --locked -- plan-witnesses --joint-verdicts $OUT/joint/joint-verdicts.jsonl \
  --rust-contracts $OUT/contracts/rust-contracts.jsonl --output-dir $OUT/plans \
  --run-id rusqlite-m12-e2e-2026-08-23
cargo run -p bw-cli --locked -- generate-safe-client --plans $OUT/plans/witness-plans.jsonl \
  --adapter <adapter TOML，见下> --repo-root $OUT --output-dir $OUT/clients
cargo run -p bw-cli --locked -- run-safe-client --clients-dir $OUT/clients \
  --controls <controls TOML> --toolchain nightly --output-dir $OUT/run
# 6) 每个产物目录 verify-run
```

adapter 与 controls 是本轮的 scratch 产物（外部源路径指向 scratch，不入库），全文
见下文「冻结记录」。

## 判定链（真实数据）

| 阶段 | 数量 | 说明 |
| --- | --- | --- |
| 静态事实 | 1008 | bw-rustc 对 rusqlite lib 的全部观察 |
| 交出点 | 32 | 22 个缺证是正确拒绝（trampoline/行映射闭包不过 FFI 等） |
| 装配契约 | 10 | `update_hook` 链 3 条 + 其它 hooks API |
| 联结 | 2 | `sqlite3_update_hook` 两个 Rust 层级（Connection / InnerConnection），0 拒绝 |
| 计划 | 3 + 1 拒绝 | 2× `borrowed_capture_escaping_scope`（captured_referent）+ 1× `allocation_freed_by_wrapper`；`insufficient_evidence_without_obligation` 拒绝 1 |
| 客户端 | 4 | 2 计划 × {primary, no-trigger} |
| 执行 | 4 | **2 `confirmed_counterexample` + 2 `clean`**，控制违规 0 |

联结判定（公开入口级）：

- `static_verdict: insufficient_evidence`、`evidence_grade: same_slot_invoke_candidate`、
  `witness_obligation: establish_late_invoke`；
- 假设显式记录：同符号多静态注册点需要 witness 归属；晚调只有同槽位间接调用证据。
- Rust 契约：`capture_admission: permits_non_static_capture`（编译器确认 M12 形状）、
  `guard: none`、`registration_generation: multiple_static_sites`。
- 外部事实（真实 sqlite3 IR）：`may_retain` + `may_invoke_after_return`（槽位
  `%struct.sqlite3[0.51]/[0.52]`），Q4′ `unresolved`（clear 只在部分路径可证）。

ASan 证据（primary 客户端，`#![forbid(unsafe_code)]` 的纯安全客户端）：

```
ERROR: AddressSanitizer: heap-use-after-free ... READ of size 8
  #0 main.rs:17            ← 闭包体 black_box(*payload)（对失效堆块的真实读取）
  #1 rusqlite hooks.rs:527 call_boxed_closure   ← 插桩 trampoline
  #7 sqlite3VdbeExec       ← INSERT 的写执行路径
```

栈轨迹与静态侧预言完全一致：写操作经 sqlite3 → trampoline → 客户端闭包解引用
已释放内存。no-trigger 控制（同一客户端删掉触发步）干净退出——晚调确实由
`establish_late_invoke` 义务对应的触发动作引起。

## 本轮修掉的三个真实缺陷

fixture 太小，以下问题只有真实组件能暴露：

1. **lineage 全局完整性一刀切**（`compiler/bw-rustc/src/rustc_api/mir.rs`
   `safe_entry_lineages`）：crate 里任何一处解析不出被调方的间接调用都会把**全部**
   交出点的 safe-entry lineage 打成 `Unresolved`（`lineage_call_graph_incomplete`），
   32 个交出点 0 装配。修复保持语义方向不变：**正向证明不依赖全局完整性**——
   入口本身是公开安全 fn（0 跳，不需要调用边）、沿已解析 FnDef 边反向可达公开安全
   入口（未解析边只会增加 caller、不会推翻已有路径）都直接成立；只有**否定性**
   结论（NoPublicSafeEntry）在图不完整时降级 `Unresolved`。fixture golden 测试不变。
2. **userdata 角色误判**（同文件，foreign call 参数扫描）：不约束「回调之后」，导致
   `sqlite3_update_hook(db, cb, pArg)` 的 db 指针（下标 0）被记成 userdata；联结被
   `UserDataRoleMismatch` 正确拒绝（外部 RoleMap 说 2，Rust 侧报 0——交叉校验按
   设计工作）。修复：userdata 只在 callback_arg_index 之后找。
3. **闭包参数类型推断失败**（生成器）：带环境捕获的闭包交给高阶 fn trait 边界时
   nightly 求解器报「implementation of `FnMut` is not general enough」。修复：生成
   闭包按 `callback_signature` **显式标注参数类型**（公开签名的转写，不含行为语义），
   实测可编译并触发。

## 生成引擎为真实组件扩展的 adapter schema（全部是公开 API 形状数据）

- `[target] features = [...]`：组件依赖的 feature（rusqlite 需要 bundled/hooks）；
- `[target] links_foreign_directly = false`：组件自带外部库时客户端不再写 build.rs
  链第二份 sqlite3（符号会冲突）；checksum 清单按实际写出文件登记；
- `[[registration_forms]] wraps_callback_in_option = true`：`update_hook(Option<F>)`
  形状生成 `Some(callback)`；
- `callback_signature` 的参数列表用于闭包元数与显式类型标注。

Gate B 纪律：adapter 在 rusqlite 尚无任何 P3 判定时冻结
（`p3_verdict_available_at_freeze = false`），只描述如何合法调用 API。

### 冻结记录（scratch 全文）

```toml
schema_version = "bw.adapter/0.1"
adapter_id = "adapter:rusqlite:update_hook"
[freeze]
frozen_at = "2026-08-23T10:50:37Z"
frozen_at_commit = "208f47707ef57566124743c728d73059aefa7e19"
p3_verdict_available_at_freeze = false
authored_from = "rusqlite 公开 API 文档与 sqlite3 update hook 的公开文档；签名形状取自公开类型 FnMut(Action,&str,&str,i64)"
[target]
crate = "rusqlite"
version = "0.26.1"
path_from_repo_root = "src/rusqlite-0.26.1"
edition = "2018"
features = ["bundled", "hooks"]
links_foreign_directly = false
[[setup]]
step = "open_connection"
rust = "let conn = rusqlite::Connection::open_in_memory().unwrap();"
[[setup]]
step = "create_table"
rust = "conn.execute_batch(\"CREATE TABLE t (v INTEGER)\").unwrap();"
[[registration_forms]]
form = "non_static_capture"
methods = ["update_hook"]
callback_signature = "FnMut(rusqlite::hooks::Action, &str, &str, i64)"
wraps_callback_in_option = true
returns_guard = false
[trigger]
step = "perform_write"
rust = "conn.execute(\"INSERT INTO t (v) VALUES (1)\", []).unwrap();"
foreign_symbol = "sqlite3_update_hook"
requires_component_trigger = true
[[foreign_build]]
id = "bundled-sqlite3"
source = "sqlite3/sqlite3.c"
provides_trigger_symbol = true
[teardown]
step = "drop_connection"
rust = "drop(conn);"
```

控制矩阵（2 条）：primary/primary 变体 → `confirmed`；no_trigger 角色/no_trigger
变体 → `clean`。**教训**：控制条目的 `role` 必须按角色命名（no_trigger 条目写
`role = "primary"` 时，聚合器会把 clean 收据当主证据，计划被正确降级为
`inconclusive`——语义护栏按设计工作，是配置写错了）。

## 测试

- `cargo fmt --all --check`：干净。
- `cargo test -p bw-model --locked`：28 项通过。
- `cargo test -p bw-cli --locked`：171 项通过（含 7 项链路集成测试与新增的
  closure_params / 真实组件形状单测）。
- `(cd compiler/bw-rustc && cargo test --locked)`：70 项通过（fixture golden 不变，
  证明两处 wrapper 修复对既有完整调用图场景零回归）。

## 边界与下一步

- 本轮结果按纪律只标 `Implemented`；正式 D2 对齐需要把 scratch 产物（adapter、
  controls、组件源）纳入受管位置并重跑正式记录。
- `allocation_freed_by_wrapper` 计划（InnerConnection 层的
  `rust_retains_and_may_free_early`）本轮未生成客户端运行（其 primary 判定属于
  同一符号的另一个交出点）；后续可补对应 controls。
- 固定侧（0.26.2）判别目前只在**静态侧**成立：`+ 'static` 界让借用闭包在编译期
  被拒（compatible 拒绝路径）。动态侧的固定组件控制需要独立计划，未在本轮范围。
- sqlite3 IR 提取性能实测 4.4 s（782,531 行文本 IR），无性能问题。
