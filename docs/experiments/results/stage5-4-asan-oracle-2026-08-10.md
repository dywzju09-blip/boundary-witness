# 阶段 5.4：ASan 执行与独立 oracle 出证

- 日期：2026-08-10
- 执行计划：[execution plan](../../roadmap/execution-plan.md) 阶段 5.3/5.4
- 状态：**vulnerable（rusqlite 0.26.1）在 ASan 下触发 heap-use-after-free，独立
  oracle 出证。** 证据链完整：safe-only 客户端 → rusqlite trampoline → SQLite
  VDBE 晚调 → 访问失效对象。

## 1. 证据链（ASan 栈帧，完整回查）

```
ERROR: AddressSanitizer: heap-use-after-free on address 0x7b4a70ae0710
READ of size 8
  #0  Vec<u8>::len / String::len
  #1  main::{closure#0}          harness 回调访问失效对象（main.rs:19:34）
  #2  InnerConnection::update_hook::call_boxed_closure  rusqlite trampoline（hooks.rs:527）
  #8  sqlite3VdbeExec             SQLite VDBE 执行（sqlite3.c:92015）——INSERT 的晚调路径
  #11 sqlite3_step
  #14 Statement::execute
  #20 main                       INSERT 语句（main.rs:23）
```

- harness 源码：`#![forbid(unsafe_code)]`，创建 `Box<String>` → 闭包借用并访问 →
  注册 → `drop(witness_referent)` → INSERT 触发 SQLite 晚调 → 闭包读失效对象；
- 链接 vendored rusqlite 0.26.1 + bundled sqlite3（与静态分析同源的精确外部构建）；
- 独立 oracle = ASan（nightly-2026-07-08，`RUSTFLAGS=-Zsanitizer=address`）；
- 运行退出码 1（ASan abort），日志 2 处 `heap-use-after-free`；
- artifact hash：`src/main.rs=03f7c4a7…`、`Cargo.toml=ed8e29b6…`、
  `asan-vulnerable-0.26.1.log=d950fe27…`（远端 `<results-root>/stage5-4/`）。

## 2. 两个必须写下来的坑

### 2.1 Rust ASan 的栈 use-after-scope 检测不可靠

第一版 referent 是栈上 `String`。晚调**确实发生且成功读到失效对象**（一次性验证
脚本打印 `CALLBACK-INVOKED len=19`，脚本已删除）——但 ASan 无任何报告。这是
rust-lang 已知限制：Rust 的 `-Zsanitize=address` 对 Rust 栈变量的
stack-use-after-scope 插桩不完整（[research thesis §11.31] 预言的 oracle 缺口）。

**oracle 适配**：referent 改用堆对象 `Box<String>`。失效后访问变成
heap-use-after-free——ASan 对堆的检测可靠。**缺陷形状不变**：referent 真实失效、
注册真实存活、外部真实晚调、回调真实访问失效对象。这是 oracle 选型，不是放宽判据。

[research thesis §11.31]: ../../project/research-thesis.md

### 2.2 生成器的注册调用不能写死 `?`

`conn.update_hook(...)` 返回 `()`，`?` 编不过。已在 5.3 修复为 `let _ = ...;`
（对 `()` 与 `Result` 都成立），本次执行确认。

## 3. 复现

```bash
# 生成（5.3 产物）
bw generate-witness-harness --adapter adapters/rusqlite/update_hook.toml \
    --contracts <results-root>/stage5-2/rust-contracts/rust-contracts.jsonl \
    --verdicts <results-root>/stage5-2/joint/joint-verdicts.jsonl \
    --repo-root <repo> --output-dir <results-root>/stage5-3/harness-vulnerable \
    --run-id stage5-3-2026-08-10
# ASan 构建 + 运行
cd <results-root>/stage5-3/harness-vulnerable
RUSTUP_TOOLCHAIN=nightly-2026-07-08 RUSTFLAGS="-Zsanitizer=address" cargo build
./target/debug/bw-witness-adapter_rusqlite_update_hook-0_26_1  # 预期 ASan abort
```

## 4. 这一步证明了什么，没证明什么

**证明了**：

- 从 5.2 的静态判定产物自动生成的 safe-only harness，在精确外部构建上真的触发
  释放后使用，独立 oracle（ASan）给出可回查的栈证据——**C1 的纵向闭环成立**；
- 晚调由 SQLite 真实执行路径触发（`sqlite3VdbeExec` 在 INSERT 语句的 VDBE 循环里
  调用 update hook），不是模拟 runtime 事件；
- 回调实际访问失效对象（`String::len` 读 freed 内存），不是空转；
- 栈 use-after-scope 的 ASan 盲区被实测确认，堆对象适配后出证。

**没证明**：

- **fixed（0.26.2）与负对照矩阵。** 未触发统一记 Inconclusive 的口径、fixed 的
  「编不过」、owned / unregister-before-drop / no-trigger / 同步外部实现四类负对照
  都没有跑——那是 5.5；
- **X=A（回调分配提前释放）形状。** 当前 harness 只覆盖 referent 分离；`'static`
  回调 + `Box<F>` 提前释放的分配类缺陷没有生成器形状；
- **不是「该 API 在所有配置下都不健全」。** 出证只绑定 pinned 构建（vendored
  0.26.1 + bundled + hooks）；按 [research thesis §12] 分级，这是 executable
  counterexample，不是普遍结论；
- **确定性。** 单次运行出证；ASan 对堆 UAF 是确定性的，但正式数字需要重复运行与
  receipt（5.5 补）。

[research thesis §12]: ../../project/research-thesis.md
