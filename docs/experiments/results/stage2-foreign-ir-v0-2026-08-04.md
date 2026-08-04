# 阶段 2：参考目标的真实外部 IR 与 V0 绑定

- 日期：2026-08-04
- 执行计划：[execution plan](../../roadmap/execution-plan.md) 阶段 2.1–2.4
- 代码 commit：`809cc2f`
- 状态：**2.1–2.3 完成，2.4 的 V0 检查通过。** 这是纵向闭环的第一段真实外部证据

## 1. 参考目标（2.1）

| 项 | 值 |
| --- | --- |
| crate | `rusqlite` |
| vulnerable / fixed | `0.26.1` / `0.26.2`（RUSTSEC-2021-0128） |
| feature | `bundled`, `hooks` |
| 外部库 | SQLite，由 `libsqlite3-sys` 的 `bundled` feature **随构建从源码编译** |
| IR tier | **L1** |

选它的理由只有三条：有历史 vulnerable/fixed pair、构建可控、外部源码随构建提供。

> **它不代表泛化性。** rusqlite 是本项目的主开发对象，按 [research thesis §7.6](../../project/research-thesis.md) 属于开发集，
> **其结果永远不能进精度主表**。首个目标的唯一作用是打通纵向闭环。跨库可行性由
> [Gate C0](../../roadmap/milestone-gates.md) 单独回答。

### adapter 已冻结

`adapters/rusqlite/update_hook.toml`，冻结于 `809cc2f` / `2026-08-04T16:57:00Z`。

**冻结时本目标没有任何 P3 判定**——P1/P2 外部侧分析尚未实现，所以不存在"看着判定结果补
触发信息"的可能。这一点是 [Gate B](../../roadmap/milestone-gates.md) 判据的前提，因此
连同 commit 与时间戳一起写进 adapter 自身。

adapter 只描述如何合法使用 API：开连接、建表、注册回调、执行一次写入触发回调、关连接。
**不含 drop 时机、不含触发缺陷的顺序、不含预期结果。**

## 2. 构建捕获与 IR 获取（2.2 / 2.3）

`tools/foreign-ir/cc-capture` 作为 `CC` 交给 cargo。对每一次真实的 C 编译，它先原样调用
真实编译器产出构建需要的目标文件，再用**同一组参数**重跑一次 `-emit-llvm -c`。

**同一组参数是关键。** 执行计划明确要求不得另编一份"相似的 C 源码"——宏、include path、
优化级别任何一项不同，得到的 IR 就不是这次构建里的那份代码。

每次捕获追加一条 manifest，含源文件、目标文件、bitcode 与参数的 SHA-256。捕获失败也写
一条 `capture_failed` 记录：**静默丢弃会让 IR 覆盖率虚高**。

### 本次结果

| 指标 | 值 |
| --- | --- |
| 捕获的编译单元 | 40 |
| 捕获失败 | 0 |
| 其中目标外部库 | `sqlite3/sqlite3.c` |
| 环境 | clang 14.0.0，`llvm-dis-14` |

捕获里同时出现了 `zstd/lib/**`——它是依赖链上另一个 C 库。这不是噪声：它说明包装器捕获
构建中**全部** C 编译，由 manifest 决定哪一份对应目标交出点。

## 3. V0 纵向检查（2.4）

**问题**：Rust 侧的交出点能否绑定到正确的外部 artifact 与符号。

`rusqlite::Connection::update_hook` 交给的外部符号是 `sqlite3_update_hook`。在捕获的
bitcode 中检索：

```text
sqlite3/sqlite3.c -> 893cfdb54c1457e6.bc
FOUND: define ... sqlite3_update_hook
```

**该符号在从真实构建捕获的 IR 里有定义。** V0 通过。

## 4. 这一步证明了什么，没证明什么

**证明了**：能从目标 crate 的真实构建里取得与该次构建对应的外部 LLVM IR，并在其中定位到
Rust 交出点所指向的外部符号。这是 P1/P2 全部工作的输入前提。

**没证明**：

- **没有做任何行为分析。** Q1（逃逸）、Q3（晚调）、Q4′（清槽）都还没实现，本次只确认
  IR 可得、符号可定位；
- **绑定还不是 `HandOffId` 级的。** 当前是"符号名在 IR 里有定义"，还没建立
  artifact hash → 符号 → 参数角色 → 槽位 → registration generation 的分层身份，那是 P0；
- **单库。** 见上，不代表泛化性。

## 5. 复现

```bash
export BW_FOREIGN_IR_DIR=<capture-dir>
export BW_REAL_CC=clang
export CC=<repo>/tools/foreign-ir/cc-capture
cd benchmarks/historical-cves/rusqlite/update-hook/vulnerable
cargo build
```

manifest 在 `$BW_FOREIGN_IR_DIR/capture-manifest.jsonl`。

按 [VPS 与本地工作流](../../development/vps-local-workflow.md)，构建在远端执行；bitcode
与目标文件留在远端，**不进公开仓库**（见 [data alignment](../data-alignment.md)）。
