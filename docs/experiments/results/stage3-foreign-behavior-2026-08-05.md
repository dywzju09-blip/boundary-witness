# 阶段 3：从真实 IR 读取外部侧行为

- 日期：2026-08-05
- 执行计划：[execution plan](../../roadmap/execution-plan.md) 阶段 3.1–3.4
- 状态：**四个 matched fixture 全部通过，参考目标上的 V1 通过。** Q4′ 第一次从 IR 分开了
  fixture 2 与 fixture 3

## 1. 工具链选择：不链接 LLVM

新建 `crates/bw-foreign-ir`，读 `llvm-dis` 产出的**文本 IR**，进程内不链接任何 LLVM 库。

理由不是省事，是本项目已经撞过的一堵墙：编译器前端链着 `rustc_driver`，它自带一份
LLVM；再链 `llvm-sys` 就是
[baseline comparison](../runbooks/baseline-comparison.md) 里记的那个冲突——FFIChecker
正是栽在这里。

| | 用法 | 代价 |
| --- | --- | --- |
| `clang` / `llvm-dis` | 外部命令 | 阶段 2 已在用，零额外风险 |
| `llvm-sys` / `inkwell` | 进程内链接 | 与 `rustc_driver` 的 LLVM 冲突 |

读取器是**有界**的：只认 `alloca` / `store` / `load` / `getelementptr` / `call` /
`icmp` 与终结指令，其余归为未知并沿数据流传播成缺证。

### 为什么这点分析够用

目标 IR 是 `-O0` 带 debug info 的（cargo dev profile 下 `cc` 的默认，也就是阶段 2 实际
捕获到的形状）。形参先 `store` 进 `alloca`、用时再 `load`，数据流是显式的。

**换 profile 前提就不成立**：`-O2` 下 alloca 被消掉、函数被内联，需要另一套分析。分析
用的 profile 必须与捕获时一致。

## 2. matched fixture 结果（3.1–3.3）

输入是四个 C stub 由 clang 14 直接产出的 IR，见
`benchmarks/compiler-fixtures/callback-retention-relation/foreign/ir/`。

| fixture | Q1 保留 | Q3 晚调 | Q4′ 清槽 | 路径 |
| --- | --- | --- | --- | --- |
| 1 `retain_late_invoke` | MayRetain，2 槽位 | MayInvokeAfterReturn（候选级） | Unresolved（无注销符号） | RetainOnEveryPath |
| 2 `retain_late_invoke_clearing` | MayRetain，2 槽位 | 同上 | **ClearsOnAllPaths** | RetainOnEveryPath |
| 3 `retain_late_invoke_leaky` | MayRetain，**4 槽位** | 同上（含回退路径） | **MayLeaveSlotPopulated** | RetainOnEveryPath |
| 负对照 `synchronous_only` | **NoRetain**，0 槽位 | SynchronousInvokeOnly | Unresolved | Unresolved |

### 判别力落在哪里

**fixture 2 与 3 的 Rust 侧完全相同**，两者的 Q1 与 Q3 结论也完全相同。分开它们的只有
Q4′，而 Q4′ 的判别力来自 Q1 找全了槽位集合：

- leaky stub 注册时写四个槽位，注销只清两个 → 另外两个是 `NotWritten`；
- clearing stub 注册写两个、注销清两个 → 全部 `WritesNullOnEveryPath`。

端到端接上 `bw_model::judge` 之后，同一份 Rust 契约事实得到不同判定，且 leaky 那侧的
证据等级是 `GuardDefeated`。Rust-only 变体在同一输入上只能得出 `InsufficientEvidence`
——**外部侧的净贡献是可测的**。

### 这些测试不是空的

把 Q1 改成「每个参数只记第一个槽位」这一处变异，16 条断言里有 6 条转红，其中包括端到端
那条：leaky 被判成 `CompatibleWithinAnalyzedFragment`，正是要防的漏报。

## 3. 参考目标上的 V1（3.1 纵向检查）

对象是阶段 2 从 `rusqlite` 0.26.1 真实构建里捕获的 `sqlite3.c` bitcode。

```
外部 artifact  sqlite3.c:dce7451f…0524
RoleMap        adapters/rusqlite/update_hook.foreign-roles.json
```

| 项 | 结果 |
| --- | --- |
| Q1 | `MayRetain`，槽位 `%struct.sqlite3[0.52]`（回调）与 `[0.51]`（user data） |
| Q3 | `MayInvokeAfterReturn`，`sqlite3VdbeExec` 里 **2 个真实间接调用点**，证据等级 `SameSlotInvokeCandidate` |
| Q4′ | `Unresolved`，原因 `ClearOnlyOnSomePaths` ×2 |
| 路径 | `RetainOnSomePaths` |

**V1 通过**：Rust 交出点指向的外部符号在真实 IR 里连接到了真实的外部槽位，且那两个字段
下标与人工阅读源码得到的一致。

## 4. 过程中发现并修掉的三个缺陷

这一节留着，因为三条都不是打字错误，而是判定纪律上的错误。

### 4.1 认不出的指令不进使用点索引

Q1 的否定结论（`NoRetain`）建立在**枚举全了指针的每一个使用点**之上。最初的实现对读不懂
的指令返回空操作数列表，于是那些使用点是隐形的——否定结论就建立在「我们没看见」上。

改为：读不懂的指令退化为扫原文里的 `%` token。宁可多记几个不存在的名字，不能漏一个真实
使用点。同时把 `icmp` 单列为 `Compare`，否则 `if (callback)` 这种判空会被算成逃逸，负
对照永远得不出结论。

### 4.2 槽位身份里混进了「基址怎么来的」

最初要求字段槽位的基址来自形参，否则不认。真实 sqlite3 上的后果是：注册函数里 `db` 是
形参，派发函数 `sqlite3VdbeExec` 里是 `p->db`，于是 **5 个调用点全部丢失**，Q3 直接变成
缺证。

槽位身份应当只是「哪个结构体类型的哪个字段」。「跨调用存活」是 Q1 单独需要的论证，改为
独立的 caller-owned 判定，不进身份。修完之后 Q3 在真实目标上找到了调用点。

### 4.3 入口参数校验被当成了 guard 被击穿

`sqlite3_update_hook` 开头是：

```c
if( !sqlite3SafetyCheckOk(db) ){ return 0; }
```

于是写槽位的 store 只落在两条返回路径中的一条上。最初的聚合把「写了但不在所有路径上」
和「根本没写」并成同一类 `MayLeaveSlotPopulated`，结果真实 sqlite3 被判成 guard 被击穿。

**照这个走法，每一个带入口参数校验的 C API 都会被判成 guard 被击穿，Q4′ 到规模上就没有
判别力了。** 改为：只有 `NotWritten` 才是 `MayLeaveSlotPopulated`；「部分路径」降级为
缺证并记 `ClearOnlyOnSomePaths`。fixture 2 与 3 的分离不受影响——leaky 的信号正是
`NotWritten`。

## 5. 这一步证明了什么，没证明什么

**证明了**：

- 外部侧行为结论可以只从真实构建的 IR 得出，RoleMap 只参与符号与参数角色绑定；
- Q4′ 在 matched fixture 上有判别力，且这份判别力 Rust-only 拿不到；
- 在一个真实库上，Q1 与 Q3 都能落到指令级证据。

**没证明**：

- **Q4′ 在真实目标上还没有结论。** sqlite3 上是缺证，原因已定位到入口校验的提前返回。
  要给出结论需要区分「正常路径」与「参数校验失败路径」，这超出首期分析片段；
- **Q3 仍是降级的。** 找到的是同槽位间接调用点，不是晚调可达性。输出固定为
  `InsufficientEvidence` 加一条 `EstablishLateInvoke` 反证义务；
- **两侧还没有联结。** 产物里刻意没有 `HandOffId`——身份要两侧各出一半，那是阶段 4 的
  P0。填占位身份只会诱使别人拿去 join；
- **单库。** 与阶段 2 同样的限制：rusqlite 是开发对象，结果不进精度主表。

## 6. 复现

```bash
# 捕获（阶段 2 的包装器，产物落在持久路径）
export BW_FOREIGN_IR_DIR=<results-root>/foreign-ir/rusqlite-0.26.1
export BW_REAL_CC=clang
export CC=<repo>/tools/foreign-ir/cc-capture
cd benchmarks/historical-cves/rusqlite/update-hook/vulnerable && cargo build

# 转文本并提取
llvm-dis-14 "$BW_FOREIGN_IR_DIR/<hash>.bc" -o "$BW_FOREIGN_IR_DIR/sqlite3.ll"
bw extract-foreign-facts \
  --ir "$BW_FOREIGN_IR_DIR/sqlite3.ll" \
  --roles adapters/rusqlite/update_hook.foreign-roles.json \
  --output-dir "$BW_FOREIGN_IR_DIR/facts" \
  --run-id <run> --foreign-artifact <source-sha256>
```

> 阶段 2 那次捕获的产物没有留在持久路径上，本次已不可用，因此重跑了一遍，并把捕获目录
> 改到结果根目录下的固定位置而不是临时目录。**捕获目录必须是持久路径**，否则复现要连
> 构建一起重来。bitcode 与文本 IR 留在远端，**不进公开仓库**（见
> [data alignment](../data-alignment.md)）。
