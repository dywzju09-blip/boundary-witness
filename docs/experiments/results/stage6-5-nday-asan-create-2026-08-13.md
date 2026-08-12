# 阶段 6.5（出证）：create_scalar_function / create_collation ASan 出证

- 日期：2026-08-13
- 前置：能力①（userdata 角色，54d289b）+ 能力②（堆逃逸追踪，dcc76e7）
- 状态：**RUSTSEC-2021-0128 家族 7 个 API 中 5 个 ASan 出证**
  （update/commit/rollback hook + create_scalar_function + create_collation）

## 1. 出证结果

| API | vulnerable 0.26.1 | fixed 0.26.2（标准流程） | owned | no-trigger |
| --- | --- | --- | --- | --- |
| `create_scalar_function` | **heap-use-after-free**（exit=1，2 处） | **E0425 编译期拒绝** | ASan 干净 | ASan 干净 |
| `create_collation` | **heap-use-after-free**（exit=1，2 处） | **E0425 编译期拒绝** | — | — |

证据链（两 API 同形状，ASan 栈帧完整回查）：

- `create_scalar_function`：`main::{closure#0}`（main.rs:18 访问失效对象）→
  `call_boxed_closure`（functions.rs:484/491）→ `sqlite3VdbeExec`
  （sqlite3.c:94806，SELECT 晚调路径）→ `Statement::query_row` → `main`
  （main.rs:23）；
- `create_collation`：`main::{closure#0}`（main.rs:18）→
  `vdbeCompareMemString`（sqlite3.c:83393，排序比较晚调路径）。

harness 全部 `#![forbid(unsafe_code)]`、链接与静态分析同源的精确外部构建
（vendored rusqlite 0.26.1 + bundled sqlite3）。日志与产物在远端
`<results-root>/stage65-userdata/`（asan-*.log、harness-*、control-*.asan.log）。

## 2. 生成器扩展（crates/bw-cli generate_witness_harness.rs）

原生成器只支持「注册方法只收回调参数」（update_hook 特例）。create_* 需要：

1. **`prefix_args`**：注册方法里回调之前的固定参数（`create_scalar_function` 的
   `fn_name, n_arg, flags` / `create_collation` 的 `collation_name`），生成器按序
   拼在回调参数之前；
2. **`callback_ret_tail`**：回调返回类型不是 `()`/`bool` 时（`Result<i32>` /
   `Ordering`），adapter 显式给出尾表达式（`Ok(5)` / `Ordering::Equal`）；
   `()`/`bool` 的既有自动构造逻辑不变。

两者都是 serde `#[serde(default)]`，旧 adapter（update_hook）不受影响。
变异检查：改坏 prefix 拼接后 `prefix_args_and_ret_tail_render_into_register_and_callback`
转红；恢复后全绿（bw-cli 33+31+1+1+80，bw-foreign-ir 11+10+16）。

## 3. fixed 负对照的两个路径（如实区分）

- **标准流程**（stage5-5 同款）：用 0.26.2 的 static-facts → contracts
  （`capture_admission = requires_static_capture`）→ 生成器 `invalidate=refused`、
  `expected_compile=false` → 构建 **E0425**（witness_referent 未声明）。
  **判定说不能分离 → 不生成分离 → 程序编不过**——这是负对照要的行为；
- 非标准路径（沿用 0.26.1 契约生成 0.26.2 harness）：也编不过，但错误是
  E0373/E0505（借用检查拒绝），且 `expected_compile=true` 预测不准——这是已知
  生成器缺口（git2 §8.3 同类：生成器不知道 fixed 版 bound 变化）。**只把标准
  流程记作负对照证据**，非标准路径的行为记录为生成器缺口，不修（待 Gate B
  生成器缺口统一处理）。

## 4. create_collation trigger 的踩坑

首版 trigger 用 `SELECT ('a' = 'b') COLLATE bw_witness_collation`——SQLite
**常量折叠**，collation 回调未被调用，ASan 干净（exit=0，0 处）。改用
`ORDER BY a COLLATE bw_witness_collation`（排序必须调用 collation）后出证。
教训：trigger 必须选**外部组件不可优化掉**的调用路径。

## 5. 证明了什么 / 没证明什么

**证明了**：

- 能力①+② 的完整闭环：静态判定（joined + establish_late_invoke 义务）→
  自动 harness（invalidate 由判定推出）→ ASan 独立出证 → fixed/owned/no-trigger
  对照全对齐；
- 生成器能消费 `InsufficientEvidence + EstablishLateInvoke` 义务（不止
  `SupportedIncompatibility`），并支持多参数注册方法与非常规回调返回类型；
- 工具对同族 nday 的 5 个 API 端到端可复现（第 5 个独立 ASan 证据）。

**没证明**：

- **create_aggregate_function / create_window_function 仍未出证**：多回调参数
  （xStep/xFinal/xValue/xInverse）形状未建模，Rust 侧连 callback_site 都没有
  （能力③，下一步）；
- **A 类（allocation 提前释放）未被触发**：本形状走 R 类（referent 借用失效），
  xDestroy 由外部释放（A 类安全路径）；
- Q4′ clear 语义未分辨（`not_written` ≠ guard 被击穿，见能力②记录）；
- fixed 负对照只在 bound 变量上隔离（外部 SQLite 构建相同）——同步外部实现
  对照仍未做（需改 C 侧构建，超出范围）；
- 生成器对 fixed 版 `expected_compile` 预测缺口未修（非标准路径，见 §3）。

## 6. 下一步

能力③：多回调参数建模（create_aggregate_function / create_window_function）
→ 4 个 API 全部 joined + ASan → 阶段 6.5 完整收尾。
