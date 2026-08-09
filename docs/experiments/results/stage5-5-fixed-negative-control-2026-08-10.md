# 阶段 5.5：rusqlite 0.26.2 负对照与对照矩阵

- 日期：2026-08-10
- 执行计划：[execution plan](../../roadmap/execution-plan.md) 阶段 5.4 完成条件
- 状态：**fixed（0.26.2）负对照完成；客户端安全使用三变体对照全部干净。**

## 1. fixed 负对照（rusqlite 0.26.2）

流程与 vulnerable 完全一致，只换源码版本：

1. vendor 0.26.2（crates.io 官方包，`libsqlite3-sys` 依赖同为 0.23，外部 SQLite
   构建不变——对照只隔离 Rust bound 这一变量）；
2. `bw extract-static-facts`（--all-features）→ 2274 条事实；
3. `bw extract-rust-contracts` → `hooks::<impl Connection>::update_hook` 契约
   **`capture_admission = requires_static_capture`**（0.26.1 是
   `permits_non_static_capture`；源码 diff 确认 `'c` → `'static` 收紧，
   RUSTSEC-2021-0128 的修复形状）；
4. `bw generate-witness-harness --crate-version 0.26.2` →
   `invalidate = refused（requires_static_capture：类型层排除借用捕获）`、
   `expected_compile = false`；
5. `cargo build` → `E0425: cannot find value 'witness_referent'`——**编不过**。

**判定说不能分离 → 不生成 invalidate → 程序编不过**：fixed 版在编译期就拒绝该
时序，不需要跑 ASan。这正是负对照要的行为。

## 2. 客户端安全使用变体（0.26.1 构建 + ASan，各 1 次运行）

| 变体 | 动作 | ASan 报告 | exit |
| --- | --- | --- | --- |
| owned callback | 回调不捕获任何借用 | 0 | 0 |
| unregister-before-drop | 注册 → `update_hook(None)` 注销 → referent 失效 → INSERT | 0 | 0 |
| no-trigger | 注册 → referent 失效 → 不执行任何语句 | 0 | 0 |

日志在远端 `<results-root>/stage5-5/control-*.asan.log`。

## 3. 对照矩阵汇总

| 对照 | 结果 |
| --- | --- |
| vulnerable 0.26.1 | ASan **heap-use-after-free**（5.4，栈帧完整回查） |
| fixed 0.26.2 | **编译期拒绝**（E0425，invalidate refused） |
| owned callback | ASan 干净 |
| unregister-before-drop | ASan 干净 |
| no-trigger | ASan 干净 |
| 同步外部实现 | **未做**（需要修改 C 侧的外部构建，超出本次范围；首期外部实现是 SQLite 的保存+晚调形状） |

## 4. 这一步证明了什么，没证明什么

**证明了**：

- fixed 版本（`'static` bound）在真实流程上走完全程：静态契约
  `requires_static_capture` → 生成器拒绝分离 → 编译失败，**负对照在编译期成立**；
- vulnerable/fixed 的判别力来自 Rust 侧契约（`permits` vs `requires`），外部侧
  SQLite 构建完全相同——本对照隔离了唯一变量；
- 客户端安全使用（owned / unregister / no-trigger）在 ASan 下全部干净，
  「触发」与「客户端动作序列」的因果对应成立；
- 0.26.2 的 vendor 目录进入仓库（与 0.26.1 惯例一致），负对照可复现。

**没证明**：

- **同步外部实现对照。** 一个「注册后立即同步调用、不保存」的外部实现应该同样
  干净——需要第二份外部构建（C stub 形状），本次没有构造；
- **重复运行的确定性。** 每个对照只跑 1 次；ASan 对堆 UAF 是确定性的，但正式
  数字需要 N 次重放与 receipt；
- **X=A 分配类缺陷。** 对照矩阵覆盖的是 referent（X=R）分离；`'static` 回调 +
  `Box<F>` 提前释放的形状仍无生成器支持；
- **不是「0.26.2 整体健全」。** 编不过只证明 referent 分离不可构造；其他 API、
  其他 feature 组合不在本对照范围。
