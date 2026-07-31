# Runbook：规模化精度对照

本 runbook 是 [Gate A 外部证据必要性](../../roadmap/milestone-gates.md#gate-a外部证据必要性)的组成部分，执行 [research thesis §7](../../project/research-thesis.md) 实验表中「vs Yuga / FFIChecker」这一行。

**执行顺序**：本实验排在 [Gate P 猎物存在性探针](prey-existence-probe.md)**之后**。Gate P 决定这条路线是否值得继续；本实验决定 C2（跨界精化检查）是否成立。

前置阅读：[Gate 0 外部基线对照](../results/gate0-baseline-comparison-2026-07-31.md)、[Yuga 误报归因](../results/gate0-yuga-precision-triage-2026-07-31.md)。构建两个工具的环境障碍与绕过见 [baseline comparison runbook](baseline-comparison.md)，本文不重复。

## 1. 这件事决定什么

2026-07-31 的单 crate 对照给出：同一个 crate 上 Yuga 精度 5/13、本系统 5/5，召回都是 5/7。**那不是证据**：样本量为 1，而且那个 crate 是本系统的开发对象。

本实验有两种结果，后果完全不同：

| 结果 | 后果 |
| --- | --- |
| 更大样本上 Yuga 误报率仍高，且根因统一 | C2（类型契约 × 外部 effect 的精化检查）的动机成立，继续按 [implementation plan](../../roadmap/implementation-plan.md) 投入 P1/P2 |
| 更大样本上 Yuga 精度并不差 | **C2 失去动机**，按 [Gate A](../../roadmap/milestone-gates.md#gate-a外部证据必要性) 的失败动作转路线 B：以 C1 反证合成为主线，外部分析只服务触发规划 |

注意本实验**不能单独证明 C2**：它只说明先验工具误报率高。C2 成立还需要 Gate A 的另一半——matched pair 上 Full 相对 Rust-only 的信息增益。**「别人不准」不等于「我们的机制有效」。**

**如实报告。不要为了让结论好看而调整样本或判定标准。** 本项目已经因为「假设别人做不到」而返工一次，第二次返工的代价更高。

## 2. 样本选择

### 2.1 数量与分组

目标 10–20 个 crate，分两组：

- **A 组｜有已披露公告**：公告属于回调/生命周期类。提供锚定的真阳性与召回分母。
- **B 组｜无已知公告但有 FFI 回调表面**：提供误报率。该组中任何报告都必须逐条判定。

两组都要有。只有 A 组测不出误报率，只有 B 组没有召回基准。

### 2.2 必须排除的「已调优」crate

本系统开发期间接触过的 crate **不能计入精度证据**，必须单列或排除：

- `rusqlite`——主开发对象
- `openssl`、`pyo3`、`diesel`——其 API 已写入本仓库 `contracts/callback-retention/` 的清单

这些可以跑，但结果单独标注为「调优过」，不进入主表。**主表只用未参与开发的 crate。**

### 2.3 选样偏差必须记录

Yuga 需要 `nightly-2022-11-18`。太新的 crate 可能无法用该工具链编译，因而被迫排除。**这会造成系统性偏差**（偏向较老的代码）。记录：

- 候选 crate 全集
- 每个被排除者的排除原因（编译失败 / 无 FFI 回调表面 / 其他）
- 最终纳入者

不记录排除原因的样本集不可用。

## 3. 判定规程

这是本实验最容易失去客观性的地方，所以规则先定死，再看数据。

### 3.1 三分类

对每一条报告：

| 类别 | 判据 |
| --- | --- |
| **TP** | 该报告指出的生命周期关系**确实不受 Rust 侧约束**，安全 API 允许调用方构造出悬垂。有对应公告可直接锚定 |
| **FP** | 该关系**实际已被 Rust 侧机制约束** |
| **Unknown** | 读源码无法判定。**计入分母，不计入 TP，也不计入 FP** |

不允许把 Unknown 归到任一侧凑数字。

### 3.2 FP 必须归类到约束机制

判为 FP 时，必须记录是哪一种 Rust 侧机制使其安全。已知的四类来自单 crate triage。**代号用 `M` 前缀，不要与创新点编号 C1/C2/C3 混淆。**

| 代号 | 机制 | 单 crate 实例 |
| --- | --- | --- |
| M1 | 值存进受借用检查器约束的 Rust 结构体，未跨边界 | `MappedRows<'stmt, F> { rows, map: F }` |
| M2 | `Arc` / `Rc` 等引用计数锚点 | `InterruptHandle { db_lock: Arc::clone(..) }` |
| M3 | 结构体自身的 lifetime 参数约束 | `Backup<'a, 'b>` |
| M4 | 返回值 lifetime 由输入参数约束 | `fn prepare<'a>(&mut self, conn: &'a Connection) -> Result<Statement<'a>>` |
| M5+ | 新机制，需描述并编号 | — |

**这一栏是本实验的核心产出。** C2 的动机建立在「误报根因统一为分不清跨界交出与 Rust 内部存储」之上；若 FP 大量落在 M1 之外的新机制上，说明根因不统一，动机要相应削弱。

### 3.3 差分作为辅助判据

若 crate 有「缺陷版 / 修复版」配对，跑两遍：**修复后消失的报告是 TP 的强证据，修复后仍在的是 FP 的强证据。** 这比单纯读源码客观，优先使用。

### 3.4 交叉检查

至少对 20% 的判定做独立复核（另一人或另一次独立通读），记录不一致率。不一致率高说明判定规程不够客观，需要先修规程。

## 4. 执行

### 4.1 环境

按 [baseline comparison runbook](baseline-comparison.md) 构建 Yuga 与 FFIChecker。已验证有效的关键点：

- 用 `codeload` 取 tarball，不要 `git clone`
- 2022 版 cargo 拉不动 git 协议的 crates.io 索引，改用 sparse：
  `CARGO_UNSTABLE_SPARSE_REGISTRY=true`、`CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse`、`CARGO_NET_RETRY=5`
- Yuga 随附 `Cargo.lock` 与其 `Cargo.toml` 不同步，需在项目外生成兼容锁，**不得修改其分析源码**
- FFIChecker 的 `llvm-sys` 静态链接与 `rustc_driver` 自带 LLVM 冲突，需启用 `no-llvm-linking`
- 完整输出重定向到日志文件，不要在最外层套管道；退出码用 `cmd >log 2>&1; echo $?`

### 4.2 每个 crate 的运行

```bash
# 三方工具
cargo yuga --all-features        > yuga-<crate>-<version>.report 2>&1; echo $?
cargo ffi-checker --all-features > ffichecker-<crate>-<version>.report 2>&1; echo $?

# 本系统：见 tools/experiment/run-scan.sh --help
#   --all-features 必须给；回调表面通常在非默认 feature 之后
#   --runs-root 指向仓库之外的目录
#   --witness-limit 要足够大，默认值会截断掉可绑定的候选
```

**`--all-features` 不可省。** 本项目已实测：默认 feature 下回调表面根本不参与编译，空结果没有意义。

### 4.3 正对照

每次环境变更后都要重跑正对照，确认工具确实在工作。正对照为空则整批结果作废。

## 5. 需要产出的表

### 5.1 主表（仅未调优 crate）

| crate | 版本 | 组 | Yuga TP | Yuga FP | Yuga Unknown | 本系统 TP | 本系统 FP | 本系统 Unknown |

由此计算两边的精度与召回，并给出置信区间或至少给出样本量。

### 5.2 误报机制分布

| 机制 | Yuga FP 数 | 本系统 FP 数 |

**这张表回答 C2 的动机成不成立。**

### 5.3 分歧表

两个工具判定不一致的每一条：谁报了、谁没报、判定为何。**本系统漏而 Yuga 报中的条目要重点分析**——那是本系统的召回缺口。

## 6. 结论怎么写

允许的结论形式：

- 「在 N 个未调优 crate 上，Yuga 精度 X%、本系统 Y%，误报机制分布如表」
- 「Yuga 的误报中 Z% 落在 M1，支持 / 不支持根因统一的主张」

不允许的结论形式：

- 把调优过的 crate 计入主表
- 把 Unknown 计入任一侧
- 在样本量不足时给出精度百分比而不标注样本量
- 表述为「本系统检出能力更强」——召回若相当，贡献在精度，不在检出

产出放入 [results](../results/)，遵循 [data alignment](../data-alignment.md)。

在本实验完成前，[research thesis](../../project/research-thesis.md) 的 C2 仍标为 `Planned`，不得表述为已成立。
