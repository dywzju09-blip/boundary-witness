# Runbook：猎物存在性探针

本 runbook 执行 [Gate P](../../roadmap/milestone-gates.md#gate-p猎物存在性)，是 [research thesis](../../project/research-thesis.md) 路线上的**第一道止损点**。

前置阅读：[research thesis §7.2](../../project/research-thesis.md)（新发现是硬要求）、[implementation plan 的 PP](../../roadmap/implementation-plan.md)。

## 1. 这件事决定什么

本项目的主线缺陷类——安全 API 允许回调捕获非 `'static` 借用、外部组件保存并晚调——在 Rust 社区**是公开知识**。RUSTSEC-2021-0128 已公开多年，`'static` 收紧是标准修法，许多维护者早已照做。

因此在投入外部侧 LLVM IR 分析（[implementation plan](../../roadmap/implementation-plan.md) 的 P1/P2，全路线最贵的一段）之前，必须先回答：

> **生态里还剩多少个这样的位置？**

| 结果 | 后果 |
| --- | --- |
| 候选池规模足够，且未调优 crate 上占比非平凡 | Gate P 通过，按计划投入 P1/P2 |
| 候选池只有个位数，或全部集中在已修复的历史版本 | **路线 A 死于新发现硬要求**，转路线 C（经验研究），不投入外部侧实现 |

**这个实验的成本约为 P1+P2 的百分之一。** 它排在一切之前的唯一理由是：它能用最小代价否定最大投入。

## 2. 为什么现在就能做

判定所需的能力**已经实现**：`compiler/bw-rustc/src/rustc_api/mir.rs` 的 `callback_lifetime_bounds` 从 HIR 签名读出回调 bound 的四态取值（绑在 receiver 声明的 lifetime / 绑在其他声明的 lifetime / `'static` / 无 outlives bound）。

它**不依赖外部侧分析，也不依赖人工 API 清单**。探针要做的只是把它跑到规模上并统计。

## 3. 判据

统计同时满足以下四条的公开函数：

| 条件 | 判据 | 数据来源 |
| --- | --- | --- |
| C-1 安全 API | 不是 `unsafe fn`，且在 crate 的公开路径上可达 | HIR |
| C-2 有回调参数 | 存在 Fn 家族的泛型参数或 trait object 参数 | `callback_lifetime_bounds` |
| C-3 bound 不是 `'static` | 该参数的 outlives bound 短于 `'static`，或不存在 outlives bound | `callback_lifetime_bounds` 的四态取值 |
| C-4 同函数内跨界 | 同一函数体内存在 `extern` 调用 | MIR 调用点 |

四条都满足的位置记为一个**候选交出点**。

### 3.1 两个取值必须分开统计

C-3 的两种情况证据强度不同，**不得合并计数**：

- **bound 短于 `'static`**：签名明确允许捕获借用。这是强候选。
- **无 outlives bound**：签名不表态。可能是真候选，也可能该值根本不跨界（[Gate 0 的 8 条误报](../results/gate0-yuga-precision-triage-2026-07-31.md)里 `query_map` 一族正是这种形状）。这是弱候选。

Gate P 的判据以**强候选**为准，弱候选单列。

### 3.2 保护性形状不在本探针内排除

`Arc` 锚点、结构体 lifetime 参数、`unregister` 路径等 Rust 侧约束机制**不在本探针的判据内**。探针给出的是**上界**，不是最终候选集。这是有意的：探针的作用是判断池子的数量级，过早收紧会把「不确定」误判成「没有」。

## 4. 样本选择

### 4.1 规模与来源

目标 300–500 个 crate。来源为 crates.io 上具有 FFI 表面的 crate，客观判据优先于人工挑选：

- 依赖 `cc`、`bindgen`、`pkg-config` 构建脚本，或
- 存在 `-sys` 后缀的直接依赖，或
- crate 自身以 `-sys` 结尾。

**选样判据必须先写死再执行**，且记录全集与每个被排除者的原因。

### 4.2 必须分组

| 组 | 内容 | 用途 |
| --- | --- | --- |
| **已调优** | `rusqlite`、`openssl`、`pyo3`、`diesel`——本项目开发期接触过或已写入 `contracts/callback-retention/` 清单的 crate | 单列，**不进入 Gate P 判据** |
| **未调优** | 其余全部 | Gate P 的判据以此组为准 |

### 4.3 feature 处理

**`--all-features` 不可省。** 本项目已实测：FFI 绑定 crate 通常把回调表面放在非默认 feature 之后，默认扫描会完全看不到那部分注册点，并把组件报成没有受支持的边界。

`--all-features` 编译失败的 crate 记入排除表并注明原因，不得静默丢弃。

## 5. 执行

```bash
# 本项目：见 tools/experiment/run-scan.sh --help
#   --all-features 必须给
#   --runs-root 指向仓库之外的目录（否则下次同步的 --delete-excluded 会抹掉结果）
#   本探针只需要 Rust 侧前端，不需要 witness plan 阶段
```

所有资源密集的构建与扫描按 [VPS 与本地工作流](../../development/vps-local-workflow.md) 在远端执行。

### 5.1 正对照

每次环境变更后重跑正对照，确认探针确实在工作：`benchmarks/compiler-fixtures/callback-lifetime-bound/` 的六种签名形状必须全部命中预期取值。**正对照为空则整批结果作废。**

### 5.2 非空性检查

把 C-3 反向（只统计 bound 为 `'static` 的位置），确认命中集合与正向结果不相交且非空。这条阻止「判据写错导致恒为空」这一已在本项目发生过多次的失败模式。

## 6. 需要产出的表

### 6.1 主表（仅未调优 crate）

| crate | 版本 | 强候选数（bound 短于 `'static`） | 弱候选数（无 bound） | 涉及的外部库 |

### 6.2 分布表

| 指标 | 值 |
| --- | --- |
| 扫描 crate 总数 | |
| `--all-features` 构建成功数 | |
| 至少有一个强候选的 crate 数 | |
| 强候选总数 | |
| 弱候选总数 | |

**「至少有一个强候选的 crate 数」是 Gate P 最重要的一个数字**——它直接对应可能的新发现来源数量。

### 6.3 排除表

| crate | 排除原因（构建失败 / 无 FFI 表面 / 已调优 / 其他） |

不记录排除原因的样本集不可用。

## 7. 结论怎么写

允许的结论形式：

- 「在 N 个未调优 FFI crate 中，M 个至少含一个强候选交出点，强候选共 K 个」
- 「候选池规模支持 / 不支持 [research thesis §7.7](../../project/research-thesis.md) 的确认集与新发现目标」

不允许的结论形式：

- 把候选交出点表述为漏洞、缺陷或 finding——**它们只是「值得分析的位置」**，没有任何外部侧证据
- 把强候选数直接当作预期新发现数
- 把已调优 crate 计入主表
- 在未记录排除原因时给出比例

**本探针不产出任何缺陷结论。** 它只回答「还有没有东西可找」。

产出放入 [results](../results/)，遵循 [data alignment](../data-alignment.md)。逐样本细节与未披露候选身份不进入公开仓库，边界见 [仓库与数据治理](../../project/repository-and-data-governance.md)。
