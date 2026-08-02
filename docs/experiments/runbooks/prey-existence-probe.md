# Runbook：猎物存在性探针

本 runbook 执行 [Gate P](../../roadmap/milestone-gates.md#gate-p猎物存在性)，是 [research thesis](../../project/research-thesis.md) 路线上的**第一道止损点**。

前置阅读：[research thesis §7.2](../../project/research-thesis.md)（新发现是竞争力要求）、[implementation plan 的 PP](../../roadmap/implementation-plan.md)。

> **本 runbook 于 2026-07-31 复审后重写。** 旧版本有四处会导致错误结论的方法学缺陷：判据用语法四态、C-4 只是语法共现、未与 L1 分析片段对齐、运行会烧掉整个前瞻池。**旧版本的判据不得使用。**
>
> **前置**：[implementation plan 的 PC](../../roadmap/implementation-plan.md)（`EffectiveCaptureAdmission`）必须先完成。

## 1. 这件事决定什么

本项目的主线缺陷类——安全 API 允许回调捕获非 `'static` 借用、外部组件保存并晚调——在 Rust 社区**是公开知识**。RUSTSEC-2021-0128 已公开多年，`'static` 收紧是标准修法，许多维护者早已照做。

因此在投入外部侧 LLVM IR 分析（[implementation plan](../../roadmap/implementation-plan.md) 的 P1/P2，全路线最贵的一段）之前，必须先回答：

> **生态里还剩多少个这样的位置？**

判据用置信界与**换算公式**，不用「足够」这类事后可移动的词。

**候选数不能直接推出确认发现数**，中间隔着一个转化率。因此本 gate 拆成两个子探针：

| 子 gate | 问题 | 样本 |
| --- | --- | --- |
| **Gate P-a** | 未调优、L1、Tier A 的交出点还有多少 | 前瞻池（盲化） |
| **Gate P-b** | 这些候选里有多大比例能真正走到确认 | **开发集**（不消耗前瞻池） |

判定：

```text
可用猎物估计 = eligible_pool_lower_bound × conversion_rate_lower_bound
```

| 结果 | 判据 | 后果 |
| --- | --- | --- |
| `Pass` | 该乘积仍足以支撑预注册的确认集规模 | 按计划投入 P1/P2 |
| `No-Go` | 上置信界仍不足 | 转路线 C（经验研究），不投入外部侧实现 |
| `Amber` | 介于两者之间 | 扩大样本或增加人工审计，不得直接判 Pass |

**聚类单位**：crate / repository / 外部库家族**不是独立同分布样本**。同一仓库下的多个 crate、同一外部库的多个绑定共享设计习惯与维护者。**必须按这三个单位分别聚类报告**，按 alert 计数会系统性高估。

**referent 与 allocation 两支分别套用上式，分别判定。**

预定确认集的规模见 [research thesis §7.8](../../project/research-thesis.md)。**全部参数必须在探针运行之前预注册**，见 [ADR-0005](../../decisions/ADR-0005-evidence-trust-and-experiment-statistics.md)。

> **口头判断不构成 Gate P 通过。** 维护者对猎物池规模的印象可以决定是否值得跑这个实验，但不能替代预注册的正式结果。

**这个实验的成本约为 P1+P2 的百分之一。** 它排在 P1/P2 之前的唯一理由是：它能用最小代价否定最大投入。**但它排在 [Gate R](../../roadmap/milestone-gates.md#gate-r关系正确性) 之后**——关系错了，数出来的候选也是错的。

## 2. 前置能力

Rust 侧的回调 bound 判定已实现（`compiler/bw-rustc/src/rustc_api/mir.rs` 的 `callback_lifetime_bounds`），不依赖外部侧、不依赖人工 API 清单。语义取值 `EffectiveCaptureAdmission`（PC）与 `RegistrationGuard`（PG-1）均已实现。

**仍缺三项，缺任何一项数出来的候选池都不可信**，见 [execution plan 的 0.3](../../roadmap/execution-plan.md)：

| 缺口 | 后果 | 状态 |
| --- | --- | --- |
| 事实层不记录该 API 是不是 `unsafe fn` | C-1 在事实层过滤不掉。实测：fixture 中的 `unsafe extern "C" fn trampoline<F: FnMut()>` 也产出了 callback bound 事实 | `Planned` |
| 没有 safe-entry lineage | C-1 的「公开路径上可达」无法证明，藏在内部 helper 里、安全客户端够不着的交出点会被计入 | `Planned` |
| `AllocationOwnership` 未实现 | Tier A-A 无法统计，allocation 类猎物全部记零 | `Planned`（PG-2） |

## 3. 判据

### 3.1 两级统计，只有 Tier A 能作判据

| 级别 | 定义 | 用途 |
| --- | --- | --- |
| **Tier A-R** | 满足 C-1、C-2、C-4、C-5，且 C-3R 成立 | **Gate P referent 子路线的判据** |
| **Tier A-A** | 满足 C-1、C-2、C-4、C-5，且 C-3A 成立 | **Gate P allocation 子路线的判据** |
| **Tier B** | 回调表面与 `extern` 调用只发生**语法共现**（同一函数体内出现 extern 调用） | 仅探索性筛选 |

共同的四条：

| 条件 | 判据 | 数据来源 |
| --- | --- | --- |
| C-1 安全 API | 不是 `unsafe fn`，**且存在一条从 public safe 入口经 wrapper/helper 到达该交出点的可回查 lineage** | HIR + 调用图，见 §3.5 |
| C-2 有回调参数 | 存在 Fn 家族的泛型参数或 trait object 参数 | 签名 |
| C-4 真的交出去了 | 回调 / trampoline / userdata 经过程内或**有界过程间 dataflow 到达精确的 extern 参数** | MIR dataflow |
| C-5 外部侧可分析 | 能绑定到精确的外部 LLVM IR（L1 tier） | 构建方式，见 §3.4 |

**互斥的第三条**，它把 Tier A 分成两支：

| 条件 | 判据 | 对应缺陷类 |
| --- | --- | --- |
| C-3R 允许捕获借用 | `EffectiveCaptureAdmission = PermitsNonStaticCapture` | referent 被捕后失效 |
| C-3A 分配可提前释放 | `EffectiveCaptureAdmission = RequiresStaticCapture` **且** `AllocationOwnership = RustRetainsAndMayFreeEarly` | `Box<F>` 提前回收、外部调用悬垂指针 |

### 3.1.1 为什么必须分两支

**这是本 runbook 最容易出错、后果也最严重的一处。**

allocation 类缺陷的 `EffectiveCaptureAdmission` 恰恰是 `RequiresStaticCapture`——`F: 'static` 保证闭包没捕获借用，但**对 `Box<F>` 本身的存活完全不表态**。如果只用 C-3R 作 Tier A 判据，**这一整类猎物会被判据直接排除、记成零**，而 Gate P 的 No-Go 会按 [research thesis §8](../../project/research-thesis.md) 触发"转路线 C，不再投入外部侧"。

**结果就是一条从未被测量过的子路线被一个没测过它的实验杀掉。**

因此：

- 两支**分别统计、分别判定**；
- **不得因 Tier A-R 的 No-Go 自动放弃 A 子路线**；
- 若 `AllocationOwnership`（PG-2）尚未实现导致 Tier A-A 无法统计，必须明确写：**Gate P 本次只决定 R 子路线，A 保持 `Unknown` 并单独设 gate**，不得默认为零。

**Tier B 既不是精确候选，也不是上界。** 它同时**高估**（把无关的 extern 调用计为候选）和**低估**（漏掉 helper 函数、RAII 构造器、宏生成的桥、多层 wrapper 里发生的交出）。旧版本把它当作上界是错的。**不得用 Tier B 的数字作 Go/No-Go。**

### 3.2 C-3 必须用语义取值，不能用语法四态

**这是旧版本最严重的判据缺陷。**

对泛型 `fn register<F: Fn()>(f: F)`，没有 `'static` bound **恰恰是允许 `F` 包含局部借用**——这是**最强**的候选形状，不是「不表态」。而 `Box<dyn Fn()>` 中省略的 trait object lifetime 在多数位置**默认到 `'static`**，根本不是候选。

旧版本把这两种语义相反的情况合并成同一个「无 bound → 弱候选」，会**系统性错估猎物池**：把最强的一类记成弱，把不是候选的一类也记成弱。

规范取值：

| 取值 | 计入哪一支 |
| --- | --- |
| `PermitsNonStaticCapture` | **Tier A-R** |
| `RequiresStaticCapture` | **Tier A-A**（当且仅当 `AllocationOwnership = RustRetainsAndMayFreeEarly` 一并成立），否则单列 |
| `ContextDependent` | 都不计入，单列 |
| `Unresolved` | 都不计入，单列，且计入分母 |

### 3.3 保护性形状不在本探针内排除

`Arc` 锚点、结构体 lifetime 参数、registration guard、`unregister` 路径等 Rust 侧约束机制**不在本探针的判据内**。探针给出的是**候选上界**（在 Tier A 的意义上），不是最终候选集。

这是有意的：探针的作用是判断池子的数量级，过早收紧会把「不确定」误判成「没有」。**但 guard 形状必须单独统计**——按 [research thesis §2.4](../../project/research-thesis.md)，guard 是否真的保护取决于外部侧的清槽行为，Rust 侧看到 guard 不等于该候选无效。`RegistrationGuard`（PG-1）已实现，可以在探针里直接分列。

**因此 Tier A 是"带保护性形状的候选上界"，不是最终候选集。** Gate P-b 的转化率下界正是用来把这个上界折算成可确认量的；两者必须配套使用，单用 Tier A 计数会高估。

### 3.5 C-1 的 safe-entry lineage

**只证明"回调到达 extern 参数"不足以证明"安全客户端能到达这个交出点"。**

研究对象是 public safe API：缺陷的含义是"不写 `unsafe` 的调用方能触发 UB"。一个藏在内部 helper 里、公开 API 根本够不着的交出点不构成本研究的缺陷，把它计入会高估猎物池。

因此 C-1 要求保留一条可回查的链：

```text
public safe 入口 → wrapper / helper → 具体的 extern 交出点
```

lineage 断裂、或只能到达 `unsafe fn` 入口的交出点，**单列为 `unreachable-from-safe-entry`，不计入 Tier A**。该字段与身份分层的"安全入口身份"同源，见 [ADR-0003](../../decisions/ADR-0003-target-verifier-dataflow-and-identity.md)。

### 3.4 C-5 必须与 L1 分析片段对齐

**这是旧版本第二处会导致假「通过」的缺陷。**

主线只支持外部源码随构建提供、能取得精确 LLVM IR 的 **L1** crate。但一个 crate 完全可能有大量 Rust 侧候选，却因为链接系统库而**一个都进不了 P1/P2**。

主表必须记录：

| 字段 | 内容 |
| --- | --- |
| IR acquisition tier | L1 源码随构建 / L2 链接系统库 / L3 仅二进制 |
| 实际 build mode | vendored / bundled feature / system / 静态或动态链接 |
| foreign artifact 来源 | 具体的 `-sys` crate 与其构建方式 |
| 能否绑定精确 IR | 是 / 否 / 未确定 |

**Gate P 的通过条件以「未调优 + L1 可分析 + Tier A」的候选数为准。L2/L3 只能单列。**

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

### 4.3 feature 策略必须预注册，`--all-features` 不能是唯一配置

**`--all-features` 不可省。** 本项目已实测：FFI 绑定 crate 通常把回调表面放在非默认 feature 之后，默认扫描会完全看不到那部分注册点，并把组件报成没有受支持的边界。

**但它也不能是唯一配置。** Cargo 允许互斥 feature，全开构建失败是**可预期的正常情况**，不能直接成为排除该 crate 的理由。按固定顺序回退：

1. default features；
2. `--all-features`；
3. 全开失败时，按**预先写死的算法**运行文档中记载的 feature bundle；
4. 必要时 one-feature-at-a-time；
5. 固定 target 与 toolchain；
6. **按 hand-off identity 跨配置去重**，避免同一交出点被多个配置重复计数；
7. 单独报告只在某个配置下出现的候选。

只有走完这个回退链仍然构建失败的 crate，才记入排除表。

### 4.4 抽样必须预注册

「目标 300–500 crate」只是样本量，不是抽样方法。执行前必须写死并记录：

- crates.io snapshot 日期；
- 版本选择规则（例如 latest non-yanked）；
- target、OS、toolchain；
- sampling frame 的定义；
- 超过 500 时的随机或分层抽样方法**与随机种子**；
- crate / repository / 外部库家族的去重规则；
- build failure、unsupported、Unknown 的处理方式；
- 若要宣称生态频率，使用的抽样权重与置信区间算法。

### 4.5 运行前必须完成 family-level sealed split

**这是旧版本第三处缺陷，且后果不可逆。**

直接查看 300–500 个 crate 的身份与候选数，再据此开发 P1–P4，会按 [research thesis §7.6](../../project/research-thesis.md) 的规则把**整个前瞻池变成开发集**——本项目自己的数据隔离纪律写明「pilot 中暴露的 crate 此后永久转为开发集」。

运行前必须：

1. 按 repository、fork / 版本家族、外部库家族**聚类**；
2. 划分 screening / development pool；
3. 封存 confirmation holdout；
4. 在算法、阈值、Contract、feature 策略冻结前，**不查看 holdout 的身份与逐样本输出**。

**默认做法：由独立 runner 执行，只返回盲化的聚合统计，开发者不接触 crate 身份。** 这不增加成本，却保住整个池子。备选方案是使用冻结日期之后发布的 temporal holdout。

## 5. 执行

```bash
# 本项目：见 tools/experiment/run-scan.sh --help
#   --all-features 必须给
#   --runs-root 指向仓库之外的目录（否则下次同步的 --delete-excluded 会抹掉结果）
#   本探针只需要 Rust 侧前端，不需要 witness plan 阶段
```

所有资源密集的构建与扫描按 [VPS 与本地工作流](../../development/vps-local-workflow.md) 在远端执行。

### 5.1 正对照

每次环境变更后重跑正对照，确认探针确实在工作：`benchmarks/compiler-fixtures/callback-lifetime-bound/` 的全部签名形状必须命中预期取值。**正对照为空则整批结果作废。**

### 5.2 非空性检查

`dyn Fn` 与泛型 `F: Fn` 两个 fixture 必须落到**相反**的 `EffectiveCaptureAdmission` 取值。若两者仍相同，说明 PC 的归一化没生效，整批结果作废。

再把 C-3 反向（只统计 `RequiresStaticCapture` 的位置），确认命中集合与正向结果不相交且非空。

### 5.3 随机抽审

**合成 fixture 与反向检查只能发现恒空的分类器，不能证明生态召回率。**

必须随机抽取一部分 **Tier A 阳性**与**候选阴性**做人工判读，估计探针的 PPV 与漏检率，并把这两个数字连同置信区间一起报告。没有抽审的 Tier A 计数不能支撑 Gate P 的置信界判据。

## 6. 需要产出的表

### 6.1 主表（仅未调优 crate）

| crate | 版本 | feature 配置 | IR tier | Tier A 候选 | Tier B 共现 | `RequiresStaticCapture` | `ContextDependent` | `Unresolved` | 含 guard 形状 | 外部库 |

**只有「IR tier = L1」的 Tier A 列进入 Gate P 判据。**

### 6.2 分布表

| 指标 | 值 |
| --- | --- |
| sampling frame 规模 | |
| 实际扫描 crate 数 | |
| 走完 feature 回退链后构建成功数 | |
| 其中 IR tier = L1 的 crate 数 | |
| **至少含一个 L1 Tier A 候选的 crate 数** | |
| L1 Tier A 候选总数（含置信区间） | |
| Tier B 共现总数（仅参考） | |
| 抽审得到的 PPV / 漏检率 | |

**「至少含一个 L1 Tier A 候选的 crate 数」是 Gate P 最重要的一个数字**——它直接对应可能的新发现来源数量。

### 6.3 IR 获取分级表

| crate | IR tier | 实际 build mode | foreign artifact 来源 | 能否绑定精确 IR |

**这张表回答「Rust 侧候选池里有多少真的能进 P1/P2」。** 缺了它，一个很大的候选池可能给出假的「通过」。

### 6.4 排除表

| crate | 排除原因（feature 回退链走完仍构建失败 / 无 FFI 表面 / 已调优 / 其他） |

不记录排除原因的样本集不可用。

### 6.5 预注册记录

抽样、feature 策略、阈值与 sealed split 的预注册内容（§4.4、§4.5）必须与结果同时存档，且**时间戳早于运行**。

## 7. 结论怎么写

允许的结论形式：

- 「在 N 个未调优、L1 可分析的 FFI crate 中，M 个至少含一个 Tier A 交出点，Tier A 候选共 K 个（95% CI 如表），抽审 PPV 为 X%」
- 「按预注册阈值，Gate P 判为 Pass / No-Go / Amber」

不允许的结论形式：

- 把候选交出点表述为漏洞、缺陷或 finding——**它们只是「值得分析的位置」**，没有任何外部侧证据；
- 用 **Tier B 共现数**作 Go/No-Go；
- 把候选数直接当作预期新发现数；
- 把已调优 crate 计入主表；
- 把 L2/L3 候选计入 Gate P 判据；
- 在未记录排除原因、未做抽审、未预注册阈值时给出比例或判定；
- 使用「足够」「非平凡」这类事后可移动的措辞。

**本探针不产出任何缺陷结论。** 它只回答「还有没有东西可找，以及其中有多少真的能进外部侧分析」。

产出放入 [results](../results/)，遵循 [data alignment](../data-alignment.md)。逐样本细节与未披露候选身份不进入公开仓库，边界见 [仓库与数据治理](../../project/repository-and-data-governance.md)。
