# 完整功能实现计划

本文是 [roadmap](roadmap.md) 各阶段的可执行细化。方向权威是 [research thesis](../project/research-thesis.md)：**任何一项如果不能落到 C1/C2/C3 之一，就不该做。**

> **执行顺序与依赖类型以 [execution plan](execution-plan.md) 为准**，本文只给技术细节。两者冲突时改本文。

本文于 2026-07-30 全量重写，取代此前所有版本。旧版本的 P0–P7 编号、`Mismatch`/`NoMismatch` 判定表、以及「P1 消除人工 API 清单」阶段一律作废。

当前阶段是 **V3.2.x core-effect hardening**。本文描述计划，不是已达成能力。

---

## 现状基线

**已有**：Rust 侧 HIR/MIR 事实抽取、候选生成、生命周期证据与图、排序、witness plan、runtime/oracle/fuzz observer 基础、单一库的 harness。

持有期维度的 Rust 侧契约可以从签名读出——`EffectiveCaptureAdmission` 的语义取值（PC）与 `RegistrationGuard`（PG-1）都已从 HIR/MIR 产出，并已与外部边界事实联结、把判定与判定来源写入产物。**语法四态 `CallbackLifetimeBoundScope` 只作底层观察，不得用于判定**，见本文末尾的已撤销计划项。

**缺口：外部侧不存在。** 持有期维度的外部侧那一半目前由 API 清单分类出的注册/注销事实**推断**得来，不是外部代码行为。三条创新点因此都未成立。

**逐组件的保留 / 冻结 / 重构 / 删除决定见 [代码库对齐审计](../development/codebase-realignment.md)**，本文只写要做什么，不重复处置理由。该审计的三条具名决定（D1 冻结 returned-borrow、D2 一次性 schema 升版、D3 重写反证生成器的产出目标）对本文各阶段有约束力。

## 关键路径

2026-07-31 复审后调整：**关系正确性排在一切之前**，它不依赖外部侧流水线。

```text
PF 关系与四 fixture ──（Gate R）── 已完成
PC EffectiveCaptureAdmission ───── 已完成
PG-1 RegistrationGuard ─────────── 已完成
PG-2 AllocationOwnership ───────── 下一步
        ↓
safe-entry / RustContractFact
        ↓
真实外部 IR → P1 Q1 → P2 Q4′ → 降级 Q3
        ↓
P0 identity + Schema → P3 判定器 → P4 反证合成
        ↓
单目标 Core Complete → PP / Gate P → P5 由小到大的评估
```

- **PF 排在一切之前**：关系错了，后面所有测量都在测错的东西。它的外部侧用手写 C stub，**与 P1/P2 完全解耦**。已完成。
- **PC 是 PP 的前置**：语法四态会让 PP 系统性错估猎物池。已完成。
- **PP 在核心闭环后决定是否投入规模化评估和新发现搜索。由维护者自行执行**，见该节。
- **PG 是 P3 能吃到真实数据的前提**：关系需要三个 Rust 侧事实，PC 只做完其中一个。
- **Q4′ 已从附属查询升为主查询**，见 P2。

---

## PF — 核心关系与四个 matched fixture

**服务 [Gate R](milestone-gates.md#gate-r关系正确性)。前置：无。风险：低。成本：小。**

### 问题

旧的 2×2 判定矩阵（bound 形状 × 外部行为）有可构造的假阳性与假阴性，见 [research thesis §2.5](../project/research-thesis.md)。必须先把关系换成 §2.4 的轨迹可行性形式，并用 fixture 验证它真的能分开该分开的情况。

### 要做

实现 [research thesis §2.4](../project/research-thesis.md) 的关系，三类生命周期 R / A / G 分开建模，然后构造四个 matched fixture。

| # | Rust 侧 | 外部 C stub | 应判 | 检验什么 |
| --- | --- | --- | --- | --- |
| 1 | `PermitsNonStaticCapture`，无 guard | 保存 + 晚调 | 不相容 | 基本正确性（正对照） |
| 2 | `PermitsNonStaticCapture`，返回 `Registration<'a>` guard | 保存 + 晚调，**注销真的清槽** | 相容 | 不得误报 guard 保护的 API |
| 3 | 与 #2 **完全相同的 Rust 侧** | 保存 + 晚调，**注销没清干净** | 不相容 | **外部侧是否有判别力** |
| 4 | `RequiresStaticCapture`，分配提前释放 | 保存 + 晚调 | 不相容 | R / A 分离，不得漏报 |

**fixture 2 与 3 的 Rust 侧必须逐字节相同**，只有 C stub 不同。这是本阶段唯一真正重要的设计约束。

### 完成谓词

四条全部判对；且在 2 与 3 上，Full 能分开而 Rust-only 不能。**若 Rust-only 也能分开，说明外部侧在这条关系上没有净贡献**——那是 [Gate A](milestone-gates.md#gate-a外部证据必要性) 的提前失败信号，应转路线 B。

### 非空性检查

把 fixture 3 的 C stub 换成「注销真的清槽」，确认判定翻转为相容且翻转位置符合预期。

---

## PC — `EffectiveCaptureAdmission`

**服务 PP 的正确性。前置：无，可与 PF 并行。风险：中。**

### 问题

现有 `CallbackLifetimeBoundScope` 是**语法**四态。其中 `NoLifetimeBound` 把两种语义相反的情况合并了：

- `fn register<F: Fn()>(f: F)` —— 没有 `'static` **恰恰允许捕获借用**，是最强候选；
- `Box<dyn Fn()>` —— 省略的 trait object lifetime **默认到 `'static`**，根本不是候选。

**在修正前，PP 会把最强的一类候选记成弱候选。**

### 要做

改为语义取值 `PermitsNonStaticCapture` / `RequiresStaticCapture` / `ContextDependent` / `Unresolved`。归一化至少覆盖：泛型 `F: Fn`；`impl Fn`；`dyn Fn` 的默认 lifetime 规则；容器产生的 implied bound；参数与返回值的 implied lifetime；HRTB；回调参数 lifetime 与捕获环境 lifetime 的区别；registration guard 对 lifetime 的约束。

### 代码入口

`compiler/bw-rustc/src/rustc_api/mir.rs` 的 `callback_lifetime_bounds`；`crates/bw-model/src/static_fact.rs` 的 `CallbackLifetimeBoundScope`。

### 完成谓词

对上列每一种签名形状都有 fixture，且取值与手工判读一致。`benchmarks/compiler-fixtures/callback-lifetime-bound/` 需按新取值扩充。

### 非空性检查

`dyn Fn` 与泛型 `F: Fn` 两个 fixture 必须落到**相反**的取值。若两者仍相同，说明归一化没生效。

---

## PG — Rust 侧剩余的两个事实

**服务 C2。前置：无，可与 P1 并行。风险：中。**

### 问题

[research thesis §2.4](../project/research-thesis.md) 的关系需要**三个** Rust 侧事实。PC 只做完了第一个：

| 事实 | 状态 | 缺了会怎样 |
| --- | --- | --- |
| `EffectiveCaptureAdmission` 回调 bound 允不允许捕获借用 | **已完成**（PC） | — |
| `RegistrationGuard` 有没有 guard 把注册绑在被捕对象上 | **已完成**（PG-1） | **「为什么必须看外部侧」的论证落空**——那条论证建立在「Rust 看得到 guard、但判断不了它是否有效」上 |
| `AllocationOwnership` 回调分配交出后归谁 | **零行代码** | `'static` 只管住捕获、管不住 `Box<F>` 的存活。这一整类漏报看不见（PF 的 fixture 4 就是它） |

**另有一处**：目前没有任何代码把编译器输出装成 `RustContractFact`。PF 阶段那四个 fixture 的 Rust 侧事实是**手写**的。这一步属于 P0。

### 要做

**PG-1 `RegistrationGuard`**（**已完成**）：判定一个安全 API 是否返回「其 `Drop` 调用外部函数、且类型上把注册存活绑到被捕对象」的值。三条判据：返回类型带本函数声明的 lifetime 参数；该 lifetime 与回调 bound 指向同一个声明；该类型的 `Drop` impl 的 MIR 里有指向**外部函数**的调用。

> **第 3 条的措辞较原计划收窄。** 原文写的是「指向注销角色 API 的调用」，而角色分类只能来自人工 API map，用它当必要条件会让 guard 检测无法规模化，也把人工标注的语义当成了 Rust 侧观察。**「Rust 只能看到 `Drop` 调了某个外部函数、判断不了它是否真的清空槽位」正是 [§2.6](../project/research-thesis.md) 那条论证本身**，因此只判这个形状，有效性交给 Q4′。有 API map 时角色信息仍在 `RegistrationSiteFact` 里，作交叉验证而非必要条件。

**不产出 `OwnerDropUnregisters`**：其判据是 owner 类型 drop 路径的证明，与 `ReleasePathProofFact` 同源，不是返回值形状。已知覆盖缺口：`Result<Registration<'a>, E>` 这类包一层的返回值、以及定义在别的 crate 因而拿不到 `Drop` MIR 的 guard 类型，都落 `Unresolved`（不是判「无 guard」）。

**PG-2 `AllocationOwnership`**：判定回调分配交出之后是否仍可能被 Rust 侧提前释放。

### 可复用的原材料

**PG-2 不是从零开始。** 编译器已有：`RawPointerTransferKind::{IntoRaw, FromRaw, FromRawParts}`（所有权转移方向）、`ReleasePathProofFact`（释放路径的控制流证明）、`DropPreventionFact`。需要的是把它们按交出点聚合，再加一层分类。

**PG-1 是新的**，但形状不复杂：`Drop` impl 的 MIR 里找注销角色的调用，注册角色分类已有（`compiler/bw-rustc/src/registration.rs`）。

### 完成谓词

三个 Rust 侧事实都能从真实 crate 的签名与 MIR 产出；在 `benchmarks/compiler-fixtures/callback-retention-relation/` 的 Rust 形状上，产出的取值与 PF 阶段手写的那组**逐字段一致**。

### 非空性检查

**PG-1 已做，两半都做了**（2026-07-31）：

| 扰动 | 结果 |
| --- | --- |
| 让「`Drop` 里调了外部函数」判据失效 | `register_guarded` 从 `TiesSlotToSubject` 落到 **`Unresolved`**，失败落在 golden 的预期断言上；其余断言不受影响 |
| 把 fixture 2/3 手写事实的 guard 改成 `Unresolved` | 14 项里 5 项失败，含 `full_separates_fixtures_2_and_3`——**Gate R 的分离能力依赖这个事实** |

第一项的落点是 `Unresolved` 而不是本文原先预测的 `None`：`Registration::drop` 里确实有调用，只是分类不出来，那是缺证而不是「没有 guard」。取值阶梯按可测量的区别分格，见实现的 `DropForeignCall`。

**PG-2 待做**：把分配归属判据的「注册后存在 `FromRaw` 释放路径」这一条去掉，确认 `register_static_then_free` 的取值从 `RustRetainsAndMayFreeEarly` 落回 `ForeignOwnedUntilUnregister`，且 PF 的 fixture 4 判定随之翻转。

---

## PP — 猎物存在性探针

**服务 [Gate P](milestone-gates.md#gate-p猎物存在性)。实现前置：PC、PG-2、`is_unsafe_fn`、safe-entry lineage；正式 Gate P-b 还依赖 P1–P4 的核心闭环。风险：低。**

> **执行归属：由维护者自行执行**（2026-07-31 决定）。维护者已确认猎物池中存在相当数量的相关问题，因此本阶段不由 Agent 推进。判据与统计口径仍以本节及 [runbook](../experiments/runbooks/prey-existence-probe.md) 为准——**由谁执行不改变 Gate P 的判据**，尤其是 Tier A、L1 可分析、置信界与 family-level sealed split 四条。

### 问题

在投入规模化评估之前必须知道：生态里还剩多少个**安全客户端可能形成 lifetime separation 的交出点**，以及这些候选有多少能经完整流水线转成独立确认。Gate P-a 测池子，Gate P-b 测转化率。**若池子不足以支撑 [research thesis §7.8](../project/research-thesis.md) 的确认集与新发现目标，路线 A 不继续扩大，但已经完成的核心工具链仍可支持路线 B/C/D。**

### 为什么核心闭环后再正式做

Gate P-a 的 Rust-only 扫描内核可以提前开发；但 Gate P-b 需要真实的 candidate → join → verdict → witness → confirmation 流水线。先完成一个纵向闭环，才能测转化率而不是使用手工估计。

### 要做

先在 5–10 个目标上校准，在 10–30 个 crate 上做小型 pilot，再根据预注册样本量决定是否扩到 300–500 个 FFI crate。按两级统计：

**Tier A-R（referent 子路线）** —— 同时满足：

1. 是安全 API（无 `unsafe fn`）；
2. 有 Fn 家族的泛型或 trait object 参数；
3. 该参数的 `EffectiveCaptureAdmission` 为 `PermitsNonStaticCapture`（**语义取值，不是语法四态**，见 PC）；
4. 回调 / trampoline / userdata 经过程内或**有界过程间 dataflow 到达精确的 extern 参数**；
5. 能绑定到精确的外部 LLVM IR（L1 tier）。

**Tier A-A（allocation 子路线）** —— 前四项中的安全入口、精确 hand-off 与 L1 要求相同，但契约条件改为 `RequiresStaticCapture + RustRetainsAndMayFreeEarly`。R 与 A 必须分别统计、分别判定，不能因 R 的 No-Go 把 A 默认为零。

**Tier B（仅探索性筛选）** —— 回调表面与 `extern` 调用只发生**语法共现**（同函数内出现 extern 调用）。

**Tier B 既不是精确候选，也不是上界**——它同时高估（无关 extern 调用）和低估（helper、RAII 构造器、宏生成桥、多层 wrapper 里的交出）。**不得用 Tier B 数字作 Go/No-Go。**

执行步骤、抽样预注册与 sealed split 见 [猎物存在性探针 runbook](../experiments/runbooks/prey-existence-probe.md)。

### 完成谓词

产出一张按 crate 分组的候选池表，分列 Tier A / Tier B，标注 IR acquisition tier，区分「已参与本项目开发的 crate」与未调优 crate，并对每个候选记录 `EffectiveCaptureAdmission` 取值。**判据是未调优、L1 可分析的 Tier A 候选数的置信下界。**

**运行前必须完成 family-level sealed split**，默认由独立 runner 只返回盲化聚合统计——否则按 [research thesis §7.6](../project/research-thesis.md) 整个前瞻池会变成开发集。

### 非空性检查

在已知含有该形状的 fixture（`benchmarks/compiler-fixtures/callback-lifetime-bound/`）上必须命中；把条件 3 反向后必须落空。另需**随机抽审**一部分 Tier A 阳性与候选阴性，估计探针的 PPV 与漏检率——合成 fixture 与反向检查只能发现恒空分类器，**不能证明生态召回率**。

---

## P0 — hand-off 身份与双侧事实模型

**服务 C2 的前提。前置：无。风险：低，但必须一次做对。**

### 问题

现有事实全部单侧，两侧连接键是函数名。已发生两次由此导致的错误：候选按边界切分，把同一函数的两半分到不同候选；判定只挂给持有其中一半的候选，导致另一半读不到结论。

### 要做

引入交出点身份，并把事实按「契约 / 行为 / 判定」三类重组：

```rust
/// 交出点身份：跨越语言边界的那一次调用。
/// 必须足以在同一个冻结构建内唯一定位一次真实交出。
struct HandOffId {
    rust_artifact: ArtifactHash,        // Rust 侧构建产物
    rust_def_instance: DefInstanceId,   // 单态化实例，不是泛型定义
    call_occurrence: SiteId,            // 该实例内的调用出现次序
    foreign_artifact: ArtifactHash,     // 外部构建产物
    foreign_symbol: SymbolRef,          // 符号 + 符号版本
    callback_arg_index: u32,
    userdata_arg_index: Option<u32>,
    registration_key: Option<RegistrationKey>,
    build_profile: BuildProfileId,      // target + features + 编译配置
}

struct RustContractFact    { hand_off: HandOffId, dimension: Dimension, contract: Contract }
struct ForeignBehaviorFact { hand_off: HandOffId, dimension: Dimension,
                             behavior: Behavior, evidence: Vec<IrEvidenceRef> }
/// 三个维度正交，不得合并成一个枚举。见 research thesis §2.7。
struct CompatibilityVerdict{ hand_off: HandOffId, dimension: Dimension,
                             contract: Contract, behavior: Option<Behavior>,
                             static_verdict: StaticVerdict,
                             evidence_grade: Option<EvidenceGrade>,
                             witness_status: WitnessStatus,
                             assumptions: Vec<AssumptionRef>,
                             witness_obligation: Option<WitnessObligation> }

enum StaticVerdict {
    SupportedIncompatibility,
    CompatibleWithinAnalyzedFragment,
    InsufficientEvidence,
}

enum EvidenceGrade {
    SameSlotInvokeCandidate,   // 降级 Q3 的上限
    ReachableMayInvoke,
    PathSupportedLateInvoke,
    GuardDefeated,
}

enum WitnessStatus {
    NotAttempted, Generated, Executed,
    ConfirmedCounterexample, Inconclusive,
}
```

**`SupportedIncompatibility (weak)` 及任何第四态一律禁止。** 证据强度由 `EvidenceGrade` 承载，反证结果由 `WitnessStatus` 承载。

`Dimension` 取 [research thesis §4](../project/research-thesis.md) 的八维；当前只实例化 `HoldPeriod`。

**源码位置与函数名只能作为诊断字段，不能参与联结。**

### 迁移方式

不要一次性删除现有事实种类。新增这一层，让持有期维度先走通。现有 `StaticFact` 继续作为底层观察，新层是它们的聚合。

### 代码入口

`crates/bw-model/src/static_fact.rs`、`crates/bw-model/src/lifecycle_v326.rs`、`crates/bw-model/src/id.rs`、`compiler/bw-rustc/src/site.rs`（`SiteDescriptor` 是现成的可扩展入口）、`compiler/bw-rustc/src/domain.rs`。

### 完成谓词

两侧事实可在**不依赖候选切分**的前提下联结。用持有期维度验证：契约事实与行为事实分属不同候选时，判定仍然成立且两侧候选都能读到。同一调用包含多组 callback/userdata 时仍能区分。

### 非空性检查

把 join key 改回函数名或候选 ID，确认联结测试失败且失败落在预期断言上。

---

## P1 — 外部侧 Q1：逃逸（前提，非判别项）

**服务 C2 的前提。前置：无，可与 P0 并行。风险：中。**

### 查询定义

> 对外部函数 `f` 的指针形参 `p`，`p` 是否到达一处「`f` 返回后仍存活」的存储。

### 定位说明

**Q1 是前提，不是判别项。** 进入候选集合的 API 按定义都带注册语义，因此 Q1 的答案在候选集合上可能几乎恒为「是」，恒为真的项没有判别力。外部侧真正的判别力在 **Q4′（清槽）**，见 [research thesis §2.6](../project/research-thesis.md) 与 P2。

Q1 仍然必须做——它提供槽位身份，Q3 与 Q4′ 都建立在它之上。但**不得把 Q1 的产出当作 C2 的机制证据**。

### IR 获取分级

| 级别 | 情况 | 处理 |
| --- | --- | --- |
| L1 | 外部 C 源码随构建提供 | **先只支持这一级。** 用 clang 产出与 Rust 侧同配置的 LLVM IR |
| L2 | 链接系统库，源码需单独获取 | 暂不支持 |
| L3 | 仅有二进制 | 放弃，写入 limitation |

外部 IR 的编译配置必须与该 crate 实际构建一致（同 target、同宏定义、同优化级别）。**不得另行编译一份「相似的 C 源码」代替真实构建产物。**

### 算法

从指针形参出发的前向传播：

1. 以 `p` 为起点建立值集合；
2. 沿 `bitcast`、GEP、`phi`、`select`、参数透传传播；
3. 命中以下任一即判 `MayRetain`：写入全局变量；写入通过其他指针参数可达的内存；写入堆对象字段；被 `memcpy` 到上述位置；传入未知 callee；
4. 若 `p` 只在本函数内被 load/比较/同步使用后返回，判不逃逸；
5. 有限深度的过程间 summary，深度与边界必须显式记录。

### 纪律

**查不出逃逸不得判定为安全。** 分析不完整、IR 不可得、间接调用无法解析，一律记 `InsufficientEvidence`。误报方向必须落在保守的一侧。

### 完成谓词

单一库上端到端产出指令级可回查的逃逸证据，且能与该库的 Rust 侧契约事实按 `HandOffId` 联结。正负 pattern suite 通过。

### 止损条件

**若两三周内看不到端到端结果，贡献结构需要重新设计。** 早暴露比晚暴露便宜。

---

## P2 — 外部侧 Q4′ 清槽 与降级 Q3 晚调

**服务 C2。前置：P1。风险：全路线最高。**

**内部顺序是 Q1 → Q4′ → 降级 Q3**，不按查询编号排。理由：Q1 只提供槽位身份、答案在候选集合上可能恒为真；判别力全在 Q4′；降级 Q3 只产出反证义务。**先做完 Q4′ 再做 Q3**，否则会在没有判别项的情况下先投入产出最弱的一段。

**Q4′ 已从附属查询升为主查询之一**，见 2.5。它是外部侧真正有判别力的部分。

Q3 是判定矩阵右列的那一半——没有它，「逃逸到存储」无法升级为「会在返回后被调用」。**本节记录当前决定的降级、降级的确切代价，以及完整实现的分阶段计划。**

### 2.1 Q3 的完整形式

> 对外部函数 `f` 的函数指针形参 `p`，是否存在一条执行路径，使 `p` 所指函数在 `f` **返回之后**被调用。

完整判定需要同时解决三个子问题：

| 子问题 | 内容 | 代价 |
| --- | --- | --- |
| **S1** | `p` 逃逸到跨调用存活的存储槽 `S` | = Q1，可做 |
| **S2** | 存在一个从库的**任一导出入口**可达的间接调用点 `i` | **全库可达性** |
| **S3** | `i` 的 callee 操作数在某条路径上确实取自 `S` | **间接调用的 callee 解析** |

S2 与 S3 是昂贵的：

- **S2** 要在整个外部库上建立调用图并做可达性。以 sqlite3 为例，amalgamation 约 25 万行 C、数百个导出符号；查询不再是「以这个调用点为中心」的局部问题，而是每个外部构建产物一次的全库分析。
- **S3** 按定义就是**通过存储槽的间接调用**——正是 points-to 分析最难的情形。要精确建立 `S → i` 的取值关系，需要 field-sensitive、flow-sensitive 的堆模型。

### 2.2 首期实现：降级为「同槽间接调用存在性」

**判据**：

> 若 `p` 逃逸到槽 `S`（Q1 成立），且外部库内存在任一间接调用点 `i`，其 callee 操作数经 `load` / `bitcast` / GEP / `phi` 链可回溯到与 `S` **同一个字段位置**（同一 struct 类型 + 同一字节偏移，或同一全局符号），则判 `MayInvokeAfterReturn`；否则若 `p` 仅出现在 `call` 指令的被调位置且不逃逸，判 `SynchronousInvokeOnly`；其余情况判 `InsufficientEvidence`。

这把 S2+S3 从「可达性 + 精确取值」降为「同槽位存在一个间接调用点」，代价降低一个数量级。

**保守方向**：宁可多判 `MayInvokeAfterReturn`，不可漏判成 `SynchronousInvokeOnly`。降级后的判据在 may 方向上放宽，符合这个要求。

### 2.3 降级的确切代价

**降级版不证明的事**：它**不证明**存在一条真实的返回后调用路径。它只证明「存在一个从同一槽位取出函数指针的间接调用点」。该调用点可能不可达、可能被路径条件排除、可能读的是同类型的另一个分配。

**因此降级版单独不足以下 `SupportedIncompatibility`。** 按 [research thesis §2.7](../project/research-thesis.md) 的正交维度，它的正确输出是：

```text
StaticVerdict      = InsufficientEvidence
InvokeReachability = 同槽调用点级别（最低档）
WitnessObligation  = EstablishLateInvoke
```

**不得输出 `SupportedIncompatibility (weak)` 或任何第四态**——旧版本引入的那个写法破坏三态模型，已废除。必须由 C1 的反证补上真实可达性证明：反证真的跑起来、外部组件真的回调进来，才产生 `WitnessStatus = ConfirmedCounterexample`。**动态确认不改变静态 verdict 的语义。**

### 2.3.1 这条输出必须能被 P4 消费

**降级 Q3 永远输出 `InsufficientEvidence`，永不输出 `SupportedIncompatibility`。** 若 P4 只接受后者，首期实现里 P4 就没有合法输入——这是计划里的死锁，不是措辞问题。

**解法**：P4 的合格输入是两类之一，见 [P4 的输入接口](#p4-的输入接口)与 [ADR-0004](../decisions/ADR-0004-joint-trace-verdict-semantics.md)。

**降级并非纯粹的损失。** 对能够生成反证的候选，动态执行证据的强度**高于**静态可达性证明——前者是真实发生的，后者是 may-behavior。降级 Q3 的真正损失落在**不能生成反证的候选上**：那里只能停在 `StaticVerdict = InsufficientEvidence` + `EvidenceGrade = SameSlotInvokeCandidate`，无法给出结论。

这条取舍必须写进论文的 limitation，并且**必须量化**。

### 2.4 必须报告的三个数字

对所有被降级 Q3 判为 `MayInvokeAfterReturn` 的候选：

| 指标 | 含义 |
| --- | --- |
| `WitnessStatus = ConfirmedCounterexample` 的比例 | 降级判据的有效精度**下界** |
| `WitnessStatus = Inconclusive` 的比例 | 反证已执行但未触发。**这不是证伪** |
| `WitnessStatus = NotAttempted` 的比例 | 无法生成反证，即 limitation 的实际规模 |

**「反证未触发」只能记 `Inconclusive`，不得记为候选被证伪。** 有限次动态执行不能证伪一个 may-property——被判 `MayInvokeAfterReturn` 的槽位可能需要特定输入、特定并发交错或特定配置才会走到那条路径。把 `Inconclusive` 记成误报，会系统性地高估降级判据的错误率，并可能导致错误地放弃真实缺陷。

这三个数字是论文里 Q3 降级 limitation 的全部内容。没有它们，降级就是一个未量化的弱点。

### 2.5 Q4′ 清槽：外部侧真正的判别项

> `unregister` / `replace` 类外部符号是否在**所有相关路径上**把槽 `S` 写回空值。

**2026-07-31 复审后从附属查询升为主查询。** 理由见 [research thesis §2.6](../project/research-thesis.md)：Q1 的答案在候选集合上可能恒为真，判别力全在这一项。

要回答的四个子问题：

| 子问题 | 为什么 Rust 侧看不见 |
| --- | --- |
| 注销是否在**所有路径**上清空槽位 | Rust 侧只看到 `Drop` impl 调了某个外部函数，看不到它内部是否真的清了 |
| `replace` 的覆盖语义 | 是覆盖旧槽、还是追加到列表、还是写到第二个槽 |
| 是否存在**绕过 guard 的第二条晚调路径** | 另一个外部入口可能从别的槽位读到同一个指针 |
| 同一槽位是否被多个 registration instance 共享 | 影响「注销了哪一个」的判定 |

**这也是 guard 有效性的判据来源。** [research thesis §2.4](../project/research-thesis.md) 中「registration guard 否定 `SafeLifetimeSeparationPossible`」这一条**依赖 Q4′**——guard 只有在其 drop 路径真的清空槽位时才成立。没有 Q4′，guard 只能记 `InsufficientEvidence`，不能记「相容」。

`GuardDefeated` 这一 `EvidenceGrade` 取值即由本查询产生。

它同时服务：C1 反证中 `unregister-before-drop` 负对照的义务；[research thesis §7.7](../project/research-thesis.md) 中 `Full − unregister analysis` 这一项消融；PF 阶段 fixture 2 与 3 的分离。

范围仍然窄，与 Q1 共用传播框架。**它本身不是独立创新点**——创新点是把它接进 §2.4 的关系里。

### 2.6 完整 Q3 的未来工作计划

按依赖顺序。每一阶段独立可交付，可在论文成稿后继续推进。

| 阶段 | 内容 | 完成谓词 | 解锁什么 |
| --- | --- | --- | --- |
| **F1 库级可达性** | 对每个外部构建产物建一次调用图，间接边按函数指针类型签名保守连接；产出「槽 `S` 是否被任一导出入口可达的间接调用点读取」 | 在目标库上产出可达性判定，且对 fixture 中人为不可达的槽给出否定 | 把 S2 从「存在调用点」提升为「存在可达调用点」 |
| **F2 分配点敏感的槽模型** | 把 `S` 从「struct 类型 + 偏移」精化为具体分配点（allocation-site-based 堆模型） | 同类型的两个不同实例不再互相污染，fixture 上可分离 | 消除 2.3 中「读的是同类型的另一个分配」这一误报来源 |
| **F3 路径条件** | 判定该间接调用是否受「是否已注册」的守卫控制（如 `if (db->xCallback) db->xCallback(...)`） | 能区分「无条件调用」与「注册后才可能调用」 | 把「存在可达调用点」提升为「注册后必然可被调用」，此时静态判定可独立支撑 `SupportedIncompatibility` |
| **F4 与清槽的交互** | 把 Q4′ 的清槽 effect 接入 F3 的路径条件，给出完整的 release protocol | 能判定「注销后该路径不再可达」 | 判定器可输出精确的 release 义务，而不只是「存在需清除的槽」 |

**F1–F4 完成后应称为「declared abstraction 内的高精度 Q3」，不得称为独立确认。** 即使四个阶段全做完，静态分析仍不能自动证明：抽象路径条件可满足；任意导出入口可从 safe Rust wrapper 到达；register 与 invoke 对应同一个运行时实例；保守的间接调用边不是虚假边；线程入口、动态链接与别名关系完整。

`if (db->xCallback) { db->xCallback(...); }` 只说明存在一个受注册状态约束的 **may-call 形状**，不说明「注册后必然可被调用」。

因此 F1–F4 提高的是 `EvidenceGrade`（从 `SameSlotInvokeCandidate` 升到 `PathSupportedLateInvoke`），**不改变「`SupportedIncompatibility` 的完整形式需要反证或人工 ground truth」这一结论**。降级判据在 F1–F4 之后退化为快速预筛。

### 2.7 P2 的完成谓词

单一库上：Q1、降级 Q3 与 Q4′ 端到端产出指令级可回查证据；与 Rust 侧契约按 `HandOffId` 联结；`StaticVerdict` / `EvidenceGrade` / `WitnessStatus` 三个维度分别可测试；2.4 的三个指标有采集通路（数值本身在 P4 之后才有）。

**Q4′ 必须能分开 PF 阶段的 fixture 2 与 3**——那是它有判别力的最小证明。

### 2.8 Plan B

把范围收缩为「外部源码随构建提供的 FFI crate」，作为明确 scope 写入论文而非当作失败。该子集足以支撑评估。

---

## P3 — 关系判定器

**服务 C2。前置：P0 + P2。风险：低。**

实现 [research thesis §2.4](../project/research-thesis.md) 的关系（**不是旧的 2×2 矩阵，那个已因可构造的假阳性与假阴性废除**），把外部侧证据来源从「注册事实推断」换成 Q1/Q3/Q4′ 证据。人工版本边界保留为**交叉验证**：两路结论都写入产物，不一致时都保留。

### 判定过程

对每个 `(X, Slot)`，`X ∈ {R referent, A allocation}`，分两步：

**第一步：`SafeLifetimeSeparationPossible(X, Slot)`**

| Rust 侧观察 | 对 X = R | 对 X = A |
| --- | --- | --- |
| `EffectiveCaptureAdmission = RequiresStaticCapture` | **否定**（排除借用捕获） | 不否定——`'static` 不约束分配存活 |
| `EffectiveCaptureAdmission = PermitsNonStaticCapture` | 不否定 | 不否定 |
| 返回 registration guard，其类型把 Slot 存活绑到 X | **否定**，但**需 Q4′ 证明该 guard 的 drop 路径真的清槽**；否则记 `InsufficientEvidence` | 同左 |
| owner 的 drop 必然触发注销 | 否定，同样需 Q4′ | 同左 |
| 分配由外部拥有直到注销 | 不适用 | 否定 |
| `ContextDependent` / `Unresolved` | `InsufficientEvidence` | `InsufficientEvidence` |

**第二步：`ForeignLateUsePossible(Slot, X)`**

| 外部侧证据 | 结果 |
| --- | --- |
| Q1 判不逃逸 | 否定 → `CompatibleWithinAnalyzedFragment` |
| Q1 逃逸 + Q3 有晚调路径 + Q4′ 证明无有效 clear | 成立，`EvidenceGrade` 按 Q3 的强度取值 |
| Q1 逃逸 + Q4′ 证明存在**可证明有效**的 clear 支配所有晚调路径 | 否定 → `CompatibleWithinAnalyzedFragment` |
| Q1 逃逸 + Q4′ 发现绕过 guard 或未清空的路径 | 成立，`EvidenceGrade = GuardDefeated` |
| 外部侧不可得 / Q3 只有降级证据 | `InsufficientEvidence` + 相应 `EvidenceGrade` + witness obligation |

两步都成立且 `SameArtifactSlotAndRole` 满足时，`StaticVerdict = SupportedIncompatibility`。

### 三条纪律

- **`'static` 只否定 X = R，不否定 X = A。** 把它当作整体安全会漏掉分配提前释放这一整类。
- **guard 不是纯 Rust 侧判据。** 没有 Q4′ 就没有「guard 有效」这个结论，只有 `InsufficientEvidence`。
- **`OverRestrictive` 标签只在闭世界地证明所有相关路径均为同步时可用**；否则最多称 `PotentiallyStrongerThanObservedForeignRequirement`。

### 完成谓词

判定来源字段显示为外部侧证据；与人工边界不一致的条目被单独列出；Full / Rust-only / Foreign-only / manual-foreign-oracle 四个变体能作用于**同一 candidate universe**；PF 阶段的四个 fixture 全部判对。

### 非空性检查

把 Q4′ 的输出强制为「注销总是清槽」，确认 PF fixture 3 从不相容翻转为相容——**这条同时验证判定器接了 Q4′，也验证 Q4′ 确实在起判别作用**。

---

## P4 — 反证合成与执行

**服务 C1（首要创新点）。前置：P3。风险：中高。**

### P4 的输入接口

**合格输入有两类**，不只是不相容判定：

1. `StaticVerdict = SupportedIncompatibility`；
2. `StaticVerdict = InsufficientEvidence` + `WitnessObligation = EstablishLateInvoke`，**前提是** Rust 侧分离性、Q1、Q4′ 与身份都已充分——缺的只是晚调可达性。

**第 2 类是首期实现的主要输入**，因为降级 Q3 永远落在这一档。动态成功写入 `WitnessStatus = ConfirmedCounterexample`，**不静默改变原有静态判定的语义**。

`JointTraceObligation`（两侧分别成立但联合可行性未证明）同样可作为输入——反证跑通本身就是一条实际发生过的联合轨迹。

### 拆成 P4a 与 P4b

冻结时机是 Gate B 的判据，所以规格必须与生成分离：

| 子阶段 | 内容 | 时机 |
| --- | --- | --- |
| **P4a** | adapter schema、合法 API 使用方式的描述规范、人工成本口径 | 核心闭环早期定义；crate-specific adapter 必须在该 crate 的判定跑出来之前冻结 |
| **P4b** | 由判定/义务推导危险动作序列并执行 | P3 之后 |

**对正式 unseen 样本**：crate-specific adapter 必须在看到判定与 ground truth 之前冻结；最好由独立准备者完成；vulnerable/fixed pair 尽量复用同一份 adapter。

### adapter 边界（Gate B 的判据）

反证生成需要每个 crate 一份声明式 adapter。这与「不得手写每个 crate 的专用 harness」之间的界线必须写死，否则 C1 退化为手工 PoC：

> **adapter 只描述「如何合法使用这个 API」**——怎么创建前置对象、参数怎么构造、怎么触发一次外部调用。
>
> **adapter 不得包含任何与缺陷相关的信息**——不得写「注册后 drop 该对象」、不得写触发顺序、不得写预期结果。
>
> **触发缺陷的动作序列必须由判定结果自动推导。**

**可测的执行纪律**：adapter 必须在该 crate 的判定跑出来**之前**写好并冻结，记录冻结时的 commit 与时间戳。事后修改 adapter 的记录必须保留并计入人工成本。

### 生成物

- `#![forbid(unsafe_code)]` 的最小客户端；
- pinned 依赖与构建配置，绑定 P1 使用的同一外部 artifact hash；
- vulnerable / fixed / 负对照变体；
- 执行日志、oracle 输出与 witness checksum。

### 必须包含的对照

| 对照 | 预期 |
| --- | --- |
| vulnerable + 借用回调 + 晚触发 | 产生目标证据 |
| fixed version | 干净，或客户端因正确 bound 无法编译 |
| owned callback | 干净 |
| unregister-before-drop | 干净 |
| no-trigger | 干净 |
| 同步外部实现（matched pair） | 干净 |

### oracle 选型与 admissibility

依据 MiriLLI 的结论：Miri 无法观察外部函数内部。因此对真实外部库采用 sanitizer；跨语言联合解释器路线更强但更重，写入 discussion。

**一把 sanitizer 打不了所有情况**——普通 ASan 不覆盖所有 Rust lifetime / provenance UB。三类缺陷分别定义可接受 oracle，每类都要有正负对照：

| 缺陷类 | 典型现象 | 可接受 oracle |
| --- | --- | --- |
| referent 失效后被访问 | stack-use-after-scope | 栈对象失效检测 |
| allocation 提前释放 | heap use-after-free | 堆分配器检测 |
| 清槽失败后仍被调用 | callback-after-clear | 语义事件 + 独立执行证据 |

**本项目自有的 runtime/oracle 只能作为辅助定位证据，不能单独构成 UB 结论。未触发统一记 `Inconclusive`。**

### 完成谓词

至少一个**未参与 adapter 模板开发**的新 crate，可以从候选自动到达独立证据；失败必须有可统计的原因分类。回调实际访问已失效对象；结果不由 synthetic 事件单独决定；同一反证能稳定重放；所有对照绑定各自 artifact hash。

### 非空性检查

把 fixed 版本喂给生成器，确认它拒绝生成或生成物无法编译，且拒绝理由是 bound 已收紧而不是其他原因。

---

## P5 — 评估

实验结构、指标定义、ground truth、数据隔离与消融见 [research thesis §7](../project/research-thesis.md)，不在此重复。执行顺序按“功能闭环优先、规模评估后置”：

1. PF 四个 matched fixture（Gate R）
2. LLVM micro/pattern suite
3. 单一真实 historical vulnerable/fixed pair
4. matched pairs（Gate A1）与 safe-only witness（Gate B 最小线）
5. 5–10 个目标的接入校准
6. 10–30 个 crate 的小型 pilot
7. PP 猎物探针与真实转化率（Gate P）
8. 消融八项与 Gate A2
9. 与 Yuga / FFIChecker 的精度对照（[runbook](../experiments/runbooks/precision-comparison-at-scale.md)）
10. 与 MiriLLI、deepSURF 和现有测试套件对照；固定环境并报告 timeout-censored time-to-witness
11. 生态级扫描，报告完整 attrition waterfall
12. 前瞻扫描与披露（Gate D）

---

## 已撤销的计划项

以下阶段在旧版计划中存在，现予撤销。**不得因为代码里还有相关骨架就恢复它们。**

| 旧阶段 | 撤销原因 |
| --- | --- |
| 旧 P1「消除人工 API 清单」 | 其立论（现有工具需要清单才能报）已于 2026-07-31 被 Yuga 基线否定。结构化角色推断仍会实现，但作为工程属性，不排独立阶段、不做消融立论 |
| 旧 P5「别名与重入维度」 | 持有期一维闭环前不扩维。转 future work |
| 旧 P6「线程维度」 | 同上 |
| 旧 Q2「写穿」 | 服务别名维度，随之转 future work |
| 旧 2×2 判定矩阵 | 有可构造的假阳性（guard）与假阴性（`'static` 不保证分配存活），已由 [research thesis §2.4](../project/research-thesis.md) 的轨迹可行性关系取代 |
| `SupportedIncompatibility (weak)` | 破坏三态模型，由 `EvidenceGrade` + `WitnessStatus` 两个正交维度取代 |
| 语法四态 `CallbackLifetimeBoundScope` | `NoLifetimeBound` 合并了语义相反的两种情况，由 `EffectiveCaptureAdmission` 取代（PC） |

---

## 贯穿全程的纪律

见 [research thesis §15](../project/research-thesis.md)。摘要：

- 缺证、相容、不相容三态必须可区分，缺证不是安全；
- 静态判定、证据强度、反证状态三个维度正交，不得用一个枚举表达；
- 反证未触发只能记 `Inconclusive`，**有限次执行不能证伪 may-property**；
- 两半齐才是缺陷，单侧证据只产出候选；
- join key 必须是被判定对象的身份，不是分析产物的切分单位；
- 改判定器必须做非空性验证：破坏判据的一半，确认对应断言失败且落在预期位置；
- 模型与 schema 双向比对，不靠逐条手写断言；
- 先测量再编码：实现任何判据之前，先测量它在真实样本上会返回什么。
