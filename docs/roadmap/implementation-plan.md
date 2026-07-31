# 完整功能实现计划

本文是 [roadmap](roadmap.md) 各阶段的可执行细化。方向权威是 [research thesis](../project/research-thesis.md)：**任何一项如果不能落到 C1/C2/C3 之一，就不该做。**

本文于 2026-07-30 全量重写，取代此前所有版本。旧版本的 P0–P7 编号、`Mismatch`/`NoMismatch` 判定表、以及「P1 消除人工 API 清单」阶段一律作废。

当前阶段是 **V3.2.x core-effect hardening**。本文描述计划，不是已达成能力。

---

## 现状基线

**已有**：Rust 侧 HIR/MIR 事实抽取、候选生成、生命周期证据与图、排序、witness plan、runtime/oracle/fuzz observer 基础、单一库的 harness。

持有期维度的 Rust 侧契约可以从签名读出（四态：绑在 receiver 声明的 lifetime / 绑在其他声明的 lifetime / `'static` / 无 outlives bound），并已与外部边界事实联结、把判定与判定来源写入产物。

**缺口：外部侧不存在。** 持有期维度的外部侧那一半目前由 API 清单分类出的注册/注销事实**推断**得来，不是外部代码行为。三条创新点因此都未成立。

## 关键路径

```text
PP 猎物存在性探针 ──（决定后续是否投入）──┐
                                          │
P0 hand-off 身份与双侧事实模型 ───────────┼─→ P3 关系判定器 ─→ P4 反证合成 ─→ P5 评估
                                          │
P1 外部侧 Q1 逃逸 ─→ P2 外部侧 Q3 晚调 ───┘
```

- **PP 排在一切之前。** 它成本最低、否定力最强。
- **P0 与 P1 可并行起步。**
- **P2 是关键路径上风险最高的一段**，其降级方案见该节。

---

## PP — 猎物存在性探针

**服务 [Gate P](milestone-gates.md#gate-p猎物存在性)。前置：无。风险：低。成本：约为 P1+P2 的百分之一。**

### 问题

在投入外部侧实现之前必须知道：生态里还有多少个「safe API + 非 `'static` 的 Fn bound + 同函数内 FFI 注册」的位置。这一缺陷类在 Rust 社区是公开知识，`'static` 修法众所周知，猎物池可能已被维护者清空。**若池子只有个位数，[research thesis §7.2](../project/research-thesis.md) 的新发现硬要求无法满足，路线 A 直接死。**

### 为什么现在就能做

Rust 侧的回调 bound 四态判定**已实现**（`compiler/bw-rustc/src/rustc_api/mir.rs` 的 `callback_lifetime_bounds`），不依赖外部侧、不依赖 API 清单。探针只需要把它跑到规模上。

### 要做

在 300–500 个 FFI crate 上运行 Rust-only 前端，统计同时满足以下条件的公开函数：

1. 是安全 API（无 `unsafe fn`）；
2. 有 Fn 家族的泛型或 trait object 参数；
3. 该参数的 outlives bound 短于 `'static` 或不存在；
4. 同一函数体内存在 `extern` 调用。

执行步骤与统计口径见 [猎物存在性探针 runbook](../experiments/runbooks/prey-existence-probe.md)。

### 完成谓词

产出一张按 crate 分组的候选池表，区分「已参与本项目开发的 crate」与未调优 crate，并对每个候选记录 bound 形状。**候选池规模与其中未调优部分的占比是 Gate P 的判据。**

### 非空性检查

在已知含有该形状的 fixture（`benchmarks/compiler-fixtures/callback-lifetime-bound/`）上必须命中；把条件 3 反向后必须落空。

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
struct CompatibilityVerdict{ hand_off: HandOffId, dimension: Dimension,
                             contract: Contract, behavior: Option<Behavior>,
                             verdict: Verdict, assumptions: Vec<AssumptionRef>,
                             witness_obligation: Option<WitnessObligation> }

enum Verdict {
    SupportedIncompatibility,
    CompatibleWithinAnalyzedFragment,
    InsufficientEvidence,
}
```

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

## P1 — 外部侧 Q1：逃逸

**服务 C2。前置：无，可与 P0 并行。风险：中。**

### 查询定义

> 对外部函数 `f` 的指针形参 `p`，`p` 是否到达一处「`f` 返回后仍存活」的存储。

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

## P2 — 外部侧 Q3：晚调（含降级方案）

**服务 C2 的核心判据。前置：P1。风险：全路线最高。**

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

**因此降级版单独不足以下 `SupportedIncompatibility`。** 它只能产出 `SupportedIncompatibility (weak)`，必须由 C1 的反证补上真实可达性证明：反证真的跑起来、外部组件真的回调进来，才把「存在同槽间接调用」升级为「确实会被晚调」。

**降级并非纯粹的损失。** 对能够生成反证的候选，动态执行证据的强度**高于**静态可达性证明——前者是真实发生的，后者是 may-behavior。降级 Q3 的真正损失落在**不能生成反证的候选上**：那里只能停在 `InsufficientEvidence` 或 `weak`，无法给出结论。

这条取舍必须写进论文的 limitation，并且**必须量化**。

### 2.4 必须报告的三个数字

对所有被降级 Q3 判为 `MayInvokeAfterReturn` 的候选：

| 指标 | 含义 |
| --- | --- |
| 被反证证实的比例 | 降级判据的有效精度下界 |
| 被反证证伪的比例 | 降级引入的误报，且必须给出误报机制归因 |
| 无法生成反证的比例 | 降级未被覆盖的部分，即 limitation 的实际规模 |

这三个数字是论文里 Q3 降级 limitation 的全部内容。没有它们，降级就是一个未量化的弱点。

### 2.5 附属查询 Q4′：清槽

> `unregister` / `replace` 类外部符号是否把槽 `S` 写回空值。

范围窄，与 Q1 共用传播框架。它服务两件事：C1 反证中 `unregister-before-drop` 负对照的义务；[research thesis §7.6](../project/research-thesis.md) 中 `Full − unregister analysis` 这一项消融。**不作为独立创新点。**

### 2.6 完整 Q3 的未来工作计划

按依赖顺序。每一阶段独立可交付，可在论文成稿后继续推进。

| 阶段 | 内容 | 完成谓词 | 解锁什么 |
| --- | --- | --- | --- |
| **F1 库级可达性** | 对每个外部构建产物建一次调用图，间接边按函数指针类型签名保守连接；产出「槽 `S` 是否被任一导出入口可达的间接调用点读取」 | 在目标库上产出可达性判定，且对 fixture 中人为不可达的槽给出否定 | 把 S2 从「存在调用点」提升为「存在可达调用点」 |
| **F2 分配点敏感的槽模型** | 把 `S` 从「struct 类型 + 偏移」精化为具体分配点（allocation-site-based 堆模型） | 同类型的两个不同实例不再互相污染，fixture 上可分离 | 消除 2.3 中「读的是同类型的另一个分配」这一误报来源 |
| **F3 路径条件** | 判定该间接调用是否受「是否已注册」的守卫控制（如 `if (db->xCallback) db->xCallback(...)`） | 能区分「无条件调用」与「注册后才可能调用」 | 把「存在可达调用点」提升为「注册后必然可被调用」，此时静态判定可独立支撑 `SupportedIncompatibility` |
| **F4 与清槽的交互** | 把 Q4′ 的清槽 effect 接入 F3 的路径条件，给出完整的 release protocol | 能判定「注销后该路径不再可达」 | 判定器可输出精确的 release 义务，而不只是「存在需清除的槽」 |

**F1–F4 全部完成后，Q3 不再依赖反证补证**，降级判据退化为快速预筛。在此之前，`SupportedIncompatibility` 的完整形式必须包含反证。

### 2.7 P2 的完成谓词

单一库上：Q1 与降级 Q3 端到端产出指令级可回查证据；与 Rust 侧契约按 `HandOffId` 联结；`SupportedIncompatibility (weak)` 与 `InsufficientEvidence` 的分界可测试；2.4 的三个指标有采集通路（数值本身在 P4 之后才有）。

### 2.8 Plan B

把范围收缩为「外部源码随构建提供的 FFI crate」，作为明确 scope 写入论文而非当作失败。该子集足以支撑评估。

---

## P3 — 关系判定器

**服务 C2。前置：P0 + P2。风险：低。**

实现 [research thesis §2.4](../project/research-thesis.md) 的判定矩阵，把持有期判定的外部侧证据来源从「注册事实推断」换成 Q1/Q3 证据。人工版本边界保留为**交叉验证**：两路结论都写入产物，不一致时都保留。

### 判定表

| Rust 侧契约 | 外部侧行为 | 判定 |
| --- | --- | --- |
| bound 短于 `'static` | `MayRetain` + `MayInvokeAfterReturn`（完整 Q3） | `SupportedIncompatibility` |
| bound 短于 `'static` | `MayRetain` + 降级 Q3 判 `MayInvokeAfterReturn` | `SupportedIncompatibility (weak)`，反证义务待补 |
| bound 短于 `'static` | `SynchronousInvokeOnly` | `CompatibleWithinAnalyzedFragment` |
| bound 为 `'static` | `MayRetain` | `CompatibleWithinAnalyzedFragment` |
| bound 为 `'static` | `SynchronousInvokeOnly` | `CompatibleWithinAnalyzedFragment` + `OverRestrictive` 标记 |
| 任意 | 外部侧不可得 | `InsufficientEvidence` |
| 无 outlives bound | 任意 | `InsufficientEvidence`（签名不表态） |

**`'static` 只排除非静态捕获这一子问题，不得解释为回调分配永远存活或 API 整体安全。**

### 完成谓词

判定来源字段显示为外部侧证据；与人工边界不一致的条目被单独列出；Full / Rust-only / Foreign-only / manual-foreign-oracle 四个变体能作用于**同一 candidate universe**。

### 非空性检查

把外部侧行为强制为 `SynchronousInvokeOnly`，确认所有 `SupportedIncompatibility` 消失且消失位置符合预期。

---

## P4 — 反证合成与执行

**服务 C1（首要创新点）。前置：P3。风险：中高。**

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

### oracle 选型

依据 MiriLLI 的结论：Miri 无法观察外部函数内部。因此对真实外部库采用 sanitizer；跨语言联合解释器路线更强但更重，写入 discussion。

**本项目自有的 runtime/oracle 只能作为辅助定位证据，不能单独构成 UB 结论。**

### 完成谓词

至少一个**未参与 adapter 模板开发**的新 crate，可以从候选自动到达独立证据；失败必须有可统计的原因分类。回调实际访问已失效对象；结果不由 synthetic 事件单独决定；同一反证能稳定重放；所有对照绑定各自 artifact hash。

### 非空性检查

把 fixed 版本喂给生成器，确认它拒绝生成或生成物无法编译，且拒绝理由是 bound 已收紧而不是其他原因。

---

## P5 — 评估

实验结构、指标定义、ground truth、数据隔离与消融见 [research thesis §7](../project/research-thesis.md)，不在此重复。执行顺序：

1. PP 猎物探针（Gate P）
2. LLVM micro/pattern suite
3. matched pairs（Gate A）
4. historical vulnerable/fixed pairs
5. 消融八项
6. 与 Yuga / FFIChecker 的精度对照（[runbook](../experiments/runbooks/precision-comparison-at-scale.md)）
7. 与 MiriLLI + 现有测试套件的对照
8. 与 deepSURF 类工作的确认率/生成率/time-to-witness 对照
9. 生态级扫描
10. 前瞻扫描与披露（Gate D）

---

## 已撤销的计划项

以下阶段在旧版计划中存在，现予撤销。**不得因为代码里还有相关骨架就恢复它们。**

| 旧阶段 | 撤销原因 |
| --- | --- |
| 旧 P1「消除人工 API 清单」 | 其立论（现有工具需要清单才能报）已于 2026-07-31 被 Yuga 基线否定。结构化角色推断仍会实现，但作为工程属性，不排独立阶段、不做消融立论 |
| 旧 P5「别名与重入维度」 | 持有期一维闭环前不扩维。转 future work |
| 旧 P6「线程维度」 | 同上 |
| 旧 Q2「写穿」 | 服务别名维度，随之转 future work |

---

## 贯穿全程的纪律

见 [research thesis §15](../project/research-thesis.md)。摘要：

- 缺证、相容、不相容三态必须可区分，缺证不是安全；
- 两半齐才是缺陷，单侧证据只产出候选；
- join key 必须是被判定对象的身份，不是分析产物的切分单位；
- 改判定器必须做非空性验证：破坏判据的一半，确认对应断言失败且落在预期位置；
- 模型与 schema 双向比对，不靠逐条手写断言；
- 先测量再编码：实现任何判据之前，先测量它在真实样本上会返回什么。
