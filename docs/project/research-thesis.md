# 研究主线与创新点

本文是**唯一的方向权威**。路线图、实现计划、范围边界、当前状态都必须服从本文；任何实现如果不能落到本文的某一条创新点上，就不该做。

本文于 2026-07-30 全量重写，取代此前所有版本。**旧版本中的中心论题、创新点编号（N1/N2/N3）、判定枚举（`Mismatch`/`NoMismatch`）与「现有工作检不出」类表述一律作废**，不得在论文、代码注释、提交信息或对外材料中继续出现。

当前阶段是 **V3.2.x core-effect hardening**。本文描述目标研究包，**不表示仓库已经具备相应能力**；实现状态以 [current status](current-status.md) 为准，能力边界以 [scope and boundaries](scope-and-boundaries.md) 为准。

---

## 1. 统领主张

Rust 的全部安全价值建立在一条保证之上：**不写 `unsafe` 的代码不可能触发未定义行为。** 库作者用 `unsafe` 换取这条保证向调用者的传递——安全 API 的类型签名即是它对调用者作出的承诺。

在 FFI 边界上这条保证会被系统性地打破，且打破的方式是机械可检测的：Rust 的类型签名允许回调捕获一个短生命周期借用，而边界另一侧的外部组件把这个回调保存到调用返回之后并再次执行它。此时**只用 safe Rust 就能触发释放后使用**，安全抽象不成立。

> **本研究度量这条保证在 Rust FFI 边界上被打破的频率与形态，并对每一次打破给出只使用 safe Rust 的可执行反证。**

这一句是论文的中心主张，摘要、引言、模型、实现和实验必须共用它。它把工作定位为**对一项安全机制的度量**，而不是又一个 lint 或又一个检测器——这是本工作能进入安全顶会而非工具论文的唯一区别。

**但在拿到 §7.3 的 attrition waterfall 之前，这一句只是目标主张。** 系统实际产生四个不会天然相等的集合（可分析总体、静态判定、反证生成、独立确认），「对每一次打破都给出反证」是其中最窄的一个。用中心主张替代分级报告，是对结果的系统性美化。

### 1.1 目标会议与判据

IEEE S&P、USENIX Security、ACM CCS、NDSS。这类 PC 接受两种东西：真实漏洞与其影响，或对某一安全性质的类级别可度量结论。本工作押注后者，并以前者作为其可信度锚点。

---

## 2. 研究问题与分析片段

### 2.1 判定的问题

研究对象是 Rust crate 对外暴露的**安全 API**。该 API 接受回调或 user data，并将其交给 C/C++ 等外部组件。

> 对一个确定构建中的具体交出点（hand-off），**安全客户端能否构造出一条轨迹，使某个被外部持有的对象失效而注册仍然有效，且外部随后仍可能使用它？** 若能，能否生成一个只使用 safe Rust 的可执行反例？

判定的是**安全客户端可达的时序状态**，不是 lifetime bound 的字面形状。这一点在 2026-07-31 的复审后改写——原表述以 bound 形状为判据，可被构造出假阳性与假阴性，见 §2.5。

### 2.2 分析片段（analyzed fragment）

第一阶段只支持**外部源码随构建提供、能够取得 LLVM IR** 的 crate。论文必须在模型一节显式给出这个片段，评估结论只在片段内成立。

系统**不承诺**：

- 覆盖仅有二进制的外部库；
- 建立完整的跨语言全程序语义；
- 完成任意深度、完全精确的 points-to 分析；
- 证明整个 crate 或整个 API 在所有维度上健全；
- 进行可利用性判断或 exploit 生成。

外部 IR、间接调用、动态链接或别名关系不足时，系统必须返回 `InsufficientEvidence`。**「没有观察到逃逸」不得推断为安全。**

### 2.3 三类生命周期必须分开

**这是判定正确性的前提。** 合并任意两类都会产生可构造的错判。

| 记号 | 对象 | 由什么约束 |
| --- | --- | --- |
| **R** referent | 回调**捕获的**借用对象 | 回调类型的 outlives bound；guard 的类型 |
| **A** allocation | 回调分配本身与 trampoline userdata（`Box<F>` 等） | Rust 侧的所有权与 drop；注销路径 |
| **G** registration | 外部槽位上的注册实例 | 外部的 register / replace / clear effect |

`F: 'static` **只约束 R，完全不约束 A**。一个 `'static` 回调的 `Box<F>` 仍然可能被 Rust wrapper 提前释放，而外部随后调用悬垂指针。把 R 与 A 合并，就会把这一整类缺陷判成相容。

### 2.4 核心关系

判据是**安全客户端的轨迹可行性**，不是 bound 的字面形状：

```text
SupportedIncompatibility(X, Slot)
  ⇐ SeparationCertificate(X, Slot)
  ∧ ForeignLateUseEffect(Slot, X)
  ∧ JointTraceFeasible(X, Slot)
其中 X ∈ { R, A }
```

**`JointTraceFeasible` 不是可以省略的第三项。** 2026-07-31 复审后新增：前两项是两条独立的 **may-property**，分别成立**不蕴含它们能在同一条执行上同时发生**。而 `SupportedIncompatibility` 这个结论读起来正是后者。要求两侧证据在**同一构建、同一交出点、同一槽位、同一 registration generation，且路径条件相容**下能形成一条联合轨迹。

`SameArtifactSlotAndRole` 是 `JointTraceFeasible` 的必要条件，**但不充分**：它保证两侧指的是同一个槽位，却分不开同一槽位上的不同注册实例（"注册 A → 注销 → 注册 B"）。registration generation 见 [ADR-0003](../decisions/ADR-0003-target-verifier-dataflow-and-identity.md)。

三条纪律：

- **`SeparationCertificate` 是正面证据。** 「没有观察到保护机制」不等于「已证明不存在保护机制」——前者只是缺证，后者才构成证书；
- **静态证不出联合可行性时返回 `InsufficientEvidence`**，并附一条 `JointTraceObligation`，不得因为两项分别成立就下不相容结论；
- **动态反证可以完成联合轨迹的证明**：反证真的跑起来、外部真的回调进来，那就是一条实际发生过的联合轨迹。这也是 C1 在关系上的位置。

**`SeparationCertificate(X, Slot)`**

> 存在一条 well-typed、只使用安全 API 的客户端轨迹，使 `X` 失效而 `Slot` 上的注册仍然有效。**这是一份正面证书**，需要证据支持；查不到保护机制只产出缺证，不产出证书。

Rust 侧能够**否定**它的机制（这些让 API 健全）：

- 回调 bound 要求 `'static` —— **只否定 X = R，不否定 X = A**；
- registration guard 的类型把 `Slot` 的存活绑到 `X` 上（例如返回 `Registration<'a>`）；
- owner 的 drop 必然触发注销；
- 对 X = A：分配由外部拥有直到注销。

**`ForeignLateUseEffect(Slot, X)`**

> 同一 registration slot 上存在 retain 与「返回之后 use/invoke」的 may-path，**且中间不存在可证明有效的 clear / unregister**。

**最后那个从句是本关系里外部侧真正有判别力的部分**，它由 Q4′ 回答。见 §2.6。

**`SameArtifactSlotAndRole`**

两侧事实必须引用同一 artifact、同一 hand-off、同一 callback/userdata 参数角色、同一 registration slot 才能组合。按函数名、API 名或候选分片联结一律禁止。

### 2.5 原 2×2 矩阵为什么被废除

2026-07-31 的复审构造出两个反例，`non-'static bound + MayRetain + MayInvokeAfterReturn ⇒ 不相容` 因此不成立：

**假阳性——guard 使 API 健全。** API 接受 `F: 'a` 并返回 `Registration<'a>`，guard 的类型保证被捕对象至少活到注册结束，drop 时先执行 unregister。外部**确实**保存并晚调，但安全客户端构造不出 `referent_dead ∧ registration_live`。旧矩阵会报——错报。

**假阴性——`'static` 不保证分配存活。** 见 §2.3。旧矩阵判「相容」——漏报。

**一处事实错误一并更正：** 旧文档称 rusqlite 0.26.2 的修复落在「`'static` + 仅同步调用」格。**这是错的。** [RUSTSEC-2021-0128](https://rustsec.org/advisories/RUSTSEC-2021-0128.html) 说明这些函数注册回调供 SQLite 稍后调用；0.26.2 收紧了 bound，**没有把 SQLite 的行为改成同步**。修复版落在 `'static + retain/late-invoke`，即在借用捕获这一子问题上相容。

`OverRestrictive` 这一标签只有在**闭世界地证明了所有相关路径均为同步**时才能使用；否则最多称 `PotentiallyStrongerThanObservedForeignRequirement`。

### 2.6 外部侧的判别力在 Q4′ 而不在 Q1

一个推论，直接决定 [Gate A](#gate-a外部证据必要性) 能否通过。

进入候选集合的 API 按定义都带注册/注销语义——一个只做同步回调的 API 根本不需要把回调交出去。因此 **Q1（是否保存）的答案在候选集合上可能几乎恒为「是」，恒为真的项没有判别力。**

真正因库而异、且 Rust 侧看不见的是：

- 注销是否在**所有路径**上都清空槽位；
- replace 的覆盖语义；
- 是否存在**绕过 guard 的第二条晚调路径**；
- 同一槽位是否被多个 registration instance 共享。

**这也是 guard 有效性的判据来源。** Rust 侧只能看到 guard 的 `Drop` impl 调了某个外部函数；**那次调用是否真的清空了槽位，只有外部侧能回答**。所以 §2.4 中「否定 `SafeLifetimeSeparationPossible` 的 guard 机制」本身依赖外部证据，guard 不是纯 Rust 侧的事。

因此 Q4′ 从附属查询升为**主查询之一**，见 [implementation plan](../roadmap/implementation-plan.md)。

### 2.7 判定的三个正交维度

**不得用一个枚举同时表达「静态判定」「证据强度」「反证状态」。** 旧文档引入的 `SupportedIncompatibility (weak)` 破坏了三态模型，予以废除。

```text
StaticVerdict
  = SupportedIncompatibility          // 两侧证据共同支持不相容
  | CompatibleWithinAnalyzedFragment  // 片段与假设内未形成该类不相容
  | InsufficientEvidence              // 任一侧事实、联结身份、行为证据或联合可行性不足

ForeignEvidence                        // 外部证据，四个**正交**字段（Planned）
  = { RetentionEffect                 // Q1：是否到达跨调用存活的存储
    , InvokeReachability              // 晚调证据强度：同槽调用点 / 可达 / 路径支持
    , ClearReplaceStatus              // Q4′：是否所有路径清槽、是否存在绕过 guard 的路径
    , PathCompatibility }             // 两侧路径条件是否相容——JointTraceFeasible 的输入

WitnessStatus
  = NotAttempted | Generated | Executed
  | ConfirmedCounterexample | Inconclusive

WitnessObligation
  = EstablishLateInvoke               // 只有降级 Q3 的同槽调用点证据
  | JointTraceObligation              // 两侧分别成立，联合可行性未证明
```

**外部证据必须是四个正交字段，不是一个枚举。** 现有实现用单一 `EvidenceGrade` 同时表达"同槽调用候选/可达/路径支持"与"guard 被击穿"——前三者是一条可达性阶梯，第四者是清槽结论，两者不可比较。实测后果是 guard 被击穿时晚调证据等级被直接覆盖丢失。可以派生一个报告级总体等级用于展示，**不得丢失原始维度**。字段拆分状态为 `Planned`，见 [ADR-0004](../decisions/ADR-0004-joint-trace-verdict-semantics.md)。

三条纪律：

- **降级 Q3 的输出是 `StaticVerdict = InsufficientEvidence` + 同槽调用点级别的 `InvokeReachability` + 一条 `EstablishLateInvoke` 义务**，不是任何形式的 `SupportedIncompatibility`；
- **反证阶段消费义务，不只消费不相容判定。** 降级 Q3 永不产出 `SupportedIncompatibility`，若 C1 只接受后者，首期实现里 C1 将没有合法输入。合格输入是：`SupportedIncompatibility`，**或** `InsufficientEvidence` + `EstablishLateInvoke`（前提是 Rust 侧分离性、Q1、Q4′ 与身份都已充分，缺的只是晚调可达性）；
- **动态反证成功产生 `ConfirmedCounterexample`，不改变静态 verdict 的语义。** 反证未触发只能记 `Inconclusive`——**有限次动态执行不能证伪一个 may-property。**

`CompatibleWithinAnalyzedFragment` **只排除本研究定义的回调持有期不相容**，不表示 API 整体健全。

### 2.8 `EffectiveCaptureAdmission`：取代语法四态

原实现按签名语法给出四态（绑 receiver lifetime / 绑其他声明 lifetime / `'static` / 无 outlives bound）。**「无 outlives bound」这一态语义上是错的。**

对泛型 `fn register<F: Fn()>(f: F)`，没有 `'static` 恰恰是**允许 `F` 包含局部借用**，不是「不表态」。而 `Box<dyn Fn()>` 中省略的 trait object lifetime 在多数位置**默认到 `'static`**。两者语义相反，却被合并成同一个 `no_lifetime_bound`。

规范取值改为语义事实：

```text
PermitsNonStaticCapture | RequiresStaticCapture | ContextDependent | Unresolved
```

归一化至少必须处理：泛型 `F: Fn`；`impl Fn`；`dyn Fn` 的默认 lifetime；容器产生的 implied bound；参数与返回值中的 implied lifetime；HRTB；**回调参数 lifetime 与捕获环境 lifetime 的区别**；registration guard 对 lifetime 的约束。

**在这一项修正前，[Gate P](#gate-p猎物存在性) 会系统性错估猎物池**——它现在把最强的一类候选记成弱候选。

---

## 3. 三条创新点

**按可辩护程度排列，不按流水线顺序排列。** 论文的贡献列表必须与本节顺序一致。按流水线顺序（身份 → 判定 → 见证）陈述贡献是本项目此前的错误，它让工作读起来像「我们搭了个系统」而不是「我们有一个想法」。

### C1 — Safe-only 可执行反证的定向合成

**这是最强、也最难被归约到已有工作的一条。**

从一条有证据支持的不相容出发，自动合成一段带 `#![forbid(unsafe_code)]` 的最小 Rust 客户端，链接与静态分析绑定的**精确外部构建**，让外部组件在被借对象失效之后真的回调进来，由独立 oracle 出证。

产出的不是 bug report，是**安全抽象不健全性的可执行证明**：这个库的安全 API 允许纯 safe 代码触发 UB。

反证的最小动作序列由判定结果反推：

```text
创建有限生命周期对象
→ 构造借用该对象的回调
→ 通过目标安全 API 注册
→ 让对象生命周期结束
→ 保持外部 registration 存活
→ 触发外部组件稍后调用回调
→ 回调实际读写失效对象
→ 收集独立 UB 或等价语义证据
```

合格反证必须同时满足：

- 客户端源码 `#![forbid(unsafe_code)]`；
- 调用的是被分析 crate/version 的目标安全 API；
- 链接的是与静态分析绑定的精确外部构建；
- 回调捕获并**实际访问**真实借用对象；
- 晚调行为由外部组件**真实触发**，而不是发送模拟 runtime 事件；
- 由 sanitizer、跨语言执行器或严格可审计的独立 oracle 提供证据；
- vulnerable / fixed / 负对照结果一致；
- 反证、静态候选与外部 IR 证据可通过 hand-off 身份互相回查。

本项目自有的 runtime/oracle 可以记录语义事件并帮助定位，但**不能单独构成最终 UB 证据**，否则形成「自己生成事件、再由自己确认事件」的循环论证。

#### C1 相对已有工作的 delta

**以下几项单独都不是创新点，不得写进贡献列表**（2026-07-31 复审后更正，deepSURF 论文原文已核实）：

- 生成 safe-only 程序；
- 使用 `#![forbid(unsafe_code)]`；
- 从静态候选生成 harness；
- 用 sanitizer 确认；
- 保存 artifact hash 与 lineage。

它们仍是证据质量与 artifact evaluation 的组成部分，写在实现与评估一节。

| 已有工作 | 差别 |
| --- | --- |
| **deepSURF**（S&P 2026） | **不得描述为「盲测求崩溃」。** 论文原文：所有生成的 harness「contain only safe code, enforced by the `#![forbid(unsafe_code)]` directive」，并用 AFL++（ASan + CmpLog 双线程、每 harness 24 小时）覆盖率引导，配合静态 unsafe-reachability 分析、LLM 序列生成与泛型/trait 实现合成。**差别在于搜索 vs 推导**：它生成大量语义合理的 API 序列再靠覆盖率碰，本工作从外部 effect 反推**唯一确定的**时序目标 `referent_dead ∧ registration_live ∧ later_invoke` 并直接构造那一条序列 |
| PinChecker | 同样合成暴露安全抽象不健全的程序，但对象是纯 Rust 的 Pin API 误用模式，**不涉及跨语言**——其触发义务可从 Rust 源码本身推出。本工作的触发义务来自边界另一侧的 effect，Rust 源码里推不出来 |
| SyRust 等程序合成 | 符合 Rust 类型与所有权约束的程序合成已有先例。本工作的合成目标是**具体时序状态**，不是类型可行的任意序列 |
| MiriLLI | 需要一个已经能触发缺陷的测试才能观察到 UB。**本工作合成那个测试。** 度量指标即「现有测试到不了、本系统能到」的数量 |

#### deepSURF 在 rusqlite 上的数据点

论文 Table IV 中 rusqlite 一行为 `0 | 84.2% (108)`：**108 个可编译 harness、84.2% 的 unsafe-reachable API 覆盖、每个 harness AFL++ 加 ASan 跑满 24 小时、发现 0 个 bug**——而该 crate 有已公开的回调持有期公告。

**这是 C1 最有力的头对头设计**：通用覆盖率搜索在该预算下到不了这一类时序路径。若本工作的定向合成能到，差别是可量化的（确认率、time-to-witness）。比较时必须固定 crate/version/feature/target、CPU 与时间预算、工具与 LLM 版本、随机种子、重复次数，并报告 timeout-censored 的 time-to-witness。

**这个数据点也约束我们自己**：若本工作在同一 crate 上同样得到 0，那说明差别不在方法而在别处。

### C2 — 类型契约作为规约、外部 effect 作为实现的精化检查

**核心问题**：如何区分 Rust 侧形状相同、外部语义不同的两种情况——回调只在外部调用中同步执行；回调或 user data 被写入跨调用存活的存储并可能稍后执行。

在 Rust 侧这两者不可区分：都是「一个泛型值活得比某个借用长，并且出现在一个外部指针附近」。区分只能来自边界另一侧。

**这条创新点的知识主张不是「我们做了一个逃逸分析」，而是：**

> Rust 安全 API 的**契约**构成一份隐式规约，外部实现必须满足它；这份规约从未被检查，因为规约与实现分处两门语言，且规约分散在类型签名、guard 协议与 wrapper 的所有权效果里。本工作抽取规约、抽取外部 effect、检查精化关系。

必须这样陈述。Q1/Q3 本身是标准的逃逸与可达性分析，把它们当创新点会被当场驳回；新意在**规约的来源**和**被检查的性质**。

**规约来源不止签名**（2026-07-31 复审后更正）。三个 Rust 侧事实里只有第一个是纯签名事实：

| 事实 | 来源 | 是不是纯签名 |
| --- | --- | --- |
| `EffectiveCaptureAdmission` | HIR 签名的 outlives bound | 是 |
| `RegistrationGuard` | 返回类型的 lifetime + guard 类型 `Drop` impl 的 MIR | 否——需要 drop 协议 |
| `AllocationOwnership` | wrapper 的所有权转移与释放路径（MIR） | 否——需要所有权效果 |

因此**不得把 C2 表述成「类型签名/lifetime bound 是全部规约」**。lifetime bound 仍是 referent 子问题的核心规约来源，但把分配归属包装成签名事实是不准确的，审稿人会追问。准确表述是：**Rust safe-API contract（类型签名、guard 协议、wrapper 所有权效果）作为规约，foreign effect 作为实现。**

Rust 侧抽取：回调泛型或 trait object 的 outlives bound；是否允许捕获非 `'static` 借用；回调分配的 owner 与存活锚；register/replace/unregister 与 owner drop 的关系；回调与 userdata 参数在 FFI 调用中的角色。

外部侧针对精确构建的 LLVM IR 抽取：回调/userdata 是否传播到全局、堆对象、结构体字段等跨调用存储；是仅同步调用还是存在返回后的 may-invoke 路径；replace/unregister 是否清除对应槽位；release 回调是否存在并在相关路径上被调用；unknown callee、间接调用与不可解析别名造成的证据缺口。

#### C2 相对已有工作的 delta

必须在相关工作一节正面回答这两个问题，不能留给审稿人提。

| 问题 | 回答 |
| --- | --- |
| **和 FFIChecker（ESORICS'22）的跨语言 LLVM IR 分析有什么区别？** | FFIChecker 判的是**内存所有权**（这块内存被 free 了吗、有没有 double free）。本工作判的是**时序契约**：函数指针是否被存储并在注册调用返回之后被执行。更关键的是**规约来源不同**——FFIChecker 的判据是内存操作本身的配对关系，本工作的判据是另一门语言的类型系统写下的承诺 |
| **和 MiriLLI（ICSE'25）有什么区别？** | MiriLLI 是动态研究，依赖既有测试触达缺陷路径。本工作静态判定并**合成**触达路径。两者互补：MiriLLI 可作为本工作的 oracle 之一 |

### C3 — 生态级度量与新发现

前两条是机制，这一条是把机制变成安全结论：

> 在**预注册的抽样框**内、可分析片段内的 FFI crate 上，有多少安全 API 允许纯 safe 代码触发 UB；这些破坏呈现哪些形态；其中哪些此前未知。

**措辞必须是「抽样框上的估计」，不是「全集」**（2026-07-31 复审后更正）。§7.8 的规模参考线是约 100 个客观选取的 crate，那是抽样不是普查。**只有真正做了 census 才能用「全集」。** 估计必须给出抽样框定义、抽样方式与置信区间，并按 crate / repository / 外部库家族聚类——这三者不是独立同分布样本。

必须报告的是**分布与形态**，不是一个 precision 数字。至少包括：可构建/可分析比例、判定覆盖率、`InsufficientEvidence` 比例、按 root-cause 聚类的形态分类、新发现及其披露状态。

**新发现是这条的硬要求。** 见 §7.2。

### 不作为创新点的：artifact-aligned hand-off identity

系统需要一个稳定的联结主键，至少包含：

```text
RustArtifactId
+ RustDefInstance / monomorphized instance
+ call occurrence
+ ResolvedForeignArtifact
+ foreign symbol / symbol version
+ callback_arg_index
+ userdata_arg_index
+ registration slot or key
+ target / feature profile / build configuration
```

Rust 事实、外部 IR 事实、静态判定、反证与动态回执全部引用同一个 hand-off 身份；源码位置与函数名只能作诊断信息，不能单独充当联结主键。

**这是任何跨语言分析的基本前提，不是贡献。** 它写在实现一节，一段话讲完。此前版本把它列为第一条创新点是错误的——那会向审稿人表明作者分不清「必要的工程」与「贡献」。它带来的证据 lineage 是好的工件性质，通过 artifact evaluation，不通过 PC。

实现要求见 [implementation plan](../roadmap/implementation-plan.md) 的 P0。

---

## 4. 八维契约模型的定位

系统的通用抽象仍是**逐维契约错配**：每个交出点上，Rust 侧类型层契约与外部侧实际行为在某一维上比较，错配 = 契约允许的比实际发生的宽。

| 维度 | Rust 侧契约（类型/签名层） | 外部侧实际行为（LLVM IR） |
| --- | --- | --- |
| **持有期** | 回调 bound 是声明 lifetime 还是 `'static` | 指针是否逃逸到返回后仍存活的存储、是否可能晚调 |
| 别名与可变性 | 来源是 `&T` 还是 `&mut T`、参数是否 const | 是否被写穿 |
| 线程 | 是否要求 `Send` / `Sync` | 是否被另一线程可达 |
| 重入 | 交出时是否持有 `&mut` 或运行时借用 | 是同步调用还是存起来稍后调用 |
| 展开 | trampoline 是否有 `catch_unwind` | 调用点是否处于不可展开上下文 |
| 释放责任 | 分配与释放是否同侧 | 是否有配对 free 回调、是否真调 |
| 值域不变量 | 返回值被当作何种 Rust 类型 | 实际可能返回的值域 |
| 初始化 | 传入 buffer 的初始化状态假设 | 实际写入范围 |

**本文的定位是：给出这个通用框架，并在持有期一维上完整实例化。** 其余七维是框架的其他实例，作为 taxonomy 与 future work 陈述。

两条纪律：

- **不得表述为「八维错配等价于安全 API 整体健全性」。** Rust 安全抽象的整体健全性不能由这八类局部错配充分且必要地刻画。框架是组织缺陷类的方式，不是健全性的定义。
- **不得为了「统一框架」并行实现其余七维。** 在持有期一维形成真实跨界闭环之前，铺开其余维度只会摊薄。这不是砍掉七维，是先做透一维。

---

## 5. 相关工作定位

| 工作 | 覆盖 | 与本系统的边界 |
| --- | --- | --- |
| **Yuga**（TSE 2024） | 函数签名上的生命周期标注错误 | **已实测：它能报出本项目主线缺陷类的 5/7，修复版精确消失。**「它不建模外部持有者所以不会报」是错的，不得再使用该表述。同一 crate 上 13 条报告有 8 条不对应公告，但**不得表述为「根因完全统一」**——[逐条记录](../experiments/results/gate0-yuga-precision-triage-2026-07-31.md)显示至少四种机制（`Arc` 锚、外层转发、结构体 lifetime 参数、输入到输出的 lifetime），只有其中 4 条接近「Rust 内部结构与外部槽位混淆」。且该记录明确说明**本系统排除这 8 条只用了 Rust 侧签名形状、没有使用外部证据**，因此 n=1 数据**不构成**「外部侧信息消除了这些误报」的证据。它只能给出 "probably assigned"、"potential use-after-free" |
| **FFIChecker**（ESORICS'22） | Rust/C FFI 堆内存管理，LLVM IR 分析 | 判 alloc/dealloc 错配与 double free，规约来自内存操作配对；本工作判时序契约，规约来自 Rust 类型系统。释放责任维度与其重叠，该维度**不作为创新点** |
| **MiriLLI**（ICSE 2025） | Miri + LLVM 解释器联合执行，跨 FFI 的 UB 实证研究 | 动态、依赖既有测试触达路径。**必须作为本工作的 baseline 之一**：指标是「现有测试到不了、本系统能到」。其结论「Miri 看不进外部函数」也是本工作 oracle 选型的直接依据 |
| **deepSURF**（S&P 2026） | 静态 unsafe-reachability + LLM 序列生成 + 泛型/trait 合成 + AFL++ 覆盖率引导，**harness 为 safe-only 并带 `#![forbid(unsafe_code)]`**，用 ASan 确认 | **撞车风险最高。** 已核实原文，**不得描述为盲测**。差别是搜索 vs 推导，见 §3 C1。rusqlite 上 108 harness / 84.2% 覆盖 / 24h 每个 / 0 bug 是最重要的对照数据点 |
| **PinChecker**（2025） | 合成程序暴露 Pin API 安全抽象不健全 | 思路最近的一条，但对象是纯 Rust 的 Pin，不涉跨语言，触发义务可从 Rust 源码本身推出 |
| **SyRust** 类程序合成 | 符合 Rust 类型与所有权约束的 API 序列合成 | 本工作的合成目标是具体时序状态，不是类型可行的任意序列 |
| **Rudra**（SOSP'21） | panic safety、higher-order safety invariant、Send/Sync variance | 技术路线同为 HIR+MIR，但三类缺陷均为 Rust 内部，不含跨界持有期 |
| **ACORN / 多语言 Rust** | Rust 与 C 均译为统一 IR | 本系统不做全量翻译，只做有界查询，须说明代价与精度取舍。**发表年份需核实后再写入**——旧文档标注的 2025 存疑 |

### 5.1 待核实并补入的相关工作

2026-07-31 的复审列出以下工作，**本项目尚未逐篇核实，不得在核实前写进论文或对外材料**。核实后按上表格式补入，每一篇必须写出与本工作的具体差别，不得只列名字。

CRUST（统一 Rust/C 跨语言分析）、CREMA（Rust/foreign 代码的 UAF / never-free / double-free 静态分析）、CULPA（安全要求 → executable predicate → triggerability，**与本工作路线最接近，优先核实**）、SafeFFI（边界运行时 spatial/temporal sanitization）、CapsLock（跨 Rust/FFI/assembly 的运行时 ownership 强制）、Omniglot（safe foreign interaction 与 temporal constraints）、SAILOR / SAVIOR / Helium（静态候选 → harness → 动态确认这一范式的先例，**用于避免过宽的首创声明**）。

**照抄一份未核实的相关工作表，是另一种形式的不严谨。**

### 5.2 绝对新颖性表述一律禁止

不得出现「目前无人做」「首个」这类未经限定的说法；新颖性只能表述为对上表某一行的具体差别。经过本轮更正，可辩护的范围已被压缩到：

```text
role/slot-sensitive 的回调时序协议分析
+ 安全客户端的 lifetime-separation 可行性
+ effect 定向的可执行反证
```

---

## 6. 威胁模型中必须预先声明的一条

维护者对前瞻性发现最可能的回应是：*「文档写了必须先 unregister，这是使用错误。」*

本工作的立场必须在威胁模型一节写死，不能等审稿人或维护者提出来：

> **safe Rust 无论文档如何声明，都不得允许 UB。** 若一个 API 不加 `unsafe`、不要求调用者维持文档约定之外的不变量，就允许纯 safe 代码触发释放后使用，则该 API 不健全。文档中的使用约定不能替代类型层约束——这正是 RustSec 对该类缺陷的判准，也是 rusqlite 通过收紧 bound 而非补文档来修复 RUSTSEC-2021-0128 的原因。

§7.2 的新发现路线依赖维护者确认，这一条是它的前提。

---

## 7. 评估设计

### 7.1 实验结构

| 实验 | 目的 |
| --- | --- |
| LLVM micro/pattern suite | 验证外部侧查询的基本正确性与 unknown 边界 |
| 同 Rust wrapper、不同外部实现的 matched pairs | **证明外部侧信息不可替代**，是 C2 的机制证据 |
| Historical vulnerable/fixed pairs | 已知缺陷 recall 与补丁敏感性 |
| 经审计的 safe/negative wrapper | precision 与 abstention |
| Full vs Rust-only vs Foreign-only vs manual-foreign-oracle | 两侧联结的净贡献；分离外部分析误差与关系模型误差 |
| Static-only vs static+witness | 反证带来的确认增益与 triage 成本变化 |
| **vs Yuga / FFIChecker** | 同任务同分母的精度对照，见 [runbook](../experiments/runbooks/precision-comparison-at-scale.md) |
| **vs MiriLLI + 该 crate 现有测试套件** | 「现有测试到不了、本系统能到」的数量。**此前版本遗漏了这一行** |
| **vs deepSURF 类 harness/fuzzing** | 确认率、生成率、time-to-witness。**此前版本遗漏了这一行** |
| 生态级扫描 | buildability、coverage、`InsufficientEvidence` 比例与成本 |
| Prospective scan | 新问题与维护者反馈 |

### 7.2 新发现是本项目的竞争力要求

「新发现或强 correctness argument 至少具备其一」的旧写法会让项目误以为形式化是真备胎，必须改。但 2026-07-31 的复审指出一个更准确的措辞——四大安全会的 CFP 列出的核心标准是原创性、相关性、科学严谨性、正确性与清晰度，**没有把「必须发现新漏洞」写成形式规则**。

准确表述：

> **鉴于 §3 与 §5 更正后机制 delta 已被显著压缩，实证回报必须承担更多重量。新发现是本项目的竞争力要求，不是会场的形式规则。** 形式化路线在这四个会需要达到 POPL 级别的语义与证明才能替代实证，本项目不具备也不打算具备——形式化补偿只在路线 D（§9）的目标会议成立。

竞争力目标：2–3 个独立新问题；至少跨两个外部库 / 协议族；至少一个获得维护者确认或修复。

### 7.3 必须报告完整的 attrition waterfall

系统会产生四个**不会天然相等**的集合。只报告 precision 而不报告集合之间的收缩，是对结果的系统性美化。

论文必须逐级报告：

```text
eligible hand-off population   （预注册的可分析总体，分母）
→ statically decided           （非 InsufficientEvidence 的比例）
→ supported candidates         （StaticVerdict = SupportedIncompatibility）
→ witness attempted
→ witness generated            （可编译的 safe-only 客户端）
→ witness executed
→ independently confirmed      （独立 oracle 出证）
```

每一级都要给出流失原因的分类。**在拿到这些数字之前，禁止使用以下表述：**

- 「FFI 边界上的保证被系统性打破」；
- 「对每一次 break 都提供证明」；
- 「LLVM IR 给出外部的实际行为」——静态 IR 分析给出的是指定抽象与假设下的 **IR-supported may-effect**，只有动态反证说明某次具体执行真实发生。

§1 的统领主张在 Gate 通过前是**目标主张**，不是能力陈述。

### 7.4 必须报告的指标

不同工具必须在**预先定义的共同任务**上比较。不得用 Yuga 的全部 lifetime 报告对比本系统的窄回调持有期输出。

至少同时报告：raw-alert precision、eligible hand-off precision、decision coverage、abstention/Unknown 比例、known-defect recall、independent root-cause recall、build/analyzability coverage。

```text
conditional precision      = TP / (TP + FP)
decision coverage          = decided / eligible
conservative precision bound = TP / (TP + FP + Unknown)
```

### 7.5 Ground truth

- 确认集结果由两名独立标注者审阅，尽量对工具身份盲化；
- 分歧由第三人裁决；
- 报告一致性、分歧率与证据等级；
- **同一 advisory 的多个 API 不得伪装成多个独立根因。**

四条附加纪律（2026-07-31 复审后补入）：

- **「无公告」不是安全负例。** 没有 advisory 只说明没人报过，不说明 API 健全。把它当负例会同时高估 precision 与低估召回的分母；
- **vulnerable/fixed 差分只是证据之一**，不自动决定 TP/FP。补丁可能同时修了别的东西，也可能用收紧 bound 之外的方式规避；
- **资源不足时明确标 `Blocked`，不得把抽查等价成双人 ground truth。** 20% 抽查是质量控制，不是双人标注；
- **按 repository、外部库家族与 root cause 聚类报告**，这三者都不是独立同分布样本。

### 7.5.1 人工 Role map 的信任边界

**人工 API / Role map 与外部行为事实是两类东西，不得混。**

| 来源 | 允许声明 | **不得**声明 |
| --- | --- | --- |
| 人工 Role map | 符号绑定；callback / userdata 参数角色；register / unregister / replace 的**候选**角色；接入所需的静态元数据 | 实际是否保留；实际是否晚调；是否所有路径清槽；guard 是否有效 |
| 外部 effect 事实 | 上述全部行为结论 | — |

正式 Full 判定中的外部 effect **必须**来自外部 IR 抽取。**手工 foreign oracle 必须带独立的 provenance 与来源等级**，只能用于 fixture、交叉验证与消融，不得伪装成自动分析结果——Gate R 的 C stub 标注即属此类。

这条把 §11 第 4 条与 §12 的主张分级表落成可检查的字段要求，见 [ADR-0005](../decisions/ADR-0005-evidence-trust-and-experiment-statistics.md)。

### 7.5.2 私有 holdout 与第三方可重放

sealed holdout 要求样本身份不公开，而 artifact evaluation 要求第三方能完整重放——两者直接冲突。解决方式是 artifact-evaluation escrow、延迟公开或受控访问。

**不得一边只提供聚合摘要、一边宣称第三方可完整重放。**

### 7.6 数据隔离

- rusqlite 与所有已读源码样本属于**开发集**；
- pilot 中暴露的 crate 此后**永久**转为开发集；
- 算法、阈值、Contract、feature 与 corpus 冻结后才打开 holdout；
- 同一外部库、fork、版本家族与 vulnerable/fixed pair 不得跨集合泄漏。

### 7.7 消融

| 变体 | 回答的问题 |
| --- | --- |
| Full | 目标系统效果 |
| Rust-only | 外部证据的净贡献 |
| Foreign-only | Rust 契约的净贡献 |
| Manual foreign oracle | 分离外部分析误差与关系模型误差 |
| Full − invoke 分析 | 晚调证据的边际作用 |
| Full − unregister 分析 | release protocol 的边际作用 |
| Static-only | 只报告不相容的效果 |
| Static + witness | 反证对确认率与 triage 成本的影响 |

**若关闭外部分析后 precision、coverage 与误报归因没有实质变化，C2 失败**，不得继续把跨界判别写成主创新。

### 7.8 规模参考线

不是会议硬性数字，作为投稿准备线：约 100 个客观选取的 FFI crate 做适用性扫描；至少 10 个未参与开发的 crate 进入人工确认集；至少 30 个独立 hand-off 获得双人标注；至少 5 个独立 root-cause family 或 protocol shape；最好有 2–3 个新问题，至少一个获得维护者确认或修复。

**外部库家族的数量下限不在本阶段设定**，见 §8 Gate C。

---

## 8. Go/No-Go 门槛

本节按 gate 编号解释研究判据，不代表工程实现顺序。**实际实现先完成一个真实目标上的 Rust → foreign IR → join → verdict → witness 核心闭环，再用 Gate P 决定是否扩大到论文级规模。每一道 gate 仍是研究方向的止损点，不是工程里程碑。**

### Gate R：关系正确性（最先做）

**2026-07-31 复审后新增，排在 Gate P 之前。** 关系错了，后面所有测量都在测错的东西。

用四个 matched fixture 验证核心关系（§2.4）。**外部侧用手写 C stub，不需要 LLVM IR 流水线**，因此该 gate 与 P1/P2 完全解耦。

| # | Rust 侧 | 外部 C stub | 应判 | 谁能判出来 |
| --- | --- | --- | --- | --- |
| 1 | 允许捕获借用，无 guard | 保存 + 晚调 | **不相容** | 两侧都能怀疑 |
| 2 | 允许捕获借用，有 guard | 保存 + 晚调，**注销真的清槽** | 相容 | 需要 Q4′ |
| 3 | 允许捕获借用，有 guard | 保存 + 晚调，**注销没清干净** | **不相容** | **只有外部侧能判** |
| 4 | `'static`，分配提前释放 | 保存 + 晚调 | **不相容** | 需要 A 的生命周期建模 |

- **通过**：四条全部判对；且 fixture 2 与 3 的 Rust 侧完全相同、只有 C stub 不同，Full 能分开而 Rust-only 不能。
- **No-Go**：fixture 2 与 3 分不开。
- **失败动作**：外部侧对 C2 没有判别力，转路线 B。

**fixture 3 是整个 gate 的重点**，它是 [§2.6](#26-外部侧的判别力在-q4-而不在-q1) 的直接检验：如果外部侧的价值真的在 Q4′ 而不在 Q1，这一条就必须能分开。fixture 4 检验 R/A 分离，防止 §2.3 的假阴性。

### Gate P：猎物存在性

在投入规模化评估与新发现搜索之前必须回答：**生态里还剩多少个安全客户端可能形成 lifetime separation 的交出点，这些候选有多少能经完整流水线转成独立确认。**

RUSTSEC-2021-0128 这一类在 Rust 社区是公开知识，`'static` 修法众所周知，很多维护者早已收紧。**若猎物池不足以支撑 §7.8 的确认集与新发现目标，路线 A 不再扩大**；保留已完成的核心闭环，根据现有证据转路线 B、C 或 D。

**判据必须满足六条方法学要求**，缺一不可，详见 [runbook](../experiments/runbooks/prey-existence-probe.md)：

1. **以 `EffectiveCaptureAdmission` 为准，不用语法四态**（§2.8）——否则最强的一类候选被记成弱候选；
2. **以 Tier A 为准**：回调 / trampoline / userdata 经过程内或有界过程间 dataflow **到达精确的 extern 参数**。仅「同函数内出现 extern 调用」是 Tier B 语法共现，只能作探索性筛选；
3. **以 L1 可分析为准**：候选必须能绑定到精确的外部 LLVM IR。主表必须标注 IR acquisition tier——**一个很大的 Rust 侧候选池可能全部进不了 P1/P2**；
4. **要求 safe-entry lineage**：只证明回调到达 extern 参数不足以证明**安全客户端能到达该交出点**。缺 lineage 的单列，不计入 Tier A；
5. **以未调优 crate 为准**；
6. **判据是公式，不是形容词**——见下。

### Gate P 拆成两个子 gate

**候选数不能直接推出确认发现数**，中间隔着一个转化率。原判据只写「下置信界仍足以支撑预定确认集」，没有任何换算关系，等于没有判据。

| 子 gate | 问题 | 样本 |
| --- | --- | --- |
| **Gate P-a** | 未调优、L1、Tier A 的交出点还有多少 | 前瞻池（盲化） |
| **Gate P-b** | 这些候选里有多大比例能真正走到确认 | **已跑通 P0–P4 的开发集**，不消耗前瞻池 |

```text
可用猎物估计 = eligible_pool_lower_bound × conversion_rate_lower_bound

Pass   = 该乘积仍足以支撑预注册的确认集规模
No-Go  = 上置信界仍不足
Amber  = 扩大样本或增加人工审计
```

**必须按 crate / repository / 外部库家族聚类报告**——三者都不是独立同分布样本，按 alert 计数会系统性高估。

### R 与 A 必须分开判定

**这是本 gate 最容易出错的一处。** Tier A 的「允许捕获借用」判据只筛 referent 类；allocation 类（`'static` bound + `Box<F>` 提前释放，即 §2.3 的 X = A）的 `EffectiveCaptureAdmission` 恰恰是 `RequiresStaticCapture`，**会被该判据直接排除、记成零**。

因此拆成 `Tier A-R` 与 `Tier A-A`，分别统计、分别套用上式、分别判定。

- **不得因 Tier A-R 的 No-Go 自动放弃 A 子路线**——那是一条从未被测量过的路线；
- 若 `AllocationOwnership` 尚未实现导致 Tier A-A 无法统计，必须明确写「本次只决定 R 子路线，A 保持 `Unknown` 并单独设 gate」，**不得默认为零**。

**运行前必须完成 family-level sealed split。** 直接查看 300–500 个 crate 的身份与候选数，会按 §7.6 把整个前瞻池变成开发集。默认做法是**独立 runner 只返回盲化聚合统计**，开发者不接触 crate 身份。

**全部参数必须在探针运行之前预注册。口头判断不构成通过**——维护者对猎物池的印象可以决定是否值得跑这个实验，不能替代预注册的正式结果。

- 失败动作：R 与 A 都 No-Go 时停止扩大样本与新发现搜索；保留已经完成的核心工具链，转路线 B/C/D。

### Gate A：外部证据必要性

**拆成两个子 gate。** 机制上能分开与端任务上有收益是两件事，混在一起会让"增益"无从归因。

**Gate A1 — 机制增益**

- 通过：在**同一 candidate universe** 上，Full 能区分「注销真清槽」与「注销没清干净」，Rust-only 对两者给出相同结果或必须 abstain；
- No-Go：关闭外部分析后结果不变；所谓增益主要来自更窄的候选范围；外部行为仍主要由 API 清单预先给定。

**Gate A2 — 端任务增益**

- 通过：加入反证后，确认率或判定覆盖率有预注册幅度的提升，或人工 triage 成本有预注册幅度的下降。

**判据必须预注册，不得用「可解释的增益」这类事后可移动的措辞**——本文自己批评过「足够」「非平凡」，这里是同一个毛病。至少写死：比较单位（交出点 / API / crate / root cause，选一个并全程一致）、最小效应量、置信区间下界、允许的 Unknown 与 abstention 比例。

**增益必须归因到 role/slot 敏感的外部证据（主要是 Q4′）。** 按 §2.6，Q1 在候选集合上可能几乎恒为真，恒为真的项没有判别力。已知一处边界：**回调分配的归属是纯 Rust 侧事实**，`ForeignOwnedUntilUnregister` 时 Rust-only 就能正确判相容——外部证据的净贡献集中在 guard 分支，Gate A1 的增益必须归到那里，不能笼统说「因为我们看了外部侧」。

- 失败动作：放弃 C2 作为主角，转路线 B。

### Gate B：反证真实性

**最小工程闭环与投稿竞争线必须分开**，否则一个成功案例会被当成规模化能力，或反过来因为规模不够而否定已经跑通的机制。

- **最小通过线**：至少一个**真正 unseen**（未参与 adapter 模板开发）的候选走通全程——自动生成 safe-only harness、外部组件真实晚调回调、回调实际访问失效对象、独立 oracle 在 vulnerable 上产生证据、fixed 与全部负对照干净；
- **投稿竞争线**：生成率、编译率、执行率、确认率、重放成功率与 adapter 人工成本达到预注册门槛。
- No-Go：只能产生 contract trace；必须手写每个 crate 的专用 harness（判据见 [implementation plan](../roadmap/implementation-plan.md) 的 adapter 边界定义）；结果依赖 synthetic 桥接才成立；无法建立反证与原候选的 identity lineage。
- 失败动作：C1 降级为 contract-path synthesis，不得称为不健全性确认。

**输入接口**：反证阶段接受 `SupportedIncompatibility`，**也接受** `InsufficientEvidence` + `EstablishLateInvoke` 义务（前提是 Rust 侧分离性、Q1、Q4′ 与身份都已充分）。见 §2.7 的第二条纪律。

**oracle admissibility 按缺陷类分别定义。** 普通 ASan 不覆盖所有 Rust lifetime / provenance UB（见 §11 第 31 条），一把 sanitizer 打天下会让某一类缺陷系统性地测不出来：

| 缺陷类 | 典型现象 | 可接受 oracle |
| --- | --- | --- |
| referent 失效后被访问 | stack-use-after-scope | 栈对象失效检测 |
| allocation 提前释放 | heap use-after-free | 堆分配器检测 |
| 清槽失败后仍被调用 | callback-after-clear | 语义事件 + 独立执行证据 |

每一类都必须有正负对照。**未触发统一记 `Inconclusive`**，不是候选被证伪。**本项目自有的 runtime 事件不能单独构成 UB 证据。**

### Gate C0：可移植性 smoke（早期，低成本）

**2026-07-31 复审后新增。** 把「取得外部库 IR 的工程可行性」这个已知风险完全推到认证期，等于最后才发现整套方法只对一个库有效。C0 是它的早期廉价检查：

- 3–5 个外部库家族，至少两种 C 构建方式；
- **只验证**真实 IR 获取、符号解析、artifact 绑定与新库接入成本，不要求判定或反证；
- **失败信号**：若每接入一个新库都要修改分析器内核，立即收窄 scope 或转路线，不要等到认证期。

### Gate C：跨库泛化（认证期决定，当前不设下限）

跨外部库家族的泛化是**投稿认证期**的问题。**本阶段不对家族数量设置实现约束**——P1/P2 的完成谓词只要求单库端到端打通。

**Gate C 不是路线 A 的前置。** §9 的路线 A 条件是「Gate R、P、A、B、D 全通过」，不含 C；§13 的投稿就绪清单同样不含 C。C 在认证期报告，其结果影响的是外部效度陈述的强度，不构成实现阶段的止损点。**早期风险由 Gate C0 承担。**

认证期需要报告的：外部库家族数、新 API 的接入方式与成本、生成成功率、coverage gap。

### Gate D：确认性评估

- **最低通过线**：冻结后的 unseen corpus；公平 baseline 与全套消融；双人 ground truth；coverage、Unknown、cluster 与置信区间完整；**至少一个有独立外部确认的新发现**；
- **投稿竞争线**：2–3 个独立新问题、至少两个外部库或协议家族、至少一个维护者确认或修复（§7.8）。
- No-Go：结论仍来自开发集；100% precision 依赖大量 abstention；指标单位在 alert、API、crate 与 root cause 之间混用；没有新发现。

---

## 9. 投稿路线与备选

| 路线 | 适用条件 | 主张 |
| --- | --- | --- |
| **A：Verifier + Witness 联合主线** | Gate R、P、A、B、D 全通过 | 完整的 §1 统领主张。**当前的目标路线** |
| **B：Witness 合成为主** | 外部侧消融没有明显精度增益，但候选到真实 UB 的自动转化率显著优于 fuzzing baseline | 收窄为「利用静态 lifetime obligation 定向合成 safe-Rust 反例，并以独立跨语言 oracle 验证」。C2 不再是核心，外部分析只服务触发规划 |
| **C：经验研究** | Gate P 失败，或自动化泛化不足，但能建立大规模严格标注的 corpus | 需要生态级样本、vulnerable/fixed pair、多工具盲评、coverage/Unknown、高质量 taxonomy 与 benchmark。**缺少生态级新结论时更适合软件工程会议** |
| **D：形式化 effect/trace calculus** | 实证规模受限，但能为限定片段给出清晰的 compatibility relation、推理规则与正确性论证 | 目标会议改为 CSF、PLDI、OOPSLA。**不能只用一个统一 enum 代替正式语义** |

### 9.1 时间判断

外部侧目前 0% 实现。P2 是一整块静态分析工作，P4 是另一篇论文体量的工作。按当前推进方式，**现实目标是 2027 年中的 USENIX Security 周期或 S&P 2028**，不是 2027 年初。

关键路径与可并行项见 [implementation plan](../roadmap/implementation-plan.md)。

---

## 10. 明确做什么

1. **先做透回调持有期一维。** 外部行为、关系判定、反证与确认性评估全部闭合后，再讨论扩维。
2. **先过 Gate R，再完成单目标核心闭环，然后跑 Gate P。** Gate R 用四个 matched fixture 验关系；随后完成 Rust、真实外部 IR、双侧联结、P3 与 P4，得到可测的真实转化率。Gate P 决定是否继续规模化评估，不阻塞核心原型。
3. **分析真实构建产物。** feature、target、宏、链接对象与 artifact hash 必须与 Rust 分析一致，不得另行编译一份「相似的 C 源码」代替。
4. **保留第三态。** unknown callee、IR 不可得、join 失败全部显式进入 coverage。
5. **制作 matched pairs。** 保持 Rust wrapper 相同，只替换外部的同步/保存行为，直接验证信息增益。
6. **使用真实失效对象。** 反证中必须发生真实借用访问，runtime 事件仅作辅助证据。
7. **提供负对照。** fixed、owned callback、unregister-before-drop、no-trigger、同步外部实现，缺一不可。
8. **保留证据 lineage。** 每个结论都能追溯到 source、IR、artifact、witness 与 receipt。
9. **报告自动化边界。** adapter 数量、人工时间、拒绝原因、失败率与 Unknown 必须量化。
10. **公平比较先验工作。** 承认 Yuga 能检出部分缺陷；把 MiriLLI 与 deepSURF 纳入 baseline。
11. **优先寻找新问题。** 新发现及维护者确认是最有说服力的实际安全价值证据，且按 §7.2 是硬要求。

## 11. 明确不做什么

1. 不再写「八维错配等价于整体健全性」。
2. 不再声称现有工作无法检出回调 lifetime 缺陷。
3. 不把「不需要人工 API 清单」重新包装成创新点——该主张已于 2026-07-31 被基线否定，结构化推断仍会实现，但只作工程属性。
4. 不把人工 API map 当作外部行为证据。
5. 不把 `'static` 解释成回调分配永远存活——它只排除非静态捕获这一子问题。
6. 不把「没有看到 escape」直接判成安全。
7. 不把任何判定写成 API 整体 sound。
8. 不按函数名、API 名或候选分片模糊联结两侧事实。
9. 不用 synthetic 回调事件单独确认 UB。
10. 不把 harness 文件、witness plan、编译成功或单次 crash 当作 witness。
11. 不用 rusqlite 的 5/5 作为确认性精度结果——它是开发对象。
12. 不用不同候选范围比较工具 precision。
13. 不从 precision 分母中删除 Unknown、build failure 与 unsupported。
14. 不把同一公告的多个 API 当成多个独立漏洞根因。
15. 不在 freeze 前反复查看 holdout。
16. 不为追求「统一框架」并行实现其余七个维度。
17. 不做完整外部语义建模、全程序 points-to 或 exploit 生成。
18. 不在没有维护者确认、补丁或独立证据时把前瞻候选称为漏洞。
19. 不使用「目前无人做」之类未经限定的绝对新颖性表述。
20. 不把 artifact-aligned identity 列为创新点。
21. 不把 `SupportedIncompatibility (weak)` 或任何第四态写进判定枚举（§2.7）。
22. 不把「反证未触发」写成候选被证伪——有限次执行不能证伪 may-property。
23. 不把「注册状态守卫下的 may-call」写成「注册后必然被调用」。
24. 不把无显式 outlives bound 一律归为 unknown（§2.8）。
25. 不把「同函数内出现 extern 调用」称为已确认的 hand-off（Tier B ≠ Tier A）。
26. 不把 IR 的 may-effect 称为运行时实际行为。
27. 不把 deepSURF 描述为纯盲测——已核实原文，它生成 safe-only harness 并用 ASan。
28. 不把 rusqlite 0.26.2 写进「同步 / 过度限制」格（§2.5）。
29. 不把 Yuga 的 8 条误报描述为完全相同的单一机制（§5）。
30. 不在核实前把复审列出的相关工作写进论文（§5.1）。
31. 不用普通 ASan 的覆盖结果代表所有 Rust lifetime / provenance UB。
32. 不用维护者确认替代正确性 ground truth。
33. 不把两个分别成立的 may-property 直接合取成不相容结论——需要联合轨迹可行性（§2.4）。
34. 不把「没有观察到保护机制」当成「已证明不存在保护机制」。
35. 不用人工 Role map 预写待验证的外部行为（§7.5.1）。
36. 不把「无公告」当作安全负例（§7.5）。
37. 不用抽查替代双人 ground truth（§7.5）。
38. 不把 Tier A 候选数直接当作可确认发现数——中间隔着转化率（§8 Gate P）。
39. 不因 referent 子路线的 No-Go 自动放弃 allocation 子路线（§8 Gate P）。
40. 不把抽样估计写成「全集」（§3 C3）。

---

## 12. 主张分级规则

| 当前证据 | 允许表述 | 禁止升级为 |
| --- | --- | --- |
| 只有 Rust 事实 | lifecycle-sensitive candidate | 跨界不相容 |
| Rust 事实 + 人工 API map | contract-guided candidate | foreign behavior verified |
| Rust 事实 + 外部 IR effect + exact join | `SupportedIncompatibility` | executable UB |
| 已生成 harness，尚未执行 | witness candidate | dynamic witness |
| 执行了 contract trace | protocol/path confirmation | independent UB confirmation |
| safe client + 真实晚访问 + 独立 oracle | executable counterexample | 对所有客户端或所有版本的普遍结论 |
| vulnerable/fixed/controls + receipt | confirmed finding for pinned artifacts | 整个库或其他配置均不健全 |

---

## 13. 投稿就绪定义

**Gate C 不在本清单内**，见 §8 Gate C。

- [ ] Gate R 通过：四个 matched fixture 全部判对，且 fixture 2/3 只有 Full 能分开；
- [ ] Gate P-a 与 P-b 通过（Tier A-R / A-A + L1 + safe-entry lineage + 未调优 + 置信界 + 转化率），猎物池规模支撑 §7.8 的目标；
- [ ] Gate C0 通过：3–5 个外部库家族的 IR 获取与符号解析可行，接入成本已量化；
- [ ] Gate A1 与 A2 分别通过，增益可归因到 role/slot 敏感的外部证据；
- [ ] 核心主张已从整体 soundness 收窄到回调持有期 compatibility；
- [ ] 分层 hand-off identity（含 registration generation 与 safe-entry lineage）与双侧事实模型完成；
- [ ] 外部侧 Q1/Q3/Q4′ 在真实构建 IR 上完成，Q3 的降级与 limitation 已量化；
- [ ] matched-pair 证明 Full 的信息增益；
- [ ] 三态判定与分析片段写清；
- [ ] 至少一个 unseen 候选自动生成 safe-only 反证；
- [ ] vulnerable/fixed/negative controls 全部对齐；
- [ ] 独立 UB 或等价语义证据存在；
- [ ] Full/Rust-only/Foreign-only/manual-oracle 消融完成；
- [ ] MiriLLI 与 deepSURF 两条 baseline 有数字；
- [ ] 开发集、pilot 与 sealed holdout 严格隔离；
- [ ] precision、recall、coverage、Unknown 与 root-cause clustering 完整；
- [ ] evidence receipt 与 artifact lineage 可公开复核；
- [ ] **至少一个新发现**（§7.2 竞争力要求）；
- [ ] 完整的 attrition waterfall 已报告（§7.3）；
- [ ] 摘要、引言、模型、实现与实验使用同一范围与术语。

---

## 14. 推荐的贡献表述

英文：

> We measure how often Rust's safe-abstraction guarantee is broken at the FFI boundary, and prove each break with an automatically synthesized `#![forbid(unsafe_code)]` counterexample. Our verifier treats a Rust safe API's lifetime bounds as an implicit specification and the foreign implementation's LLVM IR retain/invoke effects as the implementation, and checks the refinement between them at artifact-aligned, parameter-role-level hand-off identities.

中文：

> 本文度量 Rust 的安全抽象保证在 FFI 边界上被打破的频率与形态。系统把 Rust 安全 API 的 lifetime bound 视为一份隐式规约、把外部实现 LLVM IR 中的 retain/invoke effect 视为实现，在参数角色级的交出点身份上检查两者的精化关系，并把有证据支持的不相容自动转化为只使用 safe Rust 的可运行、可独立验证的反例。

**在 Gate R、P、A、B、D 通过前，上述句子只能作为目标主张，不能作为当前能力陈述。**

---

## 15. 方法学纪律

以下几条来自本项目已发生的返工。违反任何一条都会产出「看起来正常但什么都没判出来」的结果。

- **缺证与健全必须可区分。** 没有事实不等于安全。任何判定都要有第三态。
- **两半齐才是缺陷。** 单侧证据只产出候选，不产出结论。
- **join key 必须是被判定对象本身的身份**，不是分析产物的切分单位。候选按边界切分，会把同一函数的两半分到不同候选。
- **改判定器必须做非空性验证**：故意破坏判据的一半，确认对应断言失败且失败落在预期位置。
- **模型与 schema 必须双向比对**，逐条手写断言会漏。
- **先测量再编码。** 本项目已两次在实现某个判据前先测量它会返回什么，两次都发现它恒为空。这一条阻止了两个「静默什么都不判」的分类器上线。

## 16. 相关文档

- 实现路线与阶段划分：[roadmap](../roadmap/roadmap.md)
- 可执行细化与 Q3 降级记录：[implementation plan](../roadmap/implementation-plan.md)
- 当前所处阶段：[current work](../roadmap/current-work.md)
- 能力边界与允许/禁止表述：[scope and boundaries](scope-and-boundaries.md)
- 逐项状态：[current status](current-status.md)
- 研究 gate：[milestone gates](../roadmap/milestone-gates.md)
