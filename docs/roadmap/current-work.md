# 当前工作

本文只记录当前所处阶段与下一步，不保存 Agent prompt 或逐日执行过程。阶段定义见 [roadmap](roadmap.md)，方向权威见 [research thesis](../project/research-thesis.md)。状态词含义见 [terminology](../project/terminology.md)。

## 所处位置

**执行顺序的权威是 [execution plan](execution-plan.md)**；本文只说现在在哪一步。

**Rust 侧三个契约事实做完两个，外部侧零行代码。** 研究路线于 2026-07-30 重定向、2026-07-31 复审后修正核心关系。当前进度：

| 阶段 | 状态 |
| --- | --- |
| PF 核心关系与四 fixture（Gate R） | ✅ `Implemented` |
| PC `EffectiveCaptureAdmission` | ✅ `Implemented` |
| PG-1 `RegistrationGuard` | ✅ `Implemented` |
| PG-2 `AllocationOwnership` | ⬜ 零行代码，**下一步** |
| PP 猎物探针 / Gate P | ⬜ 核心闭环后由维护者执行，决定是否扩大评估 |
| P0 / P1 / P2 / P3 / P4 | ⬜ `Planned`，按 execution plan 完成单目标闭环 |

Rust 侧现在可以走完「从签名读出契约 → 与外部边界事实关联 → 把判定与判定来源写入产物」整条链。但外部侧那一半的证据来自 API 清单分类出的注册与注销事实，不是外部代码本身的行为。因此：

| 创新点 | 状态 |
| --- | --- |
| C1 safe-only 可执行反证合成 | 未开始（roadmap P4） |
| C2 类型契约 × 外部 effect 的精化检查 | 未成立——两侧事实还不是真正的两侧（roadmap P1/P2/P3） |
| C3 生态级度量与新发现 | 未开始 |

## 已完成：PF 核心关系与四个 matched fixture（Gate R）

2026-07-31 完成。落点：

| 内容 | 位置 |
| --- | --- |
| 关系实现 | `crates/bw-model/src/compatibility.rs` |
| 四个 fixture 的判定断言 | `crates/bw-model/tests/compatibility.rs`（14 项） |
| Rust 侧三种形状 | `benchmarks/compiler-fixtures/callback-retention-relation/src/lib.rs` |
| 外部侧四个 C stub | 同目录 `foreign/`，对应关系见其 `README.md` |

**结果**：四个 fixture 全部判对。fixture 2 与 3 的 Rust 事实完全相同、只有 C stub 的注销是否真清槽不同——**Full 能分开，Rust-only 只能记缺证**。按 [Gate R](milestone-gates.md#gate-r关系正确性) 这是通过，且不构成 Gate A 的提前失败信号。

**非空性检查已做**：故意让 guard 分支忽略 Q4′ 证据后，恰好 6 项依赖该分支的断言失败、8 项不依赖的仍通过，失败位置符合预期。

### 这一步证明了什么，没证明什么

- **证明了**：关系本身能分开该分开的情况；外部侧的判别力确实落在 Q4′（清槽）上；`'static` 不约束回调分配这一漏报已被 fixture 4 覆盖。
- **没证明**：Q4′ 能从真实的 LLVM IR 推导出来。外部侧取值当前由 C stub **手工标注**（评估设计里的 `manual foreign oracle` 变体）。这一半由 P1/P2 回答。

### 一处顺带的边界发现

并非关系的每一项都需要外部证据：**回调分配的归属是纯 Rust 侧事实**，`ForeignOwnedUntilUnregister` 时 Rust-only 就能正确判为相容。外部证据的净贡献集中在 guard 分支。

**[Gate A](milestone-gates.md#gate-a外部证据必要性) 的增益必须归因到那里**，不能笼统地说「因为我们看了外部侧」。

## 已完成：PC `EffectiveCaptureAdmission`（Rust 契约事实之一）

2026-07-31 完成。落点：`crates/bw-model/src/static_fact.rs`（语义取值与映射）、
`compiler/bw-rustc/src/rustc_api/mir.rs`（trait object 覆盖）、
`crates/bw-model/src/lifecycle_v326.rs`（判定推导的更正）。

### 先测量后写代码，探针改了方案

按纪律先跑探针看现状，四项结果里有三项与预期不同：

| 探针结果 | 影响 |
| --- | --- |
| APIT（`impl Fn`）**已经能工作** | 原计划的一项工作取消 |
| **`dyn Fn` 一条事实都不产出** | trait object 是参数类型，不在 `generics.predicates` 里，现有分类器完全看不到。是漏报 |
| `Box<dyn Fn()>` 与 `&'c mut dyn Fn()` 在 HIR 里是**同一个** `ImplicitObjectLifetimeDefault` | 语义相反，只看 lifetime kind 会把一半判反。必须靠外层容器区分 |
| `lifecycle_v326.rs` 的判定推导对 `no_lifetime_bound` 直接 `continue` | `fn register<F: Fn()>(f: F)` **产出零个判定**——猎物池被数少的确切机制 |

### 改了什么

- `NoLifetimeBound` 的语义订正为 `PermitsNonStaticCapture`。没有 `'static` 恰恰是允许捕获借用，这是候选形状里最强的一种，不是最弱的；
- 新增 `UnresolvedLifetime`，真正「解析不出」的那一格。容器不在已知集合（`Box`/`Rc`/`Arc`）时落这里，**不猜**；
- trait object 覆盖，object lifetime 的默认值由外层容器解析；
- `is_shorter_than_static()` 改为由语义映射推导，并有断言钉死两者不得分叉。

### 非空性检查

故意让容器判据失效后，`boxed_dyn_default` 从 `RequiresStaticCapture` 落到 `Unresolved`，断言在预期那一行失败。

### 一处顺带修掉的自造问题

`EffectiveCaptureAdmission` 一度在 `compatibility.rs` 与 `static_fact.rs` 各有一份定义——正是 [代码库审计 §7.3](../development/codebase-realignment.md) 记的 `sanitize_id` 那种分歧。已合并成一份，放在事实层，关系层 import。

## Gate P（PP 猎物存在性探针）：核心闭环后由维护者执行

**2026-08-04 调整执行时机。** 本阶段仍由维护者执行，但不再阻塞 P0–P4 的核心功能实现；它在 Core Complete 后决定是否投入规模化评估和新发现搜索。

**维护者对猎物池规模的印象可以决定是否值得跑这个实验，但不构成 Gate P 通过**——通过需要预注册的正式结果。

**由谁执行不改变判据。** [runbook](../experiments/runbooks/prey-existence-probe.md) 的六条方法学要求缺一条结论就不可用：语义取值 `EffectiveCaptureAdmission`（不用语法四态）；只数 Tier A（dataflow 到达精确 extern 参数，不是语法共现）；**safe-entry lineage**（只到达 extern 参数不证明安全客户端够得着）；只算 L1 可分析；**Tier A-R 与 Tier A-A 分开判定**；判据用换算公式与置信界，不用「足够」这类事后可移动的措辞。**运行前必须完成 family-level sealed split**，否则整个前瞻池变成开发集。

**三处必须先修的判据缺口**，见 [execution plan 阶段 1 与阶段 7](execution-plan.md)：事实层不记录 `is_unsafe_fn`（实测 `unsafe extern "C" fn trampoline` 也产出 callback bound 事实）；没有 safe-entry lineage；`AllocationOwnership` 未实现导致 Tier A-A 无法统计。**第三项若来不及做，必须写明本次只决定 R 子路线，A 保持 `Unknown`，不得默认为零。**

## 已完成：PG-1 `RegistrationGuard`

2026-07-31 完成。落点：`compiler/bw-rustc/src/rustc_api/mir.rs` 的 `registration_guards`、
`crates/bw-model/src/static_fact.rs`（`RegistrationGuard` + `RegistrationGuardFact`）、
golden 见 `compiler/bw-rustc/tests/callback_retention_relation_golden.rs`。

在 Gate R fixture 的 Rust 侧上，编译器产出的取值与 `tests/compatibility.rs` 手写的那组一致：
`register_guarded` → `TiesSlotToSubject`（guard 类型 `Registration`，`Drop` 里调 `fixture_unregister`）；
其余三个 → `None`。

### 第 3 条判据改了措辞

计划原文是「`Drop` impl 里有指向**注销角色 API** 的调用」，实现改为「有指向**外部函数**的调用」。
角色分类目前只能来自人工 API map（`registration.rs`），拿它当必要条件有两个后果：guard 检测只能
在有清单的 crate 上工作，规模化探针拿不到这个事实；而且那是人工标注的语义，不是 Rust 侧观察。

**更重要的是，「Rust 只能看到 `Drop` 调了某个外部函数、判断不了它是否真的清空槽位」正是要外部侧
证据的那条论证本身**（[research thesis §2.6](../project/research-thesis.md)）。所以只判 Rust 侧看得见的形状，
是否真的注销由 Q4′ 回答。有 API map 时角色信息仍在 `RegistrationSiteFact` 里，可作交叉验证。

### 非空性检查（两半都做了）

| 扰动 | 结果 |
| --- | --- |
| 让「`Drop` 里调了外部函数」判据失效 | `register_guarded` 从 `TiesSlotToSubject` 落到 `Unresolved`，失败落在 golden 的第 31 行；其余断言不受影响 |
| 把 fixture 2/3 手写事实的 guard 改成 `Unresolved` | 14 项里恰好 5 项失败，且 **`full_separates_fixtures_2_and_3` 是其中之一**——guard 取值错了，Full 就分不开 fixture 2 与 3 |

第二项值得单独记：**Gate R 的分离能力依赖这个事实**，而它此前是手写的。

### 没有覆盖的形状

- **不产出 `OwnerDropUnregisters`**：那一取值的判据是 owner 类型 drop 路径的证明，与 `ReleasePathProofFact` 同源，不是返回值形状；
- `Result<Registration<'a>, E>` 这类包一层的返回值落 `Unresolved`，是已知覆盖缺口，不是判「无 guard」；
- guard 类型定义在别的 crate 时拿不到 `Drop` 的 MIR，落 `Unresolved`。

## 下一步：PG-2 `AllocationOwnership`

| 事实 | 状态 |
| --- | --- |
| `EffectiveCaptureAdmission` | ✅ PC |
| `RegistrationGuard` | ✅ PG-1 |
| `AllocationOwnership` | ❌ **零行代码** |

**这一项是漏报来源**：`'static` 只管住回调借了什么，管不住 `Box<F>` 还活着没有。PF 的 fixture 4 就是这一类。

**原材料已经在产出。** PG-1 的探针顺带确认：同一个 fixture 上，`register_static_then_free` 产出
`RawPointerTransfer{IntoRaw}` + `RawPointerTransfer{FromRaw}` + `DropSite{Explicit}`，而只差一行
`Box::from_raw` 的 `register_static_owned` 只产出 `IntoRaw`。两者的区别在事实层**已经可见**，
需要的是按交出点聚合再加一层分类。

另有一处：**目前没有任何代码把编译器输出装成 `RustContractFact`**，PF 那四个 fixture 的 Rust 侧事实
仍是手写的。这一步属于 P0。

细化、可复用原材料与非空性检查见 [implementation plan 的 PG](implementation-plan.md#pg-rust-侧剩余的两个事实)。

## PG-2 之后的直接顺序

完整顺序与每一步验收见 [execution plan](execution-plan.md)。当前主线不先跑大规模 Gate P：

```text
PG-2
→ is_unsafe_fn + safe-entry lineage
→ RustContractFact 自动装配
→ 真实外部 IR 获取与 artifact binding
→ Q1 → Q4′ → 降级 Q3
→ P0 identity + Schema → P3
→ P4 witness + 独立 oracle
→ Core Complete
→ 小样本 Gate P / Gate C0
```

### P0 hand-off 身份与双侧事实模型

| 字段 | 内容 |
| --- | --- |
| 服务 | C2 的前提 |
| 状态 | `Planned` |
| 代码入口 | `crates/bw-model/src/static_fact.rs`、`crates/bw-model/src/lifecycle_v326.rs`、`crates/bw-model/src/id.rs`、`compiler/bw-rustc/src/site.rs`（`SiteDescriptor` 是现成的可扩展入口）、`compiler/bw-rustc/src/domain.rs` |
| 完成谓词 | 两侧事实可在不依赖候选切分的前提下联结；同一调用含多组 callback/userdata 时仍能区分；判定按 `StaticVerdict` / `EvidenceGrade` / `WitnessStatus` 三个正交维度记录 |
| 风险 | 低，但必须一次做对 |

### P1 外部侧 Q1 逃逸

| 字段 | 内容 |
| --- | --- |
| 服务 | C2 的**前提**，不是判别项 |
| 状态 | `Planned` |
| 范围 | 只支持外部 C 源码随构建提供的 crate（L1） |
| 完成谓词 | 单一库上端到端产出指令级可回查的逃逸证据；查不出逃逸时记 `InsufficientEvidence` 而非判安全 |
| 风险 | 中。**止损**：两三周内看不到端到端结果，贡献结构需重新设计 |

## 已记录的降级

**Q3 晚调查询首期降级为「同槽间接调用存在性」。** 完整 Q3 需要全库可达性加间接调用 callee 解析，代价高一个数量级。降级版输出 `StaticVerdict = InsufficientEvidence` + 最低档晚调证据 + `EstablishLateInvoke` 义务，由 P4 的反证补上真实可达性证明。**不得输出 `SupportedIncompatibility (weak)` 或任何第四态。**

**P4 必须能消费这条输出。** 降级 Q3 永不产出 `SupportedIncompatibility`，若 P4 只接受不相容判定，首期实现里 P4 就没有合法输入。见 [ADR-0004](../decisions/ADR-0004-joint-trace-verdict-semantics.md)。

外部证据当前是单一 `EvidenceGrade` 枚举，**拆成四个正交字段的设计状态为 `Planned`**，随一次性 schema 升版落地。

**即使 F1–F4 全部完成，静态 Q3 也只能称「declared abstraction 内的高精度」，不能称独立确认。**

降级的确切代价、必须量化的三个指标、完整实现的 F1–F4 分阶段计划，见 [implementation plan 的 P2](implementation-plan.md#p2-外部侧-q4-清槽-与降级-q3-晚调)。

## 代码处置

逐组件的保留 / 冻结 / 重构 / 删除见 [代码库对齐审计](../development/codebase-realignment.md)。结论是**补充优化而非重构**：编译器 Rust 侧在新路线中价值上升，身份模型是可扩展的 builder，外部侧属纯新增。

三条具名决定：

| 编号 | 决定 |
| --- | --- |
| D1 | 冻结 returned-borrow 维度——不删除、不新增投入、不作为贡献陈述 |
| D2 | `HandOffId` + 三态判定 + 外部侧事实合并为**一次** schema 升版 |
| D3 | 重写 `generate_witness_harness.rs` 的产出目标，保留其推导逻辑 |

## 已推迟的决定

**跨外部库家族的数量下限推迟到认证期。** 取得多个外部库 LLVM IR 的工程可行性是已知风险，但按当前决定不构成现阶段的实现约束——P1/P2 只要求单库端到端打通。见 [Gate C](milestone-gates.md#gate-c跨库泛化)。

## 已知未收口项

不阻塞关键路径，但影响评估质量。

| 项 | 影响 |
| --- | --- |
| `CallbackLifetimeBoundFact` 不记录该 API 是不是 `unsafe fn` | Gate P 的 Tier A 判据第一条是「是安全 API」，事实层没有这个字段。PG-1 探针实测：fixture 的 `unsafe extern "C" fn trampoline<F: FnMut()>` 也产出了一条 callback bound 事实。**PP 探针必须能过滤掉它**，否则猎物池被高估 |
| 排名未把可绑定的注册候选排进默认输出上限 | 默认扫描看不到判定结果，每次都要手动放宽上限 |
| 保护性特征仍依赖源码文本匹配 | 同类候选内部排序不可靠 |
| n-day 度量仪器只接入了单一库 | 召回率数字不具代表性 |
| 跨函数对象流只覆盖有限形状 | 影响未来扩维，当前不阻塞 |
| release/use ordering 中 unregister-before-drop 与 conditional release gap 未分开报告 | 需在 release-proof 层新增事实种类，不能靠扩展 ordering 枚举解决 |

## V3.3

`Blocked`。依赖 clean method commit、公开数据集 manifest、Contract/config hash、pair gate、动态桥接与约 100 crate pilot。判据见 [milestone gates](milestone-gates.md) 的工程 gate 部分与 [public regression runbook](../experiments/runbooks/public-regression.md)。准备 V3.3 设施不改变当前阶段判断，也**不能替代研究 gate**。
