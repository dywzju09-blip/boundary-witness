# 执行计划

**本文是执行顺序的唯一权威。** [roadmap](roadmap.md) 解释各模块是什么，[implementation plan](implementation-plan.md) 记录算法与代码细节，[current work](current-work.md) 只记录当前位置。发生冲突时，以本文的顺序为准。

方向与创新点仍以 [research thesis](../project/research-thesis.md) 为准。本文只回答三个问题：**现在做什么、做到什么算完成、完成后进入哪一步。**

---

## 1. 当前执行策略

本项目采用以下顺序：

1. 先完成 Rust 侧契约事实；
2. 再取得真实 C/LLVM IR，并完成外部行为分析；
3. 尽早用一个小案例把两侧身份、事实和判定接成完整闭环；
4. 完成 safe-only witness 与独立 oracle；
5. 先做小样本验证，再逐步扩大；
6. 最后才做大规模扫描、完整 baseline、消融、冻结和 sealed holdout。

**大规模验证后置，不等于验证后置。** 开发期间必须持续运行 fixture、vulnerable/fixed pair 和负对照。后置的是论文级规模评估，不是功能正确性检查。

### 三类验证必须分开

| 类型 | 什么时候做 | 回答什么问题 | 能否用于论文正式数字 |
| --- | --- | --- | --- |
| 开发回归 | 每个步骤完成时 | 新功能有没有按定义工作、旧功能有没有被破坏 | 否 |
| 小型纵向验证 | 核心模块集成期间 | 一个真实目标能否从 Rust safe API 一直走到判定和 witness | 只能标为 exploratory |
| 正式规模评估 | 核心功能冻结后 | 方法在未调优样本上的覆盖率、确认率、成本和泛化性 | 可以，但必须预注册并绑定当前 commit |

### “主要功能完成”的定义

只有以下六项全部满足，才允许宣称核心功能完成：

- Rust 侧能自动产出 `EffectiveCaptureAdmission`、`RegistrationGuard`、`AllocationOwnership` 和 safe-entry lineage；
- 能取得与 Rust 构建严格对应的真实外部 IR；
- C 侧能产出 Q1、Q4′ 和降级 Q3 的可回查证据；
- 两侧能按 build、hand-off、slot 和 registration generation 精确联结；
- P3 能输出 `SupportedIncompatibility`、`CompatibleWithinAnalyzedFragment` 或 `InsufficientEvidence`；
- 至少一个真实 vulnerable/fixed pair 能通过 safe-only witness 和独立 oracle 完成重放。

候选数量、100 crate pilot、多个 baseline 和新发现数量都不属于“主要功能完成”的定义，它们属于后续评估。

---

## 2. 执行纪律

### 2.1 依赖类型

| 依赖 | 含义 |
| --- | --- |
| `start` | 前置未完成时不能开始这一步 |
| `integration` | 可以先开发算法内核，但未与前置产物接通前不能称完成 |
| `formal-run` | 前置未冻结时可以调试，不能产生正式实验数字 |

### 2.2 状态词

| 状态 | 含义 |
| --- | --- |
| `Planned` | 设计明确，尚未实现 |
| `Implemented` | 代码和开发回归存在 |
| `Integrated` | 已进入端到端流水线，不依赖手工修改中间产物 |
| `Verified` | 当前 commit 上存在配置、Schema、Contract、数据和 run ID 全部对齐的正式证据 |
| `Blocked` | 有明确且可复述的外部前置条件 |

`Implemented` 不等于 `Verified`。历史运行不能自动证明当前 commit。

### 2.3 每一步的统一交付格式

每个实现步骤必须同时交付：

1. **代码或规范产物**；
2. **正例、反例和 Unknown 路径测试**；
3. **非空性检查**，证明测试确实依赖新逻辑；
4. **失败分类**，不得把 unsupported、join failure 或 IR 缺失写成安全；
5. **状态更新**，同步 [current work](current-work.md)。

---

## 3. 当前位置

```text
✅ PF：核心关系与四个 matched fixture                 Implemented
✅ PC：EffectiveCaptureAdmission                     Implemented
✅ PG-1：RegistrationGuard                           Implemented
✅ PG-2：AllocationOwnership                         Implemented
✅ safe-entry lineage / is_unsafe_fn                 Implemented
✅ RustContractFact 自动装配                         Implemented
✅ 1.4 Rust 侧输出固定与回归                         Implemented
⬜ 真实外部 IR 获取与绑定                            下一步
⬜ Q1 / Q4′ / 降级 Q3                                Planned
⬜ P0 identity / Schema / P3                          Planned
⬜ P4 witness / 独立 oracle                           Planned
⬜ 小样本与大规模评估                                后置
```

**阶段 1 已完成（2026-08-04，含 1.4）。** Rust 侧现在能自动产出四样：`EffectiveCaptureAdmission`、
`RegistrationGuard`、`AllocationOwnership`、safe-entry lineage，并按 `(api_id, callback_param)`
装配成 `RustContractFact`；缺任何一半产出写明缺什么的 gap，不静默丢弃。

1.4 的三项也已落地：`bw extract-rust-contracts` 让 Rust 侧**能独立运行**并写出带
checksum 的产物；重复运行产出逐字节相同（有断言）；`Unresolved` 带 `UnresolvedReason`
机器可读原因，并按原因分类计数——那是 attrition waterfall 的输入。

**当前唯一主线下一步是阶段 2.1：选一个真实参考目标并取得精确外部 IR。** 不先跑
300–500 crate，不先做完整 baseline，也不先准备 sealed holdout。

**选定目标时必须同时写完并冻结该目标的 adapter**（记 commit 与时间戳）。adapter 直到
阶段 5 才用得上，很容易拖到那时再写——但那时 P3 结果已经出来，写出来的 adapter 无法
证明没有掺入缺陷信息，[Gate B](milestone-gates.md) 的判据就废了。

---

## 4. 总体执行顺序

| 阶段 | 目标 | 阶段结束时得到什么 |
| --- | --- | --- |
| 0 | 固定最小范围和接口草案 | 所有人按同一语义、身份层次和 fixture 开发 |
| 1 | 完成 Rust 侧 | 从 public safe API 到 extern hand-off 的契约事实 |
| 2 | 取得并绑定真实外部 IR | 与 Rust 构建对应的 C/LLVM 分析输入 |
| 3 | 完成 C 侧行为分析 | Q1、Q4′、降级 Q3 的正交证据 |
| 4 | 连接两侧并完成 P3 | 从源码与 IR 到三态判定的端到端静态闭环 |
| 5 | 完成 P4 与独立 oracle | 从静态义务到 safe-only 可执行反证 |
| 6 | 核心功能验收 | 一个真实目标完整跑通，达到 Core Complete |
| 7 | 小样本验证 | 暴露构建、适用性、转化率和人工成本问题 |
| 8 | 规模化评估 | baseline、消融、waterfall 和规模结论 |
| 9 | 冻结与确认性评估 | holdout、新发现和最终论文证据 |

---

## 阶段 0：固定最小范围与接口草案

### 目标

先固定两侧共同依赖的语义，避免 Rust 和 C 分别开发数月后才发现输出接不上。

### 按顺序执行

#### 0.1 固定首期分析片段

- 只支持 L1：外部 C 源码随 crate 构建提供，并能取得该次真实构建的 LLVM IR；
- 先支持 global/field slot、有限层级过程间传播和明确的 null/replace store；
- 完整 Q3 暂不实现，首期只做同槽间接调用候选；
- alias、callee、路径或构建绑定不足时输出 `InsufficientEvidence`，不得猜测。

**产物**：scope 文档与 limitation 清单。

#### 0.2 固定设计级接口

先固定记录职责，不立即迁移 Schema：

```text
RustContractFact
ForeignBehaviorFact
CompatibilityVerdict
WitnessObligation
WitnessReceipt
```

身份至少分为：build artifact → safe entry → hand-off → symbol/parameter role → slot → registration generation。函数名和源码位置只用于诊断，不能作为最终 join key。

**产物**：接口草案、字段来源表和 provenance 规则。

#### 0.3 固定验收 fixture 矩阵

在现有四个 matched fixture 基础上，确保覆盖：

- referent 失效后晚调；
- guard 真清槽；
- guard 调了 unregister 但外部没清干净；
- `'static` 回调分配提前释放；
- 证据不足，应返回 Unknown；
- build 不匹配，join 必须拒绝；
- 同一 slot 注销后重新注册，generation 必须分开。

**产物**：每个 fixture 的预期 Rust facts、foreign facts、verdict 和 witness status。

#### 0.4 固定 adapter 规范

adapter 只能描述“如何合法调用公开 API”，不能包含 drop 时机、漏洞触发顺序或预期结果。crate-specific adapter 必须在该目标的正式判定出来前冻结。

**产物**：adapter schema、允许字段、禁止字段和冻结记录格式。

#### 0.5 安排预注册时点

不要求现在写完所有统计协议，但每个 gate 必须在看对应数据之前冻结判据：

- Gate A1 / Gate B 最小线：阶段 6 运行前；
- Gate P / Gate C0：阶段 7 运行前；
- Gate A2：阶段 8 运行前；
- Gate C / Gate D：阶段 9 运行前。

**产物**：每个 gate 的负责人、冻结时点、比较单位、阈值和失败动作清单。

#### 0.6 并行核实相关工作

相关工作核实不阻塞阶段 1–5 的功能开发，但必须在写论文主张和选择 baseline 前完成。未核实的论文、工具能力和实验数字不得进入正式对外材料。

**产物**：可追溯的来源表、已核实能力边界和 baseline 选择理由。

### 完成条件

- 五类核心记录的职责没有重叠；
- fixture 的预期结果不存在第四种静态判定；
- RoleMap 只描述符号和参数角色，不预先声明真实保留、晚调和清槽行为；
- 每个研究 gate 都有明确的预注册时点；
- 后续步骤可以根据接口草案独立实现，但最终 Schema 尚未迁移。

---

## 阶段 1：完成 Rust 侧契约分析

### 目标

从 public safe API 自动追踪到具体 extern hand-off，并输出 P3 真正需要的 Rust 契约事实。

### 按顺序执行

#### 1.1 实现 PG-2 `AllocationOwnership`

- 聚合同一 hand-off 上的 `IntoRaw`、`FromRaw`、drop 和 return/escape 路径；
- 区分 `RustRetainsAndMayFreeEarly`、`ForeignOwnedUntilUnregister` 和 `Unresolved`；
- 解析不出释放路径时必须落 `Unresolved`。

**验收**：`register_static_then_free` 与 `register_static_owned` 得到不同结果；删除关键 `FromRaw` 证据后，相关 fixture 必须按预期翻转。

#### 1.2 增加安全入口过滤

- 给相关事实记录 `is_unsafe_fn`；
- 从 public safe entry 追踪 wrapper/helper 到精确 extern 参数；
- 内部 helper 可见但 public safe API 不可达时，不计为 safe hand-off；
- 路径无法证明时单列 lineage gap。

**验收**：safe、unsafe、private-helper-only 三组 fixture 分别进入正确分类。

#### 1.3 自动装配 `RustContractFact`

- 将 PC、PG-1、PG-2 和 safe-entry lineage 聚合到同一 hand-off；
- 同一调用包含多组 callback/userdata 时按参数角色分开；
- 不再依赖 PF 测试里的手写 Rust 事实。

**验收**：现有四 fixture 的自动事实与手写 oracle 逐字段一致。

#### 1.4 固定 Rust 侧输出与回归

- 输出稳定、可校验的中性事实；
- 同一源码和构建配置重复运行结果一致；
- unsupported 和 unresolved 有明确 reason code；
- Rust-only 不得根据 API map 猜测外部是否保留或清槽。

### 阶段产物

- 自动生成的 Rust 契约事实；
- safe-entry → wrapper/helper → extern hand-off 的 lineage；
- PG 三事实的正负回归；
- Rust 侧 coverage 与 failure taxonomy。

### 完成条件

Rust 侧可以独立运行并回答：**哪个 public safe API，在什么 hand-off，把什么生命周期义务交给了外部组件。** 任何核心事实都不再由测试手写。

---

## 阶段 2：取得并绑定真实外部 IR

### 目标

得到与 Rust 侧同一次构建严格对应的 C/LLVM IR。不得另编一份“相似的 C 源码”。

### 按顺序执行

#### 2.1 选择一个参考目标

先选一个已有历史 vulnerable/fixed pair、构建可控、外部源码随构建提供的库。首个目标只用于打通纵向闭环，不代表泛化性。选定后立即依据公开 API 文档编写并冻结 crate-specific adapter；vulnerable/fixed 尽量复用同一份 adapter，且不得等待 P3 结果后再补漏洞触发信息。

#### 2.2 捕获真实构建

记录并固定：

- crate/version/features；
- target/toolchain；
- C compiler、宏、include path、优化级别；
- 外部 source/object/IR hash；
- Rust artifact 与外部 artifact 的共同 build/run identity。

#### 2.3 建立 IR acquisition 与索引

- 从实际构建获得 bitcode/LLVM IR；
- 索引外部符号、函数参数、callsite、global/field store 和 indirect call；
- IR 缺失、版本不兼容、link-time 消失分别记原因，不得合并成“不可分析”。

#### 2.4 做第一次纵向检查 V0

在一个 fixture 或参考目标上确认：Rust hand-off 能绑定到正确外部 artifact、符号和参数角色。此时还不要求 Q1/Q4′/Q3 全部完成。

### 阶段产物

- 参考目标的冻结 adapter 与冻结记录；
- 可重放的 IR 获取命令或长期工具入口；
- artifact manifest 与 hash；
- 外部符号和参数角色索引；
- V0 绑定结果。

### 完成条件

从 clean build 可以重复取得相同语义的分析输入；切换 feature、target 或外部对象后，build identity 必须变化并阻止错误 join。

---

## 阶段 3：完成 C/外部侧行为分析

### 目标

从真实 IR 读取外部组件的实际行为，而不是从 API 名字或 RoleMap 推断。

### 按顺序执行

#### 3.1 Q1：槽位与保留身份

- 从 callback/userdata 参数跟踪到跨调用存活的 global/field slot；
- 记录 slot identity、store 指令、传播路径和分析边界；
- 查不出逃逸时输出缺证，不输出“未保留”。

**纵向检查 V1**：至少一个 Rust hand-off 能连接到一个真实外部 slot。

#### 3.2 Q4′：clear / replace

- 查找 unregister/replace 对同一 slot 的写入；
- 判断相关路径是否明确写入 null、新 generation 或其他替代值；
- guard 只证明 Rust 调了外部函数，是否真清槽必须由本步骤回答；
- all-path 证明超出首期片段时返回 Unknown。

**验收**：matched fixture 2 与 3 必须被 Q4′ 分开。

#### 3.3 降级 Q3：同槽晚调候选

- 查找从同一 slot load 后发生的 indirect invoke；
- 记录调用点、slot 和最小路径信息；
- 首期不把“同槽调用点存在”升级为真实晚调可达性。

输出语义固定为：

```text
StaticVerdict     = InsufficientEvidence
WitnessObligation = EstablishLateInvoke
```

#### 3.4 输出正交外部事实

至少分开记录：

- `RetentionEffect`；
- `InvokeReachability`；
- `ClearReplaceStatus`；
- `PathCompatibility`。

不得用一个总枚举覆盖前一个查询的结果。

### 阶段产物

- 指令级可回查的 Q1/Q4′/Q3 证据；
- 正交外部事实；
- unknown callee、alias gap、path gap 和 IR gap 统计。

### 完成条件

在 matched fixtures 和一个真实参考目标上，外部事实都来自 IR；RoleMap 只参与绑定和参数角色解释，不参与行为结论。

---

## 阶段 4：连接两侧并完成 P3

### 目标

形成从 Rust source、真实外部 IR 到三态静态判定的完整闭环。

### 按顺序执行

#### 4.1 定稿 P0 分层身份

最终联结至少同时检查：

```text
build artifact
→ safe entry
→ hand-off/callsite
→ symbol + callback/userdata role
→ slot
→ registration generation
```

candidate 只作为下游展示和调度投影，不再承担事实 join。

#### 4.2 一次性升级 Schema

将分层身份、Rust/foreign facts、三态判定、正交证据、witness obligation 一次性加入版本化 Schema。同步更新 model、producer、consumer、validator、golden 和 roundtrip 测试。

#### 4.3 实现精确 join

- 同一构建、同一 hand-off、同一角色、同一 slot 和同一 generation 才能组成 joint trace；
- 多组 callback/userdata 不能串线；
- build mismatch、缺 slot 或 generation 不明必须拒绝或返回 Unknown；
- 不允许按函数名、API 名或 candidate 分片兜底联结。

#### 4.4 实现 P3 联合关系判定器

输出只允许：

- `SupportedIncompatibility`；
- `CompatibleWithinAnalyzedFragment`；
- `InsufficientEvidence`。

两侧 may-property 分别成立，不等于联合轨迹成立。路径相容性无法证明时必须附带 `JointTraceObligation`。

#### 4.5 建立静态端到端入口

一次运行应能产出：Rust facts → foreign facts → join → verdict → evidence lineage。中间产物允许保存用于审计，但不允许人工修改后再继续流水线。

### 阶段产物

- vNext Schema 和校验器；
- 精确 identity join；
- P3 三态判定；
- 一条命令或 runbook 可重放的静态闭环。

### 完成条件

- fixture 2 与 3 的 Rust facts 相同，但 Full 判定不同；
- build mismatch 和 generation 混淆测试被拒绝；
- 至少一个真实参考目标完成 source-to-verdict；
- 所有 Unknown 都有具体缺证原因。

---

## 阶段 5：完成 P4 safe-only witness 与独立 oracle

### 目标

把静态不相容或晚调义务转成可执行反证，让独立 oracle 判断是否真的发生目标错误。

### 每个目标的固定执行顺序

```text
冻结 crate-specific adapter
→ 运行 P3
→ 读取 verdict / witness obligation
→ 自动推导危险动作序列
→ 生成 #![forbid(unsafe_code)] 客户端
→ 编译、执行、收集独立 oracle
→ 生成 receipt 与重放信息
```

adapter 规范在阶段 0 定义；**目标 adapter 必须在该目标的 P3 结果出来前冻结。**

### 按顺序实现

#### 5.1 实现 witness planner

同时接受：

1. `SupportedIncompatibility`；
2. `InsufficientEvidence + EstablishLateInvoke`，前提是 Rust 分离性、Q1、Q4′ 和 identity 已充分；
3. `JointTraceObligation`。

#### 5.2 生成 safe-only 客户端

生成器负责推导：创建有限生命周期对象 → 注册回调 → 结束对象生命周期 → 保持外部注册 → 请求外部稍后调用 → 回调访问失效对象。adapter 不得直接写入这条危险顺序。

#### 5.3 接入独立 oracle

- referent：能观察 stack-use-after-scope 的 oracle；
- allocation：能观察 heap use-after-free 的 oracle；
- callback-after-clear：语义事件必须与独立执行证据共同出现；
- 项目自有 runtime 事件只能辅助定位，不能单独确认 UB。

#### 5.4 运行固定对照

至少包含：vulnerable、fixed、owned callback、unregister-before-drop、no-trigger、同步外部实现。

未触发统一记 `Inconclusive`，不能记安全或 false positive。

### 阶段产物

- witness plan；
- safe-only harness；
- pinned artifact 与构建配置；
- oracle 输出、日志、checksum 和 replay receipt；
- 生成/编译/执行/确认失败分类。

### 完成条件

至少一个不参与模板开发的目标能从静态输入自动到达独立证据；fixed 和所有负对照保持干净；同一 receipt 可稳定重放。

---

## 阶段 6：核心功能验收（Core Complete）

### 目标

在扩大样本前证明完整工具链真的可用。

### 必须执行的验收

1. 跑完阶段 0 的全部 fixture；
2. 在一个真实 historical vulnerable/fixed pair 上跑完整流水线；
3. 检查 Rust facts、foreign facts、join、verdict、witness、oracle 的 lineage；
4. 检查 fixed 与至少三个负对照；
5. 人为制造 build mismatch、IR 缺失、slot 不明和 unknown callee，确认都落入正确失败类；
6. 重复运行并比较 artifact、verdict 与 receipt；
7. 执行 Gate A1：Full 与 Rust-only 在同一 candidate universe 上比较；
8. 执行 Gate B 最小通过线：至少一个真正 unseen 目标完成 safe-only 反证。

### Core Complete 判据

```text
Rust side complete
+ Foreign IR acquisition complete
+ Foreign behavior analysis complete
+ Exact cross-language join complete
+ Tri-state P3 complete
+ Safe-only P4 + independent oracle complete
+ One real vertical target replayable
```

阶段 6 通过后，才能说“主要功能完成”。这时仍不能宣称完成生态级验证或达到投稿标准。

---

## 阶段 7：从小样本开始验证

### 目标

先暴露适用性、构建、转化率和人工成本问题，再决定是否扩大。

### 7.1 修正并完成 PP 探针

- 增加 `is_unsafe_fn` 和 safe-entry lineage；
- Tier A-R 与 Tier A-A 分开；
- 只把能绑定精确外部 IR 的 L1 样本计入主口径；
- 输出 crate/repository/library-family 聚类结果。

### 7.2 分三级扩展

| 级别 | 建议规模 | 目的 |
| --- | ---: | --- |
| S0 | 5–10 个目标 | 验证接入流程和 failure taxonomy |
| S1 | 10–30 个 crate、至少 2 个库家族 | 估计覆盖率、Unknown、adapter 成本和实际转化率 |
| S2 | 20–50 个未调优 crate | 做 Gate P-a 的探索性 pilot，校准正式样本量 |

这些数字是个人论文的工程建议，不自动构成正式统计充分性。正式样本量必须由预注册目标与置信区间决定。

### 7.3 此时再执行 Gate P

- **Gate P-a**：候选池是否足以继续扩大；
- **Gate P-b**：在开发集上用已经跑通的完整流水线测真实候选→确认转化率；
- R 与 A 两条子路线分别判定；
- Gate P 现在决定的是**是否投入规模化评估和新发现搜索**，不再阻塞核心功能原型。

如果 Gate P No-Go，保留已完成的工具原型和纵向案例，转路线 B、C 或 D；不继续烧资源做大规模扫描。

### 7.4 运行 Gate C0

先验证 2 个库家族，再扩到 Gate C0 要求的 3–5 个家族和至少两种 C 构建方式。只检查 IR 获取、符号解析、artifact 绑定和接入成本，不要求每个家族都产生 finding。

### 阶段产物

- S0/S1/S2 结果；
- 初版 attrition waterfall；
- adapter 工时和失败分类；
- Gate P 与 Gate C0 决策记录。

---

## 阶段 8：规模化评估

### 启动条件

- Core Complete；
- 小样本没有发现会推翻 Schema、身份或判定语义的问题；
- Gate P 支持继续扩大，或论文明确选择不依赖猎物规模的路线；
- 指标、聚类单位、Unknown 口径和停止规则已经预注册。

### 按顺序执行

1. 扩大到 50–100+ crate 的适用性扫描；
2. 完成 public regression；
3. 在同一 candidate universe 上运行公平 baseline；
4. 运行 Full、Rust-only、Foreign-only、manual-oracle 等核心消融；
5. 执行 Gate A2，测确认率、覆盖率或人工成本的端任务增益；
6. 报告完整 attrition waterfall：输入 → 构建 → Rust facts → IR → join → verdict → witness → execution → independent confirmation；
7. 每一级报告 timeout、unsupported、tool error、Unknown 和人工拒绝原因。

### 完成条件

所有规模结论都绑定当前 commit、Contract、Schema、配置、数据 manifest 和 run ID；不能只报告“发现了多少问题”。

---

## 阶段 9：冻结与确认性评估

### 目标

证明最终结论不是在开发集上调出来的。

### 按顺序执行

1. 冻结 scanner、Contract、feature profile、adapter policy、threshold、dataset hash 和 ranked output hash；
2. 隔离 runner 与 curator；
3. 使用新的、未 reveal 的 sealed holdout；
4. 运行前瞻扫描、人工确认和披露流程；
5. 执行 Gate C 与 Gate D；
6. 根据证据选择路线 A/B/C/D 和论文主张强度。

### 最低论文通过线

- 至少一个冻结后、未参与设计的独立确认发现；
- vulnerable/fixed/negative controls 对齐；
- baseline、消融、Unknown、coverage、cluster 和置信区间完整；
- 所有结论有 source → artifact → facts → verdict → witness → receipt 的 lineage。

---

## 完整依赖图

```text
阶段 0  范围 + 接口草案 + fixture + adapter 规范
   │
   ▼
阶段 1  PG-2 → safe-entry/is_unsafe → RustContractFact → Rust 回归
   │
   ▼
阶段 2  参考目标 → 真实 IR → artifact manifest → V0 绑定
   │
   ▼
阶段 3  Q1 → V1 → Q4′ → 降级 Q3 → 正交 foreign facts
   │
   ▼
阶段 4  P0 identity → 一次 Schema 升版 → exact join → P3 → 静态闭环
   │
   ▼
阶段 5  adapter freeze → P4 planner → safe-only harness → oracle → receipt
   │
   ▼
阶段 6  fixture + real vulnerable/fixed + Gate A1 + Gate B → Core Complete
   │
   ▼
阶段 7  S0 → S1 → S2 → Gate P / Gate C0
   │
   ▼
阶段 8  50–100+ crate + baseline + 消融 + Gate A2 + waterfall
   │
   ▼
阶段 9  freeze → sealed holdout → prospective findings → Gate C / Gate D
```

---

## 当前可直接领取的任务顺序

严格按下面顺序领取；前一项未达到完成条件时，不把后一项标为完成：

1. PG-2 `AllocationOwnership`；
2. `is_unsafe_fn` 与 safe-entry lineage；
3. 自动装配 `RustContractFact`；
4. 选择一个真实参考目标并取得精确外部 IR；
5. 建立 build/artifact binding；
6. 实现 Q1 并完成 V1；
7. 实现 Q4′，分开 fixture 2/3；
8. 实现降级 Q3 与 `EstablishLateInvoke`；
9. 定稿 P0 identity 并一次性升级 Schema；
10. 实现 exact join 与 P3；
11. 冻结参考目标 adapter；
12. 实现 P4、独立 oracle 和固定对照；
13. 完成 Core Complete 验收；
14. 才开始 S0/S1/S2 小样本扩展；
15. 最后进入规模化与确认性评估。

---

## 相关文档

- 方向与创新点：[research thesis](../project/research-thesis.md)
- 模块定义：[roadmap](roadmap.md)
- 算法和代码细节：[implementation plan](implementation-plan.md)
- 当前任务：[current work](current-work.md)
- gate 判据：[milestone gates](milestone-gates.md)
- 目标数据流与身份：[target verifier pipeline](../architecture/target-verifier-pipeline.md)
- 状态边界：[current status](../project/current-status.md)
