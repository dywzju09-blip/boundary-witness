# 术语

本文给出 BoundaryWitness 正式文档中的规范术语。英文标识符保持代码与 Schema 中的拼写。

## 分析对象与证据

### `ObjectFlow`

由 compiler 或经审计 contract 产生的中性对象传递事实，描述对象从一个静态 site 到另一个 site 的关系，例如参数到返回值、字段写入/读取、wrapper move/destructure、collection store/load 或 closure capture/use。`ObjectFlow` 只描述传递；是否同一对象、是否存在危险顺序，必须由 binding key、endpoint continuity、barrier 和 ordering 继续证明。

### claimant

某条共享静态事实所归属的 candidate。claimant 只有在候选对该事实存在唯一、可回查的 exact anchor 时才能确定；候选得分、candidate ID、同名 API 或源码距离不能代替精确归属。多个候选竞争且无法唯一证明时，事实应丢弃或标记 ambiguous。

### identity transport

对象链 proof layer 之一，表示保存/读回、store/load 或参数/返回传递属于同一逻辑对象。它不包含 release、invalidation、use 的先后关系，也不等同于完整风险链。代码枚举值为 `identity_transport`。

### lifecycle ordering

对象链 proof layer 之一，表示 release、owner invalidation、callback use 或 returned-view use 等事件的顺序已由可回查证据证明。它回答“何时发生”，不单独回答“是否同一对象”或“是否构成完整风险”。代码枚举值为 `lifecycle_ordering`。

### complete risk chain

对象链 proof layer 之一，表示同一对象身份、生命周期顺序和风险路径在静态证据中同时闭合。代码枚举值为 `complete_risk_chain`。它仍是静态风险候选，不替代真实执行中的 dynamic witness。

### contract

对 API family 的角色、保留/释放义务、参数位置和身份组成作出的可审计声明。contract 为 facts 提供语义约束，但不包含 CVE 编号、样本标签或漏洞答案。未经验证的命名猜测或 LLM 建议只能作为 contract candidate，不能进入强结论链。

### fact

对程序或运行行为的中性、结构化观察。static fact 可以来自 compiler 或经审计 contract；runtime fact 来自实际事件。fact 记录“发生了什么”，不应直接写入“这是漏洞”之类结论。

### candidate

由边界索引和生命周期分析产生的待审查对象，包含 candidate ID、证据引用、风险/保护性特征、缺证原因和排序。candidate 不是 finding，也不是漏洞确认。

### finding

oracle 将 static facts、runtime events 与 contract 组合后产生的规则级结构化结果。finding 必须保留 evidence lineage、对象、顺序、规则和运行标识；后续仍需用负对照、sanitizer/UB 证据和人工核验区分其确认等级。

## 跨界判定

### hand-off（交出点）

一次跨越语言边界的调用，Rust 侧把回调或 user data 交给外部组件。它是本项目全部判定的基本单位。

身份是**分层**的（目标形态为 `Planned`，见 [ADR-0003](../decisions/ADR-0003-target-verifier-dataflow-and-identity.md)），至少五层：

| 层 | 回答什么 |
| --- | --- |
| 构建产物身份 | 这是哪一次构建的产物（两侧 artifact hash、target、feature、宏、优化、链接配置） |
| 安全入口身份 | 安全客户端从哪个 public API 进来 |
| 静态交出点身份 | 哪一次跨界调用把回调交了出去（单态化实例、调用出现次序、参数角色索引） |
| 符号槽位身份 | 外部把它存进了哪个槽位（符号 + 符号版本、`#[link_name]` 解析后的真实符号） |
| 注册实例身份 | 这是该槽位上的第几次注册（**registration generation**） |

**源码位置与函数名只能作为诊断字段，不能单独充当联结主键。** 按函数名、API 名或候选分片联结两侧事实是明确禁止的做法。

### registration generation

同一个槽位上的不同注册实例——「注册 A → 注销 → 注册 B」是两次不同的注册。**`SameArtifactSlotAndRole` 保证两侧指同一槽位，但分不开不同的注册实例**，而联合轨迹要求两侧事实指向同一次注册。运行期实例若与静态推出的 generation 不一致，单独记录，不合并。

### safe-entry lineage

从 public safe 入口经 wrapper / helper 到达具体 extern 交出点的可回查链。**只证明「回调到达 extern 参数」不足以证明「安全客户端能到达该交出点」**——藏在内部 helper 里、公开 API 够不着的交出点不构成本研究的缺陷。它同时是 [Gate P](../roadmap/milestone-gates.md#gate-p猎物存在性) 中 Tier A 判据的一条。

### joint trace feasibility（联合轨迹可行性）

两条 may-property 分别成立**不蕴含它们能在同一条执行上同时发生**。判定要求两侧证据在同一构建、同一交出点、同一槽位、同一 registration generation 且路径条件相容下形成联合轨迹。

- **`SeparationCertificate`** 是正面证据：「没有观察到保护机制」只是缺证，不构成证书；
- 静态证不出联合可行性 → `InsufficientEvidence` + `JointTraceObligation`；
- **动态反证可以完成联合轨迹的证明**——反证跑起来、外部真的回调进来，就是一条实际发生过的联合轨迹。

### analyzed fragment（分析片段）

判定结论成立的前提集合，包括支持的 IR 获取级别、过程间分析深度、假设与未覆盖路径。所有精度、召回与覆盖结论只在片段内成立；论文与结果文档必须显式给出片段定义。

### `StaticVerdict` / 外部证据 / `WitnessStatus`

三个**正交**维度，不得用一个枚举表达。

- **`StaticVerdict`**：`SupportedIncompatibility` / `CompatibleWithinAnalyzedFragment` / `InsufficientEvidence`；
- **外部证据**：`RetentionEffect`（Q1 是否到达跨调用存活的存储）、`InvokeReachability`（同槽调用点 / 自导出入口可达 / 路径条件支持）、`ClearReplaceStatus`（Q4′ 是否所有路径清槽、是否存在绕过 guard 的路径）、`PathCompatibility`（两侧路径条件是否相容）。**四个字段正交**，可派生报告级总体等级用于展示，不得丢失原始维度。字段拆分状态为 `Planned`，当前实现是单一 `EvidenceGrade` 枚举，已知会互相覆盖丢信息；
- **`WitnessStatus`**：`NotAttempted` / `Generated` / `Executed` / `ConfirmedCounterexample` / `Inconclusive`。

**`SupportedIncompatibility (weak)` 及任何第四态一律禁止。** 降级的外部侧查询产出的是 `InsufficientEvidence` + 低 `InvokeReachability` + 一条 witness obligation，不是弱化的不相容结论。

**动态反证不改变静态 verdict 的语义**；反证未触发只能记 `Inconclusive`，有限次执行不能证伪 may-property。

### `WitnessObligation`

判定不成立时缺的具体那一步，反证阶段消费它：

- **`EstablishLateInvoke`**：只有降级 Q3 的同槽调用点证据，需要真实执行证明晚调确实发生；
- **`JointTraceObligation`**：两侧分别成立，但联合可行性未证明。

**反证阶段接受 `SupportedIncompatibility`，也接受 `InsufficientEvidence` + `EstablishLateInvoke`。** 降级 Q3 永不产出前者，若只接受前者，首期实现里反证阶段没有合法输入。

### `SupportedIncompatibility`

两侧证据共同支持某交出点上的回调持有期不相容。**它是接口层结论，不等于可执行的 UB**——升级到后者需要一份合格的 safe-only 反证。

### `EffectiveCaptureAdmission`

回调类型**在语义上**是否允许捕获非 `'static` 借用：`PermitsNonStaticCapture` / `RequiresStaticCapture` / `ContextDependent` / `Unresolved`。

它取代了按签名语法给出的四态。**「无 outlives bound」不是一个语义取值**：对泛型 `fn register<F: Fn()>(f: F)` 它意味着 `PermitsNonStaticCapture`（最强候选），而 `Box<dyn Fn()>` 的省略 lifetime 在多数位置默认到 `'static`，是 `RequiresStaticCapture`。把两者合并会系统性错估候选池。

### referent / allocation / registration

判定必须分开的三类生命周期：**referent** 是回调捕获的借用对象；**allocation** 是回调分配本身与 trampoline userdata；**registration** 是外部槽位上的注册实例。

`'static` bound 只约束 referent。合并任意两类都会产生可构造的错判。

### `CompatibleWithinAnalyzedFragment`

在明确给出的分析片段与假设内，未形成该类不相容。**它只排除回调持有期这一个子问题，不表示 API 整体健全。**

### `InsufficientEvidence`

任一侧事实、联结身份或外部行为证据不足。**缺证不是安全**：没有观察到逃逸不得判定为不逃逸。

### safe-only counterexample（safe-only 反证）

一段带 `#![forbid(unsafe_code)]` 的最小 Rust 客户端，链接与静态分析绑定的精确外部构建，使外部组件在被借对象失效之后真的回调进来，并由独立 oracle 出证。它证明的是**安全抽象不健全**：纯 safe 代码可触发 UB。

harness 文件、witness plan、编译成功或单次 crash 都不是反证。本项目自有的 runtime/oracle 只能作辅助定位证据，不能单独构成 UB 结论。

## 运行与数据

### run manifest

描述一次具体运行所使用代码、工具链、Schema、Contract、数据集、配置、主机和时间的清单。正式运行至少应可绑定 `run_id`、`code_commit`、`code_dirty`、工具链、各类 checksum、`dataset_id`、`dataset_version` 和运行状态。它回答“这次运行具体用了什么”。

### dataset manifest

描述一个数据集快照的身份、版本、内容范围、文件统计、SHA-256、来源和访问边界的清单。它不保存大型数据本体，也不代替 run manifest。它回答“被引用的数据快照是什么”。

### run ID（`run_id`）

一次运行的稳定标识，用于连接 manifest、日志、trace、finding、摘要和回执。目录名或时间戳不能替代 `run_id` 与 checksum 对齐。

### evidence reference

从 candidate、fact、object chain 或 finding 回查原始静态/动态证据的稳定引用。派生结果必须保留父证据引用，文件名或自然语言说明本身不构成证据。

## 验证与隔离

### dynamic witness

能在真实执行中稳定重放的最小输入或 API 动作序列，并产生 contract finding、sanitizer、崩溃或其他明确观测。dynamic witness 必须记录环境、重复性和负对照；计划或 harness 文件本身不是 witness。

### oracle ground truth

在检测器运行之外维护的预期标签和根因依据，例如 advisory、补丁差分、人工审查与 fixed/negative 对照。它用于 reveal 后评估，不得泄漏到候选、ranking 或搜索输入。

### sealed holdout

在 scanner、Contract、feature profile 和实验配置冻结后，才由 blind 流程揭示的未参与开发样本。sealed holdout 用于检验泛化；揭示后即失去 sealed 身份。

### negative control

按设计不应形成目标 finding 的固定版本、安全写法、及时释放/注销路径或无触发样本。negative control 与 vulnerable 样本同等重要，用于约束误报和过拟合。

### witness plan

静态分析为候选生成的后续动作与证据收集计划。它可以描述 register、persist、release、trigger、Miri 或 fuzz 路线，但在 executor 实际执行并形成回执前，不是 dynamic witness。

## 状态词

- `Implemented`：代码存在，相关实现测试可通过；不代表已经有正式实验运行证据。
- `Verified`：存在与当前代码/配置/数据严格对齐的运行记录和证据。
- `Planned`：目标或设计已明确，但实现尚不完整。
- `Blocked`：继续推进前存在明确、可检查的 gate 或依赖。
- `Deprecated`：为兼容仍保留，但不再承载新的规范语义或扩展方向。
