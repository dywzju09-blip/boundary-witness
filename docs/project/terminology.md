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

一次跨越语言边界的调用，Rust 侧把回调或 user data 交给外部组件。它是本项目全部判定的基本单位，由 `HandOffId` 标识：至少包含 Rust/外部两侧的 artifact hash、单态化实例、调用出现次序、外部符号与符号版本、callback/userdata 参数索引、registration key 与构建配置。

**源码位置与函数名只能作为诊断字段，不能单独充当联结主键。** 按函数名、API 名或候选分片联结两侧事实是明确禁止的做法。

### analyzed fragment（分析片段）

判定结论成立的前提集合，包括支持的 IR 获取级别、过程间分析深度、假设与未覆盖路径。所有精度、召回与覆盖结论只在片段内成立；论文与结果文档必须显式给出片段定义。

### `SupportedIncompatibility`

两侧证据共同支持某交出点上的回调持有期不相容。**它是接口层结论，不等于可执行的 UB**——升级到后者需要一份合格的 safe-only 反证。

外部侧晚调证据来自降级查询时，判定记为 `SupportedIncompatibility (weak)`，反证义务待补。

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
