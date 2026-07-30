# 范围与边界

本文固定 BoundaryWitness 当前验证版的能力边界。

项目的**最终目标是在 Rust 组件中自动发现未知（0-day）生命周期缺陷**；当前处于 **V3.2.x hardening**，本阶段目标是建立可审计、可证伪的已知缺陷验证链，尚不是通用 0-day 自动发现器。两者的距离见 [路线图](../roadmap/roadmap.md)。

**扫描对象是 Rust 组件（crate + 版本）本身，不是使用该组件的应用。** 需要具体触发实例时由 witness harness 生成，不去真实项目中寻找。详见 [项目概览的威胁模型](overview.md#威胁模型)。

## 1. 五类对象必须分开

| 概念 | 回答的问题 | 可以支持的结论 | 不能支持的结论 |
| --- | --- | --- | --- |
| 静态候选（static candidate） | 哪个边界位置值得进一步分析？ | 排序、人工审查、生成后续验证计划 | 真实漏洞、已复现 UB、0-day |
| 静态风险链（static risk chain） | 静态事实是否证明同对象传递、危险顺序及风险路径？ | 解释风险来源和缺证；形成高优先级候选 | 动态可触发、真实运行影响、维护者确认 |
| 动态 witness | 某个输入或 API 动作序列是否在真实执行中形成可重放证据？ | 证明受控环境中的触发链；与 fixed/negative 对照比较 | 自动代表真实应用入口可利用性或广泛泛化 |
| oracle ground truth | 独立标签、advisory、补丁和人工核验如何定义预期？ | 运行后评估命中、误报和差分 | 作为 detector 输入；替代运行证据 |
| sealed holdout | 冻结方法后未揭示的样本能否检验泛化？ | 通过 blind 协议评估冻结方法 | 揭示后继续充当 sealed 证据；单次成功代表 V3.3 已通过 |

这五类对象在存储、输入时机、状态词和报告措辞上都不得合并。

## 2. 静态分析范围

### 2.1 当前纳入

- Rust–C 边界定位、callback/userdata、raw pointer、returned borrow、external buffer、iterator 和 opaque handle；
- candidate-scoped 静态事实和证据 lineage；
- 参数/返回值、字段、wrapper、collection、closure capture slot 及有限 same-crate helper 的 `ObjectFlow`；
- release proof、release/use ordering、owned anchor、drop guard、mutation/reassignment barrier；
- identity transport、lifecycle ordering、complete risk chain 三层 proof；
- 基于风险和保护性事实的 ranking，以及明确的 incomplete reason。

### 2.2 当前不完整

以下形状不能假定已有通用覆盖：

- 任意深度跨函数或跨 crate `ObjectFlow`；
- trait/dyn dispatch、async/coroutine、复杂循环和控制流合流；
- 动态 key/index、范围索引、多来源对象合流和任意堆别名；
- 复杂 deref/downcast、条件 release、复杂 Drop 路径；
- 未经审计的外部函数对象语义；
- 所有组件均可纯数据接入的 contract registry。

遇到缺证时应保留候选并报告 identity、ordering、contract 或 dynamic witness 缺口，不得从 API 名称、变量名、源码相邻或候选得分补链。

### 2.3 能力边界：哪些缺陷是「发现」的，哪些是「被告知」的

§2.2 列的是**代码形状**缺口。本节列的是更根本的**能力**缺口：对某些缺陷类别，工具并不自己发现问题，而是靠人工输入被告知问题在哪。

| 缺陷类别 | 识别方式 | 现状 |
| --- | --- | --- |
| 返回借用寿命不受输入约束（`fn f<'a>(&self) -> &'a T`） | 定义点、类型层自动分析 | 已实现：[`unconstrained_return_lifetime_relation`](../../compiler/bw-rustc/src/rustc_api/mir.rs) 读 HIR 签名，比较输入与输出的生命周期参数集合 |
| 回调参数 bound 过松（`F: ... + 'c` 绑定在 `&'c self` 上） | **人工写入 API map** | 未自动化。哪些 API 属于回调注册、bound 边界在哪个版本，均由 `contracts/callback-retention/*.toml` 声明 |

这条边界的直接推论必须写明：

- **接入一个新组件，必须先有人手写 API map，工具才能对它工作。** API map registry 目前也不是「所有组件无需改 compiler 即可扩展」的统一语义注册层。
- 因此在回调家族上，工具当前的能力是**验证已知**，不是**发现未知**。用已知 n-day 评测这一层时，"版本边界"部分是循环的——边界是我们写进 map 的。真正非循环的评测只有一种：在**不读 API map** 的前提下重新发现这些 API。
- 这正是通往 0-day 的主要障碍，也是路线图上阶段 B 要攻的目标。

## 3. 动态验证范围

仓库已有 runtime、oracle、D0/D1/D2 实验基础和 rusqlite adapter/harness。当前可用于：

- 已知动作序列的确定性回放；
- 结构化 API action 的受控搜索；
- contract finding、ASan、panic、native crash、timeout 和 tool error 的分离；
- artifact 最小化、独立重放和结果摘要；
- vulnerable/fixed/safe/unregister 等正负对照。

当前尚未形成面向任意静态候选的通用：

```text
witness plan
→ harness 生成或选择
→ executor
→ Miri / fuzz / runtime / oracle
→ 稳定重放
→ 带 checksum 的回执
```

因此“存在 witness plan”不等于“存在动态 witness”，“单元测试通过”也不等于“候选已动态验证”。

## 4. Finding 的边界

`finding` 是 oracle 对事实、contract 和运行时事件应用规则后的结构化输出。解释 finding 时必须同时记录：

- 事实来源和 evidence refs；
- 触发的 contract/rule；
- 对象与事件顺序；
- 运行环境和 `run_id`；
- fixed/negative 对照；
- 是否有 sanitizer、原生崩溃或其他独立影响证据。

静态 candidate 或 ranking 不得改名为 finding。finding 也应继续区分 contract violation、reproduced UB、security relevance、维护者确认和修复状态，不能一步升级成“漏洞”或“0-day”。

## 5. Ground truth 与 blind 边界

- oracle ground truth 与公开扫描输入分离保存；标签只在运行结束后 reveal。
- detector、candidate 生成、ranking 和 witness 搜索不得读取 CVE 编号、补丁、PoC、vulnerable/fixed 标签或预期根因。
- 历史公开 PoC 可以用于 D0 ground truth，但不得复制为 D1 初始 seed。
- sealed holdout 在 scanner、Contract、feature profile、预算和 checksum 冻结后执行。
- 样本一旦 reveal，就只能作为回归或开发样本，不能再次计入 sealed holdout。
- 负对照和失败结果必须保留；不能只发布成功 witness。

数据与仓库隔离规则以 [仓库与数据治理设计](repository-and-data-governance.md) 为准。

## 6. 研究结论边界

当前允许的项目表述：

- **在 API map 已覆盖的 API 范围内**，能定位并排序生命周期敏感的静态候选；
- 对返回借用寿命不受约束这一类，能在无 API map 的情况下从签名自动识别；
- 在已支持代码形状中能恢复部分同对象关系和生命周期顺序；
- 能为受控动态验证生成计划，并已有 runtime/oracle/fuzz 基础；
- 最终目标是在 Rust 组件中自动发现未知生命周期缺陷，当前处于该目标的第一阶段；
- 最新 hardening 仍需完整 public regression、工程 pilot 和 sealed holdout gate。

当前禁止的项目表述：

- 已经自动发现或广泛确认 0-day；
- 在回调家族上「自动发现」不健全 API——该类别当前依赖人工 API map，见 §2.3；
- 把针对已知 n-day 的检出成绩表述为发现能力——n-day 是度量仪器，其版本边界由我们写入；
- 所有 `verified_static_chain` 都是完整风险链；
- 静态高分等同于动态可触发；
- 单次 crash 等同于根因确认；
- 已通过 V3.3、100-crate pilot 或 sealed holdout gate；
- 无法证明的对象关系可用名称或启发式补齐。

## 7. 版本与阶段边界

当前阶段是 **V3.2.x core-effect hardening**。V3.3 只有在 clean method commit、完整 public regression、约 100 crate 工程 pilot、scanner/Contract/feature checksum 冻结及新的未 reveal sealed blind smoke 全部满足后才能通过 gate。准备 V3.3 基础设施或执行小规模 diagnostic 不改变该阶段判断。
