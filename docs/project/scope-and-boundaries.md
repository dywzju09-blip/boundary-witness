# 范围与边界

本文固定 BoundaryWitness 当前验证版的能力边界。项目处于 **V3.2.x hardening**，目标是建立可审计、可证伪的已知 CVE 检测验证链，而不是宣称已经成为通用 0-day 自动发现器。

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

- 能定位并排序生命周期敏感的静态候选；
- 在已支持代码形状中能恢复部分同对象关系和生命周期顺序；
- 能为受控动态验证生成计划，并已有 runtime/oracle/fuzz 基础；
- 最新 hardening 仍需完整 public regression、工程 pilot 和 sealed holdout gate。

当前禁止的项目表述：

- 已经自动发现或广泛确认 0-day；
- 所有 `verified_static_chain` 都是完整风险链；
- 静态高分等同于动态可触发；
- 单次 crash 等同于根因确认；
- 已通过 V3.3、100-crate pilot 或 sealed holdout gate；
- 无法证明的对象关系可用名称或启发式补齐。

## 7. 版本与阶段边界

当前阶段是 **V3.2.x core-effect hardening**。V3.3 只有在 clean method commit、完整 public regression、约 100 crate 工程 pilot、scanner/Contract/feature checksum 冻结及新的未 reveal sealed blind smoke 全部满足后才能通过 gate。准备 V3.3 基础设施或执行小规模 diagnostic 不改变该阶段判断。
