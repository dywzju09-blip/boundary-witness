# 项目概览

BoundaryWitness 的**最终目标是在 Rust 组件中自动发现未知（0-day）生命周期缺陷**。当前处于通往该目标的第一个阶段：**V3.2.x hardening，即可审计、可证伪的已知缺陷验证版**。它围绕 Rust–C 边界恢复生命周期事实，将中性静态证据组织为对象链和风险候选，并为后续动态验证准备可追溯输入。项目不把候选排序等同于漏洞确认，也不把历史样本回归包装成未知漏洞发现。

## 目标层级

最终目标与当前能力必须分开陈述，两者的距离就是路线图：

```text
最终目标：在 Rust 组件中自动发现未知（0-day）生命周期缺陷
  ↑
阶段 B：定义点分析——自动识别哪些 API 的回调 bound 过松
  ↑
阶段 A（当前）：给定已知不健全的组件，能否把它证明出来
  ↑
仪器：n-day 数据集，用于度量阶段 A 的检出率与误报率
```

已知 n-day 是**度量工具能力的仪器**，不是交付目标。下文"明确非目标"列出的是当前阶段尚未达成的能力，不是项目放弃的方向。

## 研究问题

核心问题是：在不向检测流程提供 CVE 编号、补丁、PoC、预期标签或人工编写的违规事件时，能否从真实 Rust–C 程序中取得足够的对象身份、所有权、借用、保留、释放和使用证据，使统一的 contract 与 oracle：

1. 在历史 vulnerable/fixed 对照中识别已知生命周期缺陷；
2. 对 safe-move、及时注销、无触发路径等负对照保持中性或不报；
3. 明确指出对象身份、生命周期顺序或动态证据缺失的位置；
4. 让每个高优先级候选都能回查到代码位置、静态事实、contract 和后续验证需求。

当前工程重点不是扩大候选数量，而是收紧同对象判定、release/use ordering 和完整风险链的真实性。

## 系统目标

- 扫描可构建的 Rust 组件并定位 Rust–C 边界及生命周期敏感位置。
- 由 compiler 提取中性静态事实，而不是直接注入“vulnerable”结论。
- 以 candidate-scoped 方式组织 `ObjectFlow`、release proof、ordering 和保护性事实，避免跨候选污染。
- 将对象身份传递、生命周期顺序和完整风险链分层表达。
- 基于证据而非 API 名称模板生成风险特征、缺证原因和候选排序。
- 使用固定的 Schema、Contract、manifest、checksum 和负对照建立可重放、可审计的验证流程。
- 在进入更大规模实验前，以完整 public regression、工程 pilot 和新的 sealed holdout 作为 gate。

## 当前阶段尚未达成

以下能力当前版本**不承诺**。其中通用 0-day 自动发现是项目的最终目标，列在这里表示当前阶段尚未达成，不表示放弃；其余各条是范围之外，不在路线上。

**尚未达成，但在路线上**：

- 通用 0-day 自动发现与自动确认（最终目标，见上文目标层级）；
- 自动识别未经人工 api map 声明的回调注册 API（阶段 B）；
- 对 trait/dyn dispatch、async/coroutine、复杂循环合流、动态 key/index 的普遍精确处理；
- 任意深度跨函数/跨 crate `ObjectFlow`；
- 在 V3.3 gate 通过前开展正式前瞻大规模扫描（时序限制，非能力限制）。

**范围之外，不在路线上**：

- 漏洞利用生成、RCE 或攻击影响评估；
- 从静态候选直接得出真实漏洞结论（candidate 不是 finding，这是永久纪律而非待补能力）；
- 完整全程序 points-to 或任意堆别名；
- 二进制-only、C++、大规模并发调度搜索或完整 LLVM 插桩；
- 以 LLM 判断替代编译器事实、contract、oracle 或运行证据。

## 威胁模型

当前验证范围面向可取得源码并能在固定环境构建的 **Rust 组件（crate + 版本）**及其 C 依赖。

**扫描对象是组件本身，不是使用该组件的应用。** 缺陷在于组件的安全 API 允许 UB——例如注册回调的 bound 绑在 `&'c self` 而不是 `'static`——这个事实与是否已有应用踩中无关，组件的洞会一直摆在那里等着被踩。需要一个具体触发实例时，由 witness harness **生成**，而不是去真实项目里寻找；这正是 [`generate_witness_harness.rs`](../../crates/bw-cli/src/commands/generate_witness_harness.rs) 存在的理由。

关注对象跨 Rust–C 边界后发生的内存安全与 Rust soundness 风险，重点包括：

- borrowed userdata 被 foreign callback 保留到 Rust 生命周期之外；
- transferred/retained 对象被错误释放、重复释放或释放后使用；
- returned borrow、external buffer 或 iterator 内部指针在 owner 失效后继续使用；
- callback replacement、opaque handle、field/wrapper/collection 存储导致的对象身份或顺序错配。

组件级缺陷与应用级可利用性是两个层次：前者说明"这个安全 API 允许写出 UB"，后者还需要某个应用真的写出了它、且外部输入能驱动到那条路径。本项目只做前者。判定组件不健全**不需要**证明存在受影响的应用——正如 rusqlite 的 advisory 记在 rusqlite 头上，而不是记在任何下游应用头上。相应地，组件级结论也**不得**被表述为已证明真实应用入口可利用。

## 静态与动态证据层级

证据必须按层级解释，不能跨层升级：

1. **边界与候选层**：boundary index 和 candidate 只回答“哪里值得分析”。
2. **静态事实层**：compiler 或经审计 contract 描述观察到的 register、capture、store/load、release、barrier 等事实。
3. **静态链层**：
   - `identity_transport` 只证明对象身份或传递；
   - `lifecycle_ordering` 证明 release、invalidation、use 等顺序；
   - `complete_risk_chain` 表示同对象、顺序与风险路径在静态证据中闭合。
4. **动态 witness 层**：固定输入或搜索得到的动作序列在真实程序中重放，并由 runtime/oracle、sanitizer 或其他观测记录支持。
5. **ground truth 与对照层**：advisory、修复差分和独立标签用于运行后核对；不得作为检测器输入，也不能替代动态执行证据。
6. **sealed holdout 层**：冻结方法后才可揭示的样本，用于检验泛化；揭示过的样本不能再次作为 sealed 证据。

静态完整风险链仍是高优先级候选证据，不自动成为动态确认的 finding。崩溃也不能单独证明根因；固定版本和安全写法的负对照同样属于结论的一部分。

## 主要组件

| 组件 | 主要路径 | 职责 |
| --- | --- | --- |
| 数据模型与 Schema | `crates/bw-model/`、`schemas/` | 定义静态事实、候选、生命周期图、排序、run 和 contract 数据结构 |
| 编译器事实提取器 | `compiler/bw-rustc/` | 通过 rustc/MIR/HIR 提取 callback、capture、对象流、release、barrier 和 ordering 事实 |
| CLI 与静态流水线 | `crates/bw-cli/` | 构建边界索引、候选、生命周期证据/图、排序、pair comparison 和 witness plan |
| Contract | `contracts/callback-retention/` | 提供经审计的 callback/API 角色及 opaque-handle 参数身份语义 |
| Runtime | `crates/bw-runtime/` | 记录对象、callback、epoch 和运行时事件，不直接输出漏洞答案 |
| Oracle | `crates/bw-oracle/` | 融合 static facts、runtime events 与 contract，产生规则级 finding 和可比较证据 |
| 实验与 fuzz 基础 | `crates/bw-experiment/`、`crates/bw-fuzz-observer/` | 管理 D0/D1/D2、结果分类、重放、预算和 contract-state feedback |
| 历史样本与 compiler fixtures | `benchmarks/`、`fixtures/` | 提供 vulnerable/fixed/negative 对照和确定性编译器验收输入 |
| Blind 协议 | `crates/bw-blind-model/`、`crates/bw-blind-curator/`、`crates/bw-blind-runner/` | 隔离公开输入、私有标签、运行回执和 reveal 流程 |
| 治理与数据边界 | `docs/project/repository-and-data-governance.md` | 规定公开仓库、私有索引、大型数据、运行对齐和发布边界 |

## 当前研究路线

当前路线保持在 **V3.2.x core-effect hardening**：

1. 收紧 opaque-handle identity、returned-borrow claimant 和 proof-layer 语义；
2. 扩展但不放宽同对象 `ObjectFlow` 与 release/use ordering；
3. 将 contract 消费推进为可审计、可加载的通用 registry；
4. 打通 witness plan 到 executor、runtime/oracle、重放回执的通用动态桥；
5. 在 clean method commit 上执行完整 public regression 和约 100 crate 工程 pilot；
6. 冻结 scanner、Contract、feature profile 与 checksum；
7. 使用新的、未 reveal 的 sealed holdout 进行 blind smoke；
8. 仅在全部 gate 通过后进入 V3.3。

详细状态见 [当前状态](current-status.md)，范围解释见 [范围与边界](scope-and-boundaries.md)，字段与概念见 [术语](terminology.md)。
