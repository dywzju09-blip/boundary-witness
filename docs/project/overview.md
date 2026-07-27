# 项目概览

BoundaryWitness 当前定位为 **V3.2.x hardening 阶段的、可审计、可证伪的已知 CVE 检测验证版**。它围绕 Rust–C 边界恢复生命周期事实，将中性静态证据组织为对象链和风险候选，并为后续动态验证准备可追溯输入。项目不把候选排序等同于漏洞确认，也不把历史样本回归包装成未知漏洞发现。

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

## 明确非目标

当前版本不承诺：

- 通用 0-day 自动发现、自动确认或漏洞利用生成；
- 从静态候选直接得出真实漏洞结论；
- 完整全程序 points-to、任意堆别名或任意深度跨函数/跨 crate 追踪；
- 对 trait/dyn dispatch、async/coroutine、复杂循环合流、动态 key/index 的普遍精确处理；
- 二进制-only、C++、大规模并发调度搜索或完整 LLVM 插桩；
- RCE、可利用性或攻击影响评估；
- 以 LLM 判断替代编译器事实、contract、oracle 或运行证据；
- 在 V3.3 gate 通过前开展正式前瞻大规模扫描。

## 威胁模型

当前验证范围面向可取得源码并能在固定环境构建的 Rust 下游程序及其 C 依赖。关注对象跨 Rust–C 边界后发生的内存安全与 Rust soundness 风险，重点包括：

- borrowed userdata 被 foreign callback 保留到 Rust 生命周期之外；
- transferred/retained 对象被错误释放、重复释放或释放后使用；
- returned borrow、external buffer 或 iterator 内部指针在 owner 失效后继续使用；
- callback replacement、opaque handle、field/wrapper/collection 存储导致的对象身份或顺序错配。

攻击面假设外部输入通过合法应用入口、配置、文件、网络消息或 API 参数驱动程序状态。当前验证版以历史 CVE、受控 fixture 和本地实验为主，不据此声称已证明真实应用入口可利用性。

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
