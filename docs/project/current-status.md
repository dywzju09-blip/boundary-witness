# 当前状态

**阶段锚点：V3.2.x core-effect hardening；P4 反证合成已在 fixture 级实现（2026-08-08）。V3.3 gate 未通过。**

本文只陈述当前公开工作树中可以由代码、测试和运行记录支撑的状态。方向权威见 [research thesis](research-thesis.md)；能力边界见 [scope and boundaries](scope-and-boundaries.md)。状态含义见 [术语](terminology.md#状态词)。`Implemented` 说明实现和测试存在；只有与当前 commit、配置、数据及 checksum 对齐的正式运行记录才能标为 `Verified`。

## 相对研究主线的位置

[research thesis](research-thesis.md) 于 2026-07-30 重写，创新点编号由 N1/N2/N3 改为 C1/C2/C3。**2026-08-08 起静态闭环（C2）与反证合成链路（C1）在 fixture 上实现并端到端验证；2026-08-23 起反证合成链路在真实组件（rusqlite 0.26.1 / RUSTSEC-2021-0128）上端到端复验：**

| 创新点 | 状态 | 缺什么 |
| --- | --- | --- |
| C1 safe-only 可执行反证合成 | `Implemented`（fixture + 真实组件） | fixture：7/7 primary 触发 ASan heap-use-after-free、19 个控制组全干净。真实组件：rusqlite 0.26.1 M12 家族三个 API（update_hook / commit_hook / rollback_hook）6/6 borrowed-capture 计划全部 confirmed、no-trigger 判别控制全干净，witness 回执已接入 checksum 清单（十四个产物目录 verify-run 全过）**正式 Verified 仍需按 D2 判据把 scratch 产物纳入受管位置并对齐 commit 与 checksum 的运行记录** |
| C2 类型契约 × 外部 effect 的精化检查 | `Implemented`（fixture + 真实 IR） | 两侧事实均从真实构建产物推导（wrapper MIR/HIR + clang IR），分层联结产出三态判定与证据来源记录；真实 sqlite3.c IR（78 万行）上 Q1/Q3/Q4′ 提取实测 4.4 s。跨库泛化（Gate C）、别名/线程/重入/展开/值域/初始化六维未做 |
| C3 生态级度量与新发现 | `Planned` | 猎物存在性尚未测量（roadmap PP），无法判断新发现目标是否可达 |

**外部基线对照结果见 [Gate 0](../experiments/results/gate0-baseline-comparison-2026-07-31.md)**（历史记录：排除误报当时只用了 Rust 侧签名形状）。Gate R 关系正确性已通过（2026-07-31），且自 stage3 起「外部侧手工标注」这一限制已解除——Q1/Q4′/降级 Q3 均由真实 LLVM IR 推导。

**当前最高优先级是 stage6 剩余收口**：verify-run checksum 清单接入与真实 rusqlite 组件端到端复验均已完成（2026-08-23，见 [stage6 记录](../experiments/results/stage6-checksum-and-rusqlite-e2e-2026-08-23.md)）；剩 Gate 复核材料准备与正式 D2 对齐。完整执行顺序见 [execution plan](../roadmap/execution-plan.md)。

## 状态总览

| 状态 | 能力或事项 | 结论 |
| --- | --- | --- |
| `Implemented` | 静态候选、candidate-scoped 生命周期事实、graph-v3、ranking 和 witness plan 主链 | 代码与测试存在；输出仍是候选与验证计划 |
| `Implemented` | mutation/reassignment barrier | model、compiler 与 collection/storage barrier 已实现并有测试 |
| `Implemented` | closure capture slot 与 use-side projection | compiler golden 和 graph tests 已有本地验收 |
| `Implemented` | opaque handle identity schema enforcement | 当前工作树包含结构化 generation key 与 validator；仍需完整回归复验 |
| `Implemented` | returned-borrow exact claimant | 共享事实只接受唯一 exact anchor；仍需完整回归复验 |
| `Implemented` | object-chain proof-layer split | identity、ordering、complete risk chain 已分层；仍需完整回归复验 |
| `Implemented` | runtime、oracle 与 fuzz observer 基础 | 组件测试通过；不是任意候选 executor |
| `Implemented` | 持有期维度的 Rust 侧契约抽取 | 从 HIR 签名判定回调 bound，无需 API 清单；健全与不健全两侧都产出事实。语义取值由 `effective_capture_admission()` 给出，覆盖泛型 / APIT / HRTB / trait object |
| `Implemented` | 返回借用寿命不受输入约束的定义点识别 | 从 HIR 签名比较输入与输出的 lifetime 参数集合，无需 API 清单。此维度与 Yuga 重叠，不作创新点 |
| `Implemented` | 持有期维度的两侧联结与判定来源记录 | 要求同一函数上既有非 `'static` 的 bound、又有外部边界事实；两路结论不一致时都留在产物中 |
| `Implemented` | 核心关系与四个 matched fixture（roadmap PF） | `crates/bw-model/src/compatibility.rs` + `crates/bw-model/tests/compatibility.rs`（14 项）+ `benchmarks/compiler-fixtures/callback-retention-relation/`。四个 fixture 全部判对，Full 能分开 2 与 3、Rust-only 不能。**外部侧事实由 C stub 手工标注**（manual foreign oracle），不是从 IR 推导 |
| `Implemented` | `EffectiveCaptureAdmission`（roadmap PC） | 语法 scope 到语义取值的映射 + `dyn Fn` 覆盖。`crates/bw-model/src/static_fact.rs`、`compiler/bw-rustc/src/rustc_api/mir.rs`。golden 与模型测试覆盖 APIT / HRTB / `Box<dyn>` / `&mut dyn` / 显式 lifetime |
| `Implemented` | `RegistrationGuard` 检测（roadmap PG-1） | 从 HIR 签名与 guard 类型的 `Drop` MIR 判定，无需 API map。`compiler/bw-rustc/src/rustc_api/mir.rs` 的 `registration_guards`、`crates/bw-model/src/static_fact.rs` 的 `RegistrationGuard`/`RegistrationGuardFact`。golden 见 `compiler/bw-rustc/tests/callback_retention_relation_golden.rs`。**不产出 `OwnerDropUnregisters`**——那一取值的判据是 owner drop 路径证明，不是返回值形状 |
| `Implemented` | `AllocationOwnership` 检测（roadmap PG-2，2026-08-06） | 编译器探针先行：容器形状 + raw-pointer transfer 证据推导分配归属取值。`crates/bw-model/src/static_fact.rs` 的 `AllocationOwnership` + `compiler/bw-rustc/src/rustc_api/mir.rs`。计划见 [execution plan](../roadmap/execution-plan.md) |
| `Implemented` | 编译器输出装成 `RustContractFact`（roadmap P0，2026-08-06） | `extract-rust-contracts` 命令 + `bw-model::RustContractFact`（schema `bw.rust-contract/0.1`）。PF 阶段的手写事实已被生产者取代 |
| `Planned` | 猎物存在性探针（roadmap PP） | 未测量。P-a 前置是 PC、PG-2、`is_unsafe_fn`、safe-entry lineage 与 L1 binding；P-b 还依赖 P0–P4 核心闭环 |
| `Implemented` | 外部行为事实：Q1 逃逸、Q4′ 清槽、降级 Q3（roadmap P1/P2/P3，2026-08-05） | `extract-foreign-facts` 从 clang IR 推导 `ForeignRetention`/`ForeignInvocation`/`ForeignClear`，RoleMap JSON 声明符号角色（不接受人工标注行为）。降级 Q3 只产出 `same_slot_invoke_candidate` 级证据且从不输出 `SupportedIncompatibility`（ADR-0004） |
| `Implemented` | hand-off 身份与双侧事实模型（roadmap P0，2026-08-06） | `HandOffId` 五层身份 + `judge-hand-offs` 分层联结 + 三态判定（`SupportedIncompatibility`/`CompatibleWithinAnalyzedFragment`/`InsufficientEvidence`），判定来源与证据等级全部入产物。**artifact-aligned identity 是实现属性，不是创新点** |
| `Planned` | 别名、线程、重入、展开、值域、初始化六个维度 | 两侧均未实现，属 future work，持有期一维闭环前不扩维 |
| `Implemented` | safe-only 反证合成与执行（roadmap P4，2026-08-08；真实组件 2026-08-23） | `plan-witnesses` → `generate-safe-client` → `run-safe-client` 全链。fixture：7 计划全部合成并确认为反例（ASan heap-use-after-free），25 条拒绝留痕，19 控制组全绿。真实组件 rusqlite 0.26.1 `update_hook`：联结零拒绝、2 borrowed-capture 计划 confirmed + no-trigger 控制干净。结果见 [stage5 记录](../experiments/results/stage5-p4-witness-synthesis-2026-08-08.md)与 [stage6 记录](../experiments/results/stage6-checksum-and-rusqlite-e2e-2026-08-23.md)。正式 D2 对齐未做 |
| `Planned` | 排名把可绑定的注册候选排进默认输出上限 | 默认上限取不到它们，默认扫描看不到判定结果 |
| `Planned` | 通用跨函数 `ObjectFlow`、完整 release/use ordering、通用 contract registry | 仅覆盖有限代码形状 |
| `Blocked` | V3.3、约 100 crate pilot、sealed holdout | clean method commit、完整 public regression、pilot、freeze 与新 sealed smoke 尚未全部完成 |
| `Deprecated` | 以 `verified_static_chain` 单字段代表所有证明层 | 字段仅作兼容保留，规范语义改用 `verified_layers`/`missing_layers` |
| `Verified` | 正式实验能力结论 | 无；仓库内尚无与当前 commit 对齐的完整运行证据可支撑 `Verified` 声明 |

## Implemented：静态分析主链

当前代码已包含边界索引、候选生成、生命周期证据提取、graph-v2/v3、ranking、匿名 pair comparison 和 witness plan 命令。

- 代码路径：
  - `crates/bw-cli/src/commands/index_boundaries.rs`
  - `crates/bw-cli/src/commands/emit_candidates.rs`
  - `crates/bw-cli/src/commands/extract_lifecycle_evidence.rs`
  - `crates/bw-cli/src/commands/build_lifecycle_graph_v3.rs`
  - `crates/bw-cli/src/commands/rank_lifecycle_v2.rs`
  - `crates/bw-cli/src/commands/build_witness_plan.rs`
  - `crates/bw-model/src/lifecycle_v326.rs`
- 测试路径：
  - `crates/bw-cli/tests/lifecycle_v326_cli.rs`
  - `crates/bw-cli/tests/help.rs`
  - `crates/bw-model/tests/lifecycle_v326.rs`
  - `crates/bw-model/tests/schema_roundtrip.rs`

该状态只证明主链实现存在并受测试约束，不证明任意组件都能形成完整对象链。

## Implemented：mutation/reassignment barrier

同对象链在共享 binding key 的 field、container 或 storage 中出现覆盖、替换或 mutation 时，会被 barrier 阻断。barrier 是反向证据，不是漏洞结论；它不应扩大为 whole-crate 降级。

- 代码路径：
  - `compiler/bw-rustc/src/rustc_api/mir.rs`
  - `compiler/bw-rustc/src/domain.rs`
  - `crates/bw-model/src/lifecycle_v326.rs`
- 测试路径：
  - `crates/bw-model/tests/lifecycle_v326.rs`
  - `compiler/bw-rustc/tests/mir_sites_golden.rs`
  - `benchmarks/compiler-fixtures/callback-sites/src/lib.rs`
  - `benchmarks/compiler-fixtures/diesel-sites/src/lib.rs`

已覆盖 model 层 binding-key 阻断、raw pointer field/aggregate/place-alias reassignment，以及 returned-borrow collection exact-key/prefix mutation guard。新增 wrapper、跨 crate 或复杂 storage 形状仍属于覆盖扩展，不改变该能力已实现的状态。

## Implemented：closure capture slot/use-side projection

closure capture 不再仅按 callback endpoint 合并。compiler 使用 capture ordinal 和受限 field projection 生成 slot key，并从 closure body MIR 产生对应 `FieldLoad`；graph 只有在 capture slot 与 use slot 严格一致时才晋升对象链。

- 代码路径：
  - `compiler/bw-rustc/src/rustc_api/captures.rs`
  - `compiler/bw-rustc/src/rustc_api/mir.rs`
  - `compiler/bw-rustc/src/domain.rs`
  - `crates/bw-model/src/lifecycle_v326.rs`
- 测试路径：
  - `compiler/bw-rustc/tests/captures_golden.rs`
  - `fixtures/compiler/captures.expected.jsonl`
  - `benchmarks/compiler-fixtures/callback-captures/src/lib.rs`
  - `crates/bw-model/tests/lifecycle_v326.rs`

本地验收覆盖 borrowed/owned、多 capture、字段投影、重复读取和 slot 分离。复杂 deref/index/downcast、trait object 与 async/coroutine capture 仍应退回缺证。

## Implemented：opaque handle identity schema enforcement

当前工作树为 audited opaque-handle API map 增加结构化 `opaque_generation_key`，并要求 identity 至少包含 binding API、handle 参数和 key 参数；set role 还必须包含 payload。OpenSSL API map 已按该结构声明。

- 代码路径：
  - `crates/bw-model/src/contract.rs`
  - `contracts/callback-retention/openssl-api-map.toml`
  - `compiler/bw-rustc/src/config.rs`
  - `compiler/bw-rustc/src/rustc_api/mir.rs`
- 测试路径：
  - `crates/bw-model/tests/schema_roundtrip.rs`
  - `crates/bw-model/tests/lifecycle_v326.rs`
  - `compiler/bw-rustc/tests/mir_sites_golden.rs`

迁入工作树中的实现和局部测试不能替代迁移后的完整 compiler/public regression。新增 opaque-handle contract 仍必须证明 handle origin、slot/key 和 payload lineage，不能只复用同名 API。

## Implemented：returned-borrow exact claimant

returned-borrow 共享事实不再通过 candidate score、candidate ID 或源码距离选择归属。只有一个 candidate 同时满足 exact API key 与已锚定 returned-borrow relation 时，才成为 canonical claimant；否则不将共享事实挂入候选。

- 代码路径：
  - `crates/bw-cli/src/commands/extract_lifecycle_evidence.rs`
  - `crates/bw-model/src/lifecycle_v326.rs`
- 测试路径：
  - `crates/bw-cli/tests/lifecycle_v326_cli.rs`
  - `crates/bw-cli/tests/cli.rs`
  - `crates/bw-model/tests/lifecycle_v326.rs`

该改动已在当前工作树中存在，仍需通过迁移后的完整 public regression 检查对 candidate coverage、pair separability 和 incomplete reasons 的总体影响。

## Implemented：object-chain proof-layer split

graph-v3 以 `verified_layers` 和 `missing_layers` 分开记录：

1. `identity_transport`；
2. `lifecycle_ordering`；
3. `complete_risk_chain`。

ranking summary 分别统计三类 chain。单个 external-buffer binding 只能点亮 identity transport；returned-borrow 必须同时具备 relation、persistence 和 invalidation/use ordering 才能闭合完整链。

- 代码路径：
  - `crates/bw-model/src/lifecycle_v326.rs`
  - `schemas/v3-2-6/lifecycle-graph-v3.schema.json`
  - `schemas/v3-2-6/ranked-candidate-v2.schema.json`
- 测试路径：
  - `crates/bw-model/tests/lifecycle_v326.rs`
  - `crates/bw-model/tests/schema_roundtrip.rs`
  - `crates/bw-cli/tests/cli.rs`

迁移后仍需完整 regression 确认旧消费者、graph 统计和 ranking gate 均按新层级解释，不能把兼容字段 `verified_static_chain` 继续当作完整风险链。

## Implemented：runtime、oracle 与 fuzz observer 基础

runtime 能记录对象和 callback 事件；oracle 能融合 static/runtime/contract 事实；fuzz observer 能把 contract-state 转换为稳定 feedback。三者的迁移后组件测试均通过。

- 代码路径：
  - `crates/bw-runtime/src/`
  - `crates/bw-oracle/src/`
  - `crates/bw-fuzz-observer/src/`
- 测试路径：
  - `crates/bw-runtime/tests/`
  - `crates/bw-oracle/tests/`
  - `crates/bw-fuzz-observer/tests/`

这些测试证明组件行为，不构成当前迁移 commit 上的正式动态实验记录，因此不标为 `Verified`。`bw-experiment` 与 rusqlite 定向 harness 的代码和公开 fixtures 已迁入，可用于组件级测试，但 formal D0/D1/D2 和 public regression 仍需要独立 run manifest、checksum 与对照证据。

## Implemented：反证合成链路（roadmap P4，2026-08-08）

判定 → 反证计划 → safe-only 客户端 → oracle 回执 → 控制矩阵的完整链路已实现并在
callback-retention-relation fixture 上端到端验证。

- 代码路径：
  - `crates/bw-model/src/witness.rs`（计划推导、schema 常量）
  - `crates/bw-cli/src/commands/plan_witnesses.rs`
  - `crates/bw-cli/src/commands/safe_client.rs`（生成引擎）
  - `crates/bw-cli/src/commands/generate_safe_client.rs`
  - `crates/bw-cli/src/commands/run_safe_client.rs`
  - `experiments/configs/p4-fixture-controls.toml`（判决后控制矩阵）
  - `contracts/callback-retention/callback-retention.foreign-roles.json`
- 测试路径：
  - `crates/bw-cli/tests/witness_pipeline_cli.rs`（真实 wire 格式的链路集成测试）
  - `crates/bw-cli/src/commands/safe_client.rs`（引擎单测：变体重排、覆盖断言、拒绝路径）
  - `crates/bw-cli/src/commands/plan_witnesses.rs`（关联键身份性测试）

fixture 运行结果：7 计划全部合成并执行，primary 全部触发 ASan heap-use-after-free；
25 条拒绝留痕；19 个控制组（fixed_foreign / owned_callback / unregister_before_drop /
no_trigger / synchronous）全部符合预期。回执 schema `bw.witness-receipt/0.1`，
含 binary/stderr sha256、sanitizer 结构化报告与可重放 argv。**这是 fixture 级
`Implemented`：真实组件复验、verify-run checksum 清单接入、跨库泛化均未完成，
不标 `Verified`。** 结果与边界见 [stage5 记录](../experiments/results/stage5-p4-witness-synthesis-2026-08-08.md)。

## Planned：仍不完整的核心能力

以下能力有明确方向，但当前实现不能被描述为通用完成：

- 任意深度、任意控制流的跨函数 `ObjectFlow`；
- trait/dyn dispatch、async/coroutine、复杂循环合流和跨 crate unknown helper；
- 条件 release、复杂 Drop、完整 release/use coverage 与 ordering；
- 动态 key/index、多来源合流和任意堆别名；
- 无需改 compiler 代码即可接入新组件的统一 contract registry；
- 通用 executor：把反证计划驱动到 Miri、fuzz、runtime、oracle 与 replay receipt 的任意后端组合（当前 oracle 后端只覆盖 ASan heap-use-after-free 一类证据）。

相关现有入口包括 `compiler/bw-rustc/src/rustc_api/mir.rs`、`crates/bw-cli/src/commands/build_witness_plan.rs`、`crates/bw-experiment/src/` 和 `contracts/callback-retention/`，但这些路径的存在不能升级状态。

## Blocked：V3.3 与正式 gate

迁移后的 `bw-experiment` 组件测试现在包含公开 ASan parser fixtures：

- `crates/bw-experiment/tests/asan_log_parser.rs` 读取 `fixtures/experiment/asan/positive.log` 与 `fixtures/experiment/asan/negative.log`；
- 这两个 fixture 是公开、合成、最小的 parser 输入，不包含私有 run 或样本身份；
- 组件测试通过只支持 `Implemented` 层的 parser/runner/summary 基础，不支持把动态实验能力标为 `Verified`。

以下事项仍为 `Blocked`：

- V3.3 正式前瞻扫描；
- 约 100 crate 工程 pilot；
- 新的 sealed holdout blind smoke；
- 用最新 hardening 结果形成正式效果结论。

解除阻塞必须至少完成：

1. clean method commit；
2. 当前 commit 上的完整 compiler 与 public regression；
3. 约 100 crate pilot；
4. scanner、Contract、feature profile 与 checksum freeze；
5. 新的、未 reveal sealed holdout；
6. controls、完整率、pair separability 和运行回执审查。

当前可准备基础设施和 diagnostic，但不得称为 V3.3 gate 通过。

## Deprecated：`verified_static_chain` 的宽泛解释

`chain_status=verified_static_chain` 仍可能作为兼容字段存在，但不再单独表示完整生命周期风险。新文档、Schema 消费者和 gate 应读取 `verified_layers`/`missing_layers` 及 ranking 的分层计数。依赖旧字段把 identity transport、ordering 和 complete risk chain 合并解释的做法为 `Deprecated`。

- 兼容代码路径：`crates/bw-model/src/lifecycle_v326.rs`
- 兼容 Schema 路径：`schemas/v3-2-6/lifecycle-graph-v3.schema.json`
- 测试路径：`crates/bw-model/tests/lifecycle_v326.rs`、`crates/bw-model/tests/schema_roundtrip.rs`

## Verified：当前无新增声明

本迁移工作树目前没有与当前公开 commit、完整数据 manifest、Contract/config checksum 和正式运行回执对齐的 public regression、100-crate pilot 或 sealed holdout 记录。因此本文不把任何最新 hardening 能力标为 `Verified`。局部单元、集成和 compiler golden 测试只支撑 `Implemented`。
