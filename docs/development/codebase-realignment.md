# 代码库对齐审计与处置决定

本文审计当前代码库相对 [research thesis](../project/research-thesis.md) 新路线的对齐情况，并给出**逐组件的处置决定**。

审计日期：2026-07-30。审计基线 commit：`46abf7f`。2026-07-31 复审后补充执行顺序（§9）与两处受影响的处置。

**处置分类本身未因复审改变**——复审修正的是研究关系与 gate 方法学，不是代码资产的去留。

## 0. 本文的效力

**本文的处置决定具有约束力。** 与本文冲突的实现选择需要先改本文，不能直接实施。

三条具名决定见 §6，它们是本文最容易被时间冲淡、也最需要写下来的部分：

| 编号 | 决定 |
| --- | --- |
| **D1** | 冻结 returned-borrow 维度：不删除，不新增投入，不作为贡献陈述 |
| **D2** | `HandOffId` + 三态判定 + 外部侧事实合并为**一次** schema 升版 |
| **D3** | 重写 `generate_witness_harness.rs` 的**产出目标**，保留其推导逻辑 |

## 1. 审计口径

- 统计单位是行数（`wc -l`，含空行与注释），不区分声明与逻辑；
- `src` 与 `tests` 分开计数，测试资产是本文判断「重构 vs 补充」的重要输入；
- 「是否在关键路径上」以 `tools/experiment/run-scan.sh` 实际调用的 stage 为准，不以 CLI 是否注册为准。**这两者已经出现分叉**，见 §7。

## 2. 总量与分布

约 114k 行（src + tests）。

| 组件 | src | tests | 合计 | 新路线中的角色 |
| --- | ---: | ---: | ---: | --- |
| `compiler/bw-rustc` | 27.6k | 8.7k | **36.3k** | C2 的规约抽取侧。**最大资产，价值不降反升** |
| `crates/bw-model` | 15.9k | 11.7k | 27.6k | 事实模型与身份，可扩展 |
| `crates/bw-cli` | 15.5k | 9.7k | 25.2k | 流水线，多数保留，一处重写 |
| `crates/bw-blind-*` | 12.2k | — | 12.2k | 数据隔离，Gate D 仍需要 |
| `crates/bw-experiment` | 7.7k | — | 7.7k | 实验编排，角色降级 |
| `bw-oracle`/`bw-runtime`/`bw-fuzz-observer` | 5.3k | — | 5.3k | **从「就是 oracle」降为「辅助定位」** |
| `crates/bw-v3-nday-adapter` | 1.1k | — | 1.1k | 度量仪器，保留 |

**外部侧分析：0 行。** 这是与新路线之间最大的缺口，但它是纯新增，不构成重构理由。

## 3. 核心发现：投入方向与新优先级成反比

`compiler/bw-rustc/src/rustc_api/mir.rs` 共 21481 行。按关键词统计：

| 关键词 | 出现次数 | 函数数 | 在新路线中的地位 |
| --- | ---: | ---: | --- |
| `returned_borrow` | **1121** | **225** | 非跨界维度，与 Yuga 重叠，[明确不作创新点](../project/scope-and-boundaries.md) |
| `release` | 296 | 4 | 服务 Q4′ 与负对照，保留 |
| `registration` | 267 | 24 | 保留 |
| `capture` | 119 | 15 | 保留 |
| `object_flow` | 116 | 23 | 未来扩维用，冻结 |
| `object_binding` | 34 | — | 冻结 |
| `atomic_ordering` | 28 | 6 | 冻结 |
| `external_buffer` | 26 | 5 | 冻结 |
| **`callback_lifetime_bound`** | **5** | **1** | **C1/C2/C3 全部依赖它** |

编译器里最大的一块投入，落在新路线明确不作贡献的维度上；而三条创新点共同依赖的那一条判定，只有一个函数（`mir.rs:20997` 的 `callback_lifetime_bounds`）。

**这不是要删代码。** 它是 D1 的依据：这块代码会持续吸走维护精力，也会持续把论文叙事往「我们覆盖很多维度」上带——那正是 [research thesis §11](../project/research-thesis.md) 第 16 条禁止的方向。

## 4. 处置分类的定义

| 分类 | 含义 | 允许的操作 |
| --- | --- | --- |
| **保留** | 在新路线上有明确角色 | 正常演进 |
| **冻结** | 能跑、有测试，但不服务当前创新点 | 只做保持编译通过的最小修改。**不新增功能、不扩覆盖、不写进贡献列表** |
| **重构** | 角色仍在，但当前形态与新路线冲突 | 按本文指定的方向改造 |
| **删除** | 无消费方，或与新路线冲突且无保留价值 | 删除前必须先执行本文给出的验证命令 |
| **新建** | 当前不存在 | 见 [implementation plan](../roadmap/implementation-plan.md) |

## 5. 逐组件处置

### 5.1 `compiler/bw-rustc`（36.3k）

| 路径 | 行数 | 处置 | 理由 |
| --- | ---: | --- | --- |
| `src/rustc_api/mir.rs` 的 `callback_lifetime_bounds` 及其调用点 | ~120 | **保留并重构** | C2 的规约抽取，PP 探针的全部依赖。**取值需从语法四态改为 `EffectiveCaptureAdmission` 语义取值**（roadmap PC）——现状把「无 bound 的泛型」与「默认 `'static` 的 `dyn Fn`」这两种语义相反的情况合并了 |
| `src/rustc_api/mir.rs` 的 returned-borrow 族（225 函数） | ~8k 估 | **冻结**（D1） | 非跨界维度 |
| `src/rustc_api/mir.rs` 的 external-buffer / atomic-ordering / object-binding-gap | ~1k 估 | **冻结** | 服务已转 future work 的维度 |
| `src/rustc_api/mir.rs` 的 registration / capture / release 族 | ~3k 估 | **保留** | 服务 Q4′、负对照与 hand-off 身份 |
| `src/site.rs`（`SiteDescriptor`） | 245 | **保留并扩展** | 见下 |
| `src/registration.rs` | 1479 | **保留** | 角色分类，`HandOffId` 的参数索引来源 |
| `src/domain.rs` | 2104 | **保留并扩展** | 事实产出边界 |
| `src/config.rs` | 1287 | **保留** | API map 装载 |
| `src/coverage.rs`、`src/args.rs`、`src/cargo_metadata.rs`、`src/path_remap.rs`、`src/callbacks.rs` | ~625 | **保留** | 基础设施 |

**`SiteDescriptor` 是 P0 的现成入口，不需要重写。** 它已经是 builder 模式，把这些字段哈希成稳定 `SiteId`：

```
package / target / def_path / role / mir_location / capture_ordinal / relative_path / span
```

`HandOffId` 还需要：Rust artifact hash、单态化实例、外部符号、callback/userdata 参数索引、build profile。**全部通过新增 `with_*` 方法加入**，既有调用点不受影响。

**外部符号是可推导的，只是没记录。** `mir.rs:21398` 的 `owner_is_foreign_callback` 已经在判 `extern "C"` ABI，被调方 `def_path` 也拿得到；`libsqlite3_sys::sqlite3_update_hook` 到链接符号是一一对应关系（`#[link_name]` 是唯一例外，必须处理）。这是 P0 的一项具体工作，不是新能力。

### 5.2 `crates/bw-model`（27.6k）

| 路径 | 行数 | 处置 | 理由 |
| --- | ---: | --- | --- |
| `src/id.rs` | 58 | **保留并扩展** | `HandOffId` 的 newtype 落点 |
| `src/static_fact.rs` | 692 | **保留并扩展** | 19 变体枚举，新增 `ForeignBehaviorFact` 是加法 |
| `src/lifecycle_v326.rs` | 9764 | **保留 + 局部重构** | 见下 |
| `src/contract.rs` | 491 | **保留并扩展** | API map 模型，需加外部符号字段 |
| `src/lifecycle.rs` | 848 | **冻结** | V3.2 legacy ranked/graph 模型，仍被 pilot 计量链消费 |
| `src/candidate.rs` | 351 | **保留** | `V32CandidateRecord` 是活跃类型，「V32」只是 schema 代号 |
| `src/validate.rs`、`src/schema.rs`、`src/jsonl.rs`、`src/error.rs`、`src/run.rs` | ~1.2k | **保留** | 基础设施 |
| `src/boundary_index.rs`、`src/buildability.rs`、`src/corpus.rs` | 672 | **保留** | PP 探针与生态扫描要用 |
| `src/failure_taxonomy.rs`、`src/adapter_effort.rs` | 667 | **保留** | Gate D 要报告 adapter 成本与失败分类 |
| `src/static_ranking_reveal.rs` | 687 | **保留** | blind reveal 链 |
| `src/scanner_freeze.rs` | 242 | **保留** | Gate 6 freeze |
| `src/runtime_event.rs` | 165 | **保留** | 降级为辅助证据，模型仍需要 |
| `src/finding.rs`、`src/public_tokens.rs` | 124 | **保留** | |

**`lifecycle_v326.rs` 的局部重构范围**（不是重写这 9764 行）：

- `V326CallbackBoundVerdict`、`V326DerivedCallbackBound`、`V326WitnessCallbackBoundScope` → 改为**三个正交维度** `StaticVerdict` / `EvidenceGrade` / `WitnessStatus`。**不得引入 `SupportedIncompatibility (weak)` 或任何第四态**；
- `CallbackLifetimeBoundScope` → `EffectiveCaptureAdmission`（随 PC 一起做，同属 D2 的一次升版）；
- 新增 `RustContractFact` / `ForeignBehaviorFact` / `CompatibilityVerdict` 三层，作为现有 `StaticFact` 的聚合，**不删除底层事实种类**；
- `V326LifecycleFactKind::ALL` 与 `schema_token()` 的双向 schema 测试必须同步扩展——这条机制已经挡住过遗漏，不能绕过。

### 5.3 `crates/bw-cli`（25.2k）

| 路径 | 行数 | 处置 | 理由 |
| --- | ---: | --- | --- |
| `commands/extract_static_facts.rs` | 1510 | **保留** | **PP 探针的入口，且不依赖 API map** |
| `commands/index_boundaries.rs` | 962 | **保留并扩展** | 需记录外部符号 |
| `commands/emit_candidates.rs` | 1016 | **保留** | |
| `commands/extract_lifecycle_evidence.rs` | 2832 | **保留 + 局部重构** | join 逻辑改挂 `HandOffId` |
| `commands/build_lifecycle_graph_v3.rs` | 365 | **保留** | |
| `commands/rank_lifecycle_v2.rs` | 231 | **保留，降优先级** | 排序不是贡献，仅用于 triage |
| `commands/build_witness_plan.rs` | 1545 | **保留 + 局部重构** | 输出改为反证义务；判定字段拆成 `StaticVerdict` / `EvidenceGrade` / `WitnessStatus` 三个正交维度 |
| **`commands/generate_witness_harness.rs`** | **1266** | **重构（D3）** | 见 §6 |
| `commands/validate.rs` | 1074 | **保留** | schema 校验 |
| `commands/audit_lifecycle_contracts.rs` | 854 | **保留** | |
| `commands/build_precheck.rs` | 803 | **保留** | 生态扫描的 buildability |
| `commands/compare_anonymous_pairs.rs` | 657 | **保留** | blind pair gate |
| `commands/materialize_lifecycle_contracts.rs` | 375 | **保留** | |
| `commands/reveal_static_ranking.rs` | 319 | **保留** | |
| `commands/build_failure_taxonomy.rs` | 239 | **保留** | |
| `commands/rank_lifecycle.rs`（v1） | 235 | **冻结** | 仍被 adapter-effort 与 failure-taxonomy 消费，不能直接删 |
| `commands/account_adapter_effort.rs` | 206 | **保留** | Gate D 的人工成本口径 |
| `commands/verify_run.rs` | 228 | **保留** | |
| **`commands/build_lifecycle_graph_v2.rs`** | **217** | **删除候选** | 见 §7 |
| `commands/analyze.rs`、`commands/diff.rs` | 156 | **保留** | |

### 5.4 动态验证栈（`bw-runtime` / `bw-oracle` / `bw-fuzz-observer` / `bw-experiment`，13k）

**全部保留，但角色统一降级。**

这一栈当初是按「它就是 oracle」建的。新路线明确：

> 本项目自有的 runtime/oracle 可以记录语义事件并帮助定位，但**不能单独构成最终 UB 证据**，否则形成「自己生成事件、再由自己确认事件」的循环论证。

因此：

| 组件 | 新角色 |
| --- | --- |
| `bw-runtime` | 辅助定位。记录事件用于诊断，**不进入证据链顶层** |
| `bw-oracle` | contract finding 与 protocol 确认。按 [research thesis §12](../project/research-thesis.md) 的分级，止于 `protocol/path confirmation` |
| `bw-fuzz-observer` | 保留，服务受控搜索 |
| `bw-experiment` | 保留。运行编排、checksum、对照矩阵、最小化，Gate B 全部需要 |

**主证据链换成 sanitizer。** 这个转变必须在代码里体现——P4 的 executor 要以 sanitizer 输出为判定输入，runtime trace 只作附加记录。否则实现会不自觉地又走回自证。

### 5.5 `crates/bw-blind-*`（12.2k）

**全部保留，与研究路线正交。**

它实现的是 [research thesis §7.5](../project/research-thesis.md) 的数据隔离与 [Gate D](../roadmap/milestone-gates.md) 的 sealed holdout：pack / reveal / run snapshot / audit / isolation / output scan / provenance。新路线对数据隔离的要求只增不减。

不在当前阶段推进，但**不冻结**——Gate D 前必须可用。

### 5.6 `contracts/` 与 `schemas/`

**`contracts/callback-retention/`：保留并扩展。**

API map 已经带 `callback_arg_indices` 与 `user_data_arg_indices`——`HandOffId` 需要的参数角色数据**已经存在**，只是放在 contract 而不是 fact 里。搬过去是接线，不是新能力。

需要新增的字段：**外部符号名**。当前 `callback_family = "sqlite_update_hook"` 是语义分组，不是链接符号，P1/P2 无法直接用它定位 IR。

**`schemas/`：一次性升版（D2）。**

现有四个版本目录：`v3-2/`（8 个）、`v3-2-5/`（2 个）、`v3-2-6/`（11 个）、`v3-2-7/`（1 个）。升版有先例，机制成熟。

### 5.7 `tools/`

| 路径 | 处置 | 说明 |
| --- | --- | --- |
| `tools/experiment/run-scan.sh` | **保留 + 新增旁路** | 见下 |
| `tools/experiment/materialize_corpus.py` | **保留** | PP 探针的语料准备 |
| `tools/experiment/run-witness.sh` | **随 D3 重构** | |
| `tools/experiment/run-d0/d1/d2*.sh`、`verify-*` | **保留** | 实验编排 |
| `tools/repository/`、`tools/blind/`、`tools/deploy/`、`tools/containers/`、`tools/toolchain/` | **保留** | 治理与部署 |
| `tools/remote/` | **未跟踪，披露判断未决** | 硬编码主机名与私有路径，是否进公开仓库需单独决定 |

**`run-scan.sh` 的旁路是 PP 的前置。** 当前 `run-scan.sh:174` 在找不到任何 API map 时直接失败——那是整条流水线的要求。但 PP 探针要跑 300–500 个没有 API map 的 crate，而 `bw extract-static-facts` **本身不需要 API map**（`callback_lifetime_bounds` 在 `mir.rs:201` 被调用，不经过 contract）。

所以 PP 需要的是一个**批量驱动器**：语料准备 → 逐 crate 调 `bw extract-static-facts` → 按 [prey-existence-probe runbook](../experiments/runbooks/prey-existence-probe.md) 的判据统计。**几百行，不改流水线。**

## 6. 三个具名决定

### D1 — 冻结 returned-borrow 维度

**决定**：`returned_borrow` 相关的 225 个函数、3 个 `StaticFact` 变体（`ReturnedBorrowRelation`、`PersistedReturnedBorrow`、`ReturnedBorrowInvalidationOrder`）及其模型、schema、测试**全部保留，不删除**；同时**不再新增投入**。

**允许**：保持编译通过的最小修改；已知 bug 的修复。

**禁止**：新增覆盖形状；新增 fact 种类；在论文、README 或对外材料中作为贡献陈述。

**理由**：

1. 它是**非跨界**维度——`fn prepare<'a>(&mut self, conn: &'a Connection) -> Result<Statement<'a>>` 这类判定完全在 Rust 内部，与边界另一侧无关；
2. 它与 Yuga **直接重叠**，[scope-and-boundaries](../project/scope-and-boundaries.md) 已记为「不作创新点」；
3. 它是代码库中最大的单块投入（mir.rs 中 1121 次出现），不冻结会持续吸走维护精力；
4. 删除的代价大于收益：代码能跑、有测试，未来扩维时可能回来。

**为什么必须写下来**：这是本文中最容易随时间漂移的一条。代码规模本身会产生引力——遇到它的 bug 会想修，修着修着会想扩，扩完会想写进论文。

**复核方式**：任何触及 `returned_borrow` 的改动，PR 描述必须说明它属于「保持编译通过」还是「已知 bug 修复」。

### D2 — 一次性 schema 升版

**决定**：把以下三项合并为**一次** schema 版本升级，不分三次做：

1. `HandOffId` 进入事实与判定记录；
2. 判定枚举改为三态 `SupportedIncompatibility` / `CompatibleWithinAnalyzedFragment` / `InsufficientEvidence`；
3. 新增 `ForeignBehaviorFact` 与外部侧证据引用。

**理由**：改判定枚举会动 `schemas/v3-2-6/` 下 11 个 schema 及其 roundtrip 测试。分三次做要付三次迁移、三次 golden 更新、三次消费方对齐的代价，而三项在时间上必然相邻。

**前置**：升版前必须先完成 P0 的设计（`HandOffId` 字段定稿）与 P1 的外部侧事实形状（`ForeignBehaviorFact` 的 evidence 引用格式）。**在这两项定稿前不要动 schema。**

**纪律**：模型与 schema 必须双向比对。`V326LifecycleFactKind::ALL` + `schema_token()` 那套穷尽匹配的测试必须覆盖新字段——逐条手写断言会漏，这在本项目已经发生过。

### D3 — 重写 `generate_witness_harness.rs` 的产出目标

**决定**：保留其**推导逻辑**，重写其**产出目标**。

**当前形态与新路线的冲突**（`crates/bw-cli/src/commands/generate_witness_harness.rs`，1266 行，44 处提到 `rusqlite`）：

| 现状 | 冲突的 Gate B 判据 |
| --- | --- |
| `SUPPORTED_APIS: [&str; 4]`，写死四个 API（公告有 7 个函数） | 「必须手写每个 crate 的专用 harness」 |
| `render_scalar_function_main` / `render_update_hook_main` 是两段硬编码的 Rust 源码模板 | 同上 |
| 生成的 `Cargo.toml` 写死 `rusqlite-lab-shared` 与 `[patch.crates-io]` 指向 vendored 0.26.1 | 同上 |
| 生成的 harness 依赖 `bw-runtime`，产出我们自己的 trace | 「只能产生 contract trace」「结果依赖 synthetic 桥接才成立」 |
| 生成物没有 `#![forbid(unsafe_code)]` | C1 的合格反证第一条 |

它自己的注释已经说清了产物的性质：

> harness 只重放序列并产出 runtime trace，判定由 oracle 做；重放成功本身不是结论。

**必须保留的部分**：同一文件的另一段注释记录了正确的做法——

> 序列不是写死的剧本：`drop(owner)` 只有在候选确实被观察到「owner 在 callback 仍注册期间释放」时才生成，callback 里对该对象的使用同理。固定剧本无条件制造这两步，跑出的违规是剧本自带的，与被扫 crate 无关。

**这个推导方向就是 C1 的种子，必须保留。** 要换的是产出目标，不是这条纪律。

**重写方向**：

| 从 | 到 |
| --- | --- |
| 每 API 一段硬编码 Rust 源码模板 | 声明式 adapter + 由判定结果自动推导的动作序列 |
| 产出 runtime trace | 产出 `#![forbid(unsafe_code)]` 客户端 + sanitizer 判定 |
| `[patch.crates-io]` 指向单一 vendored 版本 | pinned 依赖绑定 P1 使用的同一外部 artifact hash |
| 拒绝理由用于 triage | 拒绝理由进入 Gate B 的失败原因分类统计 |

**adapter 边界**（Gate B 的核心判据，[implementation plan 的 P4](../roadmap/implementation-plan.md#p4-反证合成与执行) 已定义）：adapter 只描述如何合法使用 API，不得包含任何与缺陷相关的信息，且必须在该 crate 的判定跑出来之前冻结并记录时间戳。

## 7. 删除清单

**删除前必须先跑验证命令。** 本文给出的是删除**候选**，不是已确认可删。

### 7.1 `commands/build_lifecycle_graph_v2.rs`（217 行）

**证据**：`tools/experiment/run-scan.sh` 调用的 stage 中**没有** `build-lifecycle-graph-v2`——流水线只跑 `build-lifecycle-graph-v3`。该命令的全部引用是：自身文件、`commands/mod.rs` 的注册（两处）、`tests/lifecycle_v326_cli.rs:968`、`tests/help.rs:20`、`docs/reference/cli.md:69`。

**这是 CLI 注册与关键路径已经分叉的一个实例**：命令存在、被测试、被文档记录，但没有任何生产者或消费者。

**验证命令**：

```bash
grep -rn 'build-lifecycle-graph-v2\|BuildLifecycleGraphV2' \
  --include=*.sh --include=*.rs --include=*.py --include=*.json --include=*.md .
```

确认结果只剩上述五处后方可删除。连带处理：`mod.rs` 注册、两个测试、`docs/reference/cli.md` 表格行。

**注意**：`V326LifecycleGraphRecord`（`lifecycle_v326.rs:150`）是 graph-v2 的记录类型，与 graph-v3 的 `V326LifecycleGraphV3Record`（`lifecycle_v326.rs:1204`）是两个类型。删除命令后需单独确认该记录类型是否还有其他生产者，**不确认不要连带删除模型**。

### 7.2 不在删除清单上的东西

以下**明确不删**，避免执行时误伤：

| 项 | 为什么不删 |
| --- | --- |
| `commands/rank_lifecycle.rs`（v1） | `run-scan.sh` 仍在跑它——`account-adapter-effort` 与 `build-failure-taxonomy` 消费 legacy ranked candidate schema。冻结，不删 |
| `src/lifecycle.rs`（V3.2 模型） | 同上，是 v1 ranking 的模型层 |
| `V32*` 类型 | 「V32」是 schema 代号不是 legacy 标记。`V32CandidateRecord` 是当前活跃的候选类型，被 12 个命令使用 |
| `schemas/v3-2/`、`schemas/v3-2-5/` | 仍被 `schema_roundtrip.rs` 与 `fixture_samples.rs` 消费，且历史 run 记录绑定这些版本 |
| returned-borrow 全族 | D1：冻结不删 |
| `bw-blind-*` | Gate D 需要 |

## 8. 新建清单

见 [implementation plan](../roadmap/implementation-plan.md) 的完整定义，此处只列代码落点。

| 新建 | 落点 | 服务 |
| --- | --- | --- |
| PP 批量驱动器 | `tools/experiment/` 新增脚本 | Gate P |
| `HandOffId` 与三层事实 | `crates/bw-model/src/id.rs`、`static_fact.rs`；`compiler/bw-rustc/src/site.rs` 扩展 | P0 |
| 外部符号记录 | `compiler/bw-rustc/src/registration.rs`、`crates/bw-model/src/contract.rs`、API map TOML | P0 |
| 外部侧 IR 分析（Q1/Q3/Q4′） | **新 crate** | P1/P2 |
| 关系判定器 | `crates/bw-model/src/lifecycle_v326.rs` + 新 CLI 命令 | P3 |
| 声明式 adapter 与反证生成器 | `generate_witness_harness.rs` 重写 + adapter 格式定义 | P4 |

**外部侧分析建议新开 crate 而不是塞进 `bw-cli`。** 它有独立的工具链依赖（LLVM/clang），与 `bw-rustc` 的 nightly 工具链和 workspace 的 1.97.0 都不同；混进现有 crate 会把三套工具链纠缠在一起，而 [server-b 的缓存分离](vps-local-workflow.md)正是为避免这种纠缠建立的。

## 9. 执行顺序

2026-07-31 复审后调整：**关系正确性排到最前**，猎物探针相应后移。

| 步 | 事项 | 依赖 | 规模 |
| --- | --- | --- | ---: |
| 1 | 删除 `build_lifecycle_graph_v2`（先跑 §7.1 验证） | 无 | 小 |
| 2 | **PF：核心关系 + 四个 matched fixture（Gate R）** | 无。外部侧用手写 C stub | 中 |
| 3 | PC：`EffectiveCaptureAdmission` | 无，可与 2 并行 | 中 |
| 4 | PP 批量驱动器 | 3 | 小 |
| 5 | **跑 Gate P** | 4 | 实验 |
| 6 | `SiteDescriptor` 扩展 + 外部符号记录 | Gate P 通过 | 中 |
| 7 | 外部侧新 crate 的 Q1 骨架 + Q4′ | 6 | 大 |
| 8 | 一次性 schema 升版（D2） | 6、7 定稿 | 中 |
| 9 | Q3 降级版 + 关系判定器 | 8 | 大 |
| 10 | 反证生成器重写（D3） | 9 | 大 |

**两条硬约束：**

- **第 2 步之前不要做第 6 步及以后。** 关系错了，后面所有实现都在实现错的判据。
- **第 5 步之前不要做第 6 步及以后。** Gate P 的结论可能是「转路线 C」，那样第 6 步之后的全部工作都不该发生。

第 1 步不受任何 gate 影响，可以随时做。

## 10. 本次审计明确不做的事

- **不做全局重构。** 最大最贵的资产（编译器 Rust 侧）在新路线中价值上升；身份模型是 builder，加字段不动既有调用点；外部侧是 0 行，属纯新增；30k 行测试资产会被重构大批作废，而这些测试正是「非空性检查」纪律的载体。
- **不做「先清理再干活」。** 除 §7.1 一项外，不在推进 Gate P 之前做清理。
- **不删除任何有测试覆盖且能跑的能力**，除非确认无消费方。
- **不为了统一而合并 v1/v2/v3 三代 ranking 链**。它们服务不同消费者，合并的收益不抵风险。

## 11. 复核方式

本文的处置是否被执行，用以下方式检查：

| 决定 | 复核 |
| --- | --- |
| D1 | `git log -- compiler/bw-rustc/src/rustc_api/mir.rs` 中触及 returned-borrow 的提交，是否都能归入「保持编译通过」或「已知 bug 修复」 |
| D2 | schema 版本目录数量：升版后应为五个，不是七个 |
| D3 | 生成的 harness 是否包含 `#![forbid(unsafe_code)]`，是否仍依赖 `bw-runtime` |
| §7.1 | `build_lifecycle_graph_v2.rs` 是否已删除，且 `cli.md` 表格同步 |
| 整体 | [current status](../project/current-status.md) 的状态表是否与实际一致 |

## 12. 相关文档

- 方向权威：[research thesis](../project/research-thesis.md)
- 阶段划分与完成谓词：[implementation plan](../roadmap/implementation-plan.md)
- 研究与工程 gate：[milestone gates](../roadmap/milestone-gates.md)
- 当前所处阶段：[current work](../roadmap/current-work.md)
- 能力边界：[scope and boundaries](../project/scope-and-boundaries.md)
- 目录职责：[repository layout](repository-layout.md)
