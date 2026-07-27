# 动态验证架构

动态验证把静态 candidate/witness plan 转换为真实执行观测，但当前尚无面向任意 candidate 的通用 `plan -> harness -> executor -> runtime/oracle -> replay receipt` 闭环。现有 D0/D1/D2、runtime、oracle、adapter 与 blind runner 是可复用基础，不应描述成该闭环已普遍完成。

## D0：确定性回放与对照

D0 对固定案例矩阵执行已知动作序列或 compile check。`D0CaseMatrix` 公开保存 case ID、API、operation、static facts/executable/source、重复次数和 timeout；scenario/expectation 位于独立 [`experiments/ground-truth/d0-cases.toml`](../../experiments/ground-truth/d0-cases.toml)，不进入执行矩阵。

[`d0_runner.rs`](../../crates/bw-experiment/src/d0_runner.rs) 规划 preflight/formal work，运行目标，读取 trace，以 `StaticFactIndex + CallbackRetentionContract + Oracle` 产生 finding，并把 contract finding、ASan、native crash、panic、timeout、invalid input、tool error 分开。D0 适合历史/受控正负对照和确定性回归；它不证明对未知样本的泛化。

## D1：结构化动作搜索

D1 使用 [`FuzzAction`](../../crates/bw-experiment/src/fuzz/actions.rs) 表达 register borrowed/owned、unregister、owner end、SQL trigger、connection close 等 API 动作。campaign 固定 API、target、CPU budget、max sequence、initial corpus、objective policy、sanitizer、replay count 与 seed。primary/progress/secondary objective 分离，artifact 需最小化并重复重放。

### PoC seed 禁止边界

初始 corpus 只能包含安全 fragment。[`CorpusPolicy`](../../crates/bw-experiment/src/fuzz/corpus.rs) 拒绝已经构成完整危险链的 seed，例如 borrowed registration 后 owner end 再触发对应 callback。历史公开 PoC 可以服务 D0 ground truth/replay，但不得复制、改名或编码为 D1 初始 seed。campaign config 也拒绝 CVE、vulnerable、fixed、expected 等标签泄漏。

## D2：同预算基线比较

D2 比较 `random_action`、`coverage_only` 与 `coverage_state`。[`D2SharedBudget`](../../crates/bw-experiment/src/fuzz/d2_compare.rs) **声明** campaign count、CPU minutes、seed list、initial corpus digest、max sequence、objective policy digest、target build 与 sanitizer。当前 `verify_d2_budget_equivalence` 对组配置实际强制的是 CPU minutes、max sequence、seed 属于共享 seed list，以及 coverage 组的 sanitizer 一致；`random_action` 仅在自身声明 sanitizer 时比较该字段。它也校验共享 campaign count 与 seed-list 长度、digest 的 SHA-256 文本形状和非空 target build。加载完成的 campaign records 时，还会检查每组记录数、CPU、seed membership、API 与该组配置的 target。现有记录没有证明实际 initial corpus、objective policy 或 target build 与共享字段中声明的 digest/ID 一致，因此这里的“预算等价”只指上述已强制字段，不能扩展为所有声明字段均已运行时对齐。D2 用于观察 contract-state feedback 相对基线的差异，不是新的漏洞确认层。

## runtime、oracle 与 witness

[`bw-runtime`](../../crates/bw-runtime/) 记录对象、callback、capture、epoch、checkpoint 和 trace 生命周期。[`bw-oracle`](../../crates/bw-oracle/) 校验 trace schema、run/build 一致性和事件状态机，再将 static facts、Contract clause 与 runtime event 融合为 rule-level finding。

dynamic witness 必须是可重复执行的最小输入或动作序列，并保存：

- 固定代码/构建/工具链/容器或主机身份；
- `run_id`、`build_id`、config/Contract/corpus checksum；
- trace、finding、独立 outcome 与最小 artifact digest；
- replay attempts/successes；
- fixed/safe/unregister/no-trigger 等负对照。

**动态 witness 不能替代 oracle。** witness 证明某动作序列可重放；oracle/规则与独立 sanitizer/UB 观测解释事件是否违反 Contract。反过来，oracle finding 也不能替代 witness 的真实重放、环境与负对照。crash 更不能单独确定对象、顺序和根因。

## ground truth 隔离

oracle engine 与 oracle ground truth 必须分开：前者参与运行分析，后者只在运行完成后评估预期。blind public manifest 不含 private label；runner 只产 observation 与 receipt；curator 在 method commit、policy、manifest 与 output checksum 对齐后 reveal。任何 CVE、patch、PoC、expected root cause 或 vulnerable/fixed 标签都不得进入 detector、ranking、search/objective 或 seed。

## 本地大规模运行与 VPS smoke

- **VPS smoke**：验证打包、安装、依赖、容器/namespace 隔离、命令可执行、少量 case timeout、结果同步与 receipt/checksum；只证明部署链可工作。
- **本地或受控大规模运行**：执行完整 campaign/repetition、保留 artifacts/logs/traces、最小化和重放，形成统计与负对照；结果必须绑定实际环境和 run manifest。

VPS smoke 不能替代正式预算运行，本地一次成功也不能替代跨环境部署检查。两者都不能跳过 blind/ground-truth 隔离。

## 当前缺口与状态

- witness plan 到通用 harness 选择/生成、Miri/fuzz/runtime/oracle 和 receipt 的自动桥尚未完成；
- `bw-experiment` 完整测试当前因公开工作树缺少 ASan parser fixture 而受阻，不能把整个 crate 写成已完整验证；
- 当前工作树没有与最新 commit、数据 manifest、Contract/config checksum 对齐的正式 public regression、约 100-crate pilot 或新 sealed holdout 记录；
- 因此 V3.3 gate 未通过。

## 代码、契约与测试入口

- 代码：[`crates/bw-experiment/src/d0_runner.rs`](../../crates/bw-experiment/src/d0_runner.rs)、[`crates/bw-experiment/src/fuzz/`](../../crates/bw-experiment/src/fuzz/)、[`crates/bw-runtime/src/`](../../crates/bw-runtime/src/)、[`crates/bw-oracle/src/`](../../crates/bw-oracle/src/)、[`crates/bw-blind-runner/src/`](../../crates/bw-blind-runner/src/)。
- Schema/Contract：[`experiments/configs/`](../../experiments/configs/)、[`experiments/schemas/`](../../experiments/schemas/)、[`contracts/callback-retention/contract.toml`](../../contracts/callback-retention/contract.toml)、[`schemas/v3-2-6/witness-plan.schema.json`](../../schemas/v3-2-6/witness-plan.schema.json)。
- 测试：[`crates/bw-experiment/tests/d0_runner.rs`](../../crates/bw-experiment/tests/d0_runner.rs)、[`crates/bw-experiment/tests/d1_action_model.rs`](../../crates/bw-experiment/tests/d1_action_model.rs)、[`crates/bw-experiment/tests/d1_artifact_replay.rs`](../../crates/bw-experiment/tests/d1_artifact_replay.rs)、[`crates/bw-experiment/tests/d2_budget_equivalence.rs`](../../crates/bw-experiment/tests/d2_budget_equivalence.rs)、[`crates/bw-runtime/tests/`](../../crates/bw-runtime/tests/)、[`crates/bw-oracle/tests/`](../../crates/bw-oracle/tests/)、[`tests/containers/d0-image-smoke.sh`](../../tests/containers/d0-image-smoke.sh)。

公开措辞与 reveal 规则见[排序与报告](ranking-and-reporting.md)，项目阶段见[当前状态](../project/current-status.md)。
