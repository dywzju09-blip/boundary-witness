# 编译器分析架构

`bw-rustc` 是 rustc wrapper。未设置 `BW_RUSTC_CONFIG` 时它透传真实 rustc；配置命中 allowlist 后，在 `after_analysis` 中读取 HIR/MIR，输出中性 `bw.static/0.2` facts 和 MIR coverage。它不直接产生 candidate score 或漏洞结论。

## 执行与输出

1. [`main.rs`](../../compiler/bw-rustc/src/main.rs) 解析 wrapper argv、加载 [`config.rs`](../../compiler/bw-rustc/src/config.rs) 并决定透传或分析。
2. [`rustc_api/mod.rs`](../../compiler/bw-rustc/src/rustc_api/mod.rs) 在 `after_analysis` 调用 capture 与 MIR collector。
3. [`domain.rs`](../../compiler/bw-rustc/src/domain.rs) 将 observation 转为稳定 `StaticFactEnvelope`，按 artifact 分片并汇总为 `static-facts.jsonl`/manifest。
4. [`coverage.rs`](../../compiler/bw-rustc/src/coverage.rs) 合并 expected/seen package、target、body 与 skipped 原因，写入 `mir-coverage.json`。

上层 [`extract_static_facts.rs`](../../crates/bw-cli/src/commands/extract_static_facts.rs) 负责 Cargo metadata、feature profile、wrapper 环境、日志、状态统计与 checksum。构建失败、wrapper 失败和 coverage 缺失均是显式状态，不能解释为“没有风险”。

## 分析面

### MIR 提取

[`rustc_api/mir.rs`](../../compiler/bw-rustc/src/rustc_api/mir.rs) 遍历本 crate MIR body，识别 drop/drop prevention、raw pointer transfer、registration/release、returned borrow、external buffer、atomic ordering、storage mutation 与 `ObjectFlow`。控制流证明使用 basic block/path 覆盖，例如 release post-dominance；源码行先后本身不构成 ordering proof。

### API map 与 Contract 接入

[`config.rs`](../../compiler/bw-rustc/src/config.rs) 支持内联或带 SHA-256/manifest 的 callback-retention API map registry，以及 collection lookup contract registry。API map 提供 callback/userdata 参数位置、contract API role、family 与 opaque metadata；配置加载时调用 model validator。当前 registry 仍不是所有组件无需改 compiler 即可扩展的统一语义注册层。

### callback / userdata

[`registration.rs`](../../compiler/bw-rustc/src/registration.rs) 解释 register/unregister/replace 与已审计 API mapping；MIR collector 回溯 callback operand、raw userdata、`Box`/`Arc`/`Rc` raw transfer、foreign destructor、owner reconstruction 和 release path。生成的 `RegistrationSiteFact`、`CallbackUserDataReconstructionFact`、`ReleasePathProofFact` 与 `CallbackReleaseUseOrderFact` 仍要共享精确 object/site identity 才能组成强链。

### closure capture

[`rustc_api/captures.rs`](../../compiler/bw-rustc/src/rustc_api/captures.rs) 从 HIR/typeck 收集 capture mode、capture ordinal、source span 与有限 field projection。MIR use-side 为 closure body 产生对应 `FieldLoad`。capture slot 与 use slot 不一致、复杂 deref/index/downcast 或缺少 closure-body use 时，只能保留部分链或 binding gap。

### opaque handle

opaque set/get 必须由 API map 声明结构化 `opaque_generation_key`。set identity 包含 binding API、handle arg、key arg、payload arg；get identity包含 binding API、handle arg、key arg。MIR 以 handle/slot/payload lineage 生成 `WrapperMove`/`WrapperDestructure` 等 `ObjectFlow`。同 slot key 但不同 handle 不得合并。

### returned borrow

collector 产生 `ReturnedBorrowRelationFact`、`PersistedReturnedBorrowFact` 与 `ReturnedBorrowInvalidationOrderFact`，覆盖直接返回借用、未约束返回 lifetime、字段/集合持久化、owner invalidation 与后续 use 的受支持形状。collection key/index 只有在精确、静态可判定时才能连接；动态 key、范围索引或多来源合流会退回缺证。

### external buffer

`ExternalBufferBindingFact` 只记录 Rust source 与外部 buffer/handle 的静态绑定。它能支持 identity transport，不能自行证明 owner invalidation、use ordering 或完整风险链。

### mutation / reassignment barrier

field、aggregate、place alias、collection/storage 的覆盖或 mutation 会产生 `ObjectBindingGapFact`，kind 为 `mutation_barrier` 或 `reassignment_barrier`。graph 按 binding key 阻断受影响链；barrier 不应把无关 candidate 或整个 crate 一并降级。

调用边界上的绑定丢失记为 `call_boundary`：callee 已被证明是注册 helper 且 userdata 参数下标已知，但调用者一侧该实参解析不回被跟踪对象。该缺口的 `adapter` 记录涉及的注册 API，因此可以按注册 API 统计缺口频次，用来决定优先扩展哪个 callee 识别器。跨函数识别器本身仍是按形状手写的，未匹配的形状不产生对象链——记录缺口的目的是让这类覆盖缺失在事实流中可数，而不是把它当成"没有注册"。

### 跨函数 summary

当前存在有限 same-crate summary：registration passthrough、returned-borrow collection entry/value/use/persist/mutation、wrapper field、部分 OpenSSL ex_data 与 callback storage/release 形状。summary 必须保持参数 projection、storage key 和 object lineage；未知 helper 不以名称猜测。

## 已知缺口

- 任意深度跨函数或跨 crate dataflow；
- trait/dyn dispatch、async/coroutine 与复杂循环/CFG 合流；
- 动态 key/index、多来源对象合流、任意堆别名；
- 复杂 deref/downcast、条件 release、复杂 Drop 路径；
- 未经审计的外部 API 对象语义；
- 对任意库形状都适用的完整 contract registry。

这些形状应进入 coverage gap、binding gap、unknown ordering 或 partial chain，而不是用 API 名称、candidate ID 或源码距离补链。

## 代码、契约与测试入口

- 代码：[`compiler/bw-rustc/src/rustc_api/mir.rs`](../../compiler/bw-rustc/src/rustc_api/mir.rs)、[`compiler/bw-rustc/src/rustc_api/captures.rs`](../../compiler/bw-rustc/src/rustc_api/captures.rs)、[`compiler/bw-rustc/src/domain.rs`](../../compiler/bw-rustc/src/domain.rs)、[`compiler/bw-rustc/src/config.rs`](../../compiler/bw-rustc/src/config.rs)。
- Schema/Contract：[`crates/bw-model/src/static_fact.rs`](../../crates/bw-model/src/static_fact.rs)、[`contracts/callback-retention/`](../../contracts/callback-retention/)、[`experiments/schemas/mir-coverage.schema.json`](../../experiments/schemas/mir-coverage.schema.json)。
- 测试：[`compiler/bw-rustc/tests/captures_golden.rs`](../../compiler/bw-rustc/tests/captures_golden.rs)、[`compiler/bw-rustc/tests/mir_sites_golden.rs`](../../compiler/bw-rustc/tests/mir_sites_golden.rs)、[`compiler/bw-rustc/tests/dependency_coverage.rs`](../../compiler/bw-rustc/tests/dependency_coverage.rs)、[`compiler/bw-rustc/tests/wrapper_passthrough.rs`](../../compiler/bw-rustc/tests/wrapper_passthrough.rs)、[`fixtures/compiler/`](../../fixtures/compiler/)。

下游解释见[生命周期对象流](lifecycle-object-flow.md)与[Contract 和 Schema](contracts-and-schemas.md)。
