# 阶段 4：两侧联结与静态闭环

- 日期：2026-08-06
- 执行计划：[execution plan](../../roadmap/execution-plan.md) 阶段 4.1–4.5
- 状态：**4.1、4.3、4.4、4.5 完成并在真实产出上跑通；4.2（一次性 schema 升版）未做**

## 1. 身份分层：两侧各持半个键

[ADR-0003](../../decisions/ADR-0003-target-verifier-dataflow-and-identity.md) 要求身份至少
五层。落地时撞上一个绕不开的事实：**`HandOffId` 哪一侧都填不全。**

| 层 | 谁知道 |
| --- | --- |
| 构建产物身份 | 各知道自己那个 artifact |
| 安全入口身份 | 只有 Rust 侧 |
| 静态交出点身份 | 只有 Rust 侧 |
| 符号 + 参数角色 | **两侧都知道——这是唯一的重叠** |
| 槽位 | 只有外部侧 |
| 注册代次 | 只有 Rust 侧 |

阶段 1.4 当时用 `"pending-stage-2"` 之类的占位串把它凑齐。那是假数据：一旦有人拿去
join，得到的是两个不相干事实的组合。

因此改成 `RustHandOffKey` + `ForeignHandOffKey` 两个半键，完整身份**只能由
`join_hand_off` 在校验重叠部分之后合成**。占位串从代码里消失了。

## 2. 补上缺的那把钥匙：外部链接符号

在此之前，**Rust 侧没有任何静态事实携带外部链接符号**。`RegistrationSiteFact` 与
`ExternalCallSiteFact` 记的都是 `api_id`（Rust API 路径），而外部侧 IR 里只有符号。两侧
根本没有共同的键。

新增 `ForeignSymbolBindingFact`，由编译器从 MIR 推导：在交出点所在函数体里找「调用一个
`extern` 块声明的函数、且实参含函数指针」的调用，记下符号与参数角色。

两个实现细节是量出来才知道的：

- **符号取自 `tcx.symbol_name` 而不是读属性。** 这个 nightly 的 `CodegenFnAttrs` 上没有
  `link_name` 字段；`symbol_name` 本来就是链接符号的权威来源，`#[link_name]` 由它处理。
- **回调参数是 `Option<unsafe extern "C" fn(..)>`，不是裸函数指针。** 这是 C 头文件绑定
  的常态（空指针优化）。只判 `is_fn_ptr()` 会把真实 FFI 里绝大多数注册调用全部漏掉。

找到多个外部调用一律 `AmbiguousForeignCalls`，**不挑一个当答案**——ADR-0003 第四条。

## 3. 精确联结（4.3）

`join_hand_off` 逐层校验，任何一层对不上都拒绝，并把**全部**不匹配的层一次列出。
拒绝原因是分类枚举，不合并成「联结失败」：

| 原因 | 挡的是什么 |
| --- | --- |
| `BuildProfileMismatch` | 两侧不是同一次构建 |
| `ForeignSymbolMismatch` | 根本没在谈同一个函数 |
| `CallbackRoleMismatch` / `UserDataRoleMismatch` | 同一符号上多组 callback/userdata 串线 |
| `RegistrationKeyMismatch` | 同一符号上的不同注册槽位 |
| `GenerationUnresolved` | 不知道代次，无法归属证据 |
| `MissingSlotEvidence` | 没有槽位证据，且保留与否也没结论 |

**`NoRetain` 时槽位为空不算缺口**，那是结论而不是缺失——否则负对照永远拿不到答案。

## 4. P3 判定：路径相容性是第五项（4.4）

`JointTraceFeasible` 拆成五项，前四项由联结负责，第五项由判定负责：**保留 store 是不是
在注册入口的每一条会返回的路径上**。

两条 may-property 分别成立不等于它们能在同一条执行上同时发生。保留只落在部分路径上时，
那条路径未必就是能走到晚调的那条；此时给「不相容」就是把联合命题当成了两个独立命题的
合取。因此改为缺证加一条 `EstablishJointTrace` 反证义务。

## 5. 端到端（4.5）

新增 `bw judge-hand-offs`。完整链路在 Gate R 的 fixture crate 上跑通：

```
真实 Rust 源码 ──bw-rustc──→ 44 条静态事实（含 5 条符号绑定）
                              ↓ extract-rust-contracts
                            4 条契约 + 1 条 gap
真实 C 源码 ──clang──→ IR ──extract-foreign-facts──→ 4 个槽位
                              ↓ judge-hand-offs
                            4 条联结 + 8 条判定
```

**Gate R 的判别力在真实流水线上显现**——`Registry::register_guarded` 的 Rust 源码一个
字没变：

| 外部 stub | `CapturedReferent` 判定 | 证据等级 |
| --- | --- | --- |
| `retain_late_invoke_clearing` | `CompatibleWithinAnalyzedFragment` | — |
| `retain_late_invoke_leaky` | `InsufficientEvidence` | `GuardDefeated` |

leaky 那侧停在缺证而不是「不相容」，是因为 Q3 仍是降级的（同槽间接调用候选），带
`EstablishLateInvoke` 义务。这正是设计要的。

## 6. 过程中发现并修掉的一个设计错误

**「同一符号有多个 Rust 注册点」被我当成了「同一槽位上注册 A → 注销 → 注册 B」。**

第一次端到端跑出来 4 条全部被拒，原因 `generation_ambiguous`。查下去发现规则写错了：
fixture crate 的四个 Rust API 都调 `fixture_register`，于是每一条都被判成代次不明。

这是两回事。外部侧的行为结论描述的是**外部函数的代码**，对每个注册点一样成立；安全
客户端也完全可以只调其中一个 API，那时就只有一次注册。真正分不开的是**运行期**的重复
注册，静态看不到，由反证负责。

**照原来那条规则，任何有一个以上注册 API 的真实 crate 都会产出零判定。** 改为
`MultipleStaticSites` 放行并在判定里记一条归属假设，只有 `Unresolved` 才拒绝。

## 7. 这一步证明了什么，没证明什么

**证明了**：

- 从 Rust 源码与外部 IR 到三态判定的静态闭环可以一条命令链跑通；
- 联结的主键由编译器自己推导，不是人工对齐的；
- 身份任何一层对不上都会被拒绝并分类计数；
- fixture 2 与 3 的分离在端到端产出上成立。

**没证明**：

- **4.2 的一次性 schema 升版没做。** 三类记录目前用 `bw.*/0.1` 的进程内版本号，
  `schemas/v3-2-6/` 下还没有对应的 JSON Schema 与 validator。按 D2 的复核判据，升版
  不得新增 schema 目录；
- **参考目标（rusqlite）的 source-to-verdict 还没跑。** 端到端验证用的是 Gate R 的
  fixture crate。rusqlite 侧需要先跑一次带 wrapper 的静态事实抽取；
- **`rust_def_instance` 还不是单态化实例 id**，当前用定义路径。它不参与跨侧匹配（那只看
  符号与参数角色），因此不违反 ADR-0003 第五条，但身份精度未达定稿要求；
- **`registration_key` 恒为 `None`。** 一个符号上多个注册槽位的情况还没有产出方。
