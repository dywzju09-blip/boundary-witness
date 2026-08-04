# 范围与边界

本文服从 [research thesis](research-thesis.md)，是能力边界与允许表述的权威表述。当前阶段是 **V3.2.x core-effect hardening**。

本文于 2026-07-30 随研究主线重写，2026-07-31 复审后更新判定语义。旧版本的 `Mismatch`/`NoMismatch` 措辞与 `SupportedIncompatibility (weak)` 均已作废，规范枚举见 [research thesis §2.7](research-thesis.md)。

## 1. 扫描对象

**输入是可构建的 Rust 组件（crate + 版本），不是应用程序。**

被判定的缺陷位于组件自身的安全 API 与其外部调用之间。应用代码不是扫描输入；需要触发实例时由反证生成器构造。

外部 feature 门控的代码必须显式启用才可见。FFI 绑定 crate 通常把回调表面放在非默认 feature 后面，默认扫描会完全看不到那部分注册点，并把组件报成没有受支持的边界。**默认 feature 选择是一个真实的选择，不是「没有选择」。**

## 2. 分析片段

第一阶段只支持**外部源码随构建提供、能够取得 LLVM IR** 的 crate（L1）。链接系统库（L2）与仅有二进制（L3）不在片段内。

所有精度、召回与覆盖结论**只在片段内成立**，论文与结果文档必须显式给出片段定义。

## 3. 逐维覆盖状态

维度定义见 [research thesis §4](research-thesis.md)。当前只实例化持有期一维；其余七维是框架的其他实例，属 future work。

| 维度 | Rust 侧契约 | 外部侧行为 | 联结判定 |
| --- | --- | --- | --- |
| 持有期 | **Rust 侧已完成**：`EffectiveCaptureAdmission`、`RegistrationGuard`、`AllocationOwnership` 与 safe-entry lineage 均可从 HIR/MIR 自动产出，并装配成 `RustContractFact` | **未实现**：当前由 API 清单分类出的注册/注销事实**推断**，不是外部代码行为 | 已实现但证据来源为推断；人工版本边界作交叉验证 |
| 别名与可变性 | 未实现 | 未实现 | 未实现 |
| 线程 | 未实现 | 未实现 | 未实现 |
| 重入 | 未实现 | 未实现 | 未实现 |
| 展开 | 未实现 | 未实现 | 未实现 |
| 释放责任 | 部分：所有权交出与回收可从 MIR 观察 | 未实现 | 未实现 |
| 值域不变量 | 未实现 | 未实现 | 未实现 |
| 初始化 | 未实现 | 未实现 | 未实现 |
| 返回借用寿命（非跨界） | 已实现：从 HIR 签名比较输入与输出的 lifetime 参数集合 | 不适用 | 已实现 |

### 这张表的两条推论

**第一，只有持有期与返回借用两维有 Rust 侧判定，且只有前者试图跨界。**

**第二，外部侧一栏全部未实现。** 这是当前与 [research thesis](research-thesis.md) 论题之间最大的差距：论题声称判定需要跨语言联结，而系统目前只有一侧的证据。持有期维度的外部侧那一半是从 API 清单**推断**出来的——清单告诉系统哪个外部符号是注册、哪个是注销，系统据此推断存在一个需显式清除的槽位。这个推断合理，但不是证明。

因此：**接入一个新组件仍然必须先有人手写 API 清单。** 已经不需要人工声明的只有两项：回调 bound 的形状，以及「bound 从哪个版本开始收紧」这条版本边界。

**第三，Rust 侧的契约事实已齐备（2026-08-04）。** 判定关系需要的三个事实——回调 bound 的语义取值、registration guard、回调分配归属——都已实现，加上 safe-entry lineage 作为过滤，可自动装配成 `RustContractFact`。**但这只是关系的一半**：外部侧仍然是零，因此判定仍不成立。

## 4. 判定的三态纪律与三个正交维度

任何判定都必须能区分三种情况，不得合并。规范枚举见 [research thesis §2.7](research-thesis.md)：

- **`SupportedIncompatibility`**：两侧证据共同支持该交出点上的持有期不相容；
- **`CompatibleWithinAnalyzedFragment`**：在明确给出的片段与假设内，未形成该类不相容；
- **`InsufficientEvidence`**：任一侧事实、联结身份或外部行为证据不足。

**静态判定、证据强度、反证状态是三个正交维度**，不得用一个枚举表达：`StaticVerdict` / `EvidenceGrade` / `WitnessStatus`。**`SupportedIncompatibility (weak)` 及任何第四态一律禁止。**

**缺证不是安全。** 没有观察到事实不得解释为不存在问题。查不出外部侧逃逸时必须记 `InsufficientEvidence`。

**反证未触发只能记 `Inconclusive`**，不得记为候选被证伪——有限次动态执行不能证伪一个 may-property。

**`CompatibleWithinAnalyzedFragment` 不表示 API 整体健全**，它只排除本研究定义的回调持有期不相容这一个子问题。

## 4.1 三类生命周期必须分开

见 [research thesis §2.3](research-thesis.md)。**`F: 'static` 只约束回调捕获的 referent，完全不约束回调分配本身。** 把两者合并会把「分配提前释放、外部随后调用悬垂指针」这一整类判成相容。

**guard 不是纯 Rust 侧判据。** registration guard 是否真的保护，取决于其 drop 路径调用的外部函数**是否真的清空了槽位**——那是外部侧问题。没有 Q4′ 就没有「guard 有效」这个结论，只有 `InsufficientEvidence`。

## 5. 候选与结论的分层

- **candidate** 表示待分析位置，不是 finding，不得改名；
- 单侧证据只产出候选。两半齐才构成缺陷候选；
- 静态风险链不是动态反证；静态高分不等同于可触发；
- 工具退出成功、报告措辞或排序位置都不提升证据层级。

完整分级见 [research thesis §12](research-thesis.md) 的主张分级表。

## 6. 动态验证范围

已有 runtime、oracle、实验基础与单一库的 adapter/harness。当前可用于已知动作序列的确定性回放、结构化 API action 的受控搜索、contract finding 与 sanitizer/panic/crash/timeout 的分离、artifact 最小化与独立重放、正负对照。

尚未形成从任意静态候选到自动 harness、executor、receipt 的通用闭环。反证合成（[roadmap](../roadmap/roadmap.md) 的 P4）尚未开始。

**本项目自有的 runtime/oracle 不能单独构成 UB 结论**——否则形成「自己生成事件、再由自己确认事件」的循环论证。最终证据必须来自 sanitizer 或其他独立 oracle。

## 7. 当前允许的表述

- 能在给定组件版本上定位并排序生命周期敏感的静态候选。对回调家族，此表述仅在 API 清单已覆盖的 API 范围内成立；
- 能从签名判定回调 bound 的语义取值（`EffectiveCaptureAdmission`），无需 API 清单；
- 能从签名与 guard 类型的 `Drop` MIR 判定是否存在 registration guard，无需 API 清单。**但只能判出"`Drop` 里调了某个外部函数"这个形状**——那次调用是否真的清空槽位属于外部侧问题（Q4′），因此**不得表述为"能判断 guard 是否有效"**；
- 能从本函数体内的 raw pointer 转移判定回调分配交出后是否仍有 Rust 侧回收路径。**限于本函数体**——指针被别处回收看不到，见 [implementation plan 的 PG-2](../roadmap/implementation-plan.md);
- 能判定交出点是否可从公开的安全入口到达（含经 wrapper/helper 的多跳）。**限于本 crate 的直接调用边**——出现无法解析被调方的调用时整个 crate 降为缺证；
- 能在受控样本上形成可审计的动态验证闭环。

## 8. 当前不允许的表述

- 现有工作检不出本项目的主线缺陷类（**已被 2026-07-31 外部基线否定**，Yuga 能报 5/7）；
- 「不需要人工 API 清单」是本项目的创新点（该主张已撤销，见 [research thesis §11](research-thesis.md)）；
- 能判断 registration guard **是否有效**（只能看到形状，有效性需要 Q4′）；
- 八维错配等价于安全 API 整体健全性；
- 跨语言契约不相容判定已达成（外部侧未实现）；
- 不读 API 清单也能识别回调注册 API；
- `'static` bound 意味着回调分配永远存活（它只约束 referent，见 §4.1）；
- 「无显式 outlives bound」一律等于「不表态」——对泛型 `F: Fn` 它恰恰是**允许捕获借用**；
- 「同一函数内出现 extern 调用」等于已确认的 hand-off（那只是语法共现）；
- 静态 IR 分析给出的 may-effect 等于运行时的实际行为；
- 「反证未触发」等于候选被证伪；
- 「没有看到 escape」等于安全；
- 把针对已披露公告的检出成绩表述为发现能力——公告是度量仪器，其版本边界由人写入；
- 所有 `verified_static_chain` 都是完整风险链；
- 静态高分等同于动态可触发；
- 单次 crash 等同于根因确认；
- 已通过 V3.3、约 100 crate pilot 或 sealed holdout gate；
- 无法证明的对象关系可用名称或启发式补齐；
- 「目前无人做」这类未经限定的绝对新颖性表述。

## 9. 明确的非目标

不做全程序任意深度 points-to；不做外部库的完整语义建模；不把静态候选表述为漏洞确认；不做可利用性评估或 exploit 生成；不为追求「统一框架」并行实现其余七个维度。
