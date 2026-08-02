# 执行计划

**本文是执行顺序的唯一权威。** 后续所有实现按本文推进；[roadmap](roadmap.md) 描述每个阶段是什么，[implementation plan](implementation-plan.md) 给出每个阶段的技术细节，[current work](current-work.md) 只说现在在哪一步。四份文档必须表达同一张依赖图，冲突时以本文的顺序为准。

方向权威仍是 [research thesis](../project/research-thesis.md)：**任何一步如果不能落到 C1/C2/C3 之一，就不该做。**

本文用通俗语言写，每一步都写清**这步做出什么功能**——不是"改哪个文件"，而是"做完之后系统多了什么能力"。

---

## 怎么读这份计划

### 三种依赖，不要混

同一个"依赖"在本项目里有三种完全不同的强度，混起来会让人要么过早动手、要么无谓等待：

| 依赖类型 | 含义 | 例子 |
| --- | --- | --- |
| **可以开始**（start） | 前置没做完也能开工，因为这一步的内核不碰前置的产物 | Q1 的 IR 传播算法可以在身份模型定稿前就写 |
| **可以宣称完成**（integration） | 前置没做完就不能说这一步做完了 | Q1 端到端完成必须等身份模型，否则它的产物接不进判定 |
| **可以正式跑实验**（formal-run） | 前置没冻结就不能出正式实验数字 | 任何正式运行都要等 schema、生产方、消费方、校验器和 artifact 对齐全部冻结 |

下面每一步都标了它对上游是哪种依赖。**只有 formal-run 依赖没满足时，跑出来的数字才是无效的**；start 依赖没满足只是意味着还不能收工。

### 状态词

`Implemented` = 代码在、测试过；`Verified` = 有与当前 commit 对齐的正式运行记录；`Planned` = 设计明确但没实现；`Blocked` = 有明确的前置 gate。**目前全项目没有任何 `Verified` 条目。**

---

## 现在在哪

```text
✅ 阶段 0 部分完成
   ├─ PF 关系与四 fixture（Gate R 通过）        Implemented
   ├─ PC EffectiveCaptureAdmission              Implemented
   ├─ PG-1 RegistrationGuard                    Implemented
   └─ 文档一致性对齐                            本次提交
⬜ 阶段 0 剩余：PG-2、Tier A 判据修正、PP 驱动器、统计协议预注册、相关工作核实
⬜ 阶段 1：Gate P（止损点，由维护者执行）
⬜ 阶段 2 及以后：全部 Planned，且**只有 Gate P 通过才启动**
```

**三条创新点目前一条都没成立。** Rust 侧三个事实做完两个，外部侧零行代码。

---

## 阶段 0：把地基铺平（进行中，不被任何 gate 阻塞）

这一阶段的共同点是：**都不依赖外部侧，且即使 Gate P 判定转路线 C 也不浪费**——因为路线 C（经验研究）同样需要这些事实和这套统计口径。

### 0.1 文档一致性对齐 ✅ 本次提交

**做出什么功能**：让下一个接手的人读到的状态是真的。此前 `current-work.md` 开头说"PF/PC 均未开始"，而同一文件后面写着"已完成 PF / PC"；`current-status.md` 说"当前最高优先级是 PC"，而 PC 已经做完了。按这些描述开工会重复劳动或按错误依赖动手。

同时把判定语义里几个会导致错误实现的缺口补上，见[阶段 0 的语义决定](#阶段-0-一并落定的语义决定)。

### 0.2 PG-2 `AllocationOwnership`（下一步）

**做出什么功能**：让系统能回答"回调分配（`Box<F>`）交出去之后归谁"。

现在系统只能看出"回调**借了**什么"，看不出"装回调的那块内存还活着没有"。这两件事被 `'static` 分开：`F: 'static` 保证闭包没捕获借用，**对 `Box<F>` 本身的存活完全不表态**。缺了这个事实，「Rust wrapper 交出指针后立刻回收、外部随后调用悬垂指针」这一整类问题系统看不见——Gate R 的 fixture 4 就是这一类。

**原材料已经在产出**（PG-1 期间实测确认）：同一个 fixture 上，`register_static_then_free` 产出 `RawPointerTransfer{IntoRaw}` + `RawPointerTransfer{FromRaw}` + `DropSite{Explicit}`，而只差一行 `Box::from_raw` 的 `register_static_owned` 只产出 `IntoRaw`。差别在事实层已经可见，要做的是按交出点聚合再加一层分类。

- **依赖**：无
- **完成谓词**：四个 fixture 函数的取值与手写的那组逐字段一致；解析不出释放路径时落 `Unresolved`，不落"外部拥有"
- **非空性检查**：去掉"注册后存在 `FromRaw` 释放路径"这一条，确认 `register_static_then_free` 从 `RustRetainsAndMayFreeEarly` 落回 `ForeignOwnedUntilUnregister`，且 fixture 4 判定随之翻转

### 0.3 Tier A 判据修正 + 猎物探针驱动器

**做出什么功能**：让 Gate P 数出来的候选数**是可信的**，并且能在几百个 crate 上批量跑。

Tier A 是 Gate P 唯一的判据，但当前定义有**三个已知的计数错误**，不修就跑等于用一把没校准的尺子做止损决策：

| 问题 | 后果 | 修法 |
| --- | --- | --- |
| 事实层不记录该 API 是不是 `unsafe fn` | Tier A 第一条是"是安全 API"，但事实层过滤不掉。实测：fixture 里的 `unsafe extern "C" fn trampoline<F: FnMut()>` 也产出了 callback bound 事实 | 给 callback bound 事实加 `is_unsafe_fn`（`Planned`） |
| 只要求"回调到达 extern 参数"，不要求这个交出点能被 public safe API 到达 | 藏在内部 helper 里、安全客户端根本够不着的交出点也被计入。而整个立论是"**安全 API** 允许 UB" | Tier A 增加 safe-entry lineage 一条，见 [research thesis §2.2](../project/research-thesis.md) |
| 判据 `EffectiveCaptureAdmission = PermitsNonStaticCapture` 只筛 referent 类 | **allocation 类（`'static` bound + 分配提前释放）的取值恰恰是 `RequiresStaticCapture`，会被直接排除。** Gate P 因此只测了一半，而 No-Go 会连带杀掉从没被测过的另一半 | 拆成 `Tier A-R` 与 `Tier A-A`，见[阶段 1](#阶段-1gate-p猎物存在性止损点) |

驱动器本身：语料准备 → 逐 crate 调静态事实抽取（**不需要 API 清单**）→ 按 runbook 判据统计。几百行，不改现有流水线。

- **依赖**：`start` 依赖 PG-2（Tier A-A 的判据需要分配归属事实）
- **盲化**：默认由独立 runner 只返回盲化聚合统计，crate 身份不经过开发者。**运行前必须完成 family-level sealed split**，否则整个前瞻池按 [§7.6](../project/research-thesis.md) 变成开发集
- **非空性检查**：在已知含该形状的 fixture 上必须命中；把判据反向后必须落空；另需**随机抽审**一部分阳性与候选阴性估 PPV 与漏检率——合成 fixture 只能发现恒空分类器，证明不了生态召回率

### 0.4 Gate P / A / B 的统计协议预注册

**做出什么功能**：让 gate 的判定不能事后移动门槛。

现在 Gate P 写的是"下置信界仍足以支撑预定确认集"，但**没有任何公式**把"候选数"换算成"确认发现数"。这等于没有判据。同类问题在 Gate A（"可解释的增益"）也存在——而文档自己批评过"足够""非平凡"这类事后可移动的措辞。

预注册内容见 [milestone gates](milestone-gates.md)：换算公式、聚类单位、最小效应量、置信界、允许的 Unknown 比例。**必须在看到数据之前写死。**

- **依赖**：无。Gate P 的部分必须在 0.3 跑之前完成；A/B 的部分可以晚一点，但要在对应 gate 之前

### 0.5 相关工作核实

**做出什么功能**：避免论文里出现照抄的、没核实过的相关工作表。

[research thesis §5.1](../project/research-thesis.md) 列了七项待核实工作，其中 **CULPA 标为"与本工作路线最接近，优先核实"**。核实前不得写进论文或对外材料。

- **依赖**：无，可随时做

### 阶段 0 一并落定的语义决定

这几条不改代码，但**决定后面所有实现的形状**，所以放在最前面：

| 决定 | 解决什么问题 |
| --- | --- |
| **联合轨迹语义** | 两个 may-property 分别成立，不等于能同时发生。判定必须要求两侧在同一构建、同一交出点、同一槽位、同一 registration generation 且路径条件相容下形成**联合轨迹**；静态证不出就是 `InsufficientEvidence` |
| **外部证据拆成正交字段** | 现在 `EvidenceGrade` 把"槽位保留""晚调可达性""清槽状态""路径相容性"压成一个枚举，实测会互相覆盖丢信息 |
| **Q3 → P4 接口** | 降级 Q3 永远输出 `InsufficientEvidence`，而反证合成的输入被写成"从一条不相容出发"——首期实现里反证阶段**没有合法输入**，是计划里的死锁 |
| **C2 措辞修正** | 规约来源不只是类型签名，还包括 guard 协议与 wrapper 所有权效果（分配归属就是从 MIR 的所有权转移读出来的，不是从签名） |
| **RoleMap 信任边界** | 人工 API 清单只能声明符号绑定与参数角色，**不得预先写死待验证的外部行为**（实际保留、实际晚调、所有路径清槽、guard 是否有效） |

规范定义见 [research thesis §2](../project/research-thesis.md) 与 [terminology](../project/terminology.md)；目标数据结构见 [target verifier pipeline](../architecture/target-verifier-pipeline.md)（全部 `Planned`）。

---

## 阶段 1：Gate P 猎物存在性（止损点）

**做出什么功能**：回答"这条研究路线还值不值得做"。

这一缺陷类在 Rust 社区是公开知识，`'static` 的修法众所周知，很多维护者早就收紧了 bound。**如果生态里已经没有足够的猎物，路线 A 不成立**，该转路线 C 做经验研究，而不是先花几个月写外部侧分析再发现无猎可打。成本约为外部侧实现的百分之一。

**执行归属：由维护者执行。** 由谁执行不改变判据。

### 拆成两个子 gate

单靠"候选数"推不出"能确认几个新发现"，中间隔着一个转化率。所以拆开：

| 子 gate | 问题 | 判据 |
| --- | --- | --- |
| **Gate P-a** | 未调优、L1 可分析、Tier A 的交出点还有多少 | 候选池规模的**下置信界** |
| **Gate P-b** | 这些候选里有多大比例能真正走到确认 | 在**开发集**上测保守转化率的下界 |

合起来的判定形式：

```text
可用猎物估计 = eligible_pool_lower_bound × conversion_rate_lower_bound
Pass   = 该乘积仍足以支撑预注册的确认集规模
No-Go  = 上置信界仍不足
Amber  = 扩大样本或增加人工审计
```

**必须按 crate / repository / 外部库家族聚类报告**——同一个仓库里的多个 crate、同一个外部库的多个绑定不是独立样本，按 alert 计数会系统性高估。

### R 与 A 分开决策

**Tier A-R**（referent 类）与 **Tier A-A**（allocation 类）分别统计、分别判定。

**如果 A 的探针暂时做不出来**，那就明确写：Gate P 只决定 R 子路线，A 保持 `Unknown` 并单独设 gate。**不得因为 R 的 No-Go 就自动放弃 A**——那是两类不同的缺陷，A 从来没有被测过。

- **失败动作**：R 与 A 都 No-Go → 转路线 C，不再投入外部侧实现
- **纪律**："维护者说猎物不少"不是 Gate P 通过。**没有预注册的正式结果就不能宣称通过。**

---

## 阶段 2：只有 Gate P 通过才启动

**这是本计划最重要的一条硬约束。** Gate P 的结论可能是"转路线 C"，那样阶段 2 及以后的全部工作都不该发生。

四项可并行：

### 2.1 P0a 身份模型与目标数据流

**做出什么功能**：让两侧事实能精确地指向同一次真实交出，而不是靠函数名对齐。

现在所有事实都是单侧的，两侧的连接键是函数名。已经因此出过两次错：候选按边界切分，把同一函数的两半分到不同候选；判定只挂给持有其中一半的候选，另一半读不到结论。

身份要**分层**，不是塞进一个扁平 ID（详见 [target verifier pipeline](../architecture/target-verifier-pipeline.md)）：构建产物 → 安全入口 → 静态交出点 → 符号槽位 → registration generation。其中 **registration generation 是新增的**：同一个槽位上"注册 A → 注销 → 注册 B"是不同的注册实例，现在的身份分不开它们，而 Q4′ 的一个子问题正是"同一槽位是否被多个 registration instance 共享"。

同时把 **candidate 降级为下游展示/调度视图**：

```text
中性事实 → 精确联结 → 判定 → candidate / ranking 投影
```

candidate 不再充当两侧事实的连接主干。

- **依赖**：`formal-run` 依赖 Gate P
- **完成谓词**：两侧事实可在不依赖候选切分的前提下联结；同一调用含多组 callback/userdata 时仍能区分
- **非空性检查**：把联结键改回函数名，确认联结测试失败且落在预期断言

### 2.2 外部 IR 获取 spike

**做出什么功能**：确认"能不能真的拿到与 Rust 侧同配置的外部 LLVM IR"——这是整个外部侧的地基，也是已知风险最高的工程环节。

必须用**该 crate 实际构建产生的**外部对象，同 target、同宏定义、同优化级别。**不得另编一份"相似的 C 源码"代替。**

### 2.3 Gate C0 可移植性 smoke

**做出什么功能**：提前暴露"这套方法只对 sqlite 有效"这个风险。

正式的 Gate C（跨库泛化）推迟到投稿认证期，但把一个已知风险完全推到最后，等于最后才发现只有一个库能跑。C0 是个便宜的早期检查：

- 3–5 个外部库家族，至少两种 C 构建方式；
- 只验证真实 IR 获取、符号解析、artifact 绑定和新库接入成本；
- **若每接一个新库都要改分析器内核，立即收窄 scope 或转路线。**

### 2.4 P4a adapter 规格

**做出什么功能**：把"怎么合法使用这个 API"这件事标准化，并且**在看到判定结果之前冻结**。

adapter 只描述如何合法使用 API——怎么创建前置对象、参数怎么构造、怎么触发一次外部调用。**不得包含任何与缺陷相关的信息**：不写"注册后 drop 该对象"、不写触发顺序、不写预期结果。触发缺陷的动作序列必须由判定结果自动推导。

放在这么早，是因为**冻结时机本身就是 Gate B 的判据**：adapter 必须在该 crate 的判定跑出来之前写好并记录 commit 与时间戳。放到 P4 再写就没法证明它没被结果污染了。

---

## 阶段 3：外部侧行为分析

顺序按判别力排，不按查询编号排。

### 3.1 Q1 槽位与保留身份

**做出什么功能**：认出"外部把这个指针存到了哪个跨调用存活的槽位里"。

**Q1 是前提，不是判别项。** 进入候选集的 API 按定义都带注册语义，Q1 的答案可能几乎恒为真，恒为真的项没有判别力。它的价值是**提供槽位身份**，Q3 与 Q4′ 都建在它上面。不得把 Q1 的产出当作 C2 的机制证据。

- **依赖**：`start` 无（算法内核可与 2.1 并行开写）；`integration` 依赖 2.1 身份模型
- **纪律**：查不出逃逸**不得判安全**，一律 `InsufficientEvidence`
- **止损**：**两三周内看不到端到端结果，贡献结构需要重新设计**

### 3.2 Q4′ 清槽 / 替换（外部侧真正的判别项）

**做出什么功能**：回答"注销到底有没有把槽位清干净"——这是 Rust 侧**永远看不到**的那一半。

Rust 侧只能看到 guard 的 `Drop` 里调了某个外部函数（PG-1 已经能看到这个了）。**那次调用是否真的清空了槽位，只有外部侧能回答。** 所以：

- guard 有效性的结论来自这里。没有 Q4′ 就没有"guard 有效"，只有 `InsufficientEvidence`；
- Gate R 的 fixture 2 与 3 Rust 侧逐字节相同，**唯一差别就是这里**。

**Q4′ 排在完整 Q3 之前**，因为文档自己认定判别力主要在清槽/替换，而 Q1 主要提供槽位身份。

### 3.3 降级 Q3 晚调候选

**做出什么功能**：找出"同一个槽位上存在一个间接调用点"。

完整 Q3 要全库可达性加间接调用 callee 解析（sqlite3 amalgamation 约 25 万行 C），代价高一个数量级。首期降级为"同槽间接调用存在性"。

**降级版证明不了什么，必须写清楚**：它不证明存在一条真实的返回后调用路径，那个调用点可能不可达、可能被路径条件排除、可能读的是同类型的另一个分配。所以它的正确输出是缺证加一条反证义务，**不是弱化的不相容结论**：

```text
StaticVerdict     = InsufficientEvidence
证据字段           = 同槽间接调用候选（不是"已确认晚调"）
WitnessObligation = EstablishLateInvoke
```

**不得输出 `SupportedIncompatibility (weak)` 或任何第四态。**

- **全程保留 Unknown**：unknown callee、IR 不可得、别名不足一律显式进入 coverage 统计

---

## 阶段 4：把两侧接起来

### 4.1 一次性 schema 升版

**做出什么功能**：让新的身份、三态判定和外部侧事实真正落到产物里，可以被下游读取和校验。

分层身份、三态判定枚举、外部侧事实与正交证据字段**合并为一次**版本升级。分三次做要付三次迁移、三次 golden 更新、三次消费方对齐的代价。

- **依赖**：`start` 依赖阶段 2 和 3 的记录形状定稿。**在那之前不要动 schema。**
- **纪律**：模型与 schema 双向比对，穷尽匹配的测试必须同步扩展——逐条手写断言会漏，这在本项目发生过（PG-1 就是被这套机制挡下来的，三处穷尽匹配全部报错）

### 4.2 P3 联合关系判定器

**做出什么功能**：把外部侧证据从"靠 API 清单推断"换成"从外部代码读出来"，并按联合轨迹语义出判定。

判定要求两侧在同一构建、同一交出点、同一槽位、同一 registration generation、路径条件相容下能形成联合轨迹。**分别成立的 may-path 不自动能同时发生**；证不出联合可行性就是 `InsufficientEvidence` 加一条反证义务。

人工版本边界保留作**交叉验证**：两路结论都写进产物，不一致时都保留。

- **依赖**：`integration` 依赖 PG（全部三个 Rust 事实）+ P0 + 阶段 3
- **非空性检查**：把 Q4′ 输出强制为"注销总是清槽"，确认 fixture 3 从不相容翻转为相容——这条同时验证判定器接了 Q4′、也验证 Q4′ 确实在起判别作用

---

## 阶段 5：Gate A1 机制增益

**做出什么功能**：证明"看外部侧"这件事本身带来了 Rust 侧拿不到的判别力。如果证明不了，C2 就不该继续当主创新点。

在**同一个候选全集**上比较 Full 与 Rust-only：Full 能区分"注销真清槽"与"注销没清干净"，Rust-only 只能 abstain。

**必须预先定义**：比较单位、最小效应量、置信界下界、允许的 Unknown 比例。不能只写"有可解释的增益"。

**增益必须可归因到 role/slot 敏感的外部证据（主要是 Q4′）**，不能只归因到"候选范围更窄了"。已知一处边界：回调分配的归属是**纯 Rust 侧事实**，Rust-only 就能正确判相容——外部证据的净贡献集中在 guard 分支，Gate A 的增益必须归到那里。

- **失败动作**：转路线 B（以反证合成为主，外部分析只服务触发规划）

---

## 阶段 6：P4b 反证合成 → Gate B

**做出什么功能**：把"可能不健全"变成"已证明不健全"——自动写出一段纯 safe 的客户端，让外部组件在对象失效之后真的回调进来，由独立 oracle 出证。**这是 C1，首要创新点。**

反证的动作序列由判定结果反推：创建有限生命周期对象 → 构造借用它的回调 → 通过目标安全 API 注册 → 让对象生命周期结束 → 保持外部注册存活 → 触发外部组件稍后调用 → 回调实际读写失效对象 → 收集独立 UB 证据。

### 输入接口（解掉那个死锁）

反证阶段可以消费两种输入：

1. `SupportedIncompatibility`；
2. **`InsufficientEvidence` + `EstablishLateInvoke` 义务**，前提是 Rust 侧分离性、Q1、Q4′ 和身份都已充分——缺的只是晚调可达性。

第 2 种是首期实现的主要输入。动态成功写入 `WitnessStatus = ConfirmedCounterexample`，**但不静默改变原有的静态判定语义**。

### oracle admissibility

三类缺陷需要**不同的**可接受 oracle，不能一把 ASan 打天下：

| 缺陷类 | 典型现象 | 需要的观测 |
| --- | --- | --- |
| referent 失效后被访问 | stack-use-after-scope | 栈对象失效检测 |
| allocation 提前释放 | heap use-after-free | 堆分配器检测 |
| 清槽失败后仍被调用 | callback-after-clear | 语义事件 + 独立执行证据 |

每类都要有正负对照。**未触发统一记 `Inconclusive`**，不是候选被证伪。**本项目自有的 runtime 事件不能单独构成 UB 证据。**

### 两条线分开

- **最小通过线**：至少一个真正 unseen 的候选成功走通全程；
- **投稿竞争线**：生成率、编译率、执行率、确认率、重放成功率、adapter 人工成本达到预注册门槛。

- **失败动作**：C1 降级为 contract-path synthesis，不得称为不健全性确认

---

## 阶段 7：规模化评估

**做出什么功能**：把机制变成可发表的安全结论。

- **Gate A2 端任务增益**：加入反证之后，确认率、判定覆盖率是否提高、人工成本是否下降；
- public regression；
- 公平 baseline 对照（Yuga / FFIChecker / MiriLLI / deepSURF）；
- 八项消融；
- 约 100 crate pilot；
- **完整 attrition waterfall**：可分析总体 → 静态判定 → 支持的候选 → 尝试反证 → 生成反证 → 执行 → 独立确认，每一级给出流失原因分类。

**拿到 waterfall 之前，禁止使用**"FFI 边界上的保证被系统性打破""对每一次 break 都提供证明""LLVM IR 给出外部的实际行为"这三种表述。

关键对照点：deepSURF 在 rusqlite 上 108 harness / 84.2% 覆盖 / 每个 24 小时 / **0 bug**，而该 crate 有已公开的回调持有期公告。**这个数据点也约束我们自己**——若我们在同一 crate 上同样得 0，差别不在方法而在别处。

---

## 阶段 8：冻结与确认性评估

**做出什么功能**：证明结论不是在开发集上调出来的。

冻结 scanner / Contract / feature profile / 阈值 / 数据集 hash → 新的未揭示 sealed holdout → 前瞻扫描与披露 → Gate C（跨库泛化）→ Gate D（确认性评估）。

Gate D 两条线：

- **最低通过线**：至少一个有独立外部确认的新发现；
- **投稿竞争线**：2–3 个独立新问题、至少两个外部库或协议家族、至少一个维护者确认或修复。

---

## 完整依赖图

```text
阶段 0（无 gate 阻塞）
  0.1 文档一致性 ✅
  0.2 PG-2 分配归属
  0.3 Tier A 判据修正 + 探针驱动器  ←── start 依赖 0.2
  0.4 统计协议预注册（Gate P 部分必须在 0.3 跑之前）
  0.5 相关工作核实
        │
        ▼
阶段 1  Gate P-a 候选池 ＋ Gate P-b 转化率     ←── 止损点
        │  R 与 A 分别判定
        │  No-Go（两者皆）→ 路线 C，结束
        ▼
阶段 2（仅 Gate P Pass）    ── 四项并行 ──
  2.1 P0a 身份分层 + candidate 降为投影
  2.2 外部 IR 获取 spike
  2.3 Gate C0 可移植性 smoke（3–5 家族）
  2.4 P4a adapter 规格并冻结
        │
        ▼
阶段 3  3.1 Q1 槽位身份 → 3.2 Q4′ 清槽 → 3.3 降级 Q3 晚调候选
        │  （Q1 内核可与 2.1 并行开始；端到端完成依赖 2.1）
        ▼
阶段 4  4.1 一次性 schema 升版 → 4.2 P3 联合关系判定器
        │
        ▼
阶段 5  Gate A1 机制增益 ──No-Go──→ 路线 B
        │
        ▼
阶段 6  P4b 反证合成 → Gate B ──No-Go──→ C1 降级
        │
        ▼
阶段 7  Gate A2 + regression + baseline + 消融 + pilot + waterfall
        │
        ▼
阶段 8  freeze + sealed holdout + 前瞻扫描 + Gate C + Gate D
```

---

## 每一步做出的功能，一览

| 步骤 | 做完之后系统多了什么能力 |
| --- | --- |
| PF ✅ | 能按轨迹可行性判定相容性，并用四个 matched fixture 验证它分得开该分开的情况 |
| PC ✅ | 能从签名读出回调**语义上**允不允许捕获借用，不再把语义相反的两种写法合并 |
| PG-1 ✅ | 能看出安全 API 有没有返回一个把注册绑在被捕对象上的 guard，以及它 drop 时调没调外部函数 |
| PG-2 | 能看出回调分配交出后归谁，补上 `'static` 管不住的那一类 |
| Tier A 修正 + 驱动器 | 能在几百个 crate 上数出**可信的**候选池，并区分 referent 类与 allocation 类 |
| Gate P | 能回答"这条路线还值不值得做" |
| P0a | 两侧事实能精确指向同一次真实交出，不再靠函数名对齐 |
| IR spike / C0 | 能拿到与 Rust 侧同配置的外部 IR，并知道换个库要付多少成本 |
| P4a | 有一份不含缺陷知识、且可证明冻结在判定之前的 adapter 规格 |
| Q1 | 能认出外部把指针存进了哪个跨调用存活的槽位 |
| Q4′ | 能回答"注销到底清没清干净"——Rust 侧永远看不到的那一半 |
| 降级 Q3 | 能找出同槽位上的间接调用点，作为反证义务的起点 |
| schema 升版 | 新身份与三态判定真正落进产物，可被下游读取校验 |
| P3 | 判定的外部侧证据来自外部代码本身，而不是 API 清单推断 |
| Gate A1 | 能证明"看外部侧"带来了 Rust 侧拿不到的判别力 |
| P4b | 能自动写出纯 safe 的可执行反证，把"可能不健全"变成"已证明不健全" |
| Gate A2 / 阶段 7 | 有公平 baseline、完整消融和 attrition waterfall 支撑的量化结论 |
| 阶段 8 | 有冻结后、未参与设计的样本上的泛化证据与新发现 |

---

## 相关文档

- 方向权威与创新点：[research thesis](../project/research-thesis.md)
- 阶段是什么：[roadmap](roadmap.md)
- 阶段的技术细节：[implementation plan](implementation-plan.md)
- 现在在哪一步：[current work](current-work.md)
- gate 判据：[milestone gates](milestone-gates.md)
- 目标数据流与身份分层（`Planned`）：[target verifier pipeline](../architecture/target-verifier-pipeline.md)
- 代码处置约束：[codebase realignment](../development/codebase-realignment.md)
