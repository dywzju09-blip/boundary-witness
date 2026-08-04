# 目标判定管线（`Planned`）

**本文描述的全部内容状态为 `Planned`，没有任何一项已经实现。** 当前实现见 [system overview](system-overview.md) 与 [current status](../project/current-status.md)；本文只说明**目标形态**以及它与当前形态的差别。

**本文的落地按 [execution plan](../roadmap/execution-plan.md) 的核心闭环推进。** 身份模型与数据流不再等待 Gate P：先在一个真实目标上完成 Rust → IR → foreign facts → join → verdict → witness，Gate P 随后决定是否投入规模化评估和新发现搜索。若 Gate P No-Go，保留该核心工具链并转路线 B/C/D，不继续扩大样本。

---

## 1. 当前形态与目标形态的差别

| 方面 | 当前（`Implemented`） | 目标（`Planned`） |
| --- | --- | --- |
| 两侧事实的连接键 | 函数名 / 候选分片 | 分层身份，精确到 registration generation |
| candidate 的角色 | **承担两侧事实的连接主干** | 降为下游展示与调度投影 |
| 判定的外部侧输入 | 由人工 API 清单分类出的注册/注销事实**推断** | 从外部构建产物的 LLVM IR 抽取的 effect |
| 判定关系 | 两个 may-property 的合取 | 联合轨迹可行性 |
| 外部证据强度 | 单一枚举 `EvidenceGrade` | 四个正交字段 |
| Rust 侧契约事实 | 三缺一（capture admission、guard 已实现；allocation 未实现） | 三项齐备并装配成契约事实 |

### 已经发生过的两次错误

目标设计不是凭空提出的，它针对的是已经发生的失败：

1. **候选按边界切分，把同一函数的两半分到了不同候选**——因为连接键是候选分片；
2. **判定只挂给持有其中一半的候选，另一半读不到结论**——同上。

因此目标数据流把"联结"从候选切分中彻底移出。

---

## 2. 目标数据流

```text
中性事实（Rust 侧 + 外部侧，各自独立产出）
      │
      ▼
精确联结（按分层身份，不经过候选）
      │
      ▼
判定（联合轨迹可行性 → 三态判定 + 正交证据字段 + 反证义务）
      │
      ▼
candidate / ranking / 报告（下游投影，只用于展示与调度）
```

**关键约束**：箭头是单向的。candidate 由判定投影而来，**不参与产生判定**。任何让 candidate 回流进联结或判定的设计都回到了上面那两次错误。

---

## 3. 身份分层

不要把所有概念塞进一个扁平 ID。目标至少区分五层，每层回答一个不同的问题：

| 层 | 回答什么 | 至少包含 |
| --- | --- | --- |
| **构建产物身份** | 这是哪一次构建的产物 | Rust 侧与外部侧各自的 artifact hash；target；feature 集合；宏定义；优化级别；链接配置 |
| **安全入口身份** | 安全客户端从哪个 public API 进来 | public safe API 的定义路径与签名身份；是否 `unsafe fn` |
| **静态交出点身份** | 哪一次跨界调用把回调交了出去 | 单态化实例（不是泛型定义）；调用出现次序；callback 参数索引；userdata 参数索引 |
| **符号槽位身份** | 外部把它存进了哪个槽位 | 外部符号 + 符号版本；`#[link_name]` 重定向后的真实符号；槽位的结构体类型与偏移或全局符号 |
| **注册实例身份** | 这是该槽位上的第几次注册 | registration generation：同一槽位上"注册 A → 注销 → 注册 B"是不同实例 |

### 为什么需要 registration generation

`SameArtifactSlotAndRole` 能保证两侧事实指的是同一个槽位，**但分不开同一槽位上的不同注册实例**。而 [research thesis §2.6](../project/research-thesis.md) 自己把"同一槽位是否被多个 registration instance 共享"列为 Q4′ 的子问题——文档知道这个区别重要，身份模型里却没有它。

联合轨迹要求两侧事实指向**同一次注册**，不只是同一个槽位。缺这一层，"注册 A 之后 B 被晚调"这类错配无法表达。

运行期的注册实例如果与静态推出的 generation 不一致，必须单独记录，不得合并。

### 安全入口 lineage

研究对象是 **public safe API**，因此最终判定必须保留一条可回查的链：

```text
public safe 入口 → wrapper / helper → 具体的 extern 交出点
```

**只证明"回调到达了 extern 参数"不足以证明"安全客户端能到达这个交出点"。** 藏在内部 helper 里、公开 API 根本够不着的交出点不构成本研究的缺陷。这条同时是 [Gate P](../roadmap/milestone-gates.md#gate-p猎物存在性) 中 Tier A 判据的组成部分。

### 必须返回 Unknown 的情形

LTO、动态链接、符号解析歧义、`#[link_name]` 无法解析、单态化实例无法确定——一律返回 Unknown，**不得用名称近似补齐**。

### 只能作诊断的字段

源码位置、span、函数名、API 名、候选 ID。**它们不得参与联结**，只用于人工回查与报告。

---

## 4. 判定语义

### 4.1 联合轨迹可行性

当前关系是两个 may-property 的合取：

```text
SupportedIncompatibility ⇐ SafeLifetimeSeparationPossible ∧ ForeignLateUsePossible ∧ SameArtifactSlotAndRole
```

**问题**："存在一条客户端轨迹使 X 失效而注册仍有效"与"存在一条外部路径在返回后调用该槽位"分别成立，**不蕴含存在同一条执行同时满足两者**。

目标形态要求两侧证据能形成**联合轨迹**：同一构建、同一交出点、同一槽位、同一 registration generation，且路径条件相容。

```text
SupportedIncompatibility(X, Slot)
  ⇐ SeparationCertificate(X, Slot)          // 正面证书，不是"没看到保护"
  ∧ ForeignLateUseEffect(Slot, X)
  ∧ JointTraceFeasible(...)                 // 两者能在同一条执行上同时成立
```

三条纪律：

- **`SeparationCertificate` 是正面证据。** "没有观察到保护机制"不等于"已证明不存在保护机制"——后者才能构成证书，前者只是缺证；
- **静态证不出联合可行性时返回 `InsufficientEvidence`**，并附一条 `JointTraceObligation`；
- **动态反证可以完成联合轨迹的证明**：反证真的跑起来、外部真的回调进来，就是一条实际发生过的联合轨迹。

### 4.2 三态判定不变

`SupportedIncompatibility` / `CompatibleWithinAnalyzedFragment` / `InsufficientEvidence`。**不得引入第四态。**

### 4.3 外部证据拆成正交字段

当前 `EvidenceGrade` 把四件不可比较的事压成一个枚举，实测会互相覆盖：guard 被击穿时，晚调证据等级被直接覆盖丢失。

目标形态拆成四个正交字段：

| 字段 | 回答什么 |
| --- | --- |
| `RetentionEffect` | 指针有没有到达跨调用存活的存储（Q1） |
| `InvokeReachability` | 晚调证据有多强：同槽调用点存在 / 自导出入口可达 / 路径条件支持 |
| `ClearReplaceStatus` | 注销与替换是否在所有相关路径清空槽位（Q4′），是否存在绕过 guard 的路径 |
| `PathCompatibility` | 两侧路径条件是否相容——联合轨迹的直接输入 |

可以派生一个报告级的总体等级用于展示，**但不得丢失原始维度**。

### 4.4 反证义务

判定不成立时，要写清**缺的是哪一步**，而不只是"缺证"：

| 义务 | 含义 |
| --- | --- |
| `EstablishLateInvoke` | 只有降级 Q3 的同槽调用点证据，需要真实执行证明晚调确实发生 |
| `JointTraceObligation` | 两侧分别成立但联合可行性未证明 |

反证阶段消费这些义务，见 [execution plan 阶段 5](../roadmap/execution-plan.md)。

---

## 5. 事实来源的信任边界

**人工 API / Role map 与外部行为事实是两类东西，不得混。**

| 来源 | 允许声明 | **不得**声明 |
| --- | --- | --- |
| 人工 Role map | 符号绑定；callback / userdata 参数角色；register / unregister / replace 的**候选**角色；接入所需的静态元数据 | 实际是否保留；实际是否晚调；是否所有路径清槽；guard 是否有效 |
| 外部 effect 事实 | 上述全部行为结论 | — |

正式 Full 判定中的外部 effect **必须**来自外部 IR 抽取。手工 foreign oracle（例如 Gate R 的 C stub 标注）必须带**独立的 provenance 与来源等级**，只能用于 fixture、交叉验证和消融，**不得伪装成自动分析结果**。

这条不是新规矩，是把 [research thesis §11](../project/research-thesis.md) 第 4 条与 §12 的主张分级表落成可检查的字段。

---

## 6. 与现有代码的关系

本文不要求重写现有实现。按 [codebase realignment](../development/codebase-realignment.md) 的判断，最大的资产（编译器 Rust 侧）在新路线中价值上升，身份模型是可扩展的 builder，外部侧属纯新增。

落地方式：

- 现有静态事实继续作为**底层观察**保留，新的契约 / 行为 / 判定三层是它们的聚合；
- 身份字段通过 builder 的 `with_*` 方法新增，既有调用点不受影响；
- 分层身份、三态判定与外部侧事实**合并为一次** schema 升版（见 realignment 的 D2），在 execution plan 阶段 1–3 的记录形状定稿、进入阶段 4 时进行。

---

## 7. 相关文档

- 方向权威：[research thesis](../project/research-thesis.md)
- 执行顺序与阶段：[execution plan](../roadmap/execution-plan.md)
- 当前实现形态：[system overview](system-overview.md)
- 证据分层与 lineage：[evidence model](evidence-model.md)
- 术语：[terminology](../project/terminology.md)
- 决策记录：[ADR-0003](../decisions/ADR-0003-target-verifier-dataflow-and-identity.md)、[ADR-0004](../decisions/ADR-0004-joint-trace-verdict-semantics.md)、[ADR-0005](../decisions/ADR-0005-evidence-trust-and-experiment-statistics.md)
