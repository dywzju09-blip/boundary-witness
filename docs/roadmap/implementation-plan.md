# 完整功能实现计划

本文是 [roadmap](roadmap.md) 各阶段的可执行细化。方向权威是 [research thesis](../project/research-thesis.md)：**任何一项如果不能落到 N1/N2/N3 之一，就不该做。**

当前阶段是 **V3.2.x core-effect hardening**，V3.3 gate 未通过。本文描述计划，不是已达成能力。

## 现状基线

已有：Rust 侧 HIR/MIR 事实抽取、候选生成、生命周期证据与图、排序、witness plan、runtime/oracle/fuzz observer 基础、单一库的 harness。

持有期维度的 Rust 侧契约可以从签名读出（四态：绑在 receiver 声明的 lifetime / 绑在其他声明的 lifetime / `'static` / 无 outlives bound），并已与外部边界事实联结、把判定与判定来源写入产物。

**缺口：外部侧不存在。** 持有期维度的外部侧那一半目前由 API 清单分类出的注册/注销事实**推断**得来，不是外部代码行为。三条创新点因此都未成立。

---

## P0 — 边界事实模型二元化

**服务 N1。前置：无。风险：低，但必须一次做对。**

### 问题

现有事实全部单侧，两侧连接键是"函数名"。已发生两次由此导致的错误：候选按边界切分，把同一函数的两半分到不同候选；判定只挂给持有其中一半的候选，导致另一半读不到结论。

### 要做

引入稳定的交出点身份，并把事实按"契约/行为/判定"三类重组：

```rust
/// 交出点身份：跨越语言边界的那一次调用
struct HandOffId {
    crate_name: String,
    crate_version: String,
    foreign_symbol: String,   // 被调外部符号
    call_site: SiteId,        // 调用点稳定站点 id
}

struct RustContractFact   { hand_off: HandOffId, dimension: Dimension, contract: Contract }
struct ForeignBehaviorFact{ hand_off: HandOffId, dimension: Dimension, behavior: Behavior, evidence: Vec<String> }
struct MismatchVerdict    { hand_off: HandOffId, dimension: Dimension,
                            contract: Contract, behavior: Option<Behavior>,
                            decision: Decision, witness_plan: Option<WitnessPlanRef> }

enum Decision { Mismatch, NoMismatch, Undecided }
```

`Dimension` 取 [research thesis §2](../project/research-thesis.md) 的八维。

### 迁移方式

不要一次性删除现有事实种类。新增这一层，让持有期维度先走通，其余维度逐个迁移。现有 `StaticFact` 继续作为底层观察，新层是它们的聚合。

### 代码入口

`crates/bw-model/src/static_fact.rs`、`crates/bw-model/src/lifecycle_v326.rs`、`compiler/bw-rustc/src/domain.rs`、`crates/bw-model/src/site.rs` 对应的站点身份构造。

### 完成谓词

任一维度的两侧事实可在**不依赖候选切分**的前提下联结。用持有期维度验证：契约事实与行为事实分属不同候选时，判定仍然成立且两侧候选都能读到。

### 非空性检查

把 join key 改回候选，确认联结测试失败且失败落在预期断言上。

---

## P1 — 消除人工 API 清单

**服务 N2。前置：无。风险：中。**

### 三个结构信号

| 信号 | 判据 | 证明什么 |
| --- | --- | --- |
| S1 签名形状 | 外部函数为 `extern "C"`，参数同时含**函数指针**与**不透明数据指针** | 这是一次回调交出 |
| S2 可清空性 | 同一外部符号在别处存在"空回调"调用点 | 外部侧存在需显式清除的槽位 |
| S3 所有权交出 | 调用前对被交出数据执行 `Box::into_raw` / `mem::forget`，且本函数返回前未回收 | Rust 侧已停止追踪 |

S1 单独会误报（不是所有"函数指针 + 数据指针"都构成长期持有），靠 S2/S3 收紧。

### 可行性

已确认：编译器侧已有读取任意函数签名与 ABI 的能力（判断"某函数是否为外部回调"即用此方式），因此在调用点读被调函数的参数类型是现成能力。参数形状判定（区分"传了回调"与"传了空"）也已存在。

### 代码入口

`compiler/bw-rustc/src/registration.rs`、`compiler/bw-rustc/src/rustc_api/mir.rs`。

### 完成谓词

**消融实验有数字**：关闭 API 清单后，在目标样本上的召回与精度，且漏报有归因。这是 N2 唯一的证据来源。

---

## P2 — 外部侧有界分析（关键路径）

**服务 N1 的前提。前置：无，可与 P0 并行。风险：高，全路线最大不确定性。**

### 范围决定

不做全量 IR 翻译（对比 ACORN 把 Rust 与 C 都译为 Wasm）。只做四个有界查询，代价与精度取舍写入论文。

| 查询 | 问题 | 服务维度 |
| --- | --- | --- |
| Q1 逃逸 | 指针参数是否到达"调用返回后仍存活"的存储（全局、结构体字段、堆） | 持有期 |
| Q2 写穿 | 指针指向的内存是否被写 | 别名与可变性 |
| Q3 调用还是存储 | 函数指针参数是被**同步调用**，还是被**存起来**供以后调用 | 持有期（核心判据） |
| Q4 释放契约 | 是否存在配对的 free 回调参数，控制流上是否真的调用 | 持有期、释放责任 |

Q3 是最关键的一个：它直接回答"外部侧是否持有到调用返回之后"，而不需要推断。

### IR 获取分级

| 级别 | 情况 | 处理 |
| --- | --- | --- |
| L1 | 外部 C 源码随构建提供 | **先只支持这一级。** 用 clang 产出 LLVM IR |
| L2 | 链接系统库，源码需单独获取 | 工程量大，暂不支持 |
| L3 | 仅有二进制 | 放弃，写入 limitation |

先例：FFIChecker 已证明取得双侧 LLVM IR 可行（它即在 LLVM IR 上工作）。**本项目的新意在查询本身**——持有期与别名，而非 alloc/dealloc 配对。

### 算法草案

Q1/Q3 都是从「形参」出发的前向逃逸查询：

1. 以外部函数的指针形参为起点建立值集合
2. 沿 store / bitcast / GEP / phi / call 参数传播
3. 命中以下任一即判定逃逸：写入全局变量、写入通过其他指针参数可达的内存、传入另一个未知外部函数、被 `memcpy` 到上述位置
4. 若指针只在本函数内被 load/比较/同步调用后返回，判不逃逸

Q3 在 Q1 基础上加一条区分：函数指针形参若出现在 `call` 指令的被调位置且不逃逸，则为同步调用；若被 store 到逃逸位置，则为存储。

### 纪律

**查不出逃逸不得判定为安全。** 分析不完整、IR 不可得、间接调用无法解析，一律记 `Undecided`。误报方向必须是保守的一侧。

### 完成谓词

单一库上 Q1 与 Q3 端到端产出可回查证据，且能与该库的 Rust 侧契约事实按 `hand_off_id` 联结。

### 止损条件

**若两三周内看不到端到端结果，贡献结构需要重新设计。** 早暴露比晚暴露便宜。

Plan B：把范围收缩为「外部源码随构建提供的 FFI crate」，作为明确 scope 写入论文而非当作失败。该子集足以支撑评估。

---

## P3 — 持有期维度闭环

**服务 N1。前置：P0 + P2。风险：低。**

把持有期判定的外部侧证据来源从"注册事实推断"换成"Q1/Q3 逃逸证据"。人工版本边界保留为交叉验证：两路结论都写入产物，不一致时都保留。

判定表：

| Rust 侧契约 | 外部侧行为 | 判定 |
| --- | --- | --- |
| bound 短于 `'static` | 指针逃逸到返回后存活的存储 | Mismatch |
| bound 短于 `'static` | 不逃逸 | NoMismatch |
| bound 为 `'static` | 任意 | NoMismatch |
| 任意 | 外部侧不可得 | Undecided |
| 无 outlives bound | 任意 | Undecided（签名不表态） |

### 完成谓词

判定来源字段显示为外部侧证据；与人工边界不一致的条目被单独列出。

---

## P4 — 定向见证与动态确认

**服务 N3。前置：P3。风险：中。**

### 与盲测的区别

不是 fuzz。见证由静态已证明的**那一条**契约违反反推构造，oracle 判定契约违反而非仅崩溃。

持有期维度模板：

```
建立一个有限存活期的对象
  → 构造借用它的回调
  → 通过被判定的 API 交出
  → 释放该对象
  → 驱动外部库调用回调
  → 观察
```

### oracle 选型

依据 MiriLLI 的结论：Miri 无法观察外部函数内部。因此对真实外部库采用 sanitizer；Miri + LLVM 解释器的联合路线更强但更重，写入 discussion 而非实现。

### 各维度 oracle

| 维度 | 触发构造 | 判据 |
| --- | --- | --- |
| 持有期 | 上述模板 | sanitizer 报释放后使用 |
| 别名 | 交出共享引用来源的指针，令外部写入 | Rust 侧观察到本不应变化的值 |
| 重入 | 在回调内再次进入同一 API | 运行时借用冲突 |
| 展开 | 令回调 panic | 是否展开越过边界 |

### 完成谓词

至少一维上，静态候选可自动转为可编译可运行的见证，并产出可复现判定。

---

## P5 — 别名与重入维度

**服务 N1 的广度。前置：P2、P4。**

- **别名**：Rust 侧记录指针来源（`&T` 还是 `&mut T`）与形参 const 性；外部侧 Q2。错配 = 共享引用来源的指针被外部写入
- **重入**：Rust 侧记录交出时是否持有可变借用或运行时借用；外部侧 Q3 判定为"存储"；再加回调体是否触达同一对象

重入依赖跨函数触达分析，是现有对象流分析的延伸，而后者已知只覆盖有限形状——这是该维度的主要风险。

---

## P6 — 线程维度（可裁）

**优先级最低。** 外部侧线程分析难度高。缩到可做子集：外部符号是否把指针存入被线程入口函数读取的结构。做不到就诚实降级为 future work，不硬做。

---

## P7 — 规模化与评估

评估设计见 [research thesis §5](../project/research-thesis.md)，不在此重复。执行顺序：

1. Gate 0 外部基线对照（[runbook](../experiments/runbooks/baseline-comparison.md)）
2. 消融三项
3. 已披露公告上的召回与漏报归因
4. 生态级扫描：L1 级别的 FFI crate 全集
5. 新发现与披露流程

---

## 依赖与并行

```text
P0 ──┐
     ├─→ P3 ─→ P4 ─→ P5
P2 ──┘              └─→ P6（可裁）
P1 ──────────────────→ P7
```

- **P0 与 P2 并行起步**
- **P2 是关键路径**：它决定持有期维度的精度，也决定别名维度能否成立
- P1 独立，随时可做，但它的价值要到 P7 的消融才体现

## 贯穿全程的纪律

来自本项目已发生的返工，见 [research thesis §6](../project/research-thesis.md)。摘要：

- 缺证、健全、错配三态必须可区分，缺证不是安全
- 两半齐才是缺陷，单侧证据只产出候选
- join key 必须是被判定对象的身份，不是分析产物的切分单位
- 改判定器必须做非空性验证：破坏判据的一半，确认对应断言失败且落在预期位置
- 模型与 schema 双向比对，不靠逐条手写断言
