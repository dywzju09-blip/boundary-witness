//! 跨界回调持有期的相容性判定。
//!
//! 判据是**安全客户端的轨迹可行性**，不是 lifetime bound 的字面形状：
//!
//! ```text
//! SupportedIncompatibility(X, Slot)
//!   ⇐ SafeLifetimeSeparationPossible(X, Slot)
//!   ∧ ForeignLateUsePossible(Slot, X)
//!   ∧ SameArtifactSlotAndRole
//! 其中 X ∈ { CapturedReferent, CallbackAllocation }
//! ```
//!
//! 规范定义见 `docs/project/research-thesis.md` §2.3–§2.7。
//!
//! # 为什么不是按 bound 形状判定
//!
//! 此前的 2×2 矩阵（bound 形状 × 外部行为）已废除，它有两个可构造的错判：
//!
//! - **假阳性**：API 接受 `F: 'a` 并返回 `Registration<'a>` guard，外部**确实**保存并
//!   晚调，但安全客户端构造不出「被借对象已失效而注册仍有效」。旧矩阵会报。
//! - **假阴性**：`F: 'static` 只约束**回调捕获的对象**，完全不约束**回调分配本身**。
//!   `Box<F>` 被 Rust 侧提前释放、外部随后调用悬垂指针——旧矩阵判「相容」。
//!
//! 因此本模块把两类生命周期分开（[`LifetimeSubject`]），并把判定建立在
//! 「安全客户端能否让 X 失效而注册仍有效」之上。
//!
//! # guard 不是纯 Rust 侧判据
//!
//! registration guard 是否真的保护，取决于它 drop 时调用的外部函数**是否真的清空了
//! 槽位**——Rust 侧只能看到「`Drop` 里调了某个 extern 函数」。因此没有外部侧的清槽
//! 证据（Q4′）时，guard 只能得出 [`StaticVerdict::InsufficientEvidence`]，不能得出
//! 「相容」。这是外部侧在本关系中的主要判别力所在。
//!
//! # 本模块暂不提供 schema
//!
//! 按 `docs/development/codebase-realignment.md` 的 D2，`HandOffId`、三态判定与外部侧
//! 事实合并为**一次** schema 升版，在 P0/P1 的字段定稿后进行。在那之前这些类型只在
//! 进程内使用，不写出产物。

use serde::{Deserialize, Serialize};

use crate::{
    StaticFact, StaticFactEnvelope,
    static_fact::{
        AllocationOwnership, EffectiveCaptureAdmission, ForeignSymbolBindingFact,
        RegistrationGuard, SafeEntryLineage,
    },
};

/// 注册实例身份：同一槽位上「注册 A → 注销 → 注册 B」是不同的注册实例。
///
/// [ADR-0003](../../../docs/decisions/ADR-0003-target-verifier-dataflow-and-identity.md)
/// 把它列为身份的第五层。`SameArtifactSlotAndRole` 保证两侧指的是同一个槽位，**但分不开
/// 同一槽位上的不同注册实例**——把两次注册的证据拼在一起会得出谁都没发生过的结论。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationGeneration {
    /// 本构建里该符号只有这一个静态注册点，代次由交出点唯一确定。
    UniqueStaticSite,
    /// 同一符号还有别的静态注册点。
    ///
    /// **这不是拒绝联结的理由。** 外部侧的行为结论描述的是外部函数的代码，对每个注册点
    /// 一样成立；而安全客户端完全可以只调其中一个 API，那时就只有一次注册。真正分不开的
    /// 是**运行期**的「注册 A → 注销 → 注册 B」，静态看不到，由反证负责。
    ///
    /// 早先这里判的是拒绝，结果任何有一个以上注册 API 的 crate 都产出零判定。
    MultipleStaticSites,
    /// 尚未判定。**join 必须拒绝**——不知道代次就无法把证据归属到任何一次注册。
    Unresolved,
}

/// 交出点身份：跨越语言边界的那一次调用。
///
/// 两侧事实只有在本身份完全相等时才能组合——这就是关系里的 `SameArtifactSlotAndRole`
/// 那一项。**按函数名、API 名或候选分片联结一律禁止**（ADR-0003 第五条）。
///
/// # 字段按身份层次排列
///
/// [ADR-0003](../../../docs/decisions/ADR-0003-target-verifier-dataflow-and-identity.md)
/// 第二条要求至少五层。槽位（第四层的后半）**不在这里**：Rust 侧看不见槽位，把它写进
/// 两侧都要构造的身份会让 Rust 侧永远填不出来。槽位由外部侧携带，在
/// [`crate::JointTrace`] 里合流。
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandOffId {
    // ---- 第一层：构建产物身份 ----
    /// Rust 侧构建产物的 hash。
    pub rust_artifact: String,
    /// 外部侧构建产物的 hash。阶段 2 的 capture manifest 记的那个。
    pub foreign_artifact: String,
    /// 构建配置。切 feature、target 或优化级别都必须让它变化，否则会错误联结。
    pub build_profile: String,

    // ---- 第二层：安全入口身份 ----
    /// 该交出点所属的 public safe 入口的单态化实例 id。
    ///
    /// 研究对象是「安全 API 允许 UB」，只证明回调到达 extern 参数不够——还要证明安全
    /// 客户端到得了这里（ADR-0003 第三条）。
    pub safe_entry_instance: String,

    // ---- 第三层：静态交出点身份 ----
    /// 声明回调参数的那个函数的单态化实例 id。
    pub rust_def_instance: String,
    /// 该实例内交出点的稳定位置标识。
    pub call_occurrence: String,

    // ---- 第四层：符号与参数角色 ----
    /// 外部链接符号。`#[link_name]` 解析不出来时不得用函数名近似（ADR-0003 第四条）。
    pub foreign_symbol: String,
    pub callback_arg_index: u32,
    pub userdata_arg_index: Option<u32>,
    /// 同一符号上区分多个注册槽位的键（例如一个 API 同时注册 update 与 commit 钩子）。
    pub registration_key: Option<String>,

    // ---- 第五层：注册实例身份 ----
    pub registration_generation: RegistrationGeneration,
}

/// 装配 Rust 侧半键时，只有构建层面才知道的那两项。
///
/// 其余字段全部来自静态事实本身——**不接受调用方传入符号或参数角色**，那是编译器的
/// 观察结果，从外面塞进来就等于人工标注。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustHandOffBuildContext {
    pub rust_artifact: String,
    pub build_profile: String,
}

/// Rust 侧在联结前能填出的那半个身份。
///
/// # 为什么要分成两半
///
/// [`HandOffId`] **哪一侧都填不全**：Rust 侧不知道哪个外部构建产物提供了这个符号，外部
/// 侧不知道交出点是从哪个 public safe 入口来的。阶段 1.4 当时用 `"pending-stage-2"` 之类
/// 的占位串把它凑齐，那是假数据——一旦有人拿去 join，得到的是两个不相干事实的组合。
///
/// 因此两侧各产出半个键，完整身份**只能由 [`crate::join_hand_off`] 合成**，且合成前会
/// 校验重叠部分（符号与参数角色）确实一致。
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RustHandOffKey {
    pub rust_artifact: String,
    pub build_profile: String,
    pub safe_entry_instance: String,
    pub rust_def_instance: String,
    pub call_occurrence: String,
    /// 编译器解析出的外部链接符号。这是与外部侧唯一的重叠部分，也是联结的主键。
    pub foreign_symbol: String,
    pub callback_arg_index: u32,
    pub userdata_arg_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_key: Option<String>,
    pub registration_generation: RegistrationGeneration,
}

/// 外部侧在联结前能填出的那半个身份。
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignHandOffKey {
    pub foreign_artifact: String,
    pub build_profile: String,
    pub foreign_symbol: String,
    pub callback_arg_index: u32,
    pub userdata_arg_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_key: Option<String>,
}

/// 判定必须分开的两类生命周期。
///
/// 合并它们会产生可构造的漏报：`'static` bound 只约束前者。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifetimeSubject {
    /// 回调**捕获的**借用对象。由回调类型的 outlives bound 与 guard 的类型约束。
    CapturedReferent,
    /// 回调分配本身与 trampoline userdata（`Box<F>` 等）。由 Rust 侧的所有权与 drop
    /// 约束，**不受 `'static` bound 约束**。
    CallbackAllocation,
}

impl LifetimeSubject {
    pub const ALL: [Self; 2] = [Self::CapturedReferent, Self::CallbackAllocation];
}

/// Rust 侧契约事实。只描述类型层允许什么，不描述外部做了什么。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RustContractFact {
    pub hand_off: RustHandOffKey,
    pub capture_admission: EffectiveCaptureAdmission,
    pub guard: RegistrationGuard,
    pub allocation: AllocationOwnership,
    /// 可回查的来源，仅作诊断，**不参与联结**。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

/// 装配 [`RustContractFact`] 时能说明为什么装不出来的原因。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RustContractGap {
    /// 缺 `EffectiveCaptureAdmission`。
    MissingCaptureAdmission,
    /// 缺 `RegistrationGuard`。
    MissingGuard,
    /// 缺 `AllocationOwnership`。
    MissingAllocationOwnership,
    /// 缺 safe-entry lineage。
    MissingSafeEntryLineage,
    /// 安全客户端到不了这个交出点，不构成「安全 API 允许 UB」的证据。
    NotReachableFromSafeEntry,
    /// safe-entry 可达性未判定。
    SafeEntryLineageUnresolved,
    /// 没有外部符号绑定事实。**没有符号就没有联结主键**，这个交出点接不上外部侧。
    MissingForeignSymbol,
    /// 有符号绑定事实，但没解析出符号（函数体里找不到外部调用，或找到多个）。
    ForeignSymbolUnresolved,
}

/// 一个交出点上装配的结果：要么是完整的契约事实，要么是缺了哪一半。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RustContractAssembly {
    Assembled(Box<RustContractFact>),
    Gap {
        api_id: String,
        callback_param: String,
        gaps: Vec<RustContractGap>,
    },
}

/// 把三个 Rust 侧事实按 `(api_id, callback_param)` 装配成 [`RustContractFact`]。
///
/// **这一步取代 PF 阶段测试里手写的那组事实。** 判定关系需要三样齐备；缺任何一样都
/// 不装配，而是产出一条写明缺什么的 [`RustContractAssembly::Gap`]——静默丢弃会让下游
/// 分不清「已检查且相容」与「根本没看到」。
///
/// safe-entry 可达性是**过滤条件**而不是字段：只能从 `unsafe fn` 或私有路径到达的交出点
/// 不构成本研究的证据，因此不装配，并记
/// [`RustContractGap::NotReachableFromSafeEntry`]。
///
/// # 身份只填 Rust 侧那一半
///
/// `hand_off_key` 产出 [`RustHandOffKey`]，**不是完整的 [`HandOffId`]**。外部 artifact
/// 与槽位这一侧看不见，凑占位串再拼成完整身份会得到假数据。完整身份由
/// [`crate::join_hand_off`] 在校验重叠部分之后合成。
#[must_use]
pub fn assemble_rust_contract_facts(
    facts: &[StaticFactEnvelope],
    build: &RustHandOffBuildContext,
) -> Vec<RustContractAssembly> {
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Parts {
        admission: Option<EffectiveCaptureAdmission>,
        guard: Option<RegistrationGuard>,
        allocation: Option<AllocationOwnership>,
        lineage: Option<SafeEntryLineage>,
        entry_def_path: Option<String>,
        binding: Option<ForeignSymbolBindingFact>,
        evidence: Vec<String>,
    }

    let mut by_hand_off = BTreeMap::<(String, String), Parts>::new();
    for envelope in facts {
        match &envelope.payload {
            StaticFact::CallbackLifetimeBound(fact) => {
                let parts = by_hand_off
                    .entry((fact.api_id.clone(), fact.callback_param.clone()))
                    .or_default();
                parts.admission = Some(fact.bound_scope.effective_capture_admission());
                parts.evidence.push(fact.site_id.to_string());
            }
            StaticFact::RegistrationGuard(fact) => {
                let parts = by_hand_off
                    .entry((fact.api_id.clone(), fact.callback_param.clone()))
                    .or_default();
                parts.guard = Some(fact.guard);
                parts.evidence.push(fact.site_id.to_string());
            }
            StaticFact::AllocationOwnership(fact) => {
                let parts = by_hand_off
                    .entry((fact.api_id.clone(), fact.callback_param.clone()))
                    .or_default();
                parts.allocation = Some(fact.ownership);
                parts.evidence.push(fact.site_id.to_string());
            }
            StaticFact::SafeEntryLineage(fact) => {
                let parts = by_hand_off
                    .entry((fact.api_id.clone(), fact.callback_param.clone()))
                    .or_default();
                parts.lineage = Some(fact.lineage);
                parts.entry_def_path = fact.entry_def_path.clone();
                parts.evidence.push(fact.site_id.to_string());
            }
            StaticFact::ForeignSymbolBinding(fact) => {
                let parts = by_hand_off
                    .entry((fact.api_id.clone(), fact.callback_param.clone()))
                    .or_default();
                parts.binding = Some(fact.clone());
                parts.evidence.push(fact.site_id.to_string());
            }
            _ => {}
        }
    }

    // 注册代次：同一个外部符号被本构建里几个交出点注册过。
    //
    // 一个就能由交出点唯一确定代次；多个就分不开证据属于哪一次——**这不是可以忽略的
    // 细节**，「注册 A → 注销 → 注册 B」的证据拼在一起会得出谁都没发生过的结论。
    let mut sites_per_symbol = BTreeMap::<String, usize>::new();
    for parts in by_hand_off.values() {
        if let Some(symbol) = parts.binding.as_ref().and_then(|fact| fact.symbol.as_ref()) {
            *sites_per_symbol.entry(symbol.clone()).or_default() += 1;
        }
    }

    by_hand_off
        .into_iter()
        .map(|((api_id, callback_param), parts)| {
            let mut gaps = Vec::new();
            if parts.admission.is_none() {
                gaps.push(RustContractGap::MissingCaptureAdmission);
            }
            if parts.guard.is_none() {
                gaps.push(RustContractGap::MissingGuard);
            }
            if parts.allocation.is_none() {
                gaps.push(RustContractGap::MissingAllocationOwnership);
            }
            match parts.lineage {
                None => gaps.push(RustContractGap::MissingSafeEntryLineage),
                Some(SafeEntryLineage::NoPublicSafeEntry) => {
                    gaps.push(RustContractGap::NotReachableFromSafeEntry);
                }
                Some(SafeEntryLineage::Unresolved) => {
                    gaps.push(RustContractGap::SafeEntryLineageUnresolved);
                }
                Some(
                    SafeEntryLineage::DirectPublicSafeEntry
                    | SafeEntryLineage::ReachableFromPublicSafeEntry,
                ) => {}
            }
            // 没有符号就没有联结主键，这个交出点接不上外部侧。
            match parts.binding.as_ref() {
                None => gaps.push(RustContractGap::MissingForeignSymbol),
                Some(fact) if fact.symbol.is_none() || fact.callback_arg_index.is_none() => {
                    gaps.push(RustContractGap::ForeignSymbolUnresolved);
                }
                Some(_) => {}
            }
            if !gaps.is_empty() {
                return RustContractAssembly::Gap {
                    api_id,
                    callback_param,
                    gaps,
                };
            }
            let mut evidence = parts.evidence;
            evidence.sort();
            let binding = parts.binding.expect("checked above");
            let symbol = binding.symbol.expect("checked above");
            let registration_generation = match sites_per_symbol.get(&symbol) {
                Some(1) => RegistrationGeneration::UniqueStaticSite,
                Some(_) => RegistrationGeneration::MultipleStaticSites,
                None => RegistrationGeneration::Unresolved,
            };
            RustContractAssembly::Assembled(Box::new(RustContractFact {
                hand_off: RustHandOffKey {
                    rust_artifact: build.rust_artifact.clone(),
                    build_profile: build.build_profile.clone(),
                    // lineage 为可达时必有入口；`DirectPublicSafeEntry` 时入口就是它自己。
                    safe_entry_instance: parts.entry_def_path.unwrap_or_else(|| api_id.clone()),
                    // 单态化实例 id 还需要更多编译器工作，当前用定义路径。它**不参与
                    // 跨侧匹配**（那只看符号与参数角色），因此不违反 ADR-0003 第五条。
                    rust_def_instance: api_id.clone(),
                    call_occurrence: binding.site_id.to_string(),
                    foreign_symbol: symbol,
                    callback_arg_index: binding.callback_arg_index.expect("checked above"),
                    userdata_arg_index: binding.userdata_arg_index,
                    registration_key: None,
                    registration_generation,
                },
                capture_admission: parts.admission.expect("checked above"),
                guard: parts.guard.expect("checked above"),
                allocation: parts.allocation.expect("checked above"),
                evidence,
            }))
        })
        .collect()
}

/// Q1：指针是否到达「调用返回后仍存活」的存储。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForeignRetention {
    MayRetain,
    NoRetain,
    Unresolved,
}

/// Q3：是同步调用还是可能在返回之后调用。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForeignInvocation {
    MayInvokeAfterReturn,
    SynchronousInvokeOnly,
    Unresolved,
}

/// Q4′：注销 / 替换是否在所有相关路径上清空槽位。
///
/// **这是外部侧真正有判别力的一项。** 进入候选集合的 API 按定义都带注册语义，因此 Q1
/// 的答案可能几乎恒为「是」；因库而异、且 Rust 侧看不见的是清槽是否可靠。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForeignClear {
    /// 注销被调用时，槽位在所有路径上都被清空。
    ClearsOnAllPaths,
    /// 存在注销后槽位仍被填充、或绕过该槽位的第二条晚调路径。
    MayLeaveSlotPopulated,
    Unresolved,
}

/// 保留发生在注册入口的哪些路径上。
///
/// **它不声称保留路径与晚调路径能在同一条轨迹上同时成立**——那需要解路径条件，超出首期
/// 分析片段，是反证义务要补的那一步。本字段只回答一件能从 IR 直接读出的事：那条 store
/// 是无条件发生的，还是只在某个分支上发生。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForeignPathCompatibility {
    /// 注册入口每一条会返回的路径都执行了保留 store。
    RetainOnEveryPath,
    /// 存在一条会返回、却不经过保留 store 的路径。
    RetainOnSomePaths,
    Unresolved,
}

/// 外部侧行为事实。
///
/// 四个取值是**正交**的，按执行计划阶段 3.4 分开记录：不得用一个总枚举覆盖前一个查询的
/// 结果。`retention` 是 Q1，`invocation` 是降级 Q3，`clear` 是 Q4′，`path_compatibility`
/// 是保留路径的无条件性。
///
/// **PF 阶段这些取值由 matched fixture 的 C stub 手工标注**，即评估设计里的
/// `manual foreign oracle` 变体。阶段 3 起改由 `bw-foreign-ir` 从真实构建的 LLVM IR 推导；
/// 关系本身不因来源改变。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignBehaviorFact {
    pub hand_off: ForeignHandOffKey,
    pub retention: ForeignRetention,
    pub invocation: ForeignInvocation,
    pub clear: ForeignClear,
    pub path_compatibility: ForeignPathCompatibility,
    /// Q3 晚调证据的强度。降级实现只能给出
    /// [`EvidenceGrade::SameSlotInvokeCandidate`]。
    pub invoke_evidence: Option<EvidenceGrade>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

/// 静态判定。**只有三态**，不得引入第四态。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticVerdict {
    SupportedIncompatibility,
    CompatibleWithinAnalyzedFragment,
    InsufficientEvidence,
}

/// 支撑判定的外部证据强度。与 [`StaticVerdict`] 正交。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceGrade {
    /// 降级 Q3：同槽位存在间接调用点。**不足以支撑 `SupportedIncompatibility`。**
    SameSlotInvokeCandidate,
    /// 该调用点自导出入口可达。
    ReachableMayInvoke,
    /// 路径条件支持返回后调用。
    PathSupportedLateInvoke,
    /// Q4′ 发现绕过 guard 或未清空槽位的路径。
    GuardDefeated,
}

/// 反证状态。与 [`StaticVerdict`] 正交，**动态结果不改变静态判定的语义**。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessStatus {
    NotAttempted,
    Generated,
    Executed,
    ConfirmedCounterexample,
    /// 已执行但未触发。**这不是候选被证伪**——有限次执行不能证伪 may-property。
    Inconclusive,
}

/// 判定成立还欠缺的、需要由反证补上的那一步。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessObligation {
    /// 只有降级 Q3 证据，需要真实执行证明晚调确实发生。
    EstablishLateInvoke,
    /// 身份五层全部对上，但**路径条件相容性没有被证明**。
    ///
    /// 这就是 research thesis §2.5 的 `JointTraceObligation`。两侧各自的 may-property
    /// 成立，不蕴含它们能在同一条执行上同时发生：保留只在部分路径上发生时，那条路径
    /// 未必就是能走到晚调的那条。首期不解路径条件，因此这一步交给反证。
    EstablishJointTrace,
}

/// 一个交出点上、针对一类生命周期的判定结果。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityVerdict {
    pub hand_off: HandOffId,
    pub subject: LifetimeSubject,
    pub static_verdict: StaticVerdict,
    pub evidence_grade: Option<EvidenceGrade>,
    pub witness_status: WitnessStatus,
    pub witness_obligation: Option<WitnessObligation>,
    /// 判定所依赖的假设与降级说明。缺证时必须写清缺哪一半。
    pub assumptions: Vec<String>,
}

/// 三值逻辑：某个合取项是被否定、成立，还是无法判定。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Tri {
    Denied,
    Possible,
    Unresolved,
}

/// `SafeLifetimeSeparationPossible(X, Slot)`。
///
/// > 存在一条 well-typed、只使用安全 API 的客户端轨迹，使 `X` 失效而 `Slot` 上的注册
/// > 仍然有效。
fn safe_lifetime_separation_possible(
    rust: &RustContractFact,
    subject: LifetimeSubject,
    foreign: Option<&ForeignBehaviorFact>,
    assumptions: &mut Vec<String>,
) -> (Tri, bool) {
    let mut guard_defeated = false;

    // 第一步：类型层是否直接否定这一类生命周期的分离。
    let by_shape = match subject {
        LifetimeSubject::CapturedReferent => match rust.capture_admission {
            // `'static` 排除借用捕获——但**只对这一类生命周期**。
            EffectiveCaptureAdmission::RequiresStaticCapture => Tri::Denied,
            EffectiveCaptureAdmission::PermitsNonStaticCapture => Tri::Possible,
            EffectiveCaptureAdmission::ContextDependent | EffectiveCaptureAdmission::Unresolved => {
                assumptions.push("capture admission unresolved".to_owned());
                Tri::Unresolved
            }
        },
        LifetimeSubject::CallbackAllocation => match rust.allocation {
            // 这一格正是旧 2×2 矩阵的漏报来源：`'static` 对分配存活不表态。
            AllocationOwnership::ForeignOwnedUntilUnregister => Tri::Denied,
            AllocationOwnership::RustRetainsAndMayFreeEarly => Tri::Possible,
            AllocationOwnership::Unresolved => {
                assumptions.push("allocation ownership unresolved".to_owned());
                Tri::Unresolved
            }
        },
    };
    if by_shape == Tri::Denied {
        return (Tri::Denied, guard_defeated);
    }

    // 第二步：guard 是否否定分离。**这一步必须读外部侧的清槽证据。**
    let by_guard = match rust.guard {
        RegistrationGuard::None => by_shape,
        RegistrationGuard::Unresolved => {
            assumptions.push("registration guard shape unresolved".to_owned());
            Tri::Unresolved
        }
        RegistrationGuard::TiesSlotToSubject | RegistrationGuard::OwnerDropUnregisters => {
            match foreign.map(|fact| fact.clear) {
                // guard 有效：注销真的清空槽位。
                Some(ForeignClear::ClearsOnAllPaths) => Tri::Denied,
                // guard 被击穿：注销没清干净，或存在绕过它的晚调路径。
                Some(ForeignClear::MayLeaveSlotPopulated) => {
                    guard_defeated = true;
                    assumptions
                        .push("registration guard defeated by foreign clear evidence".to_owned());
                    by_shape
                }
                Some(ForeignClear::Unresolved) => {
                    assumptions.push("foreign clear effect unresolved".to_owned());
                    Tri::Unresolved
                }
                // 没有外部证据时，guard 只能记缺证，**不能记相容**。
                None => {
                    assumptions.push(
                        "registration guard present but no foreign clear evidence; \
                         guard validity is a foreign-side question"
                            .to_owned(),
                    );
                    Tri::Unresolved
                }
            }
        }
    };

    (by_guard, guard_defeated)
}

/// `ForeignLateUsePossible(Slot, X)`。
///
/// > 同一 registration slot 上存在 retain 与「返回之后 use/invoke」的 may-path。
fn foreign_late_use_possible(
    foreign: Option<&ForeignBehaviorFact>,
    assumptions: &mut Vec<String>,
) -> Tri {
    let Some(fact) = foreign else {
        assumptions.push("no foreign behavior fact for this hand-off".to_owned());
        return Tri::Unresolved;
    };
    match (fact.retention, fact.invocation) {
        (ForeignRetention::NoRetain, _) => Tri::Denied,
        (_, ForeignInvocation::SynchronousInvokeOnly) => Tri::Denied,
        (ForeignRetention::MayRetain, ForeignInvocation::MayInvokeAfterReturn) => Tri::Possible,
        (ForeignRetention::Unresolved, _) => {
            assumptions.push("foreign retention unresolved".to_owned());
            Tri::Unresolved
        }
        (_, ForeignInvocation::Unresolved) => {
            assumptions.push("foreign invocation unresolved".to_owned());
            Tri::Unresolved
        }
    }
}

/// 对一个交出点、一类生命周期作出判定。
///
/// `foreign` 为 `None` 即 Rust-only 变体。**Rust-only 不得对 guard 保护的 API 给出
/// 「相容」**——guard 的有效性是外部侧问题。
#[must_use]
pub fn judge(
    rust: &RustContractFact,
    foreign: Option<&ForeignBehaviorFact>,
    subject: LifetimeSubject,
) -> CompatibilityVerdict {
    let mut assumptions = Vec::new();

    // `SameArtifactSlotAndRole`：身份对不上的两侧事实不得组合。
    //
    // 正式联结在 [`crate::join_hand_off`]，这里再挡一道是因为 `judge` 是公开入口：
    // 少了它，任意两条事实都能被凑进来判一次。
    let foreign = match foreign {
        Some(fact) if !rust.hand_off.joins_with(&fact.hand_off) => {
            assumptions.push("foreign fact hand-off identity does not match".to_owned());
            None
        }
        other => other,
    };

    if rust.hand_off.registration_generation == RegistrationGeneration::MultipleStaticSites {
        assumptions.push(
            "the same foreign symbol is registered from more than one static site; \
             attributing a runtime registration to this one needs a witness"
                .to_owned(),
        );
    }
    let (separation, guard_defeated) =
        safe_lifetime_separation_possible(rust, subject, foreign, &mut assumptions);
    let late_use = foreign_late_use_possible(foreign, &mut assumptions);

    let mut evidence_grade = if guard_defeated {
        Some(EvidenceGrade::GuardDefeated)
    } else {
        foreign.and_then(|fact| fact.invoke_evidence)
    };
    let mut witness_obligation = None;

    let static_verdict = match (separation, late_use) {
        (Tri::Denied, _) | (_, Tri::Denied) => {
            evidence_grade = if guard_defeated { evidence_grade } else { None };
            StaticVerdict::CompatibleWithinAnalyzedFragment
        }
        (Tri::Possible, Tri::Possible) => {
            // 降级 Q3 只证明「同槽位存在间接调用点」，不证明存在真实的返回后调用路径。
            // 它的正确输出是缺证加一条反证义务，**不是弱化的不相容结论**。
            if foreign.and_then(|fact| fact.invoke_evidence)
                == Some(EvidenceGrade::SameSlotInvokeCandidate)
            {
                assumptions.push(
                    "late invoke supported only by same-slot indirect call; \
                     reachability must be established by a witness"
                        .to_owned(),
                );
                witness_obligation = Some(WitnessObligation::EstablishLateInvoke);
                StaticVerdict::InsufficientEvidence
            } else {
                // `JointTraceFeasible` 的第五项：路径条件相容。前四项由 `join_hand_off`
                // 负责，这一项只有外部侧看得到。
                //
                // **两条 may-property 分别成立不等于它们能在同一条执行上同时发生。**
                // 保留 store 只落在部分路径上时，那条路径未必就是能走到晚调的那条；
                // 此时给出「不相容」就是把联合命题当成了两个独立命题的合取。
                match foreign.map(|fact| fact.path_compatibility) {
                    Some(ForeignPathCompatibility::RetainOnEveryPath) => {
                        StaticVerdict::SupportedIncompatibility
                    }
                    other => {
                        assumptions.push(match other {
                            Some(ForeignPathCompatibility::RetainOnSomePaths) => {
                                "retention happens on only some returning paths; \
                                 joint trace feasibility not established"
                                    .to_owned()
                            }
                            _ => "path compatibility unresolved".to_owned(),
                        });
                        witness_obligation = Some(WitnessObligation::EstablishJointTrace);
                        StaticVerdict::InsufficientEvidence
                    }
                }
            }
        }
        _ => StaticVerdict::InsufficientEvidence,
    };

    CompatibilityVerdict {
        hand_off: HandOffId::from_keys(&rust.hand_off, foreign.map(|fact| &fact.hand_off)),
        subject,
        static_verdict,
        evidence_grade,
        witness_status: WitnessStatus::NotAttempted,
        witness_obligation,
        assumptions,
    }
}

/// 对一个交出点的两类生命周期分别判定。
///
/// **不要把两者合并成一个结论再报告**——它们的成因不同，反证的构造方式也不同。
#[must_use]
pub fn judge_hand_off(
    rust: &RustContractFact,
    foreign: Option<&ForeignBehaviorFact>,
) -> Vec<CompatibilityVerdict> {
    LifetimeSubject::ALL
        .iter()
        .map(|subject| judge(rust, foreign, *subject))
        .collect()
}

/// 该交出点上是否有任意一类生命周期被判为不相容。
#[must_use]
pub fn hand_off_is_incompatible(verdicts: &[CompatibilityVerdict]) -> bool {
    verdicts
        .iter()
        .any(|verdict| verdict.static_verdict == StaticVerdict::SupportedIncompatibility)
}
