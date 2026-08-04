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
        AllocationOwnership, EffectiveCaptureAdmission, RegistrationGuard, SafeEntryLineage,
    },
};

/// 交出点身份：跨越语言边界的那一次调用。
///
/// 两侧事实只有在本身份完全相等时才能组合——这就是关系里的 `SameArtifactSlotAndRole`
/// 那一项。**按函数名、API 名或候选分片联结一律禁止。**
///
/// 当前各字段是占位的稳定字符串。P0 会把 `rust_artifact` / `foreign_artifact` 换成真实
/// 构建产物的 hash、把 `rust_def_instance` 换成单态化实例 id，字段集合不变。
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandOffId {
    pub rust_artifact: String,
    pub rust_def_instance: String,
    pub call_occurrence: String,
    pub foreign_artifact: String,
    pub foreign_symbol: String,
    pub callback_arg_index: u32,
    pub userdata_arg_index: Option<u32>,
    pub registration_key: Option<String>,
    pub build_profile: String,
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
    pub hand_off: HandOffId,
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
/// # `HandOffId` 是占位的
///
/// 当前只填得出 Rust 侧那几段；`foreign_artifact` / `foreign_symbol` 等要等 P0 接上
/// 外部构建才有真值。装配出的事实因此**只能用于 Rust 侧回归**，不能直接进 P3 的
/// 联结——那需要完整身份。
#[must_use]
pub fn assemble_rust_contract_facts(
    facts: &[StaticFactEnvelope],
    hand_off_id: &dyn Fn(&str, &str) -> HandOffId,
) -> Vec<RustContractAssembly> {
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Parts {
        admission: Option<EffectiveCaptureAdmission>,
        guard: Option<RegistrationGuard>,
        allocation: Option<AllocationOwnership>,
        lineage: Option<SafeEntryLineage>,
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
                parts.evidence.push(fact.site_id.to_string());
            }
            _ => {}
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
            if !gaps.is_empty() {
                return RustContractAssembly::Gap {
                    api_id,
                    callback_param,
                    gaps,
                };
            }
            let mut evidence = parts.evidence;
            evidence.sort();
            RustContractAssembly::Assembled(Box::new(RustContractFact {
                hand_off: hand_off_id(&api_id, &callback_param),
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

/// 外部侧行为事实。
///
/// **PF 阶段这些取值由 matched fixture 的 C stub 手工标注**，即评估设计里的
/// `manual foreign oracle` 变体。P1/P2 会把它们换成从真实构建的 LLVM IR 推导的结果；
/// 关系本身不因来源改变。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignBehaviorFact {
    pub hand_off: HandOffId,
    pub retention: ForeignRetention,
    pub invocation: ForeignInvocation,
    pub clear: ForeignClear,
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

    // `SameArtifactSlotAndRole`：身份不等的两侧事实不得组合。
    let foreign = match foreign {
        Some(fact) if fact.hand_off != rust.hand_off => {
            assumptions.push("foreign fact hand-off identity does not match".to_owned());
            None
        }
        other => other,
    };

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
                StaticVerdict::SupportedIncompatibility
            }
        }
        _ => StaticVerdict::InsufficientEvidence,
    };

    CompatibilityVerdict {
        hand_off: rust.hand_off.clone(),
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
