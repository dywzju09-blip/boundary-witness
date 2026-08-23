//! 反证计划的推导（执行计划阶段 5.1，服务创新点 C1）。
//!
//! 输入是一个交出点上的三态判定，输出要么是一份反证计划——它携带由判定**反推**的
//! 最小危险动作序列——要么是一条可计数的拒绝原因。
//!
//! # 合格输入只有三类
//!
//! [implementation plan](../../../docs/roadmap/implementation-plan.md) 的 P4 节固定了
//! 输入接口：[`StaticVerdict::SupportedIncompatibility`]，或者带义务的
//! [`StaticVerdict::InsufficientEvidence`]。**降级 Q3 永不产出不相容结论**，因此第二类
//! 是首期实现的主要输入；若反证阶段只接受不相容判定，首期实现里它将没有合法输入。
//!
//! 义务的存在本身就证明了输入前提：判定器只在两侧分离性均可能、身份五层已联结、缺的
//! 只是晚调可达性或联合轨迹可行性时才挂义务。任何**不带义务**的缺证都不可由反证补上
//! ——缺的是事实，不是一次执行。
//!
//! # 动作序列来自判定，不来自模板
//!
//! research thesis §3 C1 固定了最小动作序列。本模块把序列表示成类型化的步骤列表，
//! 由判定的（subject, admission, guard, evidence）四元组机械推导。生成器消费步骤，
//! adapter 提供中性的 API 表面；两者都不携带「先 drop 什么」这类缺陷知识。

use serde::{Deserialize, Serialize};

use crate::{
    AllocationOwnership, CompatibilityVerdict, EffectiveCaptureAdmission, EvidenceGrade, HandOffId,
    LifetimeSubject, RegistrationGuard, StaticVerdict, WitnessObligation,
};

/// 计划的合格输入类别。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessInputKind {
    /// 两侧证据共同支持不相容。直接合成。
    SupportedIncompatibility,
    /// 缺的只是晚调可达性（降级 Q3 的输出）。
    EstablishLateInvoke,
    /// 身份与两侧 may-property 均成立，但联合轨迹可行性未被静态证明。
    EstablishJointTrace,
}

/// 反证客户端的结构形状。由 Rust 侧契约事实决定，一个形状对应一套生成模板。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessShape {
    /// 允许捕获借用且无 guard：注册在对象失效后仍然存活（没有任何类型把它绑住）。
    BorrowedCaptureEscapingScope,
    /// guard 存在且外部证据表明注销没有真的解除注册：先释放 guard（请求注销），
    /// 再让对象失效，最后经绕过路径触发。
    GuardDefeatedBypass,
    /// `'static` bound 且分配被 wrapper 提前回收：闭包自己拥有堆状态即可。
    AllocationFreedByWrapper,
}

/// 危险动作序列的一步。research thesis §3 C1 的序列，按形状裁剪。
///
/// 步骤只描述**做什么**，不描述对哪个符号做——符号绑定是 adapter（中性 API 表面）
/// 的事。顺序即语义：生成器必须按列表顺序发射语句。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DangerStep {
    /// 创建一个有限生命周期的堆对象作为被捕获的主体。
    ///
    /// 选堆不选栈是为了让独立 oracle 的证据类确定（见
    /// [`ExpectedEvidenceClass`]）：栈对象的失效窗口依赖作用域插桩，堆分配的失效
    /// 由分配器直接回答。
    CreateHeapSubject,
    /// 为 `'static` 形状创建由回调**自己拥有**的堆状态（无捕获借用）。
    CreateOwnedCallbackState,
    /// 构造捕获主体的回调。
    ConstructCapturingCallback,
    /// 通过目标安全 API 注册。
    RegisterThroughSafeApi,
    /// 注册继续存活：本形状没有任何类型把它与主体绑在一起。
    RetainRegistrationBeyondSubject,
    /// 释放 registration guard。这一步**请求**注销；注销是否真的解除注册是外部侧
    /// 结论，正是判定说「guard 被击穿」的那一半。
    ReleaseRegistrationGuard,
    /// 让主体生命周期结束。
    EndSubjectLifetime,
    /// 请求外部组件执行它存储的回调。
    RequestForeignLateInvoke,
    /// 回调实际访问已失效的主体。这一步发生在外部组件内部发起的调用里。
    CallbackAccessesInvalidatedSubject,
}

/// 反证预期产生的独立 oracle 证据类。
///
/// 按 implementation plan P4 的 admissibility 表，「堆分配提前失效」类由堆分配器
/// 检测回答。当前三个形状的主体都落在堆上（[`DangerStep::CreateHeapSubject`] /
/// [`DangerStep::CreateOwnedCallbackState`]），因此只有一个取值；
/// `StackUseAfterScope` 为栈主体模板保留，当前没有生产者。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedEvidenceClass {
    HeapUseAfterFree,
    StackUseAfterScope,
}

/// 计划为什么被拒绝。这些原因是**可计数的覆盖缺口**，不是错误。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessPlanRefusal {
    /// 判定为相容：片段内没有要见证的东西。
    VerdictCompatibleNothingToWitness,
    /// 缺证但没挂任何义务——缺的是事实，不是一次执行，反证补不上。
    InsufficientEvidenceWithoutObligation,
    /// 判定没能关联回 Rust 契约事实，无法选择生成形状。
    RustContractNotCorrelated,
    /// guard 在场但没有「被击穿」的外部证据：安全客户端到不了绕过路径，
    /// 结构上造不出合法的反证。
    GuardPresentWithoutDefeatEvidence,
    /// 分配由外部持有直到注销：结构上不存在「Rust 提前释放」这回事。
    AllocationForeignOwnedUntilUnregister,
    /// 契约事实的组合没有对应模板。宁可不生成——编不过或语义不对的 harness 会把
    /// 「没能验证」伪装成「验证过没问题」。
    NoTemplateForContractShape,
}

impl WitnessPlanRefusal {
    /// 稳定的机器可读 token，供 manifest 分类计数。
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::VerdictCompatibleNothingToWitness => "verdict_compatible_nothing_to_witness",
            Self::InsufficientEvidenceWithoutObligation => {
                "insufficient_evidence_without_obligation"
            }
            Self::RustContractNotCorrelated => "rust_contract_not_correlated",
            Self::GuardPresentWithoutDefeatEvidence => "guard_present_without_defeat_evidence",
            Self::AllocationForeignOwnedUntilUnregister => {
                "allocation_foreign_owned_until_unregister"
            }
            Self::NoTemplateForContractShape => "no_template_for_contract_shape",
        }
    }
}

/// 一份反证计划。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessPlan {
    /// 决定性的计划 id，同时用作产物目录名。
    pub plan_id: String,
    /// 诊断用：让人一眼看出是哪个 Rust API。**不参与联结。**
    pub api_id: String,
    /// 完整交出点身份，回查 joint-verdicts 用。
    pub hand_off: HandOffId,
    pub subject: LifetimeSubject,
    pub input_kind: WitnessInputKind,
    pub shape: HarnessShape,
    /// 按序执行的危险动作。生成器不得增删或重排。
    pub steps: Vec<DangerStep>,
    pub expected_evidence_class: ExpectedEvidenceClass,
    /// 上游判定记录的 sha256，lineage 回查键。
    pub verdict_digest: String,
    /// 判定携带的假设与降级说明，原样带入——读计划的人必须看到它建立在什么假设上。
    pub assumptions: Vec<String>,
}

/// 规划的输入。字段在模块文档与单元测试里有完整的行为约定。
#[derive(Debug)]
pub struct WitnessPlanInput<'a> {
    pub api_id: &'a str,
    pub verdict: &'a CompatibilityVerdict,
    /// 与该判定对应的 Rust 契约事实。模板选择需要它；关不上就是覆盖缺口。
    pub rust_contract: Option<&'a crate::RustContractFact>,
    /// 判定记录的指纹（sha256 hex），由调用方计算。
    pub verdict_digest: String,
}

/// 从一条三态判定推导反证计划。
///
/// 判定语义与本函数的关系是单向的：**本函数只消费判定，永远不改写它**。动态结果
/// 写进 receipt 的 `WitnessStatus`，那是与 [`StaticVerdict`] 正交的维度。
#[must_use]
pub fn plan_witness(input: &WitnessPlanInput<'_>) -> Result<WitnessPlan, WitnessPlanRefusal> {
    let verdict = input.verdict;

    // 第一道门：输入类别。规则与模块文档一一对应，多一类输入都是对 P4 接口的修改。
    let input_kind = match (verdict.static_verdict, verdict.witness_obligation) {
        (StaticVerdict::SupportedIncompatibility, _) => WitnessInputKind::SupportedIncompatibility,
        (StaticVerdict::InsufficientEvidence, Some(WitnessObligation::EstablishLateInvoke)) => {
            WitnessInputKind::EstablishLateInvoke
        }
        (StaticVerdict::InsufficientEvidence, Some(WitnessObligation::EstablishJointTrace)) => {
            WitnessInputKind::EstablishJointTrace
        }
        (StaticVerdict::CompatibleWithinAnalyzedFragment, _) => {
            return Err(WitnessPlanRefusal::VerdictCompatibleNothingToWitness);
        }
        (StaticVerdict::InsufficientEvidence, None) => {
            return Err(WitnessPlanRefusal::InsufficientEvidenceWithoutObligation);
        }
    };

    // 第二道门：形状。需要关联回 Rust 契约事实。
    let contract = input
        .rust_contract
        .ok_or(WitnessPlanRefusal::RustContractNotCorrelated)?;
    let shape = derive_shape(verdict.subject, contract, verdict.evidence_grade)?;

    Ok(WitnessPlan {
        plan_id: build_plan_id(
            &contract.hand_off.safe_entry_instance,
            verdict.subject,
            &input.verdict_digest,
        ),
        api_id: input.api_id.to_owned(),
        hand_off: verdict.hand_off.clone(),
        subject: verdict.subject,
        input_kind,
        shape,
        steps: danger_sequence(shape),
        expected_evidence_class: ExpectedEvidenceClass::HeapUseAfterFree,
        verdict_digest: input.verdict_digest.clone(),
        assumptions: verdict.assumptions.clone(),
    })
}

/// 形状推导。每个分支都对得上一种**能被 safe-only 客户端构造出来**的时序状态；
/// 构造不出来就拒绝，不硬套模板。
fn derive_shape(
    subject: LifetimeSubject,
    contract: &crate::RustContractFact,
    evidence_grade: Option<EvidenceGrade>,
) -> Result<HarnessShape, WitnessPlanRefusal> {
    match subject {
        LifetimeSubject::CapturedReferent => match contract.capture_admission {
            // `'static` 排除借用捕获；能走到这里的判定不可能出自这一格（分离性会被
            // 直接否定），防御性拒绝而不是猜一个形状。
            EffectiveCaptureAdmission::RequiresStaticCapture => {
                Err(WitnessPlanRefusal::NoTemplateForContractShape)
            }
            EffectiveCaptureAdmission::PermitsNonStaticCapture => match contract.guard {
                RegistrationGuard::None => Ok(HarnessShape::BorrowedCaptureEscapingScope),
                RegistrationGuard::TiesSlotToSubject | RegistrationGuard::OwnerDropUnregisters => {
                    // 只有外部证据表明注销被绕过，绕过路径才存在。没有这份证据时，
                    // 安全客户端构造不出「referent 失效而注册有效」——那正是 guard
                    // 的类型承诺，也是 fixture 2 必须保持相容的原因。
                    if evidence_grade == Some(EvidenceGrade::GuardDefeated) {
                        Ok(HarnessShape::GuardDefeatedBypass)
                    } else {
                        Err(WitnessPlanRefusal::GuardPresentWithoutDefeatEvidence)
                    }
                }
                RegistrationGuard::Unresolved => {
                    Err(WitnessPlanRefusal::NoTemplateForContractShape)
                }
            },
            EffectiveCaptureAdmission::ContextDependent | EffectiveCaptureAdmission::Unresolved => {
                Err(WitnessPlanRefusal::NoTemplateForContractShape)
            }
        },
        LifetimeSubject::CallbackAllocation => match contract.allocation {
            AllocationOwnership::RustRetainsAndMayFreeEarly => {
                Ok(HarnessShape::AllocationFreedByWrapper)
            }
            AllocationOwnership::ForeignOwnedUntilUnregister => {
                Err(WitnessPlanRefusal::AllocationForeignOwnedUntilUnregister)
            }
            AllocationOwnership::Unresolved => Err(WitnessPlanRefusal::NoTemplateForContractShape),
        },
    }
}

/// 按形状发射危险动作序列。顺序即语义，见各变种的注释。
fn danger_sequence(shape: HarnessShape) -> Vec<DangerStep> {
    match shape {
        HarnessShape::BorrowedCaptureEscapingScope => vec![
            DangerStep::CreateHeapSubject,
            DangerStep::ConstructCapturingCallback,
            DangerStep::RegisterThroughSafeApi,
            // 没有 guard：注册在对象失效后自然存活，这是缺陷本身。
            DangerStep::RetainRegistrationBeyondSubject,
            DangerStep::EndSubjectLifetime,
            DangerStep::RequestForeignLateInvoke,
            DangerStep::CallbackAccessesInvalidatedSubject,
        ],
        HarnessShape::GuardDefeatedBypass => vec![
            DangerStep::CreateHeapSubject,
            DangerStep::ConstructCapturingCallback,
            DangerStep::RegisterThroughSafeApi,
            // 先释放 guard：注销被请求了，但外部证据表明槽位没有被清干净。
            // 对象只能在 'reg 结束之后失效——这正是该形状必须先 drop guard 的原因。
            DangerStep::ReleaseRegistrationGuard,
            DangerStep::EndSubjectLifetime,
            DangerStep::RequestForeignLateInvoke,
            DangerStep::CallbackAccessesInvalidatedSubject,
        ],
        HarnessShape::AllocationFreedByWrapper => vec![
            DangerStep::CreateOwnedCallbackState,
            // 无捕获：`'static` 闭包自带堆状态。分配的提前释放发生在组件内部
            // （RegisterThroughSafeApi 的实现里），不是客户端的一个步骤。
            DangerStep::RegisterThroughSafeApi,
            DangerStep::RetainRegistrationBeyondSubject,
            DangerStep::RequestForeignLateInvoke,
            DangerStep::CallbackAccessesInvalidatedSubject,
        ],
    }
}

/// 决定性的计划 id。同一输入重复规划得到同一个 id；文件系统安全字符。
fn build_plan_id(
    safe_entry_instance: &str,
    subject: LifetimeSubject,
    verdict_digest: &str,
) -> String {
    let mut sanitized = String::with_capacity(safe_entry_instance.len() + 24);
    for character in safe_entry_instance.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            sanitized.push(character);
        } else {
            sanitized.push('_');
        }
    }
    let subject = match subject {
        LifetimeSubject::CapturedReferent => "captured_referent",
        LifetimeSubject::CallbackAllocation => "callback_allocation",
    };
    let digest_tail: String = verdict_digest.chars().take(8).collect();
    format!("witness_{sanitized}_{subject}_{digest_tail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ForeignBehaviorFact, ForeignClear, ForeignHandOffKey, ForeignInvocation,
        ForeignPathCompatibility, ForeignRetention, RegistrationGeneration, RustContractFact,
        RustHandOffKey,
    };

    const DIGEST: &str = "d41d8cd98f00b204e9800998ecf8427e";

    fn rust_key() -> RustHandOffKey {
        RustHandOffKey {
            rust_artifact: "rust:fixture".to_owned(),
            build_profile: "aarch64-apple-darwin/dev".to_owned(),
            safe_entry_instance: "Registry::register_guarded".to_owned(),
            rust_def_instance: "Registry::register_guarded::<F>".to_owned(),
            call_occurrence: "bb2[0]".to_owned(),
            foreign_symbol: "fixture_register".to_owned(),
            callback_arg_index: 0,
            userdata_arg_index: Some(1),
            registration_key: None,
            registration_generation: RegistrationGeneration::MultipleStaticSites,
        }
    }

    fn contract(guard: RegistrationGuard) -> RustContractFact {
        RustContractFact {
            hand_off: rust_key(),
            capture_admission: EffectiveCaptureAdmission::PermitsNonStaticCapture,
            guard,
            allocation: AllocationOwnership::ForeignOwnedUntilUnregister,
            evidence: Vec::new(),
        }
    }

    fn verdict_for(
        subject: LifetimeSubject,
        verdict_kind: StaticVerdict,
        grade: Option<EvidenceGrade>,
        obligation: Option<WitnessObligation>,
    ) -> CompatibilityVerdict {
        // 判定本体由 judge 的单测负责；这里构造的是规划层的输入形状。
        let foreign = ForeignBehaviorFact {
            hand_off: ForeignHandOffKey {
                foreign_artifact: "foreign:stub".to_owned(),
                build_profile: "aarch64-apple-darwin/dev".to_owned(),
                foreign_symbol: "fixture_register".to_owned(),
                callback_arg_index: 0,
                userdata_arg_index: Some(1),
                registration_key: None,
            },
            retention: ForeignRetention::MayRetain,
            invocation: ForeignInvocation::MayInvokeAfterReturn,
            clear: match grade {
                Some(EvidenceGrade::GuardDefeated) => ForeignClear::MayLeaveSlotPopulated,
                _ => ForeignClear::Unresolved,
            },
            path_compatibility: ForeignPathCompatibility::RetainOnEveryPath,
            invoke_evidence: grade,
            evidence: Vec::new(),
        };
        let mut verdict = crate::judge(&contract(RegistrationGuard::None), Some(&foreign), subject);
        // 覆盖判定取值以覆盖规划的每条分支——judge 自己的输出空间由它自己的测试钉死。
        verdict.static_verdict = verdict_kind;
        verdict.evidence_grade = grade;
        verdict.witness_obligation = obligation;
        verdict
    }

    fn plan(
        subject: LifetimeSubject,
        verdict_kind: StaticVerdict,
        grade: Option<EvidenceGrade>,
        obligation: Option<WitnessObligation>,
        guard: RegistrationGuard,
    ) -> Result<WitnessPlan, WitnessPlanRefusal> {
        let verdict = verdict_for(subject, verdict_kind, grade, obligation);
        let contract = contract(guard);
        plan_witness(&WitnessPlanInput {
            api_id: "api:test",
            verdict: &verdict,
            rust_contract: Some(&contract),
            verdict_digest: DIGEST.to_owned(),
        })
    }

    #[test]
    fn direct_incompatibility_plans_an_escaping_scope_witness() {
        let outcome = plan(
            LifetimeSubject::CapturedReferent,
            StaticVerdict::SupportedIncompatibility,
            Some(EvidenceGrade::PathSupportedLateInvoke),
            None,
            RegistrationGuard::None,
        );
        let witness_plan = outcome.expect("无 guard + 允许捕获借用是第一类合格形状");
        assert_eq!(
            witness_plan.shape,
            HarnessShape::BorrowedCaptureEscapingScope
        );
        assert_eq!(
            witness_plan.input_kind,
            WitnessInputKind::SupportedIncompatibility
        );
        assert_eq!(
            witness_plan.expected_evidence_class,
            ExpectedEvidenceClass::HeapUseAfterFree
        );
        // 顺序即语义：注册在主体失效之前，触发在失效之后。
        let steps = &witness_plan.steps;
        let register = steps
            .iter()
            .position(|s| *s == DangerStep::RegisterThroughSafeApi)
            .unwrap();
        let end = steps
            .iter()
            .position(|s| *s == DangerStep::EndSubjectLifetime)
            .unwrap();
        let fire = steps
            .iter()
            .position(|s| *s == DangerStep::RequestForeignLateInvoke)
            .unwrap();
        assert!(register < end && end < fire);
        assert!(!steps.contains(&DangerStep::ReleaseRegistrationGuard));
    }

    #[test]
    fn late_invoke_obligation_is_a_legal_input() {
        // 降级 Q3 永不产出不相容结论；它的合法出口就是这条义务。
        let outcome = plan(
            LifetimeSubject::CapturedReferent,
            StaticVerdict::InsufficientEvidence,
            Some(EvidenceGrade::SameSlotInvokeCandidate),
            Some(WitnessObligation::EstablishLateInvoke),
            RegistrationGuard::None,
        );
        let witness_plan = outcome.expect("EstablishLateInvoke 是 P4 的主要首期输入");
        assert_eq!(
            witness_plan.input_kind,
            WitnessInputKind::EstablishLateInvoke
        );
        assert_eq!(
            witness_plan.shape,
            HarnessShape::BorrowedCaptureEscapingScope
        );
    }

    #[test]
    fn joint_trace_obligation_is_a_legal_input() {
        let outcome = plan(
            LifetimeSubject::CapturedReferent,
            StaticVerdict::InsufficientEvidence,
            Some(EvidenceGrade::PathSupportedLateInvoke),
            Some(WitnessObligation::EstablishJointTrace),
            RegistrationGuard::None,
        );
        let witness_plan = outcome.expect("联合轨迹义务由反证补上");
        assert_eq!(
            witness_plan.input_kind,
            WitnessInputKind::EstablishJointTrace
        );
    }

    #[test]
    fn guard_defeat_requires_the_defeat_grade() {
        let defeated = plan(
            LifetimeSubject::CapturedReferent,
            StaticVerdict::InsufficientEvidence,
            Some(EvidenceGrade::GuardDefeated),
            Some(WitnessObligation::EstablishLateInvoke),
            RegistrationGuard::TiesSlotToSubject,
        );
        let witness_plan = defeated.expect("guard 被击穿时绕过路径存在");
        assert_eq!(witness_plan.shape, HarnessShape::GuardDefeatedBypass);
        // 先释放 guard，再让对象失效，最后经绕过路径触发。
        let steps = &witness_plan.steps;
        let release = steps
            .iter()
            .position(|s| *s == DangerStep::ReleaseRegistrationGuard)
            .unwrap();
        let end = steps
            .iter()
            .position(|s| *s == DangerStep::EndSubjectLifetime)
            .unwrap();
        let fire = steps
            .iter()
            .position(|s| *s == DangerStep::RequestForeignLateInvoke)
            .unwrap();
        assert!(release < end && end < fire);

        // 非空性检查：同一契约形状但证据不是 GuardDefeated 时必须拒绝——
        // 没有击穿证据就没有安全客户端到得了的绕过路径。
        let unevidenced = plan(
            LifetimeSubject::CapturedReferent,
            StaticVerdict::InsufficientEvidence,
            Some(EvidenceGrade::ReachableMayInvoke),
            Some(WitnessObligation::EstablishJointTrace),
            RegistrationGuard::TiesSlotToSubject,
        );
        assert_eq!(
            unevidenced,
            Err(WitnessPlanRefusal::GuardPresentWithoutDefeatEvidence)
        );
    }

    #[test]
    fn allocation_freed_by_wrapper_plans_an_owned_state_witness() {
        let mut allocation_contract = contract(RegistrationGuard::None);
        allocation_contract.allocation = AllocationOwnership::RustRetainsAndMayFreeEarly;
        let verdict = verdict_for(
            LifetimeSubject::CallbackAllocation,
            StaticVerdict::SupportedIncompatibility,
            None,
            None,
        );
        let outcome = plan_witness(&WitnessPlanInput {
            api_id: "api:test",
            verdict: &verdict,
            rust_contract: Some(&allocation_contract),
            verdict_digest: DIGEST.to_owned(),
        });
        let witness_plan = outcome.expect("分配提前释放是 fixture 4 的形状");
        assert_eq!(witness_plan.shape, HarnessShape::AllocationFreedByWrapper);
        // `'static` 形状没有捕获借用步骤，也没有对象失效步骤——释放发生在组件内部。
        assert!(
            !witness_plan
                .steps
                .contains(&DangerStep::ConstructCapturingCallback)
        );
        assert!(!witness_plan.steps.contains(&DangerStep::EndSubjectLifetime));
        assert!(
            witness_plan
                .steps
                .contains(&DangerStep::CreateOwnedCallbackState)
        );
    }

    #[test]
    fn compatible_verdicts_are_refused() {
        let outcome = plan(
            LifetimeSubject::CapturedReferent,
            StaticVerdict::CompatibleWithinAnalyzedFragment,
            None,
            None,
            RegistrationGuard::None,
        );
        assert_eq!(
            outcome,
            Err(WitnessPlanRefusal::VerdictCompatibleNothingToWitness)
        );
    }

    #[test]
    fn bare_insufficient_evidence_is_refused() {
        // 非空性检查：把义务去掉，同一份缺证立即从「可计划」变成「不可计划」。
        // 反证补的是一次执行，不是缺失的事实。
        let with_obligation = plan(
            LifetimeSubject::CapturedReferent,
            StaticVerdict::InsufficientEvidence,
            Some(EvidenceGrade::SameSlotInvokeCandidate),
            Some(WitnessObligation::EstablishLateInvoke),
            RegistrationGuard::None,
        );
        assert!(with_obligation.is_ok());
        let without_obligation = plan(
            LifetimeSubject::CapturedReferent,
            StaticVerdict::InsufficientEvidence,
            Some(EvidenceGrade::SameSlotInvokeCandidate),
            None,
            RegistrationGuard::None,
        );
        assert_eq!(
            without_obligation,
            Err(WitnessPlanRefusal::InsufficientEvidenceWithoutObligation)
        );
    }

    #[test]
    fn missing_correlation_is_refused() {
        let verdict = verdict_for(
            LifetimeSubject::CapturedReferent,
            StaticVerdict::SupportedIncompatibility,
            None,
            None,
        );
        let outcome = plan_witness(&WitnessPlanInput {
            api_id: "api:test",
            verdict: &verdict,
            rust_contract: None,
            verdict_digest: DIGEST.to_owned(),
        });
        assert_eq!(outcome, Err(WitnessPlanRefusal::RustContractNotCorrelated));
    }

    #[test]
    fn foreign_owned_allocation_is_structurally_unwitnessable() {
        let outcome = plan(
            LifetimeSubject::CallbackAllocation,
            StaticVerdict::SupportedIncompatibility,
            None,
            None,
            RegistrationGuard::None,
        );
        // 契约里 allocation 仍是 ForeignOwnedUntilUnregister（默认构造），而判定的
        // subject 是 CallbackAllocation：分配由外部持有，结构上造不出「Rust 提前释放」。
        assert_eq!(
            outcome,
            Err(WitnessPlanRefusal::AllocationForeignOwnedUntilUnregister)
        );
    }

    #[test]
    fn plan_ids_are_deterministic_and_subject_scoped() {
        let first = plan(
            LifetimeSubject::CapturedReferent,
            StaticVerdict::SupportedIncompatibility,
            Some(EvidenceGrade::PathSupportedLateInvoke),
            None,
            RegistrationGuard::None,
        )
        .expect("shape ok");
        let second = plan(
            LifetimeSubject::CapturedReferent,
            StaticVerdict::SupportedIncompatibility,
            Some(EvidenceGrade::PathSupportedLateInvoke),
            None,
            RegistrationGuard::None,
        )
        .expect("shape ok");
        assert_eq!(first.plan_id, second.plan_id);
        assert!(first.plan_id.ends_with("d41d8cd9"));
    }
}
