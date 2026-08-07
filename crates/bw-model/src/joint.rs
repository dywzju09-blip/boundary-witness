//! 两侧事实的精确联结与联合轨迹。
//!
//! # 联结是判定的前提，不是判定的一部分
//!
//! `SupportedIncompatibility` 读起来是「存在一条安全客户端轨迹，让 X 失效而注册仍有效，
//! 且外部随后使用它」。这是**一条轨迹上的联合命题**。两侧各自的 may-property 分别成立
//! 并不蕴含它——见 [research thesis](../../../docs/project/research-thesis.md) §2.5 的
//! `JointTraceFeasible`。
//!
//! 该命题拆成五项，前四项由本模块的联结负责，第五项由判定负责：
//!
//! | # | 项 | 由谁回答 |
//! | --- | --- | --- |
//! | 1 | 同一构建 | [`join_hand_off`] |
//! | 2 | 同一交出点 | [`join_hand_off`] |
//! | 3 | 同一符号与参数角色 | [`join_hand_off`] |
//! | 4 | 同一注册代次 | [`join_hand_off`] |
//! | 5 | 路径条件相容 | [`crate::judge`] |
//!
//! # 兜底联结一律禁止
//!
//! [ADR-0003](../../../docs/decisions/ADR-0003-target-verifier-dataflow-and-identity.md)
//! 第五条：源码位置、span、函数名、API 名、候选 ID 只能作诊断字段。本模块不提供任何按
//! 名字近似匹配的入口——差一点就该拒绝，拒绝会被计数，近似匹配不会。

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    CompatibilityVerdict, ForeignBehaviorFact, ForeignHandOffKey, ForeignRetention, HandOffId,
    RegistrationGeneration, RustContractFact, RustHandOffKey, SlotId, judge_hand_off,
};

impl HandOffId {
    /// 从两侧半键合成完整身份。
    ///
    /// **只应在联结校验通过后调用。** 外部侧缺席时（Rust-only 变体）外部那几段填空串，
    /// 这样的身份只能用于诊断输出，不得再拿去联结。
    #[must_use]
    pub fn from_keys(rust: &RustHandOffKey, foreign: Option<&ForeignHandOffKey>) -> Self {
        Self {
            rust_artifact: rust.rust_artifact.clone(),
            foreign_artifact: foreign
                .map(|key| key.foreign_artifact.clone())
                .unwrap_or_default(),
            build_profile: rust.build_profile.clone(),
            safe_entry_instance: rust.safe_entry_instance.clone(),
            rust_def_instance: rust.rust_def_instance.clone(),
            call_occurrence: rust.call_occurrence.clone(),
            foreign_symbol: rust.foreign_symbol.clone(),
            callback_arg_index: rust.callback_arg_index,
            userdata_arg_index: rust.userdata_arg_index,
            registration_key: rust.registration_key.clone(),
            registration_generation: rust.registration_generation,
        }
    }
}

impl RustHandOffKey {
    /// 两侧半键的重叠部分是否一致。
    ///
    /// 只看重叠部分：构建配置、符号与三项参数角色。artifact 各是各的，代次只有 Rust 侧
    /// 有，都不参与这一步。
    #[must_use]
    pub fn joins_with(&self, foreign: &ForeignHandOffKey) -> bool {
        self.build_profile == foreign.build_profile
            && self.foreign_symbol == foreign.foreign_symbol
            && self.callback_arg_index == foreign.callback_arg_index
            && self.userdata_arg_index == foreign.userdata_arg_index
            && self.registration_key == foreign.registration_key
    }
}

/// 联结被拒绝的原因。
///
/// **每一类分开保留**：attrition waterfall 要区分「构建对不上」「符号对不上」「代次分不
/// 开」，把它们合并成「联结失败」等于丢掉全部诊断价值。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinRejection {
    /// 两侧不是同一次构建。切 feature、target 或优化级别都会走到这里。
    BuildProfileMismatch,
    /// 外部符号不同。这是最基本的一条：两侧根本没在谈同一个函数。
    ForeignSymbolMismatch,
    /// 回调参数位置不同。
    CallbackRoleMismatch,
    /// user data 参数位置不同。**不能因为「回调对上了」就放过它**——同一符号上多组
    /// callback/userdata 串线正是这一条要挡的。
    UserDataRoleMismatch,
    /// 同一符号上的注册槽位键不同。
    RegistrationKeyMismatch,
    /// 注册代次尚未判定。不知道代次就无法把证据归属到任何一次注册。
    GenerationUnresolved,
    /// 外部侧没有槽位证据，而保留与否又没有结论。
    ///
    /// **保留被证否（`NoRetain`）时不走这里**：那时「没有槽位」是结论而不是缺口。
    MissingSlotEvidence,
}

/// 一条联合轨迹：两侧事实在同一身份上合流之后的完整结论。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointTrace {
    pub hand_off: HandOffId,
    /// 外部侧证据落在的槽位。保留被证否时为空。
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub slots: BTreeSet<SlotId>,
    /// 两类生命周期各一条判定。**不要合并成一个结论再报告。**
    pub verdicts: Vec<CompatibilityVerdict>,
}

/// 联结的结果。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum JoinOutcome {
    Joined(Box<JointTrace>),
    /// 拒绝。保留两侧半键，报告要说清楚是拿什么去对什么。
    Rejected {
        rust: Box<RustHandOffKey>,
        foreign: Box<ForeignHandOffKey>,
        reasons: Vec<JoinRejection>,
    },
}

/// 按分层身份精确联结一个交出点的两侧事实。
///
/// `slots` 是外部侧 Q1 找到的槽位集合，由调用方从外部侧分析结果传入——它不在
/// [`ForeignBehaviorFact`] 里，因为那是行为结论而这是身份。
///
/// # 拒绝优先于猜测
///
/// 任何一层对不上都拒绝，并把**全部**不匹配的层一次列出，而不是遇到第一条就返回。
/// 只报第一条会让排查变成反复试错。
#[must_use]
pub fn join_hand_off(
    rust: &RustContractFact,
    foreign: &ForeignBehaviorFact,
    slots: &BTreeSet<SlotId>,
) -> JoinOutcome {
    let mut reasons = Vec::new();
    let rust_key = &rust.hand_off;
    let foreign_key = &foreign.hand_off;

    if rust_key.build_profile != foreign_key.build_profile {
        reasons.push(JoinRejection::BuildProfileMismatch);
    }
    if rust_key.foreign_symbol != foreign_key.foreign_symbol {
        reasons.push(JoinRejection::ForeignSymbolMismatch);
    }
    if rust_key.callback_arg_index != foreign_key.callback_arg_index {
        reasons.push(JoinRejection::CallbackRoleMismatch);
    }
    if rust_key.userdata_arg_index != foreign_key.userdata_arg_index {
        reasons.push(JoinRejection::UserDataRoleMismatch);
    }
    if rust_key.registration_key != foreign_key.registration_key {
        reasons.push(JoinRejection::RegistrationKeyMismatch);
    }
    match rust_key.registration_generation {
        // 多个注册点不阻止联结：外部行为对每个注册点一样成立，判定里记一条假设即可。
        RegistrationGeneration::UniqueStaticSite | RegistrationGeneration::MultipleStaticSites => {}
        RegistrationGeneration::Unresolved => {
            reasons.push(JoinRejection::GenerationUnresolved);
        }
    }
    // 槽位为空只有在「保留被证否」时是合法结论；否则是缺口。
    if slots.is_empty() && foreign.retention != ForeignRetention::NoRetain {
        reasons.push(JoinRejection::MissingSlotEvidence);
    }

    if !reasons.is_empty() {
        return JoinOutcome::Rejected {
            rust: Box::new(rust_key.clone()),
            foreign: Box::new(foreign_key.clone()),
            reasons,
        };
    }

    JoinOutcome::Joined(Box::new(JointTrace {
        hand_off: HandOffId::from_keys(rust_key, Some(foreign_key)),
        slots: slots.clone(),
        verdicts: judge_hand_off(rust, Some(foreign)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AllocationOwnership, EffectiveCaptureAdmission, EvidenceGrade, ForeignClear,
        ForeignInvocation, ForeignPathCompatibility, RegistrationGuard, StaticVerdict,
        WitnessObligation,
    };

    fn rust_key() -> RustHandOffKey {
        RustHandOffKey {
            rust_artifact: "rust:abc".to_owned(),
            build_profile: "x86_64-unknown-linux-gnu/dev".to_owned(),
            safe_entry_instance: "Registry::register_borrowed".to_owned(),
            rust_def_instance: "Registry::register_borrowed::<F>".to_owned(),
            call_occurrence: "bb2[0]".to_owned(),
            foreign_symbol: "fixture_register".to_owned(),
            callback_arg_index: 0,
            userdata_arg_index: Some(1),
            registration_key: None,
            registration_generation: RegistrationGeneration::UniqueStaticSite,
        }
    }

    fn foreign_key() -> ForeignHandOffKey {
        ForeignHandOffKey {
            foreign_artifact: "foreign:def".to_owned(),
            build_profile: "x86_64-unknown-linux-gnu/dev".to_owned(),
            foreign_symbol: "fixture_register".to_owned(),
            callback_arg_index: 0,
            userdata_arg_index: Some(1),
            registration_key: None,
        }
    }

    fn rust_fact() -> RustContractFact {
        RustContractFact {
            hand_off: rust_key(),
            capture_admission: EffectiveCaptureAdmission::PermitsNonStaticCapture,
            guard: RegistrationGuard::None,
            allocation: AllocationOwnership::ForeignOwnedUntilUnregister,
            evidence: Vec::new(),
        }
    }

    fn foreign_fact() -> ForeignBehaviorFact {
        ForeignBehaviorFact {
            hand_off: foreign_key(),
            retention: ForeignRetention::MayRetain,
            invocation: ForeignInvocation::MayInvokeAfterReturn,
            clear: ForeignClear::Unresolved,
            path_compatibility: ForeignPathCompatibility::RetainOnEveryPath,
            invoke_evidence: Some(EvidenceGrade::PathSupportedLateInvoke),
            evidence: Vec::new(),
        }
    }

    fn slots() -> BTreeSet<SlotId> {
        BTreeSet::from([SlotId::global("g_callback")])
    }

    fn rejections(outcome: &JoinOutcome) -> Vec<JoinRejection> {
        match outcome {
            JoinOutcome::Rejected { reasons, .. } => reasons.clone(),
            JoinOutcome::Joined(_) => Vec::new(),
        }
    }

    #[test]
    fn matching_identities_join() {
        let outcome = join_hand_off(&rust_fact(), &foreign_fact(), &slots());
        let JoinOutcome::Joined(trace) = outcome else {
            panic!("expected a join");
        };
        assert_eq!(trace.hand_off.rust_artifact, "rust:abc");
        assert_eq!(trace.hand_off.foreign_artifact, "foreign:def");
        assert_eq!(trace.slots, slots());
        assert_eq!(trace.verdicts.len(), 2);
    }

    #[test]
    fn a_build_mismatch_is_rejected() {
        // 同一份源码换个 profile 编出来的外部产物，行为可能完全不同。
        let mut foreign = foreign_fact();
        foreign.hand_off.build_profile = "x86_64-unknown-linux-gnu/release".to_owned();
        let outcome = join_hand_off(&rust_fact(), &foreign, &slots());
        assert_eq!(rejections(&outcome), [JoinRejection::BuildProfileMismatch]);
    }

    #[test]
    fn a_crossed_user_data_role_is_rejected_even_when_the_callback_matches() {
        // 同一符号上多组 callback/userdata 串线：回调对上了不等于可以联结。
        let mut foreign = foreign_fact();
        foreign.hand_off.userdata_arg_index = Some(2);
        let outcome = join_hand_off(&rust_fact(), &foreign, &slots());
        assert_eq!(rejections(&outcome), [JoinRejection::UserDataRoleMismatch]);
    }

    #[test]
    fn multiple_static_sites_still_join_but_record_the_assumption() {
        // **这一条来自一次真实的错判。** 早先「同一符号有多个注册点」被当成拒绝理由，
        // 结果 fixture crate 的四个交出点全被拒，整条流水线产出零判定——而任何有一个
        // 以上注册 API 的真实 crate 都是这个形状。
        //
        // 外部侧的行为结论描述的是外部函数的代码，对每个注册点一样成立；安全客户端也
        // 完全可以只调其中一个。真正分不开的是运行期的重复注册，那是反证的事。
        let mut rust = rust_fact();
        rust.hand_off.registration_generation = RegistrationGeneration::MultipleStaticSites;
        let JoinOutcome::Joined(trace) = join_hand_off(&rust, &foreign_fact(), &slots()) else {
            panic!("多个静态注册点不应阻止联结");
        };
        assert!(
            trace.verdicts.iter().any(|verdict| verdict
                .assumptions
                .iter()
                .any(|note| note.contains("more than one static site"))),
            "放行必须留下假设记录：{:?}",
            trace.verdicts
        );
    }

    #[test]
    fn an_unresolved_generation_is_rejected() {
        // 不知道代次就无法把证据归属到任何一次注册。
        let mut rust = rust_fact();
        rust.hand_off.registration_generation = RegistrationGeneration::Unresolved;
        let outcome = join_hand_off(&rust, &foreign_fact(), &slots());
        assert_eq!(rejections(&outcome), [JoinRejection::GenerationUnresolved]);
    }

    #[test]
    fn every_mismatched_layer_is_listed_at_once() {
        // 只报第一条会把排查变成反复试错。
        let mut foreign = foreign_fact();
        foreign.hand_off.build_profile = "other".to_owned();
        foreign.hand_off.foreign_symbol = "other_register".to_owned();
        foreign.hand_off.callback_arg_index = 3;
        let outcome = join_hand_off(&rust_fact(), &foreign, &slots());
        assert_eq!(
            rejections(&outcome),
            [
                JoinRejection::BuildProfileMismatch,
                JoinRejection::ForeignSymbolMismatch,
                JoinRejection::CallbackRoleMismatch,
            ]
        );
    }

    #[test]
    fn missing_slot_evidence_is_rejected_when_retention_is_unresolved() {
        let mut foreign = foreign_fact();
        foreign.retention = ForeignRetention::Unresolved;
        let outcome = join_hand_off(&rust_fact(), &foreign, &BTreeSet::new());
        assert_eq!(rejections(&outcome), [JoinRejection::MissingSlotEvidence]);
    }

    #[test]
    fn a_proven_absence_of_retention_joins_without_slots() {
        // 负对照：外部不保存，因此没有槽位。这是**结论**，不是缺口，必须能联结出
        // 「相容」——否则负对照永远拿不到答案。
        let mut foreign = foreign_fact();
        foreign.retention = ForeignRetention::NoRetain;
        foreign.invocation = ForeignInvocation::SynchronousInvokeOnly;
        let outcome = join_hand_off(&rust_fact(), &foreign, &BTreeSet::new());
        let JoinOutcome::Joined(trace) = outcome else {
            panic!("expected a join, got {outcome:?}");
        };
        assert!(trace.slots.is_empty());
        assert!(trace.verdicts.iter().all(
            |verdict| verdict.static_verdict == StaticVerdict::CompatibleWithinAnalyzedFragment
        ));
    }

    #[test]
    fn an_unprovable_path_condition_attaches_a_joint_trace_obligation() {
        // 前四层都对上了，但保留只发生在部分路径上——**联合轨迹没有被证明**。
        // 真实的 `sqlite3_update_hook` 就是这个形状（入口参数校验的提前返回）。
        let mut foreign = foreign_fact();
        foreign.path_compatibility = ForeignPathCompatibility::RetainOnSomePaths;
        let JoinOutcome::Joined(trace) = join_hand_off(&rust_fact(), &foreign, &slots()) else {
            panic!("identity layers all match, so it must join");
        };
        let referent = &trace.verdicts[0];
        assert_eq!(referent.static_verdict, StaticVerdict::InsufficientEvidence);
        assert_eq!(
            referent.witness_obligation,
            Some(WitnessObligation::EstablishJointTrace)
        );
    }
}
