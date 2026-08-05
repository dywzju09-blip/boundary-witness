//! Q1 / Q4′ / 降级 Q3 三个查询。
//!
//! 全部结论**只来自 IR**。[`ForeignRoleMap`] 只回答「哪个符号是注册入口、第几个参数是
//! 回调」，不回答「它是否保留、是否晚调、是否清槽」——执行计划阶段 3 的完成条件就是
//! 这一条。
//!
//! # 三个查询靠槽位串起来
//!
//! ```text
//! Q1  回调参数 ─────→ 跨调用存活的槽位集合 S
//! Q4′ 注销入口 ──?──→ S 里的每一个是否都被清空
//! Q3  S 里任意一个 ──load──→ 间接调用点
//! ```
//!
//! **Q4′ 的判别力来自 Q1 找全了 S。** matched fixture 3 的注册函数写了四个槽位、注销只清
//! 了其中两个；只要 Q1 没漏掉后两个，Q4′ 就能把它和 fixture 2 分开。这正是外部侧相对
//! Rust 侧的净贡献所在——Rust 侧两个 fixture 完全相同。

use std::collections::{BTreeMap, BTreeSet};

use bw_model::{
    EvidenceGrade, ForeignBehaviorFact, ForeignClear, ForeignInvocation, ForeignPathCompatibility,
    ForeignRetention, HandOffId,
};
use serde::{Deserialize, Serialize};

use crate::{
    dataflow::{FunctionFlow, PathInfo, ValueOrigin, path_info},
    ir::{Function, InstKind, IrModule, Operand},
    slot::SlotId,
};

/// 外部符号与参数角色。**只用于绑定，不参与行为结论。**
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignRoleMap {
    /// 注册入口的链接符号名。
    pub register_symbol: String,
    /// 回调函数指针在注册入口里的参数下标。
    pub callback_arg_index: usize,
    /// user data 参数下标。没有 user data 的 API 为 `None`。
    #[serde(default)]
    pub userdata_arg_index: Option<usize>,
    /// 注销 / 替换入口。
    ///
    /// 有些 API 没有独立的注销符号，而是**再调一次注册入口并传 null**；那种情况这里填
    /// 注册符号本身，Q4′ 会得出「槽位被实参改写」而不是「被写成字面 null」。
    #[serde(default)]
    pub clear_symbol: Option<String>,
}

/// 被保留的是哪一个。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainedSubject {
    Callback,
    UserData,
}

/// Q1 的一条证据：某个参数在某条 store 指令上进了某个槽位。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionSite {
    pub subject: RetainedSubject,
    pub slot: SlotId,
    pub function: String,
    pub instruction: String,
    /// 该 store 是否在注册入口的每一条会返回的路径上。
    pub on_every_returning_path: bool,
}

/// Q4′ 对单个槽位的结论。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotClearEvidence {
    /// 每一条会返回的路径上都把该槽位写成字面 `null`。
    WritesNullOnEveryPath,
    /// 每一条会返回的路径上都把该槽位改写为清槽入口的回调实参。
    ///
    /// 调用方传 null 即清空。**「传 `None` 注销」这类 API 是这个形状**，它和写死 null
    /// 一样能解除注册，但成立与否取决于调用方，因此单列。
    OverwrittenByArgumentOnEveryPath,
    /// 有写入，但存在一条会返回、却不经过该写入的路径。
    WrittenOnSomePaths,
    /// 清槽入口根本没写这个槽位。**这就是 guard 被击穿的形状。**
    NotWritten,
    /// 有写入，但写进去的值解不出来。
    WrittenWithUnresolvedValue,
}

/// Q4′ 的一条证据。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClearSite {
    pub slot: SlotId,
    pub evidence: SlotClearEvidence,
    pub function: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
}

/// 降级 Q3 的一条证据：从某槽位读出后发生的间接调用。
///
/// **它不证明晚调真的可达**，只证明存在这样一个调用点。升级为可达性是反证义务。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvokeSite {
    pub slot: SlotId,
    pub function: String,
    pub instruction: String,
}

/// 分析走到边界的地方。**每一条都必须留下来**：缺证统计要靠它区分「查过了没有」与
/// 「根本没查到」。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisBoundary {
    pub function: String,
    pub reason: BoundaryReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryReason {
    /// 模块里没有这个符号的定义。
    SymbolNotDefined,
    /// 参数下标超出该函数的形参个数。RoleMap 与 IR 对不上。
    ParamIndexOutOfRange,
    /// 指针被交给读取器无法分析的被调方，可能在那里被保留。
    EscapesToUnknownCallee,
    /// store 的目标指针解析不出槽位。
    StoreToUnresolvedPointer,
    /// 目标槽位所属的对象无法证明由调用方持有，因而无法断言它跨调用存活。
    SlotNotProvenCallerOwned,
    /// 清槽入口写了这个槽位，但存在一条会返回、却不经过该写入的路径。
    ///
    /// 真实 C API 的入口参数校验（`if(!safety_check) return;`）就会产生这种形状。
    /// **它不等于「注销漏了槽位」**，见 [`analyze_clear`]。
    ClearOnlyOnSomePaths,
    /// 指针被读取器不认识的指令使用。
    UsedByUnmodelledInstruction,
    /// CFG 不完整，「所有路径」类结论不可用。
    ControlFlowIncomplete,
    /// RoleMap 没有声明清槽入口。
    NoClearEntryDeclared,
}

/// 一个交出点上从 IR 得到的全部外部侧结论与证据。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignAnalysis {
    pub retention: ForeignRetention,
    pub invocation: ForeignInvocation,
    pub clear: ForeignClear,
    pub path_compatibility: ForeignPathCompatibility,
    pub invoke_evidence: Option<EvidenceGrade>,
    pub slots: BTreeSet<SlotId>,
    pub retention_sites: Vec<RetentionSite>,
    pub clear_sites: Vec<ClearSite>,
    pub invoke_sites: Vec<InvokeSite>,
    pub boundaries: Vec<AnalysisBoundary>,
}

impl ForeignAnalysis {
    /// 装配成模型层的外部侧事实。
    ///
    /// `hand_off` 必须由调用方给出：本 crate 只看外部 IR，凑不齐交出点身份里 Rust 侧
    /// 那一半。**身份不完整就不得进 P3 的联结。**
    #[must_use]
    pub fn into_behavior_fact(self, hand_off: HandOffId) -> ForeignBehaviorFact {
        let mut evidence: Vec<String> = Vec::new();
        for site in &self.retention_sites {
            evidence.push(format!(
                "retain {} in {}: {}",
                site.slot.describe(),
                site.function,
                site.instruction.trim()
            ));
        }
        for site in &self.clear_sites {
            evidence.push(format!(
                "clear {} in {}: {:?}",
                site.slot.describe(),
                site.function,
                site.evidence
            ));
        }
        for site in &self.invoke_sites {
            evidence.push(format!(
                "invoke {} in {}: {}",
                site.slot.describe(),
                site.function,
                site.instruction.trim()
            ));
        }
        for boundary in &self.boundaries {
            evidence.push(format!(
                "boundary {:?} in {}",
                boundary.reason, boundary.function
            ));
        }
        evidence.sort();
        evidence.dedup();
        ForeignBehaviorFact {
            hand_off,
            retention: self.retention,
            invocation: self.invocation,
            clear: self.clear,
            path_compatibility: self.path_compatibility,
            invoke_evidence: self.invoke_evidence,
            evidence,
        }
    }

    /// 什么都没查出来时的结论。**全部是缺证，没有一项是否定结论。**
    fn unresolved(boundaries: Vec<AnalysisBoundary>) -> Self {
        Self {
            retention: ForeignRetention::Unresolved,
            invocation: ForeignInvocation::Unresolved,
            clear: ForeignClear::Unresolved,
            path_compatibility: ForeignPathCompatibility::Unresolved,
            invoke_evidence: None,
            slots: BTreeSet::new(),
            retention_sites: Vec::new(),
            clear_sites: Vec::new(),
            invoke_sites: Vec::new(),
            boundaries,
        }
    }
}

/// 在一个模块上按 RoleMap 跑完 Q1 → Q4′ → 降级 Q3。
#[must_use]
pub fn analyze(module: &IrModule, roles: &ForeignRoleMap) -> ForeignAnalysis {
    let mut boundaries = Vec::new();

    let Some(register) = module.function(&roles.register_symbol) else {
        boundaries.push(AnalysisBoundary {
            function: roles.register_symbol.clone(),
            reason: BoundaryReason::SymbolNotDefined,
            instruction: None,
        });
        return ForeignAnalysis::unresolved(boundaries);
    };
    let flow = FunctionFlow::new(module, register);
    let paths = path_info(register);
    if paths.cfg_incomplete {
        boundaries.push(AnalysisBoundary {
            function: register.name.clone(),
            reason: BoundaryReason::ControlFlowIncomplete,
            instruction: None,
        });
    }

    // ---- Q1：回调与 user data 分别跟到跨调用存活的槽位 ----
    let mut retention_sites = Vec::new();
    let mut escaped = false;
    let mut subjects = vec![(RetainedSubject::Callback, roles.callback_arg_index)];
    if let Some(index) = roles.userdata_arg_index {
        subjects.push((RetainedSubject::UserData, index));
    }
    for (subject, index) in subjects {
        if index >= register.params.len() {
            boundaries.push(AnalysisBoundary {
                function: register.name.clone(),
                reason: BoundaryReason::ParamIndexOutOfRange,
                instruction: None,
            });
            escaped = true;
            continue;
        }
        let found = trace_param(
            module,
            register,
            &flow,
            &paths,
            index,
            roles.callback_arg_index,
            subject,
            &mut boundaries,
        );
        escaped |= found.escaped;
        retention_sites.extend(found.sites);
    }

    let slots: BTreeSet<SlotId> = retention_sites
        .iter()
        .map(|site| site.slot.clone())
        .collect();

    let retention = if !retention_sites.is_empty() {
        ForeignRetention::MayRetain
    } else if escaped {
        // 使用点没枚举全，**不能说「没保留」**。
        ForeignRetention::Unresolved
    } else {
        // 全部使用点都看过了，没有一个到达跨调用存活的存储。
        ForeignRetention::NoRetain
    };

    // ---- Q4′：注销 / 替换是否清空了 Q1 找到的每一个槽位 ----
    let (clear, clear_sites) = analyze_clear(module, roles, &slots, &mut boundaries);

    // ---- 降级 Q3：从同一槽位读出后的间接调用 ----
    let invoke_sites = find_same_slot_invokes(module, &slots);
    let synchronous = has_synchronous_invoke(&flow, roles.callback_arg_index);
    let (invocation, invoke_evidence) = if !invoke_sites.is_empty() {
        (
            ForeignInvocation::MayInvokeAfterReturn,
            Some(EvidenceGrade::SameSlotInvokeCandidate),
        )
    } else if synchronous && slots.is_empty() && !escaped {
        (ForeignInvocation::SynchronousInvokeOnly, None)
    } else {
        (ForeignInvocation::Unresolved, None)
    };

    let path_compatibility = if paths.cfg_incomplete || retention_sites.is_empty() {
        ForeignPathCompatibility::Unresolved
    } else if retention_sites
        .iter()
        .all(|site| site.on_every_returning_path)
    {
        ForeignPathCompatibility::RetainOnEveryPath
    } else {
        ForeignPathCompatibility::RetainOnSomePaths
    };

    ForeignAnalysis {
        retention,
        invocation,
        clear,
        path_compatibility,
        invoke_evidence,
        slots,
        retention_sites,
        clear_sites,
        invoke_sites,
        boundaries,
    }
}

struct ParamTrace {
    sites: Vec<RetentionSite>,
    /// 有使用点走出了分析边界。置位时不得给出「没保留」。
    escaped: bool,
}

/// 枚举某个形参的全部使用点，判断它是否到达跨调用存活的存储。
///
/// **枚举必须是完备的**：只要有一个使用点看不懂，结论就只能是缺证。否则「没保留」这个
/// 否定结论会建立在「我们没看见」之上。
#[allow(clippy::too_many_arguments)]
fn trace_param(
    module: &IrModule,
    register: &Function,
    flow: &FunctionFlow<'_>,
    paths: &PathInfo,
    index: usize,
    callback_arg_index: usize,
    subject: RetainedSubject,
    boundaries: &mut Vec<AnalysisBoundary>,
) -> ParamTrace {
    let mut trace = ParamTrace {
        sites: Vec::new(),
        escaped: false,
    };
    let boundary = |reason: BoundaryReason, instruction: Option<String>| AnalysisBoundary {
        function: register.name.clone(),
        reason,
        instruction,
    };

    for alias in flow.param_aliases(index) {
        for inst in flow.uses_of(&alias) {
            match &inst.kind {
                InstKind::Store { value, dest } if value.as_local() == Some(alias.as_str()) => {
                    if let Some(slot) = flow.pointer_slot(module, dest) {
                        // 槽位身份认出来了，还要能论证它跨调用存活。写进本函数内新分配
                        // 的结构体的字段不构成保留，但也不构成「没保留」。
                        if flow.is_caller_owned(dest) {
                            trace.sites.push(RetentionSite {
                                subject,
                                slot,
                                function: register.name.clone(),
                                instruction: inst.text.clone(),
                                on_every_returning_path: paths
                                    .on_every_returning_path
                                    .contains(&inst.block),
                            });
                        } else {
                            trace.escaped = true;
                            boundaries.push(boundary(
                                BoundaryReason::SlotNotProvenCallerOwned,
                                Some(inst.text.clone()),
                            ));
                        }
                    } else if dest.as_local().is_some_and(|name| flow.is_spill(name)) {
                        // 形参落栈。数据流已经跟住了，不是逃逸。
                    } else {
                        trace.escaped = true;
                        boundaries.push(boundary(
                            BoundaryReason::StoreToUnresolvedPointer,
                            Some(inst.text.clone()),
                        ));
                    }
                }
                // 指针被当成写入目标：改的是它指向的对象，不构成对指针本身的保留。
                // `Cast` 的结果继承来源，会作为别名被重新检查。
                // `Compare` 只是判空，不保留。
                InstKind::Store { .. }
                | InstKind::Load { .. }
                | InstKind::Cast { .. }
                | InstKind::Compare { .. } => {}
                // 指针算术的结果**不继承来源**，因此不会作为别名被重新检查；把它当成
                // 已跟踪会让「偏移之后再存起来」这条保留路径整条隐形。首期记缺证。
                InstKind::Gep { .. } => {
                    trace.escaped = true;
                    boundaries.push(boundary(
                        BoundaryReason::UsedByUnmodelledInstruction,
                        Some(inst.text.clone()),
                    ));
                }
                InstKind::Call { callee, args } => {
                    if callee.as_local() == Some(alias.as_str()) {
                        // 它就是被调用的那个回调，不是被保留。
                        continue;
                    }
                    if callee
                        .as_global()
                        .is_some_and(|name| name.starts_with("llvm.dbg."))
                    {
                        continue;
                    }
                    // 把 user data 交回给正在被调用的那个回调，是注册协议本身的动作，
                    // 不是外部组件保留了它。
                    let handed_to_callback = flow.origin(callee)
                        == ValueOrigin::Param(callback_arg_index)
                        && args
                            .iter()
                            .any(|arg| arg.as_local() == Some(alias.as_str()));
                    if handed_to_callback {
                        continue;
                    }
                    // 其余被调方可能把它存起来，首期不做过程间传播。
                    trace.escaped = true;
                    boundaries.push(boundary(
                        BoundaryReason::EscapesToUnknownCallee,
                        Some(inst.text.clone()),
                    ));
                }
                _ => {
                    trace.escaped = true;
                    boundaries.push(boundary(
                        BoundaryReason::UsedByUnmodelledInstruction,
                        Some(inst.text.clone()),
                    ));
                }
            }
        }
    }
    trace
}

/// Q4′：清槽入口对 Q1 找到的每一个槽位做了什么。
fn analyze_clear(
    module: &IrModule,
    roles: &ForeignRoleMap,
    slots: &BTreeSet<SlotId>,
    boundaries: &mut Vec<AnalysisBoundary>,
) -> (ForeignClear, Vec<ClearSite>) {
    let Some(symbol) = roles.clear_symbol.as_ref() else {
        boundaries.push(AnalysisBoundary {
            function: roles.register_symbol.clone(),
            reason: BoundaryReason::NoClearEntryDeclared,
            instruction: None,
        });
        return (ForeignClear::Unresolved, Vec::new());
    };
    let Some(clear_fn) = module.function(symbol) else {
        boundaries.push(AnalysisBoundary {
            function: symbol.clone(),
            reason: BoundaryReason::SymbolNotDefined,
            instruction: None,
        });
        return (ForeignClear::Unresolved, Vec::new());
    };
    if slots.is_empty() {
        // Q1 没找到槽位时 Q4′ 是空谈。**不能记成「清空了所有路径」**——那会让判定器
        // 把 guard 当成有效保护。
        return (ForeignClear::Unresolved, Vec::new());
    }

    let flow = FunctionFlow::new(module, clear_fn);
    let paths = path_info(clear_fn);
    if paths.cfg_incomplete {
        boundaries.push(AnalysisBoundary {
            function: clear_fn.name.clone(),
            reason: BoundaryReason::ControlFlowIncomplete,
            instruction: None,
        });
        return (ForeignClear::Unresolved, Vec::new());
    }

    // 同一个槽位可能被写多次，取最强的一条证据。
    let mut best: BTreeMap<SlotId, (SlotClearEvidence, String)> = BTreeMap::new();
    for inst in flow.insts() {
        let InstKind::Store { value, dest } = &inst.kind else {
            continue;
        };
        let Some(slot) = flow.pointer_slot(module, dest) else {
            continue;
        };
        if !slots.contains(&slot) {
            continue;
        }
        let on_every_path = paths.on_every_returning_path.contains(&inst.block);
        let evidence = match (flow.origin(value), on_every_path) {
            (_, false) => SlotClearEvidence::WrittenOnSomePaths,
            (ValueOrigin::Null, true) => SlotClearEvidence::WritesNullOnEveryPath,
            (ValueOrigin::Param(index), true) if index == roles.callback_arg_index => {
                SlotClearEvidence::OverwrittenByArgumentOnEveryPath
            }
            // user data 槽位由 user data 实参改写，同样是「调用方传 null 即清空」。
            (ValueOrigin::Param(index), true) if Some(index) == roles.userdata_arg_index => {
                SlotClearEvidence::OverwrittenByArgumentOnEveryPath
            }
            _ => SlotClearEvidence::WrittenWithUnresolvedValue,
        };
        let entry = best.entry(slot).or_insert((evidence, inst.text.clone()));
        if clear_strength(evidence) > clear_strength(entry.0) {
            *entry = (evidence, inst.text.clone());
        }
    }

    let mut sites = Vec::new();
    for slot in slots {
        match best.get(slot) {
            Some((evidence, instruction)) => sites.push(ClearSite {
                slot: slot.clone(),
                evidence: *evidence,
                function: clear_fn.name.clone(),
                instruction: Some(instruction.clone()),
            }),
            None => sites.push(ClearSite {
                slot: slot.clone(),
                evidence: SlotClearEvidence::NotWritten,
                function: clear_fn.name.clone(),
                instruction: None,
            }),
        }
    }

    // 只要有一个槽位**根本没被碰过**，注销就不能解除注册。这是 guard 被击穿的形状，
    // 也是 matched fixture 3 与 fixture 2 的全部差别。
    let leaves_populated = sites
        .iter()
        .any(|site| site.evidence == SlotClearEvidence::NotWritten);

    // 「写了但不在所有路径上」是另一回事，**不能并进上面那一类**。
    //
    // 真实测量：`sqlite3_update_hook` 开头有 `if(!sqlite3SafetyCheckOk(db)) return 0;`，
    // 于是两条 store 都落在「部分路径」上。若把它算成「可能留下槽位」，那么每一个带
    // 入口参数校验的 C API 都会被判成 guard 被击穿——Q4′ 到规模上就没有判别力了。
    // 首期的正确输出是缺证加一条写明原因的边界。
    let written_on_some_paths: Vec<&ClearSite> = sites
        .iter()
        .filter(|site| site.evidence == SlotClearEvidence::WrittenOnSomePaths)
        .collect();
    for site in &written_on_some_paths {
        boundaries.push(AnalysisBoundary {
            function: clear_fn.name.clone(),
            reason: BoundaryReason::ClearOnlyOnSomePaths,
            instruction: site.instruction.clone(),
        });
    }
    let partial = !written_on_some_paths.is_empty();
    let all_cleared = sites.iter().all(|site| {
        matches!(
            site.evidence,
            SlotClearEvidence::WritesNullOnEveryPath
                | SlotClearEvidence::OverwrittenByArgumentOnEveryPath
        )
    });
    let clear = if leaves_populated {
        ForeignClear::MayLeaveSlotPopulated
    } else if partial {
        ForeignClear::Unresolved
    } else if all_cleared {
        ForeignClear::ClearsOnAllPaths
    } else {
        ForeignClear::Unresolved
    };
    (clear, sites)
}

/// 同一槽位上多条写入取「最强」那条：全路径写入强于部分路径写入。
fn clear_strength(evidence: SlotClearEvidence) -> u8 {
    match evidence {
        SlotClearEvidence::NotWritten => 0,
        SlotClearEvidence::WrittenOnSomePaths => 1,
        SlotClearEvidence::WrittenWithUnresolvedValue => 2,
        SlotClearEvidence::OverwrittenByArgumentOnEveryPath => 3,
        SlotClearEvidence::WritesNullOnEveryPath => 4,
    }
}

/// 降级 Q3：全模块扫描「从槽位 load 出来后被间接调用」。
///
/// 扫全模块而不只是某个函数——晚调点通常在派发函数里，与注册入口无关。
fn find_same_slot_invokes(module: &IrModule, slots: &BTreeSet<SlotId>) -> Vec<InvokeSite> {
    let mut sites = Vec::new();
    if slots.is_empty() {
        return sites;
    }
    for function in &module.functions {
        let flow = FunctionFlow::new(module, function);
        for inst in flow.insts() {
            let InstKind::Call { callee, .. } = &inst.kind else {
                continue;
            };
            if !matches!(callee, Operand::Local(_)) {
                continue;
            }
            let ValueOrigin::SlotLoad(slot) = flow.origin(callee) else {
                continue;
            };
            if slots.contains(&slot) {
                sites.push(InvokeSite {
                    slot,
                    function: function.name.clone(),
                    instruction: inst.text.clone(),
                });
            }
        }
    }
    sites
}

/// 注册入口内部是否直接调用了回调参数——同步调用的形状。
fn has_synchronous_invoke(flow: &FunctionFlow<'_>, callback_arg_index: usize) -> bool {
    flow.insts().iter().any(|inst| {
        matches!(&inst.kind, InstKind::Call { callee, .. }
            if matches!(callee, Operand::Local(_))
                && flow.origin(callee) == ValueOrigin::Param(callback_arg_index))
    })
}
