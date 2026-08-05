//! 从真实构建捕获的 LLVM IR 里读取外部组件的**实际行为**。
//!
//! 这是执行计划阶段 3 的实现：回答 Q1（保留到哪个槽位）、Q4′（注销是否真的清槽）和降级
//! Q3（同槽位是否存在间接调用点）。三个查询的结论**只来自 IR**，RoleMap 只负责把符号和
//! 参数角色对上。
//!
//! # 不链接 LLVM
//!
//! LLVM 只以外部命令的身份出现（阶段 2 的 `tools/foreign-ir/cc-capture` 用 `clang
//! -emit-llvm`，读之前用 `llvm-dis` 转文本）。进程内不链接 `llvm-sys`——本项目的编译器
//! 前端链着 `rustc_driver`，它自带一份 LLVM，再链一份会撞上
//! [baseline comparison](../../../docs/experiments/runbooks/baseline-comparison.md) 里
//! 记录的那个冲突。
//!
//! # 分析片段
//!
//! 首期只支持 [execution plan](../../../docs/roadmap/execution-plan.md) 0.1 固定的片段：
//! global / 字段槽位、明确的 null / replace store、-O0 形状的函数内数据流。走出这个片段
//! 一律输出缺证，并在 [`AnalysisBoundary`] 里记下走出的位置和原因。

mod dataflow;
mod ir;
mod query;
mod slot;

pub use dataflow::{PathInfo, ValueOrigin, path_info};
pub use ir::{Block, Function, Global, Inst, InstKind, IrModule, Operand, ParseError};
pub use query::{
    AnalysisBoundary, BoundaryReason, ClearSite, ForeignAnalysis, ForeignRoleMap, InvokeSite,
    RetainedSubject, RetentionSite, SlotClearEvidence, analyze,
};
pub use slot::{SlotBase, SlotId};

/// 解析文本 IR 并按 RoleMap 跑完三个查询。
///
/// 输入是 `llvm-dis` 或 `clang -emit-llvm -S` 的输出。
pub fn analyze_text(text: &str, roles: &ForeignRoleMap) -> Result<ForeignAnalysis, ParseError> {
    let module = IrModule::parse(text)?;
    Ok(analyze(&module, roles))
}
