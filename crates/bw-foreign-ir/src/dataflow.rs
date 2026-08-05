//! 函数内的值来源与路径信息。
//!
//! # 为什么这点分析就够
//!
//! 目标 IR 是 **-O0 且带 debug info** 的（cargo dev profile 下 `cc` 的默认）。这种 IR 里
//! 形参先被 `store` 进 `alloca`、用的时候再 `load` 回来，数据流是**显式**的：没有
//! mem2reg、没有 SROA、没有内联把它揉碎。因此「参数流到哪个 store」这件事只需要一层
//! 通过单赋值 alloca 的传播就能解，不需要通用的指针分析。
//!
//! **换 profile 这个前提就不成立。** -O2 下 alloca 会被消掉、函数会被内联，那时需要的是
//! 另一套分析。分析用的 profile 必须与捕获 IR 时的一致，见阶段 2 的 manifest。
//!
//! # 解不出来一律是未知
//!
//! 任何一步走出上述形状，结果就是 [`ValueOrigin::Unknown`]，并沿数据流传播。下游据此
//! 输出**缺证**，而不是「没有保留」——两者的区别是本项目全部判定纪律的基础。

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::{
    ir::{Function, Inst, InstKind, IrModule, Operand},
    slot::SlotId,
};

/// 一个 SSA 值的来源。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueOrigin {
    /// 本函数的第 n 个形参。
    Param(usize),
    /// 字面 `null`。
    Null,
    /// 从某个跨调用存活的槽位读出。降级 Q3 靠它找间接调用。
    SlotLoad(SlotId),
    /// 解不出来。**不等于「不是形参」**。
    Unknown,
}

/// 这些 intrinsic 收下一个指针不构成逃逸：它们不读也不存这个指针。
///
/// **`llvm.dbg.declare` 必须在这里。** 带 debug info 的 IR 会把每个 alloca 交给它一次；
/// 少了这一条，每个形参都会被判成「逃逸到未知调用」，Q1 将永远得不出结论。
fn is_non_escaping_intrinsic(name: &str) -> bool {
    name.starts_with("llvm.dbg.")
        || name.starts_with("llvm.lifetime.")
        || name.starts_with("llvm.invariant.")
}

/// 一个函数的值来源、槽位寻址与使用点索引。
pub struct FunctionFlow<'a> {
    /// 按函数内序号排布的全部指令。
    insts: Vec<&'a Inst>,
    /// SSA 名 → 来源。
    origins: HashMap<String, ValueOrigin>,
    /// SSA 名 → 该指针指向的槽位（`getelementptr` 与其透传）。
    slots: HashMap<String, SlotId>,
    /// 单赋值 alloca → 存进去的那个值。这是 -O0 形参落栈的还原。
    spills: HashMap<String, Operand>,
    /// SSA 名 → 引用它的指令序号。
    uses: HashMap<String, Vec<usize>>,
    /// 能证明「基址由调用方持有」的槽位指针。
    ///
    /// 槽位**身份**不含基址来源，但 Q1 的「跨调用存活」论证需要它：写进一个本函数内
    /// 新分配的结构体的字段，不构成外部组件保留。
    caller_owned: HashSet<String>,
}

impl<'a> FunctionFlow<'a> {
    #[must_use]
    pub fn new(module: &IrModule, function: &'a Function) -> Self {
        let insts: Vec<&Inst> = function.insts().collect();
        let uses = build_use_index(&insts);
        let spills = find_spill_allocas(&insts, &uses);

        let mut flow = Self {
            insts,
            origins: HashMap::new(),
            slots: HashMap::new(),
            spills,
            uses,
            caller_owned: HashSet::new(),
        };
        for (index, param) in function.params.iter().enumerate() {
            if !param.is_empty() {
                flow.origins
                    .insert(param.clone(), ValueOrigin::Param(index));
            }
        }
        flow.solve(module);
        flow
    }

    /// 来源与槽位寻址一起迭代到不动点。
    ///
    /// 两者互相依赖：`getelementptr` 的基址是不是形参要问来源，而 `load` 出来的值是不是
    /// 槽位读取要问槽位。轮数上界取指令数，`-O0` 下实际两三轮就收敛。
    fn solve(&mut self, module: &IrModule) {
        for _ in 0..=self.insts.len() {
            let mut changed = false;
            for index in 0..self.insts.len() {
                let inst = self.insts[index];
                let Some(result) = inst.result.as_ref() else {
                    continue;
                };
                match &inst.kind {
                    InstKind::Gep {
                        base,
                        base_type,
                        indices,
                    } => {
                        if let Some(slot) = self.gep_slot(module, base, base_type, indices)
                            && self.slots.get(result) != Some(&slot)
                        {
                            self.slots.insert(result.clone(), slot);
                            changed = true;
                        }
                        if self.base_is_caller_owned(base)
                            && self.caller_owned.insert(result.clone())
                        {
                            changed = true;
                        }
                    }
                    InstKind::Cast { src } => {
                        // 指针透传：槽位、来源与 caller-owned 都跟着走。
                        if let Some(slot) = self.pointer_slot(module, src)
                            && self.slots.get(result) != Some(&slot)
                        {
                            self.slots.insert(result.clone(), slot);
                            changed = true;
                        }
                        if self.base_is_caller_owned(src)
                            && self.caller_owned.insert(result.clone())
                        {
                            changed = true;
                        }
                        changed |= self.set_origin(result, self.origin(src));
                    }
                    InstKind::Load { src } => {
                        let origin = self.load_origin(module, src);
                        changed |= self.set_origin(result, origin);
                    }
                    InstKind::Alloca => {}
                    _ => {
                        changed |= self.set_origin(result, ValueOrigin::Unknown);
                    }
                }
            }
            if !changed {
                return;
            }
        }
    }

    fn set_origin(&mut self, name: &str, origin: ValueOrigin) -> bool {
        if self.origins.get(name) == Some(&origin) {
            return false;
        }
        self.origins.insert(name.to_owned(), origin);
        true
    }

    fn load_origin(&self, module: &IrModule, src: &Operand) -> ValueOrigin {
        // 先看是不是形参落栈的那个 alloca——这是 -O0 IR 里最常见的一步。
        if let Some(name) = src.as_local()
            && let Some(spilled) = self.spills.get(name)
        {
            return self.origin(spilled);
        }
        // 再看是不是从跨调用存活的槽位读出。
        match self.pointer_slot(module, src) {
            Some(slot) => ValueOrigin::SlotLoad(slot),
            None => ValueOrigin::Unknown,
        }
    }

    fn gep_slot(
        &self,
        module: &IrModule,
        base: &Operand,
        base_type: &str,
        indices: &[String],
    ) -> Option<SlotId> {
        match base {
            Operand::Global(symbol) => {
                let global = module.globals.get(symbol)?;
                (!global.is_constant).then(|| SlotId {
                    base: crate::slot::SlotBase::Global {
                        symbol: symbol.clone(),
                    },
                    field_path: indices.to_vec(),
                })
            }
            Operand::Local(name) => {
                // 嵌套 gep：在已知槽位上再取字段，索引路径接起来。
                if let Some(parent) = self.slots.get(name) {
                    let mut slot = parent.clone();
                    slot.field_path.extend(indices.iter().cloned());
                    return Some(slot);
                }
                // 结构体字段。**基址从哪来不进身份**——那是 caller-owned 判定的事。
                base_type
                    .starts_with('%')
                    .then(|| SlotId::field(base_type, indices.to_vec()))
            }
            _ => None,
        }
    }

    /// 这个基址能否证明由调用方持有。
    ///
    /// 判据只有三条，都保守：模块级全局；本函数的指针形参；已经证明是调用方持有的
    /// 槽位上再取字段。证不出来就是证不出来，不猜。
    fn base_is_caller_owned(&self, base: &Operand) -> bool {
        match base {
            Operand::Global(_) => true,
            Operand::Local(name) => {
                matches!(self.origins.get(name), Some(ValueOrigin::Param(_)))
                    || self.caller_owned.contains(name)
            }
            _ => false,
        }
    }

    /// 这个槽位指针的基址是否可证明由调用方持有。
    #[must_use]
    pub fn is_caller_owned(&self, pointer: &Operand) -> bool {
        match pointer {
            Operand::Global(_) => true,
            Operand::Local(name) => self.caller_owned.contains(name),
            _ => false,
        }
    }

    /// 这个指针操作数指向的槽位。
    #[must_use]
    pub fn pointer_slot(&self, module: &IrModule, pointer: &Operand) -> Option<SlotId> {
        match pointer {
            Operand::Global(symbol) => module
                .globals
                .get(symbol)
                .filter(|global| !global.is_constant)
                .map(|_| SlotId::global(symbol.clone())),
            Operand::Local(name) => self.slots.get(name).cloned(),
            _ => None,
        }
    }

    /// 操作数的来源。
    #[must_use]
    pub fn origin(&self, operand: &Operand) -> ValueOrigin {
        match operand {
            Operand::Null => ValueOrigin::Null,
            Operand::Local(name) => self
                .origins
                .get(name)
                .cloned()
                .unwrap_or(ValueOrigin::Unknown),
            _ => ValueOrigin::Unknown,
        }
    }

    /// 全部源自第 `index` 个形参的 SSA 名，含形参本身。
    #[must_use]
    pub fn param_aliases(&self, index: usize) -> BTreeSet<String> {
        self.origins
            .iter()
            .filter(|(_, origin)| **origin == ValueOrigin::Param(index))
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// 引用了 `name` 的指令。
    #[must_use]
    pub fn uses_of(&self, name: &str) -> Vec<&'a Inst> {
        self.uses
            .get(name)
            .map(|ordinals| ordinals.iter().map(|index| self.insts[*index]).collect())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn insts(&self) -> &[&'a Inst] {
        &self.insts
    }

    /// 该 alloca 是否是被识别出的单赋值落栈位置。
    #[must_use]
    pub fn is_spill(&self, name: &str) -> bool {
        self.spills.contains_key(name)
    }
}

/// SSA 名 → 引用它的指令序号。
fn build_use_index(insts: &[&Inst]) -> HashMap<String, Vec<usize>> {
    let mut uses: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, inst) in insts.iter().enumerate() {
        for operand in operands_of(inst) {
            if let Operand::Local(name) = operand {
                uses.entry(name.clone()).or_default().push(index);
            }
        }
    }
    uses
}

/// 一条指令引用的全部操作数。**不含结果寄存器。**
///
/// # 认不出的指令也必须进 use 索引
///
/// Q1 的否定结论（「没保留」）建立在**枚举全了这个指针的每一个使用点**之上。如果一条
/// 读取器看不懂的指令用了它却不进索引，这个使用点就成了隐形的，否定结论会建立在「我们
/// 没看见」上——那正是本项目反复要避免的错误。因此认不出的指令退化为扫原文里的 `%`
/// token：宁可多记几个不存在的名字，也不能漏掉一个真实使用点。
fn operands_of(inst: &Inst) -> Vec<Operand> {
    match &inst.kind {
        InstKind::Store { value, dest } => vec![value.clone(), dest.clone()],
        InstKind::Load { src } | InstKind::Cast { src } => vec![src.clone()],
        InstKind::Gep { base, .. } => vec![base.clone()],
        InstKind::Compare { operands } => operands.clone(),
        InstKind::Call { callee, args } => {
            let mut operands = vec![callee.clone()];
            operands.extend(args.iter().cloned());
            operands
        }
        InstKind::Alloca => Vec::new(),
        _ => locals_in_text(&inst.text),
    }
}

/// 扫出一段 IR 原文里出现的全部 `%name`。
///
/// 类型名也以 `%` 开头（`%struct.sqlite3`），会被一并扫进来。多认几个不存在的名字没有
/// 后果——它们不会是任何形参的别名；漏认才有后果。
fn locals_in_text(text: &str) -> Vec<Operand> {
    let mut locals = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        let start = index + 1;
        let mut end = start;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || b"._$-".contains(&bytes[end]))
        {
            end += 1;
        }
        if end > start {
            locals.push(Operand::Local(text[start..end].to_owned()));
        }
        index = end.max(start);
    }
    locals
}

/// 找出「形参落栈」用的单赋值 alloca。
///
/// 判据是保守的：只被 store 一次，其余用途只有 load 和非逃逸 intrinsic。任何一条不满足
/// 就不算，从它 load 出来的值来源为未知。
fn find_spill_allocas(
    insts: &[&Inst],
    uses: &HashMap<String, Vec<usize>>,
) -> HashMap<String, Operand> {
    let mut spills = HashMap::new();
    for inst in insts {
        if inst.kind != InstKind::Alloca {
            continue;
        }
        let Some(name) = inst.result.as_ref() else {
            continue;
        };
        let Some(ordinals) = uses.get(name) else {
            continue;
        };
        let mut stored: Option<Operand> = None;
        let mut disqualified = false;
        for ordinal in ordinals {
            match &insts[*ordinal].kind {
                InstKind::Store { value, dest } if dest.as_local() == Some(name.as_str()) => {
                    if stored.is_some() {
                        disqualified = true;
                    }
                    stored = Some(value.clone());
                }
                InstKind::Load { src } if src.as_local() == Some(name.as_str()) => {}
                InstKind::Call { callee, .. }
                    if callee.as_global().is_some_and(is_non_escaping_intrinsic) => {}
                // 地址被存到别处、被传给真实调用、或被当成值 store——都不再是纯落栈。
                _ => disqualified = true,
            }
            if disqualified {
                break;
            }
        }
        if let Some(value) = stored
            && !disqualified
        {
            spills.insert(name.clone(), value);
        }
    }
    spills
}

/// 函数的路径信息。
#[derive(Clone, Debug, Default)]
pub struct PathInfo {
    /// 从入口出发、**每一条会返回的路径**都必经的块。
    pub on_every_returning_path: BTreeSet<usize>,
    /// CFG 不完整：有读取器不认识的终结指令，或根本没有 `ret`。
    ///
    /// 置位时一切「所有路径」结论都必须降级为未判定。
    pub cfg_incomplete: bool,
}

/// 计算「所有会返回的路径都必经哪些块」。
///
/// 这是入口块的后支配集合。Q4′ 要靠它区分「注销在所有路径上清了槽位」与「只在某个
/// 分支上清了」——后者不足以支撑「guard 有效」。
#[must_use]
pub fn path_info(function: &Function) -> PathInfo {
    let count = function.blocks.len();
    let mut info = PathInfo::default();
    if count == 0 {
        info.cfg_incomplete = true;
        return info;
    }

    let mut successors: Vec<Vec<usize>> = vec![Vec::new(); count];
    let mut exits: Vec<usize> = Vec::new();
    for (index, block) in function.blocks.iter().enumerate() {
        match block.terminator().map(|inst| &inst.kind) {
            Some(InstKind::Branch { targets }) => {
                for target in targets {
                    match function.block_index(target) {
                        Some(successor) => successors[index].push(successor),
                        // 跳到一个不存在的标签：CFG 不可信。
                        None => info.cfg_incomplete = true,
                    }
                }
            }
            Some(InstKind::Return) => exits.push(index),
            Some(InstKind::Unreachable) => {}
            // 没有终结指令，或终结指令读不懂。
            _ => info.cfg_incomplete = true,
        }
    }
    if exits.is_empty() {
        info.cfg_incomplete = true;
        return info;
    }

    // 只有「能到达 ret」的后继才参与。经由 `unreachable` 的路径不返回，不构成
    // 「某条路径漏掉了清槽」的反例。
    let reaches_exit = blocks_reaching_exit(&successors, &exits, count);
    let all: BTreeSet<usize> = (0..count).collect();
    let mut post_dominators: Vec<BTreeSet<usize>> = (0..count)
        .map(|index| {
            if exits.contains(&index) {
                BTreeSet::from([index])
            } else {
                all.clone()
            }
        })
        .collect();

    for _ in 0..=count {
        let mut changed = false;
        for index in (0..count).rev() {
            if exits.contains(&index) || !reaches_exit.contains(&index) {
                continue;
            }
            let live: Vec<usize> = successors[index]
                .iter()
                .copied()
                .filter(|successor| reaches_exit.contains(successor))
                .collect();
            if live.is_empty() {
                continue;
            }
            let mut next = post_dominators[live[0]].clone();
            for successor in &live[1..] {
                next = next
                    .intersection(&post_dominators[*successor])
                    .copied()
                    .collect();
            }
            next.insert(index);
            if next != post_dominators[index] {
                post_dominators[index] = next;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    info.on_every_returning_path = post_dominators[0].clone();
    info
}

fn blocks_reaching_exit(
    successors: &[Vec<usize>],
    exits: &[usize],
    count: usize,
) -> HashSet<usize> {
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); count];
    for (index, targets) in successors.iter().enumerate() {
        for target in targets {
            predecessors[*target].push(index);
        }
    }
    let mut reached: HashSet<usize> = exits.iter().copied().collect();
    let mut worklist: Vec<usize> = exits.to_vec();
    while let Some(block) = worklist.pop() {
        for predecessor in &predecessors[block] {
            if reached.insert(*predecessor) {
                worklist.push(*predecessor);
            }
        }
    }
    reached
}
