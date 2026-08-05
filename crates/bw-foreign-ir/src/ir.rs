//! LLVM 文本 IR 的有界读取器。
//!
//! # 为什么读文本而不链接 libLLVM
//!
//! 本项目的编译器前端链着 `rustc_driver`，它自带一份 LLVM。再链 `llvm-sys` 就会撞上
//! [baseline comparison](../../../docs/experiments/runbooks/baseline-comparison.md) 已经
//! 记录过的那个冲突——FFIChecker 正是栽在这里。因此 LLVM 只以**外部命令**的身份出现
//! （`clang -emit-llvm`、`llvm-dis`），进程内不链接任何 LLVM 库。
//!
//! # 这个读取器是有界的
//!
//! 它**不是通用 LLVM IR 解析器**，只认 Q1/Q4′/Q3 需要的那几类指令：`alloca`、`store`、
//! `load`、`getelementptr`、`call` 和终结指令。其余一律归为 [`InstKind::Other`]，其结果
//! 寄存器的来源因此是未知的——这会让下游得出**缺证**而不是错误结论。
//!
//! 认不出的**终结**指令是另一回事：它会破坏 CFG，因此单独记为
//! [`InstKind::UnsupportedTerminator`]，让路径类结论整体降级。

use std::collections::BTreeMap;

/// 指令的一个操作数。
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Operand {
    /// 函数内的 SSA 寄存器或标签，如 `%0`、`%retval`。
    Local(String),
    /// 模块级符号，如 `@g_callback`。
    Global(String),
    /// 字面 `null`。Q4′ 判「清槽」时需要认出它。
    Null,
    /// 其余字面量与读取器不解释的形式（`undef`、整型常量、常量表达式……）。
    Other(String),
}

impl Operand {
    /// 从 `<类型> [属性...] <值>` 这样的片段里取出值。
    ///
    /// 值总是最后一个空白分隔的 token：类型可能含空格（`void (i8*)*`），参数属性也可能
    /// 出现在中间（`i8* noundef %5`），但值永远在末尾。
    fn parse(segment: &str) -> Self {
        let token = segment.split_whitespace().next_back().unwrap_or("");
        Self::from_token(token)
    }

    fn from_token(token: &str) -> Self {
        match token {
            "null" => Self::Null,
            _ => {
                if let Some(name) = token.strip_prefix('%') {
                    Self::Local(name.to_owned())
                } else if let Some(name) = token.strip_prefix('@') {
                    Self::Global(name.to_owned())
                } else {
                    Self::Other(token.to_owned())
                }
            }
        }
    }

    #[must_use]
    pub fn as_local(&self) -> Option<&str> {
        match self {
            Self::Local(name) => Some(name),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_global(&self) -> Option<&str> {
        match self {
            Self::Global(name) => Some(name),
            _ => None,
        }
    }
}

/// 读取器认识的指令种类。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstKind {
    Alloca,
    Store {
        value: Operand,
        dest: Operand,
    },
    Load {
        src: Operand,
    },
    /// `getelementptr`。只保留基址类型与索引，字段槽位的识别在 `slot` 模块。
    Gep {
        base: Operand,
        base_type: String,
        indices: Vec<String>,
    },
    Call {
        callee: Operand,
        args: Vec<Operand>,
    },
    /// 指针透传：`bitcast`、`addrspacecast`、`inttoptr`、`ptrtoint`。
    Cast {
        src: Operand,
    },
    /// `icmp` / `fcmp`。**比较一个指针不构成对它的保留**，因此必须与
    /// [`InstKind::Other`] 区分——否则 `if (callback)` 这种再普通不过的判空会被算成
    /// 逃逸，负对照永远得不出「没保留」。
    Compare {
        operands: Vec<Operand>,
    },
    Branch {
        targets: Vec<String>,
    },
    /// `ret`。CFG 的正常出口。
    Return,
    /// `unreachable`。**不是正常出口**：经由它的路径不返回，因此不参与「所有路径」。
    Unreachable,
    /// 读取器不解释的非终结指令。结果寄存器来源未知。
    Other,
    /// 读取器不认识的**终结**指令（`indirectbr`、`invoke`、`callbr`……）。
    ///
    /// 它会让 CFG 不完整，因此必须让路径类结论降级，不能当成 [`InstKind::Other`]。
    UnsupportedTerminator,
}

/// 一条指令。`text` 保留规范化后的原文，供证据回查。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inst {
    /// 结果寄存器名（不含 `%`）。无结果的指令为 `None`。
    pub result: Option<String>,
    pub kind: InstKind,
    /// 所在基本块在函数内的下标。
    pub block: usize,
    /// 在函数内的全局指令序号，用于稳定引用。
    pub ordinal: usize,
    pub text: String,
}

/// 一个基本块。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    /// 标签名（不含 `%`）。入口块没有显式标签时为 `None`。
    pub label: Option<String>,
    pub insts: Vec<Inst>,
}

impl Block {
    /// 终结指令。格式良好的 IR 里每个块都有一条。
    #[must_use]
    pub fn terminator(&self) -> Option<&Inst> {
        self.insts.last().filter(|inst| {
            matches!(
                inst.kind,
                InstKind::Branch { .. }
                    | InstKind::Return
                    | InstKind::Unreachable
                    | InstKind::UnsupportedTerminator
            )
        })
    }
}

/// 一个有定义的函数。`declare` 出来的外部声明不进这里。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Function {
    pub name: String,
    /// 形参的 SSA 名（不含 `%`），按声明顺序。
    pub params: Vec<String>,
    pub blocks: Vec<Block>,
}

impl Function {
    /// 按标签查块下标。
    #[must_use]
    pub fn block_index(&self, label: &str) -> Option<usize> {
        self.blocks
            .iter()
            .position(|block| block.label.as_deref() == Some(label))
    }

    /// 全部指令，按函数内序。
    pub fn insts(&self) -> impl Iterator<Item = &Inst> {
        self.blocks.iter().flat_map(|block| block.insts.iter())
    }

    /// 形参下标。
    #[must_use]
    pub fn param_index(&self, name: &str) -> Option<usize> {
        self.params.iter().position(|param| param == name)
    }
}

/// 模块级全局变量。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Global {
    pub name: String,
    /// `constant` 而非 `global`。常量不可能是注册槽位。
    pub is_constant: bool,
}

/// 一个 LLVM 模块。
#[derive(Clone, Debug, Default)]
pub struct IrModule {
    pub globals: BTreeMap<String, Global>,
    pub functions: Vec<Function>,
    /// `declare` 的外部符号名。调用它们即离开本模块的分析边界。
    pub declared: Vec<String>,
}

impl IrModule {
    #[must_use]
    pub fn function(&self, name: &str) -> Option<&Function> {
        self.functions.iter().find(|function| function.name == name)
    }

    /// 解析 `llvm-dis` 或 `clang -emit-llvm -S` 产出的文本 IR。
    ///
    /// 读取器不会因为看不懂某一行而失败——看不懂的指令归为 [`InstKind::Other`]，让缺证
    /// 沿着数据流传播。**只有结构性破损（函数体没有闭合）才是错误。**
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut module = Self::default();
        let mut lines = text.lines().enumerate();

        while let Some((line_no, raw)) = lines.next() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with("declare ") {
                if let Some(name) = declared_name(line) {
                    module.declared.push(name);
                }
                continue;
            }
            if let Some(global) = parse_global(line) {
                module.globals.insert(global.name.clone(), global);
                continue;
            }
            if line.starts_with("define ") {
                let header = line;
                let mut body = Vec::new();
                let mut closed = false;
                for (_, raw) in lines.by_ref() {
                    let body_line = strip_comment(raw).trim();
                    if body_line == "}" {
                        closed = true;
                        break;
                    }
                    if !body_line.is_empty() {
                        body.push(body_line.to_owned());
                    }
                }
                if !closed {
                    return Err(ParseError::UnterminatedFunction {
                        line: line_no + 1,
                        header: header.to_owned(),
                    });
                }
                module.functions.push(parse_function(header, &body));
                continue;
            }
        }
        Ok(module)
    }
}

/// 文本 IR 的结构性破损。语义看不懂不算错误，见 [`IrModule::parse`]。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    UnterminatedFunction { line: usize, header: String },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnterminatedFunction { line, header } => {
                write!(
                    formatter,
                    "line {line}: unterminated function body: {header}"
                )
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// 去掉行尾注释。`;` 在 LLVM 文本 IR 里是注释起始，但字符串字面量内除外。
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'"' => in_string = !in_string,
            b';' if !in_string => return &line[..index],
            _ => {}
        }
    }
    line
}

/// 按顶层分隔符切分，跳过成对括号与字符串内部的分隔符。
///
/// **这是必需的**：LLVM 的类型自带逗号（`void (i8*, i32, i8*)*`），按裸逗号切分会把
/// 一个操作数劈成几段。
fn split_top_level(text: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut start = 0usize;
    for (index, character) in text.char_indices() {
        match character {
            '"' => in_string = !in_string,
            '(' | '[' | '{' | '<' if !in_string => depth += 1,
            ')' | ']' | '}' | '>' if !in_string => depth -= 1,
            _ if character == separator && depth == 0 && !in_string => {
                parts.push(&text[start..index]);
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

/// 丢掉 `align 8`、`!dbg !30` 这类不是操作数的尾随片段。
fn is_operand_segment(segment: &str) -> bool {
    let segment = segment.trim();
    !segment.is_empty() && !segment.starts_with('!') && !segment.starts_with("align ")
}

fn declared_name(line: &str) -> Option<String> {
    let at = line.find('@')?;
    let rest = &line[at + 1..];
    let end = rest
        .find(|character: char| character == '(' || character.is_whitespace())
        .unwrap_or(rest.len());
    Some(rest[..end].to_owned())
}

/// `@g_callback = internal global void (i8*)* null, align 8`
fn parse_global(line: &str) -> Option<Global> {
    let name = line.strip_prefix('@')?;
    let (name, rest) = name.split_once('=')?;
    let name = name.trim();
    if name.is_empty() || !rest.contains(" global ") && !rest.contains(" constant ") {
        return None;
    }
    Some(Global {
        name: name.to_owned(),
        is_constant: rest.contains(" constant "),
    })
}

/// 从 `define` 头里取函数名与形参名。
///
/// 形参可能无名（`%0`）也可能有名（`%conn`）；两种都要能对上后续指令里的引用。
fn parse_function(header: &str, body: &[String]) -> Function {
    let name = declared_name(header).unwrap_or_default();
    let params = parse_params(header);

    // 入口块没有显式标签。后续每遇到一个 `label:` 就开一个新块。
    let mut blocks = vec![Block {
        label: None,
        insts: Vec::new(),
    }];
    let mut ordinal = 0usize;
    for line in body {
        if let Some(label) = parse_block_label(line) {
            blocks.push(Block {
                label: Some(label),
                insts: Vec::new(),
            });
            continue;
        }
        let block = blocks.len() - 1;
        let inst = parse_inst(line, block, ordinal);
        ordinal += 1;
        blocks[block].insts.push(inst);
    }
    Function {
        name,
        params,
        blocks,
    }
}

fn parse_params(header: &str) -> Vec<String> {
    let Some(open) = header.find('(') else {
        return Vec::new();
    };
    let rest = &header[open + 1..];
    let mut depth = 0i32;
    let mut close = rest.len();
    for (index, character) in rest.char_indices() {
        match character {
            '(' => depth += 1,
            ')' if depth == 0 => {
                close = index;
                break;
            }
            ')' => depth -= 1,
            _ => {}
        }
    }
    let inner = &rest[..close];
    if inner.trim().is_empty() {
        return Vec::new();
    }
    split_top_level(inner, ',')
        .into_iter()
        .map(|segment| match Operand::parse(segment) {
            Operand::Local(name) => name,
            // 无名形参在 IR 里总有 `%N`；走到这里说明是 `...` 之类，占位保持下标对齐。
            _ => String::new(),
        })
        .collect()
}

/// `3:` 或 `entry:` 这样的块标签行。
fn parse_block_label(line: &str) -> Option<String> {
    let label = line.strip_suffix(':')?;
    if label.is_empty()
        || !label
            .chars()
            .all(|character| character.is_alphanumeric() || "._$-".contains(character))
    {
        return None;
    }
    Some(label.to_owned())
}

fn parse_inst(line: &str, block: usize, ordinal: usize) -> Inst {
    let (result, body) = match line.split_once(" = ") {
        Some((left, right)) if left.starts_with('%') => {
            (Some(left.trim_start_matches('%').to_owned()), right.trim())
        }
        _ => (None, line),
    };
    Inst {
        result,
        kind: parse_inst_kind(body),
        block,
        ordinal,
        text: line.to_owned(),
    }
}

fn parse_inst_kind(body: &str) -> InstKind {
    let opcode = body.split_whitespace().next().unwrap_or("");
    match opcode {
        "alloca" => InstKind::Alloca,
        "store" => parse_store(body),
        "load" => parse_load(body),
        "getelementptr" => parse_gep(body),
        "call" | "tail" | "musttail" | "notail" => parse_call(body),
        "bitcast" | "addrspacecast" | "inttoptr" | "ptrtoint" => InstKind::Cast {
            src: Operand::parse(split_top_level(body, ',').first().copied().unwrap_or("")),
        },
        "icmp" | "fcmp" => InstKind::Compare {
            operands: split_top_level(body, ',')
                .into_iter()
                .filter(|segment| is_operand_segment(segment))
                .map(Operand::parse)
                .collect(),
        },
        "br" | "switch" => InstKind::Branch {
            targets: parse_labels(body),
        },
        "ret" => InstKind::Return,
        "unreachable" => InstKind::Unreachable,
        "indirectbr" | "invoke" | "callbr" | "resume" | "catchswitch" | "catchret"
        | "cleanupret" => InstKind::UnsupportedTerminator,
        _ => InstKind::Other,
    }
}

/// `store <ty> <value>, <ty>* <dest>[, align N][, !dbg !N]`
fn parse_store(body: &str) -> InstKind {
    let segments: Vec<&str> = split_top_level(body, ',')
        .into_iter()
        .filter(|segment| is_operand_segment(segment))
        .collect();
    let Some(first) = segments.first() else {
        return InstKind::Other;
    };
    let Some(second) = segments.get(1) else {
        return InstKind::Other;
    };
    // 第一段还带着 `store` 这个 opcode，取值时无所谓——值仍是最后一个 token。
    InstKind::Store {
        value: Operand::parse(first),
        dest: Operand::parse(second),
    }
}

/// `load <ty>, <ty>* <src>[, align N]`
fn parse_load(body: &str) -> InstKind {
    let segments: Vec<&str> = split_top_level(body, ',')
        .into_iter()
        .filter(|segment| is_operand_segment(segment))
        .collect();
    match segments.get(1) {
        Some(second) => InstKind::Load {
            src: Operand::parse(second),
        },
        // 旧式无类型 load（`load i32* %p`）只有一段。
        None => match segments.first() {
            Some(first) => InstKind::Load {
                src: Operand::parse(first),
            },
            None => InstKind::Other,
        },
    }
}

/// `getelementptr inbounds <ty>, <ty>* <base>, i32 0, i32 52`
fn parse_gep(body: &str) -> InstKind {
    let segments: Vec<&str> = split_top_level(body, ',')
        .into_iter()
        .filter(|segment| is_operand_segment(segment))
        .collect();
    let Some(first) = segments.first() else {
        return InstKind::Other;
    };
    // 首段形如 `getelementptr inbounds %struct.sqlite3`：去掉 opcode 与修饰词后是基址类型。
    let base_type = first
        .split_whitespace()
        .skip(1)
        .find(|token| !matches!(*token, "inbounds" | "inrange"))
        .unwrap_or("")
        .to_owned();
    let Some(second) = segments.get(1) else {
        return InstKind::Other;
    };
    let indices = segments
        .iter()
        .skip(2)
        .map(|segment| {
            segment
                .split_whitespace()
                .next_back()
                .unwrap_or("")
                .to_owned()
        })
        .collect();
    InstKind::Gep {
        base: Operand::parse(second),
        base_type,
        indices,
    }
}

/// `call void %4(i8* noundef %5)` / `call void @llvm.dbg.declare(metadata ...)`
///
/// 被调方是紧挨着实参列表左括号的那个 `%`/`@` token。返回类型本身可能带括号
/// （`call void (i8*)* @f(...)`），所以必须找**处于顶层深度**的第一个 `名字(`。
fn parse_call(body: &str) -> InstKind {
    let bytes = body.as_bytes();
    let mut depth = 0i32;
    let mut callee_start: Option<usize> = None;
    let mut callee: Option<Operand> = None;
    let mut args_range: Option<(usize, usize)> = None;

    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'%' | b'@' if depth == 0 => callee_start = Some(index),
            b'(' => {
                if depth == 0 {
                    if let Some(start) = callee_start {
                        // 名字与 `(` 之间不能有空白，否则它不是被调方。
                        let token = &body[start..index];
                        if !token.contains(char::is_whitespace) {
                            callee = Some(Operand::from_token(token));
                            args_range = Some((index + 1, 0));
                        }
                    }
                }
                depth += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0
                    && let Some((start, end)) = args_range
                    && end == 0
                {
                    args_range = Some((start, index));
                }
            }
            b' ' | b'\t' if depth == 0 => callee_start = None,
            _ => {}
        }
    }

    let Some(callee) = callee else {
        return InstKind::Other;
    };
    let args = match args_range {
        Some((start, end)) if end > start => split_top_level(&body[start..end], ',')
            .into_iter()
            .filter(|segment| !segment.trim().is_empty())
            .map(Operand::parse)
            .collect(),
        _ => Vec::new(),
    };
    InstKind::Call { callee, args }
}

/// 从 `br` / `switch` 里取全部 `label %X` 目标。
fn parse_labels(body: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut tokens = body.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "label"
            && let Some(target) = tokens.next()
        {
            let target = target.trim_end_matches(|c| c == ',' || c == ']');
            if let Some(name) = target.strip_prefix('%') {
                targets.push(name.to_owned());
            }
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_around_commas_inside_types() {
        // 裸逗号切分会把这个函数指针类型劈开，从而认错操作数。
        let text = "store void (i8*, i32, i8*)* %21, void (i8*, i32, i8*)** %23, align 8";
        let segments = split_top_level(text, ',');
        assert_eq!(segments.len(), 3, "segments: {segments:?}");
    }

    #[test]
    fn reads_store_of_register_into_global() {
        let InstKind::Store { value, dest } =
            parse_inst_kind("store void (i8*)* %5, void (i8*)** @g_callback, align 8")
        else {
            panic!("expected a store");
        };
        assert_eq!(value, Operand::Local("5".to_owned()));
        assert_eq!(dest, Operand::Global("g_callback".to_owned()));
    }

    #[test]
    fn reads_store_of_null() {
        let InstKind::Store { value, dest } =
            parse_inst_kind("store i8* null, i8** @g_user_data, align 8")
        else {
            panic!("expected a store");
        };
        assert_eq!(value, Operand::Null);
        assert_eq!(dest, Operand::Global("g_user_data".to_owned()));
    }

    #[test]
    fn reads_indirect_call() {
        let InstKind::Call { callee, args } = parse_inst_kind("call void %4(i8* noundef %5)")
        else {
            panic!("expected a call");
        };
        assert_eq!(callee, Operand::Local("4".to_owned()));
        assert_eq!(args, vec![Operand::Local("5".to_owned())]);
    }

    #[test]
    fn reads_direct_call_with_parenthesised_return_type() {
        // 返回类型自带括号时，被调方仍必须是实参列表前那个符号。
        let InstKind::Call { callee, .. } =
            parse_inst_kind("call void (i8*, ...) @sqlite3_log(i32 noundef 1)")
        else {
            panic!("expected a call");
        };
        assert_eq!(callee, Operand::Global("sqlite3_log".to_owned()));
    }

    #[test]
    fn reads_struct_field_gep() {
        let InstKind::Gep {
            base,
            base_type,
            indices,
        } = parse_inst_kind(
            "getelementptr inbounds %struct.sqlite3, %struct.sqlite3* %22, i32 0, i32 52",
        )
        else {
            panic!("expected a gep");
        };
        assert_eq!(base, Operand::Local("22".to_owned()));
        assert_eq!(base_type, "%struct.sqlite3");
        assert_eq!(indices, vec!["0".to_owned(), "52".to_owned()]);
    }

    #[test]
    fn unknown_opcode_is_other_not_an_error() {
        // 认不出的**非终结**指令必须让来源变未知，而不是让解析失败。
        assert_eq!(parse_inst_kind("fadd double %1, %2"), InstKind::Other);
    }

    #[test]
    fn null_check_is_a_comparison_not_an_unmodelled_use() {
        // `if (callback)` 编出来就是这条。把它归到 `Other` 会让每个负对照都变成缺证。
        let InstKind::Compare { operands } = parse_inst_kind("icmp ne void (i8*)* %5, null") else {
            panic!("expected a comparison");
        };
        assert_eq!(
            operands,
            vec![Operand::Local("5".to_owned()), Operand::Null]
        );
    }

    #[test]
    fn unknown_terminator_is_kept_distinct_from_other() {
        // 它破坏 CFG，路径类结论必须因此降级。
        assert_eq!(
            parse_inst_kind("indirectbr i8* %addr, [label %a, label %b]"),
            InstKind::UnsupportedTerminator
        );
    }

    #[test]
    fn parses_branch_targets() {
        let InstKind::Branch { targets } = parse_inst_kind("br i1 %2, label %3, label %6") else {
            panic!("expected a branch");
        };
        assert_eq!(targets, vec!["3".to_owned(), "6".to_owned()]);
    }

    #[test]
    fn comment_stripping_leaves_string_literals_alone() {
        assert_eq!(strip_comment("  ret void ; done"), "  ret void ");
        assert_eq!(strip_comment("c\"a;b\\00\""), "c\"a;b\\00\"");
    }
}
