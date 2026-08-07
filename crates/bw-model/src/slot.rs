//! 槽位身份。
//!
//! 「槽位」是外部组件里**跨调用存活**的那个存储位置。它是 Q1、Q4′ 与降级 Q3 三个查询
//! 之间唯一的连接物：Q1 说回调进了哪个槽位，Q4′ 问注销有没有清这个槽位，Q3 找从这个
//! 槽位取出后的间接调用。三者必须谈论同一个槽位，否则拼出来的结论没有意义。
//!
//! # 身份里不含基址是怎么来的
//!
//! 字段槽位的身份是「某结构体类型的第几个字段」，**不含那个结构体指针在某个函数里从哪
//! 来**。同一个槽位在注册函数里由形参到达，在派发函数里往往是从另一个结构体读出来的
//! （`p->db->xUpdateCallback`）。把来源写进身份，Q1 和 Q3 就会谈不到一起——真实测量
//! 里 `sqlite3VdbeExec` 的五个调用点全部因此丢失。
//!
//! 「跨调用存活」不是身份的一部分，而是 **Q1 单独需要的论证**：只有能证明那个结构体
//! 由调用方持有时，写进它的字段才算保留。见 `dataflow` 的 caller-owned 判定。

use serde::{Deserialize, Serialize};

/// 槽位的基址。
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SlotBase {
    /// 模块级全局变量。跨调用存活是定义使然。
    Global { symbol: String },
    /// 某个结构体类型的字段。
    ///
    /// 身份只到「哪个结构体的哪个字段」为止。那个结构体实例是否跨调用存活，由 Q1 用
    /// caller-owned 判定单独回答，**不进身份**。
    StructField { struct_type: String },
}

/// 一个跨调用存活的存储位置。
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotId {
    pub base: SlotBase,
    /// `getelementptr` 的索引路径。空表示基址本身就是槽位。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub field_path: Vec<String>,
}

impl SlotId {
    #[must_use]
    pub fn global(symbol: impl Into<String>) -> Self {
        Self {
            base: SlotBase::Global {
                symbol: symbol.into(),
            },
            field_path: Vec::new(),
        }
    }

    #[must_use]
    pub fn field(struct_type: impl Into<String>, field_path: Vec<String>) -> Self {
        Self {
            base: SlotBase::StructField {
                struct_type: struct_type.into(),
            },
            field_path,
        }
    }

    /// 稳定的可读形式，用于证据串与诊断输出。
    #[must_use]
    pub fn describe(&self) -> String {
        let base = match &self.base {
            SlotBase::Global { symbol } => format!("@{symbol}"),
            SlotBase::StructField { struct_type } => struct_type.clone(),
        };
        if self.field_path.is_empty() {
            base
        } else {
            format!("{base}[{}]", self.field_path.join("."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_slot_identity_ignores_where_the_base_pointer_came_from() {
        // 注册函数里 `db` 是形参，派发函数里是 `p->db`。只要结构体类型与字段路径一致，
        // Q1 与 Q3 就必须认为是同一个槽位——真实 sqlite3 上这一条决定了五个调用点
        // 是被找到还是被丢掉。
        let from_register = SlotId::field("%struct.sqlite3", vec!["0".into(), "52".into()]);
        let from_dispatch = SlotId::field("%struct.sqlite3", vec!["0".into(), "52".into()]);
        assert_eq!(from_register, from_dispatch);
    }

    #[test]
    fn different_fields_of_the_same_struct_are_different_slots() {
        let callback = SlotId::field("%struct.sqlite3", vec!["0".into(), "52".into()]);
        let user_data = SlotId::field("%struct.sqlite3", vec!["0".into(), "51".into()]);
        assert_ne!(callback, user_data);
        assert_eq!(callback.describe(), "%struct.sqlite3[0.52]");
    }

    #[test]
    fn global_slot_describes_with_the_at_sign() {
        assert_eq!(SlotId::global("g_callback").describe(), "@g_callback");
    }
}
