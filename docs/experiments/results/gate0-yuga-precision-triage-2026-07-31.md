# Gate 0 后续：Yuga 8 条非公告报告的逐条归因

- 日期：2026-07-31
- 输入：[Gate 0 外部基线对照](gate0-baseline-comparison-2026-07-31.md) 中 Yuga 在 rusqlite 0.26.1 上的 13 条报告
- 对象：其中在修复版 0.26.2 仍然存在、因而不对应 RUSTSEC-2021-0128 的 8 条
- 方法：逐条读取被报位置的 rusqlite 0.26.1 源码，判断该生命周期关系是否真的不受约束
- 状态：**8 条全部判为误报，且根因统一。** 该结论把主张从「检出」重定位为「判别」

> **本文是一份历史运行记录，不是当前路线。** 其中的数据与逐条判定保持原样；但研究方向已于 2026-07-30 重写，创新点编号由 N1/N2/N3 改为 C1/C2/C3，且**下一步不再是本文 §6 所写的规模化对照，而是 [Gate P 猎物存在性探针](../runbooks/prey-existence-probe.md)**。当前方向以 [research thesis](../../project/research-thesis.md) 为准。

## 1. 为什么做这一步

外部基线对照否定了「现有工作不会报出该缺陷类」这一前提。此后唯一可能的贡献方向是精度——但**只有在这 8 条确为误报、且误报有可归因的统一机制时才成立**。若它们多数是真问题，精度方向同样不成立。

因此这不是补充分析，是决定研究方向存续的判据。

## 2. 逐条判定

| # | 报告位置 | Yuga 给的理由 | 源码实际情况 | 判定 |
| --- | --- | --- | --- | --- |
| 1 | `inner_connection.rs:181` `get_interrupt_handle` | `ffi::sqlite3` 活得比 `'_` 长且被返回 | 返回 `InterruptHandle { db_lock: Arc::clone(&self.interrupt_lock) }`。`Arc` 是存活锚点，不是悬垂 | 误报 |
| 2 | `lib.rs:886` `get_interrupt_handle` | 同上 | 同上的外层转发 | 误报 |
| 3 | `backup.rs:187` `Backup::new` | `from` 的 db 被赋给 `to` 的 db | `pub struct Backup<'a, 'b> { phantom_from: PhantomData<&'a Connection>, to: &'b Connection, .. }`，两个连接的存活期由结构体 lifetime 参数约束 | 误报 |
| 4 | `inner_connection.rs:222` `prepare` | `ffi::sqlite3` 活得更长 | `fn prepare<'a>(&mut self, conn: &'a Connection, sql: &str) -> Result<Statement<'a>>`。`'a` 来自输入参数，返回值受其约束 | 误报 |
| 5 | `statement.rs:293` `query_map` | `*(f)` 是 `F`，活得比 `'_` 长，**被赋给 `*(self.stmt.ptr)`（`ffi::sqlite3_stmt`）** | `f` 移入 `MappedRows<'stmt, F> { rows: Rows<'stmt>, map: F }`——**纯 Rust 结构体**，`'stmt` 由 `&mut self` 借用约束。`f` 从未跨越边界 | 误报 |
| 6 | `statement.rs:320` `query_map_named` | 同上 | 转发到 `query_map` | 误报 |
| 7 | `statement.rs:387` `query_and_then` | 同上 | `f` 移入 `AndThenRows<'stmt, F> { rows, map: F }` | 误报 |
| 8 | `statement.rs:413` `query_and_then_named` | 同上 | 转发到 `query_and_then` | 误报 |

## 3. 统一根因

第 5–8 条是关键，它们暴露的机制可以直接陈述：

**Yuga 无法区分**

- 值被存进**一个受借用检查器约束的 Rust 结构体**（`MappedRows<'stmt, F>` 的 `map` 字段），与
- 值被**跨边界交给一个外部持有的槽位**

在 Rust 侧，两者的形状相同：一个泛型值活得比某个借用长，并且出现在一个外部指针附近。Yuga 的报告原文把 `f` 描述为「被赋给 `ffi::sqlite3_stmt`」，而实际上 `f` 只是与持有该指针的 `Rows<'stmt>` **同处一个结构体的相邻字段**。其字段敏感别名分析把「存进一个同时含外部指针的结构体」当成了「存进那个外部对象」。

第 1–4 条是同一族的弱化形式：`Arc` 锚点、结构体 lifetime 参数、输入约束的返回 lifetime，都是 Rust 侧已经建立的约束，被读成了不受约束。

**这个区分正是边界另一侧才能给出的**，因而它同时是误报根因与本项目贡献所在。

## 4. 本系统在同样 8 条上的输出

同一 crate、同一 feature 集合（run `comp-b-done`）：

| 函数 | 本系统产出的事实 |
| --- | --- |
| `query_map` / `query_map_named` / `query_and_then` / `query_and_then_named` | `callback_lifetime_bound`，scope 为 `no_lifetime_bound` → 判定表中恒为 `Undecided`，不会成为错配 |
| `get_interrupt_handle` / `prepare` / `Backup::new` | 无 `callback_lifetime_bound` 事实（无 `Fn` 家族 bound），不构成候选 |

排除这 8 条**只用到签名形状，不依赖 API 清单**，因此该排除能力与清单无关。

## 5. 对照数字

同一 crate、同一 feature：

| | 命中公告 | 不对应公告 | 精度 | 召回 |
| --- | ---: | ---: | ---: | ---: |
| Yuga | 5 | 8 | 5/13 ≈ 38% | 5/7 |
| 本系统 | 5 | 0 | 5/5 = 100% | 5/7 |

召回相同，漏报相同（`create_aggregate_function`、`create_window_function`）。

## 6. 结论上限

**这些数字目前不构成证据**，理由有二，必须与数字同时陈述：

1. **n=1**。单个 crate 的 13 条报告不能支撑精度结论
2. **该 crate 参与过本系统开发**，5/5 存在过拟合嫌疑

因此下一步不是写代码，而是**把对照扩大到 10–20 个 FFI crate，并在未参与开发的 crate 上复现**。若在更大样本上 Yuga 精度并不差，精度方向同样不成立，届时需再次重估研究方向。

本记录不宣称 Gate 0 通过，也不作任何跨语言错配能力已完成的结论。
