# Gate R 的四个 matched fixture

本目录的 C stub 与 `../src/lib.rs` 的 Rust 形状组成 [Gate R](../../../../docs/roadmap/milestone-gates.md#gate-r关系正确性) 的四个 matched fixture，用来验证 [research thesis §2.4](../../../../docs/project/research-thesis.md) 的关系确实能分开该分开的情况。

## 对应关系

| # | Rust 形状 | C stub | 应判 | 检验什么 |
| --- | --- | --- | --- | --- |
| 1 | `register_borrowed` | `retain_late_invoke.c` | **不相容** | 正对照 |
| 2 | `register_guarded` | `retain_late_invoke_clearing.c` | 相容 | 不得误报 guard 保护的 API |
| 3 | `register_guarded`（**同一个**） | `retain_late_invoke_leaky.c` | **不相容** | **外部侧是否有判别力** |
| 4 | `register_static_then_free` | `retain_late_invoke.c` | **不相容** | referent / allocation 分离 |

另有两个负对照：`register_static_owned` 配任意 stub（两类生命周期都被约束住），以及 `synchronous_only.c` 配任意 Rust 形状（外部不保存）。

## fixture 2 与 3 是本 gate 的重点

**它们的 Rust 侧是同一个函数**，差别全部落在 `fixture_unregister` 的实现：

- `retain_late_invoke_clearing.c` 把两个槽位都写回 `NULL`；
- `retain_late_invoke_leaky.c` 注册时写了两个槽位，注销只清了其中一个，`fixture_fire` 会回退到另一个。

Rust 侧的 `Registration` guard 在两种情况下**完全一样**：它忠实地在 `Drop` 里调用了注销。**Rust 侧看不到那次注销做了什么。**

因此：

- 若判定器能分开 2 与 3 → 外部侧证据带来了 Rust 侧拿不到的判别力，[C2](../../../../docs/project/research-thesis.md) 的机制成立；
- 若分不开，或 Rust-only 也能分开 → 外部侧对这条关系没有净贡献，按 [Gate A](../../../../docs/roadmap/milestone-gates.md#gate-a外部证据必要性) 的失败动作转路线 B。

## 这些 stub 当前不参与构建

PF 阶段只验证**关系本身**，不执行任何东西：判定的输入是手工标注的外部侧事实（评估设计里的 `manual foreign oracle` 变体），标注依据就是本目录的源码。

P1/P2 会把这些 stub 编成 LLVM IR，让 Q1/Q3/Q4′ 从 IR 推导出同样的取值；届时本目录才需要构建配置。**关系本身不因事实来源改变**，这也是把两者分开的理由。

## 判定的输入

每个 stub 顶部的注释写明了它对应的 Q1 / Q3 / Q4′ 取值。`crates/bw-model/tests/compatibility.rs` 按这些取值构造 `ForeignBehaviorFact`，断言判定结果符合上表。
