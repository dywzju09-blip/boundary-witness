# PG-1 扩展：owner-held 持有形状判据（OwnerHoldsCallback）

- 日期：2026-08-10
- 来源：阶段 5.5 / Gate B 在 git2 上实证的判据缺口（harness 编译暴露）
- 状态：**实现完成，git2 重新判定验证通过，变异检查通过。**

## 1. 判据

新增 [`RegistrationGuard::OwnerHoldsCallback`]：注册函数把回调分配**存进 receiver
字段**（如 git2 的 `self._progress = Some(boxed)`），闭包随 owner drop 释放。
类型层效果与返回 guard 等价：referent 与 allocation 的分离都不可构造。

MIR 判据（`owner_holds_callback`，mir.rs）：

1. 收集 `&mut (*self).<field>` 的借用临时（`Rvalue::Ref` 基址是 receiver 参数）；
2. store 到 receiver 字段或其借用临时，且 place 类型含 `dyn Fn*` trait object
   （穿透 Box / Option / 泛型参数）→ 命中。

只认 receiver（第一个参数）字段，不认任意局部——owner-held 的语义是「闭包随
receiver 对象 drop 释放」，只有 receiver 字段能给出这个保证。

## 2. 验证

### 2.1 fixture（foreign-symbol-roles 新增 CallbackHolder）

- `CallbackHolder::<'a>::set_callback`（`self.held = Some(boxed)`）→
  `OwnerHoldsCallback` ✓
- 对照组 `register_plain`（直接交给外部）→ `None` ✓

### 2.2 变异检查

把「直接 store 到 receiver 字段」路径改成 AND（与借用临时路径互斥）→
`owner_held_capture_is_detected_as_guard` 转红、其余 2 条仍绿；还原后全绿。
（第一轮变异 `==`→`!=` 未杀死测试：fixture 的 MIR 走直接 store 路径，判别力
证明的是直接路径；第二轮 AND 变异证明的是整体判据。）

### 2.3 git2 重新判定（真实 unseen 目标）

| 项 | 修改前 | 修改后 |
| --- | --- | --- |
| guard | none | **owner_holds_callback** |
| captured_referent | InsufficientEvidence + **EstablishLateInvoke** | InsufficientEvidence + 义务 **None**，assumption = `foreign clear effect unresolved` |
| harness 生成 | invalidate generated → 编译意外失败（E0505/E0597） | **invalidate refused（owner_holds_callback）→ expected_compile=false** |

行为变化：owner-held 目标不再被误判「可分离」而生成必然编不过的 harness；
缺证原因从「晚调可达性」变为「guard 有效性（外部清槽证据不足）」——更准确。

### 2.4 回归

bw-rustc / bw-model / bw-cli 全量测试通过；rusqlite 与 Gate R fixture 不受影响
（它们的注册函数没有 receiver 字段持有形状）。

## 3. 这一步证明了什么，没证明什么

**证明了**：

- owner-held 是可在 MIR 层机械识别的持有形状，且与借用检查器行为一致
  （git2 上 harness 编译失败 ↔ 判据判定不可分离，双向印证）；
- 生成器现在对 owner-held 目标给出**预期的**编不过（refused），不再意外编不过；
- 判据有变异验证与正/负 fixture。

**没证明**：

- **其他持有形状。** 闭包可能经 helper 函数转存、存进非 receiver 的全局/静态、
  或经 trait 对象间接持有——都不在判据里（缺证，不是否定）；
- **git2 的 11 个 permits API 全部安全。** 只有 set_progress_callback 编译验证过；
  其余 foreach 类仍需外部 IR 判定；
- **X=A 分配类的 owner-held 语义**：owner-held 下分配活到 owner drop，但若外部
  在 owner drop 之后仍持有 payload 指针（如异步线程），判据不覆盖——外部侧
  Q4′/晚调证据仍是必需。
