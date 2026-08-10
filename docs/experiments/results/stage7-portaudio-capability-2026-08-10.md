# 工具能力实测：portaudio-rs 0.3.1（RUSTSEC-2019-0022，回调 UAF nday）

- 日期：2026-08-10
- 任务：把典型 crate nday 独立放入工具，实测工具当前能力
- 结论先行：**工具对 `Box<dyn FnMut + 'a>` 回调参数形状存在识别盲区**；
  该 nday 的缺陷机制（回调内 panic 导致 transmute Box 提前释放）也不在
  本工具的判定维度内。两项都如实记录。

## 1. 选型

系统搜索 RUSTSEC advisory-db 后，**除 rusqlite（开发对象）外没有第二个
L1 回调持有期类 nday**——这是 Gate P 信号的第二次确认（首次为 git2 扫描）。

最接近「回调 nday」的 unseen 候选：**portaudio-rs 0.3.1**（CVE-2019-16881，
CVSS 9.8，callback UAF）。服务器有 portaudio-2.0 系统库与 ALSA 头文件，
可构建（注：系统库属 L2，本次为探索性运行，manifest 已标注）。

## 2. 缺陷机制（源码确认）

src/stream.rs（0.3.1）：

- 回调 bound：`StreamCallback<'a> = FnMut(...) + 'a`（允许借用捕获，
  与 rusqlite 0.26.1 同族）；
- open 里 `Box::new(StreamUserData { callback, .. })` 存闭包，
  `&mut *user_data as *mut c_void` 裸指针交给 `Pa_OpenStream`（userData）；
- 回调侧 stream_callback 用 `mem::transmute(user_data)` 重建 Box，
  正常路径 `mem::forget` 防止释放；**用户闭包 panic 时 Box 被 drop ->
  PortAudio 仍持有指针 -> 下次回调 UAF（攻击者可控制回调指针）**；
- `Stream<'a>` 持有 `user_data: Box<StreamUserData<'a>>`，`Drop` -> `close`
  -> 外部调用（guard 形状）。

**缺陷维度**：这是 panic 展开路径的分配提前释放（Rust 内部 unsound），
**不是**「类型契约允许的比外部实现宽」的错配——本工具的三维判定
（R 分离 / A 分离 / guard 有效性）不含 panic 路径建模。

## 3. 工具实测结果

| 步骤 | 结果 |
| --- | --- |
| extract-static-facts | 64 条事实（object_site 32、drop_site 26、callback_site 2、callback_user_data_reconstruction 2、drop_prevention 2） |
| extract-rust-contracts | **assembled=0, gapped=0**——没有任何回调 hand-off 被识别 |

**盲区根因**（mir.rs callback_param_bound_lifetimes）：只识别
where 谓词泛型（`F: FnMut(...)`）；portaudio 的回调参数是
`Option<Box<StreamCallback<'a>>>`（**trait object 类型参数**，非泛型），
完全不在这条路径上。配套地：没有 callback_lifetime_bound / registration_site /
foreign_symbol_binding 事实产出。

## 4. 这次实测证明了什么，没证明什么

**证明了**：

- 工具对 rusqlite/git2 之外的第三类回调形状（`Box<dyn FnMut>` 参数）存在
  **系统性识别盲区**——这类 API 在 Gate P 候选池里会完全不可见，需要扩展
  编译器（trait object 参数识别）才能覆盖；
- RUSTSEC 公开库中「L1 + 回调持有期类」nday 只有 rusqlite 一个——若保持
  L1 约束，第二个 unseen 正例只能来自前瞻扫描而非公告库；
- 治理机制正常：manifest 写入 vulnerable token 被 V3.2 校验拦截（正确拒绝）。

**没证明**：

- portaudio 的缺陷工具判不出（未走到判定——连 hand-off 都没识别）；
- 即便扩展 Box<dyn> 识别，**panic 路径 UAF 仍超出判定维度**（预期判
  guard 形状 + InsufficientEvidence，不会给 SupportedIncompatibility）——
  这是判定模型的边界，不是 bug；
- 本次构建用系统 portaudio（L2），不是 L1 片段内的正式结论。

## 5. 下一步（若继续）

1. 扩展 callback_param_bound_lifetimes：识别 `Box<dyn Fn* + 'a>` 参数
   （HIR 类型遍历：Adt(Box) -> TraitObject -> callable principal -> lifetime）；
2. fixture 测试 + 变异检查；
3. portaudio 重跑 -> 预期：契约装配（permits + ties_slot_to_subject），
   judge 缺证（无外部 IR），harness invalidate refused（guard）。

## 6. 扩展实施结果（2026-08-10 追加）

两轮编译器扩展，portaudio 从 0 hand-off 到 3/3 装配成功：

**第一轮：直接 `Box<dyn Fn*>` 参数识别**（callback_params_from_signature +
collect_callable_trait_object_lifetimes，消费点 registration_guards /
allocation_ownerships）。fixture BoxDynHolder 正例 + 变异检查。

**第二轮：type alias 展开**（callback_trait_object_lifetime 加 tcx +
TyAlias 展开：展开体是 callable trait object 时收集调用处 lifetime 实参）。
hand_off_sites 复用 callback_lifetime_bounds 产出，capture/lineage/symbol
三组事实同源对齐。fixture AliasHolder 正例 + 变异检查（TyAlias->Struct 转红）。

**portaudio 重跑：3/3 装配成功**（open / open_default / set_finished_callback）。

**剩余形状限制（如实记录，判定保守缺证不误报）**：

- admission=unresolved：portaudio 的 'a 声明在 impl 块（impl<'a> Stream<'a>），
  不在函数 generics——function_declared_lifetime_params 只收函数声明 lifetime；
- guard=none：open 把 user_data Box 存进返回值 Stream 的字段（struct 构造，
  非 receiver store）——owner-held 判据的第三种形状（返回值字段持有）未覆盖；
- 缺陷机制（panic 路径 UAF）仍超出判定维度（不产生 SupportedIncompatibility）。

**工具能力最终结论**：对 portaudio 这类老牌 FFI 绑定（别名包装 trait object
回调），工具现在能完整识别回调表面并保守判定（InsufficientEvidence 方向），
不误报；该 nday 的 panic 类机制不在判定模型内。

## 7. Rust-only 判定（案例闭环收尾）

`bw judge-hand-offs --rust-only`（无外部 IR，系统库为 L2）：
3 个 API × 2 类生命周期 = 6 条判定，**全部 InsufficientEvidence**，
缺证原因具体可回查：capture admission unresolved / allocation ownership
unresolved / no foreign behavior fact for this hand-off。

**案例闭环结论**：portaudio-rs 0.3.1（回调 UAF nday）从选型、准备、
独立放入工具到判定全流程走通。工具最终输出为保守缺证——不误报
（未把 panic 路径缺陷判成不相容，也不判安全），符合判定纪律。

## 8. impl 块 lifetime 识别 + 借用检查器实证（最终修正）

**impl 块 lifetime**：`declared_lifetime_params_with_impl`（tcx.parent ->
ItemImpl generics 合并）接入三个判定路径。portaudio admission 从
unresolved -> **permits_non_static_capture**（3/3 契约，与 rusqlite 0.26.1
同族）。全量测试无回归。

**借用检查器实证（修正 §6 的"guard none 缺口"认知）**：

- 变体 A（注册 -> drop(referent)，stream 不再使用）：**编译通过**；
- 变体 B（注册 -> drop(referent) -> stream.start()）：**编译通过**；
- 对比 git2（set_progress_callback 形状）：drop(referent) 被 E0505 拒绝。

**结论修正**：portaudio 的"返回值字段持有"**不是类型层保护**——闭包经
trait object 化（Box<dyn FnMut + 'a>）后，借用检查器不把 trait object
lifetime 与变量 drop 关联，分离可构造（两次变体实证）。git2 的具体
持有形状被 Drop 保守检查保护。**两种形状的保护差异待深究**（可能与
Drop impl 结构或 trait object lifetime 推断有关），但工具判定
（permits + guard none -> 分离可构造）与借用检查器实测**一致**。

**对工具的意义**：portaudio 的 referent 分离路径静态可构造；动态触发
需要音频设备（服务器无，start 会失败），运行验证为 Inconclusive 方向。
已知缺陷（panic 路径 UAF）仍超出判定维度。
