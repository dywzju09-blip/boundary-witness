# Gate B（unseen）：git2 0.18.1 判定与 owner-held 持有形状缺口

- 日期：2026-08-10
- 状态：**判定跑通但揭示判据缺口**。git2 的 `set_progress_callback` 在类型层
  阻止 referent 分离（借用检查器），静态判定因未建模 owner-held 持有而缺证；
  harness 编译实验充当了判据验证器。

## 1. 流水线结果（unseen crate 第二次完整走通）

| 级 | 结果 |
| --- | --- |
| static-facts | 4356 条（git2 0.18.1 + libgit2-sys bundled） |
| 契约装配 | 11 条，全部 `permits_non_static_capture` |
| 外部 IR | libgit2 真实构建 bitcode（cc-capture，217 个编译单元）；`git_packbuilder_set_callbacks` 确认保存 payload 到 `pb->field[26]`（跨调用存活） |
| 联结 | 1 joined / 0 rejected（`set_progress_callback` ↔ `git_packbuilder_set_callbacks`） |
| 判定 | `InsufficientEvidence` ×2（Q3 降级 EstablishLateInvoke；allocation unresolved） |
| harness 生成 | `invalidate: generated`、`expected_compile: true` |
| **harness 编译** | **失败：E0505/E0597——`drop(witness_referent)` 被借用检查器拒绝** |

## 2. 发现：owner-held 持有形状不在 guard 判据里

git2 的 `set_progress_callback`（packbuilder.rs:112）：

```rust
pub fn set_progress_callback<F>(&mut self, progress: F)
where F: FnMut(PackBuilderStage, u32, u32) -> bool + 'repo
{
    let mut progress = Box::new(Box::new(progress) as Box<ProgressCb<'_>>);
    let ptr = &mut *progress as *mut _;
    ...
    self._progress = Some(progress);   // ← 闭包存进 self 字段
}
```

- **guard 检测**只覆盖「注册函数返回带 lifetime 的 guard 类型，其 Drop 调外部函数」
  的形状；git2 是**把闭包存进 receiver 字段（owner-held）**，随 PackBuilder drop 释放；
- 类型层效果相同：借用检查器看到 `self._progress` 持有闭包（捕获 `&witness_referent`），
  PackBuilder 存活期间 `drop(witness_referent)` 被 E0505 拒绝，闭包借用活不过
  PackBuilder drop（E0597）——**安全客户端无法构造 referent 分离**；
- 静态判定不知道这个持有形状 → 判 `PermitsNonStaticCapture + guard none` →
  invalidate generated → **编译失败暴露了静态模型的缺口**。

## 3. 这是缺证，不是误报

按 [thesis §2.4] 纪律：静态侧没有 owner-held 建模 = 分离可行性缺证。正确输出是
`InsufficientEvidence`（现在是），但缺证原因应更精确（「owner-held 捕获未建模」，
而不是「看起来可分离」）。**harness 编译是判据的验证器**：编不过说明类型层
约束比静态模型知道的更强。

[thesis §2.4]: ../../project/research-thesis.md

## 4. 生成器泛化（本次为 git2 需要的能力，rusqlite 回归全绿）

- `--crate-source-dir`：patch 路径参数化（不再写死 rusqlite vendor）；
- Cargo.toml 依赖名从 adapter.target.crate 读取；
- 注册参数形状由 `accepts_none_to_clear` 决定（`Some(callback)` vs `callback`）；
- 回调返回类型支持 `bool`（闭包尾表达式 `true`）；其余类型拒绝（缺证）。

## 5. foreach 类 API 的判定尝试（覆盖缺口记录）

对 git2 的 foreach 类（`git_tag_foreach` 等 4 个）用真实 libgit2 IR 跑
`extract-foreign-facts`：**全部 unresolved 且无边界原因**。

- IR 事实：`git_tag_foreach` 把 callback/payload 塞进**栈上** `tag_cb_data`
  结构后传给内部同步遍历函数——回调不进入跨调用存储；
- 分析器现状：对「callback 经栈上 struct 中转再传给内部函数」的形状，Q1
  保留判定落 unresolved（无 reason）——**是分析器覆盖缺口，不是安全结论**；
- 按纪律：缺证不猜。这 4 个 API 保持 `InsufficientEvidence`，不因 IR 显示同步
  而判 Compatible（内部遍历函数内是否保存，当前单文件分析看不到）。

## 6. 这一步证明了什么，没证明什么

**证明了**：

- unseen crate（git2）完整流水线第二次跑通：静态 → 契约 → 真实 libgit2 IR →
  联结 → 判定 → harness 生成；生成器跨 crate 泛化（rusqlite 回归全绿）；
- **owner-held 持有形状是真实存在的类型层保护**，git2 的
  `set_progress_callback` 在借用检查器层面不可分离（E0505/E0597 实证）；
- harness 编译可以作为判据验证器：expected_compile=true 但编不过 = 静态模型缺证
  的信号，不是随机失败。

**没证明**：

- **git2 任何一个 API 的不相容**（也没有证明安全——只有借用检查器对
  set_progress_callback 的实证，其余 10 个 API 未编译验证）；
- **Gate B 通过**（unseen 目标需要「外部真实晚调 + 独立 oracle 出证」；git2 在
  类型层就挡住了，没有走到 ASan）；
- **owner-held 判据的实现**（这是 future work：需要建模「注册函数把回调存进
  self 字段」的形状，属于 PG-1 的扩展）；
- 其余 10 个 git2 permits API（foreach 类）的判定仍缺外部 IR 覆盖。
