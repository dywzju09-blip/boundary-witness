# git2 GIT-02 验证矩阵补全 + GIT-01 现状（owner-drop 判据探索与回退）

- 日期：2026-08-13
- 前置：git2-021-git02-detected-2026-08-13.md（GIT-02 ASan 出证）

## 1. GIT-02 对照矩阵（补全）

| 变体 | 动作 | ASan | exit |
| --- | --- | --- | --- |
| vulnerable | 注册 → into_inner 拆 guard → drop referent → 迭代触发 | **heap-use-after-free ×2**（hide 闭包 → revwalk_hide_cb → add_parents_to_list） | 1 |
| owned | hide 闭包不捕获 referent（`let _ = 0;`） | 干净 | 0 |
| no-trigger | 注册 → 拆 guard → drop referent，**不迭代** | 干净 | 0 |

no-trigger 变体注意：删 trigger 后 `bw_guard` 仍借用 `repo`，需先 `drop(bw_guard)` 再
`drop(repo)`（借用检查的清理顺序）。

## 2. GIT-01 现状：owner-drop 判据探索与回退（如实记录）

尝试修复 GIT-01（CheckoutBuilder 存字段延迟交出）：新增 `OwnerHoldsCallbackWithoutUnregister`
判据（owner-held + owner Drop 不调外部函数 → 分离可构造），理由：CheckoutBuilder 无 Drop
impl（owner drop 只释放闭包 Box，注册经 configure/rebase memcpy 到 git_rebase 上不解除）。

**回退原因**（变异/回归暴露）：fixture 的 `BoxDynHolder` / `AliasHolder` 同样"存字段 +
无 Drop"——但它们**不把 receiver 交给外部**（闭包只在 owner 内部使用，无外部注册、无晚调），
owner-held 判"分离不可构造"是正确的（安全）。`owner_drop_unregisters` 单独用会把这
类安全形状误判成"分离可构造"。

**正确判据需要**：owner-held + owner drop 不注销 + **receiver 被交给外部**（跨类型字段流：
`CheckoutBuilder` → configure 把 self 指针存进 `RebaseOptions` 字段 → `Repository::rebase`
把 opts 传给 `git_rebase_init`）。这是新分析维度（对象 A 的指针进对象 B 的字段，B 被交给
extern），不是本轮能收的。GIT-01 保持"未检到"，记录为后续工作。

## 3. 证明了什么 / 没证明什么

**证明了**：

- GIT-02 的 vulnerable/owned/no-trigger 因果对应成立（触发与客户端动作序列的因果）；
- owner-drop 判据的边界：owner-held + 无 Drop **不充分**判分离可构造（需要 receiver
  交出证据）——本轮探索用回归测试证明了这个边界，避免了一个新误判。

**没证明**：

- GIT-01 仍未检到（跨类型字段流缺失）；
- GIT-02 无 fixed 版本对（git2 无对应修复版本）。

## 4. 产物（远端 <results-root>/git2-021-*）

- `git2-021-harness-owned/`、`git2-021-harness-notrigger/`（对照变体）
- `git2-021-control-owned.log`、`git2-021-control-notrigger.log`（ASan 干净）
- `git2-021-asan-hide.log`（vulnerable 出证）
