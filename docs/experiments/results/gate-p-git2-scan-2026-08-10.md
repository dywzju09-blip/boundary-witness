# Gate P 方向数据：git2 0.18.1 回调捕获准入扫描

- 日期：2026-08-10
- 性质：**exploratory**（Gate P-a 的迷你版方向信号，不是正式猎物池估计）
- 目标：git2 0.18.1（libgit2-sys 0.16.1+1.7.1，bundled——L1 满足），
  **未参与本项目任何 adapter 开发**（unseen）

## 1. 扫描结果

| 项 | 数量 |
| --- | --- |
| 静态事实 | 4356 |
| hand-off 交出点 | 32 |
| 装配成契约 | 11（其余 21 gap） |
| **`permits_non_static_capture`** | **11 / 11** |
| guard = none | 10 |
| guard = unresolved | 1（`Revwalk::with_hide_callback`） |

装配的 11 个 API：

```
diff::Diff::print                          packbuilder::PackBuilder::foreach
odb::Odb::foreach                          packbuilder::PackBuilder::set_progress_callback
repo::Repository::fetchhead_foreach        repo::Repository::mergehead_foreach
repo::Repository::stash_foreach            repo::Repository::tag_foreach
revwalk::Revwalk::with_hide_callback       tree::Tree::walk
treebuilder::TreeBuilder::filter
```

## 2. 形状分类（静态侧）

- **foreach / walk / filter 类**（9 个）：libgit2 的 `git_*_foreach` 是**同步遍历**，
  回调只在调用期间存活。静态侧 `'repo` bound + 无 guard，但外部同步语义若成立，
  应判 Compatible（Q1 = NoRetain 或同步调用）；
- **`set_progress_callback`**（1 个）：**注册保存形状**。`F: FnMut(...) + 'repo`，
  双层 Box（外层存 `self._progress`、内层 payload 指针进
  `git_packbuilder_set_callbacks`）。Rust 侧持有外层 Box，看起来是 guard 形状；
  判定需要 libgit2 侧 IR（payload 是否跨调用保存、打包期间是否晚调、unset 是否
  真清槽）。

## 3. 为什么这值得记下来

1. **第二个 crate 家族确认 referent 类候选存在**（rusqlite 之外）——Gate P-a 的
   方向信号为正，但样本 n=2；
2. **RUSTSEC 数据库里没有 git2 的回调持有期公告**——按 [thesis §7.5] 纪律，
   「无公告」不是安全负例；git2 这 11 个 API 的判定需要真实 IR，不能靠公告缺席
   下结论；
3. 这 11 个 API 是 Gate B unseen 候选池（如果外部 IR 判定出不相容或义务）。

[thesis §7.5]: ../../project/research-thesis.md

## 4. 下一步（判定计划，未执行）

1. 为 `git_packbuilder_set_callbacks` 写 role map（**判定前冻结**，记录时间戳）；
2. 用 cc-capture 重编译 libgit2-sys（bundled）捕获 libgit2 IR（阶段 2 流程）；
3. extract-foreign-facts → judge（set_progress_callback 的 Q1/Q3/Q4′）；
4. 若 InsufficientEvidence + 义务 → 生成 harness → ASan。

## 5. 这一步证明了什么，没证明什么

**证明了**：git2 0.18.1 存在 11 个允许非静态捕获的回调 API（与 rusqlite 同族形状），
unseen crate 上的扫描流水线（static-facts → contracts）可以跑通。

**没证明**：任何一个 git2 API 的不相容或安全——**没有外部 IR 就没有判定**；
`set_progress_callback` 的 guard 形状（self._progress 持有）可能是健全设计，也可能
不是，未跑判定前不下任何结论。
