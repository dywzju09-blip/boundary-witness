# 实验结果索引（当前主线）

本目录保存由运行记录支持的结果。**它们证明对应 commit 上发生过什么，不自动证明
当前 commit 的行为。** 当前没有与最新 commit 对齐的独立 holdout gate，因此任何
「已检出」都是开发/验证证据，不是论文级 `Verified` 结论。

## 阶段主线（5.x）

| 日期 | 结果 | 结论 |
| --- | --- | --- |
| 2026-08-04 | [阶段 2：真实外部 IR](stage2-foreign-ir-v0-2026-08-04.md) | rusqlite 0.26.1/0.26.2 的 SQLite bitcode 捕获与 V0 检查 |
| 2026-08-05 | [阶段 3：外部行为](stage3-foreign-behavior-2026-08-05.md) | 外部侧 Q1/Q3/Q4′ 在真实 IR 上的指令级证据（必读：踩坑记录） |
| 2026-08-06 | [阶段 4：联结闭环](stage4-joint-closure-2026-08-06.md) | 两侧身份联结与三态判定（必读） |
| 2026-08-07 | [阶段 5.0：符号解析](stage5-0-symbol-resolution-2026-08-07.md) | rusqlite 跨界交出点 6/6 解析成功（必读） |
| 2026-08-10 | [阶段 5.2：source-to-verdict](stage5-2-source-to-verdict-2026-08-10.md) | 真实目标静态判定闭环 |
| 2026-08-17 | [阶段 5.3：生成器重写](stage5-3-witness-generator-rewrite-2026-08-17.md) | 硬编码模板清零、ASan profile 输出、extra_dependencies |
| 2026-08-17 | [阶段 5.4+5.5：oracle + 负对照](stage5-4-5-asan-oracle-and-negative-control-2026-08-17.md) | `bw run-witness-oracle` 组件化；rusqlite 0.26.1/0.26.2 对照矩阵 5/5 |

## 候选验证（0day 候选 → ASan 出证）

| 日期 | 候选 | 状态 |
| --- | --- | --- |
| 2026-08-13 | [git2 GIT-02 revwalk hide_cb](git2-021-git02-detected-2026-08-13.md) | ✅ ASan heap-UAF 出证 |
| 2026-08-13 | [git2 GIT-01 rebase checkout 回调](git2-021-git01-asan-2026-08-13.md) | ✅ ASan 出证 |
| 2026-08-13 | [git2 候选判定链](git2-021-git01-judgement-2026-08-13.md) + [对照](git2-021-controls-and-git01-status-2026-08-13.md) + [验证](git2-021-candidate-verification-2026-08-13.md) | 判定层 + 负对照 |
| 2026-08-15 | [libsql LSQL-01 receiver-as-userdata](libsql-0930-lsql01-detected-2026-08-15.md) | ✅ ASan 出证 |
| 2026-08-15 | [mosquitto MOSQ-02 self-pointer + move-escape](mosq-015-mosq02-detected-2026-08-15.md) | ✅ ASan 出证 |
| 2026-08-15 | [fluidlite set_file_api](fluidlite-021-detected-2026-08-15.md) | ✅ ASan 出证 |
| 2026-08-16 | [tree-sitter set_logger](treesitter-setlogger-detected-2026-08-16.md) | ✅ ASan 出证 |
| 2026-08-16 | [sqlite-vfs register](sqlitevfs-register-detected-2026-08-16.md) | ✅ ASan 出证 |
| 2026-08-17 | [ffmpeg input_with_interrupt](ffmpeg-030-input-with-interrupt-detected-2026-08-17.md) | ✅ ASan 出证（bridged 跨函数传播） |
| 2026-08-17 | [fltk TreeItem::draw_item_content](fltk-tree-draw-item-content-detected-2026-08-17.md) | ✅ ASan 出证 |
| 2026-08-17 | [fltk app::set_callback](fltk-set-callback-detected-2026-08-17.md) | ✅ ASan 出证（含生成器 ASan profile 缺陷发现） |
| 2026-08-17 | [fluidsynth MidiRouter::new](fluidsynth-midi-router-trigger-blocked-2026-08-17.md) | ⚠️ 触发缺证（safe API 下 router 不可达，非证伪） |
| 2026-08-16 | [高置信候选汇总](highconf-candidates-2026-08-16.md) | 6 候选：5 出证 + 1 缺证 |
| 2026-08-16 | [剩余候选处理](remaining-candidates-2026-08-16.md) | fltk/fluidsynth/ffmpeg 构建与触发记录 |

## 能力记录（历史验证，仍被当前文档引用）

- [stage6-5 系列](stage6-5-userdata-role-2026-08-13.md)：userdata 角色、外部堆逃逸、
  多回调参数、7/7 nday ASan 出证（RUSTSEC-2021-0128 家族能力补齐）
- [git2 021 候选验证](git2-021-candidate-verification-2026-08-13.md)
- [multi-family 负向验证](multi-family-negative-validation-2026-08-14.md)
- [Q3 同步/晚调基线](q3-sync-late-invoke-baseline-2026-08-14.md)
- [Gate 0 外部基线对照](gate0-baseline-comparison-2026-07-31.md) 与
  [Yuga 误报归因](gate0-yuga-precision-triage-2026-07-31.md)（research-thesis 引用；
  n=1 反例，不构成精度证据）

## 解释规则

- `candidate`、top-k、`adapter_needed` 都不是 confirmed finding。
- 缺证 ≠ 证伪：fluidsynth 触发不可达是缺证记录，候选未被否定。
- 新结果必须满足 [数据对齐规范](../data-alignment.md) 与
  [实验方法](../methodology.md)。
