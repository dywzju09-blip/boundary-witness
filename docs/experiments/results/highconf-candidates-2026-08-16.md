# ffi-callback-hunt 高置信候选工具验证汇总（2026-08-16）

- 范围：REPORT-19-candidates.md 的高置信 6 个候选（fluidsynth/tree-sitter/
  sqlite-vfs/fltk×2/ffmpeg），全部跑 BoundaryWitness 工具全链路
- 提交：6f72fd7（tree-sitter bridged 扩展）、9d258f8（sqlite-vfs 自由函数 bridged）

## 结果总表

| 候选 | 判定层 | harness | ASan | 状态 |
|---|---|---|---|---|
| tree-sitter 0.26.12 set_logger | ✅ ASSEMBLED（bridged） | ✅ 自动生成 | ✅ **heap-UAF 出证** | **完成**（6f72fd7） |
| sqlite-vfs 0.2.0 register | ✅ ASSEMBLED（bridged） | ✅ 自动生成 | ✅ **heap-UAF 出证** | **完成**（9d258f8） |
| fluidsynth 0.0.1 MidiRouter::new | ✅ ASSEMBLED（permits+None） | ✅ 生成 | ⚠️ 触发缺证 | 构建阻塞解除（编译 fluidsynth 1.1.10 → /usr/local/lib64）；1.1.10 源码确认 synth/player 事件路径不查 router，crate 唯一 safe 入口 ABI 错位，正确触发需 unsafe → harness 禁 unsafe → ASan 缺证（非证伪，详见 fluidsynth-midi-router-trigger-blocked-2026-08-17.md） |
| fltk 1.5.23 app::widget::set_callback | ✅ ASSEMBLED（permits+None） | ✅ 自动生成 | ✅ **heap-UAF 出证** | **完成**（adapter + do_callback 触发；发现生成器缺 ASan profile 段，详见 fltk-set-callback-detected-2026-08-17.md） |
| fltk 1.5.23 TreeItem::draw_item_content | ✅ ASSEMBLED（permits+ReceiverEscapes） | ✅ 自动生成 | ✅ **heap-UAF 出证** | **完成**（cfltk 下载解除 + xvfb 触发，详见 fltk-tree-draw-item-content-detected-2026-08-17.md） |
| ffmpeg 0.3.0 input_with_interrupt | ✅ ASSEMBLED（bridged，跨函数传播） | ✅ 自动生成 | ✅ **heap-UAF 出证** | **完成**（bridged 跨函数扩展 + 变异检查，详见 ffmpeg-030-input-with-interrupt-detected-2026-08-17.md） |

## 工具能力扩展（本批 3 个提交）

1. **bridged 判据扩展**（6f72fd7，tree-sitter 驱动）：
   - bridged_ptrs 收集 `Box::into_raw(Box::new(callback))` dest
   - extern 调用参数含 bridged 指针（结构体按值，如 TSLogger）→ bridged
   - 非 owner-held 分支检查 bridged（return_lifetimes 空）
   - decide_invalidate：Unresolved capture（elided lifetime）+ bridged → Generated
2. **自由函数 bridged**（9d258f8，sqlite-vfs 驱动）：return_lifetimes 空分支直接
   `bridged_in_method`（函数体自身，非仅 receiver 方法）——回调载体经 C 结构体
   指针交给 extern（sqlite3_vfs_register / ffmpeg AVIOInterruptCB 同形）

## 未完成项（后续）

- fltk ASan：xvfb + 事件循环触发（判定已过，价值是完整出证）
- ffmpeg：ffmpeg-sys 补丁（bindgen 兼容）+ input_with_interrupt 触发（FIFO/慢速 HTTP）
- fluidsynth：换 1.x libfluidsynth 或确认 2.x 触发路径（判定已过）
- tree-sitter/sqlite-vfs 的 judge verdict 模型 gap（载体维度未进三态）——与
  LSQL-01/MOSQ-02 同一 gap，论文/判定需对齐

## 证明了什么 / 没证明什么

**证明了**：

- 工具自动判定 + 自动生成 harness + ASan 出证在 2 个新 0day 候选上成立
  （tree-sitter、sqlite-vfs），均为 crates.io 最新稳定版、无 RUSTSEC；
- bridged 判据扩展到「回调载体经 C 结构体（按值/指针）间接交出」，覆盖
  非 owner-held 方法与自由函数——对 fltk/ffmpeg 同形候选有复用价值；
- 6 个高置信候选的判定层全部可达（5 个装配成功，ffmpeg 未跑因构建兼容）。

**没证明**：

- fltk/fluidsynth 的 ASan 出证未完成（触发环境限制，非证伪）；
- ffmpeg 判定未跑（ffmpeg-sys 构建兼容）；
- 外部侧（LLVM IR）全部未做（与前序候选同）；
- judge verdict 的载体维度 gap 未解决。

## 产物（远端 <results-root>/）

- treesitter-02612-*（完整出证）、sqlitevfs-020-*（完整出证）
- fluidsynth-0001-*（判定）、fltk-1523-*（判定）
- 文档：treesitter-setlogger-detected、sqlitevfs-register-detected
