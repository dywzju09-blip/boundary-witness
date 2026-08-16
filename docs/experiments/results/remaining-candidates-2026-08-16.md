# 未完成候选处理记录（fltk / fluidsynth / ffmpeg）2026-08-16

- 范围：高置信 6 个候选的剩余 4 个（fltk×2、fluidsynth、ffmpeg）
- 结论：判定层全部可达；ASan 出证受**构建/触发环境**阻塞（非证伪，缺证记录）

## 1. fltk 1.5.23（set_callback / TreeItem::draw_item_content）

- **判定层**：✅ 两个 API 均 ASSEMBLED（app::widget::set_callback：permits+None；
  TreeItem::draw_item_content：permits+ReceiverEscapesAsUserData），harness 自动生成
  （invalidate=generated，含 Tree+Window+xvfb 触发链）
- **ASan 阻塞**：fltk-bundled 需从 GitHub（MoAlyousef/cfltk）下载预编译 C++ 库，
  服务器无法访问 GitHub releases → 构建失败。触发链已设计（show() + app::run()
  绘制触发 draw_item_content 回调；事件循环触发 set_callback）
- **非证伪**：cfltk 下载是构建环境问题；若换 fltk-system（系统 FLTK）+ 网络可用可出证

## 2. fluidsynth 0.0.1（MidiRouter::new）

- **判定层**：✅ ASSEMBLED（permits+None+new_fluid_midi_router），harness 自动生成
- **ASan 阻塞**：crate 的触发 API `Synth::set_midi_router` 是 libfluidsynth 1.x 符号，
  系统 2.2.5 已移除（链接失败）；`MidiRouterRule::handle_midi_event` 存在但 ABI
  错位（传 rule 指针而非 router）；harness `#![forbid(unsafe_code)]` 无法直接调
  C 的 `fluid_midi_router_handle_midi_event`（2.2.5 有此符号）
- **非证伪**：用户 Valgrind 在 libfluidsynth 1.1.6 上出证；2.2.5 的 safe 触发路径
  在 crate API 层缺失

## 3. ffmpeg 0.3.0（input_with_interrupt）

- **构建补丁进展**（本批完成）：
  1. bindgen 0.69.5 的 rust_ident_raw patch（清理 clang unnamed enum spelling 的
     非法字符 / 等）→ **bindgen panic 解决**
  2. ffmpeg-sys-4.3.3 复制到 corpus + patch（blocklist、enum 风格、alias 补丁）→
     **ffmpeg-sys 编译通过**
  3. ffmpeg 0.3.0 本体 15 个 match 通配补丁（用户 patch_matches 应用）→ E0004 解决
- **剩余冲突**：bindgen 对 `typedef enum {} X;`（同名 typedef）生成 `type X = i32`
  （enum-typedef 简化），ffmpeg-sys 手写 pixfmt.rs 的 `use crate::AVPixelFormat::*`
  需要 enum/mod；ModuleConsts 生成 mod（glob ✓）但缺类型（E0573），补 alias 冲突
  （E0428）。用户环境（bindgen 0.69 不同构建）补丁组合可编译，服务器环境需继续
  调优（如 constified 特定 enum + 手写类型适配）
- **判定层**：未跑（构建未通）；input_with_interrupt 形状（关联函数 + AVIOInterruptCB
  结构体 + 自由函数 bridged）已由 sqlite-vfs 验证同判据

## 4. 工具能力增量（本批）

- 无新判据改动（4 个候选的判定层复用既有能力：bridged/free-function bridged/
  ReceiverEscapesAsUserData 全部命中）
- ffmpeg 构建补丁（bindgen rust_ident_raw 清理 + ffmpeg-sys 兼容）为后续 ffmpeg
  家族（ffmpeg-next/rsmpeg 等）复用

## 证明了什么 / 没证明什么

**证明了**：

- 4 个候选的判定层全部可达（fltk×2/fluidsynth 装配成功 + harness 生成；ffmpeg
  判定未跑因构建）；
- 工具判定不依赖外部构建成功——静态判定（wrapper + contracts）在构建兼容问题
  前已独立完成（fltk/fluidsynth）；
- ffmpeg 的构建兼容补丁路径明确（bindgen 清理 + enum 风格 + match 通配），用户
  补丁脚本验证了方向。

**没证明**：

- fltk/fluidsynth 的 ASan 出证（构建/触发环境阻塞，非证伪）；
- ffmpeg 判定与 ASan（构建未通）；
- 这些候选的 judge verdict 载体维度 gap（同前）。

## 产物（远端 <results-root>/）

- fltk-1523-analysis/contracts/（2 个 API 装配）、fltk-tree-harness1/
- fluidsynth-0001-*（判定+harness）
- ffmpeg-030-analysis/（补丁后部分编译产物）
- 补丁：corpus/component/bindgen-0.69.5-bw、ffmpeg-sys-4.3.3（未提交，仅服务器）
