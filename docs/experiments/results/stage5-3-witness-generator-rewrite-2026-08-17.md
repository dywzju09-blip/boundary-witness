# 5.3 witness harness 生成器重写（硬编码清理 + ASan profile 修复）

- 日期：2026-08-17
- 范围：`crates/bw-cli/src/commands/generate_witness_harness.rs` 重写收尾
- 状态：rusqlite 特化模板全部删除；ASan profile 由生成器输出；extra_dependencies
  通用化；7 个候选批量重新生成 + 2 个端到端 ASan 出证（零手动修补）

## 1. 重写内容

| 项 | 之前 | 之后 |
| --- | --- | --- |
| rusqlite 特化 trait 模板 | `render_callback_block` 内置 `Aggregate`/`WindowAggregate` 硬编码（`rusqlite::functions::Context` 等，44 处 rusqlite 引用） | **全部删除**。trait 回调必须由 adapter 冻结的 `trait_impl` 提供；缺失 → `BW-WITNESS-TRAIT-IMPL-MISSING` 报错（缺证拒绝，不凑合） |
| ASan profile | 生成器**不输出** `[profile.dev] rustflags`——新 harness 默认无 ASan（本次会话在 fltk-callback 调试中定位：`nm <bin> | grep __asan_report` = 0） | **生成器输出** `cargo-features = ["profile-rustflags"]` + `[profile.dev]`/`[profile.dev.package."*"]`/`[profile.dev.package.<harness>]`：只有 harness bin 插桩，依赖不插桩（插桩范围越小误报面越小） |
| 额外依赖 | sqlite-vfs 的 trigger 用 `rusqlite::Connection` 触发 vfs，但生成器 Cargo.toml 只有主 crate → 出证时**手动加 rusqlite** | adapter schema 新增 `[[extra_dependencies]]`（name/version/default_features/features），生成器原样写进 `[dependencies]`（不 patch，crates.io 版本）。**通用能力**：任何 adapter 都能声明 |
| fltk-tree adapter | register 模板 `let item = ...`（`draw_item_content(&mut self)` 需要 mut）→ E0596 | adapter 改 `let mut item`（adapter 层修复，生成器保持"模板原样"职责划分） |

## 2. 验证

- **单元测试**：39 个全绿。新增：`trait_callback_without_trait_impl_is_rejected`、
  `cargo_toml_renders_extra_dependencies`；`cargo_toml_pins_version_and_vendor`
  加 ASan profile 断言（`cargo-features`/`[profile.dev]`/`-Zsanitizer=address`/
  `package."*"` rustflags=[]）。
- **批量重新生成**（tree-sitter / sqlite-vfs / ffmpeg / fltk×2 / fluidlite /
  fluidsynth）：7/7 生成成功，全部含 ASan profile + `#![forbid(unsafe_code)]`。
- **端到端出证**（重写后生成物直接跑，无任何手动编辑）：
  - fltk_tree：`cargo build`（CFLTK_BUNDLE_DIR）→ 24 个 `__asan_report` 符号 →
    `xvfb-run` 运行 → **heap-use-after-free**（EXIT=1）；
  - sqlite_vfs：Cargo.toml 自动含 `rusqlite = { version = "0.32", ... }` →
    编译通过 → 24 个 ASan 符号 → 运行 → **heap-use-after-free**（EXIT=1）。
- **回归**：`cargo test -p bw-cli` 单元 39 + 集成 31 全绿（build_precheck 超时测试
  在并行跑时偶发超时、单独跑通过——环境敏感，与本次改动无关）。

## 3. 证明了什么 / 没证明什么

**证明了**：

- 生成器已无 crate 特化代码：trait 回调、闭包回调、额外依赖全部由 adapter
  冻结内容驱动，7 个不同 crate 候选用同一生成器产出可编译、可出证的 harness；
- **ASan profile 是生成物的标准组成部分**：新生成 harness 开箱即带插桩配置，
  不再依赖人工补 `[profile.dev]`（fltk-callback 调试中确认的缺陷已根治）；
- adapter 的 `trait_impl`/`extra_dependencies` 机制足够表达多方法回调结构体
  （fluidlite FileApi、sqlite-vfs Vfs）与跨 crate 触发（rusqlite→vfs）两类
  真实形状。

**没证明**：

- **生成物编译通过 ≠ ASan 触发**：批量验证只确认了生成 + profile 输出 + 2 个
  候选的编译与出证；其余候选（tree-sitter/ffmpeg/fluidlite/fluidsynth）的
  新生成物未逐一重跑 ASan（此前已出证过，且生成逻辑对它们无差异）；
- **fluidsynth 触发缺证依旧**：生成器输出正常（invalidate=generated），但
  safe 触发不可达的问题（见 fluidsynth-midi-router-trigger-blocked 记录）不在
  生成器职责内——`#![forbid(unsafe_code)]` 保持（研究主张），未为 fluidsynth
  引入 unsafe 触发通道（需用户决策）；
- `setup` 片段里的 `Command::spawn()?`（ffmpeg 慢速 HTTP 服务器）仍是 adapter
  作者的责任——生成器不干预 adapter 片段内容；
- 生成器未做「生成物最小性」审计（每个输出行是否都被消费）——属于后续清理，
  不影响本次四槽语义。
