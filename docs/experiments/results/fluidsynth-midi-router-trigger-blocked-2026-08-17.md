# fluidsynth 0.0.1 MidiRouter::new 验证记录（触发缺证，非证伪）

- 日期：2026-08-17
- 候选来源：高置信 0day 候选清单（fluidsynth crate 0.0.1，crates.io 最新，无 RUSTSEC）
- 状态：**判定层 ASSEMBLED + harness 生成 + 构建通过（1.x 库就绪）**；
  **ASan 触发缺证**——safe API 下 router 事件不可达（详见 §4），不是证伪

## 1. 候选形状（crate 源码 src/midi.rs）

`MidiRouter::new<T: Fn(MidiEvent) -> i32>(settings, callback)`（**无 'static**）：

```rust
let user_data = &callback as *const _ as *mut c_void;   // ← 栈上闭包参数地址直接交 C
let router = new_fluid_midi_router(settings.to_raw(), midi_router_callback_wrapper::<T>, user_data);
```

- **user_data 是闭包参数的栈地址**（不是 Box::into_raw 堆）：`new` 返回后参数 drop，
  C 侧 `fluid_midi_router_t` 持有悬垂栈指针；
- 判定（fluidsynth-0001-contracts）：`guard=none`、`capture_admission=permits_non_static_capture`
  → ASSEMBLED，harness invalidate=generated。

## 2. 构建阻塞解除（本次完成）

- 系统 libfluidsynth 2.2.5（.so.3）**缺 `new_fluid_midi_router` / `fluid_synth_set_midi_router`**
  （2.x 移除 midi router 创建/绑定 API）→ 之前 harness 链接失败；
- **编译 fluidsynth 1.1.10 源码**（codeload GitHub tarball + cmake 4.4 需
  `-DCMAKE_POLICY_VERSION_MINIMUM=3.5`，关闭全部音频/驱动依赖）→ 安装到
  `/usr/local/lib64`（`libfluidsynth.so.1.7.1`，含 `new_fluid_midi_router` /
  `fluid_synth_set_midi_router` / `fluid_midi_router_handle_midi_event`）；
- 系统无版本 `libfluidsynth.so` 符号链接改指 1.1.10（备份为 .bak2x）；
- harness 补 ASan profile（生成器缺陷，见 fltk-set-callback 记录）→ 构建通过，
  `nm` = 24 个 `__asan_report` 符号。

## 3. 触发尝试（全部失败，缺证）

| 触发路径 | 结果 |
| --- | --- |
| `synth.noteon(0, 60, 100)`（adapter 原 trigger） | 不经过 router（synth 直接合成，事件路径无 router 拦截） |
| `MidiRouterRule::handle_midi_event(&event)` | **ABI 错位**：crate 把 router 级函数包装在 rule 上，传 `fluid_midi_router_rule_t*` 给 `fluid_midi_router_handle_midi_event`（期望 router*）→ 实测不触发 |
| `Player` 播放 SMF（`player.add/play/join`） | player→sequencer→`fluid_synth_handle_midi_event`：1.1.10 源码确认该函数 **switch 直接处理事件，不查 `synth->midi_router`**（router 只在输入驱动层 fluid_mdriver.c 被调）→ 闭包不触发 |
| 直接调 `fluid_midi_router_handle_midi_event(router, evt)` | **需要 unsafe**（crate ffi 是 extern fn）；harness 强制 `#![forbid(unsafe_code)]`（研究主张）→ 不可用 |

## 4. 证明了什么 / 没证明什么

**证明了**：

- 判定层正确识别该形状（permits_non_static_capture + guard none → 分离可构造）；
- harness 生成 + 1.x 库链接 + ASan 插桩全部就绪（构建阻塞彻底解除，含系统
  2.2.5 缺符号问题的解决方案，供 fluidsynth 家族后续候选复用）；
- 1.1.10 源码确认：**set_midi_router 只是设置指针，synth 事件处理不查 router**——
  REPORT-19 里"noteon 触发"的假设在此版本不成立（REPORT 的 Valgrind 出证用的是
  直接 C 调用，非 safe API）。

**没证明**（缺证，具体到点）：

- **ASan 出证未完成**：没有找到 safe 且语义正确的 router 事件触发路径；
  crate 唯一 safe 入口（rule.handle_midi_event）ABI 错位，synth/player 路径
  不经过 router，正确触发必须 unsafe 直接 C 调用——与 harness 的
  `#![forbid(unsafe_code)]` 冲突；
- 因此「闭包悬垂后 C 侧晚调 → 读已释放捕获 → UAF」在**本工具 harness 约束下**
  未实证（逻辑链完整，触发工程不可达）——**不是候选被证伪**；
- 该候选的 closure user_data 是**栈地址**：即使触发，闭包体读的是堆 referent
  （ASan 可报堆 UAF），但闭包自身栈 UAF 依赖 rustc ASan 的栈插桩（已知不可靠），
  出证形态预期依赖 referent 堆读取；
- 披露状态未确认（无 RUSTSEC，是否上游已修复未知）——披露判断需用户决定。

## 5. 后续可选路径（5.3 生成器重写范围）

- harness 生成器若支持「adapter 声明的 unsafe 触发片段 + 单独的白名单审计」，
  本候选可补证（trigger 直接调 `fluid_midi_router_handle_midi_event`）；
  当前 forbid(unsafe_code) 是研究主张，改动需用户决策；
- 或换 crate（fluidlite 已出证 set_file_api，若 fluidlite 有 midi router 且
  Rust 绑定 safe 暴露 handle 事件，可作同形状替代验证）。
