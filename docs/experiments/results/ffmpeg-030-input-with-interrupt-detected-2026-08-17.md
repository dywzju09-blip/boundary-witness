# ffmpeg 0.3.0 format::input_with_interrupt 工具全链路出证（0day 候选）

- 日期：2026-08-17
- 候选来源：高置信 0day 候选清单（ffmpeg crate，crates.io 最新 0.3.0，无 RUSTSEC）
- 状态：**工具自动判定（bridged 扩展）→ 自动生成 harness → ASan heap-use-after-free 出证**；
  判定层扩展「跨函数 bridged 传播（深度 ≤3）+ 有 bridged 载体即 bridged」

## 1. 候选形状

`format::input_with_interrupt<P: AsRef<Path>, F>(path: &P, closure: F) -> Result<Input>`
（`F: FnMut() -> bool`，**无 'static bound**）：

```rust
// ffmpeg-0.3.0 src/format/mod.rs
let mut ps = avformat_alloc_context();
(*ps).interrupt_callback = interrupt::new(Box::new(closure)).interrupt;  // ← 间接交出
avformat_open_input(&mut ps, path.as_ptr(), ...)
```

- `interrupt::new`（src/util/interrupt.rs）把闭包 `Box::into_raw` **泄漏到堆**，
  构造 `AVIOInterruptCB { callback: Some(callback::<F>), opaque }` 返回；
  `Interrupt` 无 Drop，opaque 永久有效——闭包**载体**不会 UAF；
- 但 API 签名接受**非 'static 闭包**：闭包可捕获局部变量引用。`input_with_interrupt`
  返回后 Rust 类型系统认为闭包所有权已转移、借用已结束，用户合法地 `drop` 捕获对象；
  C 侧 `AVFormatContext.interrupt_callback` 仍指向堆上闭包——**packets 阶段
  av_read_frame → avio_read → ff_check_interrupt 再次调用闭包 → 访问已释放捕获对象**。
- 区别于 git2 的 receiver 桥接：这是**自由函数**的 C 结构体字段 store
  （`(*ps).interrupt_callback = ...`），回调载体经 `interrupt::new` **跨函数**
  构造（调用方没有直接 into_raw / store，只消费其返回值）。

## 2. 判定层扩展（compiler/bw-rustc/src/rustc_api/mir.rs）

| 扩展 | 位置 | 内容 |
| --- | --- | --- |
| ① 跨函数 bridged 传播 | `bridged_in_method_depth` | 调用本地函数（且非自身）时递归检查被调方 bridged；被调方 bridged → 返回值 local 加入 bridged 载体集（ffmpeg `interrupt::new` 形状） |
| ② 深度上限 | `bridged_in_method_depth` | `MAX_DEPTH = 3`，防递归环（包装层数越深结论越弱，不随手调大） |
| ③ 尾部判据 | `bridged_in_method_depth` 末尾 | `bridged_ptrs` 非空（函数体内有回调载体 into_raw / 包装指针）即 bridged——即使本函数无直接 store/extern 交出（载体由调用方转交 C） |

装配层（compatibility.rs）对 `guard=owner_holds_callback_bridged` 的契约允许
`foreign_symbol=None`（延迟交出：回调经 C 结构体桥接，符号不直接出现），
witness 层（generate_witness_harness.rs）把 bridged 判为
`InvalidateDecision::Generated`——由判定推出 invalidate 槽。

## 3. ASan 出证

时序：`spawn 慢速 HTTP server → input_with_interrupt(url, callback) → drop(witness_referent)
→ packets() 迭代（慢速网络读 → C 侧轮询 interrupt callback）`

```text
ERROR: AddressSanitizer: heap-use-after-free on address 0x7b67348e1730
READ of size 8
  #0 <alloc::vec::Vec<u8>>::len
  #1 <alloc::string::String>::len
  #2 main::{closure#0}  main.rs:19   ← 闭包读 witness_referent.len()
  #3 ffmpeg::util::interrupt::callback::{closure#0}  interrupt.rs:15（catch_unwind）
  #8 ffmpeg::util::interrupt::callback  interrupt.rs:15（extern "C" trampoline）
  #9 libavformat.so.58+0x70f47       ← C 侧 ff_check_interrupt（无符号）
  #10 avio_read
  #15 av_read_frame
  #16 ffmpeg::codec::packet::Packet::read  packet.rs:200
  #18 main  main.rs:30               ← packets.next()
freed by thread T0:
  #5 main  main.rs:26                ← drop(witness_referent) 释放 24 字节 String 堆
previously allocated:
  #2 <alloc::alloc::Global>::alloc_impl_runtime   ← Box::new(String)
SUMMARY: AddressSanitizer: heap-use-after-free in <alloc::vec::Vec<u8>>::len
```

证据链闭环：**Rust 侧闭包（捕获 referent 引用）→ 经 interrupt::new 桥接进 C
结构体 → packets 阶段 C 侧 av_read_frame 调 ff_check_interrupt → 回调闭包 → 读
已 drop 的 referent 堆 → ASan heap-use-after-free**。

## 4. 负对照（因果矩阵，detect_leaks=0）

| 变体 | 修改 | ASan | 退出码 |
| --- | --- | --- | --- |
| vulnerable（正证） | drop referent + packets 迭代 | **heap-use-after-free** | EXIT=1 |
| no-invalidate | 不 drop referent（其余同正证） | 干净（0 错误） | EXIT=0 |
| no-trigger | drop referent + 不迭代 packets | 干净（0 错误） | EXIT=0 |

invalidate 与 trigger 均为必要条件：缺任一侧都构不成 UAF。

## 5. 变异检查（bridged 尾部判据）

改坏 `bridged_in_method_depth` 尾部 `true → false`（有 bridged 载体即 bridged 的
判据关掉），重编译 bw-rustc + 重跑 ffmpeg 静态分析 + 装配：

| 运行 | assembled | gapped | input_with_interrupt guard |
| --- | --- | --- | --- |
| 基线（变异前） | 23 | 1 | owner_holds_callback_bridged |
| **变异（tail true→false）** | **7** | **17** | **None（CHANGED）** |
| 恢复（tail false→true） | 23 | 1 | owner_holds_callback_bridged |

变异使 16 条契约转红（含 ffmpeg 3 个 bridged 点：input_with_interrupt /
interrupt::new / Input::seek），证明 bridged 尾部判据有真实判别力；恢复后全绿。

## 6. 证明了什么 / 没证明什么

**证明了**：

- 工具能自动检出「自由函数把回调载体经**跨函数**构造的 C 结构体（AVIOInterruptCB）
  间接交给 C + 非 'static 闭包捕获」形状：bridged 跨函数传播 → guard
  owner_holds_callback_bridged → invalidate=Generated → harness → ASan 出证；
- 跨函数 bridged 传播（深度 ≤3）正确识别 interrupt::new 这类「调用方只消费返回值」
  的构造，且变异检查证明该判据是本候选判定的必要支撑；
- 负对照证明 invalidate（drop referent）与 trigger（packets 迭代）都是 UAF 的
  必要条件——不是剧本自带的假阳性；
- ffmpeg 0.3.0 的 `input_with_interrupt` 存在真实的 FFI 回调生命周期 soundness
  缺陷：API 接受非 'static 闭包但把闭包永久交予 C 侧，类型系统不阻止调用方
  drop 捕获对象后 C 侧再调用。

**没证明**：

- **这不是 0day 判定的最终裁决**：ffmpeg 0.3.0 是 2020 年的旧版本，未确认该
  soundness 缺陷是否已被上游修复、是否有公开编号（无 RUSTSEC 记录）——披露
  类判断需用户决定；
- judge 三态 verdict 未走完整外部侧：本次验证是 harness 层的 ASan 出证（witness
  路径），`joint-verdicts` 仍是 rust-only 模式（foreign_facts_total=0），外部侧
  LLVM IR 的「晚调可达」未独立证明——trigger 阶段 C 侧确实调用 interrupt
  callback 由 ASan 栈（av_read_frame → ff_check_interrupt）给出，但 IR 侧没有
  对应的 retain/调用证据；
- harness 生成器（stage 5.3 待重写）的 setup 槽用 `Command::spawn()?` 太脆：
  慢速 HTTP 服务器由 harness 直接 spawn，端口被占时 `?` 让程序直接退出；
  真实运行时改为容忍 spawn 失败 + 测试前手动起服务器（本验证的实际做法），
  这属于 5.3 重写范围（setup 应来自 adapter 冻结片段且容忍外部服务就绪）；
- 测试基建两个坑（记录供后人）：`ThreadingTCPServer` 的 `allow_reuse_address`
  必须在类定义/构造前设置（实例化后再设不生效，反复 kill 服务器后 TIME_WAIT
  会令 bind 失败）；ssh 远程命令里 `pkill -f "python3 server.py"` 会匹配到
  **执行该命令的 shell 自身**（cmdline 含完整命令文本）导致会话自杀，需用脚本
  文件方式或 `[p]attern` 技巧；
- ffmpeg harness spawn 的服务器继承 stdout 管道写端，harness 退出后孤儿进程
  会让 `grep`/管道永不 EOF——测试要用文件重定向 + 事后 pkill，不能直接管道。
