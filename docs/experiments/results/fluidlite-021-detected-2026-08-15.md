# fluidlite FLUID-01（set_file_api 回调结构体 UAF）工具全链路出证 + 三个判据扩展

- 日期：2026-08-15
- 候选来源：用户 30 候选清单 FLUID-01（fluidlite 0.2.1 `Loader::set_file_api`）
- 前置：rusqlite 7/7 + git2 GIT-01/GIT-02 出证；openssl/libpulse 负方向验证
- 状态：**工具自动判定 → 自动生成 harness → ASan heap-use-after-free 出证**；
  为支持「回调结构体」形状（vtable/ops）扩展了三个判据 + 生成器通用 trait 模板

## 1. 候选形状（为什么它是工具的目标洞类）

`set_file_api<F: FileApi>(&self, fileapi: F)`——**无 'static 约束**：
- F 是自定义 trait（`open/read/seek/tell` 方法 + 关联类型 File），不是 Fn 家族；
- `wrap_fileapi` 把 F `Box::into_raw(Box::new(f))` 塞进 `fluid_fileapi_t.data` 交给 C
  （fluid_sfloader_t 持有），`Synth::sfload` 晚调 `open_wrapper` → `F::open`；
- 客户端可捕获借用（`StealApi { data: &buf }`），drop buf 后 sfload → UAF。
- 与 RUSTSEC-2021-0128 同构（注册 userdata + 借用捕获 + 晚调），但**回调载体是
  trait 对象结构体指针**而非 fn_ptr+userdata 对——C API 形状（vtable/ops）不在
  工具原有模型里。

## 2. 三个判据扩展 + 生成器扩展（compiler/bw-rustc + bw-cli）

| 扩展 | 位置 | 内容 |
| --- | --- | --- |
| ① trait 回调识别泛化 | `hir_bound_is_callable_trait` | 从「Fn 家族 + rusqlite Aggregate/WindowAggregate 硬编码」扩为「任何非 auto、有关联方法的 trait」。`T: Clone` 类约束也会成为候选观察，但装配阶段要求 allocation/lineage/symbol 证据，普通约束落缺证而非契约（不误报） |
| ② 间接交出 bridged | `bridged_in_method` | 识别「回调参数经本地 helper 包装返回裸指针」（`dest = wrap_fileapi(fileapi)`，dest 类型裸指针、args 含非 receiver 参数、被调方非 extern）为 bridged 指针；store 检测放宽到 receiver 内部 C 结构体字段（base 类型在 ffi/raw/sys/_sys） |
| ③ owner-held 回调包装 | `owner_holds_callback` | 识别「回调包装指针 store 到 receiver 相关位置」（含 dyn Fn 的 store 之外，新增 wrapped-cb-ptr store 到 receiver 字段/借用临时/C 结构体字段） |
| ④ 生成器通用 trait 模板 | `render_callback_block` | adapter 提供 `trait_impl`（含 `{referent}` 占位，覆盖 FileApi 等多方法 trait），存在时优先于 rusqlite Aggregate 硬编码；跳过 `struct {acc_type};` 渲染 |

## 3. ASan 出证（harness 由生成器产出，未手工编辑）

产物 `<results-root>/fluidlite-021-harness1/`，时序：
`loader.set_file_api(BwWitnessAgg{referent:&witness_referent}) → drop(witness_referent) → synth.add_sfloader(loader) → synth.sfload("dummy.sf2")`

```text
ERROR: AddressSanitizer: heap-use-after-free
  #0 String::len
  #1 BwWitnessAgg::open  main.rs:25（回调访问已 drop 的 referent）
  #2 open_wrapper  loader.rs:132
  #3 sfload_file  fluid_defsfont.c:2017
  #4 fluid_defsfont_load / fluid_defsfloader_load / fluid_synth_sfload
  #5 Synth::sfload  synth/font.rs:20
freed by: drop(witness_referent)  main.rs:43
```

## 4. 负对照（因果矩阵）

| 变体 | 修改 | ASan（detect_leaks=0） |
| --- | --- | --- |
| vulnerable | 原样 | **heap-use-after-free**（EXIT=1） |
| no-trigger | 不调 sfload | 干净（EXIT=0） |
| no-invalidate | 不 drop referent | 干净（EXIT=0） |

注意：fluidlite 的 wrap_fileapi Box 永不回收（C 持有），LeakSanitizer 会报泄漏——
泄漏不是目标洞类，对照统一 `ASAN_OPTIONS=detect_leaks=0`。

## 5. 变异检查

改坏扩展③的 `wraps_callback_arg`（取反）→ set_file_api 从「装配成功
(owner_holds_callback_bridged)」回落到 GAPPED(foreign_symbol_unresolved)，
assembled 1→0；恢复后重新装配。**判据有判别力，出证路径依赖它。**

## 6. 全量回归

`cargo test --workspace` 全绿（判据改动未破坏 rusqlite/git2/openssl 既有判定）。

## 7. 证明了什么 / 没证明什么

**证明了**：

- 工具能自动检出「回调结构体指针」形状（fluidlite FileApi 类 vtable/ops API）的
  FFI 回调生命周期 UAF：trait 泛化识别 → bridged 间接交出 → owner-held →
  harness 自动生成 → ASan 出证，全链路无手工编辑；
- 借用随回调结构体被 Box::into_raw 转移给 C 后，Rust 认为借用已消费结束 → 分离
  可构造（编译器允许 drop referent）→ UAF 由 harness 复现，与用户 PoC 结论一致；
- 变异检查证明三个扩展判据都有判别力（改坏 → 出证路径断裂）。

**没证明**：

- 未做外部侧（LLVM IR）——判定基于 Rust-only（captured_referent
  insufficient_evidence，缺外部事实）；晚调路径（fluid_synth_sfload → open_wrapper）
  由 C 源码人工确认，自动 IR 证据未补；
- `set_default_file_api`（全局默认 loader 形状）仍 gapped（foreign_symbol_unresolved）
  ——它的 extern 调用参数是包装指针（非 fn_ptr），`foreign_callback_calls` 不识别；
  与 set_file_api 的 bridged 路径不同，未扩展；
- allocation 仍是 Unresolved（跨函数分配已知 limitation：into_raw 在 wrap_fileapi，
  不在注册函数本体）——bridged 装配豁免了符号但未豁免 allocation，当前靠
  `MissingAllocationOwnership` 不触发（Unresolved 有值即过）维持；
- 负对照只做了 no-trigger/no-invalidate；`T: Clone` 类噪音（trait 泛化的副作用）
  未做数量化评估（hand_offs_total 33 里多数是噪音候选，gapped 不进契约）。

## 8. 产物（远端 <results-root>/fluidlite-021-*）

- analysis/（static-facts 296 条）、contracts4/5/（set_file_api bridged 装配）、
  joint/（rust-only）
- harness1/（vulnerable，ASan 出证）、harness-notrigger/、harness-noinvalidate/
  （对照干净）
- asan1.log（heap-use-after-free）、control-notrigger.log、control-noinvalidate.log
