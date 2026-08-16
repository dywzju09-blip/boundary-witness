# tree-sitter 0.26.12 Parser::set_logger 工具全链路出证（0day 候选 #3）

- 日期：2026-08-16
- 候选来源：ffi-callback-hunt REPORT 候选 3（crates.io 最新稳定版，无 RUSTSEC）
- 状态：**工具自动判定 → 自动生成 harness → ASan heap-use-after-free 出证**；
  判定层扩展「非 owner-held bridged + extern 结构体参数 + Unresolved 覆盖」

## 1. 候选形状

`Parser::set_logger(&mut self, logger: Option<Logger>)`，`type Logger<'a> =
Box<dyn FnMut(LogType, &str) + 'a>`（**无 'static**，type alias 私有但可推断）：

```rust
let container = Box::new(logger);
let raw_container = Box::into_raw(container);   // 闭包堆地址
ffi::TSLogger { payload: raw_container.cast(), log: Some(log) }  // 结构体
ffi::ts_parser_set_logger(self.0.as_ptr(), c_logger);  // 结构体按值交 C
```

- 回调载体（Box<dyn FnMut>）经 **TSLogger 结构体**（payload 字段）交给 C，parse 时
  C 调 `log` shim → 闭包读已 drop 的捕获 → heap-UAF；
- 区别于 rusqlite 形状：extern setter 参数是**结构体**（非 fn-ptr+userdata 对）；
  Logger 的 lifetime 是 **elided**（签名 `Option<Logger>` 无显式 'a）。

## 2. 判定层扩展（compiler/bw-rustc + bw-cli）

| 扩展 | 位置 | 内容 |
| --- | --- | --- |
| ① bridged_ptrs 收集 into_raw | `bridged_in_method` | `Box::into_raw(Box::new(callback))` 的 dest（裸指针）加入 bridged 指针集（宽松收集，store/extern 检测兜底） |
| ② extern 结构体参数检查 | `bridged_in_method` | extern 调用的参数 local ∈ bridged_ptrs → bridged（tree-sitter `ts_parser_set_logger(parser, c_logger)`；此前只认 fn-ptr 参数） |
| ③ 非 owner-held bridged | `registration_guards` | `return_lifetimes.is_empty()` 分支也检查 `receiver_bridged_to_foreign`——回调载体经 receiver 的 C 结构体指针字段/结构体参数间接交出时（set_logger 不存 receiver 字段，仍分离可构造） |
| ④ Unresolved + bridged | `decide_invalidate` | capture_admission=Unresolved（elided lifetime）时 bridged → Generated（载体维度与 capture 独立，缺证不阻塞分离） |

## 3. ASan 出证

时序：`set_logger(Some(Box::new(callback))) → drop(referent) → set_language(JSON) → parse(json)`

```text
ERROR: AddressSanitizer: heap-use-after-free
  #2 main::{closure#0}  main.rs:18（logger 闭包读已释放 witness_referent）
  ← tree-sitter C 的 log shim（parse 期间）
```

触发需 language（tree-sitter-json 0.24.8）+ JSON 代码——无 language 的 parse
不产生日志事件。

## 4. 负对照（因果矩阵）

| 变体 | 修改 | ASan（detect_leaks=0） |
| --- | --- | --- |
| vulnerable | 原样 | **heap-use-after-free**（EXIT=1） |
| no-trigger | 不 parse | 干净（EXIT=0） |
| no-invalidate | 不 drop referent | 干净（EXIT=0） |

## 5. 变异检查

改坏 bridged 的 extern 参数检查（恒跳过 extern）→ set_logger 从 ASSEMBLED
（bridged）回落到 GAPPED（foreign_symbol_unresolved），assembled 7→0；
恢复后重新装配。全量 workspace 测试绿。

## 6. 证明了什么 / 没证明什么

**证明了**：

- 工具能自动检出「回调载体经 C 结构体（按值）交给 extern + elided lifetime」形状：
  into_raw 收集 → extern 结构体参数 bridged → 非 owner-held 分支 → Unresolved 覆盖
  → harness → ASan 出证；
- 判定维度扩展到「回调经结构体参数间接交出」（非 fn-ptr+userdata 对、非字段 store）；
- 变异检查证明新判据有判别力。

**没证明**：

- judge verdict 仍 capture 维度（Unresolved + bridged 分支）——载体维度未进三态
  verdict（与 LSQL-01/MOSQ-02 同一 gap）；
- 外部侧（LLVM IR）未做——晚调路径（parse 期间 log shim）由 C 源码人工确认；
- Logger type alias 私有（可推断）——外部可调用但类型不透明，工具 harness 依赖
  推断编译（已验证可编译）；
- bridged extern 参数检查可能让其他「extern 参数恰是 into_raw 结果」的 API 也命中
  bridged（guard None→Bridged）——判定行为等价（都 Generated），全量测试未发现
  破坏，但未逐 API 审计。

## 7. 产物（远端 <results-root>/treesitter-02612-*）

- analysis/、contracts4/（set_logger guard=owner_holds_callback_bridged）、joint/
- harness1/（vulnerable，ASan 出证）、harness-notrigger/、harness-noinvalidate/
- asan1.log（heap-use-after-free）、control-notrigger.log、control-noinvalidate.log
