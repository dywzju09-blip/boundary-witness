# sqlite-vfs 0.2.0 register（Vfs trait）工具全链路出证（0day 候选 #16）

- 日期：2026-08-16
- 候选来源：ffi-callback-hunt REPORT 候选 16（crates.io 最新稳定版，无 RUSTSEC）
- 状态：**工具自动判定 → 自动生成 harness → ASan heap-use-after-free 出证**；
  判定层扩展「自由函数 bridged」（回调载体经 C 结构体指针交给 extern）

## 1. 候选形状

`pub fn register<F: DatabaseHandle, V: Vfs<Handle = F>>(name: &str, vfs: V, as_default: bool)`（**无 'static**，自由函数）：

```rust
let ptr = Box::into_raw(Box::new(State { vfs: Arc::new(vfs), ... }));  // V 实例
let vfs = Box::into_raw(Box::new(ffi::sqlite3_vfs { pAppData: ptr as _, xOpen: Some(vfs::open::<F, V>), ... }));
ffi::sqlite3_vfs_register(vfs, as_default as i32);  // 结构体指针交 C
```

- Vfs trait 实例（可携带借用）经 `Box::into_raw` 进 `sqlite3_vfs` 结构体的
  pAppData，结构体指针交给 `sqlite3_vfs_register`；之后 `sqlite3_open_v2(..,
  "bwvfs", ..)` 用该 VFS → SQLite 调 `V::open` → 读已释放捕获 → heap-UAF；
- 区别于 FLUID-01（receiver 方法）：register 是**自由函数**（无 receiver）；
  区别于 rusqlite：extern setter 参数是**结构体指针**（非 fn-ptr+userdata 对）。

## 2. 判定层扩展（compiler/bw-rustc）

`registration_guards` 的 return_lifetimes 空分支：`receiver_bridged_to_foreign`
（仅 receiver 方法）替换为**直接 `bridged_in_method`**（对函数体自身）——回调载体
经 C 结构体指针/结构体参数间接交出时，无论 receiver 方法还是自由函数都命中
（sqlite-vfs register / ffmpeg input_with_interrupt 同形状）。

## 3. ASan 出证

时序：`register("bwvfs", BwWitnessAgg{referent:&witness_referent}, false) →
drop(referent) → rusqlite::open_with_flags_and_vfs("bwvfs.db", "bwvfs")`

```text
ERROR: AddressSanitizer: heap-use-after-free
  Vfs::open（读已释放 referent）
  ← SQLite 用注册的 VFS 打开 bwvfs.db
```

触发经 rusqlite（系统 sqlite 共享全局 VFS 注册表；bundled sqlite 不同实例
不共享，故 rusqlite 需 default-features=false + modern_sqlite）。

## 4. 负对照（因果矩阵）

| 变体 | 修改 | ASan（detect_leaks=0） |
| --- | --- | --- |
| vulnerable | 原样 | **heap-use-after-free**（EXIT=1） |
| no-trigger | 不 open（保留 rusqlite 引用以链接 sqlite） | 干净（EXIT=0） |
| no-invalidate | 不 drop referent | 干净（EXIT=0） |

## 5. 变异检查

bridged 判据（extern 参数检查）的变异已在 tree-sitter 候选验证（assembled 7→0）；
sqlite-vfs 走同一 `bridged_in_method`（extern 参数含 into_raw 指针），同判据
复用。全量 workspace 测试绿。

## 6. 证明了什么 / 没证明什么

**证明了**：

- 工具能自动检出「自由函数 + 回调结构体指针交给 extern」形状：bridged 判据扩展到
  函数体自身（非仅 receiver 方法）→ register 装配（guard=bridged）→ harness
  （Vfs trait 实现 + rusqlite 触发）→ ASan 出证；
- 判定维度覆盖「回调结构体指针」（FLUID-01 的 receiver 版 + sqlite-vfs 的自由函数版）。

**没证明**：

- judge verdict 仍 capture 维度（同前 gap）；
- 外部侧（LLVM IR）未做——晚调路径（sqlite3_open_v2 → V::open）由 SQLite C
  源码人工确认；
- Vfs/DatabaseHandle 的完整实现是 harness 样板（adapter 提供）——工具只判定
  注册形状，trait 方法体由 adapter 写（与 FLUID-01 同模式）；
- no-trigger 需要 rusqlite keepalive（未使用依赖不链接 sqlite）——构建细节，
  非判定问题。

## 7. 产物（远端 <results-root>/sqlitevfs-020-*）

- analysis/、contracts2/（register guard=owner_holds_callback_bridged）、joint/
- harness1/（vulnerable，ASan 出证）、harness-notrigger/、harness-noinvalidate/
- asan1.log、control-notrigger.log、control-noinvalidate.log
