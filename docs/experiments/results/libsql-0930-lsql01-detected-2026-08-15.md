# libsql LSQL-01（authorizer receiver-as-userdata UAF）工具全链路出证 + 四个扩展

- 日期：2026-08-15
- 候选来源：用户 30 候选清单 LSQL-01（libsql 0.9.30 `Connection::authorizer`）
- 前置：rusqlite 7/7 + git2 GIT-01/02 + fluidlite FLUID-01 出证
- 状态：**工具自动判定 → 自动生成 harness → ASan heap-use-after-free 出证**；
  为支持「receiver 自身地址作 userdata」形状扩展了判定层 + 生成器

## 1. 候选形状

`Connection::authorizer(&self, hook: Option<AuthHook>)`（AuthHook = Arc<dyn Fn>）：

```rust
*self.authorizer.write() = hook.clone();
let user_data = self as *const Connection as *mut c_void;   // receiver 地址作 userdata
sqlite3_set_authorizer(self.handle(), callback, user_data);
```

- `transaction()` 把 `self.clone()` 包进**新 Arc**（新 LibsqlConnection 结构体）；
- `drop(conn)` 释放原 LibsqlConnection → 原 local::Connection 结构体释放；
- SQLite 仍持有 user_data（指向原 local::Connection）→ 后续任何 SQL（prepare /
  事务结束）触发 `authorizer_callback` → 读已释放的 `authorizer` 字段（ArcInner）→ UAF。
- 与回调捕获无关（hook 是 'static）——**UAF 在 receiver 地址逃逸维度**。

## 2. 四个扩展

| 扩展 | 位置 | 内容 |
| --- | --- | --- |
| ① alias trait-object 识别修复 | `callback_trait_object_lifetime` | alias 无 lifetime 实参（`AuthHook = Arc<dyn Fn>`）时返回 StaticByContainerDefault；此前识别成功但不返回，与 collect 路径漂移（独立提交 629e2cc） |
| ② 动态分发调用图边 | `crate_call_graph` | trait 方法 FnDef 调用（`self.conn.authorizer` on `Arc<dyn Conn>`）把本 crate 所有同名 impl 方法加入可能目标——公开入口 → trait → impl → extern 链不再断在 trait 方法 |
| ③ `RegistrationGuard::ReceiverEscapesAsUserData` | `registration_guards` + `receiver_escapes_as_userdata` | 检测 receiver cast 裸指针作为 extern userdata（含 tuple 拷贝链数据流回溯）；独立于回调 'static-ness；decide_invalidate 在 requires_static 下也 Generated |
| ④ 生成器 | `callback_no_referent` + `default_features` + 契约精确匹配 | 回调不访问 referent（UAF 不经捕获）；`default-features=false`（libsql 默认拉 HTTP 栈）；契约匹配精确优先（ends_with 宽松会取到 wrapper 版 guard=none） |

## 3. ASan 出证（harness 由生成器产出，未手工编辑）

时序：`conn.authorizer(Arc<callback>) → tx = transaction() → drop(conn) → tx.execute("CREATE TABLE...")`

```text
ERROR: AddressSanitizer: heap-use-after-free
  #3 libsql::local::connection::authorizer_callback  connection.rs:705（读 ArcInner<RwLock<Option<Arc<dyn Fn>>>>）
  #4 sqlite3AuthCheck  sqlite3.c:122702
  #5 sqlite3StartTable  sqlite3.c:124016（CREATE TABLE 解析）
  #12 libsql_sys::statement::prepare_stmt → local::Connection::execute
  #18 bw_block_on → main  main.rs:46（tx.execute）
```

与用户 PoC trace 一致。**触发面更宽**：tx 的 drop（`sqlite3EndTransaction`）也会触发
authorizer——no-trigger 必须不创建事务（任何后续 SQL 路径都是晚调）。

## 4. 负对照（因果矩阵）

| 变体 | 修改 | ASan（detect_leaks=0） |
| --- | --- | --- |
| vulnerable | 原样 | **heap-use-after-free**（EXIT=1） |
| no-trigger | 不创建事务（无晚调路径） | 干净（EXIT=0） |
| no-invalidate | 不 drop(conn) | 干净（EXIT=0） |

注意：naive no-trigger（只删 execute）**不干净**——tx drop 的 EndTransaction 也是晚调。

## 5. 变异检查

改坏 `receiver_escapes_as_userdata` 的 extern 检查（恒跳过）→ local authorizer guard
从 `receiver_escapes_as_user_data` 回落到 none → decide_invalidate Refused →
出证路径断裂；恢复后重新装配。**判据有判别力。**

## 6. 构建注意（ASan + proc-macro）

- `-Zsanitizer=address` 与 proc-macro crate（thiserror-impl 等）冲突 → harness
  Cargo.toml 用 `cargo-features = ["profile-rustflags"]` + `[profile.dev.package."*"]
  rustflags = []` 通配排除 + 显式恢复 `libsql`/bin 的 ASan（bin 提供运行时、libsql
  提供检测）；不设 RUSTFLAGS env（会覆盖 profile）。
- 该配置是 harness 构建配置（非工具逻辑），由 adapter 文档记录。

## 7. 证明了什么 / 没证明什么

**证明了**：

- 工具能自动检出「receiver 自身地址作 userdata + clone/drop 逃逸」形状的 FFI UAF：
  动态分发穿透（Arc<dyn Conn> 委托链）→ ReceiverEscapesAsUserData 判据 →
  harness 自动生成 → ASan 出证；
- 即使回调捕获是 'static（hook 不可借用），userdata 维度逃逸独立构成 UAF——工具
  的判定维度从「回调捕获生命周期」扩展到「userdata 载体生命周期」；
- 变异检查证明新判据有判别力；全量测试绿（既有 rusqlite/git2/fluidlite 判定不受影响）。

**没证明**：

- judge 的 verdict 模型仍是 capture 维度（requires_static → compatible）——
  ReceiverEscapesAsUserData 的 userdata 维度未进 StaticVerdict 三态（verdict 显示
  compatible 而 harness 实际出证 UAF——**文档明确记录这个模型 gap**，不假装一致）；
- 外部侧（LLVM IR）未做——晚调路径（sqlite3AuthCheck → authorizer_callback）由
  C 源码人工确认，自动 IR 证据未补；
- no-trigger 只验证了「无事务」构造；「有事务但不触发」的构造不存在（EndTransaction
  本身触发），未另测；
- MALLOC_PERTURB_ 下 execute 卡死（悬垂内存填充改变行为）——作为悬垂的补充信号
  记录，不是主证据（ASan 已出证）。

## 8. 产物（远端 <results-root>/libsql-0930-*）

- analysis/、contracts6/7/（local authorizer guard=receiver_escapes_as_user_data）、
  joint/（rust-only）
- harness1/（vulnerable，ASan 出证）、harness-notrigger/、harness-noinvalidate/
  （对照干净）
- asan1.log（heap-use-after-free）、control-notrigger.log、control-noinvalidate.log
