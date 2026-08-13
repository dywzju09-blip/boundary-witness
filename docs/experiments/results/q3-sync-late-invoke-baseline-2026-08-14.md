# Q3 同步/延迟晚调判别基线验证：sqlite3_exec vs sqlite3_update_hook（2026-08-14）

- 日期：2026-08-14
- 前置：多库家族负方向验证（openssl/libpulse）暴露「同步 vs 延迟晚调」区分依赖
  外部侧；本记录用真实 sqlite3 IR 验证 Q3 现有实现（降级版）的判别力，作为
  晚调可达性升级的基线
- 目的：确认 Q3 现有实现能区分「同步回调（健全）」与「延迟注册（候选）」，不因
  降级实现把两类混为一谈

## 1. 实验

用阶段 3 的 sqlite3.ll（rusqlite 0.26.1 的 vendored sqlite3.c，48MB 文本 IR），
对两个语义相反的注册 API 跑 `bw extract-foreign-facts`：

| 注册 API | C 签名（回调位置） | 语义 | 期望 |
| --- | --- | --- | --- |
| `sqlite3_update_hook` | `(db, fn_ptr, userdata)` | 注册**延迟**回调（hook 存 db 结构，之后语句执行时触发） | may_retain + may_invoke_after_return |
| `sqlite3_exec` | `(db, sql, callback@2, userdata@3, errmsg)` | **同步**回调（exec 内逐行调用） | no_retain + synchronous_invoke_only |

## 2. 结果

```text
sqlite3_exec       | retention: no_retain                  | invocation: synchronous_invoke_only | slots: 0 | boundaries: 0
sqlite3_update_hook| retention: may_retain                 | invocation: may_invoke_after_return | evidence: same_slot_invoke_candidate
```

Q3 现有实现正确区分：

- **同步回调**（sqlite3_exec）：回调参数在入口函数内被直接调用
  （`has_synchronous_invoke`），且无槽位存储、无逃逸 → `no_retain +
  synchronous_invoke_only` → 判定链 `(NoRetain, _) → Denied`（compatible）；
- **延迟注册**（sqlite3_update_hook）：回调 userdata 存入 `%struct.sqlite3` 字段
  （槽位），全模块扫描到从槽位 load 后间接调用 → `may_retain +
  may_invoke_after_return`（`same_slot_invoke_candidate`，降级证据）→ 判定链
  `(MayRetain, MayInvokeAfterReturn) → Possible`（候选）。

## 3. 这说明了什么（Q3 升级基线）

降级 Q3（`find_same_slot_invokes`）**不做**的事，本验证明确划出边界：

- 它证明「存在从槽位读出后的间接调用点」，**不证明**该调用点从注册返回后的外部
  事件流**可达**（已知缺口：不证明晚调可达）。update_hook 的
  `may_invoke_after_return` 是"存在候选点"的最低证据，不是"一定晚调"；
- 升级方向 = 从「同槽间接调用点存在」到「该点在注册之后可达」（事件循环 /
  迭代器 next / future poll / 下一次语句执行等外部入口到该调用点的路径存在性）；
- **同步回调必须继续落 SynchronousInvokeOnly**（本次验证钉住这个正确行为），
  升级不得把同步调用误算成晚调——这是负方向回归基线。

## 4. 证明了什么 / 没证明什么

**证明了**：

- Q3 现有实现（降级）在真实 IR 上能正确分离同步回调与延迟注册两类形状
  （sqlite3_exec ↔ update_hook），`has_synchronous_invoke` 与
  `find_same_slot_invokes` 的分支选择正确；
- 外部侧同步判别的判定链 `(NoRetain, SynchronousInvokeOnly) → Denied` 有真实
  输入可达（不只在单元测试里）；
- 工具对 openssl 的 5 个 PEM permits 落 insufficient_evidence 的路径明确：缺
  libssl 外部 IR（未构建），非判别错误——若补 IR 且判 no_retain+synchronous，
  将落 compatible。

**没证明**：

- 未证明「晚调可达性」——update_hook 的 `may_invoke_after_return` 仍是降级证据
  （存在同槽间接调用点），升级（可达性证明）未实现；这是论文 C2 的核心工作，
  也是本基线服务的升级目标；
- 未做 openssl 外部 IR（libssl/libcrypto C 源码编译成本高，未执行）；
- sqlite3_exec 只验证了「回调直接调用」的同步形状；「回调经中间函数转发但整体
  同步」的形状（如 openssl PEM 的 CallbackState 包装）未在 IR 上验证
  （has_synchronous_invoke 只查入口函数内直接调用，包装形状会落
  Unresolved——按缺证纪律保留，不猜）。

## 5. 产物（远端 <results-root>/q3-sync/）

- roles/sqlite3_exec.foreign-roles.json（role map）
- foreign-facts.jsonl（sqlite3_exec：no_retain + synchronous_invoke_only）
- 对照：<results-root>/foreign-ir/rusqlite-0.26.1/facts/foreign-facts.jsonl
  （sqlite3_update_hook：may_retain + may_invoke_after_return）
