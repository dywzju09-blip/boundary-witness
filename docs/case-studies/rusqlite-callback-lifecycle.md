# rusqlite callback lifecycle

## 历史漏洞事实

[RUSTSEC-2021-0128](https://rustsec.org/advisories/RUSTSEC-2021-0128.html) 记录 rusqlite 0.25.0–0.25.3、0.26.0–0.26.1 的 callback lifetime 约束不足，修复版本为 0.25.4、0.26.2 及之后版本。多个受影响 API 属于同一 retained-borrowed-callback 根因家族，统计时算一个独立根因。[原始 issue #1048](https://github.com/rusqlite/rusqlite/issues/1048) 提供了真实触发背景。

来源等级为 `S2`。这是公开历史事实，不等于当前工作树已重新执行所有动态实验。

## 最小触发链

```text
创建局部 Rust owner
  -> callback 按引用 capture owner
  -> Connection 将 callback/user_data 注册给 SQLite
  -> 局部 owner 生命周期结束
  -> SQLite 仍保留 callback
  -> 后续 SQL 触发 callback
  -> callback 读取已结束生命周期的对象
```

同源对照必须包括 owned/move capture、owner 结束前 unregister、注册但不触发、0.26.2 borrowed compile rejection 和 0.26.2 可运行安全版本。仓库中的 12 个隔离 case 见 [benchmark README](../../benchmarks/historical-cves/rusqlite/README.md)。

## BoundaryWitness 可观察事实

### 静态

- `CallbackSite` 与 `CallbackCapture`：callback 定义、capture mode 和 capture slot；
- `RegistrationSite`：exact API、register/unregister role、callback/user-data site；
- `RawPointerTransfer`、`ReleasePathProof` 与 callback release/use ordering；
- `ObjectFlow`：capture slot、user_data、opaque handle 与 release endpoint 的 identity transport；
- mutation/reassignment barrier：阻止被覆盖的 binding 被误接成同一对象链。

rusqlite API map 当前覆盖 `update_hook`、`commit_hook`、`rollback_hook` 的 register/unregister，`create_scalar_function` register，以及 callback/user_data 与 invoke 入口，见 [`rusqlite-api-map.toml`](../../contracts/callback-retention/rusqlite-api-map.toml)。

### 运行时

`bw.trace/0.1` 可记录 object create/drop/free/use、capture bind、callback register/unregister/invoke 和三个 checkpoint。adapter 只翻译发生的事件，不写历史漏洞标签或 finding。

## Oracle

[`contract.toml`](../../contracts/callback-retention/contract.toml) 的通用语义是 register 可能 retain、unregister/owner drop release、borrow 必须覆盖 retention、生命周期结束后禁止 use、同代对象最多 free 一次。oracle 将 static capture/object site、Contract clause 与 runtime event 融合：

- borrowed object 结束但 callback 仍 retained 时产生 lifecycle exposure/violation 证据；
- later callback invoke/use 可增加动态影响证据；
- unregister-before-drop、owned capture 和 fixed runnable 必须保持 clean；
- oracle 不读取 rusqlite 版本、case role 或预期结果。

## 动态证据

- 历史 D1 formal：`unix1784400047-f3fa5ed-d1formal` 为 30/30 primary、每个 20/20 replay；第二 API smoke 为 3/3。详见 [D1 result](../experiments/results/d1-structured-search-2026-07-19.md)。
- 历史 M12 blind gate：10/10 completed、2 个 confirmed case 各 20/20 replay、controls clean。详见 [M12 result](../experiments/results/rusqlite-m12-blind-gate-2026-07-20.md)。
- 这些 evidence 绑定旧 commits；当前迁移 commit 没有新 formal run。公开 ASan parser fixtures 只支撑组件测试，完整 experiment regression 仍需新的对齐 run。

## 当前检测覆盖

| 层 | 当前状态 | 上限 |
| --- | --- | --- |
| benchmark | 0.26.1/0.26.2 的 update-hook 与 scalar-function 正负对照已迁入 | 不代表所有受影响 API 都有动态 harness |
| compiler | rusqlite dependency coverage、capture/MIR facts、xDestroy/user_data release proof 有测试 | 复杂跨函数 state machine、Drop/remove path 和任意 alias 仍可能缺证 |
| Contract | update/commit/rollback/scalar callback API map 可用 | API map 是审计输入，不是运行结果 |
| graph/ranking | object-bound graph-v3 与 proof layers 可表达 identity、ordering、complete chain | sibling unregister 只表示 availability，不能单独证明当前对象 release coverage |
| runtime/oracle | callback 生命周期事件和通用规则已实现 | 没有通用 witness-plan executor 覆盖任意 candidate |

当前最强可写结论是：rusqlite 设计家族拥有历史动态闭环，当前代码也保留静态/运行时建模与回归测试；但必须重新执行与当前 commit 对齐的 public regression，才能产生新的 `Verified` 声明。
