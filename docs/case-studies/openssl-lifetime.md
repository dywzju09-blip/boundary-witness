# OpenSSL lifetime

## 历史漏洞事实

[RUSTSEC-2025-0004](https://rustsec.org/advisories/RUSTSEC-2025-0004.html) 记录 rust-openssl `>=0.10.0, <0.10.70` 的 `select_next_proto` 返回 lifetime 绑定错误；0.10.70 修复。返回 slice 可能实际 alias `server`，旧签名却让它看起来与 `client` 同寿。source 先结束而 view 继续使用时可形成 use-after-lifetime-end。来源等级为 `S1/S2`；当前公开工作树没有该历史 case 的独立动态 harness。

## 最小触发链

```text
短生命周期 server buffer + 长生命周期 client buffer
  -> select_next_proto 返回实际 alias server 的 slice
  -> 类型签名把返回 lifetime 绑定到 client
  -> server buffer 结束
  -> caller 持久化或读取 returned slice
  -> stale read / use-after-lifetime-end
```

最小对照是同源程序在 0.10.69 接受、在 0.10.70 因修复后的 lifetime 约束被拒绝；另需一个不在 source 失效后使用 view 的安全对照。

## BoundaryWitness 可观察事实

该历史根因应由 returned-borrow 链表达：

- `ReturnedBorrowRelation`：returned view 与 source buffer 的 alias 关系；
- `PersistedReturnedBorrow`：view 进入局部 wrapper、字段、sequence/map 等 storage；
- `ReturnedBorrowInvalidationOrder`：source invalidation 与后续 use 的顺序；
- mutation/reassignment barrier：storage 被替换或 key 不再唯一时阻止错误归因；
- graph-v3 分别记录 identity transport、lifecycle ordering 和 complete risk chain。

当前 compiler 有通用 returned-borrow extraction 与模型测试，但没有 `select_next_proto` 的 exact API map 或端到端 OpenSSL returned-borrow benchmark。因此“模型能表达”不能写成“当前工具已检测该 advisory”。

## Oracle

对该家族，oracle 所需的最小闭链是：exact source/view relation、view persistence、source invalidation、invalidation 后 use。只有 relation 或一次 returned-borrow candidate 时应保留 `use_ordering_proof_missing` 等缺证，不产生 confirmed violation。修复版本 compile rejection 是类型差分证据，不由 runtime oracle 伪造。

## 动态证据

当前状态为 `R0`：仓库没有与该历史案例对齐的 ASan/Miri/native replay receipt。普通运行未崩溃不构成 negative；完整 OpenSSL FFI 也不能默认由 Miri 覆盖。未来动态 run 必须记录 source/view identity、invalidation、later read 和修复版本对照。

## OpenSSL ex_data：相关能力但不同问题

当前 [`openssl-api-map.toml`](../../contracts/callback-retention/openssl-api-map.toml) 覆盖 `SSL_CTX_set/get_ex_data` 与 `SSL_set/get_ex_data`。它使用 `binding_api_id + handle_arg + key_arg`（set 还含 payload）生成 opaque identity，并要求 audited handle、slot 与 payload lineage。

compiler 也能观察 `CRYPTO_get_ex_new_index` free callback、ex_data set/get 与 from_raw/release proof。历史公开开发回归 `v3-2-5-20-20260724-static-r27-openssl-free-callback` 中，OpenSSL free-callback proof 从 static facts 贯穿到 ranking，正确降低有释放覆盖的 foreign-retained-pointer candidate；见 [public smoke result](../experiments/results/v3-2-5-nday-blind-smoke-2026-07-21.md)。这说明 ex_data 对象链的静态降噪能力，不是 `select_next_proto` 历史漏洞的动态证据。

## 当前检测覆盖

| 层 | 当前状态 | 上限 |
| --- | --- | --- |
| returned borrow | generic relation/persistence/invalidation/use facts 与 graph/ranking tests 已实现 | 缺 `select_next_proto` exact benchmark/API contract 和 formal run |
| ex_data | exact opaque handle+slot API map、compiler fact 与 model/CLI tests 已实现 | 同 key 不同 handle 不得合并；API map 自身不证明 runtime behavior |
| dynamic | 无 OpenSSL lifetime finalized run | 不能给出 crash rate、replay 或修复对照统计 |
| current gate | historical public regression仍有 pair evidence gap | 当前迁移 commit 的最新 gate 未执行 |

因此，本案例长期保留两条清晰边界：历史 `select_next_proto` 是 returned-borrow lifetime 事实；当前 ex_data 能力是 opaque user-data/free-callback 对象链覆盖。只有各自独立证据闭链后才能形成对应结论。
