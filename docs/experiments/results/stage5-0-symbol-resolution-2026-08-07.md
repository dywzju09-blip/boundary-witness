# 阶段 5.0：真实目标上的外部符号解析

- 日期：2026-08-07
- 目标：`rusqlite` 0.26.1（本体，不是 benchmark 程序）
- 状态：**跨界交出点上 6/6 解析成功。** 三个障碍已定位并修复

## 1. 为什么先跑这一步

阶段 4 的端到端验证用的是 Gate R 的 fixture crate——真实源码、真实 IR，但形状是我们自己写的。
反证生成（阶段 5.3）的输入是真实目标的判定结果，而判定要靠外部符号联结两侧。

**先花一次构建的时间知道真相，比按错误假设写三天代码便宜。** 结论：假设确实错了，而且错在
两个地方。

## 2. 第一次测量：36 个交出点，成功 2 个

| resolution | 数量 |
| --- | ---: |
| 找不到外部调用 | 30 |
| 判成歧义 | 4 |
| **解析成功** | **2** |

关键的那条：

```
hooks::<impl Connection>::update_hook        → 找不到外部调用   ← 公开安全 API
hooks::<impl InnerConnection>::update_hook   → 歧义             ← 内层 wrapper
```

## 3. 三个障碍

### 3.1 只扫本函数体（事前预判到）

rusqlite 的调用链是：

```
Connection::update_hook          ← 回调参数在这里声明
  └─ InnerConnection::update_hook
       └─ ffi::sqlite3_update_hook   ← extern 调用在这里
```

原实现只扫声明回调参数的那个函数体。**真实 crate 几乎不在那里直接调 extern。**

### 3.2 判据把「多次调用」当成了「歧义」（事前没预判到）

查 `InnerConnection::update_hook` 的源码：

```rust
let previous_hook = match hook {
    Some(hook) => ffi::sqlite3_update_hook(self.db(), Some(cb), boxed),   // 调用 1
    _          => ffi::sqlite3_update_hook(self.db(), None, ptr::null_mut()), // 调用 2
};
```

两个调用点，**指向同一个符号**。原规则数「调用次数」，应该数「不同符号数」。

**注册/注销双分支在真实 FFI 绑定里是常态**，rusqlite 的四个 hook 全部因此被误判成歧义。

### 3.3 过程间搜索会查到没有 body 的 def_id 而崩溃

修 3.1 之后第一次跑，包装器 panic：

```
optimized_mir → mir_built → check_match → typeck
  → span_bug "can't type-check body of {def_id}"
```

调用图的边上有常量、静态项、只有声明没有默认体的 trait 方法。对它们查 `optimized_mir` 会
走进 rustc 的 `span_bug!`。

**严重性**：包装器 panic 会**把被扫 crate 的整个编译带崩**——不是我们的分析失败，是用户的
构建失败。只扫本函数体时碰不到这条路（交出点自身必有 body），过程间一走出去就撞上。

修复是一行 `is_mir_available` 守卫。

## 4. 修复后的测量

| resolution | 数量 |
| --- | ---: |
| 找不到外部调用 | 22 |
| 判成歧义 | 1 |
| **解析成功** | **13** |

`Connection::` 层的六个跨界回调 API 全部解析成功，跳数都是 1：

| API | 符号 | 跳数 |
| --- | --- | ---: |
| `update_hook` | `sqlite3_update_hook` | 1 |
| `commit_hook` | `sqlite3_commit_hook` | 1 |
| `rollback_hook` | `sqlite3_rollback_hook` | 1 |
| `progress_handler` | `sqlite3_progress_handler` | 1 |
| `authorizer` | `sqlite3_set_authorizer` | 1 |
| `create_scalar_function` | `sqlite3_create_function_v2` | 1 |

跳数 1 正是过程间搜索补上的那一层：0 是 `InnerConnection::*`，1 是 `Connection::*`。

### 剩下 22 条「未解析」里大部分是正确判断

按函数名归类：

| 函数 | 数量 | 性质 |
| --- | ---: | --- |
| `call_boxed_closure` | 6 | **trampoline 本身**，它不注册任何东西 |
| `query_row` / `query_map` / `and_then` / `map` / `mapped` | 9 | 行映射闭包，**回调是纯 Rust，不过 FFI 边界** |
| `pragma*` | 4 | 同上 |
| 其余 | 3 | 同上 |

**因此正确的口径不是 13/36，而是「跨界交出点上 6/6」。** 那 22 条不是失败——它们本来就不
交给外部。

这也是把 `NoForeignCallInBody` 改名成 `NoForeignCallWithinSearchDepth` 的理由：前者容易被
当成失败计数，后者是中性的「在这个搜索深度内没找到」。

## 5. 搜索上界是有代价的，不能随手调大

上界取 3 跳。`search_hops` 作为**证据**写进事实，不是内部细节：

**包装层数越深，「这个符号确实是这个 API 交出去的」这个结论越弱。** 调大上界会让更多交出点
「解析成功」，但每一条的可信度都在下降，而且报告里必须看得见。rusqlite 只需要 1 跳。

## 6. 这一步证明了什么，没证明什么

**证明了**：

- 真实 crate 的包装层能被穿透，符号与参数角色可以自动解析；
- 判据的两处错误（次数 vs 符号数、只扫本体）都是可测的，改完立刻反映在数字上；
- 「未解析」这个取值本身需要分类看，否则会把正确判断记成失败。

**没证明**：

- **联结还没跑。** 有了符号只是有了主键，两侧联结与判定要下一步做；
- **`registration_key` 仍恒为 `None`。** rusqlite 的四个 hook 是四个不同符号，暂时用不上；
  一个符号上多个注册槽位的情况还没有产出方；
- **上界 3 跳没有在别的 crate 上验证过。** rusqlite 只需要 1 跳，这个数字对其他包装风格是否
  够用，要等 Gate C0 的跨库检查。
