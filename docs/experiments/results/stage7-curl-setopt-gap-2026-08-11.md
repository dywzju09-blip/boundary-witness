# curl 选项式 setopt：符号解析缺口定位（第四/五层）

- 日期：2026-08-11
- 目标：解锁 curl 22 个回调 API 的符号解析（Gate P-b 第二块）

## 1. curl 真实架构（源码确认）

curl 的回调设置是**两段式**，不是单一交出点：

```
Transfer::progress_function(F)          // ① 存入点：self.data.progress = Some(Box::new(f))
    └─ 存字段，无 extern 调用
perform() → handler.setopt_ptr(...)      // ② 交出点：从字段取出函数指针，cast 后传 extern
    └─ setopt_ptr(CURLOPT_PROGRESSFUNCTION, cb as *const _)
```

- 交出点（`progress_function`）本身**不调用 extern**——只是存字段；
- 真正的 extern 调用（`curl_easy_setopt`）在 perform 路径，回调经「存字段 →
  取出 → cast 成裸指针」中转。

## 2. 尝试与边界（本次实测）

**fp-cast 识别（已实现，预备能力）**：`is_fn_pointer_cast` 识别「函数指针 cast 成
裸指针传给 extern」的实参（curl 的 `cb as *const _` 形状）。

**实测结果**：
- curl 22 个 API 仍 `no_foreign_call_within_search_depth`——因为 `progress_function`
  本身无 extern 调用，透传搜索（≤3 跳）到不了 perform 的 setopt；
- fixture 验证暴露**第五层缺口**：裸 `fn` 指针参数（`unsafe extern "C" fn`）本身
  不被回调参数识别（现有识别只覆盖泛型 F / trait object），fp-cast 的前提
  「已被识别为回调」不成立。

## 3. 缺口分层（更新后的全景）

| 层 | 形状 | 状态 |
| --- | --- | --- |
| 1 | 泛型 F 直接传 extern（rusqlite） | ✅ |
| 2 | Box<dyn Fn> / 别名 trait object 参数 | ✅（portaudio 驱动扩展） |
| 3 | 透传链（callback 经包装函数转发） | ✅（openssl 跨文件追踪） |
| 4 | **存字段 + 别处取出传 extern（中转）** | ⬜ curl 真实形状，需跨函数字段追踪 |
| 5 | **裸 fn 指针参数识别** | ⬜ fixture 暴露，需扩展回调参数识别 |

fp-cast 落在第 4 层的「取出后 cast」环节，但因第 5 层（裸 fn 指针参数）和第 4 层
（字段中转）未实现而无法独立生效。

## 4. 这一步证明了什么，没证明什么

**证明了**：

- curl 的 22 个 API 缺证根因是**架构性两段式**（存入点与交出点分离），不是简单
  判据 bug——这解释了为什么符号解析搜索深度内找不到 extern 调用；
- 缺口分层完整：1–3 层已解决（rusqlite/portaudio/openssl 实证），4–5 层待做；
- fp-cast 代码已实现（`is_fn_pointer_cast`），编译与全量测试通过，但**无独立
  生效场景**（被 4/5 层前置依赖）。

**没证明**：

- curl 的 22 个 API 能否解锁——需要先做第 5 层（裸 fn 指针参数识别）+ 第 4 层
  （跨函数字段中转追踪）；
- fp-cast 在真实目标上的判别力（fixture 未验证，因裸 fn 指针参数未被识别）；
- 第 4 层是否值得做：curl 是唯一受影响的家族，且中转追踪复杂度高（需要跨函数
  的「存字段→取字段」数据流），投入产出比待评估。

## 5. 对 Gate P 的意义

curl 22 个 API 是 P-b 分母的一部分，但缺证根因是**架构性**（两段式交出），
不是修复即通。Gate P 正式数字可以如实报告「curl 因两段式架构在分析片段内
不可见」，并把它列为片段 limitation（scope-and-boundaries 允许：缺证可分类）。
