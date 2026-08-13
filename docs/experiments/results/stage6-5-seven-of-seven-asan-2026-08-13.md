# 阶段 6.5（收尾）：7/7 API ASan 出证 + trait 回调生成器 + portaudio 负方向对照

- 日期：2026-08-13
- 状态：**RUSTSEC-2021-0128 全部 7 个 API 完成 source-to-verdict → safe-only
  harness → ASan 出证 → fixed/对照对齐**。同族 nday 验证集闭环。

## 1. 完整验证矩阵（7/7）

| API | 符号 | vulnerable 0.26.1 | fixed 0.26.2 |
| --- | --- | --- | --- |
| `update_hook` | sqlite3_update_hook | ✅ heap-use-after-free | ✅ E0425 |
| `commit_hook` | sqlite3_commit_hook | ✅ heap-use-after-free | ✅ E0425 |
| `rollback_hook` | sqlite3_rollback_hook | ✅ heap-use-after-free | ✅ E0425 |
| `create_scalar_function` | sqlite3_create_function_v2 | ✅ heap-use-after-free | ✅ E0425 |
| `create_collation` | sqlite3_create_collation_v2 | ✅ heap-use-after-free | ✅ E0425 |
| `create_aggregate_function` | sqlite3_create_function_v2 | ✅ heap-use-after-free | ✅ E0425 |
| `create_window_function` | sqlite3_create_window_function | ✅ heap-use-after-free | ✅ E0425 |

- 全部 harness `#![forbid(unsafe_code)]`、链接与静态分析同源的精确外部构建；
- owned / no-trigger 对照（create_scalar_function）ASan 干净；
- fixed 走标准流程：0.26.2 契约 `requires_static_capture` → 生成器 invalidate
  refused → E0425（与 hook 家族一致）。

## 2. trait 回调生成器（crates/bw-cli generate_witness_harness.rs）

create_aggregate / create_window 的回调是自定义 trait（`Aggregate` /
`WindowAggregate`），不是 Fn 闭包。生成器新增 `callback_kind = "trait"` 形状：

- 渲染 `struct BwWitnessAgg<'a> { referent: &'a Box<String> }` + `impl`；
- `Aggregate` 单 impl；`WindowAggregate` 双 impl（super trait 方法必须由
  Aggregate impl 提供，value/inverse 在 WindowAggregate impl）；
- referent 声明与 drop 严格受 `declare_referent` 控制：Generated 生成、
  Refused 不生成（负对照编不过的行为保持）；
- `callback_kind = "trait"` 时跳过 Fn 签名解析。

变异检查：改坏 referent 访问后两个 trait 渲染测试转红；恢复后全绿。

## 3. portaudio 负方向对照（RUSTSEC-2019-0022，panic 路径 UAF）

portaudio 的缺陷机制是「回调内 panic 展开 → Box 提前释放 → 外部仍持有指针」——
**不在本工具判定维度**（panic 路径建模缺失，stage7 已记录）。对照结果：

- 3 个 hand-off（Stream::open / set_finished_callback / open_default）joined；
- **`supported_incompatibility = 0`**——工具没有把 panic 类缺陷误判成回调持有期
  不相容；
- 全部 `insufficient_evidence`（缺证不猜），与判定模型边界一致。

## 4. 证明了什么 / 没证明什么

**证明了**：

- 同族 nday 7/7 端到端闭环：静态链 → 三态判定 → 自动 safe-only harness →
  ASan 独立出证 → fixed/对照全对齐（第 7 个独立 ASan 证据）；
- 生成器覆盖三种回调形状：Fn 闭包（hooks）、Fn 带固定参数与非常规返回
  （create_scalar/collation）、自定义 trait（aggregate/window）；
- 判定边界正确：panic 类缺陷（portaudio）保持缺证，不误判。

**没证明**：

- **A 类（allocation 提前释放）仍未在真实库上触发**：7 个 API 全部走 R 类
  （referent 借用失效），xDestroy 由外部释放（A 类安全路径）；
- Q4′ clear 语义未分辨（`not_written` ≠ guard 被击穿，删除对象型清槽未建模）；
- aggregate 判定缺 same_slot_invoke_candidate（晚调证据由 ASan 出证补齐，但静态
  链的晚调可达性仍是降级）；
- portaudio 的判定没有外部 IR（L2 系统库）——负方向对照只验证「不误判」，不验证
  「能识别 panic 类」；
- 生成器对 fixed 版 `expected_compile` 预测缺口未修（沿用 vulnerable 契约时）。

## 5. 产物（远端 <results-root>/stage65-userdata/）

- `asan-*.log`（7 个 API 的 vulnerable 出证 + 对照日志）
- `harness-*`（自动生成，含 trait 形状）
- `analysis-fixed2/`、`rust-contracts-fixed2/`（0.26.2 契约，requires_static_capture）
- `portaudio-*`（负方向对照）

## 6. 下一步（用户决定）

- 规模化 0day 探针（Gate B 正例 + Gate P）——能力已补齐；
- 或先做 Gate A1/A2 正式化、Q4′ 深化等论文级工作。
