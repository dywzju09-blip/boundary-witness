# Gate P-b 雏形：openssl 5 候选的转换率第一级

- 日期：2026-08-11
- 判据（[prey-existence-probe runbook](../runbooks/prey-existence-probe.md)）：
  P-b = 开发集上候选→判定→反证→确认的转化率
- 输入：Gate P S0 探针发现的 openssl 5 个 Tier A-R 候选（密码回调家族）

## 1. 流水线走到哪

| 级 | 数量 | 流失原因 |
| --- | --- | --- |
| Tier A-R 候选（openssl） | 5 | — |
| 外部 IR 捕获 | 5 符号定位（1102 bitcode） | — |
| extract-foreign-facts | 5 条，**全部 unresolved（无槽位）** | 分析器对"薄包装透传"形状的覆盖缺口 |
| judge-hand-offs | **0 joined / 5 rejected** | `missing_slot_evidence` ×5 |
| 反证 / ASan | 未到达 | — |

## 2. 为什么被拒（正确行为）

手动 IR 分析确认密码回调是**同步调用**形状：

```
PEM_read_bio_RSAPrivateKey → PEM_read_bio_PrivateKey_ex
  → pem_read_bio_key → pem_do_header（解析 PEM 头时同步调用密码回调）
```

callback 全程**只透传、不 store 到跨调用存储**。但自动分析器对"callback 经参数
透传"的形状**无法证明 NoRetain**（单文件 IR 看不到被调函数内部）——按纪律，
证明不了"同步"就不能给 NoRetain；retention=unresolved + 空槽位 = 缺证 →
judge 拒绝联结（missing_slot_evidence）。**这是正确行为**，不是 bug：
「同步不保存」是正面结论，需要证据，查不出只能缺证。

## 3. P-b 转换率第一级数据

```
候选 5 → 外部 IR 5 → 自动判定 0 → 反证 0 → 确认 0
```

**转换率受分析器覆盖缺口主导**，不是候选本身的问题。openssl 这 5 个
密码回调**很可能**全部同步（Compatible 方向），但自动化无法证明。

## 4. 这一步证明了什么，没证明什么

**证明了**：

- openssl 家族（第 4 个）的外部 IR 可捕获、符号可定位（1102 bitcode，
  5 符号全找到）；
- 转换率第一级数字：5 候选 → 0 自动判定，流失点精确（透传形状的
  NoRetain 证明缺口）；
- 手动 IR 分析给出了同步调用的方向性证据（回调不保存，仅透传）。

**没证明**：

- **openssl 5 候选的判定**（自动）——停在联结层；
- **"同步"的自动化证明**——需要跨文件数据流（被调函数内是否保存），
  当前单文件分析看不到；
- **P-b 正式转换率**——n=5 且全卡在同一缺口，不构成统计；
- **这些候选是 Compatible 还是缺证**——手动分析方向性支持同步，但未走
  完自动化验证。

## 5. 对 Gate P 的意义

P-b 第一级揭示了**转换率的主要瓶颈是分析器覆盖缺口**（透传/选项式 setopt
等形状），不是候选池本身。这改变了 Gate P 的解读：S0 的 29 个 Tier A-R
候选里，能走到判定的比例取决于这些缺口修多少。下一轮扩展点（按价值排序）：
① 跨文件"被调函数内是否 store callback"的证明（解决透传形状）；
② curl 选项式 setopt 符号解析；③ openssl 密码回调的同步性证明。

## 6. 跨文件透传追踪实施（2026-08-11 追加）

为解开 openssl 候选的「透传形状」缺口，实现了跨函数/跨编译单元追踪：

**新增能力**：
- `analyze_with_modules`：额外模块集（同构建其他编译单元）供被调方解析；
- `trace_param` 跨函数递归（depth≤3）：callback 实参透传给可解析被调方时，进入
  被调方继续追（参数索引映射 + caller-owned 注入）；
- `InstKind::Select` 识别（`select cond, @default_cb, %cb` 的 null 默认回调形状，
  **优先传播 Param 分支**）；
- `Operand::parse` 修复：取最后一个 `%`/`@` token（修复 bitcast 源解析）；
- caller-owned 语义修正：跨函数被调方形参只有在**实参由调用方持有**（全局/形参）
  时才视为跨调用存活；实参是调用方 alloca 时存进其字段**不构成保留**。

**测试**（crates/bw-foreign-ir/tests/cross_function.rs，4 个）：
- select+跨函数透传到不可解析被调方 → Unresolved（缺证不误判 NoRetain）；
- 跨函数 store 到全局槽位 → MayRetain；
- 跨函数 store 到全局结构体字段（GEP+bitcast）→ MayRetain；
- 跨函数 store 到调用方 alloca 字段 → Unresolved（不误报，openssl 形状）。
全量回归：bw-foreign-ir（11+4+16）、bw-model、bw-cli 全绿。

**openssl 重验（5 个密码回调候选）**：
- 之前：retention unresolved（透传形状无法追踪，escapes_to_unknown_callee）；
- 现在：**全链路穿透**（PEM_read_bio_PrivateKey → pem_read_bio_key →
  ossl_pw_set_pem_password_cb），callback 存进**栈上 passphrase alloca 字段**
  → `slot_not_proven_caller_owned` → **正确判定为不构成跨调用保留**。

**转换率更新（第一级→第二级）**：

```
openssl 候选 5 → 外部 IR 追踪 5 → 自动判定：
   2 个（PrivateKey/PUBKEY）确认「存栈上结构体，非跨调用保留」方向
   （retention 缺证，但缺证原因从「无法追踪」变为「追踪到底但非 caller-owned」）
   3 个（RSAPrivateKey/ECPrivateKey/d2i_PKCS8）停在符号定义缺失
   → judge 仍无判定（缺槽位证据）→ 反证 0
```

**意义**：密码回调（password_cb）是**同步调用**形状的证据链更完整了——手动 IR
分析（§2）与自动追踪（存栈上 alloca）一致指向「不跨调用保留」。这 5 个候选
**很可能全部 Compatible**（非缺陷），但自动判定仍需「证明 NoRetain」的槽位证据。
