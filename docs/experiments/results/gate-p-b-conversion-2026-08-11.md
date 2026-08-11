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
