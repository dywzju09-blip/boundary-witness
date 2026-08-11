# Gate P（正式运行，S0 口径）：猎物池探测

- 日期：2026-08-11
- 判据（[prey-existence-probe runbook](../runbooks/prey-existence-probe.md) §3.1）：
  Tier A-R / A-A 两级统计 + crate/家族聚类
- 样本框（**预注册 2026-08-11**）：S0 口径 5 个目标，入选条件 = FFI 绑定 +
  回调 API 候选 + 可构建（L1 优先）；rusqlite 为开发校准对象，其余 4 个 unseen

## 1. 原始数据（pp_scan 口径）

| 目标 | 家族 | 构建 | hand-offs | 装配 | Tier A-R | Tier A-A |
| --- | --- | --- | --- | --- | --- | --- |
| rusqlite 0.26.1 | SQLite | bundled cc | 50 | 17 | 10 | 0 |
| git2 0.18.1 | libgit2 | bundled cmake | 44 | 23 | 11 | 0 |
| portaudio-rs 0.3.1 | PortAudio | system (L2) | 3 | 3 | 3 | 0 |
| curl 0.4.50 | libcurl | bundled cmake | 22 | 0 | 0 | 0 |
| openssl 0.10.81 | OpenSSL | vendored perl+make | 48 | 23 | **5** | 0 |
| **合计** | | | **167** | **66** | **29** | **0** |

流失原因：foreign_symbol_unresolved ×87、safe_entry_lineage_unresolved ×45、
not_reachable_from_safe_entry ×2。

## 2. 聚类解读

**按家族**（runbook：必须聚类，不能按 alert 计数）：

- SQLite 家族：Tier A-R = 10（全在开发对象 rusqlite）
- libgit2 家族：Tier A-R = 11（git2，unseen）
- OpenSSL 家族：Tier A-R = **5**（unseen，**外部符号全部已解析**——最强信号）
- PortAudio 家族：Tier A-R = 3（unseen，L2）
- libcurl 家族：Tier A-R = 0（22 hand-off 全因选项式 setopt 形状无法解析符号）

**unseen 净信号**：非开发对象的 Tier A-R = **19**（git2 11 + openssl 5 + portaudio 3），
分布在 3 个外部库家族。

## 3. 预注册判据的判定

runbook 判定式：`可用猎物估计 = eligible_pool_lower_bound × conversion_rate_lower_bound`。

本 S0 探针未做转换率（P-b 需要完整流水线，见 §4），因此**不判 Pass/No-Go**，
只报告 P-a 方向的第一个实测下界：

- **referent 类（A-R）猎物池非空且跨家族**：3 个 unseen 家族各有 permits 候选；
- **openssl 的 5 个候选是当前最强目标**：符号已解析、无 guard，且 password
  callback 形状与 rusqlite 同族；
- **Tier A-A = 0**：样本内没有观察到 allocation 类候选（符合 runbook 预期——
  A 子路线需要单独统计，本次不判）。

## 4. 这一步证明了什么，没证明什么

**证明了**：

- 猎物池（referent 类）在 unseen 家族中**存在且可被工具识别**——3/4 unseen
  家族产出 Tier A-R 候选；
- 工具对 4 种 C 构建方式的新家族接入稳定（Gate C0 机制部分）；
- openssl 5 候选是比 git2 更值得推进的目标（符号解析成功）。

**没证明**：

- **转换率**（P-b）：候选→判定→反证→确认的比例未测——需要完整流水线跑
  openssl 候选；
- **Tier A-A 结论**：0 不代表无 allocation 类猎物（runbook 要求单独统计，
  本次样本太小）；
- **curl 的 22 个回调归属**：选项式 setopt 符号解析未实现，是已知盲区；
- **Gate P 通过与否**：S0 是方向探针，正式 Pass/No-Go 需要更大样本 +
  转换率；
- **openssl 候选是否真实不相容**：缺外部 IR + 反证。
