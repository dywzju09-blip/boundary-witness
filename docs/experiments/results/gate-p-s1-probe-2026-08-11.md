# Gate P S1：10 目标有效性验证（结果）

- 日期：2026-08-11
- 预注册：[gate-p-s1-registration-2026-08-11](./gate-p-s1-registration-2026-08-11.md)
- 状态：**有效性判据达成**——unseen crate 的 Tier A-R 候选存在且走通装配；
  发现两个新家族信号（libpulse owner-held 静态族、ssh2 回调稀疏）

## 1. 扫描结果（pp_scan，10 crate 全成功）

| crate | 家族 | hand-offs | 装配 | Tier A-R | Tier A-A | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| rusqlite 0.26.1 | SQLite | 50 | 17 | 10 | 0 | dev 校准 |
| git2 0.18.1 | libgit2 | 44 | 23 | 11 | 0 | unseen 正例 |
| portaudio-rs 0.3.1 | PortAudio | 3 | 3 | 3 | 0 | unseen 正例（L2） |
| curl 0.4.50 | libcurl | 22 | 0 | 0 | 0 | 选项式 setopt 盲区 |
| openssl 0.10.81* | OpenSSL | 48 | 23 | 5 | 0 | *vendored 补跑 |
| ssh2 0.9.6 | libssh2 | 1 | 0 | 0 | 0 | 回调稀疏 |
| zstd 0.13.3 | zstd | 0 | 0 | 0 | 0 | 无回调 API |
| lmdb-rkv 0.14.0 | LMDB | 0 | 0 | 0 | 0 | 无回调 API |
| libz-sys 1.1.29 | zlib | 0 | 0 | 0 | 0 | 无回调 API |
| libpulse-binding 2.30.1 | PulseAudio | 125 | 117 | 0 | 0 | **18 owner-held 全静态** |
| **合计** | | **293** | **183** | **29** | **0** | |

*openssl 在 pp_scan 默认 `--all-features` 下 `not_buildable`（bssl-sys 占位包，
已知 feature 陷阱），用 `--features vendored` 单独补跑，数据并入。

## 2. 有效性判据核对（预注册）

- ✅ **至少一个 unseen crate 产出 Tier A-R 候选**：git2（11）+ portaudio（3）+
  openssl（5）= **19 个 unseen Tier A-R**，跨 3 个外部库家族；
- ✅ **走通装配**：openssl 5 候选已走通「契约 → 外部 IR → 联结层」完整链
  （见 [P-b 转换率](./gate-p-b-conversion-2026-08-11.md)：跨文件追踪后
  retention 缺证原因从「无法追踪」变为「追踪到底但非 caller-owned」）。

## 3. 新家族信号（S1 独有发现）

**libpulse-binding 2.30.1（PulseAudio）**：125 hand-offs / 117 装配 /
**18 个 `owner_holds_callback`**——但**全部 `requires_static_capture`**（`'static`
bound），类型层排除借用捕获。**这是「owner-held + 静态」安全族**，与 git2 的
「owner-held + permits」不同。正确判 Tier A-R=0。

- 意义：工具能区分「owner-held 但静态」（安全）vs「owner-held 且 permits」
  （候选）——判别力有效；
- libpulse 有 RUSTSEC-2019-0038（memory-corruption，panic 类），与我们判定维度
  正交。

**ssh2 0.9.6**：仅 1 hand-off 0 装配（libssh2 回调可能经别名/宏或选项式传入，
同 curl 盲区方向）。

## 4. 这一步证明了什么，没证明什么

**证明了**：

- 工具对 10 个不同家族（7 种 C 构建方式）的批量扫描稳定，0 崩溃；
- unseen 生态里 referent 类候选跨 3 家族存在（19 个），S0 信号复现且扩大；
- libpulse 的 117 个静态回调被正确分类（不误报 Tier A-R）；
- 已知盲区复现：curl setopt、ssh2 回调稀疏、openssl feature 陷阱。

**没证明**：

- **转换率**（候选 → 判定 → 反证 → 确认）：仅 openssl 5 走到联结层且缺证，
  其余未做外部 IR；
- **这些候选是否真缺陷**：19 个 unseen Tier A-R 中 14 个（git2+portaudio）未走
  外部 IR，openssl 5 个方向性支持同步；
- **Gate P 通过/不通过**：S1 是有效性验证，正式判定需 S2 更大样本 + 完整 P-b
  转换率；
- **curl/ssh2 盲区未修**：它们的回调形状仍不可见，Gate P 分母系统性偏低。
