# Gate P S1：预注册样本框（10 目标有效性验证）

- 日期：2026-08-11
- 判据（[prey-existence-probe runbook](../runbooks/prey-existence-probe.md)）：S1 = 10–30 个 crate，
  验证覆盖率/Unknown/转换率方向，不判 Pass/No-Go（正式判定需更大样本 + P-b 完整转换率）
- **预注册于运行前**（本记录先于数据写入）

## 1. 样本框

**入选标准**（客观，非挑选有利样本）：

1. FFI 绑定 crate（含 extern 块 / sys 依赖）；
2. 回调 API 候选（泛型 Fn / Box<dyn Fn> / 回调参数）；
3. 可构建（L1 bundled/vendored 优先，系统库允许但标注 L2）；
4. **unseen**：未参与任何 adapter 开发；
5. 家族多样化：覆盖不同 C 构建方式与回调形状。

**名单（10 个）**：

| crate/版本 | 外部库 | 构建 | L1 | 家族 |
| --- | --- | --- | --- | --- |
| rusqlite 0.26.1 | SQLite | bundled cc | ✅ | **校准（开发对象）** |
| git2 0.18.1 | libgit2 | bundled cmake | ✅ | libgit2 |
| portaudio-rs 0.3.1 | PortAudio | system | ❌ L2 | PortAudio |
| curl 0.4.50 | libcurl | bundled cmake | ✅ | libcurl |
| openssl 0.10.81 | OpenSSL | vendored perl+make | ✅ | OpenSSL |
| ssh2 0.9.6 | libssh2 | bundled cmake | ✅ | libssh2 |
| zstd 0.13.3 | zstd | bundled cmake | ✅ | zstd |
| lmdb-rkv 0.14.0 | LMDB | bundled cc | ✅ | LMDB |
| libz-sys 1.1.29 | zlib | bundled cc | ✅ | zlib |
| libpulse-binding 2.30.1 | PulseAudio | system | ❌ L2 | PulseAudio |

**判据（预注册）**：

- 输出：各 crate hand-offs / 装配 / Tier A-R / Tier A-A + 流失原因分类（pp_scan 口径）；
- 有效性验证成功 = 至少一个 **unseen** crate 产出 Tier A-R 候选且能走通
  「静态契约 → 外部 IR → 联结 → 判定」至少到联结层（对标 openssl 案例）；
- 不判 Gate P 通过/不通过（S1 是方向性验证）。
