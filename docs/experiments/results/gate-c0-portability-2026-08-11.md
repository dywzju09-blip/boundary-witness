# Gate C0：跨库家族可移植性 smoke

- 日期：2026-08-11
- 判据（[milestone-gates](../../roadmap/milestone-gates.md) Gate C0）：3–5 个外部库家族、
  至少两种 C 构建方式，只验证 IR 获取、符号解析、artifact 绑定与接入成本
- 状态：**四种构建方式全部验证通过，接入成本量化；发现两类新的回调形状缺口**

## 1. 家族与构建方式矩阵

| 家族 | crate/版本 | C 构建方式 | L1 | static-facts | 结果 |
| --- | --- | --- | --- | --- | --- |
| SQLite | rusqlite 0.26.1 | bundled cc（libsqlite3-sys） | ✅ | ✅ 2252 | 校准对象 |
| libgit2 | git2 0.18.1 | bundled cmake（libgit2-sys） | ✅ | ✅ 4356 | 已记录 |
| libcurl | curl 0.4.50 | bundled cmake（curl-sys） | ✅ | ✅ 718 | **新** |
| OpenSSL | openssl 0.10.81 | vendored perl+make（openssl-src） | ✅ | ✅ 2557 | **新** |
| PortAudio | portaudio-rs 0.3.1 | 系统库 pkg-config | ❌ L2 | ✅ 64 | 已记录（L2） |

**四种 C 构建方式**：cc、cmake（×2 家族）、perl+make、pkg-config——超过 Gate C0
「至少两种」要求。

## 2. 新接入成本与发现（接入成本量化）

### 2.1 新 crate 接入成本（curl / openssl）

| 步骤 | curl | openssl |
| --- | --- | --- |
| 下载 + manifest | ~30s | ~30s |
| 首次构建 | ~9min（cmake libcurl） | ~20min（perl+make + vendored） |
| 符号解析 | **22/22 失败** | **成功** |
| 关键坑 | — | **feature 选择陷阱** |

**openssl feature 陷阱（重要 C0 数据点）**：`--all-features` 激活
`unstable_boringssl` feature → 依赖占位包 `bssl-sys`（compile_error!）→ 构建失败。
改 `--features vendored` 后成功。**这印证 scope-and-boundaries §1：默认 feature
选择是真实选择**——错误 feature 会静默改变分析对象。

### 2.2 curl：`foreign_symbol_unresolved` ×22 的根因

curl 的回调设置是**选项式 setopt**形状：

```rust
// handler.rs: setopt_ptr(curl_sys::CURLOPT_PROGRESSFUNCTION, cb as *const _)
```

回调以 `CURLOPT_*` 枚举常量 + `as *const _` 传给 `curl_easy_setopt`——不是"实参
类型含函数指针"的注册调用。**现有符号解析判据（foreign_callback_calls 按实参
函数指针类型匹配）不覆盖该形状**。这是已知限制，记录为下一步扩展点。

### 2.3 openssl：5 个 `permits_non_static_capture` 的 Tier A-R 候选

```
ec::EcKey::private_key_from_pem_callback       → PEM_read_bio_ECPrivateKey
pkey::PKey::private_key_from_pem_callback      → PEM_read_bio_PrivateKey
pkey::PKey::private_key_from_pkcs8_callback    → d2i_PKCS8PrivateKey_bio
pkey::PKey::public_key_from_pem_callback       → PEM_read_bio_PUBKEY
rsa::Rsa::private_key_from_pem_callback        → PEM_read_bio_RSAPrivateKey
```

均为宏生成（`private_key_from_pem!`），回调 `FnMut(&mut [u8]) -> usize` **无
'static bound**、guard none、**外部符号已解析**。这是目前工具在 unseen crate
上发现的**最强 referent 类候选**（git2 的 11 个 symbol 未解析；这些全解析）。

## 3. 这一步证明了什么，没证明什么

**证明了**：

- 工具对新 crate 家族的接入流程稳定（下载→manifest→构建→分析，无代码改动）；
- **四种 C 构建方式的 IR 获取全部可行**（Gate C0 的机制部分通过）；
- feature 选择陷阱被真实触发并记录（openssl bssl-sys）；
- openssl 存在 5 个真实的 Tier A-R 候选（符号已解析、permits、guard none）——
  **第二个 unseen 家族的正例信号**；
- curl 的选项式 setopt 回调形状是新的符号解析盲区（已定位根因）。

**没证明**：

- **Gate C0 完全通过**：判定部分未验证（curl/openssl 都停在装配或 gap，未到
  judge）；openssl 5 候选的外部侧（真实 openssl IR）尚未捕获；
- **这 5 个 openssl API 是否真的不相容**：缺外部 IR + 反证。password callback
  是同步调用形状的可能性高（PEM_read 在返回前调用），但不预判；
- curl 22 个 API 的归属（缺符号解析，无法联结）；
- 单次构建，无重复性验证。
