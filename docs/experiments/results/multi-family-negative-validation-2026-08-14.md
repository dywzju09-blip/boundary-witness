# 多库家族负方向批量验证：openssl / libpulse / libsql / duckdb（2026-08-14）

- 日期：2026-08-14
- 前置：rusqlite 7/7 + git2 GIT-01/GIT-02 正例出证；本记录补**不同库家族**的负方向证据
- 目的：验证工具在健全/同步回调库上不误报（supported_incompatibility=0），并确认
  「FFI 回调生命周期 UAF」类 nday 在生态中的真实分布

## 1. 目标与形状预判

按用户清单（FFI-lifetime-UAF-scan-targets）Tier 1 挑库，先看注册 API 签名：

| crate | 版本 | 注册 API 形状 | 预期 |
| --- | --- | --- | --- |
| openssl | 0.10.81 | `set_verify_callback` 等 `F: ... + 'static + Sync + Send`；`private_key_from_pem_callback` 等 `F: FnOnce` 无 'static | 前者健全（compatible）；后者 permits 但**同步回调** |
| libpulse-binding | 2.30.1 | `set_state_callback(Option<Box<dyn FnMut() + 'static>>)` | 健全（'static 强制） |
| libsql | 0.9.30 | `add_update_hook(Box<UpdateHook>)`（`Box<dyn Fn + Send + Sync>` 默认 'static）+ `Box::leak` | 健全（泄漏非 UAF，借用捕获被类型层拒绝） |
| duckdb | 1.10505.0 | 无 safe 闭包注册（UDF 是 bindgen 风格 unsafe API） | 无候选形状 |

## 2. 跑了什么（Rust 侧判定链）

对 openssl 与 libpulse-binding 跑完整 Rust 侧判定
（bw-rustc wrapper → extract-rust-contracts → judge-hand-offs --rust-only）：

- openssl：48 hand-offs / 23 装配；5 permits + 18 requires-static；**supported_incompatibility=0**
- libpulse：124 hand-offs / 116 装配；**116 全部 requires-static（compatible）**；supported_incompatibility=0

## 3. 关键发现：openssl 的 5 个 permits 是同步回调

`EcKey/PKey/Rsa::*_from_pem_callback` / `private_key_from_pkcs8_callback`：

```rust
pub fn $n3<F>(pem: &[u8], callback: F) -> Result<$t, ErrorStack>
    where F: FnOnce(&mut [u8]) -> Result<usize, ErrorStack>   // 无 'static 约束
{
    let mut cb = crate::util::CallbackState::new(callback);
    ... $f(bio.as_ptr(), ..., Some(invoke_passwd_cb::<F>), &mut cb as *mut _) ...
}
```

- 工具判 `permits_non_static_capture` **正确**（签名确实允许借用捕获）；
- 但回调在 `PEM_read_bio_PrivateKey` 调用**栈内同步**使用（`CallbackState` 栈对象），
  函数返回即失效，无「注册后延迟调用」语义 → **不可能 UAF**；
- judge（rust-only）正确落 `insufficient_evidence`（缺外部晚调证据），**未误报为
  SupportedIncompatibility**。

这实例化了已知缺口：**「同步 vs 延迟晚调」的区分依赖外部侧**（Q3/晚调证据）。
签名层只能判「允许借用捕获」（permits），不能判「回调被存住后延迟调用」。

## 4. 证明了什么 / 没证明什么

**证明了**：

- 工具在 openssl（23 装配）与 libpulse（116 装配）两个新库家族上 **zero
  supported_incompatibility**——不同代码风格（宏生成、trait 对象回调、同步
  FnOnce）都不误报；
- 'static 强制形状（openssl 18 个、libpulse 116 个）全部正确落
  `compatible_within_analyzed_fragment`；
- openssl 的非 static 同步回调（5 个）正确落 `insufficient_evidence`，不因
  「回调被调用」而断言「晚调」；
- 生态现实再确认：RustSec 同类（FFI 回调生命周期 UAF）nday 只有 rusqlite 一个
  典型；openssl/libpulse/libsql/duckdb 均无候选形状（'static 强制或同步回调或
  无 safe 闭包注册）——与 2026-08-12 普查「本类形状近绝迹」一致，git2 是例外。

**没证明**：

- 未做外部侧（LLVM IR）——以上全部是 Rust-only 判定；openssl 5 个 permits 若
  补外部 IR 且「Q3 晚调可达性」证明为同步，应落 compatible（本记录未做，留给
  Q3 升级）；
- libsql 的 `Box::leak` 是内存泄漏而非 UAF——工具目标类是 UAF，泄漏类不在当前
  判定范围（未实现 leak 检测）；
- duckdb 未实际构建/分析（源码检查无 safe 闭包注册即停止，避免无谓构建成本）；
- 未下载 Tier 1 其他家族（mlua/rocksdb/GTK/neon）——若继续扩展可补，但按
  「先验证有效性、规模不大」原则，两个新家族 + 既有正例已构成泛化证据。

## 5. 产物（远端 <results-root>/）

- openssl-01081-analysis/（static-facts 2517 条）、openssl-01081-contracts/
  （23 装配）、openssl-01081-joint/（rust-only，0 误报）
- libpulse-2301-analysis/（static-facts 2236 条）、libpulse-2301-contracts/
  （116 装配）、libpulse-2301-joint/（rust-only，0 误报）
