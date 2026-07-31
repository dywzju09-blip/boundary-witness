# Gate 0 外部基线对照：Yuga 与 FFIChecker / rusqlite 0.26.1

- 日期：2026-07-31（Asia/Shanghai；运行区间 2026-07-30T16:33:51Z–17:42:27Z）
- `run_id`：`gate0-baseline-rusqlite-0.26.1-20260730T163351Z`
- BoundaryWitness `code_commit`：`f40aa3b77781dc4265a71ee1ddabb43fa1ac2b8c`
- 目标数据：`corpus.gate0.external-baseline.rusqlite-0.26.1.20260731`
- 目标源码 SHA-256：`18e0b0ea8f15c26b5c0c846d00d85e2089cf4aacac942ffac0386c5b16dd1c94`
- 运行主机类别：x86_64 Linux，`x86_64-unknown-linux-gnu`
- 状态：**外部基线子项得到反例；N1 当前立论受威胁，必须重做或重新界定。Gate 0 整体未通过。**

## 1. 执行结论

| 工具 / 样本 | 退出码 | 总报告数 | 命中 7 个公告函数 | 判为同一持有期缺陷 |
| --- | ---: | ---: | ---: | ---: |
| Yuga / pulse-binding 正对照 | 0 | **9** | 不适用 | 正对照非空 |
| Yuga / rusqlite 0.26.1 `--all-features` | 0 | **13** | **5/7** | **5/7** |
| Yuga / rusqlite 0.26.2 `--all-features`（修复对照） | 0 | 8 | 0/7 | 0/7 |
| FFIChecker / c-in-rust-uaf 正对照 | 0 | **1** | 不适用 | 正对照非空 |
| FFIChecker / rusqlite 0.26.1 `--all-features` | 0 | **4** | 3/7（仅函数名重合） | **0/7** |
| FFIChecker / rusqlite 0.26.2 `--all-features`（修复对照） | 0 | 4 | 3/7（仅函数名重合） | **0/7** |

最关键的观察不是“Yuga 碰巧报了相同函数”，而是：

1. Yuga 对 `create_collation`、`create_scalar_function`、`commit_hook`、`rollback_hook`、`update_hook` 均把回调泛型值识别为寿命长于当前借用；
2. 五条报告均进一步指出回调“可能被赋给”由 `ffi::sqlite3` 指针代表、随所有者持续存在的对象，并以 potential use-after-free 收尾；
3. rusqlite 0.26.2 把对应 callback bound 改成 `'static` 后，这五条报告**精确消失**，其余 8 条 Yuga 报告保持不变。

因此这五条是 RUSTSEC-2021-0128 所述持有期缺陷的同类命中，不是无关的返回引用误碰。runbook 中“Yuga 看不到交给外部持有者的回调”的预期被实验否定。Yuga 是否以完备的外部行为模型得到该结论是另一问题；但 N1 不能再以“现有工作不会报出这一持有期缺陷”为前提。

FFIChecker 的三条同名命中则相反：它们都写明 `LLVM IR of C code is unknown`、`Memory Leakage`、参数状态为 `Forgotten`。相同四条报告在已经加入 `'static` 的 0.26.2 中原样存在，证明它们不是公告修复的持有期缺陷。

## 2. 输入、版本与工具链

### 2.1 目标与公告函数

目标是 rusqlite 0.26.1。源码取自 codeload 的 `rusqlite-0.26.1` tag：

- codeload tar SHA-256：`18e0b0ea8f15c26b5c0c846d00d85e2089cf4aacac942ffac0386c5b16dd1c94`
- crates.io `rusqlite-0.26.1.crate` SHA-256：`8a82b0b91fad72160c56bf8da7a549b25d7c31109f52cc1437eac4c0ad2550a7`
- 两份输入中的 `src/hooks.rs`、`src/functions.rs`、`src/collation.rs` 已逐文件比对为字节相同。
- 修复对照为 `v0.26.2` tag，codeload tar SHA-256：`25398736b4cb4893269680b2a2457d06cda73ee213ae8dbbcae250bef58dd77b`。

RUSTSEC-2021-0128 的 7 个函数为：

- `functions`：`create_scalar_function`、`create_aggregate_function`、`create_window_function`
- `hooks`：`commit_hook`、`rollback_hook`、`update_hook`
- `collation`：`create_collation`

所有目标与修复对照命令都使用了 `--all-features`。这会启用 manifest 中全部 feature，关键表面包括 `hooks`、`functions`、`collation`、`window`，而不只是默认 feature。

### 2.2 工具身份

| 工具 | 版本 | master commit | 源码 tar SHA-256 | 工具链 |
| --- | --- | --- | --- | --- |
| Yuga | `0.1.0` | `0d4180b82cf51f7b1718590e89e78be104bca109` | `e7a0fc9683f5c045f4e89e086c87638f79ceb4e9c82b456af739ee8c7836e934` | `nightly-2022-11-18`; rustc `1.67.0-nightly (83356b78c 2022-11-17)`；LLVM 15.0.4；`rustc-dev`、`llvm-tools-preview` |
| FFIChecker | `0.1.0` | `5ab17582e8b6171bfc866565e590e87778d7dda7` | `5130a78ba53be9a5757cc71ef70721da4491f636fbb75fae877dc1e966641733` | `nightly-2021-12-05`; rustc `1.59.0-nightly (efec54529 2021-12-04)`；rustc LLVM 13.0.0；system LLVM/Clang/LLD 13.0.1 |

最终二进制 SHA-256：

- `cargo-yuga`：`88baeacd083580dacacb2ec4bd71333a44175b46f4896b1084560438a59f003f`
- `yuga`：`dcb4b4b7968f580959451345a3e60be40d511386ac7f84fd1c26024485242cd1`
- `cargo-ffi-checker`：`9806bc56aa04d24aff2c2e3d3b50ef066d6c558f79a80f35319bfa7c05ecb8fe`
- FFIChecker `analyzer`：`7d5e6d0be3e2657896d926c34a3a422c5c0f8ce83834759176e718dcb7279fb4`
- FFIChecker `entry_collector`：`b6f42ad742b6f6bab67c38c116f99aec8288c2afa5482325304b43b8460358d2`

上游入口：[Yuga](https://github.com/vnrst/Yuga)、[FFIChecker](https://github.com/lizhuohua/rust-ffi-checker)、[RUSTSEC-2021-0128](https://rustsec.org/advisories/RUSTSEC-2021-0128.html)。

## 3. 环境修复与分析不变量

这些修复只解决旧工具链的依赖、传输和链接问题；没有修改 BoundaryWitness 分析代码，也没有修改 Yuga/FFIChecker 的分析实现。

### 3.1 Yuga

1. `https://index.crates.io/config.json` 先验证为 HTTP 200；运行时设置 runbook 指定的 sparse 变量。服务器 Cargo 配置把 registry 映射到 sparse HTTP 镜像。
2. 当前 Yuga master 的 `Cargo.toml` 已增加依赖，但随附 `Cargo.lock` 未同步；原锁 SHA-256 为 `e02429...`。直接解析会选中需要 edition 2024 的 `time-core 0.1.9`，Cargo 1.67 无法构建。
3. 在项目外生成兼容锁，恢复上游 `Cargo.toml` 后再执行原 `install-debug.sh`。兼容锁 SHA-256 为 `ce48ef8fde2cef318e4a9976b5e32bf1867c8ac6d91516690bbc423df77b97e5`；关键固定项为 `comrak 0.13.1`、`plist 1.5.1`、`time 0.3.17`、`time-core 0.1.0`、`serde/serde_derive 1.0.126`。分析源代码未改。
4. 目标的 Yuga 兼容锁 SHA-256 为 `24c219cc067cff455b9ab20efd18ad8cd4d4dcac23b4e1df5aedfdf6e21b89f0`。它只冻结旧工具链可接受的依赖解析；rusqlite 三个目标源文件未改。
5. 0.26.2 修复对照的 Yuga 兼容锁 SHA-256 为 `b366b758c72879ba9a099add1545f5ac257a6e34877ae6f87aa5e7fef83c2379`。

### 3.2 FFIChecker

1. Cargo 1.58 不支持服务器现有 sparse source replacement，按 runbook 兜底使用 Cargo 1.97 `cargo vendor`，再由 2021 nightly `--offline` 构建。
2. 上游 `llvm-sys = "130"` 的默认静态链接与 `rustc_driver` 自带 LLVM 同时注册命令行选项，启动时出现 duplicate registration。只对构建 manifest 启用 `llvm-sys` 的 `no-llvm-linking` feature，让程序使用 `rustc_driver` 已加载的 LLVM 13；上游 manifest SHA-256 `f893e5...`，构建 manifest SHA-256 `9fb493b...`。没有改分析源代码或规则。
3. FFIChecker 使用隔离的 `RUSTUP_HOME`，避免旧的半安装工具链互相覆盖。Clang、LLD、`llvm-as` 均固定到 13.0.1。
4. rusqlite 0.26.1 的 FFIChecker 兼容锁 SHA-256 为 `74951fa14484e24e34791e736b496bc72b04152d778f5bcbcd76df4faaccaab1`；其中将 `ahash` 固定为 0.7.6，避免 Cargo 1.58 无法解析 0.7.7 的 namespaced feature 语法。

完整锁、完整 stdout 和构建日志留在 Git 外的逻辑 artifact catalog 中，以各自 SHA-256 绑定；本目录只提交小型原始 finding 输出，不提交第三方源码、构建产物、大日志或机器路径。

## 4. 完整执行命令

下面用逻辑变量替代机器路径；变量指向仓库外目录，不改变实际参数。每个正式命令都直接重定向完整输出，并单独取被测命令的退出码。

```bash
export RUN_ROOT="${HOME}/bw-gate0-external"
export CARGO_UNSTABLE_SPARSE_REGISTRY=true
export CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
export CARGO_NET_RETRY=5
curl -sS -o /dev/null -w '%{http_code}\n' https://index.crates.io/config.json
```

源码获取全部走 codeload / 静态 crate 下载，不依赖 `git clone`：

```bash
mkdir -p "$RUN_ROOT/sources" "$RUN_ROOT/build" "$RUN_ROOT/logs" "$RUN_ROOT/reports"
curl -fL --retry 5 https://codeload.github.com/vnrst/Yuga/tar.gz/refs/heads/master \
  -o "$RUN_ROOT/sources/Yuga-master.tar.gz"
curl -fL --retry 5 https://codeload.github.com/lizhuohua/rust-ffi-checker/tar.gz/refs/heads/master \
  -o "$RUN_ROOT/sources/rust-ffi-checker-master.tar.gz"
curl -fL --retry 5 https://codeload.github.com/jnqnfe/pulse-binding-rust/tar.gz/5db934446759f51aedeee51895b4ea74a385f591 \
  -o "$RUN_ROOT/sources/pulse-binding-rust-5db9344.tar.gz"
curl -fL --retry 5 https://codeload.github.com/rusqlite/rusqlite/tar.gz/refs/tags/rusqlite-0.26.1 \
  -o "$RUN_ROOT/sources/rusqlite-0.26.1.tar.gz"
curl -fL --retry 5 https://codeload.github.com/rusqlite/rusqlite/tar.gz/refs/tags/v0.26.2 \
  -o "$RUN_ROOT/sources/rusqlite-0.26.2.tar.gz"
```

### 4.1 Yuga 构建、正对照、目标和修复对照

```bash
curl -fL --retry 5 \
  https://codeload.github.com/vnrst/Yuga/tar.gz/refs/heads/master \
  -o "$RUN_ROOT/sources/Yuga-master.tar.gz"

export RUSTUP_TOOLCHAIN=nightly-2022-11-18
export CARGO_TARGET_DIR="$RUN_ROOT/build/yuga-tool"
export LIBCLANG_PATH=/usr/lib/llvm-13/lib
export LD_LIBRARY_PATH="$(rustc --print sysroot)/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
rustc --version
cd "$RUN_ROOT/sources/Yuga-master"
./install-debug.sh > "$RUN_ROOT/logs/yuga-install.log" 2>&1; echo $?

# 正对照；见下一节关于当前 master 缺少 buildable sample 的说明
export CARGO_TARGET_DIR="$RUN_ROOT/build/yuga-positive"
cd "$PULSE_POSITIVE/pulse-binding"
cargo yuga > "$RUN_ROOT/reports/yuga-pulse-binding-positive.report.txt" 2>&1; echo $?

# 正式目标
export CARGO_TARGET_DIR="$RUN_ROOT/build/yuga-target-rusqlite-0.26.1"
cd "$RUSQLITE_0261"
cargo yuga --all-features > "$RUN_ROOT/reports/yuga-rusqlite-0.26.1-all-features.report.txt" 2>&1; echo $?

# 推荐的已修版本对照
export CARGO_TARGET_DIR="$RUN_ROOT/build/yuga-target-rusqlite-0.26.2"
cd "$RUSQLITE_0262"
cargo yuga --all-features > "$RUN_ROOT/reports/yuga-rusqlite-0.26.2-all-features.report.txt" 2>&1; echo $?
```

### 4.2 FFIChecker 构建、正对照、目标和修复对照

```bash
export PRIMARY_RUSTUP_HOME="${RUSTUP_HOME:-${HOME}/.rustup}"
export RUSTUP_HOME="$RUN_ROOT/build/rustup-ffichecker"
rustup toolchain install nightly-2021-12-05 --profile minimal \
  --component rustc-dev --component llvm-tools-preview \
  > "$RUN_ROOT/logs/ffichecker-rustup.log" 2>&1; echo $?

export RUSTUP_TOOLCHAIN=nightly-2021-12-05
export LLVM_SYS_130_PREFIX=/usr/lib/llvm-13
export LIBCLANG_PATH=/usr/lib/llvm-13/lib
export LD_LIBRARY_PATH="$(rustc --print sysroot)/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# 先由联网的新 Cargo vendor；随后旧 Cargo 离线构建。
cd "$FFICHECKER_SRC"
RUSTUP_HOME="$PRIMARY_RUSTUP_HOME" cargo +1.97.0 vendor --locked "$RUN_ROOT/build/ffichecker-vendor" \
  > "$FFICHECKER_SRC/.cargo/config" 2> "$RUN_ROOT/logs/ffichecker-vendor.log"; echo $?

# 构建期链接调整；唯一变化是给 llvm-sys 加 no-llvm-linking，分析源不变。
python3 -c 'from pathlib import Path; p=Path("Cargo.toml"); s=p.read_text(); old="llvm-sys = \"130\""; new="llvm-sys = { version = \"130\", features = [\"no-llvm-linking\"] }"; assert s.count(old) == 1; p.write_text(s.replace(old, new))'
cargo install --locked --offline --path . --root "$FFICHECKER_INSTALL" \
  > "$RUN_ROOT/logs/ffichecker-build.log" 2>&1; echo $?

# PATH 前缀中的 clang/ld.lld/llvm-as 均为 13.0.1。
export PATH="$RUN_ROOT/build/llvm13-bin:$FFICHECKER_INSTALL/bin:$PATH"
export CARGO_NET_OFFLINE=true

cd "$FFICHECKER_SRC/examples/c-in-rust-uaf"
cargo clean > "$RUN_ROOT/logs/ffichecker-positive-clean.log" 2>&1; rc_clean=$?
cargo ffi-checker > "$RUN_ROOT/reports/ffichecker-positive.report.txt" 2>&1; rc=$?
echo "FFICHECKER_POSITIVE_CLEAN_EXIT=$rc_clean"; echo "FFICHECKER_POSITIVE_EXIT=$rc"

# 对目标依赖也先由新 Cargo vendor；两个版本使用各自冻结的兼容锁。
cd "$RUSQLITE_0261"
mkdir -p .cargo
CARGO_NET_OFFLINE=false RUSTUP_HOME="$PRIMARY_RUSTUP_HOME" \
  cargo +1.97.0 vendor --locked "$RUN_ROOT/build/rusqlite-ffichecker-vendor" \
  > .cargo/config 2> "$RUN_ROOT/logs/rusqlite-ffichecker-vendor.log"; echo $?
cargo clean > "$RUN_ROOT/logs/ffichecker-0261-clean.log" 2>&1; rc_clean=$?
cargo ffi-checker --all-features > "$RUN_ROOT/reports/ffichecker-rusqlite-0.26.1-all-features.report.txt" 2>&1; rc=$?
echo "FFICHECKER_TARGET_CLEAN_EXIT=$rc_clean"; echo "FFICHECKER_TARGET_EXIT=$rc"

cd "$RUSQLITE_0262"
mkdir -p .cargo
cp "$RUSQLITE_0261/.cargo/config" .cargo/config
cargo clean > "$RUN_ROOT/logs/ffichecker-0262-clean.log" 2>&1; rc_clean=$?
cargo ffi-checker --all-features > "$RUN_ROOT/reports/ffichecker-rusqlite-0.26.2-all-features.report.txt" 2>&1; rc=$?
echo "FFICHECKER_FIXED_CLEAN_EXIT=$rc_clean"; echo "FFICHECKER_FIXED_EXIT=$rc"
```

## 5. 正对照

### 5.1 Yuga / pulse-binding：有效，9 条

当前 Yuga master 的 `examples/Rustsec/pulse-binding/` 只有作者生成的 `get_api-uaf*.md` 报告，没有 `Cargo.toml` 或样本源码，因而 runbook 中在该目录直接执行的命令不可运行。没有把这一状态误判为“0 报告”。

正对照改用这些报告对应的公开 `pulse-binding-rust` 源码 commit `5db934446759f51aedeee51895b4ea74a385f591`，只建立包含 `pulse-binding` 与 `pulse-sys` 的最小 workspace，不改源码。源码 tar SHA-256 为 `b449958abc10a6b29f1114e45301ade85e8fc319629de1eeb9ae35e40c9e8501`；workspace manifest SHA-256 为 `10da803cd66890cf7334e7a376ac91bc8408d8f9e4000f2a071f51b72c92be39`。

正式正对照退出码 0，Yuga 生成 9 条报告，包含作者公布的两条 `get_api` finding。完整 stdout：

- artifact：`artifact:run:gate0-baseline-rusqlite-0.26.1-20260730T163351Z:yuga-positive-full-stdout`
- SHA-256：`5b4eb0c951ba5ee95e8b4962c8e072c1560c6910e340ce380448a9d572a033d1`
- 大小：123,413 bytes
- 小型原始 finding 摘录：[yuga-positive-control.raw-findings.txt](gate0-baseline-comparison-2026-07-31/yuga-positive-control.raw-findings.txt)

因此随后对 rusqlite 的结论不是建立在“工具没跑起来”上。

### 5.2 FFIChecker / c-in-rust-uaf：有效，1 条

上游自带的 `examples/c-in-rust-uaf` 正对照退出码 0，报告 1 条 High 严重度 finding：已知 C IR，可能 UAF / double free / taint source meets sink。

- 完整 stdout SHA-256：`a6a0ed95e4167c38102e3718e3144e33e74a32fe6a5e03b4ba8e3378bccfa9f0`
- 小型原始报告：[ffichecker-positive-control.raw-report.txt](gate0-baseline-comparison-2026-07-31/ffichecker-positive-control.raw-report.txt)

## 6. Yuga 目标结果

Yuga 在 rusqlite 0.26.1 上共报告 13 条：

`new`、`create_collation`、`create_scalar_function`、`commit_hook`、`rollback_hook`、`update_hook`、`get_interrupt_handle`（2 条）、`prepare`、`query_map`、`query_map_named`、`query_and_then`、`query_and_then_named`。

完整 stdout SHA-256：`9b81600f1a11ea830168e2a9c4c7dec535aeb37654b91756887424c693388f06`。全部 13 个条目的原始首段、位置和逐报告 hash 在 [yuga-rusqlite-0.26.1.raw-findings.txt](gate0-baseline-comparison-2026-07-31/yuga-rusqlite-0.26.1.raw-findings.txt)。

### 6.1 7 个公告函数逐项分类

| 公告函数 | Yuga 0.26.1 | 报告理由 | 0.26.2 | 分类 |
| --- | --- | --- | --- | --- |
| `create_scalar_function` | 报 | `x_func: F` outlives borrow；可能赋给 `ffi::sqlite3` | 消失 | **同一持有期缺陷** |
| `create_aggregate_function` | 不报 | — | 不报 | 漏报 |
| `create_window_function` | 不报 | — | 不报 | 漏报 |
| `commit_hook` | 报 | `hook.0: F` outlives borrow；可能赋给 `ffi::sqlite3` | 消失 | **同一持有期缺陷** |
| `rollback_hook` | 报 | 同上 | 消失 | **同一持有期缺陷** |
| `update_hook` | 报 | 同上 | 消失 | **同一持有期缺陷** |
| `create_collation` | 报 | `x_compare: C` outlives borrow；可能赋给 `ffi::sqlite3` | 消失 | **同一持有期缺陷** |

统计：函数名命中 `5/7`；经理由与修复对照确认的同缺陷命中也是 `5/7`。

### 6.2 修复对照为何具有判别力

rusqlite 0.26.2 把五个已命中入口的泛型 callback bound 从与接收者关联的 `'c` 改为 `'static`。Yuga 0.26.2 仍报告 8 条，但 0.26.1 相比 0.26.2 的 finding 集合差恰好只有：

- `commit_hook-uaf`
- `create_collation-uaf`
- `create_scalar_function-uaf`
- `rollback_hook-uaf`
- `update_hook-uaf`

0.26.2 没有新增 Yuga finding。其原始条目见 [yuga-rusqlite-0.26.2.raw-findings.txt](gate0-baseline-comparison-2026-07-31/yuga-rusqlite-0.26.2.raw-findings.txt)，完整 stdout SHA-256 为 `8eeddf5a85a092f203ddce2c7d91ce96e81989d46f67800516e6d5397e9675e6`。

这个差分排除了“Yuga 只是因相同函数里的无关返回引用而误碰”的解释。

## 7. FFIChecker 目标结果

FFIChecker 在 0.26.1 上报告 4 条：

1. `create_module`
2. `commit_hook`
3. `update_hook`
4. `rollback_hook`

其中 3 条函数名落在公告 7 函数内，但四条的报告文本均为：外部 C IR 未知、可能 memory leakage、传给未知 FFI 的参数处于 `Forgotten` 状态，严重度 Medium。它没有报告 callback bound 过弱、外部持有时间长于 Rust 允许时间或 UAF。

更强的负对照是：0.26.2 已把 hooks callback bound 修成 `'static`，FFIChecker 仍输出相同 4 条、相同理由。因此 FFIChecker 的“3 个同名函数”不等于“3 个同缺陷”；同缺陷计数为 0。

- 0.26.1 原始报告：[ffichecker-rusqlite-0.26.1.raw-report.txt](gate0-baseline-comparison-2026-07-31/ffichecker-rusqlite-0.26.1.raw-report.txt)，完整 stdout SHA-256 `f67a9d208eb60ed389a80a542bc228313311bc7a55f9e3641c40a473969d0530`
- 0.26.2 原始报告：[ffichecker-rusqlite-0.26.2.raw-report.txt](gate0-baseline-comparison-2026-07-31/ffichecker-rusqlite-0.26.2.raw-report.txt)，完整 stdout SHA-256 `bcb1902d9aec3dd472ae2ac2fcfde3141bdfd7ec45b0f9268c5744839e6c8776`

运行生成的 `target/bitcode_paths` 有 78 条 Rust `.bc`，但没有独立 C `.o`；bundled SQLite/SQLCipher 的 C 对象进入静态 archive，而 FFIChecker 的收集器只枚举 `.ll` 与独立 LLVM object，因此报告中把 `sqlite3_*` IR 标为 unknown。这是本次实测工具路径的限制，不是把失败运行当作 0 报告：工具退出码为 0，且正对照已证明已知 C IR 路径能报告 UAF。

## 8. 对 N1 与 Gate 0 的影响

### 已证实

- Yuga master 在受影响版本上能报告 7 个公告函数中的 5 个；报告理由直接涉及 callback 值被 `ffi::sqlite3` 所代表对象持有并导致潜在 UAF。
- 同一工具在已修 0.26.2 上恰好不再报告这 5 条。
- FFIChecker 的同名 hooks finding 是释放责任 / leak 类，且修复后不消失，不是持有期契约缺陷。

### 结论上限

本次结果只完成 Gate 0 的“外部基线同 corpus 对照”子项。它给出了需要立即处理的反例：**N1 当前关于 Yuga 能力边界的前提不成立，研究命题、related-work 区分和技术投入顺序需要重审。**

这不说明 Yuga 对全部 7 个函数完备（它漏掉 aggregate/window），也不说明 Yuga 已建立与 BoundaryWitness 计划相同的外部行为证据链。可以进一步研究精度、覆盖、可解释证据或其他维度是否仍有新颖性，但不得继续沿用“Yuga 不建模此类外部持有，因此不会报”的表述。

Gate 0 另外两项仍未由本实验完成；本记录**不宣称 Gate 0 整体通过，也不作任何跨语言错配能力已经完成的结论。**

## 9. 数据对齐与 artifact

| 字段 | 值 |
| --- | --- |
| `code_commit` | `f40aa3b77781dc4265a71ee1ddabb43fa1ac2b8c`；运行开始前工作树 clean |
| `toolchain` | 见 §2.2；含 rustc commit、target triple、LLVM 与组件 |
| `contract_hash` | 不适用；外部工具没有消费 BoundaryWitness Contract/API map |
| `schema_version` | `boundary-witness/external-baseline-run-manifest/v1`；两工具原始输出均为 upstream unversioned 格式 |
| `dataset_version` | `corpus.gate0.external-baseline.rusqlite-0.26.1.20260731` |
| `dataset_hash` | `18e0b0ea8f15c26b5c0c846d00d85e2089cf4aacac942ffac0386c5b16dd1c94` |
| `config_hash` | `8d6ccd30164c227af5363bf73446261d057788fbcbeeea11e90baad26eb69647` |
| `run_id` | `gate0-baseline-rusqlite-0.26.1-20260730T163351Z` |

机器可读记录：[run-manifest.json](gate0-baseline-comparison-2026-07-31/run-manifest.json)。本目录的逐文件校验见 [SHA256SUMS](gate0-baseline-comparison-2026-07-31/SHA256SUMS)；该 checksum manifest 自身的 SHA-256 为 `e7747d7a5c03e1cadcb96c2d3acaf3a6a5d848ed0e3221548cd9f1cba3d732d6`。checksum 只使用 artifact 根下的相对路径。

环境配置阶段的失败尝试保留为 diagnostic，不并入正式计数：Yuga stale lock、无法构建的 current-master pulse 目录、Cargo 1.58 不支持 sparse source replacement、以及 FFIChecker 双 LLVM 注册。所有正式行均来自修复后退出码 0 的独立运行。
