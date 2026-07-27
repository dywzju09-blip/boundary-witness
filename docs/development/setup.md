# 开发环境安装

本文说明公开仓库的最小开发环境。所有命令默认在仓库根目录执行；存在 `Cargo.lock` 时统一使用 `--locked`。

## 工具链

仓库根目录的 [`rust-toolchain.toml`](../../rust-toolchain.toml) 固定为 Rust `1.97.0`，并安装 `clippy` 与 `rustfmt`。不要用本机默认 `stable` 替代该文件；需要更新工具链时，应同时更新测试证据和相关文档。

```bash
rustup toolchain install 1.97.0 --component clippy --component rustfmt
cargo --version
rustc --version
```

`compiler/bw-rustc/` 使用独立 [`rust-toolchain.toml`](../../compiler/bw-rustc/rust-toolchain.toml) 与独立 [`Cargo.lock`](../../compiler/bw-rustc/Cargo.lock)，因为它依赖 `rustc_private`/MIR 内部接口。不要把 compiler wrapper 的锁文件与根 workspace 锁文件合并。

## 获取依赖

根 workspace 使用 [`Cargo.lock`](../../Cargo.lock) 冻结依赖。常规检查入口：

```bash
cargo check --workspace --locked
cargo test -p bw-model --locked
cargo test -p bw-cli --locked
```

compiler wrapper 单独检查：

```bash
cargo check --manifest-path compiler/bw-rustc/Cargo.toml --locked
cargo test --manifest-path compiler/bw-rustc/Cargo.toml --locked
```

## 本地数据边界

公开仓库只保存源码、Schema、Contract、小型 fixtures、公开实验配置和正式文档。大型 corpus、sealed holdout、私有 run、服务器同步副本和未披露候选不进入 Git。数据治理见 [repository-and-data-governance](../project/repository-and-data-governance.md)，实验结果对齐见 [data-alignment](../experiments/data-alignment.md)。

## 常见阻塞

- `cargo test -p bw-experiment --locked` 只覆盖公开 fixtures 上的实验组件测试，不能替代 formal run 或 public regression。
- D0/D1/D2 formal run 还依赖 Linux 环境、固定 artifact、真实 image digest 和对齐的 run manifest。
- V3.3 gate 未通过；任何本地小测试成功都不能升级为 `Verified` 结论。
