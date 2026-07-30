# Runbook：外部基线对照（Gate 0）

本 runbook 执行 [milestone gates](../../roadmap/milestone-gates.md) 的 Gate 0 第一项：在同一 corpus 上运行既有工具，确定它们在**持有期维度**上报不报。

## 为什么这件事必须先做

[research thesis](../../project/research-thesis.md) 的 N1 声称：判定安全 FFI 封装的健全性需要联结 Rust 侧契约与外部侧行为，现有工作各做一半。**Yuga 是最近的反例候选**——它检测函数签名上的生命周期标注错误，问题陈述与本系统的持有期维度表面相近。

因此本对照有两种结果，后果完全不同：

| 结果 | 后果 |
| --- | --- |
| Yuga 在目标样本上**不报** | N1 成立的前提保住。related work 中据此精确区分两者的内存模型 |
| Yuga **能报** | **N1 的立论需要重做。** 八维框架与外部侧分析的投入顺序都要重新设计 |

在几周的外部侧分析投入之前先跑这一步，是为了让第二种结果尽早暴露，而不是事后暴露。

## 目标与判据

**目标样本**：`rusqlite 0.26.1`（公开公告 RUSTSEC-2021-0128 覆盖的版本）。该公告列出 7 个受影响函数，分布在 `hooks`、`functions`、`collation` 三个 feature 下。

**必须记录**：
1. Yuga 在该样本上报出的全部条目
2. 其中有多少落在那 7 个函数上
3. 若为 0，说明**为什么**——预期原因是 Yuga 的内存模型是 Rust 内部别名（返回引用、结构体字段生命周期），不建模"回调被交给一个 Rust 追踪不到的外部持有者"
4. FFIChecker 同样处理

## 关键纪律：先做正对照

**没有正对照的负结果不成立。** "Yuga 什么都没报"和"Yuga 根本没跑起来"在输出上无法区分。

所以顺序必须是：

1. 先在 Yuga **已知能检出**的样本上跑，确认它确实报出东西
2. 再在目标样本上跑

Yuga 仓库自带 `examples/Rustsec/`，其中 `pulse-binding` 出现在作者公布的确认检出列表里，适合作正对照。作者另有一个合成缺陷数据集（27 条，基于 RustSec 模式），也可用。

**正对照不通过就不要继续**，先解决环境问题。

## 环境准备

### 工具链

Yuga 的 `rust-toolchain.toml` 要求：

```toml
[toolchain]
channel = "nightly-2022-11-18"
components = ["rustc-dev", "llvm-tools-preview"]
```

安装：

```bash
rustup toolchain install nightly-2022-11-18 -c rustc-dev -c llvm-tools-preview
```

**这一步是大体积下载，中断会留下半装状态。** 半装状态下一次构建会自动触发修复重下，看起来像"构建很慢"。中断后先跑一次 `rustup toolchain list` 与 `rustc --version` 确认完整，再继续。

版本兼容性上这是个好消息：`rusqlite 0.26.1` 是 2021 年的代码，2022 年的 nightly 属于同期，不存在语言特性代差。

### 获取源码

```bash
curl -sSL -o yuga.tar.gz https://codeload.github.com/vnrst/Yuga/tar.gz/refs/heads/master
```

### 构建

```bash
cd Yuga
export CARGO_TARGET_DIR=<本项目之外的独立目录>   # 不要与本仓库的 target 缓存混用
./install-debug.sh
```

`install-debug.sh` 的内容是 `cargo install --locked --debug --path . --force --features backtraces`，会把 `cargo-yuga` 装进 `$CARGO_HOME/bin`。

## 已知障碍与绕过

以下三条是实际踩到的，按出现顺序列出。

### 1. crates.io **git** 索引拉不动

2022 年的 cargo 默认使用 git 协议的 crates.io 索引，该仓库体积很大。在传输受限或不稳定的网络上会失败，两种表现：

```
# libgit2 路径
SSL error: received early EOF; class=Ssl (16); code=Eof (-20)

# git CLI 路径（CARGO_NET_GIT_FETCH_WITH_CLI=true）
error: RPC failed; curl 56 GnuTLS recv error (-9): Error decoding the received TLS packet.
fatal: fetch-pack: invalid index-pack output
```

**报错指向 `crates.io-index`，但原因是传输层，不是 crates.io 不可用。** 切换到 git CLI 不能解决——它只是把同一个问题暴露在更低一层。

**绕过（推荐）**：改用 sparse HTTP 索引，只取需要的 crate 元数据，不克隆整个 git 仓库。

```bash
export CARGO_UNSTABLE_SPARSE_REGISTRY=true
export CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
export CARGO_NET_RETRY=5
```

先验证可达：`curl -sS -o /dev/null -w "%{http_code}\n" https://index.crates.io/config.json` 应返回 `200`。

**绕过（兜底）**：若 sparse 也不通，用一个网络正常的较新工具链执行 `cargo vendor`，再让 2022 工具链以 `--offline` + vendor 配置构建。

### 2. `github.com` 与 `codeload.github.com` 表现不同

同一主机上 `curl https://github.com/` 可能长时间无响应，而 `codeload.github.com` 正常返回 200。**取源码优先用 codeload 的 tarball**，不要依赖 `git clone`。

### 3. 输出与退出码的两个陷阱

这两条不是 Yuga 的问题，是执行方式的问题，但它们会让你把"没跑起来"读成"跑完了没结果"：

- **`cmd | grep | tail` 之后的 `$?` 是 `tail` 的退出码，不是 `cmd` 的。** 用 `cmd >log 2>&1; echo $?`，或者 `${PIPESTATUS[0]}`
- **在最外层套管道会缓冲到进程结束**，长时间构建期间看不到任何进度，无法区分"在编译"和"卡住了"。把完整输出重定向到日志文件，再单独查看

## 执行步骤

```bash
# 0. 确认工具链完整
rustup run nightly-2022-11-18 rustc --version

# 1. 正对照：Yuga 自带样本
cd Yuga/examples/Rustsec/pulse-binding
cargo yuga > pulse-binding.report 2>&1
# 期望：报告非空

# 2. 目标样本
#    rusqlite 的回调表面在非默认 feature 后面，必须显式启用，
#    否则 hooks / functions / collation 三组代码根本不参与编译
cd <rusqlite-0.26.1 源码目录>
cargo yuga --all-features > rusqlite-0261.report 2>&1

# 3. 对照组（可选但推荐）：已修版本
cd <rusqlite-0.26.2 源码目录>
cargo yuga --all-features > rusqlite-0262.report 2>&1
```

**feature 这一条不能省。** 本项目自己的扫描验证过：默认 feature 下 `hooks` 与 `functions` 不编译，注册点数量为 0，组件会被报成"没有受支持的边界"。用默认 feature 跑 Yuga 得到的空结果没有意义。

## 预期结果与解读

### 正对照

`pulse-binding` 上应有非空报告。**若为空，环境有问题，停止，不要据此对目标样本下结论。**

### 目标样本

预期 Yuga 在那 7 个函数上**不报**。理由是形态不匹配：

```rust
// rusqlite 0.26.1 的形态
pub fn update_hook<'c, F>(&'c self, hook: Option<F>)
where F: FnMut(Action, &str, &str, i64) + Send + 'c
```

- 没有返回引用，因此不是"返回值生命周期不受输入约束"
- 没有结构体字段生命周期错配
- bound 挂在**泛型类型参数**上，逃逸发生在 `Box::into_raw` 之后交给外部函数

Yuga 的分析对象是 Rust 内部的别名与生命周期标注关系，上述形态的"另一端"在 Rust 代码里不可见。

### 三种结果分别怎么办

| 观察 | 结论 | 动作 |
| --- | --- | --- |
| 正对照非空，目标样本 0 报 | 支持 N1 | 记录报告，写入 related work 的区分依据 |
| 正对照非空，目标样本报中若干 | **N1 受威胁** | 逐条比对它报的是不是同一回事（同一函数？同一理由？）。若确为同一缺陷，立论重做 |
| 正对照为空 | 结果无效 | 修环境，不得出任何结论 |

**注意区分"报了同一个函数"与"报了同一个缺陷"。** 若 Yuga 因为别的理由（例如某个无关的返回引用）碰巧命中同一函数，那不构成对 N1 的威胁，但必须在记录中说清。

## FFIChecker

同样流程。它基于 LLVM IR 做跨语言堆内存管理分析（alloc/dealloc 错配、double free、leak）。预期它同样不报持有期维度——它判的是释放责任，不是契约强度。

若 FFIChecker 在目标样本上报出释放责任类问题，那属于 [research thesis](../../project/research-thesis.md) 表中"释放责任"维度，本项目明确不将其作为创新点，如实记录即可。

## 产出

一份可复现记录，包含：工具版本与 commit、工具链版本、启用的 feature、完整命令、原始报告、命中/漏报统计与归因。放入 [results](../results/)，遵循 [data alignment](../data-alignment.md)。

在 Gate 0 通过前，不得在任何对外材料中表述跨语言契约错配判定已达成。
