# rusqlite 历史 callback benchmark

每个隔离 benchmark crate 都提交自己的 `Cargo.lock`。这里故意不使用一个共享 workspace lockfile，因为历史版本 `rusqlite 0.26.1` 已被 yanked，Cargo 无法在同一个新解析流程里同时稳定解析 `rusqlite = "=0.26.1"` 和 `rusqlite = "=0.26.2"`。

`rusqlite 0.26.1` 保存在 `vendor/rusqlite-0.26.1`。原因是 Cargo 不会从 registry index 重新解析这个已 yanked 的历史版本。该 vendored source 来自 crates.io 的 `rusqlite/0.26.1` `.crate` 归档；SHA-256：

```text
8a82b0b91fad72160c56bf8da7a549b25d7c31109f52cc1437eac4c0ad2550a7
```

当前可运行或可检查的隔离 case 包括：

- `update-hook/vulnerable`：`rusqlite = "=0.26.1"`，borrowed callback capture，触发后用于产生核心生命周期 witness。
- `update-hook/fixed`：`rusqlite = "=0.26.2"`，owned callback capture，作为可运行安全对照。
- `update-hook/safe-move`：`rusqlite = "=0.26.1"`，callback 捕获 owned state，证明旧版本里不是所有 retained callback 都是漏洞。
- `update-hook/unregister-before-drop`：`rusqlite = "=0.26.1"`，对象结束前先注销 callback，作为安全对照。
- `update-hook/no-trigger`：`rusqlite = "=0.26.1"`，borrow 结束后进入后续阶段但不触发 callback，最多应作为 exposure。
- `update-hook/fixed-borrowed-reject`：`rusqlite = "=0.26.2"`，borrowed capture 源码只用于 compile-rejection 证据。
- `scalar-function/vulnerable`：`rusqlite = "=0.26.1"`，borrowed callback capture，触发 `SELECT bw_counter()` 后用于产生同类生命周期 witness。
- `scalar-function/fixed`：`rusqlite = "=0.26.2"`，owned callback capture，作为可运行安全对照。
- `scalar-function/safe-move`：`rusqlite = "=0.26.1"`，callback 捕获 owned state，证明 scalar family 也不是“注册即漏洞”。
- `scalar-function/unregister-before-drop`：`rusqlite = "=0.26.1"`，对象结束前先 `remove_function`，作为安全对照。
- `scalar-function/no-trigger`：`rusqlite = "=0.26.1"`，borrow 结束后不执行 `SELECT bw_counter()`，最多应作为 exposure。
- `scalar-function/fixed-borrowed-reject`：`rusqlite = "=0.26.2"`，borrowed capture 源码只用于 compile-rejection 证据。

`shared/` 中的 adapter 只负责把具体 rusqlite 操作翻译成通用 runtime event，例如 callback register、capture bind、invoke、unregister/remove、replacement 和 owner drop。它不写入 CVE 标签，也不直接判断漏洞结论。

## M12 盲标签 runner

`shared/src/bin/bw-rusqlite-stage-artifacts.rs` 是 M12 的实验材料准备入口。它会读取真实 benchmark 源码目录，构建每个 runnable case，把可执行文件和 `static-facts.jsonl` 分拣到匿名 artifact 路径：

```text
experiments/artifacts/rusqlite-m12/bin/case-0001
experiments/artifacts/rusqlite-m12/static/case-0001.jsonl
```

staging 工具不是盲测分析器输入；它属于实验准备阶段。真实源码目录中可能出现 `vulnerable`、`fixed` 等开发用目录名，但 runner 不读取这些路径。

查看 staging 计划：

```bash
cargo run --locked --manifest-path benchmarks/historical-cves/rusqlite/shared/Cargo.toml --bin bw-rusqlite-stage-artifacts -- \
  plan .
```

在服务器上完成 `compiler/bw-rustc` 构建后，可以生成 artifacts：

```bash
cargo run --locked --manifest-path benchmarks/historical-cves/rusqlite/shared/Cargo.toml --bin bw-rusqlite-stage-artifacts -- \
  stage . compiler/bw-rustc/target/debug/bw-rustc
```

`shared/src/bin/bw-rusqlite-runner.rs` 是 M12 的盲测运行入口。它只读取匿名 case、静态事实路径、contract 路径和可执行文件路径；配置文件在 `experiments/configs/rusqlite-m12-cases.toml`。该配置故意不包含 `vulnerable`、`fixed`、`cve`、`expected` 等答案字段，case ID 由 runner 按输入顺序生成为 `case-0001`、`case-0002` 等。

runner 启动每个 child 时会设置：

- `BW_RUN_ID`
- `BW_TRACE_ID`
- `BW_TRACE_DIR`
- `BW_TRACE_COMPRESS=0`
- `BW_BUILD_ID`

因此每个 benchmark 程序默认仍可用内存 sink 独立运行；只有 runner 设置 `BW_TRACE_DIR` 时，才会把 runtime event 写入该 case 自己的 trace 目录。runner 随后把 segment 合并为 `trace.jsonl`，调用 `bw analyze`，并只保存实际观察到的 child exit、analyze exit 和 finding rule ID。

真实答案单独放在 `experiments/ground-truth/rusqlite-m12.toml`。它只能由事后 verifier 使用：

```bash
cargo run --locked --manifest-path benchmarks/historical-cves/rusqlite/shared/Cargo.toml --bin bw-rusqlite-runner -- \
  verify experiments/runs/rusqlite-m12/observed.jsonl experiments/ground-truth/rusqlite-m12.toml
```

如果需要一个不链接 oracle 和 benchmark child 的外部启动器，可以先编译 `experiments/tools/verify_blind_results.rs`，再让它调用已构建的 `bw-rusqlite-runner verify`。
