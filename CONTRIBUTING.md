# Contributing

BoundaryWitness 接受围绕 Rust-C 生命周期边界分析、Schema/Contract、实验基础设施、文档和测试的贡献。贡献流程固定为 Issue -> branch -> test -> PR。

## 1. Issue

先开 Issue，说明：

- 目标、范围和非目标；
- 涉及的代码、Schema、Contract、文档或实验文件；
- 输入/输出接口；
- 数据边界与禁止材料；
- 验收条件和完成谓词；
- 计划运行的测试命令。

实验 Issue 还应写明 commit、dataset/config/hash、run ID、对照组、证据等级和预计公开摘要。

## 2. Branch

分支命名使用：

- `feat/area-summary`
- `fix/area-summary`
- `docs/area-summary`
- `chore/area-summary`

并行贡献者应声明文件所有权。共享接口先行：先更新 Schema/model/Contract/CLI，再更新生产者、消费者、fixtures 和文档。

## 3. Test

运行与修改范围匹配的测试，并记录未运行项。存在 `Cargo.lock` 时使用 `--locked`。

```bash
cargo fmt --all --check
cargo test -p bw-model --locked
cargo test -p bw-cli --locked
cargo test --manifest-path compiler/bw-rustc/Cargo.toml --locked
```

不要删除测试、跳过失败测试、放宽 validator 或把 blocked gate 改写成通过。

## 4. PR

PR 描述应包含：

- 关联 Issue；
- 改动摘要；
- Schema/Contract/CLI 影响；
- 数据或 run 是否需要重跑；
- 实际测试结果；
- 已知限制和剩余风险。

不得提交 prompt、对话记录、迁移清单、临时脚本、debug 输出、私有路径、大型结果、sealed holdout 或未披露候选。
