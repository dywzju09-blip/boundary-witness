# BoundaryWitness 仓库与数据治理设计

**状态：** 已批准  
**批准日期：** 2026-07-27  
**适用范围：** BoundaryWitness 公开源代码仓库、私有数据索引仓库、本地与私人服务器数据存储  

## 1. 目标

本设计用于将 BoundaryWitness 整理为可公开发布、可复现、可由多个 Agent 和开发者持续接手的工程仓库。整理工作必须满足以下目标：

1. 公开仓库只包含 BoundaryWitness 的源代码、正式设计、Schema、Contract、小型测试数据和可公开验证结果；
2. 大规模数据保存在本地和私人服务器，不提交 Git 或 Git LFS；
3. VPS 只承担远程构建、单元测试和小规模 smoke test；
4. 本地工作站拉取指定代码版本后执行大规模验证；
5. 代码、数据、配置、工具链和运行结果通过版本与 SHA-256 严格对齐；
6. 原始工作区及外围资料不删除、不移动、不覆盖；
7. 新公开仓库不继承旧 Git 历史，避免把中间提示文档、临时 Agent 资料和无关材料带入公开历史。

## 2. 非目标

本次整理不负责：

- 修改 BoundaryWitness 的检测语义或放宽验证器；
- 启动 public regression、100-crate pilot 或 sealed holdout；
- 把其他任务产生的 0-day 候选、CVE 提交材料或通用漏洞文档纳入 BoundaryWitness；
- 将 40GB 级语料、完整日志、缓存或运行产物上传 GitHub；
- 删除或清理原始目录中的排除内容；
- 保留逐日执行计划、Agent prompt、对话记录或 Superpowers 中间资料。

## 3. 仓库拓扑

### 3.1 公开主仓库 `boundary-witness`

公开主仓库是代码和正式项目文档的权威来源，包含：

- Rust workspace 及各核心 crate；
- `compiler/bw-rustc` 静态事实提取器；
- API/FFI 生命周期 Contracts；
- 版本化 JSON Schemas；
- 小型、确定性、可公开的 fixtures；
- benchmark 定义、适配器和必要源码；
- 实验配置、运行工具和公开 smoke 输入；
- 容器、部署与工具链配置；
- 中文正式设计、开发、实验、参考和路线图文档；
- GitHub CI、Issue 模板、PR 模板及贡献规范。

公开仓库不得包含：

- `target/`、缓存、日志、临时目录、工作树和编辑器文件；
- 大型 corpus、完整运行产物或 sealed holdout；
- 本地或私人服务器的绝对路径；
- 未验证漏洞候选和 CVE 提交材料；
- `.superpowers/`、Agent prompt、任务简报和中途 notes；
- 与 BoundaryWitness 无直接关系的工具或研究资料。

### 3.2 私有索引仓库 `boundary-witness-data-index`

私有索引仓库只保存轻量元数据，不保存大型数据本体。其职责包括：

- 私有和 holdout 数据集 manifest；
- 数据集版本与内容校验和；
- 运行 manifest；
- 数据快照锁文件；
- 可提交的小型私有结果摘要；
- manifest Schema 和一致性检查工具。

### 3.3 本地与私人服务器数据

大型数据本体保存在：

- 本地工作站：主要执行副本；
- 私人服务器：备份或第二副本。

VPS 不保存完整 corpus，也不承担大规模验证。数据无需加密，但每次同步后必须校验文件数量、总字节数和 SHA-256。

## 4. 非破坏式迁移

源目录为：

```text
/Users/dingyanwen/Desktop/CodeLearn/boundary-witness
```

目标整理目录为：

```text
/Users/dingyanwen/Desktop/CodeLearn/boundary-witness-github
```

私有索引目录为：

```text
/Users/dingyanwen/Desktop/CodeLearn/boundary-witness-data-index
```

迁移采用选择性复制，不在源目录中执行删除、移动、覆盖、Git 清理或历史改写。目标仓库独立初始化 Git，只复制经过分类确认的内容。

当前源仓库包含未提交修改，因此导入必须以实际工作树为准，同时记录源分支、HEAD、dirty diff 和未跟踪文件；不得只按当前 HEAD 导出。

## 5. 公开仓库目标结构

```text
boundary-witness/
├── README.md
├── AGENTS.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── .github/
├── crates/
├── compiler/bw-rustc/
├── contracts/
├── schemas/
├── fixtures/
├── benchmarks/
├── experiments/
├── tests/
├── tools/
├── infra/
└── docs/
    ├── README.md
    ├── project/
    ├── architecture/
    ├── development/
    ├── experiments/
    ├── case-studies/
    ├── reference/
    ├── roadmap/
    └── decisions/
```

现有源码目录原则上保持不变，以避免破坏 Cargo workspace、脚本路径和测试引用。主要治理对象是文档体系、数据边界、生成物和 GitHub 协作规则。

## 6. 正式文档体系

### 6.1 根文档

- `README.md`：项目定位、当前状态、系统流程、目录说明、快速开始、验证方式和文档入口；
- `AGENTS.md`：Agent 最小行为约束、权威文档顺序和测试要求；
- `CONTRIBUTING.md`：分支、提交、PR、测试和文档更新规范；
- `SECURITY.md`：未公开发现、私有数据和安全材料的处置规则。

### 6.2 `docs/` 分类

- `project/`：项目概览、范围、术语和当前状态；
- `architecture/`：系统、证据模型、编译器分析、ObjectFlow、Contracts、Schemas、ranking 和动态验证设计；
- `development/`：环境、目录、测试、VPS/本地流程、Agent 接力和版本发布；
- `experiments/`：方法、数据对齐、runbook 和已验证结果；
- `case-studies/`：与项目验证直接相关的历史 CVE 案例；
- `reference/`：CLI、事件格式、Schema、Contract 和错误分类参考；
- `roadmap/`：阶段路线、里程碑 gate 和当前工作；
- `decisions/`：长期有效且影响多个模块的架构决策记录。

文档正文使用简体中文；命令、代码、协议字段、Schema 字段和标识符保持英文原文。

### 6.3 历史材料处理

总体工程计划、动态验证方案、核心设计、Schema 说明、runbook 和已验证结果中的有效内容，应合并到正式文档体系。提取后不把以下原始材料复制到目标仓库：

- 逐任务执行计划；
- parallel-agent prompts；
- 临时 notes 和 handoff；
- `.superpowers/sdd/` 简报；
- 重复 roadmap、模板和扫描进度；
- 已被正式设计完整覆盖的旧规格。

其他任务的漏洞候选、CVE 提交材料、新手版重复文档、AutoCVE 和大型数据保持原位置，不复制到目标仓库。

## 7. 状态与证据语义

正式文档统一使用以下状态：

- `Implemented`：代码存在且相关测试通过；
- `Verified`：存在对应运行记录和证据；
- `Planned`：设计已批准但尚未实现；
- `Blocked`：存在明确阻塞条件；
- `Deprecated`：仍保留兼容但不再扩展。

不得将计划、文件名、PR 描述或 Agent 结论当作验证证据。能力状态应尽可能关联代码路径、测试路径、Schema/Contract 版本、验证 commit 和实验 `run_id`。

## 8. Agent 协作模型

新 Agent 的默认阅读顺序为：

```text
README.md
→ AGENTS.md
→ docs/README.md
→ docs/project/overview.md
→ docs/project/current-status.md
→ docs/architecture/system-overview.md
→ docs/roadmap/current-work.md
→ 对应组件文档
→ 对应 GitHub Issue
```

具体任务使用 GitHub Issue 管理，不新增长期 Agent prompt 文档。每个 Issue 必须给出目标、范围、非目标、依赖、涉及文件、接口、验收条件、测试命令、数据要求和文档要求。

并行任务应尽量避免修改相同文件。公共 Schema、Contract 和类型变更先合并，后续 compiler、graph/ranking、CLI 和 regression 任务再基于固定接口推进。

## 9. VPS 与本地验证流程

### 9.1 VPS

VPS 执行：

- 拉取公开仓库；
- 格式检查；
- workspace 编译和单元测试；
- compiler fixtures；
- 小型公开 corpus；
- CLI 端到端 smoke；
- 必要的容器构建测试；
- 推送分支或创建 PR。

### 9.2 本地工作站

本地执行：

- 拉取指定 Git commit；
- 校验 Rust 工具链、Schema、Contract、配置和数据 manifest；
- public regression；
- 大型 corpus；
- D1/D2；
- sealed holdout；
- 100-crate pilot；
- 性能和统计实验。

大规模验证仅在所有版本和哈希一致时启动。

## 10. 数据对齐协议

每次正式运行必须记录：

- `run_id`；
- `code_commit`；
- `code_dirty`；
- Rust 工具链标识；
- Schema 版本；
- Contract 快照 SHA-256；
- `dataset_id`；
- `dataset_version`；
- 数据集 SHA-256；
- 实验配置 SHA-256；
- 主机配置标识；
- 开始与结束时间；
- 运行状态。

正式运行要求 `code_dirty=false`。Git commit、工具链、Schema、Contract、数据集或实验配置任一不一致时，运行必须终止，不得依靠目录名或修改时间推断一致性。

## 11. CI 与质量门槛

Pull Request 至少检查：

- `cargo fmt --all --check`；
- workspace `cargo check --locked`；
- 相关 crate 测试；
- `bw-model` Schema/Contract 测试；
- `bw-cli` smoke test；
- `compiler/bw-rustc` 独立检查与测试；
- JSON、TOML 和 Schema 格式；
- Markdown 内部链接；
- 大文件、绝对路径、私有材料和构建产物。

不得通过跳过测试、放宽 validator 或降低证据语义来使 CI 通过。

## 12. 验收条件

整理完成必须同时满足：

1. 原始目录没有文件被删除、移动或覆盖；
2. 新仓库不继承旧 Git 历史；
3. README 描述所有一级目录和 workspace crate；
4. 正式文档结构完整且内部链接有效；
5. 不包含其他任务的漏洞候选或 CVE 提交材料；
6. 不包含 Agent prompt、Superpowers 中间文档和过程 notes；
7. 不包含构建产物、缓存和大型数据；
8. 当前状态准确反映 V3.2.x 实际能力；
9. `Implemented`、`Verified`、`Planned` 和 `Blocked` 不混用；
10. VPS 可以完成构建和小规模验证；
11. 本地可以通过 manifest 对齐后启动大规模验证；
12. 数据能够在本地和私人服务器之间完成完整性校验；
13. 规定的格式、编译、测试、Schema 和文档检查通过；
14. 新仓库工作树干净，并可从全新 clone 构建。
