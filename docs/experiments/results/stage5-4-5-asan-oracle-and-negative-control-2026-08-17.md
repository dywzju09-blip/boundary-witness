# 5.4 独立 oracle 组件化 + 5.5 rusqlite 0.26.2 负对照（新生成器重跑）

- 日期：2026-08-17
- 范围：`bw run-witness-oracle`（阶段 5.4）+ rusqlite vulnerable/fixed 对照矩阵
  （阶段 5.5，在 5.3 生成器重写后用新生成器 + 新 oracle 重跑）
- 状态：**oracle 组件化完成；对照矩阵五格全部按预期判定**

## 1. 5.4：独立 oracle 组件（`bw run-witness-oracle`）

之前每个候选的 ASan 验证都是**手写脚本**（cd harness → cargo build → xvfb-run →
grep ASan → 人工看退出码），每次候选验证重复且不可复现。本阶段做成 bw-cli
正式命令，统一「构建 + 运行 + 裁决 + 证据落盘」：

- **输入**：`--harness-dir`（生成物目录）、`--run-id`、`--timeout-seconds`、
  `--asan-options`（缺省 `detect_leaks=0`）、`--env KEY=VALUE`（可重复，
  CFLTK_BUNDLE_DIR 等）、`--run-command`（xvfb-run -a 等前缀）、
  `--toolchain`、`--expect`（变异校验）。
- **流程**：cargo build（ASan profile 来自生成物 Cargo.toml，oracle 不注入）→
  `timeout <sec> [prefix] <binary>` 运行 → 解析 ASan 输出 → 写证据
  （`oracle-logs/<run-id>.log` + `.json`，含 outcome/退出码/ASan 计数/SUMMARY/
  log sha256/harness 路径/耗时）。
- **裁决五态**（不引入本项目 runtime 结论）：
  | outcome | 判定输入 |
  | --- | --- |
  | `triggered` | ASan 错误 > 0 且退出非 0 |
  | `clean` | 无 ASan 错误且退出 0 |
  | `build_failed` | cargo build 失败（负对照 fixed 版） |
  | `timeout` | 运行超时（无 ASan 错误） |
  | `runtime_error` | 非 0 退出且无 ASan |
- **`--expect`**：实测不符 → 非 0 退出 + `BW-ORACLE-EXPECT`（变异校验/CI 断言
  判据与生成器的判别力）。build 失败时错误提取**优先显示 error 行**
  （`error[E..]`），避免 cargo warning 长块掩盖 E0425 等关键证据。
- 单测 4 个：ASan 解析、五态映射、expect 匹配、包名解析。

## 2. 5.5：rusqlite vulnerable/fixed 对照矩阵（新生成器重跑）

数据流（与旧 5.5 一致，但全部换用 5.3 重写后的生成器 + 新 oracle）：

| 变体 | 契约判定 | 生成器 invalidate | oracle 实测 | 证据 |
| --- | --- | --- | --- | --- |
| **vulnerable 0.26.1** | `permits_non_static_capture` + `owner_holds_callback_bridged`（multiple_static_sites） | **generated** | **triggered**（exit=1，ASan 1 处，`heap-use-after-free`） | `stage5-5-0261-harness-new/oracle-logs/` |
| **fixed 0.26.2** | `requires_static_capture` | **refused**（类型层排除借用捕获） | **build_failed**（`E0425: cannot find value 'witness_referent'`——编译期拒绝） | `stage5-5-0262-harness-new/oracle-logs/` |
| owned callback（0.26.1） | — | — | **clean**（exit=0，ASan 0） | `stage5-5-0261-var-owned/` |
| unregister-before-drop（0.26.1） | — | — | **clean**（exit=0，ASan 0） | `stage5-5-0261-var-unregister/` |
| no-trigger（0.26.1） | — | — | **clean**（exit=0，ASan 0） | `stage5-5-0261-var-notrigger/` |

要点：
- 0.26.1 契约由**全新 extract-static-facts**（2562 条事实，当前 bw-rustc）装配，
  不再依赖 5.0 的旧 facts（旧 facts 缺 lineage 数据，extract 全 gapped）；
- 0.26.1 `update_hook` 的 `registration_generation = multiple_static_sites`
  （`Connection::update_hook` 与 `InnerConnection::update_hook` 两个静态位点，
  与执行计划预判一致）——判定仍 Generated（bridged 允许无符号装配）；
- 0.26.2 生成物 build_failed 的根因被 oracle 的 error 行提取**精确呈现**
  （E0425），不再是模糊的 warning tail；
- 全部五个 oracle 运行都带 `--expect` 且匹配——变异校验通过（如果判据或
  生成器失去判别力，expect 会转红）。

## 3. 证明了什么 / 没证明什么

**证明了**：

- **ASan 已正式化为独立 oracle 组件**：`bw run-witness-oracle` 一个命令完成
  「构建 → 运行 → 裁决 → 证据落盘 → 变异校验」，结果含 hash 与完整日志，
  可复现、可断言（`--expect`）；
- **判定 → 生成 → oracle 三层的判别力闭环**：同一 adapter、同一生成器，
  vulnerable 版（0.26.1）产出可出证 harness（triggered），fixed 版（0.26.2）
  产出编译期拒绝（build_failed + E0425）——「判定说不能分离 → 不生成 invalidate
  → 程序编不过」在真实库上实证；
- 三个安全变体（owned / unregister / no-trigger）全部 clean：UAF 不是剧本自带
  （没有 referent 捕获、注销后、不触发时都不崩），对照矩阵五格互相印证；
- 0.26.1 重新分析后契约完整（40 assembled / 112 hand_offs），修复了 5.0 旧
  facts 的 lineage 缺口。

**没证明**：

- **oracle 不是漏洞分类器**：`triggered` 只证明「ASan 观察到该时序下的内存
  错误」，不证明「该 crate 对任意安全客户端都 UAF」——外部侧（LLVM IR）的
  晚调可达性仍未独立证明（joint verdict 仍是 rust-only）；
- **build_failed 的语义**：0.26.2 编不过是「编译期拒绝」的证据，但 oracle 不
  区分 E0425（referent 未定义）与 feature 冲突等其他编译错误——本次靠 error
  行提取人工确认根因是 E0425，oracle 本身不做根因分类；
- **oracle 未做跨候选泛化测试**：本次只跑 rusqlite 家族；fltk（GUI 前缀）、
  sqlite-vfs（额外依赖 env）等不同形状未在 oracle 命令下全量重跑（此前
  harness 验证是手动脚本，未迁移到 oracle）；
- 变异校验只覆盖「expect 匹配」这一层——「把判据改坏 → oracle 转红」的完整
  变异流程未在本阶段重跑（5.3 已做过生成器层变异，5.4 oracle 的 expect 机制
  是其运行时化）。
