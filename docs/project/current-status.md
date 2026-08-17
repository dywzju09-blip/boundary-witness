# 当前状态

**阶段锚点：5.x 主线完成（0–4、5.0、5.2、5.3、5.4、5.5）。下一步：大规模 0day 探针。**

本文只陈述当前工作树中可以由代码、测试和运行记录支撑的状态。方向权威见
[research thesis](research-thesis.md)；能力边界见
[scope and boundaries](scope-and-boundaries.md)；执行顺序见
[execution plan](../roadmap/execution-plan.md)（含当前位置）。

## 相对研究主线的位置

| 创新点 | 状态 | 缺什么 |
| --- | --- | --- |
| C1 safe-only 可执行反证合成 | `Implemented`（机制） | 生成器重写（5.3）+ ASan 独立 oracle（5.4）完成；生成物 `#![forbid(unsafe_code)]`、四槽声明式、开箱 ASan profile。论文级规模评估未做 |
| C2 类型契约 × 外部 effect 的精化检查 | `Implemented`（机制） | Rust 侧三契约事实 + 外部侧 Q1/Q3 指令级证据 + 5.2 source-to-verdict + 5.5 对照矩阵 5/5（vulnerable triggered / fixed 编译期拒绝 / 三安全变体干净）。**Q4′ 在真实库上无结论**（入口校验提前返回，缺证） |
| C3 生态级度量与新发现 | `Planned` | 猎物存在性未测量；判定→生成→oracle 三层已就绪，0day 探针是下一步 |

## 状态总览（当前主线）

| 状态 | 能力或事项 | 结论 |
| --- | --- | --- |
| `Implemented` | 判定层（PC/PG-1/PG-2/lineage/装配） | `bw extract-rust-contracts` 自动产出契约事实，缺证带机器可读原因 |
| `Implemented` | 外部侧 Q1/Q3/降级 Q4′（阶段 3） | 真实构建 IR 指令级证据；Q4′ 真实库无结论（缺证，非否定） |
| `Implemented` | 联结与三态判定（阶段 4） | `bw judge-hand-offs`；缺证≠证伪纪律贯穿 |
| `Implemented` | 符号解析（5.0） | rusqlite 跨界交出点 6/6 |
| `Implemented` | witness 生成器重写（5.3） | rusqlite 特化模板清零；trait 回调走 adapter `trait_impl`（缺失报错）；生成物带 ASan profile；`extra_dependencies` 通用化 |
| `Implemented` | ASan 独立 oracle（5.4） | `bw run-witness-oracle`：构建→运行→五态裁决→证据落盘→`--expect` 变异校验 |
| `Implemented` | rusqlite 0.26.2 负对照（5.5） | 对照矩阵 5/5：0.26.1 triggered（heap-UAF）、0.26.2 build_failed（E0425 编译期拒绝）、owned/unregister/no-trigger 全 clean |
| `Implemented` | 候选验证 | 高置信 6 候选：**5 ASan 出证**（tree-sitter/sqlite-vfs/ffmpeg/fltk×2）+ git2×2/libsql/mosq/fluidlite 早期出证；**fluidsynth 触发缺证**（safe API 下 router 不可达，非证伪） |
| `Planned` | 大规模 0day 探针 | 三层流水线就绪，规模从小到大，先验证有效性；披露判断必须询问用户 |
| `Planned` | 阶段 6–9（论文级验收、holdout） | 后置，见 execution-plan |

## 纪律（违反即返工）

1. 缺证 ≠ 否定结论（枚举命名中性，如 `NoForeignCallWithinSearchDepth`）。
2. 测试绿 ≠ 有效：改判据后必须变异检查（改坏一处 → 断言转红 → 改回）。
3. 身份纪律：函数名/API 名/源码位置只做诊断，不做 join key；歧义一律
   `Unresolved`；两侧半键身份只由 `join_hand_off` 合成。
4. 禁止删测试/跳过测试/放宽 validator/给判定加第四态（StaticVerdict 只有三态）。
5. 提交前跑 `python3 tools/repository/check_public_tree.py`；不提交大型数据、
   run artifacts、target、日志、凭证、绝对本地路径、未披露候选、holdout 身份、
   ground truth。
6. 每次改完判据做变异检查；缺证路径不许把缺证写成结论。

## 已知未解决问题（不重复发现）

- Q4′ 真实库无结论（入口参数校验提前返回 → 缺证），独立于 5.x 范围；
- Q3 降级实现（只找同槽间接调用点，不证明晚调可达）；
- rust_def_instance 不是单态化实例 id；
- registration_key 恒为 None；
- 搜索上界 3 跳只在 rusqlite 验证过，不随手调大；
- fluidsynth 类候选（触发需 unsafe C 调用）在 forbid(unsafe_code) harness 下
  触发不可达 → 缺证（非证伪）；
- harness 生成器的 setup 片段是 adapter 作者责任（如 `Command::spawn()?`）。
