# 实验方法

BoundaryWitness 的实验回答三个彼此独立的问题：分析链是否正确、搜索能否在不知道触发序列时产生 witness、冻结方法能否在未参与设计的数据上保持效果。任何一个问题的证据都不能替代另外两个。

## 实验分组

### 数据角色

| 组 | 用途 | 可否调整方法 | 可支持的结论 |
| --- | --- | --- | --- |
| 设计/校准集 | 建立 Schema、Contract、oracle 和最小对象链；rusqlite 属于此组 | 可以；每次调整都必须产生新 revision | 实现与诊断结论 |
| 公开回归集 | 冻结、已揭示的历史样本和安全对照 | 可以在运行后调整，但本次结果随即成为开发回归 | 对该 revision 的回归结论 |
| sealed holdout | curator 独占标签，scanner 只见匿名公开输入 | reveal 前禁止因样本调整方法 | 冻结方法的一次性泛化证据 |
| prospective 集 | 冻结方法后扫描、此前未知的对象 | finding 必须另行验证 | 候选发现与确认记录；不自动证明影响或可利用性 |

一个样本一旦 reveal，就只能进入设计/公开回归集，不能重新计为 holdout。相同根因家族的多个 API 或编号在统计中按一个独立根因处理。

### 动态阶段

| 阶段 | 输入 | 目的 | 不证明什么 |
| --- | --- | --- | --- |
| D0 确定性回放 | 已知触发链与同源正负对照 | 验证 static fact、runtime、Contract、oracle、sanitizer 和归档闭环 | 主动搜索能力 |
| D1 结构化搜索 | 安全 fragment 与 API action grammar | 在不输入完整触发链的条件下搜索、最小化并重放 witness | 任意程序泛化 |
| D2 对照搜索 | `random_action`、`coverage_only`、`coverage_state` | 比较普通搜索与 contract-state feedback | 小样本运行不能证明统计优势 |

D0/D1/D2 是执行方式，设计集/回归集/holdout/prospective 是数据角色；两条轴必须分别记录。

## Ground truth 隔离

1. scanner、runner、adapter、oracle 和排序器不得读取漏洞编号、样本角色、预期结果、修复说明或 curator 注释。
2. runner 输入只使用匿名 `case_id`、构建信息、API/Contract 输入和允许公开的 source artifact。
3. ground truth 由 curator 保管；只有 scanner freeze、ranked artifact hash、run 完整性和 receipt 校验成功后才能 reveal。
4. reveal 生成的公开摘要只保留聚合指标、匿名失败类和 hash；身份映射与逐样本答案不进入公开仓库。
5. D1 seed 不得包含 `register borrowed -> owner end -> later trigger` 的完整危险顺序；公开 PoC 只可用于 D0。
6. 文件名、路径、candidate ID、分数和自然语言说明都不是 ground truth。oracle 只消费版本化事实、Contract 和 runtime event。

## 成功等级

成功等级描述“本次运行实际证明到哪里”，不得由历史 advisory 自动升级。

| 等级 | 要求 |
| --- | --- |
| L0 配置通过 | 输入可解析，Schema、Contract 和预算检查通过 |
| L1 类型/构建差分 | 同源程序在历史版本与修复版本之间出现预期编译或类型差分 |
| L2 状态差分 | 自动事实与通用 oracle 能产生可审计 finding，负对照不产生同类 finding |
| L3 动态影响 | sanitizer、allocator、Miri（适用时）或稳定 native signal 支撑内存影响 |
| L4 搜索 witness | D1/D2 从允许的 seed 自动得到最小化 artifact，独立 replay 达到预注册门槛 |
| L5 冻结泛化 | freeze 后的一次性 holdout reveal 通过全部预注册 gate |

一次 crash 不足以证明根因；没有 crash 也不证明安全。L2 finding、L3 动态影响与 L4 搜索成功必须分列。

## 证据等级

来源证据与本次运行证据分开记录：

- `S0`：二手描述；
- `S1`：公开 advisory 已核实；
- `S2`：原始 issue、修复 revision 或源码差分已核实；
- `R0`：当前 revision 未运行；
- `R1`：输入、构建和完整性检查通过；
- `R2`：观察到预期类型、状态或负对照差分；
- `R3`：动态工具明确报告内存影响；
- `R4`：正负对照与重复统计达到预注册门槛；
- `R5`：第三方可从绑定的 artifacts 独立重放。

`Implemented` 只表示实现和测试存在；`Verified` 还要求与当前 `code_commit`、配置、数据、Contract、Schema 和 run checksum 对齐的正式记录。状态词的统一含义见 [项目术语](../project/terminology.md)。

## 对照组

最小 callback-lifetime 矩阵包括：borrowed callback 正例、owned/move capture、owner 结束前 unregister、注册但不触发、修复版本 compile rejection、修复版本可运行负对照、malformed action rejection。OpenSSL returned-borrow 案例还需要短生命周期 source、修复签名拒绝和不发生失效后读取的对照。

D2 三组必须使用相同 campaign 数、seed list、允许的初始 corpus、最大序列长度、目标构建和机器。当前实现只强制部分共享字段，详见 [D2 runbook](runbooks/d2.md)；未被运行记录证明的等价条件必须标为未验证。

## 统计边界

- 正式 D1 预注册口径为 `30 campaigns × 30 CPU-minutes`，timeout 进入分母；报告 success rate、time-to-first（含删失）、中位数/IQR、valid-sequence ratio、最小 witness 长度与 replay 成功率。
- D2 小规模 5-campaign 结果只用于管线验收。要声明方法优势，必须统一真实 CPU-time 预算、扩大独立 campaign、预注册统计检验，并报告 effect size 与不确定区间。
- build failure、timeout、tool error、unsupported pattern、deferred 和 insufficient evidence 不能计为安全，也不能默认为方法阴性。
- 排名命中、candidate、static risk 和 `adapter_needed` 都不是漏洞结论。
- 同一根因家族不得按 API 数量重复计数；调参后重跑的同一公开数据不得当作独立 holdout。

## 归档最低要求

正式结论必须满足 [数据对齐规范](data-alignment.md)，保留 manifest、逐项 records、stdout/stderr、输出 Schema 版本、checksums、失败记录和清理状态。结果索引见 [历史结果](results/README.md)。
