# Security Policy

BoundaryWitness 处理安全研究材料时区分公开工程内容和未披露材料。公开仓库不保存未披露候选、CVE 提交材料、sealed holdout 私有数据、逐样本 ground truth、私有 run artifact 或服务器路径。

## 未披露候选

未披露候选应在独立安全任务和私有渠道中处理。不要在公开 Issue、PR、commit message、文档、fixtures 或测试名称中复制候选名称、PoC、受影响版本、私有样本身份或维护者沟通内容。

公开仓库可以保存通用 detector 代码、Schema、Contract、sanitized fixtures、公开历史结果和方法边界；不能把这些材料写成对未公开目标的确认结论。

## 报告渠道

若需要报告真实安全问题，请使用项目维护者指定的私有渠道或上游项目安全渠道。公开讨论只保留不泄漏目标身份的工程性问题，例如 validator bug、证据层误读、数据治理规则或通用测试缺口。

## 证据边界

candidate、ranking、static risk chain、dynamic witness、oracle finding、维护者确认和已发布 advisory 是不同状态。公开材料必须保留这种区分，不把候选排序直接写成漏洞确认。

## 数据边界

sealed holdout 的数据清单、身份映射、ground truth、逐样本 match detail 和 reveal 结果不进入公开仓库。大型 corpus 和 private results 存放在 Git 外 artifact catalog；公开文档只引用逻辑 artifact ID、run ID、dataset ID 和不可逆 hash。
