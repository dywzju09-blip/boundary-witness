# 案例研究

案例文档把公开历史事实与 BoundaryWitness 当前可观察事实分开。历史 advisory、修复差分和预期触发链属于 ground truth；scanner/oracle 只能使用版本化 static facts、Contract 和 runtime events。

- [rusqlite callback lifecycle](rusqlite-callback-lifecycle.md)：retained borrowed callback 设计家族，具有 D0/D1 benchmark 与历史 blind gate。
- [OpenSSL lifetime](openssl-lifetime.md)：历史 returned-borrow lifetime 错配；当前仓库另有 OpenSSL ex_data opaque-handle/free-callback 静态覆盖，两者不可混为一个漏洞结论。

证据术语与成功等级见 [实验方法](../experiments/methodology.md)。
