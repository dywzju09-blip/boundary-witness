# Contract index

## Callback-retention Contract

[`contract.toml`](../../contracts/callback-retention/contract.toml) 使用 `bw.contract/0.1`，定义：

| clause | 语义 |
| --- | --- |
| `register-retains` | register 后 external owner 可以保留 callback |
| `unregister-releases` | unregister 释放当前 callback |
| `owner-drop-releases` | external owner 结束时释放 callback |
| `invoke-retained` | 被保留的 callback 可被后续调用 |
| `borrow-outlives-retention` | borrowed capture 必须覆盖完整 retention interval |
| `no-use-after-end` | 生命周期结束后禁止使用对象 |
| `free-once` | 同一 generation 最多 free 一次 |

通用 API roles 为 `api:register`、`api:unregister`、`api:invoke`。Contract 是解释规则；发生事实来自 compiler/runtime。

## API maps

所有 map 使用 `bw.api-map/0.1`，并指向 `contract:callback-retention`。

### [`rusqlite-api-map.toml`](../../contracts/callback-retention/rusqlite-api-map.toml)

| family | exact APIs | 角色 |
| --- | --- | --- |
| update hook | `Connection::update_hook` register/unregister | `Some(callback)` retain/replace；`None` release |
| commit hook | `Connection::commit_hook` register/unregister | callback + caller user_data retention/release |
| rollback hook | `Connection::rollback_hook` register/unregister | callback + caller user_data retention/release |
| scalar function | `Connection::create_scalar_function` | callback registration with user_data |
| explicit user data | `Connection::set_callback_with_user_data` | retained raw user-data pointer |
| callback trampoline | SQLite callback trampoline | invoke role |

### [`openssl-api-map.toml`](../../contracts/callback-retention/openssl-api-map.toml)

| family | exact APIs | 角色 |
| --- | --- | --- |
| SSL_CTX ex_data | `SSL_CTX_set_ex_data` / `SSL_CTX_get_ex_data` | opaque set/get on handle + slot |
| SSL ex_data | `SSL_set_ex_data` / `SSL_get_ex_data` | opaque set/get on handle + slot |

set identity 使用 `binding_api_id + handle_arg + key_arg + payload_arg`；get 使用同一 binding API、handle 与 key。相同 slot 不同 handle 不得合并。该 map 不覆盖 `select_next_proto` returned-borrow signature。

### [`diesel-api-map.toml`](../../contracts/callback-retention/diesel-api-map.toml)

`diesel::sqlite::connection::ffi::sqlite3_create_function_v2` 映射 register role；callback 参数为 5/6/7，user_data 为 4，destructor callback 属于释放证据的一部分。

### [`pyo3-api-map.toml`](../../contracts/callback-retention/pyo3-api-map.toml)

`pyo3_ffi::cpython::capsule::PyCapsule_New` 映射 register role；pointer 参数为 user_data，destructor 参数为 callback。

## Materialize 与 audit

`bw materialize-lifecycle-contracts` 将 base Contract 与一个或多个 API maps 转为 `v3.2.6.lifecycle_contract.1`。`bw audit-lifecycle-contracts` 检查 source/checksum/evidence/registry manifest。完整参数见 [CLI reference](cli.md)。

API map 必须满足 exact API ID 唯一、Contract 引用存在、callback/user-data index 合法；opaque set/get 还必须满足 family/binding API 一致和 generation-key 组件完整。map 文件存在或 audit 通过都不等于具体 candidate 已形成对象链。
