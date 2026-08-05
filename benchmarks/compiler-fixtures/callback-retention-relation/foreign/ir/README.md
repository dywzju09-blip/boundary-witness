# 四个 matched fixture 的 LLVM IR

本目录是同级 C stub 由 clang 直接产出的文本 IR，**未经任何改写**。它是
`crates/bw-foreign-ir` 的验收输入（执行计划阶段 3）。

## 为什么把产物签进仓库

阶段 3 的分析读的是 IR，不是 C 源码。让测试在运行时现编，会带来两个问题：

- **CI 里不一定有 clang**，Gate R 的核心断言就成了有条件执行的；
- **换一个 clang 版本，文本 IR 的形状会变**。测试会随环境飘，飘了还不容易看出来。

因此把 IR 与 clang 版本一起钉死。规模是 4 个文件约 415 行，其中一半是 DWARF 元数据。

## 重新生成

```bash
cd benchmarks/compiler-fixtures/callback-retention-relation/foreign
for f in *.c; do
  clang -O0 -g -fdebug-compilation-dir=. -emit-llvm -S "$f" -o "ir/${f%.c}.ll"
done
```

按 [VPS 与本地工作流](../../../../../docs/development/vps-local-workflow.md)，编译在远端执行。

| 项 | 值 |
| --- | --- |
| 编译器 | Ubuntu clang 14.0.0-1ubuntu1.1 |
| 优化级别 | `-O0` |
| 调试信息 | `-g` |

## 这几个编译选项是有意选的

**`-O0 -g` 是 cargo dev profile 下 `cc` crate 的默认**，也就是阶段 2 的
`tools/foreign-ir/cc-capture` 从真实构建里捕获到的那个形状。分析必须针对真实捕获到的
IR，不能针对一份更好读的 IR。

这个形状对分析是有利的：形参先 `store` 进 `alloca`、用时再 `load`，数据流是显式的，
没有 mem2reg / SROA / 内联把它揉碎。`crates/bw-foreign-ir/src/dataflow.rs` 正是按这个
前提写的。

**换 profile 前提就不成立。** `-O2` 下 alloca 被消掉、函数被内联，需要的是另一套分析。
分析用的 profile 必须与捕获时一致，这一点由阶段 2 的 manifest 记录。

`-fdebug-compilation-dir=.` 只为了让调试信息里不出现绝对构建路径——否则本地路径会跟着
产物进仓库。

## 每个文件对应的预期

见同级 `README.md` 的对应表。断言写在
`crates/bw-foreign-ir/tests/matched_fixtures.rs`，其中
`q4_prime_separates_the_clearing_stub_from_the_leaky_one` 是 Gate R 的核心：
`retain_late_invoke_clearing.ll` 与 `retain_late_invoke_leaky.ll` 的 Rust 侧完全相同，
差别只在 `fixture_unregister` 少清了两个槽位。
