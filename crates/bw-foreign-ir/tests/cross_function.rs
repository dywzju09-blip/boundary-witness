//! 跨函数透传追踪与 select 透传的单元测试（阶段 7 扩展）。

use bw_foreign_ir::{ForeignRoleMap, IrModule, analyze_with_modules};
use bw_model::ForeignRetention;

/// 注册函数把回调经 select（null 时用默认回调）转给包装函数，包装函数只透传，
/// 不 store 到任何跨调用存储——Q1 应判 NoRetain。
#[test]
fn select_and_cross_function_passthrough_is_no_retain() {
    let register_ir = r#"
define i32 @fixture_register(i32 (i8*)* noundef %0, i8* noundef %1) {
  %3 = icmp eq i32 (i8*)* %0, null
  %4 = select i1 %3, i32 (i8*)* @default_cb, i32 (i8*)* %0
  %5 = call i32 @wrapper(i32 (i8*)* %4, i8* %1)
  ret i32 %5
}
declare i32 (i8*)* @default_cb()
"#;
    let wrapper_ir = r#"
define i32 @wrapper(i32 (i8*)* noundef %0, i8* noundef %1) {
  %3 = call i32 @consume(i32 (i8*)* %0, i8* %1)
  ret i32 %3
}
declare i32 @consume(i32 (i8*)*, i8*)
"#;
    let main_module = IrModule::parse(register_ir).expect("register parses");
    let other = IrModule::parse(wrapper_ir).expect("wrapper parses");
    let roles = ForeignRoleMap {
        register_symbol: "fixture_register".to_owned(),
        callback_arg_index: 0,
        userdata_arg_index: Some(1),
        clear_symbol: None,
    };
    let analysis = analyze_with_modules(&main_module, &roles, &[other]);
    // consume 是外部声明（不可解析），跨函数透传链在 consume 处断——仍应缺证，
    // 不误判 NoRetain（consume 可能保存）。
    assert_eq!(analysis.retention, ForeignRetention::Unresolved);
}

/// 跨函数透传链在可解析函数内 store 到全局槽位——Q1 应判 MayRetain。
#[test]
fn cross_function_store_to_global_is_may_retain() {
    let register_ir = r#"
@slot = global i32 (i8*)* null
define i32 @fixture_register(i32 (i8*)* noundef %0, i8* noundef %1) {
  %3 = call i32 @store_wrapper(i32 (i8*)* %0)
  ret i32 %3
}
"#;
    let wrapper_ir = r#"
@slot = global i32 (i8*)* null
define i32 @store_wrapper(i32 (i8*)* noundef %0) {
  store i32 (i8*)* %0, i32 (i8*)** @slot
  ret i32 0
}
"#;
    let main_module = IrModule::parse(register_ir).expect("register parses");
    let other = IrModule::parse(wrapper_ir).expect("wrapper parses");
    let roles = ForeignRoleMap {
        register_symbol: "fixture_register".to_owned(),
        callback_arg_index: 0,
        userdata_arg_index: None,
        clear_symbol: None,
    };
    let analysis = analyze_with_modules(&main_module, &roles, &[other]);
    assert_eq!(
        analysis.retention,
        ForeignRetention::MayRetain,
        "跨函数 store 到全局槽位必须被识别为保留"
    );
}

/// 被调方把回调存进「全局持有的结构体字段」（GEP+bitcast+store）——应 MayRetain。
#[test]
fn store_to_global_field_chain_is_may_retain() {
    let register_ir = r#"
@g_holder = global %struct.holder zeroinitializer
define i32 @fixture_register(i32 (i8*)* noundef %0, i8* noundef %1) {
  %3 = call i32 @store_wrapper(i32 (i8*)* %0, %struct.holder* @g_holder)
  ret i32 %3
}
"#;
    let wrapper_ir = r#"
%struct.holder = type { i32 (i8*)* }
define i32 @store_wrapper(i32 (i8*)* noundef %0, %struct.holder* noundef %1) {
  %3 = getelementptr inbounds %struct.holder, %struct.holder* %1, i64 0, i32 0
  %4 = bitcast i32 (i8*)** %3 to i32 (i8*)**
  store i32 (i8*)* %0, i32 (i8*)** %4, align 8
  ret i32 0
}
"#;
    let main_module = IrModule::parse(register_ir).expect("register parses");
    let other = IrModule::parse(wrapper_ir).expect("wrapper parses");
    let roles = ForeignRoleMap {
        register_symbol: "fixture_register".to_owned(),
        callback_arg_index: 0,
        userdata_arg_index: None,
        clear_symbol: None,
    };
    let analysis = analyze_with_modules(&main_module, &roles, &[other]);
    println!("retention: {:?}", analysis.retention);
    assert_eq!(analysis.retention, ForeignRetention::MayRetain);
}

/// openssl 场景：被调方把回调存进「调用方 alloca 结构体的字段」——不构成跨调用
/// 保留（alloca 随函数返回死亡），应 Unresolved（缺证）而非 MayRetain 误报。
#[test]
fn store_to_caller_alloca_field_is_not_may_retain() {
    let register_ir = r#"
define i32 @fixture_register(i32 (i8*)* noundef %0, i8* noundef %1) {
  %2 = alloca %struct.holder
  %3 = call i32 @store_wrapper(i32 (i8*)* %0, %struct.holder* %2)
  ret i32 %3
}
"#;
    let wrapper_ir = r#"
%struct.holder = type { i32 (i8*)* }
define i32 @store_wrapper(i32 (i8*)* noundef %0, %struct.holder* noundef %1) {
  %3 = getelementptr inbounds %struct.holder, %struct.holder* %1, i64 0, i32 0
  %4 = bitcast i32 (i8*)** %3 to i32 (i8*)**
  store i32 (i8*)* %0, i32 (i8*)** %4, align 8
  ret i32 0
}
"#;
    let main_module = IrModule::parse(register_ir).expect("register parses");
    let other = IrModule::parse(wrapper_ir).expect("wrapper parses");
    let roles = ForeignRoleMap {
        register_symbol: "fixture_register".to_owned(),
        callback_arg_index: 0,
        userdata_arg_index: None,
        clear_symbol: None,
    };
    let analysis = analyze_with_modules(&main_module, &roles, &[other]);
    println!("retention: {:?}", analysis.retention);
    assert_eq!(analysis.retention, ForeignRetention::Unresolved);
}

/// sqlite3CreateFunc 形状：回调值流经 **phi 节点**（判空后二选一）再 store 到全局
/// 槽位——phi 的结果必须继承入边来源，Q1 才能看到这次 store。
#[test]
fn phi_then_store_to_global_is_may_retain() {
    let register_ir = r#"
@slot = global i32 (i8*)* null
define i32 @fixture_register(i32 (i8*)* noundef %0) {
entry:
  %cond = icmp eq i32 (i8*)* %0, null
  br i1 %cond, label %if.null, label %if.set
if.null:
  br label %merge
if.set:
  br label %merge
merge:
  %1 = phi i32 (i8*)* [ %0, %if.set ], [ null, %if.null ]
  store i32 (i8*)* %1, i32 (i8*)** @slot
  ret i32 0
}
"#;
    let main_module = IrModule::parse(register_ir).expect("register parses");
    let roles = ForeignRoleMap {
        register_symbol: "fixture_register".to_owned(),
        callback_arg_index: 0,
        userdata_arg_index: None,
        clear_symbol: None,
    };
    let analysis = analyze_with_modules(&main_module, &roles, &[]);
    println!("retention: {:?}", analysis.retention);
    assert_eq!(
        analysis.retention,
        ForeignRetention::MayRetain,
        "phi 透传后 store 到全局槽位必须被识别为保留"
    );
}

/// sqlite3CreateFunc 形状（堆对象字段）：回调经 phi 透传后 store 进「非调用方持有
/// 基址」的结构体字段——不得判 NoRetain（SQLite 确实保留），只能缺证 Unresolved。
#[test]
fn phi_then_store_to_unproven_field_is_not_no_retain() {
    let register_ir = r#"
define i32 @fixture_register(i32 (i8*)* noundef %0) {
entry:
  %cond = icmp eq i32 (i8*)* %0, null
  br i1 %cond, label %if.null, label %if.set
if.null:
  br label %merge
if.set:
  br label %merge
merge:
  %1 = phi i32 (i8*)* [ %0, %if.set ], [ null, %if.null ]
  %2 = call %struct.funcdef* @malloc_like()
  %3 = getelementptr inbounds %struct.funcdef, %struct.funcdef* %2, i32 0, i32 3
  store i32 (i8*)* %1, i32 (i8*)** %3
  ret i32 0
}
declare %struct.funcdef* @malloc_like()
"#;
    let main_module = IrModule::parse(register_ir).expect("register parses");
    let roles = ForeignRoleMap {
        register_symbol: "fixture_register".to_owned(),
        callback_arg_index: 0,
        userdata_arg_index: None,
        clear_symbol: None,
    };
    let analysis = analyze_with_modules(&main_module, &roles, &[]);
    println!("retention: {:?}", analysis.retention);
    println!("boundaries: {:#?}", analysis.boundaries);
    assert_eq!(
        analysis.retention,
        ForeignRetention::Unresolved,
        "store 进非调用方持有的堆对象字段：缺证，不得判 NoRetain"
    );
}
