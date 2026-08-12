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

/// sqlite3_create_function_v2 形状：注册函数把形参落栈（store 到 alloca）再 load
/// 出来，把 **load 结果** 传给被调方，被调方 store 到全局槽位。load 结果的来源是
/// 形参（origin=Param），必须算 caller-owned，跨函数注入才能生效 → MayRetain。
/// 只查 `caller_owned` 集合（漏 origins）会把注入漏掉，Q1 空洞地判 NoRetain。
#[test]
fn spilled_load_arg_cross_function_store_to_global_is_may_retain() {
    let register_ir = r#"
define i32 @fixture_register(i32 (i8*)* noundef %0) {
  %2 = alloca i32 (i8*)*
  store i32 (i8*)* %0, i32 (i8*)** %2
  %3 = load i32 (i8*)*, i32 (i8*)** %2
  %4 = call i32 @store_wrapper(i32 (i8*)* %3)
  ret i32 %4
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
    println!("retention: {:?}", analysis.retention);
    assert_eq!(
        analysis.retention,
        ForeignRetention::MayRetain,
        "load 出的形参值传给被调方 store 到全局槽位：必须识别为保留"
    );
}


/// SQLite 形状：register 把 userdata / 回调存进「查找函数返回的堆对象」字段，
/// 查找函数内部把该对象经容器插入（HashInsert）挂进 caller-owned 可达容器
/// （db->aFunc 哈希表）→ 字段跨调用存活，MayRetain。
#[test]
fn store_to_heap_object_inserted_into_caller_container_is_may_retain() {
    let register_ir = r#"
%struct.sqlite3 = type { [80 x i8] }
%struct.FuncDef = type { i32, i32 (i8*)*, i8* }
define i32 @fixture_register(%struct.sqlite3* noundef %0, i32 (i8*)* noundef %1, i8* noundef %2) {
  %4 = call %struct.FuncDef* @fixture_find(%struct.sqlite3* noundef %0)
  %5 = getelementptr inbounds %struct.FuncDef, %struct.FuncDef* %4, i32 0, i32 2
  store i8* %2, i8** %5, align 8
  %6 = getelementptr inbounds %struct.FuncDef, %struct.FuncDef* %4, i32 0, i32 1
  store i32 (i8*)* %1, i32 (i8*)** %6, align 8
  ret i32 0
}
"#;
    let find_ir = r#"
%struct.sqlite3 = type { [80 x i8] }
%struct.FuncDef = type { i32, i32 (i8*)*, i8* }
%struct.Hash = type { i8* }
declare i8* @fixture_malloc(i64)
declare i8* @fixtureHashInsert(%struct.Hash*, i8*, i8*)
define %struct.FuncDef* @fixture_find(%struct.sqlite3* noundef %0) {
  %2 = alloca %struct.FuncDef*, align 8
  %3 = call i8* @fixture_malloc(i64 24)
  %4 = bitcast i8* %3 to %struct.FuncDef*
  store %struct.FuncDef* %4, %struct.FuncDef** %2, align 8
  %5 = load %struct.FuncDef*, %struct.FuncDef** %2, align 8
  %6 = getelementptr inbounds %struct.sqlite3, %struct.sqlite3* %0, i32 0, i32 75
  %7 = bitcast %struct.FuncDef* %5 to i8*
  %8 = call i8* @fixtureHashInsert(%struct.Hash* %6, i8* null, i8* %7)
  %9 = load %struct.FuncDef*, %struct.FuncDef** %2, align 8
  ret %struct.FuncDef* %9
}
"#;
    let main_module = IrModule::parse(register_ir).expect("register parses");
    let other = IrModule::parse(find_ir).expect("find parses");
    let roles = ForeignRoleMap {
        register_symbol: "fixture_register".to_owned(),
        callback_arg_index: 1,
        userdata_arg_index: Some(2),
        clear_symbol: None,
    };
    let analysis = analyze_with_modules(&main_module, &roles, &[other]);
    println!("retention: {:?}", analysis.retention);
    println!("slots: {:?}", analysis.slots);
    assert_eq!(
        analysis.retention,
        ForeignRetention::MayRetain,
        "插入 caller-owned 可达容器的堆对象字段必须被判为保留"
    );
    assert!(
        !analysis.slots.is_empty(),
        "该形状必须产出槽位证据（消除 missing_slot_evidence 的基础）"
    );
}

/// 负例：查找函数返回堆对象但**没有**容器插入（对象未挂进 caller-owned 可达容器）。
/// 不能证明跨调用存活 → 不得判 MayRetain；同时不得判 NoRetain（缺证不是否定）。
#[test]
fn heap_object_without_container_insert_is_not_may_retain() {
    let register_ir = r#"
%struct.sqlite3 = type { [80 x i8] }
%struct.FuncDef = type { i32, i32 (i8*)*, i8* }
define i32 @fixture_register(%struct.sqlite3* noundef %0, i32 (i8*)* noundef %1, i8* noundef %2) {
  %4 = call %struct.FuncDef* @fixture_new(%struct.sqlite3* noundef %0)
  %5 = getelementptr inbounds %struct.FuncDef, %struct.FuncDef* %4, i32 0, i32 2
  store i8* %2, i8** %5, align 8
  ret i32 0
}
"#;
    let find_ir = r#"
%struct.sqlite3 = type { [80 x i8] }
%struct.FuncDef = type { i32, i32 (i8*)*, i8* }
declare i8* @fixture_malloc(i64)
define %struct.FuncDef* @fixture_new(%struct.sqlite3* noundef %0) {
  %2 = alloca %struct.FuncDef*, align 8
  %3 = call i8* @fixture_malloc(i64 24)
  %4 = bitcast i8* %3 to %struct.FuncDef*
  store %struct.FuncDef* %4, %struct.FuncDef** %2, align 8
  %5 = load %struct.FuncDef*, %struct.FuncDef** %2, align 8
  ret %struct.FuncDef* %5
}
"#;
    let main_module = IrModule::parse(register_ir).expect("register parses");
    let other = IrModule::parse(find_ir).expect("find parses");
    let roles = ForeignRoleMap {
        register_symbol: "fixture_register".to_owned(),
        callback_arg_index: 1,
        userdata_arg_index: Some(2),
        clear_symbol: None,
    };
    let analysis = analyze_with_modules(&main_module, &roles, &[other]);
    println!("retention: {:?}", analysis.retention);
    assert_ne!(
        analysis.retention,
        ForeignRetention::MayRetain,
        "没有容器插入证明时不得判保留"
    );
    assert_ne!(
        analysis.retention,
        ForeignRetention::NoRetain,
        "缺证不是否定：不得判 NoRetain"
    );
}


/// collation 形状：查找函数内部用 HashFind 从 caller-owned 可达容器**读取**已有
/// 对象并返回（替换已有注册的路径）；register 把 userdata 存进返回对象的字段
/// → 字段跨调用存活，MayRetain。
#[test]
fn store_to_heap_object_read_from_caller_container_is_may_retain() {
    let register_ir = r#"
%struct.sqlite3 = type { [80 x i8] }
%struct.CollSeq = type { i32, i32 (i8*, i32, i8*, i32, i8*)*, i8* }
define i32 @fixture_register(%struct.sqlite3* noundef %0, i32 (i8*, i32, i8*, i32, i8*)* noundef %1, i8* noundef %2) {
  %4 = call %struct.CollSeq* @fixture_find(%struct.sqlite3* noundef %0)
  %5 = getelementptr inbounds %struct.CollSeq, %struct.CollSeq* %4, i32 0, i32 2
  store i8* %2, i8** %5, align 8
  %6 = getelementptr inbounds %struct.CollSeq, %struct.CollSeq* %4, i32 0, i32 1
  store i32 (i8*, i32, i8*, i32, i8*)* %1, i32 (i8*, i32, i8*, i32, i8*)** %6, align 8
  ret i32 0
}
"#;
    let find_ir = r#"
%struct.sqlite3 = type { [80 x i8] }
%struct.CollSeq = type { i32, i32 (i8*, i32, i8*, i32, i8*)*, i8* }
%struct.Hash = type { i8* }
declare i8* @fixtureHashFind(%struct.Hash*, i8*)
define %struct.CollSeq* @fixture_find(%struct.sqlite3* noundef %0) {
  %2 = alloca %struct.CollSeq*, align 8
  %3 = getelementptr inbounds %struct.sqlite3, %struct.sqlite3* %0, i32 0, i32 76
  %4 = call i8* @fixtureHashFind(%struct.Hash* %3, i8* null)
  %5 = bitcast i8* %4 to %struct.CollSeq*
  store %struct.CollSeq* %5, %struct.CollSeq** %2, align 8
  %6 = load %struct.CollSeq*, %struct.CollSeq** %2, align 8
  ret %struct.CollSeq* %6
}
"#;
    let main_module = IrModule::parse(register_ir).expect("register parses");
    let other = IrModule::parse(find_ir).expect("find parses");
    let roles = ForeignRoleMap {
        register_symbol: "fixture_register".to_owned(),
        callback_arg_index: 1,
        userdata_arg_index: Some(2),
        clear_symbol: None,
    };
    let analysis = analyze_with_modules(&main_module, &roles, &[other]);
    println!("retention: {:?}", analysis.retention);
    assert_eq!(
        analysis.retention,
        ForeignRetention::MayRetain,
        "从 caller-owned 可达容器读取的堆对象字段必须被判为保留"
    );
}
