; ModuleID = 'retain_late_invoke_leaky.c'
source_filename = "retain_late_invoke_leaky.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@g_callback = internal global void (i8*)* null, align 8, !dbg !0
@g_user_data = internal global i8* null, align 8, !dbg !7
@g_cached_callback = internal global void (i8*)* null, align 8, !dbg !9
@g_cached_user_data = internal global i8* null, align 8, !dbg !15

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @fixture_register(void (i8*)* noundef %0, i8* noundef %1) #0 !dbg !25 {
  %3 = alloca void (i8*)*, align 8
  %4 = alloca i8*, align 8
  store void (i8*)* %0, void (i8*)** %3, align 8
  call void @llvm.dbg.declare(metadata void (i8*)** %3, metadata !29, metadata !DIExpression()), !dbg !30
  store i8* %1, i8** %4, align 8
  call void @llvm.dbg.declare(metadata i8** %4, metadata !31, metadata !DIExpression()), !dbg !32
  %5 = load void (i8*)*, void (i8*)** %3, align 8, !dbg !33
  store void (i8*)* %5, void (i8*)** @g_callback, align 8, !dbg !34
  %6 = load i8*, i8** %4, align 8, !dbg !35
  store i8* %6, i8** @g_user_data, align 8, !dbg !36
  %7 = load void (i8*)*, void (i8*)** %3, align 8, !dbg !37
  store void (i8*)* %7, void (i8*)** @g_cached_callback, align 8, !dbg !38
  %8 = load i8*, i8** %4, align 8, !dbg !39
  store i8* %8, i8** @g_cached_user_data, align 8, !dbg !40
  ret void, !dbg !41
}

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @fixture_unregister() #0 !dbg !42 {
  store void (i8*)* null, void (i8*)** @g_callback, align 8, !dbg !45
  store i8* null, i8** @g_user_data, align 8, !dbg !46
  ret void, !dbg !47
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @fixture_fire() #0 !dbg !48 {
  %1 = load void (i8*)*, void (i8*)** @g_callback, align 8, !dbg !49
  %2 = icmp ne void (i8*)* %1, null, !dbg !49
  br i1 %2, label %3, label %6, !dbg !51

3:                                                ; preds = %0
  %4 = load void (i8*)*, void (i8*)** @g_callback, align 8, !dbg !52
  %5 = load i8*, i8** @g_user_data, align 8, !dbg !54
  call void %4(i8* noundef %5), !dbg !52
  br label %13, !dbg !55

6:                                                ; preds = %0
  %7 = load void (i8*)*, void (i8*)** @g_cached_callback, align 8, !dbg !56
  %8 = icmp ne void (i8*)* %7, null, !dbg !56
  br i1 %8, label %9, label %12, !dbg !58

9:                                                ; preds = %6
  %10 = load void (i8*)*, void (i8*)** @g_cached_callback, align 8, !dbg !59
  %11 = load i8*, i8** @g_cached_user_data, align 8, !dbg !61
  call void %10(i8* noundef %11), !dbg !59
  br label %12, !dbg !62

12:                                               ; preds = %9, %6
  br label %13

13:                                               ; preds = %12, %3
  ret void, !dbg !63
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nofree nosync nounwind readnone speculatable willreturn }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!17, !18, !19, !20, !21, !22, !23}
!llvm.ident = !{!24}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "g_callback", scope: !2, file: !3, line: 21, type: !11, isLocal: true, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "Ubuntu clang version 14.0.0-1ubuntu1.1", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, retainedTypes: !4, globals: !6, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "retain_late_invoke_leaky.c", directory: ".", checksumkind: CSK_MD5, checksum: "a13831117c6999ac4591a4c86940046f")
!4 = !{!5}
!5 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!6 = !{!0, !7, !9, !15}
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "g_user_data", scope: !2, file: !3, line: 22, type: !5, isLocal: true, isDefinition: true)
!9 = !DIGlobalVariableExpression(var: !10, expr: !DIExpression())
!10 = distinct !DIGlobalVariable(name: "g_cached_callback", scope: !2, file: !3, line: 25, type: !11, isLocal: true, isDefinition: true)
!11 = !DIDerivedType(tag: DW_TAG_typedef, name: "fixture_callback", file: !3, line: 19, baseType: !12)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !13, size: 64)
!13 = !DISubroutineType(types: !14)
!14 = !{null, !5}
!15 = !DIGlobalVariableExpression(var: !16, expr: !DIExpression())
!16 = distinct !DIGlobalVariable(name: "g_cached_user_data", scope: !2, file: !3, line: 26, type: !5, isLocal: true, isDefinition: true)
!17 = !{i32 7, !"Dwarf Version", i32 5}
!18 = !{i32 2, !"Debug Info Version", i32 3}
!19 = !{i32 1, !"wchar_size", i32 4}
!20 = !{i32 7, !"PIC Level", i32 2}
!21 = !{i32 7, !"PIE Level", i32 2}
!22 = !{i32 7, !"uwtable", i32 1}
!23 = !{i32 7, !"frame-pointer", i32 2}
!24 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}
!25 = distinct !DISubprogram(name: "fixture_register", scope: !3, file: !3, line: 28, type: !26, scopeLine: 28, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !28)
!26 = !DISubroutineType(types: !27)
!27 = !{null, !11, !5}
!28 = !{}
!29 = !DILocalVariable(name: "callback", arg: 1, scope: !25, file: !3, line: 28, type: !11)
!30 = !DILocation(line: 28, column: 40, scope: !25)
!31 = !DILocalVariable(name: "user_data", arg: 2, scope: !25, file: !3, line: 28, type: !5)
!32 = !DILocation(line: 28, column: 56, scope: !25)
!33 = !DILocation(line: 29, column: 18, scope: !25)
!34 = !DILocation(line: 29, column: 16, scope: !25)
!35 = !DILocation(line: 30, column: 19, scope: !25)
!36 = !DILocation(line: 30, column: 17, scope: !25)
!37 = !DILocation(line: 31, column: 25, scope: !25)
!38 = !DILocation(line: 31, column: 23, scope: !25)
!39 = !DILocation(line: 32, column: 26, scope: !25)
!40 = !DILocation(line: 32, column: 24, scope: !25)
!41 = !DILocation(line: 33, column: 1, scope: !25)
!42 = distinct !DISubprogram(name: "fixture_unregister", scope: !3, file: !3, line: 35, type: !43, scopeLine: 35, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !28)
!43 = !DISubroutineType(types: !44)
!44 = !{null}
!45 = !DILocation(line: 37, column: 16, scope: !42)
!46 = !DILocation(line: 38, column: 17, scope: !42)
!47 = !DILocation(line: 39, column: 1, scope: !42)
!48 = distinct !DISubprogram(name: "fixture_fire", scope: !3, file: !3, line: 41, type: !43, scopeLine: 41, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !28)
!49 = !DILocation(line: 42, column: 9, scope: !50)
!50 = distinct !DILexicalBlock(scope: !48, file: !3, line: 42, column: 9)
!51 = !DILocation(line: 42, column: 9, scope: !48)
!52 = !DILocation(line: 43, column: 9, scope: !53)
!53 = distinct !DILexicalBlock(scope: !50, file: !3, line: 42, column: 21)
!54 = !DILocation(line: 43, column: 20, scope: !53)
!55 = !DILocation(line: 44, column: 5, scope: !53)
!56 = !DILocation(line: 44, column: 16, scope: !57)
!57 = distinct !DILexicalBlock(scope: !50, file: !3, line: 44, column: 16)
!58 = !DILocation(line: 44, column: 16, scope: !50)
!59 = !DILocation(line: 45, column: 9, scope: !60)
!60 = distinct !DILexicalBlock(scope: !57, file: !3, line: 44, column: 35)
!61 = !DILocation(line: 45, column: 27, scope: !60)
!62 = !DILocation(line: 46, column: 5, scope: !60)
!63 = !DILocation(line: 47, column: 1, scope: !48)
