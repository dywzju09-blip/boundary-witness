; ModuleID = 'retain_late_invoke_clearing.c'
source_filename = "retain_late_invoke_clearing.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@g_callback = internal global void (i8*)* null, align 8, !dbg !0
@g_user_data = internal global i8* null, align 8, !dbg !7

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @fixture_register(void (i8*)* noundef %0, i8* noundef %1) #0 !dbg !21 {
  %3 = alloca void (i8*)*, align 8
  %4 = alloca i8*, align 8
  store void (i8*)* %0, void (i8*)** %3, align 8
  call void @llvm.dbg.declare(metadata void (i8*)** %3, metadata !25, metadata !DIExpression()), !dbg !26
  store i8* %1, i8** %4, align 8
  call void @llvm.dbg.declare(metadata i8** %4, metadata !27, metadata !DIExpression()), !dbg !28
  %5 = load void (i8*)*, void (i8*)** %3, align 8, !dbg !29
  store void (i8*)* %5, void (i8*)** @g_callback, align 8, !dbg !30
  %6 = load i8*, i8** %4, align 8, !dbg !31
  store i8* %6, i8** @g_user_data, align 8, !dbg !32
  ret void, !dbg !33
}

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @fixture_unregister() #0 !dbg !34 {
  store void (i8*)* null, void (i8*)** @g_callback, align 8, !dbg !37
  store i8* null, i8** @g_user_data, align 8, !dbg !38
  ret void, !dbg !39
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @fixture_fire() #0 !dbg !40 {
  %1 = load void (i8*)*, void (i8*)** @g_callback, align 8, !dbg !41
  %2 = icmp ne void (i8*)* %1, null, !dbg !41
  br i1 %2, label %3, label %6, !dbg !43

3:                                                ; preds = %0
  %4 = load void (i8*)*, void (i8*)** @g_callback, align 8, !dbg !44
  %5 = load i8*, i8** @g_user_data, align 8, !dbg !46
  call void %4(i8* noundef %5), !dbg !44
  br label %6, !dbg !47

6:                                                ; preds = %3, %0
  ret void, !dbg !48
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nofree nosync nounwind readnone speculatable willreturn }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!13, !14, !15, !16, !17, !18, !19}
!llvm.ident = !{!20}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "g_callback", scope: !2, file: !3, line: 15, type: !9, isLocal: true, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "Ubuntu clang version 14.0.0-1ubuntu1.1", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, retainedTypes: !4, globals: !6, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "retain_late_invoke_clearing.c", directory: ".", checksumkind: CSK_MD5, checksum: "05c9d0d0ad129a08372e9f0390780127")
!4 = !{!5}
!5 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!6 = !{!0, !7}
!7 = !DIGlobalVariableExpression(var: !8, expr: !DIExpression())
!8 = distinct !DIGlobalVariable(name: "g_user_data", scope: !2, file: !3, line: 16, type: !5, isLocal: true, isDefinition: true)
!9 = !DIDerivedType(tag: DW_TAG_typedef, name: "fixture_callback", file: !3, line: 13, baseType: !10)
!10 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !11, size: 64)
!11 = !DISubroutineType(types: !12)
!12 = !{null, !5}
!13 = !{i32 7, !"Dwarf Version", i32 5}
!14 = !{i32 2, !"Debug Info Version", i32 3}
!15 = !{i32 1, !"wchar_size", i32 4}
!16 = !{i32 7, !"PIC Level", i32 2}
!17 = !{i32 7, !"PIE Level", i32 2}
!18 = !{i32 7, !"uwtable", i32 1}
!19 = !{i32 7, !"frame-pointer", i32 2}
!20 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}
!21 = distinct !DISubprogram(name: "fixture_register", scope: !3, file: !3, line: 18, type: !22, scopeLine: 18, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !24)
!22 = !DISubroutineType(types: !23)
!23 = !{null, !9, !5}
!24 = !{}
!25 = !DILocalVariable(name: "callback", arg: 1, scope: !21, file: !3, line: 18, type: !9)
!26 = !DILocation(line: 18, column: 40, scope: !21)
!27 = !DILocalVariable(name: "user_data", arg: 2, scope: !21, file: !3, line: 18, type: !5)
!28 = !DILocation(line: 18, column: 56, scope: !21)
!29 = !DILocation(line: 19, column: 18, scope: !21)
!30 = !DILocation(line: 19, column: 16, scope: !21)
!31 = !DILocation(line: 20, column: 19, scope: !21)
!32 = !DILocation(line: 20, column: 17, scope: !21)
!33 = !DILocation(line: 21, column: 1, scope: !21)
!34 = distinct !DISubprogram(name: "fixture_unregister", scope: !3, file: !3, line: 23, type: !35, scopeLine: 23, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !24)
!35 = !DISubroutineType(types: !36)
!36 = !{null}
!37 = !DILocation(line: 24, column: 16, scope: !34)
!38 = !DILocation(line: 25, column: 17, scope: !34)
!39 = !DILocation(line: 26, column: 1, scope: !34)
!40 = distinct !DISubprogram(name: "fixture_fire", scope: !3, file: !3, line: 28, type: !35, scopeLine: 28, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !24)
!41 = !DILocation(line: 29, column: 9, scope: !42)
!42 = distinct !DILexicalBlock(scope: !40, file: !3, line: 29, column: 9)
!43 = !DILocation(line: 29, column: 9, scope: !40)
!44 = !DILocation(line: 30, column: 9, scope: !45)
!45 = distinct !DILexicalBlock(scope: !42, file: !3, line: 29, column: 21)
!46 = !DILocation(line: 30, column: 20, scope: !45)
!47 = !DILocation(line: 31, column: 5, scope: !45)
!48 = !DILocation(line: 32, column: 1, scope: !40)
