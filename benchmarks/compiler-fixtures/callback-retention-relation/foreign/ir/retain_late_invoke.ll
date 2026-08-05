; ModuleID = 'retain_late_invoke.c'
source_filename = "retain_late_invoke.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@g_callback = internal global void (i8*)* null, align 8, !dbg !0
@g_user_data = internal global i8* null, align 8, !dbg !5

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @fixture_register(void (i8*)* noundef %0, i8* noundef %1) #0 !dbg !20 {
  %3 = alloca void (i8*)*, align 8
  %4 = alloca i8*, align 8
  store void (i8*)* %0, void (i8*)** %3, align 8
  call void @llvm.dbg.declare(metadata void (i8*)** %3, metadata !24, metadata !DIExpression()), !dbg !25
  store i8* %1, i8** %4, align 8
  call void @llvm.dbg.declare(metadata i8** %4, metadata !26, metadata !DIExpression()), !dbg !27
  %5 = load void (i8*)*, void (i8*)** %3, align 8, !dbg !28
  store void (i8*)* %5, void (i8*)** @g_callback, align 8, !dbg !29
  %6 = load i8*, i8** %4, align 8, !dbg !30
  store i8* %6, i8** @g_user_data, align 8, !dbg !31
  ret void, !dbg !32
}

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @fixture_fire() #0 !dbg !33 {
  %1 = load void (i8*)*, void (i8*)** @g_callback, align 8, !dbg !36
  %2 = icmp ne void (i8*)* %1, null, !dbg !36
  br i1 %2, label %3, label %6, !dbg !38

3:                                                ; preds = %0
  %4 = load void (i8*)*, void (i8*)** @g_callback, align 8, !dbg !39
  %5 = load i8*, i8** @g_user_data, align 8, !dbg !41
  call void %4(i8* noundef %5), !dbg !39
  br label %6, !dbg !42

6:                                                ; preds = %3, %0
  ret void, !dbg !43
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nofree nosync nounwind readnone speculatable willreturn }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!12, !13, !14, !15, !16, !17, !18}
!llvm.ident = !{!19}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "g_callback", scope: !2, file: !3, line: 12, type: !8, isLocal: true, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "Ubuntu clang version 14.0.0-1ubuntu1.1", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !4, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "retain_late_invoke.c", directory: ".", checksumkind: CSK_MD5, checksum: "c525286f75f6767f753df5ba75ed9b49")
!4 = !{!0, !5}
!5 = !DIGlobalVariableExpression(var: !6, expr: !DIExpression())
!6 = distinct !DIGlobalVariable(name: "g_user_data", scope: !2, file: !3, line: 13, type: !7, isLocal: true, isDefinition: true)
!7 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!8 = !DIDerivedType(tag: DW_TAG_typedef, name: "fixture_callback", file: !3, line: 10, baseType: !9)
!9 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !10, size: 64)
!10 = !DISubroutineType(types: !11)
!11 = !{null, !7}
!12 = !{i32 7, !"Dwarf Version", i32 5}
!13 = !{i32 2, !"Debug Info Version", i32 3}
!14 = !{i32 1, !"wchar_size", i32 4}
!15 = !{i32 7, !"PIC Level", i32 2}
!16 = !{i32 7, !"PIE Level", i32 2}
!17 = !{i32 7, !"uwtable", i32 1}
!18 = !{i32 7, !"frame-pointer", i32 2}
!19 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}
!20 = distinct !DISubprogram(name: "fixture_register", scope: !3, file: !3, line: 15, type: !21, scopeLine: 15, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !23)
!21 = !DISubroutineType(types: !22)
!22 = !{null, !8, !7}
!23 = !{}
!24 = !DILocalVariable(name: "callback", arg: 1, scope: !20, file: !3, line: 15, type: !8)
!25 = !DILocation(line: 15, column: 40, scope: !20)
!26 = !DILocalVariable(name: "user_data", arg: 2, scope: !20, file: !3, line: 15, type: !7)
!27 = !DILocation(line: 15, column: 56, scope: !20)
!28 = !DILocation(line: 16, column: 18, scope: !20)
!29 = !DILocation(line: 16, column: 16, scope: !20)
!30 = !DILocation(line: 17, column: 19, scope: !20)
!31 = !DILocation(line: 17, column: 17, scope: !20)
!32 = !DILocation(line: 18, column: 1, scope: !20)
!33 = distinct !DISubprogram(name: "fixture_fire", scope: !3, file: !3, line: 21, type: !34, scopeLine: 21, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !23)
!34 = !DISubroutineType(types: !35)
!35 = !{null}
!36 = !DILocation(line: 22, column: 9, scope: !37)
!37 = distinct !DILexicalBlock(scope: !33, file: !3, line: 22, column: 9)
!38 = !DILocation(line: 22, column: 9, scope: !33)
!39 = !DILocation(line: 23, column: 9, scope: !40)
!40 = distinct !DILexicalBlock(scope: !37, file: !3, line: 22, column: 21)
!41 = !DILocation(line: 23, column: 20, scope: !40)
!42 = !DILocation(line: 24, column: 5, scope: !40)
!43 = !DILocation(line: 25, column: 1, scope: !33)
