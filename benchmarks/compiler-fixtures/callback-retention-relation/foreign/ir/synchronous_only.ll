; ModuleID = 'synchronous_only.c'
source_filename = "synchronous_only.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @fixture_register(void (i8*)* noundef %0, i8* noundef %1) #0 !dbg !10 {
  %3 = alloca void (i8*)*, align 8
  %4 = alloca i8*, align 8
  store void (i8*)* %0, void (i8*)** %3, align 8
  call void @llvm.dbg.declare(metadata void (i8*)** %3, metadata !19, metadata !DIExpression()), !dbg !20
  store i8* %1, i8** %4, align 8
  call void @llvm.dbg.declare(metadata i8** %4, metadata !21, metadata !DIExpression()), !dbg !22
  %5 = load void (i8*)*, void (i8*)** %3, align 8, !dbg !23
  %6 = icmp ne void (i8*)* %5, null, !dbg !23
  br i1 %6, label %7, label %10, !dbg !25

7:                                                ; preds = %2
  %8 = load void (i8*)*, void (i8*)** %3, align 8, !dbg !26
  %9 = load i8*, i8** %4, align 8, !dbg !28
  call void %8(i8* noundef %9), !dbg !26
  br label %10, !dbg !29

10:                                               ; preds = %7, %2
  ret void, !dbg !30
}

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @fixture_unregister() #0 !dbg !31 {
  ret void, !dbg !34
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nofree nosync nounwind readnone speculatable willreturn }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3, !4, !5, !6, !7, !8}
!llvm.ident = !{!9}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "Ubuntu clang version 14.0.0-1ubuntu1.1", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "synchronous_only.c", directory: ".", checksumkind: CSK_MD5, checksum: "d9f53fb3c3382fd03d614bbc0f286ff4")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !{i32 1, !"wchar_size", i32 4}
!5 = !{i32 7, !"PIC Level", i32 2}
!6 = !{i32 7, !"PIE Level", i32 2}
!7 = !{i32 7, !"uwtable", i32 1}
!8 = !{i32 7, !"frame-pointer", i32 2}
!9 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}
!10 = distinct !DISubprogram(name: "fixture_register", scope: !1, file: !1, line: 16, type: !11, scopeLine: 16, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !18)
!11 = !DISubroutineType(types: !12)
!12 = !{null, !13, !17}
!13 = !DIDerivedType(tag: DW_TAG_typedef, name: "fixture_callback", file: !1, line: 14, baseType: !14)
!14 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !15, size: 64)
!15 = !DISubroutineType(types: !16)
!16 = !{null, !17}
!17 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!18 = !{}
!19 = !DILocalVariable(name: "callback", arg: 1, scope: !10, file: !1, line: 16, type: !13)
!20 = !DILocation(line: 16, column: 40, scope: !10)
!21 = !DILocalVariable(name: "user_data", arg: 2, scope: !10, file: !1, line: 16, type: !17)
!22 = !DILocation(line: 16, column: 56, scope: !10)
!23 = !DILocation(line: 17, column: 9, scope: !24)
!24 = distinct !DILexicalBlock(scope: !10, file: !1, line: 17, column: 9)
!25 = !DILocation(line: 17, column: 9, scope: !10)
!26 = !DILocation(line: 18, column: 9, scope: !27)
!27 = distinct !DILexicalBlock(scope: !24, file: !1, line: 17, column: 19)
!28 = !DILocation(line: 18, column: 18, scope: !27)
!29 = !DILocation(line: 19, column: 5, scope: !27)
!30 = !DILocation(line: 21, column: 1, scope: !10)
!31 = distinct !DISubprogram(name: "fixture_unregister", scope: !1, file: !1, line: 23, type: !32, scopeLine: 23, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !18)
!32 = !DISubroutineType(types: !33)
!33 = !{null}
!34 = !DILocation(line: 25, column: 1, scope: !31)
