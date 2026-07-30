use std::{fmt, path::PathBuf};

use super::rustc_hir::def::DefKind;
use super::rustc_hir::def_id::LocalDefId;
use super::rustc_middle::hir::place::ProjectionKind as HirProjectionKind;
use super::rustc_middle::ty::{self, TyCtxt};
use super::rustc_span::{FileName, RemapPathScopeComponents, Span};
use bw_model::CaptureMode;

use crate::domain::CaptureObservation;

pub fn collect_crate_captures<'tcx>(
    tcx: TyCtxt<'tcx>,
) -> Result<Vec<CaptureObservation>, CaptureExtractionError> {
    let mut captures = Vec::new();
    for def_id in tcx.hir_body_owners() {
        if matches!(tcx.def_kind(def_id), DefKind::Closure) {
            captures.extend(collect_closure_captures(tcx, def_id)?);
        }
    }
    captures.sort_by(|left, right| {
        left.callback_def_path
            .cmp(&right.callback_def_path)
            .then(left.capture_ordinal.cmp(&right.capture_ordinal))
    });
    Ok(captures)
}

pub fn collect_closure_captures<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: LocalDefId,
) -> Result<Vec<CaptureObservation>, CaptureExtractionError> {
    let callback_def_path = tcx.def_path_str(def_id.to_def_id());
    let callback_span = tcx.def_span(def_id);
    let callback_source_path = source_path(tcx, callback_span)?;
    let callback_span = stable_span(tcx, callback_span)?;
    let mut observations = Vec::new();

    for (ordinal, capture) in tcx.closure_captures(def_id).iter().enumerate() {
        let capture_mode = capture_mode(
            capture.info.capture_kind,
            capture.place.ty(),
            &callback_def_path,
            ordinal,
        )?;
        let capture_span = capture.get_path_span(tcx);
        let object_span = capture.var_ident.span;
        observations.push(CaptureObservation {
            callback_def_path: callback_def_path.clone(),
            callback_source_path: callback_source_path.clone(),
            callback_span: callback_span.clone(),
            capture_ordinal: u32::try_from(ordinal).map_err(|_| {
                CaptureExtractionError::OrdinalOverflow {
                    callback_def_path: callback_def_path.clone(),
                    ordinal,
                }
            })?,
            capture_mode,
            capture_source_path: source_path(tcx, capture_span)?,
            capture_span: stable_span(tcx, capture_span)?,
            object_source_path: source_path(tcx, object_span)?,
            object_span: stable_span(tcx, object_span)?,
            object_type_name: capture.place.base_ty.to_string(),
            captured_field_path: captured_field_path(capture),
        });
    }

    Ok(observations)
}

fn captured_field_path<'tcx>(capture: &ty::CapturedPlace<'tcx>) -> Option<String> {
    let mut ty = capture.place.base_ty;
    let mut segments = Vec::new();
    for projection in &capture.place.projections {
        match projection.kind {
            HirProjectionKind::Field(index, variant) => match ty.kind() {
                ty::Tuple(_) => segments.push(format!("field:{}", index.index())),
                ty::Adt(def, ..) => {
                    let field = def.variant(variant).fields[index].name.as_str();
                    segments.push(format!("field:{field}"));
                }
                _ => return None,
            },
            HirProjectionKind::Deref
            | HirProjectionKind::Index
            | HirProjectionKind::Subslice
            | HirProjectionKind::OpaqueCast
            | HirProjectionKind::UnwrapUnsafeBinder => return None,
        }
        ty = projection.ty;
    }
    (!segments.is_empty()).then(|| segments.join(":"))
}

/// 判定一次 upvar 捕获是持有借用还是持有所有权。
///
/// `ty::UpvarCapture` 只说明**怎么**捕获（by-ref / by-value），不说明捕获了**什么**。
/// `move` 闭包的每个 upvar 都是 `ByValue`，哪怕被移动进去的值本身就是一个引用：
///
/// ```ignore
/// let borrowed = owner.get();          // &Counter
/// let owned = owner.get().clone();     // Counter
/// conn.update_hook(Some(move |..| { borrowed.record(1) }));  // ByValue，但持有借用
/// conn.update_hook(Some(move |..| { owned.record(1) }));     // ByValue，真的持有所有权
/// ```
///
/// 只看 `capture_kind` 会把两者都判成 `Owned`，于是 `has_borrowed_capture` 永远不触发
/// ——本该识别这一整类漏洞的特征恒为假，而排名照常输出分数。所以 `ByValue` 时必须
/// 追加看被捕获值的类型。
///
/// 判据是"类型里含有非 `'static` 的引用"。`&'static T` 不算：它的被引数据活得和进程
/// 一样久，回调持有它不构成滞留风险，把它算成借用只会制造假阳性。
fn capture_mode<'tcx>(
    capture_kind: ty::UpvarCapture,
    captured_ty: ty::Ty<'tcx>,
    callback_def_path: &str,
    ordinal: usize,
) -> Result<CaptureMode, CaptureExtractionError> {
    match capture_kind {
        ty::UpvarCapture::ByRef(_) => Ok(CaptureMode::Borrowed),
        ty::UpvarCapture::ByValue => {
            if carries_non_static_reference(captured_ty) {
                Ok(CaptureMode::Borrowed)
            } else {
                Ok(CaptureMode::Owned)
            }
        }
        ty::UpvarCapture::ByUse => Err(CaptureExtractionError::UnsupportedCaptureMode {
            callback_def_path: callback_def_path.to_owned(),
            ordinal,
            mode: "by_use",
        }),
    }
}

/// 类型中是否含有非 `'static` 的引用。
///
/// 遍历整个类型而不是只看最外层：`(&Counter, u32)` 或 `Wrapper<&Counter>` 同样把借用
/// 带进了闭包。region 被擦除（`ReErased`）时按含借用处理——那说明这一层已经拿不到
/// 生命周期信息，判成 owned 会把缺证当成"安全"。
fn carries_non_static_reference<'tcx>(ty: ty::Ty<'tcx>) -> bool {
    ty.walk().any(|arg| match arg.kind() {
        ty::GenericArgKind::Type(inner) => match inner.kind() {
            ty::Ref(region, ..) => !region.is_static(),
            _ => false,
        },
        _ => false,
    })
}

fn source_path<'tcx>(tcx: TyCtxt<'tcx>, span: Span) -> Result<PathBuf, CaptureExtractionError> {
    match tcx.sess.source_map().span_to_filename(span) {
        FileName::Real(name) => Ok(name
            .path(RemapPathScopeComponents::DIAGNOSTICS)
            .to_path_buf()),
        filename => Err(CaptureExtractionError::NonRealSourceFile {
            filename: format!("{filename:?}"),
        }),
    }
}

fn stable_span<'tcx>(tcx: TyCtxt<'tcx>, span: Span) -> Result<String, CaptureExtractionError> {
    let (source_file, lo_line, lo_col, hi_line, hi_col) =
        tcx.sess.source_map().span_to_location_info(span);
    if source_file.is_none() {
        return Err(CaptureExtractionError::MissingSpanLocation);
    }
    Ok(format!("{lo_line}:{lo_col}-{hi_line}:{hi_col}"))
}

#[derive(Debug)]
pub enum CaptureExtractionError {
    UnsupportedCaptureMode {
        callback_def_path: String,
        ordinal: usize,
        mode: &'static str,
    },
    OrdinalOverflow {
        callback_def_path: String,
        ordinal: usize,
    },
    NonRealSourceFile {
        filename: String,
    },
    MissingSpanLocation,
}

impl fmt::Display for CaptureExtractionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCaptureMode {
                callback_def_path,
                ordinal,
                mode,
            } => write!(
                formatter,
                "unsupported capture mode {mode} in {callback_def_path} capture #{ordinal}"
            ),
            Self::OrdinalOverflow {
                callback_def_path,
                ordinal,
            } => write!(
                formatter,
                "capture ordinal {ordinal} in {callback_def_path} does not fit u32"
            ),
            Self::NonRealSourceFile { filename } => {
                write!(
                    formatter,
                    "capture span does not point to a real source file: {filename}"
                )
            }
            Self::MissingSpanLocation => formatter.write_str("capture span has no source location"),
        }
    }
}

impl std::error::Error for CaptureExtractionError {}
