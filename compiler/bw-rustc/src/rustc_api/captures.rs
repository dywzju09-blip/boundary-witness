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
        let capture_mode = capture_mode(capture.info.capture_kind, &callback_def_path, ordinal)?;
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

fn capture_mode(
    capture_kind: ty::UpvarCapture,
    callback_def_path: &str,
    ordinal: usize,
) -> Result<CaptureMode, CaptureExtractionError> {
    match capture_kind {
        ty::UpvarCapture::ByRef(_) => Ok(CaptureMode::Borrowed),
        ty::UpvarCapture::ByValue => Ok(CaptureMode::Owned),
        ty::UpvarCapture::ByUse => Err(CaptureExtractionError::UnsupportedCaptureMode {
            callback_def_path: callback_def_path.to_owned(),
            ordinal,
            mode: "by_use",
        }),
    }
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
