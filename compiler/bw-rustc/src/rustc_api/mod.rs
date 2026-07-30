extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_index;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_span;

mod captures;
mod mir;

use crate::{
    args::WrapperInvocation,
    callbacks::write_analysis_started,
    config::AnalysisRequest,
    coverage::write_mir_coverage,
    domain::{StaticFactContext, facts_from_captures, facts_from_mir_sites, write_static_facts},
    registration,
};

pub fn run_after_analysis(invocation: WrapperInvocation, request: AnalysisRequest) -> i32 {
    let mut callbacks = BoundaryCallbacks { request };
    let args = invocation.driver_args();
    rustc_driver::run_compiler(&args, &mut callbacks);
    0
}

struct BoundaryCallbacks {
    request: AnalysisRequest,
}

impl rustc_driver::Callbacks for BoundaryCallbacks {
    fn after_analysis<'tcx>(
        &mut self,
        _compiler: &rustc_interface::interface::Compiler,
        tcx: rustc_middle::ty::TyCtxt<'tcx>,
    ) -> rustc_driver::Compilation {
        if let Err(error) = analyze_crate(tcx, &self.request) {
            eprintln!("BW-RUSTC-OUTPUT: {error}");
            return rustc_driver::Compilation::Stop;
        }
        rustc_driver::Compilation::Continue
    }
}

fn analyze_crate<'tcx>(
    tcx: rustc_middle::ty::TyCtxt<'tcx>,
    request: &AnalysisRequest,
) -> Result<(), AnalysisError> {
    write_analysis_started(request)?;
    // 分类入口从进程级配置读取 API map，因此必须在遍历 MIR 之前装载。
    registration::configure_api_maps(
        &request.callback_retention_api_maps,
        request.embedded_callback_api_maps,
    );
    let captures = captures::collect_crate_captures(tcx)?;
    let context = StaticFactContext::new(
        &request.crate_name,
        &request.crate_id,
        &request.package_name,
        &request.package_version,
        &request.target,
        request.package_root.clone(),
    );
    let mir_sites = mir::collect_mir_sites(
        tcx,
        &request.crate_name,
        &request.collection_lookup_contracts,
        &captures,
    )?;
    write_mir_coverage(request, &mir_sites.seen_bodies)?;
    let mut facts = facts_from_captures(&context, &captures)?;
    facts.extend(facts_from_mir_sites(
        &context,
        &mir_sites.drops,
        &mir_sites.drop_preventions,
        &mir_sites.callback_user_data_reconstructions,
        &mir_sites.registrations,
        &mir_sites.raw_pointer_transfers,
        &mir_sites.release_path_proofs,
        &mir_sites.callback_release_use_orders,
        &mir_sites.external_calls,
        &mir_sites.callback_lifetime_bounds,
        &mir_sites.returned_borrow_relations,
        &mir_sites.persisted_returned_borrows,
        &mir_sites.returned_borrow_invalidation_orders,
        &mir_sites.external_buffer_bindings,
        &mir_sites.atomic_orderings,
        &mir_sites.object_binding_gaps,
        &mir_sites.object_flows,
        &facts,
    )?);
    facts.sort_by(|left, right| left.record_id.cmp(&right.record_id));
    facts.dedup_by(|left, right| left.record_id == right.record_id);
    write_static_facts(&request.output_dir, &facts)?;
    Ok(())
}

#[derive(Debug)]
enum AnalysisError {
    Io(std::io::Error),
    Capture(captures::CaptureExtractionError),
    Mir(mir::MirExtractionError),
    Coverage(crate::coverage::CoverageError),
    Domain(crate::domain::DomainError),
}

impl std::fmt::Display for AnalysisError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Capture(error) => write!(formatter, "{error}"),
            Self::Mir(error) => write!(formatter, "{error}"),
            Self::Coverage(error) => write!(formatter, "{error}"),
            Self::Domain(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for AnalysisError {}

impl From<std::io::Error> for AnalysisError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<captures::CaptureExtractionError> for AnalysisError {
    fn from(value: captures::CaptureExtractionError) -> Self {
        Self::Capture(value)
    }
}

impl From<mir::MirExtractionError> for AnalysisError {
    fn from(value: mir::MirExtractionError) -> Self {
        Self::Mir(value)
    }
}

impl From<crate::coverage::CoverageError> for AnalysisError {
    fn from(value: crate::coverage::CoverageError) -> Self {
        Self::Coverage(value)
    }
}

impl From<crate::domain::DomainError> for AnalysisError {
    fn from(value: crate::domain::DomainError) -> Self {
        Self::Domain(value)
    }
}
