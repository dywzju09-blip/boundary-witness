//! Curator-only support for packing anonymous BoundaryWitness N-day cases.

mod pack;
mod private;
mod reveal;
mod run_snapshot;

pub use pack::{CuratorError, PackOptions, PackReport, PackSource, Result, pack};
pub use private::{
    BLIND_GROUND_TRUTH_SCHEMA_V01, BlindGroundTruth, BlindTruthCase, PackSourceCase, TruthRole,
    TruthSource,
};
/// Reveal results are sealed after verified construction. External callers cannot mutate the
/// report or its cases before requesting a gate decision.
///
/// ```compile_fail
/// use bw_blind_curator::RevealReport;
///
/// fn forge_gate_input(report: &mut RevealReport) {
///     report.cases.clear();
///     report.total_cases = 0;
/// }
/// ```
pub use reveal::RevealReport;
pub use reveal::{BLIND_REVEAL_SCHEMA_V01, GateDecision, RevealOptions, RevealedCase, reveal};
