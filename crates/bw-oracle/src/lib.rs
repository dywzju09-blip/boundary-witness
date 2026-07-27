//! BoundaryWitness 的生命周期状态机与判定规则。

mod diff;
mod error;
mod evidence;
mod index;
mod normalize;
mod oracle;
mod rules;
mod state;

pub use diff::{CheckpointCoverage, FindingDiff, diff_findings};
pub use error::OracleError;
pub use evidence::normalize_finding;
pub use index::StaticFactIndex;
pub use normalize::NormalizedFinding;
pub use oracle::{AnalysisSummary, Oracle, OracleEngine};
pub use state::{
    CallbackLifecycle, CallbackState, CaptureLifecycle, CaptureState, ExternalOwnerLifecycle,
    ExternalOwnerState, ObjectLifecycle, ObjectState, OracleState,
};
