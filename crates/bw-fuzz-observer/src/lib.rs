//! Contract-state feedback observer for D2 fuzzing experiments.

mod error;
mod libafl;
mod observer;
mod snapshot;
mod state;

pub use error::ObserverError;
pub use libafl::{ContractStateFeedback, FeedbackDecision};
pub use observer::ContractStateObserver;
pub use snapshot::{FeedbackStateObservation, FeedbackStateSnapshot, StableRuleContext};
pub use state::ContractFeedbackState;
