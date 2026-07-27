use std::collections::{BTreeMap, BTreeSet};

use bw_model::RecordId;
use serde::{Deserialize, Serialize};

use crate::ContractFeedbackState;

pub const FEEDBACK_STATE_SCHEMA_V01: &str = "bw.feedback-state/0.1";

/// Stable context intentionally avoids runtime object IDs, addresses and paths.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StableRuleContext {
    BorrowedCaptureRetainedCallback,
    BorrowEndedRetainedCallback,
    CallbackInvokedAfterBorrowEnd,
    CallbackReleasedBeforeBorrowEnd,
    OwnerClosedBeforeCallbackRelease,
}

/// First-observed evidence and hit count for a feedback state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackStateObservation {
    pub state: ContractFeedbackState,
    pub first_event: RecordId,
    pub context: StableRuleContext,
    pub count: u64,
}

/// Normalized D2 state feedback snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackStateSnapshot {
    pub schema_version: String,
    pub states: BTreeSet<ContractFeedbackState>,
    pub feedback_key: String,
    pub transition_count: u64,
    pub observations: Vec<FeedbackStateObservation>,

    #[serde(skip)]
    observation_index: BTreeMap<ContractFeedbackState, usize>,
}

impl Default for FeedbackStateSnapshot {
    fn default() -> Self {
        Self {
            schema_version: FEEDBACK_STATE_SCHEMA_V01.to_owned(),
            states: BTreeSet::new(),
            feedback_key: String::new(),
            transition_count: 0,
            observations: Vec::new(),
            observation_index: BTreeMap::new(),
        }
    }
}

impl FeedbackStateSnapshot {
    #[must_use]
    pub fn from_states(states: impl IntoIterator<Item = ContractFeedbackState>) -> Self {
        let mut snapshot = Self::default();
        for state in states {
            snapshot.record(
                state,
                &RecordId::from("event:feedback:synthetic"),
                context_for_state(state),
            );
        }
        snapshot
    }

    #[must_use]
    pub fn states(&self) -> &BTreeSet<ContractFeedbackState> {
        &self.states
    }

    #[must_use]
    pub fn contains(&self, state: ContractFeedbackState) -> bool {
        self.states.contains(&state)
    }

    #[must_use]
    pub fn feedback_key(&self) -> &str {
        &self.feedback_key
    }

    pub fn add_diagnostic_note(&mut self, _diagnostics: &str) {
        // Diagnostics are intentionally excluded from normalized feedback snapshots.
    }

    pub(crate) fn record(
        &mut self,
        state: ContractFeedbackState,
        event: &RecordId,
        context: StableRuleContext,
    ) {
        if let Some(index) = self.observation_index.get(&state).copied() {
            self.observations[index].count += 1;
            return;
        }

        self.states.insert(state);
        self.transition_count += 1;
        self.observation_index
            .insert(state, self.observations.len());
        self.observations.push(FeedbackStateObservation {
            state,
            first_event: event.clone(),
            context,
            count: 1,
        });
        self.feedback_key = self
            .states
            .iter()
            .map(|state| state.as_str())
            .collect::<Vec<_>>()
            .join("|");
    }
}

const fn context_for_state(state: ContractFeedbackState) -> StableRuleContext {
    match state {
        ContractFeedbackState::BorrowedRetained => {
            StableRuleContext::BorrowedCaptureRetainedCallback
        }
        ContractFeedbackState::BorrowEndedRetained => {
            StableRuleContext::BorrowEndedRetainedCallback
        }
        ContractFeedbackState::InvokedAfterEnd => StableRuleContext::CallbackInvokedAfterBorrowEnd,
        ContractFeedbackState::ReleasedBeforeEnd => {
            StableRuleContext::CallbackReleasedBeforeBorrowEnd
        }
        ContractFeedbackState::ClosedOwnerWithRetainedCallback => {
            StableRuleContext::OwnerClosedBeforeCallbackRelease
        }
    }
}
