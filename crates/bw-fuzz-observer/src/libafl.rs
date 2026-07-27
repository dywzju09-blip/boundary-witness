use std::collections::BTreeSet;

use crate::{ContractFeedbackState, FeedbackStateSnapshot};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FeedbackDecision {
    pub interesting: bool,
    pub key: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ContractStateFeedback {
    seen_states: BTreeSet<ContractFeedbackState>,
    seen_keys: BTreeSet<String>,
    previous_states: BTreeSet<ContractFeedbackState>,
}

impl ContractStateFeedback {
    #[must_use]
    pub fn observe_snapshot(&mut self, snapshot: &FeedbackStateSnapshot) -> FeedbackDecision {
        let new_states = snapshot
            .states()
            .iter()
            .filter(|state| !self.seen_states.contains(state))
            .copied()
            .collect::<Vec<_>>();

        if new_states.is_empty() {
            self.previous_states = snapshot.states().clone();
            return FeedbackDecision::default();
        }

        let key = if self.previous_states.is_empty() {
            new_states
                .iter()
                .map(|state| state.as_str())
                .collect::<Vec<_>>()
                .join("|")
        } else {
            format!(
                "{}->{}",
                state_key(&self.previous_states),
                state_key(new_states.iter())
            )
        };

        self.seen_states.extend(new_states);
        self.previous_states = snapshot.states().clone();
        if self.seen_keys.insert(key.clone()) {
            FeedbackDecision {
                interesting: true,
                key: Some(key),
            }
        } else {
            FeedbackDecision::default()
        }
    }

    #[must_use]
    pub fn observe_primary_marker(&mut self, _rule_id: &str) -> FeedbackDecision {
        FeedbackDecision::default()
    }

    #[must_use]
    pub fn seen_key_count(&self) -> usize {
        self.seen_keys.len()
    }
}

fn state_key<'a>(states: impl IntoIterator<Item = &'a ContractFeedbackState>) -> String {
    states
        .into_iter()
        .map(|state| state.as_str())
        .collect::<Vec<_>>()
        .join("|")
}
