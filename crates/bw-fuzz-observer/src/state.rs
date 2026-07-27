use serde::{Deserialize, Serialize};

/// CVE-independent lifecycle states exposed to D2 fuzz feedback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractFeedbackState {
    BorrowedRetained,
    BorrowEndedRetained,
    InvokedAfterEnd,
    ReleasedBeforeEnd,
    ClosedOwnerWithRetainedCallback,
}

impl ContractFeedbackState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::BorrowedRetained => "borrowed_retained",
            Self::BorrowEndedRetained => "borrow_ended_retained",
            Self::InvokedAfterEnd => "invoked_after_end",
            Self::ReleasedBeforeEnd => "released_before_end",
            Self::ClosedOwnerWithRetainedCallback => "closed_owner_with_retained_callback",
        }
    }
}
