use std::{fmt, str::FromStr};

use crate::{Result, error::validation};

#[derive(
    Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct BlindCaseId(String);

impl BlindCaseId {
    pub fn parse(value: &str) -> Result<Self> {
        if value.len() == 22
            && value.starts_with("blind-")
            && value[6..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value.to_owned()))
        } else {
            Err(validation("case_id must match blind-[0-9a-f]{16}"))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for BlindCaseId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for BlindCaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for BlindCaseId {
    type Err = crate::BlindModelError;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}
