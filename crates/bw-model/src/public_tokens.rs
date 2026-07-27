pub(crate) const PUBLIC_FORBIDDEN_TOKENS: [&str; 9] = [
    "vulnerable",
    "fixed",
    "cve",
    "ghsa",
    "expected",
    "patch",
    "advisory",
    "poc",
    "exploit",
];

pub(crate) fn reject_public_forbidden_token(
    field: &'static str,
    value: &str,
) -> Result<(), String> {
    let lower = value.to_ascii_lowercase();
    if let Some(token) = PUBLIC_FORBIDDEN_TOKENS
        .iter()
        .find(|token| contains_public_forbidden_token(&lower, token))
    {
        return Err(format!(
            "{field} 包含 V3.2 public artifact 禁止公开携带的身份线索 token `{token}`"
        ));
    }
    Ok(())
}

fn contains_public_forbidden_token(value: &str, token: &str) -> bool {
    value.match_indices(token).any(|(start, matched)| {
        let end = start + matched.len();
        let before = start
            .checked_sub(1)
            .and_then(|index| value.as_bytes().get(index))
            .copied();
        let after = value.as_bytes().get(end).copied();
        !before.is_some_and(|byte| byte.is_ascii_alphanumeric())
            && !after.is_some_and(|byte| byte.is_ascii_alphanumeric())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_tokens_require_identity_boundaries() {
        assert!(reject_public_forbidden_token("source_ref", "/tmp/.tmpD6xCVE/local").is_ok());
        assert!(reject_public_forbidden_token("source_ref", "sources/CVE-0000-0000").is_err());
        assert!(reject_public_forbidden_token("source_ref", "expected-result").is_err());
        assert!(reject_public_forbidden_token("source_ref", "unexpected-result").is_ok());
    }
}
