use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SanitizerKind {
    AddressSanitizer,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StackFrame {
    pub index: u32,
    pub symbol: String,
    pub location: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizerReport {
    pub kind: SanitizerKind,
    pub error_kind: String,
    pub summary: String,
    pub first_frame: Option<StackFrame>,
}

#[must_use]
pub fn parse_asan_log(stderr: &str) -> Option<SanitizerReport> {
    let lines = stderr.lines().collect::<Vec<_>>();
    let header_index = lines
        .iter()
        .position(|line| line.contains("ERROR: AddressSanitizer:"))?;
    let header = lines[header_index];
    let error_kind = header
        .split_once("ERROR: AddressSanitizer:")?
        .1
        .split_whitespace()
        .next()?
        .trim_end_matches(':')
        .to_owned();

    let summary = lines
        .iter()
        .find(|line| line.contains("SUMMARY: AddressSanitizer:"))?
        .trim()
        .to_owned();
    if !summary.contains(&error_kind) {
        return None;
    }

    let first_frame = lines[header_index + 1..]
        .iter()
        .find_map(|line| parse_stack_frame(line));

    Some(SanitizerReport {
        kind: SanitizerKind::AddressSanitizer,
        error_kind,
        summary,
        first_frame,
    })
}

#[must_use]
pub fn stderr_has_asan_signature(stderr: &str) -> bool {
    parse_asan_log(stderr).is_some()
}

fn parse_stack_frame(line: &str) -> Option<StackFrame> {
    let trimmed = line.trim_start();
    let without_hash = trimmed.strip_prefix('#')?;
    let index_len = without_hash
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .count();
    if index_len == 0 {
        return None;
    }
    let index = without_hash[..index_len].parse::<u32>().ok()?;
    let rest = without_hash[index_len..].trim_start();
    let frame_text = rest.split_once(" in ")?.1.trim();
    if frame_text.is_empty() {
        return None;
    }
    let (symbol, location) =
        frame_text
            .split_once(' ')
            .map_or((frame_text, None), |(symbol, location)| {
                let location = location.trim();
                (
                    symbol,
                    if location.is_empty() {
                        None
                    } else {
                        Some(location)
                    },
                )
            });
    Some(StackFrame {
        index,
        symbol: symbol.to_owned(),
        location: location.map(str::to_owned),
    })
}
