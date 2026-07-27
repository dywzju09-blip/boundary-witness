use sha2::{Digest, Sha256};

use bw_model::{EvidenceSourceKind, Finding, FindingClassification, FindingStateSnapshot};

use crate::{NormalizedFinding, OracleError};

/// 校验证据完整性，并生成不含运行身份的规范化 finding。
pub fn normalize_finding(finding: &Finding) -> Result<NormalizedFinding, OracleError> {
    reject_dynamic_signature(&finding.normalized_signature)?;

    let mut static_evidence_codes = Vec::new();
    let mut contract_clause_ids = Vec::new();
    let mut runtime_relation_codes = Vec::new();
    for reference in &finding.evidence {
        match reference.source_kind {
            EvidenceSourceKind::StaticFact => {
                static_evidence_codes.push(reference.description_code.clone());
            }
            EvidenceSourceKind::ContractClause => {
                contract_clause_ids.push(reference.record_id.as_str().to_owned());
            }
            EvidenceSourceKind::RuntimeEvent => {
                runtime_relation_codes.push(reference.description_code.clone());
            }
        }
    }
    normalize_set(&mut static_evidence_codes);
    normalize_set(&mut contract_clause_ids);
    normalize_set(&mut runtime_relation_codes);
    let mut context_rule_ids = finding.context_rule_ids.clone();
    normalize_set(&mut context_rule_ids);

    validate_evidence_sources(
        finding,
        &static_evidence_codes,
        &contract_clause_ids,
        &runtime_relation_codes,
    )?;

    let mut normalized = NormalizedFinding {
        rule_id: finding.rule_id.clone(),
        classification: finding.classification,
        semantic_key: finding.normalized_signature.clone(),
        static_evidence_codes,
        contract_clause_ids,
        runtime_relation_codes,
        context_rule_ids,
        state_before: finding.state_before.clone(),
        state_after: finding.state_after.clone(),
        signature: String::new(),
    };
    normalized.signature = signature(&normalized);
    Ok(normalized)
}

fn validate_evidence_sources(
    finding: &Finding,
    static_codes: &[String],
    contract_clauses: &[String],
    runtime_codes: &[String],
) -> Result<(), OracleError> {
    if static_codes.is_empty() || contract_clauses.is_empty() || runtime_codes.is_empty() {
        return Err(incomplete(format!(
            "finding {} 必须同时引用 static_fact、contract_clause 和 runtime_event",
            finding.rule_id
        )));
    }
    let required_runtime: &[&str] = match finding.rule_id.as_str() {
        "BW-LIFE-001" => &["BW-EVIDENCE-LIFETIME-END", "BW-EVIDENCE-OBJECT-USE"],
        "BW-LIFE-002" => &[
            "BW-EVIDENCE-CAPTURE-BIND",
            "BW-EVIDENCE-BORROW-END",
            "BW-EVIDENCE-CALLBACK-INVOKE",
        ],
        "BW-LIFE-003" => &[
            "BW-EVIDENCE-CAPTURE-BIND",
            "BW-EVIDENCE-CALLBACK-RETAINED",
            "BW-EVIDENCE-BORROW-END",
        ],
        "BW-FREE-001" => &["BW-EVIDENCE-FIRST-FREE", "BW-EVIDENCE-REPEATED-FREE"],
        _ if finding.classification == FindingClassification::ConfirmedViolation => {
            if runtime_codes.len() < 2 {
                return Err(incomplete(format!(
                    "confirmed finding {} 的运行证据不足",
                    finding.rule_id
                )));
            }
            &[]
        }
        _ => &[],
    };
    for required in required_runtime {
        if !runtime_codes.iter().any(|code| code == required) {
            return Err(incomplete(format!(
                "finding {} 缺少运行关系 {required}",
                finding.rule_id
            )));
        }
    }
    Ok(())
}

fn reject_dynamic_signature(value: &str) -> Result<(), OracleError> {
    const FORBIDDEN: [&str; 8] = [
        "run:",
        "event:",
        "finding:",
        "object:",
        "callback:",
        concat!("/", "Users/"),
        "/root/",
        "0x",
    ];
    if let Some(marker) = FORBIDDEN.iter().find(|marker| value.contains(**marker)) {
        return Err(OracleError::new(
            "BW-ORACLE-NORMALIZATION-DYNAMIC",
            format!("规范化语义键包含运行相关标记 {marker}"),
        ));
    }
    Ok(())
}

fn normalize_set(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn signature(finding: &NormalizedFinding) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "rule", &finding.rule_id);
    hash_field(
        &mut hasher,
        "classification",
        classification_name(finding.classification),
    );
    hash_field(&mut hasher, "semantic", &finding.semantic_key);
    hash_list(
        &mut hasher,
        "static_evidence",
        &finding.static_evidence_codes,
    );
    hash_list(&mut hasher, "contract_clause", &finding.contract_clause_ids);
    hash_list(
        &mut hasher,
        "runtime_relation",
        &finding.runtime_relation_codes,
    );
    hash_list(&mut hasher, "context_rule", &finding.context_rule_ids);
    hash_snapshot(&mut hasher, "before", &finding.state_before);
    hash_snapshot(&mut hasher, "after", &finding.state_after);
    hex_lower(&hasher.finalize())
}

fn classification_name(classification: FindingClassification) -> &'static str {
    match classification {
        FindingClassification::Exposure => "exposure",
        FindingClassification::ConfirmedViolation => "confirmed_violation",
    }
}

fn hash_snapshot(hasher: &mut Sha256, prefix: &str, snapshot: &FindingStateSnapshot) {
    hash_optional(hasher, &format!("{prefix}.object"), &snapshot.object_state);
    hash_optional(
        hasher,
        &format!("{prefix}.capture"),
        &snapshot.capture_state,
    );
    hash_optional(
        hasher,
        &format!("{prefix}.callback"),
        &snapshot.callback_state,
    );
    hash_optional(hasher, &format!("{prefix}.owner"), &snapshot.owner_state);
}

fn hash_optional(hasher: &mut Sha256, label: &str, value: &Option<String>) {
    hash_field(hasher, label, value.as_deref().unwrap_or("<none>"));
}

fn hash_list(hasher: &mut Sha256, label: &str, values: &[String]) {
    hash_u64(hasher, label.len() as u64);
    hasher.update(label.as_bytes());
    hash_u64(hasher, values.len() as u64);
    for value in values {
        hash_u64(hasher, value.len() as u64);
        hasher.update(value.as_bytes());
    }
}

fn hash_field(hasher: &mut Sha256, label: &str, value: &str) {
    hash_u64(hasher, label.len() as u64);
    hasher.update(label.as_bytes());
    hash_u64(hasher, value.len() as u64);
    hasher.update(value.as_bytes());
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_be_bytes());
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn incomplete(message: impl Into<String>) -> OracleError {
    OracleError::new("BW-ORACLE-EVIDENCE-INCOMPLETE", message)
}
