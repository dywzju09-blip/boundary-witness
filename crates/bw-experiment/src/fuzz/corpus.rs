use crate::{ActionSequence, ApiKind, ExperimentError, FuzzAction, Result, SqlOp};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CorpusPolicy;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CorpusAudit {
    pub sequences: usize,
    pub actions: usize,
}

impl CorpusPolicy {
    pub fn audit_jsonl_str(&self, input: &str) -> Result<CorpusAudit> {
        let mut audit = CorpusAudit::default();
        for (index, line) in input.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let sequence = ActionSequence::from_json_str(line).map_err(|error| {
                ExperimentError::InvalidInput(format!("invalid corpus line {}: {error}", index + 1))
            })?;
            self.audit_sequence(&sequence).map_err(|error| {
                ExperimentError::InvalidInput(format!("invalid corpus line {}: {error}", index + 1))
            })?;
            audit.sequences += 1;
            audit.actions += sequence.actions.len();
        }
        Ok(audit)
    }

    pub fn audit_sequence(&self, sequence: &ActionSequence) -> Result<()> {
        sequence.validate()?;
        let mut retained_borrowed: Option<ApiKind> = None;
        let mut borrowed_owner_ended: Option<ApiKind> = None;

        for action in &sequence.actions {
            match action {
                FuzzAction::RegisterBorrowed { api } => {
                    retained_borrowed = Some(*api);
                    borrowed_owner_ended = None;
                }
                FuzzAction::Unregister { api } => {
                    if retained_borrowed == Some(*api) {
                        retained_borrowed = None;
                    }
                    if borrowed_owner_ended == Some(*api) {
                        borrowed_owner_ended = None;
                    }
                }
                FuzzAction::EndOwnerScope => {
                    if let Some(api) = retained_borrowed {
                        borrowed_owner_ended = Some(api);
                    }
                }
                FuzzAction::ExecuteSql { op } => {
                    if let Some(api) = borrowed_owner_ended
                        && sql_triggers_api(*op, api)
                    {
                        return Err(ExperimentError::InvalidInput(format!(
                            "complete dangerous seed is forbidden: RegisterBorrowed({api:?}) -> EndOwnerScope -> ExecuteSql({op:?})"
                        )));
                    }
                }
                FuzzAction::CloseConnection => {
                    retained_borrowed = None;
                    borrowed_owner_ended = None;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn sql_triggers_api(op: SqlOp, api: ApiKind) -> bool {
    matches!(
        (op, api),
        (
            SqlOp::Insert | SqlOp::Update | SqlOp::Delete,
            ApiKind::UpdateHook
        ) | (SqlOp::SelectScalar, ApiKind::CreateScalarFunction)
    )
}
