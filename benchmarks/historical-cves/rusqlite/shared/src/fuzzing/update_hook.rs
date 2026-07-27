use std::sync::Arc;

use bw_experiment::{ActionSequence, ApiKind, FuzzAction, SqlOp};
use bw_model::CheckpointKind;
use bw_runtime::{CallbackToken, Tracked};
use rusqlite::{hooks::Action, Connection};

use crate::{
    fuzzing::harness::{
        finish_with_analysis, finish_with_analysis_and_feedback, site, HarnessOutcome,
        HarnessResult, HarnessRunResult, HarnessRuntime,
    },
    update_hook::UpdateHookConnection,
    BorrowedCounter, OwnedCounter,
};

pub fn run_update_hook_sequence(sequence: &ActionSequence) -> HarnessRunResult<HarnessResult> {
    run_update_hook_sequence_with_feedback(sequence, false)
}

pub fn run_update_hook_sequence_with_observer(
    sequence: &ActionSequence,
) -> HarnessRunResult<HarnessResult> {
    run_update_hook_sequence_with_feedback(sequence, true)
}

fn run_update_hook_sequence_with_feedback(
    sequence: &ActionSequence,
    collect_feedback: bool,
) -> HarnessRunResult<HarnessResult> {
    sequence
        .validate()
        .map_err(|error| crate::fuzzing::harness::HarnessError::new(error.to_string()))?;

    let harness = HarnessRuntime::start("update-hook")?;
    let mut state = UpdateHookHarness::new(harness.runtime.clone());
    let mut outcome = HarnessOutcome::Completed;
    let mut invalid_reason = None;
    let mut effective_actions = 0;

    for action in &sequence.actions {
        match state.apply(action) {
            Ok(()) => effective_actions += 1,
            Err(reason) => {
                outcome = HarnessOutcome::InvalidInput;
                invalid_reason = Some(reason);
                break;
            }
        }
    }

    state.cleanup()?;
    if collect_feedback {
        finish_with_analysis_and_feedback(harness, outcome, invalid_reason, effective_actions, true)
    } else {
        finish_with_analysis(harness, outcome, invalid_reason, effective_actions)
    }
}

struct UpdateHookHarness {
    runtime: bw_runtime::RuntimeContext,
    sql: Option<Connection>,
    observed: Option<UpdateHookConnection>,
    table_created: bool,
    borrowed_state: Option<Tracked<BorrowedCounter>>,
    owned_state: Option<Tracked<OwnedCounter>>,
    current_token: Option<Arc<CallbackToken>>,
}

impl UpdateHookHarness {
    fn new(runtime: bw_runtime::RuntimeContext) -> Self {
        Self {
            runtime,
            sql: None,
            observed: None,
            table_created: false,
            borrowed_state: None,
            owned_state: None,
            current_token: None,
        }
    }

    fn apply(&mut self, action: &FuzzAction) -> Result<(), String> {
        match action {
            FuzzAction::OpenConnection => self.open_connection(),
            FuzzAction::CreateTable => self.create_table(),
            FuzzAction::CreateBorrowedState => self.create_borrowed_state(),
            FuzzAction::RegisterBorrowed { api } => self.register_borrowed(*api),
            FuzzAction::RegisterOwned { api } => self.register_owned(*api),
            FuzzAction::Unregister { api } => self.unregister(*api),
            FuzzAction::EndOwnerScope => self.end_owner_scope(),
            FuzzAction::ExecuteSql { op } => self.execute_sql(*op),
            FuzzAction::CloseConnection => self.close_connection(),
        }
    }

    fn open_connection(&mut self) -> Result<(), String> {
        if self.sql.is_some() {
            return Err("connection_already_open".to_owned());
        }
        let sql = Connection::open_in_memory().map_err(|error| error.to_string())?;
        let observed =
            UpdateHookConnection::open(self.runtime.clone(), site("site:d1:update:connection"))
                .map_err(|error| error.to_string())?;
        self.sql = Some(sql);
        self.observed = Some(observed);
        Ok(())
    }

    fn create_table(&mut self) -> Result<(), String> {
        if self.table_created {
            return Err("table_already_created".to_owned());
        }
        let sql = self.sql.as_ref().ok_or("connection_not_open")?;
        sql.execute(
            "CREATE TABLE item(id INTEGER PRIMARY KEY, value INTEGER DEFAULT 0)",
            [],
        )
        .map_err(|error| error.to_string())?;
        self.table_created = true;
        Ok(())
    }

    fn create_borrowed_state(&mut self) -> Result<(), String> {
        if self.borrowed_state.is_some() {
            return Err("borrowed_state_already_live".to_owned());
        }
        self.borrowed_state = Some(Tracked::new(
            self.runtime.clone(),
            site("site:d1:update:object:borrowed"),
            BorrowedCounter::new(),
        ));
        Ok(())
    }

    fn register_borrowed(&mut self, api: ApiKind) -> Result<(), String> {
        require_update_hook(api)?;
        let observed = self.observed.as_ref().ok_or("connection_not_open")?;
        let borrowed = self
            .borrowed_state
            .as_ref()
            .ok_or("borrowed_state_not_live")?;
        let token = observed
            .register(site("site:d1:update:callback:borrowed"))
            .map_err(|error| error.to_string())?;
        token
            .bind_object(borrowed.id(), &site("site:d1:update:object:borrowed"))
            .map_err(|error| error.to_string())?;
        self.runtime
            .emit_checkpoint(CheckpointKind::Registered)
            .map_err(|error| error.to_string())?;
        self.install_sql_update_hook(Arc::clone(&token))?;
        self.current_token = Some(token);
        Ok(())
    }

    fn register_owned(&mut self, api: ApiKind) -> Result<(), String> {
        require_update_hook(api)?;
        let observed = self.observed.as_ref().ok_or("connection_not_open")?;
        if self.owned_state.is_none() {
            self.owned_state = Some(Tracked::new(
                self.runtime.clone(),
                site("site:d1:update:object:owned"),
                OwnedCounter::new(),
            ));
        }
        let owned = self.owned_state.as_ref().expect("owned state was created");
        let token = observed
            .register(site("site:d1:update:callback:owned"))
            .map_err(|error| error.to_string())?;
        token
            .bind_object(owned.id(), &site("site:d1:update:object:owned"))
            .map_err(|error| error.to_string())?;
        self.runtime
            .emit_checkpoint(CheckpointKind::Registered)
            .map_err(|error| error.to_string())?;
        self.install_sql_update_hook(Arc::clone(&token))?;
        self.current_token = Some(token);
        Ok(())
    }

    fn unregister(&mut self, api: ApiKind) -> Result<(), String> {
        require_update_hook(api)?;
        let sql = self.sql.as_ref().ok_or("connection_not_open")?;
        let observed = self.observed.as_ref().ok_or("connection_not_open")?;
        let token = self.current_token.take().ok_or("callback_not_registered")?;
        sql.update_hook(None::<fn(Action, &str, &str, i64)>);
        observed
            .unregister(&token, site("site:d1:update:unregister"))
            .map_err(|error| error.to_string())?;
        self.runtime
            .emit_checkpoint(CheckpointKind::OwnerEndedOrReleased)
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn end_owner_scope(&mut self) -> Result<(), String> {
        let mut dropped = false;
        if let Some(borrowed) = self.borrowed_state.take() {
            drop(borrowed);
            dropped = true;
        }
        if let Some(owned) = self.owned_state.take() {
            drop(owned);
            dropped = true;
        }
        if !dropped {
            return Err("owner_scope_not_live".to_owned());
        }
        self.runtime
            .emit_checkpoint(CheckpointKind::LaterCallbackPhase)
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn execute_sql(&mut self, op: SqlOp) -> Result<(), String> {
        let sql = self.sql.as_ref().ok_or("connection_not_open")?;
        if !self.table_created {
            return Err("table_not_created".to_owned());
        }
        match op {
            SqlOp::Insert => {
                sql.execute("INSERT INTO item(value) VALUES(1)", [])
                    .map_err(|error| error.to_string())?;
            }
            SqlOp::Update => {
                sql.execute("INSERT OR IGNORE INTO item(id, value) VALUES(1, 0)", [])
                    .map_err(|error| error.to_string())?;
                sql.execute("UPDATE item SET value = value + 1 WHERE id = 1", [])
                    .map_err(|error| error.to_string())?;
            }
            SqlOp::Delete => {
                sql.execute("INSERT OR IGNORE INTO item(id, value) VALUES(1, 0)", [])
                    .map_err(|error| error.to_string())?;
                sql.execute("DELETE FROM item WHERE id = 1", [])
                    .map_err(|error| error.to_string())?;
            }
            SqlOp::SelectScalar => {
                let _: i64 = sql
                    .query_row("SELECT 1", [], |row| row.get(0))
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    fn close_connection(&mut self) -> Result<(), String> {
        let sql = self.sql.take().ok_or("connection_not_open")?;
        let observed = self.observed.take().ok_or("connection_not_open")?;
        sql.update_hook(None::<fn(Action, &str, &str, i64)>);
        observed
            .close(site("site:d1:update:connection-drop"))
            .map_err(|error| error.to_string())?;
        self.current_token = None;
        self.table_created = false;
        Ok(())
    }

    fn cleanup(&mut self) -> HarnessRunResult<()> {
        if let Some(sql) = self.sql.take() {
            sql.update_hook(None::<fn(Action, &str, &str, i64)>);
        }
        if let Some(observed) = self.observed.take() {
            observed.close(site("site:d1:update:connection-drop"))?;
        }
        self.current_token = None;
        self.borrowed_state.take();
        self.owned_state.take();
        Ok(())
    }

    fn install_sql_update_hook(&mut self, token: Arc<CallbackToken>) -> Result<(), String> {
        let sql = self.sql.as_ref().ok_or("connection_not_open")?;
        sql.update_hook(Some(
            move |action: Action, database: &str, table: &str, rowid: i64| {
                let _ = (action, database, table, rowid);
                token
                    .invoke(site("site:d1:update:invoke"))
                    .expect("retained update hook token should be invokable");
            },
        ));
        Ok(())
    }
}

fn require_update_hook(api: ApiKind) -> Result<(), String> {
    if api == ApiKind::UpdateHook {
        Ok(())
    } else {
        Err("api_mismatch".to_owned())
    }
}
