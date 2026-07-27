use bw_experiment::{ActionSequence, ApiKind, FuzzAction, SqlOp};
use bw_model::CheckpointKind;
use bw_runtime::Tracked;
use rusqlite::{
    functions::{Context, FunctionFlags},
    Connection,
};

use crate::{
    fuzzing::harness::{
        finish_with_analysis, site, HarnessOutcome, HarnessResult, HarnessRunResult, HarnessRuntime,
    },
    scalar_function::{ScalarCallbackToken, ScalarFunctionConnection},
    BorrowedCounter, OwnedCounter,
};

const SCALAR_FUNCTION_NAME: &str = "bw_counter";
const SCALAR_FUNCTION_ARITY: i32 = 0;

pub fn run_scalar_function_sequence(sequence: &ActionSequence) -> HarnessRunResult<HarnessResult> {
    sequence
        .validate()
        .map_err(|error| crate::fuzzing::harness::HarnessError::new(error.to_string()))?;

    let harness = HarnessRuntime::start("scalar-function")?;
    let mut state = ScalarFunctionHarness::new(harness.runtime.clone());
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
    finish_with_analysis(harness, outcome, invalid_reason, effective_actions)
}

struct ScalarFunctionHarness {
    runtime: bw_runtime::RuntimeContext,
    sql: Option<Connection>,
    observed: Option<ScalarFunctionConnection>,
    table_created: bool,
    borrowed_state: Option<Tracked<BorrowedCounter>>,
    owned_state: Option<Tracked<OwnedCounter>>,
    current_token: Option<ScalarCallbackToken>,
}

impl ScalarFunctionHarness {
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
            ScalarFunctionConnection::open(self.runtime.clone(), site("site:d1:scalar:connection"))
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
            site("site:d1:scalar:object:borrowed"),
            BorrowedCounter::new(),
        ));
        Ok(())
    }

    fn register_borrowed(&mut self, api: ApiKind) -> Result<(), String> {
        require_scalar_function(api)?;
        let observed = self.observed.as_ref().ok_or("connection_not_open")?;
        let borrowed = self
            .borrowed_state
            .as_ref()
            .ok_or("borrowed_state_not_live")?;
        let token = observed
            .register(
                SCALAR_FUNCTION_NAME,
                SCALAR_FUNCTION_ARITY,
                site("site:d1:scalar:callback:borrowed"),
            )
            .map_err(|error| error.to_string())?;
        token
            .bind_object(borrowed.id(), &site("site:d1:scalar:object:borrowed"))
            .map_err(|error| error.to_string())?;
        self.runtime
            .emit_checkpoint(CheckpointKind::Registered)
            .map_err(|error| error.to_string())?;
        self.install_sql_scalar_function(token.clone())?;
        self.current_token = Some(token);
        Ok(())
    }

    fn register_owned(&mut self, api: ApiKind) -> Result<(), String> {
        require_scalar_function(api)?;
        let observed = self.observed.as_ref().ok_or("connection_not_open")?;
        if self.owned_state.is_none() {
            self.owned_state = Some(Tracked::new(
                self.runtime.clone(),
                site("site:d1:scalar:object:owned"),
                OwnedCounter::new(),
            ));
        }
        let owned = self.owned_state.as_ref().expect("owned state was created");
        let token = observed
            .register(
                SCALAR_FUNCTION_NAME,
                SCALAR_FUNCTION_ARITY,
                site("site:d1:scalar:callback:owned"),
            )
            .map_err(|error| error.to_string())?;
        token
            .bind_object(owned.id(), &site("site:d1:scalar:object:owned"))
            .map_err(|error| error.to_string())?;
        self.runtime
            .emit_checkpoint(CheckpointKind::Registered)
            .map_err(|error| error.to_string())?;
        self.install_sql_scalar_function(token.clone())?;
        self.current_token = Some(token);
        Ok(())
    }

    fn unregister(&mut self, api: ApiKind) -> Result<(), String> {
        require_scalar_function(api)?;
        let sql = self.sql.as_ref().ok_or("connection_not_open")?;
        let observed = self.observed.as_ref().ok_or("connection_not_open")?;
        self.current_token.take().ok_or("callback_not_registered")?;
        sql.remove_function(SCALAR_FUNCTION_NAME, SCALAR_FUNCTION_ARITY)
            .map_err(|error| error.to_string())?;
        observed
            .remove(
                SCALAR_FUNCTION_NAME,
                SCALAR_FUNCTION_ARITY,
                site("site:d1:scalar:unregister"),
            )
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
        match op {
            SqlOp::SelectScalar => {
                let _: i64 = sql
                    .query_row("SELECT bw_counter()", [], |row| row.get(0))
                    .map_err(|error| error.to_string())?;
                Ok(())
            }
            SqlOp::Insert | SqlOp::Update | SqlOp::Delete => {
                Err("sql_op_does_not_invoke_scalar_function".to_owned())
            }
        }
    }

    fn close_connection(&mut self) -> Result<(), String> {
        let observed = self.observed.take().ok_or("connection_not_open")?;
        self.sql.take().ok_or("connection_not_open")?;
        observed
            .close(site("site:d1:scalar:connection-drop"))
            .map_err(|error| error.to_string())?;
        self.current_token = None;
        self.table_created = false;
        Ok(())
    }

    fn cleanup(&mut self) -> HarnessRunResult<()> {
        self.sql.take();
        if let Some(observed) = self.observed.take() {
            observed.close(site("site:d1:scalar:connection-drop"))?;
        }
        self.current_token = None;
        self.borrowed_state.take();
        self.owned_state.take();
        Ok(())
    }

    fn install_sql_scalar_function(&mut self, token: ScalarCallbackToken) -> Result<(), String> {
        let sql = self.sql.as_ref().ok_or("connection_not_open")?;
        sql.create_scalar_function(
            SCALAR_FUNCTION_NAME,
            SCALAR_FUNCTION_ARITY,
            FunctionFlags::SQLITE_UTF8,
            move |context: &Context<'_>| {
                let _ = context.len();
                token
                    .invoke(site("site:d1:scalar:invoke"))
                    .expect("retained scalar callback token should be invokable");
                Ok(1_i64)
            },
        )
        .map_err(|error| error.to_string())
    }
}

fn require_scalar_function(api: ApiKind) -> Result<(), String> {
    if api == ApiKind::CreateScalarFunction {
        Ok(())
    } else {
        Err("api_mismatch".to_owned())
    }
}
