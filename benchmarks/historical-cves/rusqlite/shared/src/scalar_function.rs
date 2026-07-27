use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use bw_model::{
    CallbackReleaseReason, InstanceId, ObjectCreateEvent, ObjectDropEvent, ObjectKind,
    RuntimeEvent, SiteId,
};
use bw_runtime::{CallbackToken, RuntimeError, RuntimeHandle};

use crate::runtime::CREATE_SCALAR_FUNCTION_API_ID;

#[derive(Clone)]
pub struct ScalarCallbackToken {
    inner: Arc<CallbackToken>,
}

impl ScalarCallbackToken {
    fn new(inner: Arc<CallbackToken>) -> Self {
        Self { inner }
    }

    pub fn bind_object(
        &self,
        object: &InstanceId,
        object_site: &SiteId,
    ) -> Result<(), RuntimeError> {
        self.inner.bind_object(object, object_site)
    }

    pub fn invoke(&self, invoke_site_id: SiteId) -> Result<(), RuntimeError> {
        self.inner.invoke(invoke_site_id)
    }
}

impl std::panic::UnwindSafe for ScalarCallbackToken {}

impl std::panic::RefUnwindSafe for ScalarCallbackToken {}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ScalarFunctionKey {
    name: String,
    n_arg: i32,
}

impl ScalarFunctionKey {
    fn new(name: impl Into<String>, n_arg: i32) -> Self {
        Self {
            name: name.into(),
            n_arg,
        }
    }
}

pub struct ScalarFunctionConnection {
    runtime: RuntimeHandle,
    owner_id: InstanceId,
    callbacks: Mutex<BTreeMap<ScalarFunctionKey, Arc<CallbackToken>>>,
    closed: Mutex<bool>,
}

impl ScalarFunctionConnection {
    pub fn open(runtime: RuntimeHandle, owner_site_id: SiteId) -> Result<Self, RuntimeError> {
        let owner_id = runtime.next_owner_id();
        runtime.emit(RuntimeEvent::ObjectCreate(ObjectCreateEvent {
            instance_id: owner_id.clone(),
            site_id: owner_site_id,
            object_kind: ObjectKind::ExternalOwner,
            epoch: 0,
            address_diag: None,
        }))?;
        Ok(Self {
            runtime,
            owner_id,
            callbacks: Mutex::new(BTreeMap::new()),
            closed: Mutex::new(false),
        })
    }

    #[must_use]
    pub fn owner_id(&self) -> &InstanceId {
        &self.owner_id
    }

    pub fn register(
        &self,
        function_name: impl Into<String>,
        n_arg: i32,
        callback_site_id: SiteId,
    ) -> Result<ScalarCallbackToken, RuntimeError> {
        let key = ScalarFunctionKey::new(function_name, n_arg);
        let previous = self
            .callbacks
            .lock()
            .expect("scalar callback mutex should not be poisoned")
            .remove(&key);
        if let Some(previous) = previous {
            previous.release_with_reason(
                callback_site_id.clone(),
                CallbackReleaseReason::Replacement,
            )?;
        }

        let token = Arc::new(CallbackToken::register(
            self.runtime.clone(),
            callback_site_id,
            self.owner_id.clone(),
            CREATE_SCALAR_FUNCTION_API_ID,
        )?);
        self.callbacks
            .lock()
            .expect("scalar callback mutex should not be poisoned")
            .insert(key, Arc::clone(&token));
        Ok(ScalarCallbackToken::new(token))
    }

    pub fn remove(
        &self,
        function_name: impl Into<String>,
        n_arg: i32,
        remove_site_id: SiteId,
    ) -> Result<(), RuntimeError> {
        if let Some(callback) = self
            .callbacks
            .lock()
            .expect("scalar callback mutex should not be poisoned")
            .remove(&ScalarFunctionKey::new(function_name, n_arg))
        {
            callback.release(remove_site_id)?;
        }
        Ok(())
    }

    pub fn close(&self, drop_site_id: SiteId) -> Result<(), RuntimeError> {
        {
            let mut closed = self
                .closed
                .lock()
                .expect("scalar connection mutex should not be poisoned");
            if *closed {
                return Ok(());
            }
            *closed = true;
        }

        let callbacks = {
            let mut callbacks = self
                .callbacks
                .lock()
                .expect("scalar callback mutex should not be poisoned");
            std::mem::take(&mut *callbacks)
        };
        for callback in callbacks.into_values() {
            callback.release_with_reason(drop_site_id.clone(), CallbackReleaseReason::OwnerDrop)?;
        }

        self.runtime
            .emit(RuntimeEvent::ObjectDrop(ObjectDropEvent {
                instance_id: self.owner_id.clone(),
                drop_site_id,
            }))
            .map(|_| ())
    }
}
