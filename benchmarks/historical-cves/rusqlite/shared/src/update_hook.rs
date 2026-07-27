use std::sync::{Arc, Mutex};

use bw_model::{
    CallbackReleaseReason, InstanceId, ObjectCreateEvent, ObjectDropEvent, ObjectKind,
    RuntimeEvent, SiteId,
};
use bw_runtime::{CallbackToken, RuntimeError, RuntimeHandle};

use crate::runtime::UPDATE_HOOK_API_ID;

pub struct UpdateHookConnection {
    runtime: RuntimeHandle,
    owner_id: InstanceId,
    current_callback: Mutex<Option<Arc<CallbackToken>>>,
    closed: Mutex<bool>,
}

impl UpdateHookConnection {
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
            current_callback: Mutex::new(None),
            closed: Mutex::new(false),
        })
    }

    #[must_use]
    pub fn owner_id(&self) -> &InstanceId {
        &self.owner_id
    }

    pub fn register(&self, callback_site_id: SiteId) -> Result<Arc<CallbackToken>, RuntimeError> {
        let mut current_callback = self
            .current_callback
            .lock()
            .expect("update hook callback mutex should not be poisoned");
        if let Some(previous) = current_callback.take() {
            previous.release_with_reason(
                callback_site_id.clone(),
                CallbackReleaseReason::Replacement,
            )?;
        }
        let token = Arc::new(CallbackToken::register(
            self.runtime.clone(),
            callback_site_id,
            self.owner_id.clone(),
            UPDATE_HOOK_API_ID,
        )?);
        *current_callback = Some(Arc::clone(&token));
        Ok(token)
    }

    pub fn unregister(
        &self,
        token: &CallbackToken,
        unregister_site_id: SiteId,
    ) -> Result<(), RuntimeError> {
        token.release(unregister_site_id)?;
        let mut current_callback = self
            .current_callback
            .lock()
            .expect("update hook callback mutex should not be poisoned");
        if current_callback
            .as_ref()
            .is_some_and(|current| current.id() == token.id())
        {
            *current_callback = None;
        }
        Ok(())
    }

    pub fn close(&self, drop_site_id: SiteId) -> Result<(), RuntimeError> {
        {
            let mut closed = self
                .closed
                .lock()
                .expect("update hook connection mutex should not be poisoned");
            if *closed {
                return Ok(());
            }
            *closed = true;
        }
        if let Some(callback) = self
            .current_callback
            .lock()
            .expect("update hook callback mutex should not be poisoned")
            .take()
        {
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
