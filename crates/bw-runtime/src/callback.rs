use std::sync::Mutex;

use bw_model::{
    CallbackInvokeEvent, CallbackRegisterEvent, CallbackReleaseReason, CallbackUnregisterEvent,
    CaptureBindEvent, InstanceId, RuntimeEvent, SiteId,
};

use crate::{RuntimeError, RuntimeHandle};

#[derive(Debug, Eq, PartialEq)]
enum CallbackTokenState {
    Retained,
    Released,
}

pub struct CallbackToken {
    runtime: RuntimeHandle,
    id: InstanceId,
    site_id: SiteId,
    owner_instance_id: InstanceId,
    api_id: String,
    state: Mutex<CallbackTokenState>,
}

impl CallbackToken {
    pub fn register(
        runtime: RuntimeHandle,
        callback_site_id: SiteId,
        owner_instance_id: InstanceId,
        api_id: impl Into<String>,
    ) -> Result<Self, RuntimeError> {
        let api_id = api_id.into();
        let id = runtime.next_callback_id();
        runtime.emit(RuntimeEvent::CallbackRegister(CallbackRegisterEvent {
            callback_instance_id: id.clone(),
            callback_site_id: callback_site_id.clone(),
            owner_instance_id: owner_instance_id.clone(),
            registration_site_id: callback_site_id.clone(),
            api_id: api_id.clone(),
        }))?;
        Ok(Self {
            runtime,
            id,
            site_id: callback_site_id,
            owner_instance_id,
            api_id,
            state: Mutex::new(CallbackTokenState::Retained),
        })
    }

    #[must_use]
    pub fn id(&self) -> &InstanceId {
        &self.id
    }

    pub fn bind_object(
        &self,
        object: &InstanceId,
        object_site: &SiteId,
    ) -> Result<(), RuntimeError> {
        self.require_retained()?;
        self.runtime
            .emit(RuntimeEvent::CaptureBind(CaptureBindEvent {
                callback_instance_id: self.id.clone(),
                callback_site_id: self.site_id.clone(),
                object_instance_id: object.clone(),
                object_site_id: object_site.clone(),
            }))
            .map(|_| ())
    }

    pub fn invoke(&self, invoke_site_id: SiteId) -> Result<(), RuntimeError> {
        self.require_retained()?;
        self.runtime
            .emit(RuntimeEvent::CallbackInvoke(CallbackInvokeEvent {
                callback_instance_id: self.id.clone(),
                invoke_site_id,
                api_id: self.api_id.clone(),
            }))
            .map(|_| ())
    }

    pub fn release(&self, unregister_site_id: SiteId) -> Result<(), RuntimeError> {
        self.release_with_reason(unregister_site_id, CallbackReleaseReason::Explicit)
    }

    pub fn release_with_reason(
        &self,
        unregister_site_id: SiteId,
        reason: CallbackReleaseReason,
    ) -> Result<(), RuntimeError> {
        {
            let mut state = self
                .state
                .lock()
                .expect("callback token state mutex should not be poisoned");
            if *state == CallbackTokenState::Released {
                return Ok(());
            }
            *state = CallbackTokenState::Released;
        }
        self.runtime
            .emit(RuntimeEvent::CallbackUnregister(CallbackUnregisterEvent {
                callback_instance_id: self.id.clone(),
                owner_instance_id: self.owner_instance_id.clone(),
                unregister_site_id,
                api_id: self.api_id.clone(),
                reason,
            }))
            .map(|_| ())
    }

    fn require_retained(&self) -> Result<(), RuntimeError> {
        let state = self
            .state
            .lock()
            .expect("callback token state mutex should not be poisoned");
        if *state == CallbackTokenState::Released {
            return Err(RuntimeError::new(
                "BW-RUNTIME-CALLBACK-RELEASED",
                format!("callback {} has already been released", self.id),
            ));
        }
        Ok(())
    }
}
