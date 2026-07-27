use bw_model::{
    InstanceId, ObjectCreateEvent, ObjectDropEvent, ObjectKind, ObjectUseEvent, ObjectUseKind,
    RuntimeEvent, SiteId,
};

use crate::RuntimeHandle;

pub struct Tracked<T> {
    runtime: RuntimeHandle,
    id: InstanceId,
    site_id: SiteId,
    value: T,
}

impl<T> Tracked<T> {
    #[must_use]
    pub fn new(runtime: RuntimeHandle, site_id: SiteId, value: T) -> Self {
        let id = runtime.next_object_id();
        runtime.emit_deferred(RuntimeEvent::ObjectCreate(ObjectCreateEvent {
            instance_id: id.clone(),
            site_id: site_id.clone(),
            object_kind: ObjectKind::Tracked,
            epoch: 0,
            address_diag: None,
        }));
        Self {
            runtime,
            id,
            site_id,
            value,
        }
    }

    #[must_use]
    pub fn id(&self) -> &InstanceId {
        &self.id
    }

    pub fn get(&self) -> &T {
        self.emit_use(ObjectUseKind::Read);
        &self.value
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.emit_use(ObjectUseKind::Write);
        &mut self.value
    }

    fn emit_use(&self, use_kind: ObjectUseKind) {
        self.runtime
            .emit_deferred(RuntimeEvent::ObjectUse(ObjectUseEvent {
                instance_id: self.id.clone(),
                use_site_id: self.site_id.clone(),
                use_kind,
            }));
    }
}

impl<T> Drop for Tracked<T> {
    fn drop(&mut self) {
        self.runtime
            .emit_deferred(RuntimeEvent::ObjectDrop(ObjectDropEvent {
                instance_id: self.id.clone(),
                drop_site_id: self.site_id.clone(),
            }));
    }
}
