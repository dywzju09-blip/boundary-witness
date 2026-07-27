use std::ffi::c_void;

unsafe extern "C" {
    fn set_update_hook(cb: Option<extern "C" fn(*mut c_void)>, user_data: *mut c_void);
}

pub fn register_local_reference() {
    let local = 7_u32;
    let user_data = &local as *const u32 as *mut c_void;
    set_update_hook(Some(callback), user_data);
}

extern "C" fn callback(_user_data: *mut c_void) {}
