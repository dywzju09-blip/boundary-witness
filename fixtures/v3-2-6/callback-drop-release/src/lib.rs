use std::ffi::c_void;

unsafe extern "C" {
    fn set_drop_hook(cb: Option<extern "C" fn(*mut c_void)>, user_data: *mut c_void);
    fn clear_drop_hook();
}

pub struct Guard {
    data: Box<u32>,
}

impl Guard {
    pub fn register(&mut self) {
        let raw = (&mut *self.data) as *mut u32 as *mut c_void;
        set_drop_hook(Some(callback), raw);
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        clear_drop_hook();
    }
}

extern "C" fn callback(_user_data: *mut c_void) {}
