use std::ffi::c_void;

unsafe extern "C" {
    fn set_owned_hook(cb: Option<extern "C" fn(*mut c_void)>, user_data: *mut c_void);
}

pub struct Owner {
    data: Box<u32>,
}

impl Owner {
    pub fn register(self) {
        let raw = Box::into_raw(self.data) as *mut c_void;
        set_owned_hook(Some(callback), raw);
    }
}

extern "C" fn callback(_user_data: *mut c_void) {}
