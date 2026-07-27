pub struct Retained {
    value: i32,
}

pub struct ExternalBuffer {
    raw: *const u8,
    len: usize,
}

pub mod neon_runtime {
    pub mod raw {
        #[derive(Clone, Copy)]
        pub struct Env;

        #[derive(Clone, Copy)]
        pub struct Local;
    }

    pub mod buffer {
        use super::raw;

        #[inline(never)]
        pub unsafe fn new_external<T: AsMut<[u8]> + Send>(
            _env: raw::Env,
            _data: T,
        ) -> raw::Local {
            raw::Local
        }
    }

    pub mod arraybuffer {
        use super::raw;

        #[inline(never)]
        pub unsafe fn new_external<T: AsMut<[u8]> + Send>(
            _env: raw::Env,
            _data: T,
        ) -> raw::Local {
            raw::Local
        }
    }
}

pub struct NeonEnv;

impl NeonEnv {
    #[inline(never)]
    pub fn to_raw(&self) -> neon_runtime::raw::Env {
        neon_runtime::raw::Env
    }
}

pub struct UserDataHolder {
    user_data: *mut i32,
}

pub struct UserDataPairHolder {
    registered_user_data: *mut i32,
    released_user_data: *mut i32,
}

pub struct NonNullUserDataHolder {
    user_data: std::ptr::NonNull<i32>,
}

pub struct NonNullUserDataPairHolder {
    registered_user_data: std::ptr::NonNull<i32>,
    released_user_data: std::ptr::NonNull<i32>,
}

pub struct NestedUserDataHolder {
    inner: UserDataHolder,
}

pub struct NestedUserDataPairHolder {
    inner: UserDataPairHolder,
}

pub struct HookReleaseState {
    free_hook: Option<unsafe fn(*mut std::ffi::c_void)>,
}

pub struct HookFieldState {
    free_update_hook: Option<unsafe fn(*mut std::ffi::c_void)>,
    free_commit_hook: Option<unsafe fn(*mut std::ffi::c_void)>,
}

pub struct CallbackUserData {
    finished: Option<extern "C" fn()>,
}

pub struct CallbackInvocationHolder {
    callback: extern "C" fn(*mut std::ffi::c_void),
    user_data: *mut std::ffi::c_void,
}

pub struct CallbackInvocationPairHolder {
    callback: extern "C" fn(*mut std::ffi::c_void),
    registered_user_data: *mut std::ffi::c_void,
    other_user_data: *mut std::ffi::c_void,
}

unsafe fn free_boxed_hook<F>(p: *mut std::ffi::c_void) {
    drop(unsafe { Box::from_raw(p as *mut F) });
}

pub extern "C" fn retained_userdata_transmute_callback(user_data: *mut std::ffi::c_void) {
    let data: Box<CallbackUserData> = unsafe { std::mem::transmute(user_data) };
    if let Some(finished) = data.finished {
        finished();
    }
    std::mem::forget(data);
}

pub extern "C" fn retained_userdata_leak_callback(user_data: *mut std::ffi::c_void) {
    let data: &mut CallbackUserData =
        Box::leak(unsafe { Box::from_raw(user_data as *mut CallbackUserData) });
    if let Some(finished) = data.finished {
        finished();
    }
}

pub extern "C" fn retained_userdata_roundtrip_callback(user_data: *mut std::ffi::c_void) {
    let data: Box<CallbackUserData> = unsafe { std::mem::transmute(user_data) };
    if let Some(finished) = data.finished {
        finished();
    }
    std::mem::forget(data);
}

pub extern "C" fn retained_userdata_helper_roundtrip_callback(
    user_data: *mut std::ffi::c_void,
) {
    let data: Box<CallbackUserData> = unsafe { std::mem::transmute(user_data) };
    if let Some(finished) = data.finished {
        finished();
    }
    std::mem::forget(data);
}

pub extern "C" fn retained_userdata_after_release_callback(user_data: *mut std::ffi::c_void) {
    let data: Box<CallbackUserData> = unsafe { std::mem::transmute(user_data) };
    if let Some(finished) = data.finished {
        finished();
    }
    std::mem::forget(data);
}

pub extern "C" fn retained_userdata_before_release_callback(user_data: *mut std::ffi::c_void) {
    let data: Box<CallbackUserData> = unsafe { std::mem::transmute(user_data) };
    if let Some(finished) = data.finished {
        finished();
    }
    std::mem::forget(data);
}

pub extern "C" fn retained_userdata_helper_after_release_callback(
    user_data: *mut std::ffi::c_void,
) {
    let data: Box<CallbackUserData> = unsafe { std::mem::transmute(user_data) };
    if let Some(finished) = data.finished {
        finished();
    }
    std::mem::forget(data);
}

pub extern "C" fn retained_userdata_helper_before_release_callback(
    user_data: *mut std::ffi::c_void,
) {
    let data: Box<CallbackUserData> = unsafe { std::mem::transmute(user_data) };
    if let Some(finished) = data.finished {
        finished();
    }
    std::mem::forget(data);
}

pub extern "C" fn retained_userdata_helper_alias_after_release_callback(
    user_data: *mut std::ffi::c_void,
) {
    let data: Box<CallbackUserData> = unsafe { std::mem::transmute(user_data) };
    if let Some(finished) = data.finished {
        finished();
    }
    std::mem::forget(data);
}

pub extern "C" fn retained_userdata_helper_wrong_object_callback(
    user_data: *mut std::ffi::c_void,
) {
    let data: Box<CallbackUserData> = unsafe { std::mem::transmute(user_data) };
    if let Some(finished) = data.finished {
        finished();
    }
    std::mem::forget(data);
}

pub extern "C" fn retained_userdata_helper_holder_after_release_callback(
    user_data: *mut std::ffi::c_void,
) {
    let data: Box<CallbackUserData> = unsafe { std::mem::transmute(user_data) };
    if let Some(finished) = data.finished {
        finished();
    }
    std::mem::forget(data);
}

pub extern "C" fn retained_userdata_helper_holder_wrong_field_callback(
    user_data: *mut std::ffi::c_void,
) {
    let data: Box<CallbackUserData> = unsafe { std::mem::transmute(user_data) };
    if let Some(finished) = data.finished {
        finished();
    }
    std::mem::forget(data);
}

pub extern "C" fn retained_userdata_ambiguous_callback(user_data: *mut std::ffi::c_void) {
    let data: Box<CallbackUserData> = unsafe { std::mem::transmute(user_data) };
    if let Some(finished) = data.finished {
        finished();
    }
    std::mem::forget(data);
}

impl UserDataHolder {
    #[inline(never)]
    pub unsafe fn release_user_data_method(&mut self) {
        // The fixture models a receiver-method release endpoint only. It does not assert any real defect.
        let _value = unsafe { Box::from_raw(self.user_data) };
    }
}

impl UserDataPairHolder {
    #[inline(never)]
    pub unsafe fn release_released_field_method(&mut self) {
        // This method releases a different field and must not cover the registered field.
        let _value = unsafe { Box::from_raw(self.released_user_data) };
    }
}

impl ExternalBuffer {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_null() || self.len == 0
    }
}

impl Retained {
    pub fn new(value: i32) -> Self {
        Self { value }
    }

    pub fn value(&self) -> i32 {
        self.value
    }
}

impl Drop for Retained {
    fn drop(&mut self) {}
}

pub struct Connection;

impl Connection {
    #[inline(never)]
    pub fn update_hook<F>(&self, _callback: Option<F>)
    where
        F: FnMut(i32) + 'static,
    {
    }

    #[inline(never)]
    pub fn create_scalar_function<F>(&self, _name: &str, _callback: F)
    where
        F: FnMut() -> i32 + 'static,
    {
    }

    #[inline(never)]
    pub fn set_callback_with_user_data<F>(&self, _callback: F, _user_data: *mut i32)
    where
        F: FnMut() + 'static,
    {
    }
}

pub mod unrelated_component {
    pub struct Connection;

    impl Connection {
        #[inline(never)]
        pub fn update_hook<F>(&self, _callback: Option<F>)
        where
            F: FnMut(i32) + 'static,
        {
        }
    }
}

unsafe extern "C" {
    pub fn sqlite3_step() -> i32;
}

pub extern "C" fn sqlite_callback_trampoline() {}

#[inline(never)]
pub fn sqlite3_update_hook(
    _db: *mut i32,
    _callback: Option<unsafe extern "C" fn(*mut std::ffi::c_void)>,
    _user_data: *mut std::ffi::c_void,
) -> *mut i32 {
    std::ptr::null_mut()
}

pub mod libsqlite3_sys {
    pub mod bindings {
        #[inline(never)]
        pub fn sqlite3_update_hook(
            _db: *mut i32,
            _callback: Option<unsafe extern "C" fn(*mut std::ffi::c_void)>,
            _user_data: *mut std::ffi::c_void,
        ) -> *mut std::ffi::c_void {
            std::ptr::null_mut()
        }

        #[inline(never)]
        pub fn sqlite3_create_function_v2(
            _db: *mut i32,
            _name: *const i8,
            _n_arg: i32,
            _flags: i32,
            _user_data: *mut std::ffi::c_void,
            _x_func: Option<unsafe extern "C" fn()>,
            _x_step: Option<unsafe extern "C" fn()>,
            _x_final: Option<unsafe extern "C" fn()>,
            _x_destroy: Option<unsafe fn(*mut std::ffi::c_void)>,
        ) -> i32 {
            0
        }
    }
}

#[allow(non_snake_case)]
pub mod openssl_sys {
    pub enum SSL {}
    #[allow(non_camel_case_types)]
    pub enum CRYPTO_EX_DATA {}
    pub const OPENSSL_NPN_NEGOTIATED: i32 = 1;

    #[allow(non_camel_case_types)]
    pub type CRYPTO_EX_free = unsafe extern "C" fn(
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        *mut CRYPTO_EX_DATA,
        i32,
        isize,
        *mut std::ffi::c_void,
    );

    #[inline(never)]
    pub fn SSL_set_ex_data(
        _ssl: *mut SSL,
        _idx: i32,
        _data: *mut std::ffi::c_void,
    ) -> i32 {
        1
    }

    #[inline(never)]
    pub fn SSL_get_ex_data(_ssl: *mut SSL, _idx: i32) -> *mut std::ffi::c_void {
        std::ptr::null_mut()
    }

    #[inline(never)]
    pub fn CRYPTO_get_ex_new_index(
        _class_index: i32,
        _argl: isize,
        _argp: *mut std::ffi::c_void,
        _new_func: Option<unsafe extern "C" fn()>,
        _dup_func: Option<unsafe extern "C" fn()>,
        _free_func: Option<CRYPTO_EX_free>,
    ) -> i32 {
        17
    }

    #[inline(never)]
    pub unsafe fn SSL_select_next_proto(
        out: *mut *const u8,
        outlen: *mut u8,
        server: *const u8,
        server_len: u32,
        _client: *const u8,
        _client_len: u32,
    ) -> i32 {
        unsafe {
            *out = server;
            *outlen = server_len as u8;
        }
        OPENSSL_NPN_NEGOTIATED
    }
}

#[allow(non_snake_case)]
pub mod pyo3_ffi {
    #[inline(never)]
    pub unsafe fn PyCapsule_New(
        pointer: *mut std::ffi::c_void,
        _name: *const i8,
        _destructor: Option<unsafe extern "C" fn(*mut std::ffi::c_void)>,
    ) -> *mut std::ffi::c_void {
        pointer
    }

    #[inline(never)]
    pub unsafe fn PyCapsule_GetPointer(
        capsule: *mut std::ffi::c_void,
        _name: *const i8,
    ) -> *mut std::ffi::c_void {
        capsule
    }
}

#[allow(non_snake_case)]
pub mod local_openssl_shadow {
    pub mod openssl_sys {
        #[inline(never)]
        pub fn SSL_get_ex_data(
            _ssl: *mut super::super::openssl_sys::SSL,
            _idx: i32,
        ) -> *mut std::ffi::c_void {
            std::ptr::null_mut()
        }
    }
}

pub struct OpenSslExDataDropRelease {
    ssl: *mut openssl_sys::SSL,
}

pub struct OpenSslExDataUnconditionalDropRelease {
    ssl: *mut openssl_sys::SSL,
}

pub struct OpenSslExDataWrongSlot {
    ssl: *mut openssl_sys::SSL,
}

pub struct OpenSslExDataSameNameWrongSlot {
    ssl: *mut openssl_sys::SSL,
}

pub struct OpenSslExDataNestedGet {
    ssl: *mut openssl_sys::SSL,
}

pub struct OpenSslExDataWrongHandle {
    primary_ssl: *mut openssl_sys::SSL,
    secondary_ssl: *mut openssl_sys::SSL,
}

pub struct OpenSslExDataAliasedHandle {
    ssl: *mut openssl_sys::SSL,
}

pub struct OpenSslExDataAliasedWrongHandle {
    primary_ssl: *mut openssl_sys::SSL,
    secondary_ssl: *mut openssl_sys::SSL,
}

pub struct OpenSslExDataHelperSetHolder {
    ssl: *mut openssl_sys::SSL,
    slot: i32,
    user_data: *mut std::ffi::c_void,
}

pub struct OpenSslExDataHelperGetHolder {
    ssl: *mut openssl_sys::SSL,
    slot: i32,
}

pub struct OpenSslExDataHelperHolderRelease {
    ssl: *mut openssl_sys::SSL,
}

pub struct OpenSslExDataHelperHolderWrongHandle {
    primary_ssl: *mut openssl_sys::SSL,
    secondary_ssl: *mut openssl_sys::SSL,
}

pub struct OpenSslExDataNoRelease {
    ssl: *mut openssl_sys::SSL,
}

pub struct OpenSslExDataForeignFreeContract {
    ssl: *mut openssl_sys::SSL,
}

pub struct OpenSslExDataForeignFreeMissingDestructor {
    ssl: *mut openssl_sys::SSL,
}

pub struct OpenSslExDataForeignFreeNonReleasingDestructor {
    ssl: *mut openssl_sys::SSL,
}

impl OpenSslExDataDropRelease {
    const SLOT: i32 = 7;

    #[inline(never)]
    pub fn openssl_ex_data_drop_release_registration_site(&mut self) {
        let user_data = Box::into_raw(Box::new(32_i32));
        let _ = openssl_sys::SSL_set_ex_data(
            self.ssl,
            Self::SLOT,
            user_data as *mut std::ffi::c_void,
        );
    }
}

impl Drop for OpenSslExDataDropRelease {
    fn drop(&mut self) {
        let user_data = openssl_sys::SSL_get_ex_data(self.ssl, Self::SLOT);
        if !user_data.is_null() {
            // The fixture models an exact ex_data release endpoint only.
            let _value = unsafe { Box::from_raw(user_data as *mut i32) };
        }
    }
}

impl OpenSslExDataUnconditionalDropRelease {
    const SLOT: i32 = 6;

    #[inline(never)]
    pub fn openssl_ex_data_unconditional_drop_release_registration_site(&mut self) {
        let user_data = Box::into_raw(Box::new(31_i32));
        let _ = openssl_sys::SSL_set_ex_data(
            self.ssl,
            Self::SLOT,
            user_data as *mut std::ffi::c_void,
        );
    }
}

impl Drop for OpenSslExDataUnconditionalDropRelease {
    fn drop(&mut self) {
        let user_data = openssl_sys::SSL_get_ex_data(self.ssl, Self::SLOT);
        let _value = unsafe { Box::from_raw(user_data as *mut i32) };
    }
}

impl OpenSslExDataWrongSlot {
    const REGISTRATION_SLOT: i32 = 8;
    const RELEASE_SLOT: i32 = 9;

    #[inline(never)]
    pub fn openssl_ex_data_wrong_slot_registration_site(&mut self) {
        let user_data = Box::into_raw(Box::new(33_i32));
        let _ = openssl_sys::SSL_set_ex_data(
            self.ssl,
            Self::REGISTRATION_SLOT,
            user_data as *mut std::ffi::c_void,
        );
    }
}

impl Drop for OpenSslExDataWrongSlot {
    fn drop(&mut self) {
        let user_data = openssl_sys::SSL_get_ex_data(self.ssl, Self::RELEASE_SLOT);
        if !user_data.is_null() {
            let _value = unsafe { Box::from_raw(user_data as *mut i32) };
        }
    }
}

impl OpenSslExDataSameNameWrongSlot {
    #[inline(never)]
    pub fn openssl_ex_data_same_name_wrong_slot_registration_site(&mut self) {
        let user_data = Box::into_raw(Box::new(35_i32));
        let slot = 11;
        let _ = openssl_sys::SSL_set_ex_data(self.ssl, slot, user_data as *mut std::ffi::c_void);
    }
}

impl Drop for OpenSslExDataSameNameWrongSlot {
    fn drop(&mut self) {
        let slot = 12;
        let user_data = openssl_sys::SSL_get_ex_data(self.ssl, slot);
        let _value = unsafe { Box::from_raw(user_data as *mut i32) };
    }
}

impl OpenSslExDataNestedGet {
    const SLOT: i32 = 13;

    #[inline(never)]
    pub fn openssl_ex_data_nested_get_registration_site(&mut self) {
        let user_data = Box::into_raw(Box::new(36_i32));
        let _ = openssl_sys::SSL_set_ex_data(
            self.ssl,
            Self::SLOT,
            user_data as *mut std::ffi::c_void,
        );
    }
}

impl Drop for OpenSslExDataNestedGet {
    fn drop(&mut self) {
        let user_data = local_openssl_shadow::openssl_sys::SSL_get_ex_data(self.ssl, Self::SLOT);
        let _value = unsafe { Box::from_raw(user_data as *mut i32) };
    }
}

impl OpenSslExDataWrongHandle {
    const SLOT: i32 = 14;

    #[inline(never)]
    pub fn openssl_ex_data_wrong_handle_registration_site(&mut self) {
        let user_data = Box::into_raw(Box::new(37_i32));
        let _ = openssl_sys::SSL_set_ex_data(
            self.primary_ssl,
            Self::SLOT,
            user_data as *mut std::ffi::c_void,
        );
    }
}

impl Drop for OpenSslExDataWrongHandle {
    fn drop(&mut self) {
        let user_data = openssl_sys::SSL_get_ex_data(self.secondary_ssl, Self::SLOT);
        let _value = unsafe { Box::from_raw(user_data as *mut i32) };
    }
}

impl OpenSslExDataAliasedHandle {
    const SLOT: i32 = 15;

    #[inline(never)]
    pub fn openssl_ex_data_aliased_handle_registration_site(&mut self) {
        let user_data = Box::into_raw(Box::new(69_i32));
        let handle = self.ssl;
        let _ = openssl_sys::SSL_set_ex_data(
            handle,
            Self::SLOT,
            user_data as *mut std::ffi::c_void,
        );
    }
}

impl Drop for OpenSslExDataAliasedHandle {
    fn drop(&mut self) {
        let handle = self.ssl;
        let user_data = openssl_sys::SSL_get_ex_data(handle, Self::SLOT);
        let _value = unsafe { Box::from_raw(user_data as *mut i32) };
    }
}

impl OpenSslExDataAliasedWrongHandle {
    const SLOT: i32 = 16;

    #[inline(never)]
    pub fn openssl_ex_data_aliased_wrong_handle_registration_site(&mut self) {
        let user_data = Box::into_raw(Box::new(70_i32));
        let handle = self.primary_ssl;
        let _ = openssl_sys::SSL_set_ex_data(
            handle,
            Self::SLOT,
            user_data as *mut std::ffi::c_void,
        );
    }
}

impl Drop for OpenSslExDataAliasedWrongHandle {
    fn drop(&mut self) {
        let handle = self.secondary_ssl;
        let user_data = openssl_sys::SSL_get_ex_data(handle, Self::SLOT);
        let _value = unsafe { Box::from_raw(user_data as *mut i32) };
    }
}

#[inline(never)]
fn openssl_set_ex_data_holder_helper(holder: OpenSslExDataHelperSetHolder) {
    let holder_alias = holder;
    let _ = openssl_sys::SSL_set_ex_data(
        holder_alias.ssl,
        holder_alias.slot,
        holder_alias.user_data,
    );
}

#[inline(never)]
fn openssl_get_ex_data_holder_helper(holder: OpenSslExDataHelperGetHolder) -> *mut std::ffi::c_void {
    let holder_alias = holder;
    openssl_sys::SSL_get_ex_data(holder_alias.ssl, holder_alias.slot)
}

impl OpenSslExDataHelperHolderRelease {
    const SLOT: i32 = 17;

    #[inline(never)]
    pub fn openssl_ex_data_helper_holder_registration_site(&mut self) {
        let user_data = Box::into_raw(Box::new(71_i32));
        openssl_set_ex_data_holder_helper(OpenSslExDataHelperSetHolder {
            ssl: self.ssl,
            slot: Self::SLOT,
            user_data: user_data as *mut std::ffi::c_void,
        });
    }
}

impl Drop for OpenSslExDataHelperHolderRelease {
    fn drop(&mut self) {
        let user_data = openssl_get_ex_data_holder_helper(OpenSslExDataHelperGetHolder {
            ssl: self.ssl,
            slot: Self::SLOT,
        });
        let _value = unsafe { Box::from_raw(user_data as *mut i32) };
    }
}

impl OpenSslExDataHelperHolderWrongHandle {
    const SLOT: i32 = 18;

    #[inline(never)]
    pub fn openssl_ex_data_helper_holder_wrong_handle_registration_site(&mut self) {
        let user_data = Box::into_raw(Box::new(72_i32));
        openssl_set_ex_data_holder_helper(OpenSslExDataHelperSetHolder {
            ssl: self.primary_ssl,
            slot: Self::SLOT,
            user_data: user_data as *mut std::ffi::c_void,
        });
    }
}

impl Drop for OpenSslExDataHelperHolderWrongHandle {
    fn drop(&mut self) {
        let user_data = openssl_get_ex_data_holder_helper(OpenSslExDataHelperGetHolder {
            ssl: self.secondary_ssl,
            slot: Self::SLOT,
        });
        let _value = unsafe { Box::from_raw(user_data as *mut i32) };
    }
}

impl OpenSslExDataNoRelease {
    const SLOT: i32 = 10;

    #[inline(never)]
    pub fn openssl_ex_data_no_release_registration_site(&mut self) {
        let user_data = Box::into_raw(Box::new(34_i32));
        let _ = openssl_sys::SSL_set_ex_data(
            self.ssl,
            Self::SLOT,
            user_data as *mut std::ffi::c_void,
        );
    }
}

impl Drop for OpenSslExDataNoRelease {
    fn drop(&mut self) {
        let user_data = openssl_sys::SSL_get_ex_data(self.ssl, Self::SLOT);
        let _observed = !user_data.is_null();
    }
}

unsafe extern "C" fn openssl_free_data_box<T>(
    _parent: *mut std::ffi::c_void,
    ptr: *mut std::ffi::c_void,
    _ad: *mut openssl_sys::CRYPTO_EX_DATA,
    _idx: i32,
    _argl: isize,
    _argp: *mut std::ffi::c_void,
) {
    if !ptr.is_null() {
        // The fixture models OpenSSL's exact foreign free callback contract.
        let _value = unsafe { Box::<T>::from_raw(ptr as *mut T) };
    }
}

unsafe extern "C" fn openssl_non_releasing_free_data<T>(
    _parent: *mut std::ffi::c_void,
    _ptr: *mut std::ffi::c_void,
    _ad: *mut openssl_sys::CRYPTO_EX_DATA,
    _idx: i32,
    _argl: isize,
    _argp: *mut std::ffi::c_void,
) {
}

#[inline(never)]
unsafe fn get_new_ssl_idx(free_func: openssl_sys::CRYPTO_EX_free) -> i32 {
    openssl_sys::CRYPTO_get_ex_new_index(
        0,
        0,
        std::ptr::null_mut(),
        None,
        None,
        Some(free_func),
    )
}

#[inline(never)]
unsafe fn get_new_ssl_idx_without_free() -> i32 {
    openssl_sys::CRYPTO_get_ex_new_index(0, 0, std::ptr::null_mut(), None, None, None)
}

impl OpenSslExDataForeignFreeContract {
    #[inline(never)]
    pub fn openssl_ex_data_foreign_free_contract_registration_site(&mut self) {
        let slot = unsafe { get_new_ssl_idx(openssl_free_data_box::<i32>) };
        let user_data = Box::into_raw(Box::new(38_i32));
        let _ = openssl_sys::SSL_set_ex_data(
            self.ssl,
            slot,
            user_data as *mut std::ffi::c_void,
        );
    }
}

impl OpenSslExDataForeignFreeMissingDestructor {
    #[inline(never)]
    pub fn openssl_ex_data_foreign_free_missing_destructor_registration_site(&mut self) {
        let slot = unsafe { get_new_ssl_idx_without_free() };
        let user_data = Box::into_raw(Box::new(39_i32));
        let _ = openssl_sys::SSL_set_ex_data(
            self.ssl,
            slot,
            user_data as *mut std::ffi::c_void,
        );
    }
}

impl OpenSslExDataForeignFreeNonReleasingDestructor {
    #[inline(never)]
    pub fn openssl_ex_data_foreign_free_non_releasing_destructor_registration_site(&mut self) {
        let slot = unsafe { get_new_ssl_idx(openssl_non_releasing_free_data::<i32>) };
        let user_data = Box::into_raw(Box::new(40_i32));
        let _ = openssl_sys::SSL_set_ex_data(
            self.ssl,
            slot,
            user_data as *mut std::ffi::c_void,
        );
    }
}

unsafe extern "C" fn ffi_update_callback(_user_data: *mut std::ffi::c_void) {}

unsafe extern "C" fn ffi_scalar_callback() {}

#[inline(never)]
pub unsafe fn free_i32_user_data(p: *mut std::ffi::c_void) {
    // The fixture models an exact foreign destructor release endpoint only.
    let _value = unsafe { Box::from_raw(p as *mut i32) };
}

unsafe extern "C" fn pyo3_capsule_destructor(capsule: *mut std::ffi::c_void) {
    let ptr = unsafe { pyo3_ffi::PyCapsule_GetPointer(capsule, std::ptr::null()) };
    let _value = unsafe { Box::from_raw(ptr as *mut i32) };
}

#[inline(never)]
pub unsafe fn destructor_without_release(_p: *mut std::ffi::c_void) {}

#[inline(never)]
pub unsafe fn destructor_releases_different_source(_p: *mut std::ffi::c_void) {
    let other = Box::into_raw(Box::new(24_i32));
    let _value = unsafe { Box::from_raw(other) };
}

#[inline(never)]
pub fn unrelated_call() {}

pub fn explicit_drop_site() {
    let object = Retained::new(1);
    drop(object);
}

pub fn scope_end_drop_site() {
    let _object = Retained::new(2);
}

#[inline(never)]
pub fn returned_borrow_relation_site(owner: &Retained) -> &i32 {
    &owner.value
}

#[inline(never)]
pub fn external_buffer_binding_site(source: &[u8]) -> ExternalBuffer {
    ExternalBuffer {
        raw: source.as_ptr(),
        len: source.len(),
    }
}

#[inline(never)]
pub fn foreign_selector_unbound_returned_buffer_site<'a>(
    server: &[u8],
    client: &'a [u8],
) -> Option<&'a [u8]> {
    let mut out = std::ptr::null();
    let mut outlen = 0_u8;
    let status = unsafe {
        openssl_sys::SSL_select_next_proto(
            &mut out,
            &mut outlen,
            server.as_ptr(),
            server.len() as u32,
            client.as_ptr(),
            client.len() as u32,
        )
    };
    if status == openssl_sys::OPENSSL_NPN_NEGOTIATED {
        Some(unsafe { std::slice::from_raw_parts(out, outlen as usize) })
    } else {
        None
    }
}

#[inline(never)]
pub fn foreign_selector_bound_returned_buffer_site<'a>(
    server: &'a [u8],
    client: &'a [u8],
) -> Option<&'a [u8]> {
    let mut out = std::ptr::null();
    let mut outlen = 0_u8;
    let status = unsafe {
        openssl_sys::SSL_select_next_proto(
            &mut out,
            &mut outlen,
            server.as_ptr(),
            server.len() as u32,
            client.as_ptr(),
            client.len() as u32,
        )
    };
    if status == openssl_sys::OPENSSL_NPN_NEGOTIATED {
        Some(unsafe { std::slice::from_raw_parts(out, outlen as usize) })
    } else {
        None
    }
}

#[inline(never)]
pub fn neon_external_buffer_creation_site<T>(env: NeonEnv, data: T) -> neon_runtime::raw::Local
where
    T: AsMut<[u8]> + Send,
{
    unsafe { neon_runtime::buffer::new_external(env.to_raw(), data) }
}

#[inline(never)]
pub fn neon_external_arraybuffer_creation_site<T>(
    env: NeonEnv,
    data: T,
) -> neon_runtime::raw::Local
where
    T: AsMut<[u8]> + Send,
{
    unsafe { neon_runtime::arraybuffer::new_external(env.to_raw(), data) }
}

pub fn update_hook_registration_site() {
    let conn = Connection;
    let state = Retained::new(3);
    let callback = move |_operation| {
        let _ = state.value();
    };
    conn.update_hook(Some(callback));
}

pub fn named_update_callback(_operation: i32) {}

pub fn update_hook_named_registration_site() {
    let conn = Connection;
    conn.update_hook(Some(named_update_callback));
}

pub fn update_hook_unregister_site() {
    let conn = Connection;
    conn.update_hook(None::<fn(i32)>);
}

pub fn update_hook_forwarded_callback<F>(callback: Option<F>)
where
    F: FnMut(i32) + 'static,
{
    let conn = Connection;
    conn.update_hook(callback);
}

pub fn unrelated_update_hook_site() {
    let conn = unrelated_component::Connection;
    conn.update_hook(Some(|_operation| {}));
}

pub fn closure_owner_drop_site() {
    let state = Retained::new(4);
    let callback = move || state.value();
    drop(callback);
}

pub fn scalar_registration_site() {
    let conn = Connection;
    conn.create_scalar_function("value", || 1);
}

pub fn foreign_destructor_release_registration_site() {
    let user_data = Box::into_raw(Box::new(23_i32));
    let _ = libsqlite3_sys::bindings::sqlite3_create_function_v2(
        std::ptr::null_mut(),
        b"value\0".as_ptr() as *const i8,
        0,
        0,
        user_data as *mut std::ffi::c_void,
        Some(ffi_scalar_callback),
        None,
        None,
        Some(free_i32_user_data),
    );
}

pub fn foreign_destructor_missing_registration_site() {
    let user_data = Box::into_raw(Box::new(24_i32));
    let _ = libsqlite3_sys::bindings::sqlite3_create_function_v2(
        std::ptr::null_mut(),
        b"value\0".as_ptr() as *const i8,
        0,
        0,
        user_data as *mut std::ffi::c_void,
        Some(ffi_scalar_callback),
        None,
        None,
        None,
    );
}

pub fn foreign_destructor_different_source_registration_site() {
    let user_data = Box::into_raw(Box::new(25_i32));
    let _ = libsqlite3_sys::bindings::sqlite3_create_function_v2(
        std::ptr::null_mut(),
        b"value\0".as_ptr() as *const i8,
        0,
        0,
        user_data as *mut std::ffi::c_void,
        Some(ffi_scalar_callback),
        None,
        None,
        Some(destructor_releases_different_source),
    );
}

pub fn pyo3_capsule_release_registration_site() {
    let user_data = Box::into_raw(Box::new(31_i32));
    let _ = unsafe {
        pyo3_ffi::PyCapsule_New(
            user_data as *mut std::ffi::c_void,
            std::ptr::null(),
            Some(pyo3_capsule_destructor),
        )
    };
}

pub fn previous_hook_release_registration_site() {
    let mut state = HookReleaseState {
        free_hook: Some(free_i32_user_data),
    };
    let user_data = Box::into_raw(Box::new(26_i32));
    let previous_hook = libsqlite3_sys::bindings::sqlite3_update_hook(
        std::ptr::null_mut(),
        Some(ffi_update_callback),
        user_data as *mut std::ffi::c_void,
    );
    if !previous_hook.is_null() {
        if let Some(free_hook) = state.free_hook {
            unsafe { free_hook(previous_hook) };
        }
    }
    state.free_hook = Some(free_i32_user_data);
    let _free_hook_reinstalled = state.free_hook;
}

pub fn previous_hook_non_releasing_free_registration_site() {
    let state = HookReleaseState {
        free_hook: Some(destructor_without_release),
    };
    let user_data = Box::into_raw(Box::new(27_i32));
    let previous_hook = libsqlite3_sys::bindings::sqlite3_update_hook(
        std::ptr::null_mut(),
        Some(ffi_update_callback),
        user_data as *mut std::ffi::c_void,
    );
    if !previous_hook.is_null() {
        if let Some(free_hook) = state.free_hook {
            unsafe { free_hook(previous_hook) };
        }
    }
}

impl HookFieldState {
    #[inline(never)]
    pub fn install_update_hook<F>(&mut self, hook: Option<F>) {
        let free_update_hook = if hook.is_some() {
            Some(free_boxed_hook::<F> as unsafe fn(*mut std::ffi::c_void))
        } else {
            None
        };
        let previous_hook = if let Some(callback) = hook {
            let user_data = Box::into_raw(Box::new(callback));
            libsqlite3_sys::bindings::sqlite3_update_hook(
                std::ptr::null_mut(),
                Some(ffi_update_callback),
                user_data as *mut std::ffi::c_void,
            )
        } else {
            libsqlite3_sys::bindings::sqlite3_update_hook(
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        };
        if !previous_hook.is_null() {
            if let Some(free_hook) = self.free_update_hook {
                unsafe { free_hook(previous_hook) };
            }
        }
        self.free_update_hook = free_update_hook;
    }

    #[inline(never)]
    pub fn install_update_hook_wrong_field(&mut self, install: bool) {
        let free_update_hook = if install {
            Some(free_i32_user_data as unsafe fn(*mut std::ffi::c_void))
        } else {
            None
        };
        let previous_hook = if install {
            let user_data = Box::into_raw(Box::new(29_i32));
            libsqlite3_sys::bindings::sqlite3_update_hook(
                std::ptr::null_mut(),
                Some(ffi_update_callback),
                user_data as *mut std::ffi::c_void,
            )
        } else {
            libsqlite3_sys::bindings::sqlite3_update_hook(
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        };
        if !previous_hook.is_null() {
            if let Some(free_hook) = self.free_commit_hook {
                unsafe { free_hook(previous_hook) };
            }
        }
        self.free_update_hook = free_update_hook;
    }

    #[inline(never)]
    pub fn install_update_hook_non_releasing_field(&mut self, install: bool) {
        let free_update_hook = if install {
            Some(destructor_without_release as unsafe fn(*mut std::ffi::c_void))
        } else {
            None
        };
        let previous_hook = if install {
            let user_data = Box::into_raw(Box::new(30_i32));
            libsqlite3_sys::bindings::sqlite3_update_hook(
                std::ptr::null_mut(),
                Some(ffi_update_callback),
                user_data as *mut std::ffi::c_void,
            )
        } else {
            libsqlite3_sys::bindings::sqlite3_update_hook(
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        };
        if !previous_hook.is_null() {
            if let Some(free_hook) = self.free_update_hook {
                unsafe { free_hook(previous_hook) };
            }
        }
        self.free_update_hook = free_update_hook;
    }
}

pub fn field_state_update_hook_registration_site(install: bool) {
    let mut state = HookFieldState {
        free_update_hook: Some(free_boxed_hook::<i32>),
        free_commit_hook: Some(free_i32_user_data),
    };
    state.install_update_hook(install.then_some(28_i32));
}

pub fn field_state_update_hook_wrong_field_registration_site(install: bool) {
    let mut state = HookFieldState {
        free_update_hook: Some(free_i32_user_data),
        free_commit_hook: Some(free_i32_user_data),
    };
    state.install_update_hook_wrong_field(install);
}

pub fn field_state_update_hook_non_releasing_registration_site(install: bool) {
    let mut state = HookFieldState {
        free_update_hook: Some(destructor_without_release),
        free_commit_hook: Some(free_i32_user_data),
    };
    state.install_update_hook_non_releasing_field(install);
}

pub fn user_data_transfer_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(7_i32));
    conn.set_callback_with_user_data(|| {}, user_data);
    // The fixture models a local release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(user_data) };
}

pub fn ffi_callback_user_data_roundtrip_registration_site() {
    let user_data = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    let _previous = libsqlite3_sys::bindings::sqlite3_update_hook(
        std::ptr::null_mut(),
        Some(retained_userdata_roundtrip_callback),
        user_data as *mut std::ffi::c_void,
    );
    // The fixture models a local release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(user_data) };
}

pub fn ffi_callback_user_data_after_release_use_registration_site() {
    let user_data = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    let _previous = libsqlite3_sys::bindings::sqlite3_update_hook(
        std::ptr::null_mut(),
        Some(retained_userdata_after_release_callback),
        user_data as *mut std::ffi::c_void,
    );
    // The direct callback call is a deterministic local use-order witness for static analysis.
    let _value = unsafe { Box::from_raw(user_data) };
    retained_userdata_after_release_callback(user_data as *mut std::ffi::c_void);
}

pub fn ffi_callback_user_data_before_release_use_registration_site() {
    let user_data = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    let _previous = libsqlite3_sys::bindings::sqlite3_update_hook(
        std::ptr::null_mut(),
        Some(retained_userdata_before_release_callback),
        user_data as *mut std::ffi::c_void,
    );
    retained_userdata_before_release_callback(user_data as *mut std::ffi::c_void);
    let _value = unsafe { Box::from_raw(user_data) };
}

#[inline(never)]
fn install_update_hook_helper(
    callback: Option<unsafe extern "C" fn(*mut std::ffi::c_void)>,
    user_data: *mut std::ffi::c_void,
) {
    let _previous = libsqlite3_sys::bindings::sqlite3_update_hook(
        std::ptr::null_mut(),
        callback,
        user_data,
    );
}

#[inline(never)]
fn maybe_install_update_hook_helper(
    install: bool,
    callback: Option<unsafe extern "C" fn(*mut std::ffi::c_void)>,
    user_data: *mut std::ffi::c_void,
) {
    if install {
        let _previous = libsqlite3_sys::bindings::sqlite3_update_hook(
            std::ptr::null_mut(),
            callback,
            user_data,
        );
    }
}

#[inline(never)]
fn invoke_update_hook_callback_helper(
    callback: extern "C" fn(*mut std::ffi::c_void),
    user_data: *mut std::ffi::c_void,
) {
    callback(user_data);
}

#[inline(never)]
fn invoke_update_hook_callback_alias_helper(
    callback: extern "C" fn(*mut std::ffi::c_void),
    user_data: *mut std::ffi::c_void,
) {
    let callback_alias = callback;
    let user_data_alias = user_data;
    callback_alias(user_data_alias);
}

#[inline(never)]
fn invoke_update_hook_callback_wrong_object_helper(
    callback: extern "C" fn(*mut std::ffi::c_void),
    registered_user_data: *mut std::ffi::c_void,
    other_user_data: *mut std::ffi::c_void,
) {
    let callback_alias = callback;
    let _registered_alias = registered_user_data;
    let other_alias = other_user_data;
    callback_alias(other_alias);
}

#[inline(never)]
fn invoke_update_hook_callback_holder_helper(holder: CallbackInvocationHolder) {
    let holder_alias = holder;
    (holder_alias.callback)(holder_alias.user_data);
}

#[inline(never)]
fn invoke_update_hook_callback_holder_wrong_field_helper(holder: CallbackInvocationPairHolder) {
    let holder_alias = holder;
    let _registered_alias = holder_alias.registered_user_data;
    (holder_alias.callback)(holder_alias.other_user_data);
}

pub fn ffi_callback_user_data_helper_roundtrip_registration_site() {
    let user_data = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    install_update_hook_helper(
        Some(retained_userdata_helper_roundtrip_callback),
        user_data as *mut std::ffi::c_void,
    );
    // The fixture models a local release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(user_data) };
}

pub fn ffi_callback_user_data_helper_after_release_use_registration_site() {
    let user_data = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    let _previous = libsqlite3_sys::bindings::sqlite3_update_hook(
        std::ptr::null_mut(),
        Some(retained_userdata_helper_after_release_callback),
        user_data as *mut std::ffi::c_void,
    );
    // The helper call is a deterministic cross-function use-order witness for static analysis.
    let _value = unsafe { Box::from_raw(user_data) };
    invoke_update_hook_callback_helper(
        retained_userdata_helper_after_release_callback,
        user_data as *mut std::ffi::c_void,
    );
}

pub fn ffi_callback_user_data_helper_before_release_use_registration_site() {
    let user_data = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    let _previous = libsqlite3_sys::bindings::sqlite3_update_hook(
        std::ptr::null_mut(),
        Some(retained_userdata_helper_before_release_callback),
        user_data as *mut std::ffi::c_void,
    );
    invoke_update_hook_callback_helper(
        retained_userdata_helper_before_release_callback,
        user_data as *mut std::ffi::c_void,
    );
    let _value = unsafe { Box::from_raw(user_data) };
}

pub fn ffi_callback_user_data_helper_alias_after_release_use_registration_site() {
    let user_data = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    let _previous = libsqlite3_sys::bindings::sqlite3_update_hook(
        std::ptr::null_mut(),
        Some(retained_userdata_helper_alias_after_release_callback),
        user_data as *mut std::ffi::c_void,
    );
    let _value = unsafe { Box::from_raw(user_data) };
    invoke_update_hook_callback_alias_helper(
        retained_userdata_helper_alias_after_release_callback,
        user_data as *mut std::ffi::c_void,
    );
}

pub fn ffi_callback_user_data_helper_wrong_object_registration_site() {
    let user_data = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    let other_user_data = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    let _previous = libsqlite3_sys::bindings::sqlite3_update_hook(
        std::ptr::null_mut(),
        Some(retained_userdata_helper_wrong_object_callback),
        user_data as *mut std::ffi::c_void,
    );
    let _value = unsafe { Box::from_raw(user_data) };
    invoke_update_hook_callback_wrong_object_helper(
        retained_userdata_helper_wrong_object_callback,
        user_data as *mut std::ffi::c_void,
        other_user_data as *mut std::ffi::c_void,
    );
}

pub fn ffi_callback_user_data_helper_holder_after_release_use_registration_site() {
    let user_data = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    let _previous = libsqlite3_sys::bindings::sqlite3_update_hook(
        std::ptr::null_mut(),
        Some(retained_userdata_helper_holder_after_release_callback),
        user_data as *mut std::ffi::c_void,
    );
    let _value = unsafe { Box::from_raw(user_data) };
    invoke_update_hook_callback_holder_helper(CallbackInvocationHolder {
        callback: retained_userdata_helper_holder_after_release_callback,
        user_data: user_data as *mut std::ffi::c_void,
    });
}

pub fn ffi_callback_user_data_helper_holder_wrong_field_registration_site() {
    let user_data = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    let other_user_data = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    let _previous = libsqlite3_sys::bindings::sqlite3_update_hook(
        std::ptr::null_mut(),
        Some(retained_userdata_helper_holder_wrong_field_callback),
        user_data as *mut std::ffi::c_void,
    );
    let _value = unsafe { Box::from_raw(user_data) };
    invoke_update_hook_callback_holder_wrong_field_helper(CallbackInvocationPairHolder {
        callback: retained_userdata_helper_holder_wrong_field_callback,
        registered_user_data: user_data as *mut std::ffi::c_void,
        other_user_data: other_user_data as *mut std::ffi::c_void,
    });
}

pub fn ffi_callback_user_data_conditional_helper_registration_site(install: bool) {
    let user_data = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    maybe_install_update_hook_helper(
        install,
        Some(retained_userdata_helper_roundtrip_callback),
        user_data as *mut std::ffi::c_void,
    );
    // The fixture models a local release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(user_data) };
}

pub fn ffi_callback_user_data_ambiguous_registration_site() {
    let first = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    let second = Box::into_raw(Box::new(CallbackUserData { finished: None }));
    let _first_previous = libsqlite3_sys::bindings::sqlite3_update_hook(
        std::ptr::null_mut(),
        Some(retained_userdata_ambiguous_callback),
        first as *mut std::ffi::c_void,
    );
    let _second_previous = libsqlite3_sys::bindings::sqlite3_update_hook(
        std::ptr::null_mut(),
        Some(retained_userdata_ambiguous_callback),
        second as *mut std::ffi::c_void,
    );
}

pub fn raw_parts_ownership_transfer_site() -> Vec<u8> {
    let mut slice = vec![1_u8, 2, 3].into_boxed_slice();
    let len = slice.len();
    let cap = slice.len();
    unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), len, cap) }
}

pub fn raw_parts_ownership_transfer_with_forget_site() -> Vec<u8> {
    let mut slice = vec![1_u8, 2, 3].into_boxed_slice();
    let len = slice.len();
    let cap = slice.len();
    let vec = unsafe { Vec::from_raw_parts(slice.as_mut_ptr(), len, cap) };
    std::mem::forget(slice);
    vec
}

pub fn user_data_alias_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(8_i32));
    let user_data_alias = user_data;
    conn.set_callback_with_user_data(|| {}, user_data_alias);
    // The fixture models a local release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(user_data_alias) };
}

pub fn user_data_field_registration_site() {
    let conn = Connection;
    let mut holder = UserDataHolder {
        user_data: std::ptr::null_mut(),
    };
    holder.user_data = Box::into_raw(Box::new(14_i32));
    conn.set_callback_with_user_data(|| {}, holder.user_data);
    // The fixture models a local release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(holder.user_data) };
}

pub fn user_data_different_field_release_registration_site() {
    let conn = Connection;
    let mut holder = UserDataPairHolder {
        registered_user_data: std::ptr::null_mut(),
        released_user_data: std::ptr::null_mut(),
    };
    holder.registered_user_data = Box::into_raw(Box::new(15_i32));
    holder.released_user_data = Box::into_raw(Box::new(16_i32));
    conn.set_callback_with_user_data(|| {}, holder.registered_user_data);
    // The fixture releases a different field and must not prove coverage for the registered field.
    let _value = unsafe { Box::from_raw(holder.released_user_data) };
}

pub fn user_data_field_reassigned_negative_registration_site() {
    let conn = Connection;
    let mut holder = UserDataHolder {
        user_data: std::ptr::null_mut(),
    };
    let registered_user_data = Box::into_raw(Box::new(18_i32));
    let replacement_user_data = Box::into_raw(Box::new(19_i32));
    holder.user_data = registered_user_data;
    conn.set_callback_with_user_data(|| {}, holder.user_data);
    holder.user_data = replacement_user_data;
    // The fixture releases a replacement value and must not prove coverage for the registered value.
    let _value = unsafe { Box::from_raw(holder.user_data) };
}

#[inline(never)]
pub fn passthrough_user_data(user_data: *mut i32) -> *mut i32 {
    user_data
}

pub fn user_data_passthrough_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(9_i32));
    let forwarded_user_data = passthrough_user_data(user_data);
    conn.set_callback_with_user_data(|| {}, forwarded_user_data);
    // The fixture models a local release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(forwarded_user_data) };
}

#[inline(never)]
pub unsafe fn release_user_data_wrapper(user_data: *mut i32) {
    // The fixture models a wrapper release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(user_data) };
}

#[inline(never)]
pub unsafe fn release_holder_user_data_wrapper(holder: UserDataHolder) {
    // The fixture models a wrapper release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(holder.user_data) };
}

pub fn user_data_field_release_wrapper_registration_site() {
    let conn = Connection;
    let mut holder = UserDataHolder {
        user_data: std::ptr::null_mut(),
    };
    holder.user_data = Box::into_raw(Box::new(17_i32));
    conn.set_callback_with_user_data(|| {}, holder.user_data);
    unsafe { release_holder_user_data_wrapper(holder) };
}

pub fn user_data_aggregate_field_release_wrapper_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(23_i32));
    let holder = UserDataHolder { user_data };
    conn.set_callback_with_user_data(|| {}, holder.user_data);
    unsafe { release_holder_user_data_wrapper(holder) };
}

#[inline(never)]
pub fn make_user_data_holder(user_data: *mut i32) -> UserDataHolder {
    UserDataHolder { user_data }
}

#[inline(never)]
pub fn make_user_data_pair_holder(
    registered_user_data: *mut i32,
    released_user_data: *mut i32,
) -> UserDataPairHolder {
    UserDataPairHolder {
        registered_user_data,
        released_user_data,
    }
}

pub fn user_data_helper_return_field_release_wrapper_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(28_i32));
    let holder = make_user_data_holder(user_data);
    conn.set_callback_with_user_data(|| {}, holder.user_data);
    unsafe { release_holder_user_data_wrapper(holder) };
}

pub fn user_data_helper_return_different_field_release_wrapper_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(29_i32));
    let released_user_data = Box::into_raw(Box::new(30_i32));
    let holder = make_user_data_pair_holder(registered_user_data, released_user_data);
    conn.set_callback_with_user_data(|| {}, holder.registered_user_data);
    unsafe { release_pair_released_field_wrapper(holder) };
}

pub fn user_data_helper_return_field_reassigned_negative_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(31_i32));
    let released_user_data = Box::into_raw(Box::new(32_i32));
    let mut holder = make_user_data_holder(registered_user_data);
    conn.set_callback_with_user_data(|| {}, holder.user_data);
    holder = make_user_data_holder(released_user_data);
    unsafe { release_holder_user_data_wrapper(holder) };
}

#[inline(never)]
pub unsafe fn release_nested_holder_user_data_wrapper(holder: NestedUserDataHolder) {
    // The fixture models a nested wrapper release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(holder.inner.user_data) };
}

#[inline(never)]
pub unsafe fn release_nested_pair_released_field_wrapper(holder: NestedUserDataPairHolder) {
    // This wrapper releases a nested sibling field and must not cover the registered field.
    let _value = unsafe { Box::from_raw(holder.inner.released_user_data) };
}

#[inline(never)]
pub fn make_nested_user_data_holder(user_data: *mut i32) -> NestedUserDataHolder {
    NestedUserDataHolder {
        inner: UserDataHolder { user_data },
    }
}

pub fn user_data_nested_aggregate_field_release_wrapper_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(33_i32));
    let inner = UserDataHolder { user_data };
    let holder = NestedUserDataHolder { inner };
    conn.set_callback_with_user_data(|| {}, holder.inner.user_data);
    unsafe { release_nested_holder_user_data_wrapper(holder) };
}

pub fn user_data_nested_aggregate_different_field_release_wrapper_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(34_i32));
    let released_user_data = Box::into_raw(Box::new(35_i32));
    let inner = UserDataPairHolder {
        registered_user_data,
        released_user_data,
    };
    let holder = NestedUserDataPairHolder { inner };
    conn.set_callback_with_user_data(|| {}, holder.inner.registered_user_data);
    unsafe { release_nested_pair_released_field_wrapper(holder) };
}

pub fn user_data_nested_aggregate_field_reassigned_negative_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(36_i32));
    let released_user_data = Box::into_raw(Box::new(37_i32));
    let mut holder = NestedUserDataHolder {
        inner: UserDataHolder {
            user_data: registered_user_data,
        },
    };
    conn.set_callback_with_user_data(|| {}, holder.inner.user_data);
    holder = NestedUserDataHolder {
        inner: UserDataHolder {
            user_data: released_user_data,
        },
    };
    unsafe { release_nested_holder_user_data_wrapper(holder) };
}

pub fn user_data_helper_return_nested_field_release_wrapper_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(38_i32));
    let holder = make_nested_user_data_holder(user_data);
    conn.set_callback_with_user_data(|| {}, holder.inner.user_data);
    unsafe { release_nested_holder_user_data_wrapper(holder) };
}

#[inline(never)]
pub unsafe fn release_tuple_user_data_wrapper(holder: (*mut i32,)) {
    // The fixture models a tuple wrapper release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(holder.0) };
}

#[inline(never)]
pub unsafe fn release_tuple_second_field_wrapper(holder: (*mut i32, *mut i32)) {
    // This wrapper releases a sibling tuple field and must not cover the registered field.
    let _value = unsafe { Box::from_raw(holder.1) };
}

#[inline(never)]
pub fn make_user_data_tuple_holder(user_data: *mut i32) -> (*mut i32,) {
    (user_data,)
}

pub fn user_data_tuple_aggregate_field_release_wrapper_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(39_i32));
    let holder = (user_data,);
    conn.set_callback_with_user_data(|| {}, holder.0);
    unsafe { release_tuple_user_data_wrapper(holder) };
}

pub fn user_data_helper_return_tuple_field_release_wrapper_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(40_i32));
    let holder = make_user_data_tuple_holder(user_data);
    conn.set_callback_with_user_data(|| {}, holder.0);
    unsafe { release_tuple_user_data_wrapper(holder) };
}

pub fn user_data_tuple_aggregate_different_field_release_wrapper_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(41_i32));
    let released_user_data = Box::into_raw(Box::new(42_i32));
    let holder = (registered_user_data, released_user_data);
    conn.set_callback_with_user_data(|| {}, holder.0);
    unsafe { release_tuple_second_field_wrapper(holder) };
}

pub fn user_data_tuple_aggregate_field_reassigned_negative_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(43_i32));
    let released_user_data = Box::into_raw(Box::new(44_i32));
    let mut holder = (registered_user_data,);
    conn.set_callback_with_user_data(|| {}, holder.0);
    holder = (released_user_data,);
    unsafe { release_tuple_user_data_wrapper(holder) };
}

#[inline(never)]
pub fn make_option_user_data_holder(user_data: *mut i32) -> Option<*mut i32> {
    Some(user_data)
}

pub fn user_data_option_field_release_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(45_i32));
    let holder = Some(user_data);
    let Some(stored_user_data) = holder else {
        return;
    };
    conn.set_callback_with_user_data(|| {}, stored_user_data);
    // The fixture models a local release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(stored_user_data) };
}

pub fn user_data_helper_return_option_field_release_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(46_i32));
    let holder = make_option_user_data_holder(user_data);
    let Some(stored_user_data) = holder else {
        return;
    };
    conn.set_callback_with_user_data(|| {}, stored_user_data);
    // The fixture models a local release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(stored_user_data) };
}

pub fn user_data_option_field_reassigned_negative_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(47_i32));
    let released_user_data = Box::into_raw(Box::new(48_i32));
    let mut holder = Some(registered_user_data);
    if let Some(stored_user_data) = holder {
        conn.set_callback_with_user_data(|| {}, stored_user_data);
    }
    holder = Some(released_user_data);
    let Some(stored_user_data) = holder else {
        return;
    };
    // The fixture releases a replacement value and must not prove coverage for the registered value.
    let _value = unsafe { Box::from_raw(stored_user_data) };
}

#[inline(never)]
pub fn make_result_user_data_holder(user_data: *mut i32) -> Result<*mut i32, ()> {
    Ok(user_data)
}

pub fn user_data_result_ok_field_release_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(49_i32));
    let holder = Ok::<*mut i32, ()>(user_data);
    let Ok(stored_user_data) = holder else {
        return;
    };
    conn.set_callback_with_user_data(|| {}, stored_user_data);
    // The fixture models a local release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(stored_user_data) };
}

pub fn user_data_helper_return_result_ok_field_release_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(50_i32));
    let holder = make_result_user_data_holder(user_data);
    let Ok(stored_user_data) = holder else {
        return;
    };
    conn.set_callback_with_user_data(|| {}, stored_user_data);
    // The fixture models a local release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(stored_user_data) };
}

pub fn user_data_result_err_field_negative_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(51_i32));
    let released_user_data = Box::into_raw(Box::new(52_i32));
    conn.set_callback_with_user_data(|| {}, registered_user_data);
    let holder = Err::<(), *mut i32>(released_user_data);
    let Err(stored_user_data) = holder else {
        return;
    };
    // Only Result::Ok is a supported success holder in this slice; Err must not be linked.
    let _value = unsafe { Box::from_raw(stored_user_data) };
}

#[inline(never)]
pub unsafe fn release_boxed_holder_user_data_wrapper(holder: Box<UserDataHolder>) {
    // The fixture models a unique-owner wrapper release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(holder.user_data) };
}

#[inline(never)]
pub unsafe fn release_boxed_pair_released_field_wrapper(holder: Box<UserDataPairHolder>) {
    // This wrapper releases a sibling field and must not cover the registered field.
    let _value = unsafe { Box::from_raw(holder.released_user_data) };
}

#[inline(never)]
pub unsafe fn release_arc_holder_user_data_wrapper(holder: std::sync::Arc<UserDataHolder>) {
    // The fixture models a shared-owner wrapper release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(holder.user_data) };
}

#[inline(never)]
pub unsafe fn release_arc_pair_released_field_wrapper(holder: std::sync::Arc<UserDataPairHolder>) {
    // This wrapper releases a sibling field and must not cover the registered field.
    let _value = unsafe { Box::from_raw(holder.released_user_data) };
}

#[inline(never)]
pub unsafe fn release_rc_holder_user_data_wrapper(holder: std::rc::Rc<UserDataHolder>) {
    // The fixture models a shared-owner wrapper release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(holder.user_data) };
}

#[inline(never)]
pub unsafe fn release_nonnull_holder_user_data_wrapper(holder: NonNullUserDataHolder) {
    // The fixture models a NonNull holder release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(holder.user_data.as_ptr()) };
}

#[inline(never)]
pub unsafe fn release_nonnull_pair_released_field_wrapper(holder: NonNullUserDataPairHolder) {
    // This wrapper releases a sibling NonNull field and must not cover the registered field.
    let _value = unsafe { Box::from_raw(holder.released_user_data.as_ptr()) };
}

pub fn user_data_boxed_holder_release_wrapper_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(53_i32));
    let inner = UserDataHolder { user_data };
    let holder = Box::new(inner);
    conn.set_callback_with_user_data(|| {}, holder.user_data);
    unsafe { release_boxed_holder_user_data_wrapper(holder) };
}

pub fn user_data_boxed_pair_different_field_release_wrapper_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(54_i32));
    let released_user_data = Box::into_raw(Box::new(55_i32));
    let inner = UserDataPairHolder {
        registered_user_data,
        released_user_data,
    };
    let holder = Box::new(inner);
    conn.set_callback_with_user_data(|| {}, holder.registered_user_data);
    unsafe { release_boxed_pair_released_field_wrapper(holder) };
}

pub fn user_data_arc_holder_release_wrapper_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(58_i32));
    let inner = UserDataHolder { user_data };
    let holder = std::sync::Arc::new(inner);
    conn.set_callback_with_user_data(|| {}, holder.user_data);
    unsafe { release_arc_holder_user_data_wrapper(holder) };
}

pub fn user_data_arc_clone_holder_release_wrapper_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(65_i32));
    let inner = UserDataHolder { user_data };
    let holder = std::sync::Arc::new(inner);
    let release_holder = holder.clone();
    conn.set_callback_with_user_data(|| {}, holder.user_data);
    unsafe { release_arc_holder_user_data_wrapper(release_holder) };
}

pub fn user_data_arc_pair_different_field_release_wrapper_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(59_i32));
    let released_user_data = Box::into_raw(Box::new(60_i32));
    let inner = UserDataPairHolder {
        registered_user_data,
        released_user_data,
    };
    let holder = std::sync::Arc::new(inner);
    conn.set_callback_with_user_data(|| {}, holder.registered_user_data);
    unsafe { release_arc_pair_released_field_wrapper(holder) };
}

pub fn user_data_arc_clone_pair_different_field_release_wrapper_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(66_i32));
    let released_user_data = Box::into_raw(Box::new(67_i32));
    let inner = UserDataPairHolder {
        registered_user_data,
        released_user_data,
    };
    let holder = std::sync::Arc::new(inner);
    let release_holder = holder.clone();
    conn.set_callback_with_user_data(|| {}, holder.registered_user_data);
    unsafe { release_arc_pair_released_field_wrapper(release_holder) };
}

pub fn user_data_rc_holder_release_wrapper_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(61_i32));
    let inner = UserDataHolder { user_data };
    let holder = std::rc::Rc::new(inner);
    conn.set_callback_with_user_data(|| {}, holder.user_data);
    unsafe { release_rc_holder_user_data_wrapper(holder) };
}

pub fn user_data_rc_clone_holder_release_wrapper_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(68_i32));
    let inner = UserDataHolder { user_data };
    let holder = std::rc::Rc::new(inner);
    let release_holder = holder.clone();
    conn.set_callback_with_user_data(|| {}, holder.user_data);
    unsafe { release_rc_holder_user_data_wrapper(release_holder) };
}

pub fn user_data_nonnull_holder_release_wrapper_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(62_i32));
    let holder = NonNullUserDataHolder {
        user_data: unsafe { std::ptr::NonNull::new_unchecked(user_data) },
    };
    conn.set_callback_with_user_data(|| {}, holder.user_data.as_ptr());
    unsafe { release_nonnull_holder_user_data_wrapper(holder) };
}

pub fn user_data_nonnull_pair_different_field_release_wrapper_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(63_i32));
    let released_user_data = Box::into_raw(Box::new(64_i32));
    let holder = NonNullUserDataPairHolder {
        registered_user_data: unsafe { std::ptr::NonNull::new_unchecked(registered_user_data) },
        released_user_data: unsafe { std::ptr::NonNull::new_unchecked(released_user_data) },
    };
    conn.set_callback_with_user_data(|| {}, holder.registered_user_data.as_ptr());
    unsafe { release_nonnull_pair_released_field_wrapper(holder) };
}

pub fn user_data_boxed_holder_reassigned_negative_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(56_i32));
    let released_user_data = Box::into_raw(Box::new(57_i32));
    let mut holder = Box::new(UserDataHolder {
        user_data: registered_user_data,
    });
    conn.set_callback_with_user_data(|| {}, holder.user_data);
    holder = Box::new(UserDataHolder {
        user_data: released_user_data,
    });
    unsafe { release_boxed_holder_user_data_wrapper(holder) };
}

#[inline(never)]
pub unsafe fn release_pair_released_field_wrapper(holder: UserDataPairHolder) {
    // This wrapper releases a different field and must not cover the registered field.
    let _value = unsafe { Box::from_raw(holder.released_user_data) };
}

pub fn user_data_different_field_release_wrapper_registration_site() {
    let conn = Connection;
    let mut holder = UserDataPairHolder {
        registered_user_data: std::ptr::null_mut(),
        released_user_data: std::ptr::null_mut(),
    };
    holder.registered_user_data = Box::into_raw(Box::new(18_i32));
    holder.released_user_data = Box::into_raw(Box::new(19_i32));
    conn.set_callback_with_user_data(|| {}, holder.registered_user_data);
    unsafe { release_pair_released_field_wrapper(holder) };
}

pub fn user_data_aggregate_different_field_release_wrapper_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(24_i32));
    let released_user_data = Box::into_raw(Box::new(25_i32));
    let holder = UserDataPairHolder {
        registered_user_data,
        released_user_data,
    };
    conn.set_callback_with_user_data(|| {}, holder.registered_user_data);
    unsafe { release_pair_released_field_wrapper(holder) };
}

pub fn user_data_aggregate_field_reassigned_negative_registration_site() {
    let conn = Connection;
    let registered_user_data = Box::into_raw(Box::new(26_i32));
    let released_user_data = Box::into_raw(Box::new(27_i32));
    let mut holder = UserDataHolder {
        user_data: registered_user_data,
    };
    conn.set_callback_with_user_data(|| {}, holder.user_data);
    holder = UserDataHolder {
        user_data: released_user_data,
    };
    unsafe { release_holder_user_data_wrapper(holder) };
}

pub fn user_data_receiver_method_release_registration_site() {
    let conn = Connection;
    let mut holder = UserDataHolder {
        user_data: std::ptr::null_mut(),
    };
    holder.user_data = Box::into_raw(Box::new(20_i32));
    conn.set_callback_with_user_data(|| {}, holder.user_data);
    unsafe { holder.release_user_data_method() };
}

pub fn user_data_different_field_receiver_method_registration_site() {
    let conn = Connection;
    let mut holder = UserDataPairHolder {
        registered_user_data: std::ptr::null_mut(),
        released_user_data: std::ptr::null_mut(),
    };
    holder.registered_user_data = Box::into_raw(Box::new(21_i32));
    holder.released_user_data = Box::into_raw(Box::new(22_i32));
    conn.set_callback_with_user_data(|| {}, holder.registered_user_data);
    unsafe { holder.release_released_field_method() };
}

pub fn user_data_release_wrapper_registration_site() {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(12_i32));
    conn.set_callback_with_user_data(|| {}, user_data);
    unsafe { release_user_data_wrapper(user_data) };
}

#[inline(never)]
pub unsafe fn conditional_release_user_data_wrapper(user_data: *mut i32, release: bool) {
    if release {
        // Conditional release is intentionally not sufficient for a release path proof.
        let _value = unsafe { Box::from_raw(user_data) };
    }
}

pub fn user_data_conditional_release_wrapper_registration_site(release: bool) {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(13_i32));
    conn.set_callback_with_user_data(|| {}, user_data);
    unsafe { conditional_release_user_data_wrapper(user_data, release) };
}

pub fn local_sqlite3_update_hook_same_name_site() {
    let user_data = Box::into_raw(Box::new(11_i32));
    sqlite3_update_hook(
        std::ptr::null_mut(),
        Some(ffi_update_callback),
        user_data as *mut std::ffi::c_void,
    );
    // The fixture models a local release endpoint only. It does not assert any real defect.
    let _value = unsafe { Box::from_raw(user_data) };
}

pub fn user_data_branch_without_proven_release_registration_site(release: bool) {
    let conn = Connection;
    let user_data = Box::into_raw(Box::new(10_i32));
    conn.set_callback_with_user_data(|| {}, user_data);
    if release {
        // This fixture has a conditional local endpoint only; it expresses no defect conclusion.
        let _value = unsafe { Box::from_raw(user_data) };
    }
}

pub fn unrelated_call_site() {
    unrelated_call();
}

pub unsafe fn unknown_extern_call_site() -> i32 {
    unsafe { sqlite3_step() }
}

pub fn callback_trampoline_invoke_site() {
    sqlite_callback_trampoline();
}
