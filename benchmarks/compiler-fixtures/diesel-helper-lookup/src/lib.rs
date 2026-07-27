use std::{collections::HashMap, ffi::CStr};

pub fn lookup_borrowed<'map, 'a>(
    column_names: &'map HashMap<String, &'a CStr>,
    key: &str,
) -> Option<&'a CStr> {
    column_names.get(key).copied()
}
