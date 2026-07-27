pub mod sqlite {
    pub mod connection {
        pub mod raw {
            use std::ffi::c_void;

            pub mod ffi {
                use std::ffi::c_void;

                unsafe extern "C" {
                    pub fn sqlite3_create_function_v2(
                        db: *mut i32,
                        name: *const i8,
                        n_arg: i32,
                        flags: i32,
                        user_data: *mut c_void,
                        x_func: Option<unsafe extern "C" fn()>,
                        x_step: Option<unsafe extern "C" fn()>,
                        x_final: Option<unsafe extern "C" fn()>,
                        x_destroy: Option<unsafe extern "C" fn(*mut c_void)>,
                    ) -> i32;
                }
            }

            unsafe extern "C" fn run_custom_function() {}

            unsafe extern "C" fn destroy_boxed_fn(data: *mut c_void) {
                let _value = unsafe { Box::from_raw(data as *mut i32) };
            }

            pub struct DropImplSqlFunction {
                user_data: *mut i32,
            }

            impl Drop for DropImplSqlFunction {
                fn drop(&mut self) {
                    let _value = unsafe { Box::from_raw(self.user_data) };
                }
            }

            pub struct DropImplSqlFunctionPair {
                registered_user_data: *mut i32,
                released_user_data: *mut i32,
            }

            impl Drop for DropImplSqlFunctionPair {
                fn drop(&mut self) {
                    let _value = unsafe { Box::from_raw(self.released_user_data) };
                }
            }

            pub fn register_sql_function_site() {
                let callback_fn = Box::into_raw(Box::new(7_i32));
                let _ = unsafe {
                    ffi::sqlite3_create_function_v2(
                        std::ptr::null_mut(),
                        b"value\0".as_ptr() as *const i8,
                        0,
                        0,
                        callback_fn as *mut c_void,
                        Some(run_custom_function),
                        None,
                        None,
                        Some(destroy_boxed_fn),
                    )
                };
            }

            pub fn register_sql_function_drop_impl_release_site() {
                let mut holder = DropImplSqlFunction {
                    user_data: std::ptr::null_mut(),
                };
                holder.user_data = Box::into_raw(Box::new(8_i32));
                let _ = unsafe {
                    ffi::sqlite3_create_function_v2(
                        std::ptr::null_mut(),
                        b"value\0".as_ptr() as *const i8,
                        0,
                        0,
                        holder.user_data as *mut c_void,
                        Some(run_custom_function),
                        None,
                        None,
                        None,
                    )
                };
            }

            pub fn register_sql_function_wrong_field_drop_impl_release_site() {
                let mut holder = DropImplSqlFunctionPair {
                    registered_user_data: std::ptr::null_mut(),
                    released_user_data: std::ptr::null_mut(),
                };
                holder.registered_user_data = Box::into_raw(Box::new(9_i32));
                holder.released_user_data = Box::into_raw(Box::new(10_i32));
                let _ = unsafe {
                    ffi::sqlite3_create_function_v2(
                        std::ptr::null_mut(),
                        b"value\0".as_ptr() as *const i8,
                        0,
                        0,
                        holder.registered_user_data as *mut c_void,
                        Some(run_custom_function),
                        None,
                        None,
                        None,
                    )
                };
            }
        }

        pub mod stmt {
            use std::borrow::Borrow;
            use std::cell::RefCell;
            use std::collections::{HashMap, VecDeque, hash_map::Entry};
            use std::ffi::CStr;
            use std::hash::{Hash, Hasher};
            use std::sync::Arc;

            pub mod ffi {
                unsafe extern "C" {
                    pub fn sqlite3_column_name(stmt: *mut i32, idx: i32) -> *const i8;
                }
            }

            pub struct Statement {
                inner_statement: *mut i32,
            }

            impl Statement {
                pub fn new(inner_statement: *mut i32) -> Self {
                    Self { inner_statement }
                }

                pub unsafe fn field_name<'a>(&self, idx: usize) -> Option<&'a CStr> {
                    let ptr = unsafe { ffi::sqlite3_column_name(self.inner_statement, idx as i32) };
                    if ptr.is_null() {
                        None
                    } else {
                        Some(unsafe { CStr::from_ptr(ptr) })
                    }
                }
            }

            fn placeholder_column_name<'a>() -> &'a CStr {
                unsafe { CStr::from_bytes_with_nul_unchecked(b"placeholder\0") }
            }

            fn observe_column_name<'a>(name: Option<&'a CStr>) -> Option<&'a CStr> {
                name
            }

            fn discard_column_name<'a>(_name: Option<&'a CStr>) -> Option<&'a CStr> {
                None
            }

            struct ColumnNameWrapper<'a> {
                name: Option<&'a CStr>,
                other_name: Option<&'a CStr>,
            }

            struct ColumnSlot<'a> {
                column: &'a CStr,
                marker: usize,
            }

            impl<'a> ColumnNameWrapper<'a> {
                fn into_inner(self) -> Option<&'a CStr> {
                    self.name
                }

                fn into_other(self) -> Option<&'a CStr> {
                    self.other_name
                }

                fn discard(self) -> Option<&'a CStr> {
                    None
                }

                fn take_inner(&mut self) -> Option<&'a CStr> {
                    self.name.take()
                }

                fn take_other(&mut self) -> Option<&'a CStr> {
                    self.other_name.take()
                }

                fn mem_take_inner(&mut self) -> Option<&'a CStr> {
                    std::mem::take(&mut self.name)
                }

                fn replace_inner_none(&mut self) -> Option<&'a CStr> {
                    std::mem::replace(&mut self.name, None)
                }
            }

            fn helper_column_key(name: &str) -> String {
                name.to_owned()
            }

            fn unrelated_column_key(name: &str) -> String {
                format!("unrelated:{name}")
            }

            #[derive(Clone, Debug, Eq, Hash, PartialEq)]
            struct ColumnKey(String);

            impl ColumnKey {
                fn new(name: &str) -> Self {
                    Self(name.to_owned())
                }

                fn helper_new(name: &str) -> Self {
                    Self(helper_column_key(name))
                }

                fn ambiguous(name: &str, other: &str, use_name: bool) -> Self {
                    if use_name {
                        Self(name.to_owned())
                    } else {
                        Self(other.to_owned())
                    }
                }
            }

            impl Borrow<str> for ColumnKey {
                fn borrow(&self) -> &str {
                    &self.0
                }
            }

            #[derive(Clone, Debug, Eq, Hash, PartialEq)]
            struct SaltedColumnKey(String, usize);

            impl SaltedColumnKey {
                fn new(name: &str, salt: usize) -> Self {
                    Self(name.to_owned(), salt)
                }
            }

            impl Borrow<str> for SaltedColumnKey {
                fn borrow(&self) -> &str {
                    &self.0
                }
            }

            #[derive(Clone, Debug, Eq, Hash, PartialEq)]
            struct DuplicateColumnKey(String, String);

            impl DuplicateColumnKey {
                fn new(name: &str) -> Self {
                    Self(name.to_owned(), name.to_owned())
                }
            }

            impl Borrow<str> for DuplicateColumnKey {
                fn borrow(&self) -> &str {
                    &self.0
                }
            }

            #[derive(Clone, Debug)]
            struct ManualHashColumnKey(String);

            impl ManualHashColumnKey {
                fn new(name: &str) -> Self {
                    Self(name.to_owned())
                }
            }

            impl PartialEq for ManualHashColumnKey {
                fn eq(&self, other: &Self) -> bool {
                    self.0 == other.0
                }
            }

            impl Eq for ManualHashColumnKey {}

            impl Hash for ManualHashColumnKey {
                fn hash<H: Hasher>(&self, state: &mut H) {
                    0usize.hash(state);
                }
            }

            impl Borrow<str> for ManualHashColumnKey {
                fn borrow(&self) -> &str {
                    &self.0
                }
            }

            fn ambiguous_column_key(name: &str, other: &str, use_name: bool) -> String {
                if use_name {
                    name.to_owned()
                } else {
                    other.to_owned()
                }
            }

            fn lookup_column<'a>(
                column_names: &HashMap<String, &'a CStr>,
                name: &str,
            ) -> Option<&'a CStr> {
                column_names.get(name).copied()
            }

            fn nested_lookup_column<'a>(
                column_names: &HashMap<String, &'a CStr>,
                name: &str,
            ) -> Option<&'a CStr> {
                lookup_column(column_names, name)
            }

            fn lookup_column_slot<'a>(
                column_names: &HashMap<String, ColumnSlot<'a>>,
                name: &str,
            ) -> Option<&'a CStr> {
                column_names.get(name).map(|slot| {
                    let _marker = slot.marker;
                    slot.column
                })
            }

            fn ambiguous_lookup_column<'a>(
                column_names: &HashMap<String, &'a CStr>,
                fallback: &HashMap<String, &'a CStr>,
                name: &str,
                use_primary: bool,
            ) -> Option<&'a CStr> {
                if use_primary {
                    column_names.get(name).copied()
                } else {
                    fallback.get(name).copied()
                }
            }

            fn remove_column(column_names: &mut HashMap<String, &CStr>, name: &str) {
                column_names.remove(name);
            }

            fn remove_column_return<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &str,
            ) -> Option<&'a CStr> {
                column_names.remove(name)
            }

            fn remove_other_column_return<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &str,
            ) -> Option<&'a CStr> {
                column_names.remove(unrelated_column_key(name).as_str())
            }

            fn nested_remove_column(column_names: &mut HashMap<String, &CStr>, name: &str) {
                remove_column(column_names, name);
            }

            fn nested_remove_column_with_ambiguous_key(
                column_names: &mut HashMap<String, &CStr>,
                name: &str,
                other: &str,
                use_name: bool,
            ) {
                let key = ambiguous_column_key(name, other, use_name);
                nested_remove_column(column_names, &key);
            }

            fn clear_columns(column_names: &mut HashMap<String, &CStr>) {
                column_names.clear();
            }

            fn nested_clear_columns(column_names: &mut HashMap<String, &CStr>) {
                clear_columns(column_names);
            }

            fn returned_column<'a>(stmt: &'a Statement) -> Option<&'a CStr> {
                unsafe { stmt.field_name(1) }
            }

            fn ambiguous_returned_column<'a>(
                stmt: &'a Statement,
                use_first: bool,
            ) -> Option<&'a CStr> {
                if use_first {
                    unsafe { stmt.field_name(1) }
                } else {
                    unsafe { stmt.field_name(2) }
                }
            }

            fn replace_column_with_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    column_names.insert(helper_column_key(name), column);
                }
            }

            fn replace_column_with_placeholder<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
            ) {
                column_names.insert(helper_column_key(name), placeholder_column_name());
            }

            fn replace_column_with_returned_helper<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = returned_column(stmt) {
                    column_names.insert(helper_column_key(name), column);
                }
            }

            fn replace_column_with_ambiguous_returned_helper<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
                use_first: bool,
            ) {
                if let Some(column) = ambiguous_returned_column(stmt, use_first) {
                    column_names.insert(helper_column_key(name), column);
                }
            }

            fn replace_column_with_entry_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    column_names
                        .entry(helper_column_key(name))
                        .insert_entry(column);
                }
            }

            fn replace_column_with_entry_placeholder<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
            ) {
                column_names
                    .entry(helper_column_key(name))
                    .insert_entry(placeholder_column_name());
            }

            fn replace_column_with_entry_insert_entry_get_mut_assignment_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    let mut entry = column_names
                        .entry(helper_column_key(name))
                        .insert_entry(placeholder_column_name());
                    let slot = entry.get_mut();
                    *slot = column;
                }
            }

            fn replace_column_with_entry_insert_entry_get_mut_assignment_placeholder<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if unsafe { stmt.field_name(1) }.is_some() {
                    let mut entry = column_names
                        .entry(helper_column_key(name))
                        .insert_entry(placeholder_column_name());
                    let slot = entry.get_mut();
                    *slot = placeholder_column_name();
                }
            }

            fn replace_column_with_entry_match_slot_assignment_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    let slot = match column_names.entry(helper_column_key(name)) {
                        Entry::Occupied(entry) => entry.into_mut(),
                        Entry::Vacant(entry) => entry.insert(placeholder_column_name()),
                    };
                    *slot = column;
                }
            }

            fn replace_column_with_entry_match_slot_assignment_placeholder<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if unsafe { stmt.field_name(1) }.is_some() {
                    let slot = match column_names.entry(helper_column_key(name)) {
                        Entry::Occupied(entry) => entry.into_mut(),
                        Entry::Vacant(entry) => entry.insert(placeholder_column_name()),
                    };
                    *slot = placeholder_column_name();
                }
            }

            fn entry_match_column_slot<'map, 'a>(
                column_names: &'map mut HashMap<String, &'a CStr>,
                name: &'a str,
            ) -> &'map mut &'a CStr {
                match column_names.entry(helper_column_key(name)) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => entry.insert(placeholder_column_name()),
                }
            }

            fn replace_column_with_entry_match_returned_slot_helper_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    let slot = entry_match_column_slot(column_names, name);
                    *slot = column;
                }
            }

            fn replace_column_with_entry_match_returned_slot_helper_placeholder<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
            ) {
                let slot = entry_match_column_slot(column_names, name);
                *slot = placeholder_column_name();
            }

            fn entry_for_column<'map, 'a>(
                column_names: &'map mut HashMap<String, &'a CStr>,
                name: &'a str,
            ) -> Entry<'map, String, &'a CStr> {
                column_names.entry(helper_column_key(name))
            }

            fn replace_column_with_entry_helper_slot_assignment_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    let slot =
                        entry_for_column(column_names, name).or_insert_with(placeholder_column_name);
                    *slot = column;
                }
            }

            fn replace_column_with_entry_helper_slot_assignment_placeholder<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
            ) {
                let slot =
                    entry_for_column(column_names, name).or_insert_with(placeholder_column_name);
                *slot = placeholder_column_name();
            }

            fn replace_column_with_entry_return_helper_and_modify_or_insert_with_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    entry_for_column(column_names, name)
                        .and_modify(|slot| *slot = column)
                        .or_insert_with(|| column);
                }
            }

            fn replace_column_with_entry_return_helper_and_modify_or_insert_with_placeholder<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    entry_for_column(column_names, name)
                        .and_modify(|slot| *slot = column)
                        .or_insert_with(placeholder_column_name);
                }
            }

            fn replace_column_with_entry_return_helper_match_insert_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    match entry_for_column(column_names, name) {
                        Entry::Occupied(mut entry) => {
                            entry.insert(column);
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(column);
                        }
                    }
                }
            }

            fn replace_column_with_entry_return_helper_match_insert_placeholder<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    match entry_for_column(column_names, name) {
                        Entry::Occupied(mut entry) => {
                            entry.insert(column);
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(placeholder_column_name());
                        }
                    }
                }
            }

            fn replace_column_with_entry_match_promote_vacant_insert_entry_slot_assignment_returned<
                'a,
            >(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    let mut entry = match column_names.entry(helper_column_key(name)) {
                        Entry::Occupied(entry) => entry,
                        Entry::Vacant(entry) => {
                            entry.insert_entry(placeholder_column_name())
                        }
                    };
                    let slot = entry.get_mut();
                    *slot = column;
                }
            }

            fn replace_column_with_entry_match_promote_vacant_insert_entry_slot_assignment_placeholder<
                'a,
            >(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
            ) {
                let mut entry = match column_names.entry(helper_column_key(name)) {
                    Entry::Occupied(entry) => entry,
                    Entry::Vacant(entry) => {
                        entry.insert_entry(placeholder_column_name())
                    }
                };
                let slot = entry.get_mut();
                *slot = placeholder_column_name();
            }

            fn replace_column_with_entry_and_modify_placeholder<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
            ) {
                column_names
                    .entry(helper_column_key(name))
                    .and_modify(|column| *column = placeholder_column_name());
            }

            fn replace_column_with_entry_and_modify_or_insert_with_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    column_names
                        .entry(helper_column_key(name))
                        .and_modify(|slot| *slot = column)
                        .or_insert_with(|| column);
                }
            }

            fn replace_column_with_entry_and_modify_or_insert_with_placeholder<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    column_names
                        .entry(helper_column_key(name))
                        .and_modify(|slot| *slot = column)
                        .or_insert_with(placeholder_column_name);
                }
            }

            fn replace_column_with_entry_and_modify_or_insert_with_value_wrapper<'a>(
                column_names: &mut HashMap<String, ColumnSlot<'a>>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    column_names
                        .entry(helper_column_key(name))
                        .and_modify(|slot| {
                            *slot = ColumnSlot { column, marker: 2 };
                        })
                        .or_insert_with(|| ColumnSlot { column, marker: 3 });
                }
            }

            fn replace_column_with_split_entry_and_modify_or_insert_with_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    column_names
                        .entry(helper_column_key(name))
                        .and_modify(|slot| *slot = column);
                    column_names
                        .entry(helper_column_key(name))
                        .or_insert_with(|| column);
                }
            }

            fn replace_column_with_split_entry_and_modify_or_insert_with_placeholder<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    column_names
                        .entry(helper_column_key(name))
                        .and_modify(|slot| *slot = column);
                    column_names
                        .entry(helper_column_key(name))
                        .or_insert_with(placeholder_column_name);
                }
            }

            fn replace_column_with_conditional_entry_and_modify_or_insert_with_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
                write_occupied: bool,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    column_names
                        .entry(helper_column_key(name))
                        .and_modify(|slot| {
                            if write_occupied {
                                *slot = column;
                            }
                        })
                        .or_insert_with(|| column);
                }
            }

            fn replace_column_with_if_else_entry_and_modify_or_insert_with_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
                prefer_then_branch: bool,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    column_names
                        .entry(helper_column_key(name))
                        .and_modify(|slot| {
                            if prefer_then_branch {
                                *slot = column;
                            } else {
                                *slot = column;
                            }
                        })
                        .or_insert_with(|| column);
                }
            }

            fn replace_column_with_entry_slot_assignment_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    let slot = column_names
                        .entry(helper_column_key(name))
                        .or_insert_with(placeholder_column_name);
                    *slot = column;
                }
            }

            fn replace_column_with_conditional_entry_slot_assignment_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
                write_slot: bool,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    let slot = column_names
                        .entry(helper_column_key(name))
                        .or_insert_with(placeholder_column_name);
                    if write_slot {
                        *slot = column;
                    }
                }
            }

            fn replace_column_with_entry_match_single_vacant_insert_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    match column_names.entry(helper_column_key(name)) {
                        Entry::Occupied(_) => {}
                        Entry::Vacant(entry) => {
                            entry.insert(column);
                        }
                    }
                }
            }

            fn replace_column_with_entry_match_both_insert_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                if let Some(column) = unsafe { stmt.field_name(1) } {
                    match column_names.entry(helper_column_key(name)) {
                        Entry::Occupied(mut entry) => {
                            entry.insert(column);
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(column);
                        }
                    }
                }
            }

            fn replace_column_with_nested_entry_match_both_insert_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                replace_column_with_entry_match_both_insert_returned(column_names, name, stmt);
            }

            fn replace_column_with_nested_entry_match_single_vacant_insert_returned<'a>(
                column_names: &mut HashMap<String, &'a CStr>,
                name: &'a str,
                stmt: &'a Statement,
            ) {
                replace_column_with_entry_match_single_vacant_insert_returned(
                    column_names,
                    name,
                    stmt,
                );
            }

            pub struct NamedStatementIterator<'a> {
                stmt: &'a Statement,
                column_indices: HashMap<&'a str, usize>,
            }

            impl<'a> NamedStatementIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    let mut column_indices = HashMap::new();
                    if let Some(column) = unsafe { stmt.field_name(0) } {
                        if let Ok(name) = column.to_str() {
                            column_indices.insert(name, 0);
                        }
                    }
                    Self {
                        stmt,
                        column_indices,
                    }
                }

                pub fn lookup(&self, name: &str) -> Option<usize> {
                    let _stmt = self.stmt;
                    self.column_indices.get(name).copied()
                }

                pub fn step_then_lookup(&mut self, name: &str) -> Option<usize> {
                    self.step();
                    self.column_indices.get(name).copied()
                }

                fn step(&mut self) {
                    let _stmt = self.stmt;
                }
            }

            pub struct NamedStatementCollectIterator<'a> {
                stmt: &'a Statement,
                column_indices: HashMap<&'a str, usize>,
            }

            impl<'a> NamedStatementCollectIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    let column_indices = (0..1)
                        .filter_map(|i| {
                            unsafe { stmt.field_name(i) }.and_then(|column| {
                                column.to_str().ok().map(|name| (name, i))
                            })
                        })
                        .collect::<HashMap<_, _>>();
                    Self {
                        stmt,
                        column_indices,
                    }
                }

                pub fn lookup(&self, name: &str) -> Option<usize> {
                    let _stmt = self.stmt;
                    self.column_indices.get(name).copied()
                }
            }

            pub struct ConstKeyMapIterator<'a> {
                stmt: &'a Statement,
                column_names: HashMap<&'static str, &'a CStr>,
            }

            impl<'a> ConstKeyMapIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    Self {
                        stmt,
                        column_names: HashMap::new(),
                    }
                }

                fn populate_column_names(&mut self) {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert("first", column);
                    }
                }

                pub fn step_then_first(&mut self) -> Option<&'a CStr> {
                    self.step();
                    if self.column_names.is_empty() {
                        self.populate_column_names();
                    }
                    self.column_names.get("first").copied()
                }

                pub fn step_then_other(&mut self) -> Option<&'a CStr> {
                    self.step();
                    if self.column_names.is_empty() {
                        self.populate_column_names();
                    }
                    self.column_names.get("other").copied()
                }

                fn step(&mut self) {
                    let _stmt = self.stmt;
                }
            }

            pub struct SameLocalKeyMapIterator<'a> {
                stmt: &'a Statement,
                column_names: HashMap<&'a str, &'a CStr>,
            }

            impl<'a> SameLocalKeyMapIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    Self {
                        stmt,
                        column_names: HashMap::new(),
                    }
                }

                pub fn cache_then_step_lookup(&mut self, name: &'a str) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(name, column);
                    }
                    self.step();
                    self.column_names.get(name).copied()
                }

                pub fn cache_remove_step_lookup(&mut self, name: &'a str) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(name, column);
                    }
                    self.column_names.remove(name);
                    self.step();
                    self.column_names.get(name).copied()
                }

                pub fn cache_remove_return_step_use(&mut self, name: &'a str) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(name, column);
                    }
                    let removed = self.column_names.remove(name);
                    self.step();
                    removed.as_ref().copied()
                }

                pub fn cache_remove_other_return_step_use(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(name, column);
                    }
                    let removed = self.column_names.remove(other);
                    self.step();
                    removed.as_ref().copied()
                }

                pub fn cache_clear_step_lookup(&mut self, name: &'a str) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(name, column);
                    }
                    self.column_names.clear();
                    self.step();
                    self.column_names.get(name).copied()
                }

                pub fn cache_replace_step_lookup(&mut self, name: &'a str) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(name, column);
                    }
                    self.column_names.insert(name, placeholder_column_name());
                    self.step();
                    self.column_names.get(name).copied()
                }

                pub fn cache_replace_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(name, column);
                    }
                    if let Some(column) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.insert(name, column);
                    }
                    self.step();
                    self.column_names.get(name).copied()
                }

                pub fn cache_then_step_other(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(name, column);
                    }
                    self.step();
                    self.column_names.get(other).copied()
                }

                fn step(&self) {
                    let _stmt = self.stmt;
                }
            }

            pub struct BorrowEquivalentKeyMapIterator<'a> {
                stmt: &'a Statement,
                column_names: HashMap<String, &'a CStr>,
            }

            impl<'a> BorrowEquivalentKeyMapIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    Self {
                        stmt,
                        column_names: HashMap::new(),
                    }
                }

                pub fn cache_owned_key_then_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(name.to_owned(), column);
                    }
                    self.step();
                    self.column_names.get(name).copied()
                }

                pub fn cache_string_key_then_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(name.to_string(), column);
                    }
                    self.step();
                    self.column_names.get(name).copied()
                }

                pub fn cache_from_key_then_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(String::from(name), column);
                    }
                    self.step();
                    self.column_names.get(name).copied()
                }

                pub fn cache_external_helper_lookup_missing_contract_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    self.step();
                    diesel_helper_lookup::lookup_borrowed(&self.column_names, name)
                }

                pub fn cache_external_helper_lookup_with_contract_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    self.step();
                    diesel_helper_lookup::lookup_borrowed(&self.column_names, name)
                }

                pub fn cache_owned_key_then_step_other(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(name.to_owned(), column);
                    }
                    self.step();
                    self.column_names.get(other).copied()
                }

                pub fn cache_owned_key_remove_return_step_use(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(name.to_owned(), column);
                    }
                    let removed = self.column_names.remove(name);
                    self.step();
                    removed.as_ref().copied()
                }

                pub fn cache_helper_key_then_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    self.step();
                    self.column_names.get(name).copied()
                }

                pub fn cache_helper_key_then_step_other(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    self.step();
                    self.column_names.get(other).copied()
                }

                pub fn cache_ambiguous_helper_key_then_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    use_name: bool,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names
                            .insert(ambiguous_column_key(name, other, use_name), column);
                    }
                    self.step();
                    self.column_names.get(name).copied()
                }

                pub fn cache_helper_key_remove_return_step_use(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    let removed = self.column_names.remove(name);
                    self.step();
                    removed.as_ref().copied()
                }

                pub fn cache_helper_remove_return_step_use(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    let removed = remove_column_return(&mut self.column_names, name);
                    self.step();
                    removed.as_ref().copied()
                }

                pub fn cache_helper_remove_other_return_step_use(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    let removed = remove_other_column_return(&mut self.column_names, name);
                    self.step();
                    removed.as_ref().copied()
                }

                pub fn cache_then_step_helper_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_then_step_helper_lookup_other(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    self.step();
                    lookup_column(&self.column_names, other)
                }

                pub fn cache_then_step_nested_helper_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    self.step();
                    nested_lookup_column(&self.column_names, name)
                }

                pub fn cache_then_step_nested_helper_lookup_other(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    self.step();
                    nested_lookup_column(&self.column_names, other)
                }

                pub fn cache_then_step_ambiguous_helper_lookup(
                    &mut self,
                    name: &'a str,
                    use_primary: bool,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    let fallback = HashMap::new();
                    self.step();
                    ambiguous_lookup_column(&self.column_names, &fallback, name, use_primary)
                }

                pub fn cache_helper_remove_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    remove_column(&mut self.column_names, name);
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_remove_other_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    remove_column(&mut self.column_names, other);
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_nested_remove_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    nested_remove_column(&mut self.column_names, name);
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_nested_remove_other_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    nested_remove_column(&mut self.column_names, other);
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_nested_remove_ambiguous_key_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    use_name: bool,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    nested_remove_column_with_ambiguous_key(
                        &mut self.column_names,
                        name,
                        other,
                        use_name,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_clear_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    clear_columns(&mut self.column_names);
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_nested_clear_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    nested_clear_columns(&mut self.column_names);
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_replace_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    replace_column_with_returned(&mut self.column_names, name, self.stmt);
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_replace_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    replace_column_with_placeholder(&mut self.column_names, name);
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_replace_returned_via_helper_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    replace_column_with_returned_helper(&mut self.column_names, name, self.stmt);
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_replace_ambiguous_returned_helper_step_lookup(
                    &mut self,
                    name: &'a str,
                    use_first: bool,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    replace_column_with_ambiguous_returned_helper(
                        &mut self.column_names,
                        name,
                        self.stmt,
                        use_first,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_insert_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_returned(&mut self.column_names, name, self.stmt);
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn local_empty_helper_entry_insert_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    replace_column_with_entry_returned(&mut column_names, name, self.stmt);
                    self.step();
                    lookup_column(&column_names, name)
                }

                pub fn cache_helper_entry_insert_entry_get_mut_assignment_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_insert_entry_get_mut_assignment_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_insert_entry_get_mut_assignment_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    replace_column_with_entry_insert_entry_get_mut_assignment_placeholder(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_match_slot_assignment_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_match_slot_assignment_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_match_slot_assignment_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    replace_column_with_entry_match_slot_assignment_placeholder(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_match_returned_slot_helper_assignment_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(1) } {
                        let slot = entry_match_column_slot(&mut self.column_names, name);
                        *slot = column;
                    }
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_match_returned_slot_helper_assignment_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    let slot = entry_match_column_slot(&mut self.column_names, name);
                    *slot = placeholder_column_name();
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_match_returned_slot_helper_assignment_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_match_returned_slot_helper_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_match_returned_slot_helper_assignment_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_match_returned_slot_helper_placeholder(
                        &mut self.column_names,
                        name,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_helper_slot_assignment_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(1) } {
                        let slot = entry_for_column(&mut self.column_names, name)
                            .or_insert_with(placeholder_column_name);
                        *slot = column;
                    }
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_helper_slot_assignment_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    let slot = entry_for_column(&mut self.column_names, name)
                        .or_insert_with(placeholder_column_name);
                    *slot = placeholder_column_name();
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_helper_slot_assignment_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_helper_slot_assignment_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_helper_slot_assignment_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_helper_slot_assignment_placeholder(
                        &mut self.column_names,
                        name,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_return_helper_and_modify_or_insert_with_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(1) } {
                        entry_for_column(&mut self.column_names, name)
                            .and_modify(|slot| *slot = column)
                            .or_insert_with(|| column);
                    }
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_return_helper_and_modify_or_insert_with_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(1) } {
                        entry_for_column(&mut self.column_names, name)
                            .and_modify(|slot| *slot = column)
                            .or_insert_with(placeholder_column_name);
                    }
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_return_helper_and_modify_or_insert_with_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_return_helper_and_modify_or_insert_with_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_return_helper_and_modify_or_insert_with_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_return_helper_and_modify_or_insert_with_placeholder(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_return_helper_match_insert_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(1) } {
                        match entry_for_column(&mut self.column_names, name) {
                            Entry::Occupied(mut entry) => {
                                entry.insert(column);
                            }
                            Entry::Vacant(entry) => {
                                entry.insert(column);
                            }
                        }
                    }
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_return_helper_match_insert_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(1) } {
                        match entry_for_column(&mut self.column_names, name) {
                            Entry::Occupied(mut entry) => {
                                entry.insert(column);
                            }
                            Entry::Vacant(entry) => {
                                entry.insert(placeholder_column_name());
                            }
                        }
                    }
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_return_helper_match_insert_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_return_helper_match_insert_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_return_helper_match_insert_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_return_helper_match_insert_placeholder(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn local_helper_entry_insert_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        column_names.insert(helper_column_key(name), column);
                    }
                    replace_column_with_entry_placeholder(&mut column_names, name);
                    self.step();
                    lookup_column(&column_names, name)
                }

                pub fn local_helper_entry_and_modify_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        column_names.insert(helper_column_key(name), column);
                    }
                    replace_column_with_entry_and_modify_placeholder(&mut column_names, name);
                    self.step();
                    lookup_column(&column_names, name)
                }

                pub fn cache_helper_entry_insert_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    replace_column_with_entry_placeholder(&mut self.column_names, name);
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_and_modify_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    replace_column_with_entry_and_modify_placeholder(&mut self.column_names, name);
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_and_modify_or_insert_with_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_and_modify_or_insert_with_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_and_modify_or_insert_with_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_and_modify_or_insert_with_placeholder(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn local_helper_entry_and_modify_or_insert_with_value_wrapper_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(
                            helper_column_key(name),
                            ColumnSlot {
                                column: placeholder_column_name(),
                                marker: 1,
                            },
                        );
                    }
                    replace_column_with_entry_and_modify_or_insert_with_value_wrapper(
                        &mut column_names,
                        other,
                        self.stmt,
                    );
                    self.step();
                    lookup_column_slot(&column_names, other)
                }

                pub fn cache_helper_split_entry_and_modify_or_insert_with_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_split_entry_and_modify_or_insert_with_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_split_entry_and_modify_or_insert_with_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_split_entry_and_modify_or_insert_with_placeholder(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_conditional_entry_and_modify_or_insert_with_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    write_occupied: bool,
                ) -> Option<&'a CStr> {
                    replace_column_with_conditional_entry_and_modify_or_insert_with_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                        write_occupied,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_if_else_entry_and_modify_or_insert_with_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    prefer_then_branch: bool,
                ) -> Option<&'a CStr> {
                    replace_column_with_if_else_entry_and_modify_or_insert_with_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                        prefer_then_branch,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_slot_assignment_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_slot_assignment_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_conditional_entry_slot_assignment_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    write_slot: bool,
                ) -> Option<&'a CStr> {
                    replace_column_with_conditional_entry_slot_assignment_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                        write_slot,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_match_single_vacant_insert_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    self.column_names
                        .insert(helper_column_key(name), placeholder_column_name());
                    replace_column_with_entry_match_single_vacant_insert_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_match_both_insert_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_match_both_insert_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_nested_entry_match_both_insert_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_nested_entry_match_both_insert_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_nested_entry_match_single_vacant_insert_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    self.column_names
                        .insert(helper_column_key(name), placeholder_column_name());
                    replace_column_with_nested_entry_match_single_vacant_insert_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_or_insert_preserves_existing_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    if let Some(column) = unsafe { self.stmt.field_name(1) } {
                        self.column_names
                            .entry(helper_column_key(name))
                            .or_insert(column);
                    }
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_and_modify_replace_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    if let Some(column) = unsafe { self.stmt.field_name(1) } {
                        self.column_names
                            .entry(helper_column_key(name))
                            .and_modify(|slot| *slot = column);
                    }
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn local_empty_entry_or_insert_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        column_names
                            .entry(helper_column_key(name))
                            .or_insert(column);
                    }
                    self.step();
                    lookup_column(&column_names, name)
                }

                pub fn local_unknown_entry_or_insert_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        column_names
                            .entry(helper_column_key(other))
                            .or_insert(column);
                    }
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_empty_entry_or_insert_with_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    column_names
                        .entry(helper_column_key(name))
                        .or_insert_with(|| unsafe {
                            self.stmt.field_name(0).unwrap_or_else(placeholder_column_name)
                        });
                    self.step();
                    lookup_column(&column_names, name)
                }

                pub fn local_unknown_entry_or_insert_with_step_lookup(
                    &mut self,
                    name: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    column_names
                        .entry(helper_column_key(name))
                        .or_insert_with(|| unsafe {
                            self.stmt.field_name(0).unwrap_or_else(placeholder_column_name)
                        });
                    self.step();
                    lookup_column(&column_names, name)
                }

                pub fn local_unknown_entry_and_modify_or_insert_same_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    column_names
                        .entry(helper_column_key(other))
                        .and_modify(|slot| *slot = column)
                        .or_insert(column);
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_and_modify_or_insert_with_same_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    column_names
                        .entry(helper_column_key(other))
                        .and_modify(|slot| *slot = column)
                        .or_insert_with(|| column);
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_split_entry_and_modify_or_insert_with_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    column_names
                        .entry(helper_column_key(other))
                        .and_modify(|slot| *slot = column);
                    column_names
                        .entry(helper_column_key(other))
                        .or_insert_with(|| column);
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_split_entry_and_modify_or_insert_with_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    column_names
                        .entry(helper_column_key(other))
                        .and_modify(|slot| *slot = column);
                    column_names
                        .entry(helper_column_key(other))
                        .or_insert_with(placeholder_column_name);
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_and_modify_or_insert_with_key_same_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    column_names
                        .entry(helper_column_key(other))
                        .and_modify(|slot| *slot = column)
                        .or_insert_with_key(|_key| column);
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_and_modify_or_insert_with_fallback_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    column_names
                        .entry(helper_column_key(other))
                        .and_modify(|slot| *slot = column)
                        .or_insert_with(|| unsafe {
                            self.stmt.field_name(0).unwrap_or_else(placeholder_column_name)
                        });
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_and_modify_or_insert_with_conditional_return_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                    use_returned: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    column_names
                        .entry(helper_column_key(other))
                        .and_modify(|slot| *slot = column)
                        .or_insert_with(|| {
                            if use_returned {
                                column
                            } else {
                                placeholder_column_name()
                            }
                        });
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_and_modify_or_insert_with_if_else_same_return_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                    prefer_then_branch: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    column_names
                        .entry(helper_column_key(other))
                        .and_modify(|slot| *slot = column)
                        .or_insert_with(|| {
                            if prefer_then_branch {
                                column
                            } else {
                                column
                            }
                        });
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_slot_assignment_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    let slot = column_names
                        .entry(helper_column_key(other))
                        .or_insert_with(placeholder_column_name);
                    *slot = column;
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_match_slot_assignment_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    let slot = match column_names.entry(helper_column_key(other)) {
                        Entry::Occupied(entry) => entry.into_mut(),
                        Entry::Vacant(entry) => entry.insert(placeholder_column_name()),
                    };
                    *slot = column;
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_match_slot_assignment_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let slot = match column_names.entry(helper_column_key(other)) {
                        Entry::Occupied(entry) => entry.into_mut(),
                        Entry::Vacant(entry) => entry.insert(placeholder_column_name()),
                    };
                    *slot = placeholder_column_name();
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_conditional_entry_slot_assignment_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                    write_slot: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    let slot = column_names
                        .entry(helper_column_key(other))
                        .or_insert_with(placeholder_column_name);
                    if write_slot {
                        *slot = column;
                    }
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_and_modify_or_insert_with_value_wrapper_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(
                            helper_column_key(name),
                            ColumnSlot {
                                column: placeholder_column_name(),
                                marker: 1,
                            },
                        );
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    column_names
                        .entry(helper_column_key(other))
                        .and_modify(|slot| {
                            *slot = ColumnSlot { column, marker: 2 };
                        })
                        .or_insert_with(|| ColumnSlot { column, marker: 3 });
                    self.step();
                    lookup_column_slot(&column_names, other)
                }

                pub fn local_unknown_entry_match_both_insert_same_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    match column_names.entry(helper_column_key(other)) {
                        Entry::Occupied(mut entry) => {
                            entry.insert(column);
                        }
                        Entry::Vacant(entry) => {
                            entry.insert_entry(column);
                        }
                    }
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_match_vacant_insert_same_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    match column_names.entry(helper_column_key(other)) {
                        Entry::Occupied(mut entry) => {
                            entry.insert(column);
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(column);
                        }
                    }
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_match_promote_vacant_insert_entry_slot_assignment_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    let mut entry = match column_names.entry(helper_column_key(other)) {
                        Entry::Occupied(entry) => entry,
                        Entry::Vacant(entry) => {
                            entry.insert_entry(placeholder_column_name())
                        }
                    };
                    let slot = entry.get_mut();
                    *slot = column;
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_match_promote_vacant_insert_entry_slot_assignment_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let mut entry = match column_names.entry(helper_column_key(other)) {
                        Entry::Occupied(entry) => entry,
                        Entry::Vacant(entry) => {
                            entry.insert_entry(placeholder_column_name())
                        }
                    };
                    let slot = entry.get_mut();
                    *slot = placeholder_column_name();
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn cache_helper_entry_match_promote_vacant_insert_entry_slot_assignment_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_match_promote_vacant_insert_entry_slot_assignment_returned(
                        &mut self.column_names,
                        name,
                        self.stmt,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_helper_entry_match_promote_vacant_insert_entry_slot_assignment_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    replace_column_with_entry_match_promote_vacant_insert_entry_slot_assignment_placeholder(
                        &mut self.column_names,
                        name,
                    );
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn local_unknown_entry_match_single_occupied_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    match column_names.entry(helper_column_key(other)) {
                        Entry::Occupied(mut entry) => {
                            entry.insert(column);
                        }
                        Entry::Vacant(_) => {}
                    }
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_match_single_vacant_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    match column_names.entry(helper_column_key(other)) {
                        Entry::Occupied(_) => {}
                        Entry::Vacant(entry) => {
                            entry.insert_entry(column);
                        }
                    }
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_match_single_vacant_insert_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    match column_names.entry(helper_column_key(other)) {
                        Entry::Occupied(_) => {}
                        Entry::Vacant(entry) => {
                            entry.insert(column);
                        }
                    }
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_match_divergent_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let first = unsafe { self.stmt.field_name(0) }?;
                    let second = unsafe { self.stmt.field_name(1) }?;
                    match column_names.entry(helper_column_key(other)) {
                        Entry::Occupied(mut entry) => {
                            entry.insert(first);
                        }
                        Entry::Vacant(entry) => {
                            entry.insert_entry(second);
                        }
                    }
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_match_returned_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    match column_names.entry(helper_column_key(other)) {
                        Entry::Occupied(mut entry) => {
                            entry.insert(column);
                        }
                        Entry::Vacant(entry) => {
                            entry.insert_entry(placeholder_column_name());
                        }
                    }
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn local_unknown_entry_match_conditional_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    maybe_seed: bool,
                    write_occupied: bool,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    if maybe_seed {
                        column_names.insert(helper_column_key(name), placeholder_column_name());
                    }
                    let column = unsafe { self.stmt.field_name(0) }?;
                    match column_names.entry(helper_column_key(other)) {
                        Entry::Occupied(mut entry) => {
                            if write_occupied {
                                entry.insert(column);
                            }
                        }
                        Entry::Vacant(entry) => {
                            entry.insert_entry(column);
                        }
                    }
                    self.step();
                    lookup_column(&column_names, other)
                }

                pub fn cache_entry_insert_entry_replace_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    if let Some(column) = unsafe { self.stmt.field_name(1) } {
                        self.column_names
                            .entry(helper_column_key(name))
                            .insert_entry(column);
                    }
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_insert_entry_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    self.column_names
                        .entry(helper_column_key(name))
                        .insert_entry(placeholder_column_name());
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_insert_entry_then_occupied_insert_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    let mut entry = self
                        .column_names
                        .entry(helper_column_key(name))
                        .insert_entry(placeholder_column_name());
                    if let Some(column) = unsafe { self.stmt.field_name(1) } {
                        entry.insert(column);
                    }
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_insert_entry_then_get_mut_assignment_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    if let Some(column) = unsafe { self.stmt.field_name(1) } {
                        let mut entry = self
                            .column_names
                            .entry(helper_column_key(name))
                            .insert_entry(placeholder_column_name());
                        let slot = entry.get_mut();
                        *slot = column;
                    }
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_insert_entry_then_get_mut_assignment_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    let mut entry = self
                        .column_names
                        .entry(helper_column_key(name))
                        .insert_entry(placeholder_column_name());
                    let slot = entry.get_mut();
                    *slot = placeholder_column_name();
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_insert_entry_then_occupied_insert_return_old_step_return(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    let mut entry = if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names
                            .entry(helper_column_key(name))
                            .insert_entry(column)
                    } else {
                        return None;
                    };
                    let old = if let Some(column) = unsafe { self.stmt.field_name(1) } {
                        entry.insert(column)
                    } else {
                        return None;
                    };
                    self.step();
                    Some(old)
                }

                pub fn cache_entry_insert_entry_then_occupied_insert_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(helper_column_key(name), column);
                    }
                    let mut entry = self
                        .column_names
                        .entry(helper_column_key(name))
                        .insert_entry(placeholder_column_name());
                    entry.insert(placeholder_column_name());
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_match_occupied_insert_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    self.column_names
                        .insert(helper_column_key(name), placeholder_column_name());
                    match self.column_names.entry(helper_column_key(name)) {
                        Entry::Occupied(mut entry) => {
                            if let Some(column) = unsafe { self.stmt.field_name(0) } {
                                entry.insert(column);
                            }
                        }
                        Entry::Vacant(_) => {}
                    }
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn cache_entry_match_occupied_insert_placeholder_vacant_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    self.column_names
                        .insert(helper_column_key(name), placeholder_column_name());
                    match self.column_names.entry(helper_column_key(name)) {
                        Entry::Occupied(_) => {}
                        Entry::Vacant(entry) => {
                            if let Some(column) = unsafe { self.stmt.field_name(0) } {
                                entry.insert_entry(column);
                            }
                        }
                    }
                    self.step();
                    lookup_column(&self.column_names, name)
                }

                pub fn local_empty_entry_match_vacant_insert_returned_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    match column_names.entry(helper_column_key(name)) {
                        Entry::Occupied(_) => {}
                        Entry::Vacant(entry) => {
                            if let Some(column) = unsafe { self.stmt.field_name(0) } {
                                entry.insert_entry(column);
                            }
                        }
                    }
                    self.step();
                    lookup_column(&column_names, name)
                }

                pub fn local_empty_entry_match_occupied_returned_vacant_placeholder_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    let mut column_names = HashMap::new();
                    match column_names.entry(helper_column_key(name)) {
                        Entry::Occupied(mut entry) => {
                            if let Some(column) = unsafe { self.stmt.field_name(0) } {
                                entry.insert(column);
                            }
                        }
                        Entry::Vacant(entry) => {
                            entry.insert_entry(placeholder_column_name());
                        }
                    }
                    self.step();
                    lookup_column(&column_names, name)
                }

                fn step(&self) {
                    let _stmt = self.stmt;
                }
            }

            pub struct HashEquivalentKeyMapIterator<'a> {
                stmt: &'a Statement,
                column_names: HashMap<ColumnKey, &'a CStr>,
                salted_column_names: HashMap<SaltedColumnKey, &'a CStr>,
                duplicate_column_names: HashMap<DuplicateColumnKey, &'a CStr>,
                manual_hash_column_names: HashMap<ManualHashColumnKey, &'a CStr>,
            }

            impl<'a> HashEquivalentKeyMapIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    Self {
                        stmt,
                        column_names: HashMap::new(),
                        salted_column_names: HashMap::new(),
                        duplicate_column_names: HashMap::new(),
                        manual_hash_column_names: HashMap::new(),
                    }
                }

                pub fn cache_newtype_key_then_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(ColumnKey::new(name), column);
                    }
                    self.step();
                    self.column_names.get(name).copied()
                }

                pub fn cache_helper_newtype_key_then_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names
                            .insert(ColumnKey::helper_new(name), column);
                    }
                    self.step();
                    self.column_names.get(name).copied()
                }

                pub fn cache_newtype_key_then_step_other(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names.insert(ColumnKey::new(name), column);
                    }
                    self.step();
                    self.column_names.get(other).copied()
                }

                pub fn cache_ambiguous_newtype_key_then_step_lookup(
                    &mut self,
                    name: &'a str,
                    other: &'a str,
                    use_name: bool,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.column_names
                            .insert(ColumnKey::ambiguous(name, other, use_name), column);
                    }
                    self.step();
                    self.column_names.get(name).copied()
                }

                pub fn cache_salted_newtype_key_then_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.salted_column_names
                            .insert(SaltedColumnKey::new(name, 7), column);
                    }
                    self.step();
                    self.salted_column_names.get(name).copied()
                }

                pub fn cache_duplicate_newtype_key_then_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.duplicate_column_names
                            .insert(DuplicateColumnKey::new(name), column);
                    }
                    self.step();
                    self.duplicate_column_names.get(name).copied()
                }

                pub fn cache_manual_hash_newtype_key_then_step_lookup(
                    &mut self,
                    name: &'a str,
                ) -> Option<&'a CStr> {
                    if let Some(column) = unsafe { self.stmt.field_name(0) } {
                        self.manual_hash_column_names
                            .insert(ManualHashColumnKey::new(name), column);
                    }
                    self.step();
                    self.manual_hash_column_names.get(name).copied()
                }

                fn step(&self) {
                    let _stmt = self.stmt;
                }
            }

            pub struct LazyNamedStatementCollectIterator<'a> {
                stmt: &'a Statement,
                column_indices: Option<HashMap<&'a str, usize>>,
            }

            impl<'a> LazyNamedStatementCollectIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    Self {
                        stmt,
                        column_indices: None,
                    }
                }

                unsafe fn populate_column_indices(&mut self) {
                    let column_indices = (0..1)
                        .filter_map(|i| {
                            unsafe { self.stmt.field_name(i) }.and_then(|column| {
                                column.to_str().ok().map(|name| (name, i))
                            })
                        })
                        .collect::<HashMap<_, _>>();
                    self.column_indices = Some(column_indices);
                }

                pub unsafe fn step_then_lookup(&mut self, name: &str) -> Option<usize> {
                    self.step();
                    if self.column_indices.is_none() {
                        unsafe { self.populate_column_indices() };
                    }
                    self.column_indices
                        .as_ref()
                        .and_then(|indices| indices.get(name).copied())
                }

                fn step(&self) {
                    let _stmt = self.stmt;
                }
            }

            pub type QueryResult<T> = Result<T, ()>;

            pub struct NamedRow;

            impl NamedRow {
                pub fn into_named(self, _column_indices: &HashMap<&str, usize>) -> Self {
                    self
                }
            }

            pub struct RealisticLazyNamedStatementCollectIterator<'a> {
                stmt: &'a Statement,
                column_indices: Option<HashMap<&'a str, usize>>,
            }

            impl<'a> RealisticLazyNamedStatementCollectIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> QueryResult<Self> {
                    Ok(Self {
                        stmt,
                        column_indices: None,
                    })
                }

                fn populate_column_indices(&mut self) -> QueryResult<()> {
                    let column_indices = (0..1)
                        .filter_map(|i| {
                            unsafe { self.stmt.field_name(i) }.and_then(|column| {
                                column.to_str().ok().map(|name| Ok((name, i)))
                            })
                        })
                        .collect::<QueryResult<HashMap<_, _>>>()?;

                    self.column_indices = Some(column_indices);
                    Ok(())
                }

                pub fn next_named(&mut self) -> Option<QueryResult<NamedRow>> {
                    let row = match self.step() {
                        Ok(row) => row,
                        Err(e) => return Some(Err(e)),
                    };
                    if self.column_indices.is_none()
                        && let Err(e) = self.populate_column_indices()
                    {
                        return Some(Err(e));
                    }
                    row.map(|row| {
                        Ok(row.into_named(
                            self.column_indices
                                .as_ref()
                                .expect("column indices are populated"),
                        ))
                    })
                }

                fn step(&mut self) -> QueryResult<Option<NamedRow>> {
                    let _stmt = self.stmt;
                    Ok(Some(NamedRow))
                }
            }

            impl<'a> Iterator for RealisticLazyNamedStatementCollectIterator<'a> {
                type Item = QueryResult<NamedRow>;

                fn next(&mut self) -> Option<Self::Item> {
                    let row = match self.step() {
                        Ok(row) => row,
                        Err(e) => return Some(Err(e)),
                    };
                    if self.column_indices.is_none()
                        && let Err(e) = self.populate_column_indices()
                    {
                        return Some(Err(e));
                    }
                    row.map(|row| {
                        Ok(row.into_named(
                            self.column_indices
                                .as_ref()
                                .expect("column indices are populated"),
                        ))
                    })
                }
            }

            pub struct VecLazyNamedStatementCollectIterator<'a> {
                stmt: &'a Statement,
                column_names: Option<Vec<&'a CStr>>,
            }

            impl<'a> VecLazyNamedStatementCollectIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    Self {
                        stmt,
                        column_names: None,
                    }
                }

                fn populate_column_names(&mut self) {
                    let column_names = (0..1)
                        .filter_map(|i| unsafe { self.stmt.field_name(i) })
                        .collect::<Vec<_>>();
                    self.column_names = Some(column_names);
                }

                pub fn step_then_first(&mut self) -> Option<&'a CStr> {
                    self.step();
                    if self.column_names.is_none() {
                        self.populate_column_names();
                    }
                    self.column_names
                        .as_ref()
                        .and_then(|names| names.get(0).copied())
                }

                pub fn step_then_first_as_deref(&mut self) -> Option<&'a CStr> {
                    self.step();
                    if self.column_names.is_none() {
                        self.populate_column_names();
                    }
                    self.column_names
                        .as_deref()
                        .and_then(|names| names.get(0).copied())
                }

                pub fn step_then_first_as_deref_if_let(&mut self) -> Option<&'a CStr> {
                    self.step();
                    if self.column_names.is_none() {
                        self.populate_column_names();
                    }
                    if let Some(names) = self.column_names.as_deref() {
                        names.get(0).copied()
                    } else {
                        None
                    }
                }

                pub fn step_then_first_as_deref_helper(&mut self) -> Option<&'a CStr> {
                    self.step();
                    if self.column_names.is_none() {
                        self.populate_column_names();
                    }
                    read_option_as_deref_first_column_name(&self.column_names)
                }

                pub fn step_then_first_as_ref_helper(&mut self) -> Option<&'a CStr> {
                    self.step();
                    if self.column_names.is_none() {
                        self.populate_column_names();
                    }
                    read_option_as_ref_first_column_name(&self.column_names)
                }

                pub fn step_then_as_deref_discard_helper(&mut self) -> Option<&'a CStr> {
                    self.step();
                    if self.column_names.is_none() {
                        self.populate_column_names();
                    }
                    read_option_as_deref_discard_column_name(&self.column_names)
                }

                fn step(&self) {
                    let _stmt = self.stmt;
                }
            }

            #[inline(never)]
            fn read_option_as_deref_first_column_name<'a>(
                column_names: &Option<Vec<&'a CStr>>,
            ) -> Option<&'a CStr> {
                column_names
                    .as_deref()
                    .and_then(|names| names.get(0).copied())
            }

            #[inline(never)]
            fn read_option_as_ref_first_column_name<'a>(
                column_names: &Option<Vec<&'a CStr>>,
            ) -> Option<&'a CStr> {
                column_names
                    .as_ref()
                    .and_then(|names| names.get(0).copied())
            }

            #[inline(never)]
            fn read_option_as_deref_discard_column_name<'a>(
                column_names: &Option<Vec<&'a CStr>>,
            ) -> Option<&'a CStr> {
                column_names.as_deref().and_then(|_| None)
            }

            pub struct DualVecStorageIterator<'a> {
                stmt: &'a Statement,
                column_names: Option<Vec<&'a CStr>>,
                aliases: Option<Vec<&'a CStr>>,
            }

            impl<'a> DualVecStorageIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    Self {
                        stmt,
                        column_names: None,
                        aliases: None,
                    }
                }

                fn populate_column_names(&mut self) {
                    let column_names = (0..1)
                        .filter_map(|i| unsafe { self.stmt.field_name(i) })
                        .collect::<Vec<_>>();
                    self.column_names = Some(column_names);
                }

                pub fn step_then_alias_first(&mut self) -> Option<&'a CStr> {
                    self.step();
                    if self.column_names.is_none() {
                        self.populate_column_names();
                    }
                    self.aliases
                        .as_ref()
                        .and_then(|aliases| aliases.get(0).copied())
                }

                fn step(&self) {
                    let _stmt = self.stmt;
                }
            }

            pub struct BoxedVecLazyNamedStatementCollectIterator<'a> {
                stmt: &'a Statement,
                column_names: Box<Option<Vec<&'a CStr>>>,
            }

            impl<'a> BoxedVecLazyNamedStatementCollectIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    Self {
                        stmt,
                        column_names: Box::new(None),
                    }
                }

                fn populate_column_names(&mut self) {
                    let column_names = (0..1)
                        .filter_map(|i| unsafe { self.stmt.field_name(i) })
                        .collect::<Vec<_>>();
                    *self.column_names = Some(column_names);
                }

                pub fn step_then_first(&mut self) -> Option<&'a CStr> {
                    self.step();
                    if (*self.column_names).is_none() {
                        self.populate_column_names();
                    }
                    if let Some(names) = (*self.column_names).as_ref() {
                        names.get(0).copied()
                    } else {
                        None
                    }
                }

                fn step(&mut self) {
                    let _stmt = self.stmt;
                }
            }

            pub struct RawPtrVecStorageIterator<'a> {
                stmt: &'a Statement,
                column_names: *mut Option<Vec<&'a CStr>>,
            }

            impl<'a> RawPtrVecStorageIterator<'a> {
                pub unsafe fn new(
                    stmt: &'a Statement,
                    column_names: *mut Option<Vec<&'a CStr>>,
                ) -> Self {
                    Self { stmt, column_names }
                }

                unsafe fn populate_column_names(&mut self) {
                    let column_names = (0..1)
                        .filter_map(|i| unsafe { self.stmt.field_name(i) })
                        .collect::<Vec<_>>();
                    unsafe {
                        *self.column_names = Some(column_names);
                    }
                }

                pub unsafe fn step_then_first(&mut self) -> Option<&'a CStr> {
                    self.step();
                    if unsafe { (*self.column_names).is_none() } {
                        unsafe { self.populate_column_names() };
                    }
                    if let Some(names) = unsafe { (*self.column_names).as_ref() } {
                        names.get(0).copied()
                    } else {
                        None
                    }
                }

                fn step(&mut self) {
                    let _stmt = self.stmt;
                }
            }

            pub struct NestedClosureVecLazyIterator<'a> {
                stmt: &'a Statement,
                column_names: Option<Vec<&'a CStr>>,
            }

            impl<'a> NestedClosureVecLazyIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    Self {
                        stmt,
                        column_names: None,
                    }
                }

                fn populate_column_names(&mut self) {
                    let column_names = (0..1)
                        .filter_map(|i| unsafe { self.stmt.field_name(i) })
                        .collect::<Vec<_>>();
                    self.column_names = Some(column_names);
                }

                pub fn step_then_nested_self_first(&mut self) -> Option<&'a CStr> {
                    self.step();
                    if self.column_names.is_none() {
                        self.populate_column_names();
                    }
                    let outer = || {
                        let inner = || {
                            self.column_names
                                .as_ref()
                                .and_then(|names| names.get(0).copied())
                        };
                        inner()
                    };
                    outer()
                }

                fn step(&mut self) {
                    let _stmt = self.stmt;
                }
            }

            pub struct SharedOwnerVecIterator<'a> {
                stmt: &'a Statement,
                column_names: Arc<Vec<&'a CStr>>,
            }

            impl<'a> SharedOwnerVecIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    let column_names = (0..1)
                        .filter_map(|i| unsafe { stmt.field_name(i) })
                        .collect::<Vec<_>>();
                    Self {
                        stmt,
                        column_names: Arc::new(column_names),
                    }
                }

                pub fn clone_column_names_owner(&self) -> Arc<Vec<&'a CStr>> {
                    let _stmt = self.stmt;
                    Arc::clone(&self.column_names)
                }

                pub fn step_then_first_from_cloned_owner(&mut self) -> Option<&'a CStr> {
                    let names = Arc::clone(&self.column_names);
                    self.step();
                    names.get(0).copied()
                }

                pub fn step_then_first_after_make_mut(&mut self) -> Option<&'a CStr> {
                    let mut names = Arc::clone(&self.column_names);
                    let _unique_names = Arc::make_mut(&mut names);
                    self.step();
                    names.get(0).copied()
                }

                fn step(&mut self) {
                    let _stmt = self.stmt;
                }
            }

            pub struct InteriorMutableVecIterator<'a> {
                stmt: &'a Statement,
                column_names: RefCell<Vec<&'a CStr>>,
            }

            impl<'a> InteriorMutableVecIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    let column_names = (0..1)
                        .filter_map(|i| unsafe { stmt.field_name(i) })
                        .collect::<Vec<_>>();
                    Self {
                        stmt,
                        column_names: RefCell::new(column_names),
                    }
                }

                pub fn step_then_first_from_borrow(&mut self) -> Option<&'a CStr> {
                    let names = self.column_names.borrow();
                    self.step();
                    names.get(0).copied()
                }

                pub fn step_then_first_after_borrow_mut(&mut self) -> Option<&'a CStr> {
                    {
                        let _names = self.column_names.borrow_mut();
                    }
                    self.step();
                    let names = self.column_names.borrow();
                    names.get(0).copied()
                }

                fn step(&self) {
                    let _stmt = self.stmt;
                }
            }

            pub struct FieldStoredViewIterator<'a> {
                stmt: &'a Statement,
                column_name: Option<&'a CStr>,
                other_column_name: Option<&'a CStr>,
            }

            impl<'a> FieldStoredViewIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    Self {
                        stmt,
                        column_name: None,
                        other_column_name: None,
                    }
                }

                pub fn cache_then_step_return_field(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    self.column_name = name;
                    self.step();
                    self.column_name
                }

                pub fn cache_other_then_step_return_field(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    self.other_column_name = name;
                    self.step();
                    self.column_name
                }

                pub fn cache_then_step_pass_field_to_helper(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    self.column_name = name;
                    self.step();
                    observe_column_name(self.column_name)
                }

                pub fn cache_other_then_step_pass_field_to_helper(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    self.other_column_name = name;
                    self.step();
                    observe_column_name(self.column_name)
                }

                pub fn cache_then_step_discard_field_in_helper(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    self.column_name = name;
                    self.step();
                    discard_column_name(self.column_name)
                }

                pub fn cache_then_step_wrapper_into_inner(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    self.step();
                    wrapper.into_inner()
                }

                pub fn cache_then_step_wrapper_into_other(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    self.step();
                    wrapper.into_other()
                }

                pub fn cache_then_step_wrapper_discard(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    self.step();
                    wrapper.discard()
                }

                pub fn cache_then_step_moved_wrapper_into_inner(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    let moved_wrapper = wrapper;
                    self.step();
                    moved_wrapper.into_inner()
                }

                pub fn cache_then_step_moved_wrapper_into_other(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    let moved_wrapper = wrapper;
                    self.step();
                    moved_wrapper.into_other()
                }

                pub fn cache_then_step_replaced_wrapper_into_inner(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let mut wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    let _ignored = wrapper.other_name;
                    wrapper = ColumnNameWrapper {
                        name: None,
                        other_name: None,
                    };
                    self.step();
                    wrapper.into_inner()
                }

                pub fn cache_then_step_take_wrapper_field(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let mut wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    self.step();
                    wrapper.name.take()
                }

                pub fn cache_then_step_take_other_wrapper_field(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let mut wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    self.step();
                    wrapper.other_name.take()
                }

                pub fn cache_then_rewrite_field_step_take(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let mut wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    wrapper.name = None;
                    self.step();
                    wrapper.name.take()
                }

                pub fn cache_then_step_replace_wrapper_field(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let mut wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    self.step();
                    std::mem::replace(&mut wrapper.name, None)
                }

                pub fn cache_then_step_wrapper_take_inner(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let mut wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    self.step();
                    wrapper.take_inner()
                }

                pub fn cache_then_step_wrapper_take_other(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let mut wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    self.step();
                    wrapper.take_other()
                }

                pub fn cache_then_step_wrapper_mem_take_inner(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let mut wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    self.step();
                    wrapper.mem_take_inner()
                }

                pub fn cache_then_step_wrapper_replace_inner_none(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let mut wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    self.step();
                    wrapper.replace_inner_none()
                }

                pub fn cache_take_before_step_then_return_taken(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let mut wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    let taken = wrapper.take_inner();
                    self.step();
                    taken
                }

                pub fn cache_then_step_wrapper_take_then_into_inner(&mut self) -> Option<&'a CStr> {
                    let name = unsafe { self.stmt.field_name(0) };
                    let mut wrapper = ColumnNameWrapper {
                        name,
                        other_name: None,
                    };
                    let _taken = wrapper.take_inner();
                    self.step();
                    wrapper.into_inner()
                }

                fn step(&self) {
                    let _stmt = self.stmt;
                }
            }

            pub struct IndexedVecStorageIterator<'a> {
                stmt: &'a Statement,
                column_names: Vec<&'a CStr>,
            }

            impl<'a> IndexedVecStorageIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    Self {
                        stmt,
                        column_names: vec![placeholder_column_name(), placeholder_column_name()],
                    }
                }

                fn insert_second_column_name(&mut self) {
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.insert(1, name);
                    }
                }

                fn insert_dynamic_column_name(&mut self, index: usize) {
                    if let Some(name) = unsafe { self.stmt.field_name(index) } {
                        self.column_names.insert(index, name);
                    }
                }

                pub fn step_then_second_after_second_insert(&mut self) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    self.column_names.get(1).copied()
                }

                pub fn step_then_first_after_second_insert(&mut self) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    self.column_names.get(0).copied()
                }

                pub fn step_then_dynamic_after_dynamic_insert(
                    &mut self,
                    store_index: usize,
                    use_index: usize,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_dynamic_column_name(store_index);
                    self.column_names.get(use_index).copied()
                }

                pub fn step_then_range_after_second_insert(&mut self) -> Option<&[&'a CStr]> {
                    self.step();
                    self.insert_second_column_name();
                    self.column_names.get(0..1)
                }

                pub fn step_then_range_second_inner_first_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    self.column_names
                        .get(1..2)
                        .and_then(|names| names.get(0).copied())
                }

                pub fn step_then_range_first_inner_first_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    self.column_names
                        .get(0..1)
                        .and_then(|names| names.get(0).copied())
                }

                pub fn step_then_range_inclusive_second_inner_first_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    self.column_names
                        .get(1..=1)
                        .and_then(|names| names.get(0).copied())
                }

                pub fn step_then_range_to_second_inner_second_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    let names = self.column_names.get(..2)?;
                    names.get(1).copied()
                }

                pub fn step_then_range_to_last_second_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    let names = self.column_names.get(..2)?;
                    names.last().copied()
                }

                pub fn step_then_range_to_inclusive_second_inner_second_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    let names = self.column_names.get(..=1)?;
                    names.get(1).copied()
                }

                pub fn step_then_range_to_last_first_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    let names = self.column_names.get(..1)?;
                    names.last().copied()
                }

                pub fn step_then_range_to_first_inner_first_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    self.column_names
                        .get(..1)
                        .and_then(|names| names.get(0).copied())
                }

                pub fn step_then_range_from_second_inner_first_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    let names = self.column_names.get(1..)?;
                    names.get(0).copied()
                }

                pub fn step_then_range_from_first_inner_first_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    let names = self.column_names.get(0..)?;
                    names.get(0).copied()
                }

                pub fn step_then_range_from_last_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    let names = self.column_names.get(1..)?;
                    names.last().copied()
                }

                pub fn step_then_range_full_second_inner_second_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    let names = self.column_names.get(..)?;
                    names.get(1).copied()
                }

                pub fn step_then_range_full_last_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    let names = self.column_names.get(..)?;
                    names.last().copied()
                }

                pub fn step_then_range_full_first_inner_first_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    let names = self.column_names.get(..)?;
                    names.get(0).copied()
                }

                pub fn step_then_range_from_iter_nth_second_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    let names = self.column_names.get(1..)?;
                    names.iter().nth(0).copied()
                }

                pub fn step_then_range_from_iter_nth_first_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    let names = self.column_names.get(0..)?;
                    names.iter().nth(0).copied()
                }

                pub fn step_then_range_full_iter_skip_second_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    let names = self.column_names.get(..)?;
                    names.iter().skip(1).next().copied()
                }

                pub fn step_then_range_full_iter_skip_first_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    let names = self.column_names.get(..)?;
                    names.iter().skip(0).next().copied()
                }

                pub fn step_then_range_full_last_helper_after_second_insert(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.step();
                    self.insert_second_column_name();
                    read_range_full_last_column_name(&self.column_names)
                }

                fn step(&mut self) {
                    let _stmt = self.stmt;
                }
            }

            pub struct PushVecStorageIterator<'a> {
                stmt: &'a Statement,
                column_names: Vec<&'a CStr>,
            }

            impl<'a> PushVecStorageIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    Self {
                        stmt,
                        column_names: vec![placeholder_column_name()],
                    }
                }

                fn push_second_column_name(&mut self) {
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                }

                pub fn step_then_first_after_push(&mut self) -> Option<&'a CStr> {
                    self.step();
                    self.push_second_column_name();
                    self.column_names.get(0).copied()
                }

                pub fn step_then_first_after_clear_and_push(&mut self) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_first_column_name(&self.column_names)
                }

                pub fn step_then_second_after_clear_and_push(&mut self) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_second_column_name(&self.column_names)
                }

                pub fn step_then_second_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_second_column_name(&self.column_names)
                }

                pub fn step_then_first_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_first_column_name(&self.column_names)
                }

                pub fn step_then_first_method_after_clear_and_push(&mut self) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_first_column_name_with_first(&self.column_names)
                }

                pub fn step_then_first_method_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_first_column_name_with_first(&self.column_names)
                }

                pub fn step_then_last_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.last().copied()
                }

                pub fn step_then_last_after_clear_push_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.column_names.push(placeholder_column_name());
                    self.step();
                    self.column_names.last().copied()
                }

                pub fn step_then_as_slice_first_after_clear_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.as_slice().get(0).copied()
                }

                pub fn step_then_as_slice_second_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.as_slice().get(1).copied()
                }

                pub fn step_then_as_slice_first_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.as_slice().get(0).copied()
                }

                pub fn step_then_iter_next_after_clear_and_push(&mut self) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().next().copied()
                }

                pub fn step_then_iter_next_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().next().copied()
                }

                pub fn second_iter_next_after_first_before_step(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.column_names.push(placeholder_column_name());
                    let mut iter = self.column_names.iter();
                    let _first = iter.next();
                    self.step();
                    iter.next().copied()
                }

                pub fn step_then_iter_nth_second_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().nth(1).copied()
                }

                pub fn step_then_iter_nth_first_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().nth(0).copied()
                }

                pub fn step_then_iter_skip_one_next_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().skip(1).next().copied()
                }

                pub fn step_then_dynamic_get_after_clear_placeholder_and_push(
                    &mut self,
                    index: usize,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.get(index).copied()
                }

                pub fn step_then_local_const_get_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    let index = 1usize;
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.get(index).copied()
                }

                pub fn step_then_iter_dynamic_nth_after_clear_placeholder_and_push(
                    &mut self,
                    index: usize,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().nth(index).copied()
                }

                pub fn step_then_iter_local_const_nth_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    let index = 1usize;
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().nth(index).copied()
                }

                pub fn step_then_iter_dynamic_skip_after_clear_placeholder_and_push(
                    &mut self,
                    skip: usize,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().skip(skip).next().copied()
                }

                pub fn step_then_iter_local_const_skip_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    let skip = 1usize;
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().skip(skip).next().copied()
                }

                pub fn step_then_iter_skip_one_next_after_clear_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().skip(1).next().copied()
                }

                pub fn step_then_iter_last_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().last().copied()
                }

                pub fn step_then_iter_last_after_clear_push_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.column_names.push(placeholder_column_name());
                    self.step();
                    self.column_names.iter().last().copied()
                }

                pub fn step_then_iter_rev_next_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().rev().next().copied()
                }

                pub fn step_then_iter_rev_next_after_clear_push_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.column_names.push(placeholder_column_name());
                    self.step();
                    self.column_names.iter().rev().next().copied()
                }

                pub fn step_then_iter_rev_nth_one_after_clear_push_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.column_names.push(placeholder_column_name());
                    self.step();
                    self.column_names.iter().rev().nth(1).copied()
                }

                pub fn step_then_iter_rev_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().rev().nth(1).copied()
                }

                pub fn step_then_iter_rev_skip_one_next_after_clear_push_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.column_names.push(placeholder_column_name());
                    self.step();
                    self.column_names.iter().rev().skip(1).next().copied()
                }

                pub fn step_then_iter_rev_skip_one_next_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().rev().skip(1).next().copied()
                }

                pub fn step_then_iter_skip_one_rev_next_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().skip(1).rev().next().copied()
                }

                pub fn step_then_iter_skip_one_rev_next_after_clear_push_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.column_names.push(placeholder_column_name());
                    self.step();
                    self.column_names.iter().skip(1).rev().next().copied()
                }

                pub fn step_then_iter_take_two_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().take(2).nth(1).copied()
                }

                pub fn step_then_iter_take_one_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().take(1).nth(1).copied()
                }

                pub fn step_then_iter_take_two_last_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().take(2).last().copied()
                }

                pub fn step_then_iter_take_one_last_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().take(1).last().copied()
                }

                pub fn step_then_iter_take_two_rev_next_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().take(2).rev().next().copied()
                }

                pub fn step_then_iter_take_one_rev_next_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().take(1).rev().next().copied()
                }

                pub fn step_then_iter_enumerate_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().enumerate().nth(1).map(|(_, name)| *name)
                }

                pub fn step_then_iter_copied_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().copied().nth(1)
                }

                pub fn step_then_iter_cloned_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().cloned().nth(1)
                }

                pub fn step_then_iter_identity_map_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().map(|name| *name).nth(1)
                }

                pub fn step_then_iter_value_map_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names
                        .iter()
                        .map(|_name| placeholder_column_name())
                        .nth(1)
                }

                pub fn step_then_iter_identity_filter_map_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().filter_map(|name| Some(*name)).nth(1)
                }

                pub fn step_then_iter_value_filter_map_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names
                        .iter()
                        .filter_map(|_name| Some(placeholder_column_name()))
                        .nth(1)
                }

                pub fn step_then_iter_filter_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().filter(|_| true).nth(1).copied()
                }

                pub fn step_then_iter_filter_false_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names.iter().filter(|_| false).nth(1).copied()
                }

                pub fn step_then_iter_chain_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names
                        .iter()
                        .chain(self.column_names.iter())
                        .nth(1)
                        .copied()
                }

                pub fn step_then_iter_zip_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names
                        .iter()
                        .zip(self.column_names.iter())
                        .nth(1)
                        .map(|(name, _)| *name)
                }

                pub fn step_then_iter_flat_map_nth_one_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    self.column_names
                        .iter()
                        .flat_map(|name| std::iter::once(name))
                        .nth(1)
                        .copied()
                }

                pub fn step_then_last_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_last_column_name(&self.column_names)
                }

                pub fn step_then_last_helper_after_clear_push_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.column_names.push(placeholder_column_name());
                    self.step();
                    read_last_column_name(&self.column_names)
                }

                pub fn step_then_iter_last_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_last_column_name(&self.column_names)
                }

                pub fn step_then_iter_last_helper_after_clear_push_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.column_names.push(placeholder_column_name());
                    self.step();
                    read_iter_last_column_name(&self.column_names)
                }

                pub fn step_then_iter_nth_helper_second_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_nth_second_column_name(&self.column_names)
                }

                pub fn step_then_iter_nth_helper_first_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_nth_first_column_name(&self.column_names)
                }

                pub fn step_then_iter_skip_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_skip_one_next_column_name(&self.column_names)
                }

                pub fn step_then_iter_dynamic_nth_helper_after_clear_placeholder_and_push(
                    &mut self,
                    index: usize,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_dynamic_nth_column_name(&self.column_names, index)
                }

                pub fn step_then_iter_local_const_nth_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_local_const_nth_column_name(&self.column_names)
                }

                pub fn step_then_iter_dynamic_skip_helper_after_clear_placeholder_and_push(
                    &mut self,
                    skip: usize,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_dynamic_skip_column_name(&self.column_names, skip)
                }

                pub fn step_then_iter_local_const_skip_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_local_const_skip_column_name(&self.column_names)
                }

                pub fn step_then_iter_skip_helper_after_clear_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_skip_one_next_column_name(&self.column_names)
                }

                pub fn step_then_as_slice_helper_second_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_as_slice_second_column_name(&self.column_names)
                }

                pub fn step_then_as_slice_helper_first_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_as_slice_first_column_name(&self.column_names)
                }

                pub fn step_then_range_helper_second_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_range_from_iter_nth_second_column_name(&self.column_names)
                }

                pub fn step_then_range_helper_first_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_range_from_iter_nth_first_column_name(&self.column_names)
                }

                pub fn step_then_range_full_helper_second_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_range_full_iter_skip_second_column_name(&self.column_names)
                }

                pub fn step_then_range_full_helper_first_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_range_full_iter_skip_first_column_name(&self.column_names)
                }

                pub fn step_then_range_tail_helper_second_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_range_to_last_second_column_name(&self.column_names)
                }

                pub fn step_then_range_tail_helper_first_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_range_to_last_first_column_name(&self.column_names)
                }

                pub fn step_then_range_from_last_helper_second_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_range_from_last_column_name(&self.column_names)
                }

                pub fn step_then_range_full_last_helper_second_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_range_full_last_column_name(&self.column_names)
                }

                pub fn step_then_iter_rev_next_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_rev_next_column_name(&self.column_names)
                }

                pub fn step_then_iter_rev_next_helper_after_clear_push_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.column_names.push(placeholder_column_name());
                    self.step();
                    read_iter_rev_next_column_name(&self.column_names)
                }

                pub fn step_then_iter_rev_nth_one_helper_after_clear_push_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.column_names.push(placeholder_column_name());
                    self.step();
                    read_iter_rev_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_rev_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_rev_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_rev_skip_one_next_helper_after_clear_push_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.column_names.push(placeholder_column_name());
                    self.step();
                    read_iter_rev_skip_one_next_column_name(&self.column_names)
                }

                pub fn step_then_iter_rev_skip_one_next_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_rev_skip_one_next_column_name(&self.column_names)
                }

                pub fn step_then_iter_skip_one_rev_next_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_skip_one_rev_next_column_name(&self.column_names)
                }

                pub fn step_then_iter_skip_one_rev_next_helper_after_clear_push_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.column_names.push(placeholder_column_name());
                    self.step();
                    read_iter_skip_one_rev_next_column_name(&self.column_names)
                }

                pub fn step_then_iter_take_two_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_take_two_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_take_one_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_take_one_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_take_two_last_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_take_two_last_column_name(&self.column_names)
                }

                pub fn step_then_iter_take_one_last_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_take_one_last_column_name(&self.column_names)
                }

                pub fn step_then_iter_take_two_rev_next_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_take_two_rev_next_column_name(&self.column_names)
                }

                pub fn step_then_iter_take_one_rev_next_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_take_one_rev_next_column_name(&self.column_names)
                }

                pub fn step_then_iter_enumerate_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_enumerate_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_copied_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_copied_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_cloned_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_cloned_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_identity_map_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_identity_map_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_value_map_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_value_map_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_identity_filter_map_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_identity_filter_map_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_value_filter_map_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_value_filter_map_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_filter_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_filter_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_filter_false_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_filter_false_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_chain_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_chain_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_zip_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_zip_nth_one_column_name(&self.column_names)
                }

                pub fn step_then_iter_flat_map_nth_one_helper_after_clear_placeholder_and_push(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push(name);
                    }
                    self.step();
                    read_iter_flat_map_nth_one_column_name(&self.column_names)
                }

                fn step(&self) {
                    let _stmt = self.stmt;
                }
            }

            #[inline(never)]
            fn read_first_column_name<'a>(column_names: &Vec<&'a CStr>) -> Option<&'a CStr> {
                column_names.get(0).copied()
            }

            #[inline(never)]
            fn read_first_column_name_with_first<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.first().copied()
            }

            #[inline(never)]
            fn read_second_column_name<'a>(column_names: &Vec<&'a CStr>) -> Option<&'a CStr> {
                column_names.get(1).copied()
            }

            #[inline(never)]
            fn read_last_column_name<'a>(column_names: &Vec<&'a CStr>) -> Option<&'a CStr> {
                column_names.last().copied()
            }

            #[inline(never)]
            fn read_iter_last_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().last().copied()
            }

            #[inline(never)]
            fn read_iter_nth_second_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().nth(1).copied()
            }

            #[inline(never)]
            fn read_iter_nth_first_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().nth(0).copied()
            }

            #[inline(never)]
            fn read_iter_skip_one_next_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().skip(1).next().copied()
            }

            #[inline(never)]
            fn read_iter_dynamic_nth_column_name<'a>(
                column_names: &Vec<&'a CStr>,
                index: usize,
            ) -> Option<&'a CStr> {
                column_names.iter().nth(index).copied()
            }

            #[inline(never)]
            fn read_iter_local_const_nth_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                let index = 1usize;
                column_names.iter().nth(index).copied()
            }

            #[inline(never)]
            fn read_iter_dynamic_skip_column_name<'a>(
                column_names: &Vec<&'a CStr>,
                skip: usize,
            ) -> Option<&'a CStr> {
                column_names.iter().skip(skip).next().copied()
            }

            #[inline(never)]
            fn read_iter_local_const_skip_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                let skip = 1usize;
                column_names.iter().skip(skip).next().copied()
            }

            #[inline(never)]
            fn read_iter_rev_next_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().rev().next().copied()
            }

            #[inline(never)]
            fn read_iter_rev_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().rev().nth(1).copied()
            }

            #[inline(never)]
            fn read_iter_rev_skip_one_next_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().rev().skip(1).next().copied()
            }

            #[inline(never)]
            fn read_iter_skip_one_rev_next_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().skip(1).rev().next().copied()
            }

            #[inline(never)]
            fn read_iter_take_two_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().take(2).nth(1).copied()
            }

            #[inline(never)]
            fn read_iter_take_one_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().take(1).nth(1).copied()
            }

            #[inline(never)]
            fn read_iter_take_two_last_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().take(2).last().copied()
            }

            #[inline(never)]
            fn read_iter_take_one_last_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().take(1).last().copied()
            }

            #[inline(never)]
            fn read_iter_take_two_rev_next_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().take(2).rev().next().copied()
            }

            #[inline(never)]
            fn read_iter_take_one_rev_next_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().take(1).rev().next().copied()
            }

            #[inline(never)]
            fn read_iter_enumerate_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().enumerate().nth(1).map(|(_, name)| *name)
            }

            #[inline(never)]
            fn read_iter_copied_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().copied().nth(1)
            }

            #[inline(never)]
            fn read_iter_cloned_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().cloned().nth(1)
            }

            #[inline(never)]
            fn read_iter_identity_map_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().map(|name| *name).nth(1)
            }

            #[inline(never)]
            fn read_iter_value_map_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names
                    .iter()
                    .map(|_name| placeholder_column_name())
                    .nth(1)
            }

            #[inline(never)]
            fn read_iter_identity_filter_map_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().filter_map(|name| Some(*name)).nth(1)
            }

            #[inline(never)]
            fn read_iter_value_filter_map_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names
                    .iter()
                    .filter_map(|_name| Some(placeholder_column_name()))
                    .nth(1)
            }

            #[inline(never)]
            fn read_iter_filter_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().filter(|_| true).nth(1).copied()
            }

            #[inline(never)]
            fn read_iter_filter_false_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().filter(|_| false).nth(1).copied()
            }

            #[inline(never)]
            fn read_iter_chain_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names
                    .iter()
                    .chain(column_names.iter())
                    .nth(1)
                    .copied()
            }

            #[inline(never)]
            fn read_iter_zip_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names
                    .iter()
                    .zip(column_names.iter())
                    .nth(1)
                    .map(|(name, _)| *name)
            }

            #[inline(never)]
            fn read_iter_flat_map_nth_one_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names
                    .iter()
                    .flat_map(|name| std::iter::once(name))
                    .nth(1)
                    .copied()
            }

            #[inline(never)]
            fn read_as_slice_second_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.as_slice().get(1).copied()
            }

            #[inline(never)]
            fn read_as_slice_first_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.as_slice().get(0).copied()
            }

            #[inline(never)]
            fn read_range_from_iter_nth_second_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                let names = column_names.get(1..)?;
                names.iter().nth(0).copied()
            }

            #[inline(never)]
            fn read_range_from_iter_nth_first_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                let names = column_names.get(0..)?;
                names.iter().nth(0).copied()
            }

            #[inline(never)]
            fn read_range_full_iter_skip_second_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                let names = column_names.get(..)?;
                names.iter().skip(1).next().copied()
            }

            #[inline(never)]
            fn read_range_full_iter_skip_first_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                let names = column_names.get(..)?;
                names.iter().skip(0).next().copied()
            }

            #[inline(never)]
            fn read_range_to_last_second_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                let names = column_names.get(..2)?;
                names.last().copied()
            }

            #[inline(never)]
            fn read_range_to_last_first_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                let names = column_names.get(..1)?;
                names.last().copied()
            }

            #[inline(never)]
            fn read_range_from_last_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                let names = column_names.get(1..)?;
                names.last().copied()
            }

            #[inline(never)]
            fn read_range_full_last_column_name<'a>(
                column_names: &Vec<&'a CStr>,
            ) -> Option<&'a CStr> {
                let names = column_names.get(..)?;
                names.last().copied()
            }

            pub struct PushVecDequeStorageIterator<'a> {
                stmt: &'a Statement,
                column_names: VecDeque<&'a CStr>,
            }

            impl<'a> PushVecDequeStorageIterator<'a> {
                pub unsafe fn new(stmt: &'a Statement) -> Self {
                    Self {
                        stmt,
                        column_names: VecDeque::new(),
                    }
                }

                pub fn step_then_front_after_clear_and_push_back(&mut self) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push_back(name);
                    }
                    self.step();
                    self.column_names.front().copied()
                }

                pub fn step_then_front_after_clear_placeholder_and_push_back(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push_back(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push_back(name);
                    }
                    self.step();
                    self.column_names.front().copied()
                }

                pub fn step_then_back_after_clear_placeholder_and_push_back(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push_back(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push_back(name);
                    }
                    self.step();
                    self.column_names.back().copied()
                }

                pub fn step_then_back_after_clear_push_back_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push_back(name);
                    }
                    self.column_names.push_back(placeholder_column_name());
                    self.step();
                    self.column_names.back().copied()
                }

                pub fn step_then_iter_next_after_clear_and_push_back(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push_back(name);
                    }
                    self.step();
                    self.column_names.iter().next().copied()
                }

                pub fn step_then_iter_next_after_clear_placeholder_and_push_back(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push_back(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push_back(name);
                    }
                    self.step();
                    self.column_names.iter().next().copied()
                }

                pub fn step_then_iter_last_after_clear_placeholder_and_push_back(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push_back(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push_back(name);
                    }
                    self.step();
                    self.column_names.iter().last().copied()
                }

                pub fn step_then_iter_last_after_clear_push_back_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push_back(name);
                    }
                    self.column_names.push_back(placeholder_column_name());
                    self.step();
                    self.column_names.iter().last().copied()
                }

                pub fn step_then_back_helper_after_clear_placeholder_and_push_back(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push_back(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push_back(name);
                    }
                    self.step();
                    read_back_column_name(&self.column_names)
                }

                pub fn step_then_back_helper_after_clear_push_back_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push_back(name);
                    }
                    self.column_names.push_back(placeholder_column_name());
                    self.step();
                    read_back_column_name(&self.column_names)
                }

                pub fn step_then_iter_last_helper_after_clear_placeholder_and_push_back(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    self.column_names.push_back(placeholder_column_name());
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push_back(name);
                    }
                    self.step();
                    read_deque_iter_last_column_name(&self.column_names)
                }

                pub fn step_then_iter_last_helper_after_clear_push_back_and_placeholder(
                    &mut self,
                ) -> Option<&'a CStr> {
                    self.column_names.clear();
                    if let Some(name) = unsafe { self.stmt.field_name(1) } {
                        self.column_names.push_back(name);
                    }
                    self.column_names.push_back(placeholder_column_name());
                    self.step();
                    read_deque_iter_last_column_name(&self.column_names)
                }

                fn step(&mut self) {
                    let _stmt = self.stmt;
                }
            }

            #[inline(never)]
            fn read_back_column_name<'a>(
                column_names: &VecDeque<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.back().copied()
            }

            #[inline(never)]
            fn read_deque_iter_last_column_name<'a>(
                column_names: &VecDeque<&'a CStr>,
            ) -> Option<&'a CStr> {
                column_names.iter().last().copied()
            }
        }
    }
}

pub mod lifetime_signature {
    use std::marker::PhantomData;

    pub struct Entry<K, V> {
        pub key: K,
        pub value: V,
    }

    pub struct LruCache<K, V> {
        tail: *const Entry<K, V>,
        _marker: PhantomData<(K, V)>,
    }

    pub struct Iter<'a, K, V> {
        ptr: *const Entry<K, V>,
        _marker: PhantomData<(&'a K, &'a V)>,
    }

    impl<K, V> LruCache<K, V> {
        pub fn new() -> Self {
            Self {
                tail: std::ptr::null(),
                _marker: PhantomData,
            }
        }

        pub fn peek_lru<'a>(&'_ self) -> Option<(&'a K, &'a V)> {
            let _tail = self.tail;
            None
        }

        pub fn iter<'a>(&'_ self) -> Iter<'a, K, V> {
            Iter {
                ptr: self.tail,
                _marker: PhantomData,
            }
        }

        pub fn peek_lru_scoped(&self) -> Option<(&K, &V)> {
            let _tail = self.tail;
            None
        }

        pub fn iter_scoped(&self) -> Iter<'_, K, V> {
            Iter {
                ptr: self.tail,
                _marker: PhantomData,
            }
        }
    }

    impl<K, V> Iterator for Iter<'_, K, V> {
        type Item = ();

        fn next(&mut self) -> Option<Self::Item> {
            let _ptr = self.ptr;
            None
        }
    }
}
