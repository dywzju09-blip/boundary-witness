pub fn dep_marker() -> i32 {
    let value = 41;
    let callback = move || value;
    callback()
}
