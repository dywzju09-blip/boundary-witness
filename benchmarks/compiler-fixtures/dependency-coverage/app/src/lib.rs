pub fn app_marker() -> i32 {
    let value = 1;
    let callback = move || value;
    coverage_dep::dep_marker() + callback()
}
