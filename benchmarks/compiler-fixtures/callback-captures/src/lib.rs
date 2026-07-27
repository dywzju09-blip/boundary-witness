pub struct State {
    value: i32,
}

pub struct Pair {
    left: i32,
    right: i32,
}

pub fn borrowed_capture() -> i32 {
    let state = State { value: 1 };
    let callback = || state.value;
    callback()
}

pub fn owned_capture() -> i32 {
    let state = State { value: 2 };
    let callback = move || state.value;
    callback()
}

pub fn multiple_capture() -> i32 {
    let left = State { value: 3 };
    let right = State { value: 4 };
    let callback = || left.value + right.value;
    callback()
}

pub fn renamed_capture() -> i32 {
    let renamed = State { value: 5 };
    let callback = || renamed.value;
    callback()
}

pub fn branch_callback(flag: bool) -> i32 {
    let state = State { value: 6 };
    let callback = || state.value;
    if flag { callback() } else { 0 }
}

pub fn field_projection_capture() -> i32 {
    let pair = Pair { left: 7, right: 8 };
    let callback = || pair.left;
    callback()
}

pub fn two_field_projection_capture() -> i32 {
    let pair = Pair { left: 9, right: 10 };
    let callback = || pair.left + pair.right;
    callback()
}
