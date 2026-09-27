use hbs_extractor::elevate::{is_elevated, request_relaunch};

#[test]
fn is_elevated_returns_bool_without_panicking() {
    let _ = is_elevated();
}

#[test]
fn relaunch_guard_respects_no_elevate() {
    // With --no-elevate the guard must decline immediately - no UAC
    // prompt may ever appear for this call.
    assert!(!request_relaunch(true));
}
