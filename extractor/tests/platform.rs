use hbs_extractor::platform::{detect, lower_own_priority, parse_os_release, DistroFamily, Os};

#[test]
fn os_release_families() {
    let ubuntu = "NAME=\"Ubuntu\"\nVERSION=\"24.04\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=24.04\n";
    let rocky = "NAME=\"Rocky Linux\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n";
    let alpine = "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.0\n";
    let arch = "NAME=\"Arch Linux\"\nID=arch\n";
    assert_eq!(parse_os_release(ubuntu).1, DistroFamily::Debian);
    assert_eq!(parse_os_release(rocky).1, DistroFamily::Rhel);
    assert_eq!(parse_os_release(alpine).1, DistroFamily::Alpine);
    assert_eq!(parse_os_release(arch).1, DistroFamily::Arch);
    assert_eq!(parse_os_release(ubuntu).0.as_deref(), Some("Ubuntu"));
    assert_eq!(parse_os_release(""), (None, DistroFamily::Unknown));
}

#[test]
fn detect_matches_host_os() {
    let p = detect();
    if cfg!(windows) {
        assert_eq!(p.os, Os::Windows);
    } else {
        assert_eq!(p.os, Os::Linux);
    }
    assert!(!p.arch.is_empty());
    assert!(!p.kernel.is_empty());
}

#[test]
fn priority_lowering_never_panics() {
    lower_own_priority(); // idempotent, safe to call twice
    lower_own_priority();
}

#[cfg(unix)]
#[test]
fn nice_actually_increases() {
    let before = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
    lower_own_priority();
    let after = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
    assert!(after > before, "nice did not increase: {before} -> {after}");
}
