use hbs_extractor::evidence::{read_file_capped, run_command, COMMAND_ALLOWLIST, MAX_READ};
use hbs_extractor::model::SelfAudit;
use std::fs;
use std::path::PathBuf;

fn temp_file(name: &str, bytes: &[u8]) -> PathBuf {
    let p = std::env::temp_dir().join(format!("hbs-test-{}-{}", std::process::id(), name));
    fs::write(&p, bytes).unwrap();
    p
}

#[test]
fn read_is_capped_to_1mb() {
    let big = vec![b'a'; 2 * 1024 * 1024];
    let p = temp_file("big", &big);
    let mut audit = SelfAudit::default();
    let out = read_file_capped(&p, &mut audit).unwrap();
    assert!(out.len() <= MAX_READ);
    assert_eq!(audit.files_read.len(), 1);
    fs::remove_file(&p).ok();
}

#[test]
fn missing_file_returns_none() {
    let mut audit = SelfAudit::default();
    assert!(read_file_capped(PathBuf::from("/definitely/not/here/x").as_path(), &mut audit).is_none());
    assert!(audit.files_read.is_empty());
}

#[test]
fn evil_program_is_rejected_without_spawn() {
    let mut audit = SelfAudit::default();
    let injector: Option<Box<dyn Fn(&str, &[&str]) -> Option<String>>> =
        Some(Box::new(|prog, _| panic!("injector must not be consulted for blocked programs: {prog}")));
    let out = run_command("evil", &["-x"], 1000, &mut audit, &injector);
    assert!(out.is_none());
    assert!(audit.commands.is_empty());
}

#[test]
fn non_allowlisted_case_variants_rejected() {
    let mut audit = SelfAudit::default();
    let none: Option<Box<dyn Fn(&str, &[&str]) -> Option<String>>> = None;
    assert!(run_command("UNAME", &["-s"], 1000, &mut audit, &none).is_none());
}

#[test]
fn injector_canned_output_used_for_allowlisted_command() {
    let mut audit = SelfAudit::default();
    let injector: Option<Box<dyn Fn(&str, &[&str]) -> Option<String>>> =
        Some(Box::new(|prog, args| {
            assert_eq!(prog, "uname");
            assert_eq!(args, ["-s"]);
            Some("Linux".into())
        }));
    let out = run_command("uname", &["-s"], 1000, &mut audit, &injector).unwrap();
    assert_eq!(out, "Linux");
    assert_eq!(audit.commands, vec!["uname -s".to_string()]);
}

#[test]
fn restricted_verb_blocked_and_allowed() {
    let mut audit = SelfAudit::default();
    let injector: Option<Box<dyn Fn(&str, &[&str]) -> Option<String>>> =
        Some(Box::new(|_, _| Some("ok".into())));
    // reg: only query is allowed
    assert!(run_command("reg", &["delete", "HKLM\\X"], 1000, &mut audit, &injector).is_none());
    assert!(run_command("reg", &["query", "HKLM\\X"], 1000, &mut audit, &injector).is_some());
    // secedit: only /export
    assert!(run_command("secedit", &["/import"], 1000, &mut audit, &injector).is_none());
    assert!(run_command("secedit", &["/export"], 1000, &mut audit, &injector).is_some());
}

#[test]
fn allowlist_contains_required_programs() {
    for p in ["uname", "ss", "systemctl", "auditpol", "reg", "secedit", "wevtutil", "powershell", "docker", "sc", "net"] {
        assert!(COMMAND_ALLOWLIST.contains(&p), "missing {p}");
    }
}

#[cfg(unix)]
#[test]
fn real_allowlisted_command_runs() {
    let mut audit = SelfAudit::default();
    let none: Option<Box<dyn Fn(&str, &[&str]) -> Option<String>>> = None;
    let out = run_command("uname", &["-s"], 5000, &mut audit, &none).unwrap();
    assert!(!out.is_empty());
}
