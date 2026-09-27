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
    assert!(read_file_capped(
        PathBuf::from("/definitely/not/here/x").as_path(),
        &mut audit
    )
    .is_none());
    assert!(audit.files_read.is_empty());
}

#[test]
fn evil_program_is_rejected_without_spawn() {
    let mut audit = SelfAudit::default();
    let injector: Option<Box<dyn Fn(&str, &[&str]) -> Option<String>>> =
        Some(Box::new(|prog, _| {
            panic!("injector must not be consulted for blocked programs: {prog}")
        }));
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
fn evidence_allowlist_blocks_export_and_state_changes() {
    let mut audit = SelfAudit::default();
    let injector: Option<Box<dyn Fn(&str, &[&str]) -> Option<String>>> =
        Some(Box::new(|_, _| Some("ok".into())));
    assert!(run_command("reg", &["query", "HKLM\\X"], 1000, &mut audit, &injector).is_some());
    for (program, args) in [
        ("reg", &["delete", "HKLM\\X"][..]),
        ("secedit", &["/export", "/cfg", "policy.inf"][..]),
        ("net", &["stop", "Spooler"][..]),
        ("net", &["start", "Spooler"][..]),
        ("net", &["use", "Z:", r"\\server\\share"][..]),
        ("net", &["accounts", "/minpwlen:7"][..]),
        ("net", &["user", "attacker", "Pass123!", "/add"][..]),
        (
            "netsh",
            &["advfirewall", "set", "allprofiles", "state", "off"][..],
        ),
        (
            "netsh",
            &[
                "interface",
                "ip",
                "set",
                "dns",
                "name=Ethernet",
                "static",
                "1.1.1.1",
            ][..],
        ),
        ("nslookup", &["example.com"][..]),
    ] {
        assert!(
            run_command(program, args, 1000, &mut audit, &injector).is_none(),
            "state-changing/network command passed allowlist: {program} {}",
            args.join(" ")
        );
    }
    for script in [
        "secedit /export /cfg $env:TEMP\\policy.inf",
        "Export-Csv -Path policy.csv",
        "Out-File policy.txt",
        "Set-ItemProperty -Path HKLM:\\Software\\X -Name Y -Value 1",
        "Remove-Item C:\\evidence.txt",
        "New-Item C:\\evidence.txt",
        "Invoke-WebRequest -Uri http://example.com",
        "Invoke-RestMethod -Uri https://example.com/api",
        "Resolve-DnsName example.com",
        "Get-Process > C:\\evidence.txt",
        "Get-Service | Out-File C:\\services.txt",
        "Start-Service -Name Spooler",
        "Get-Process; Remove-Item C:\\evidence.txt",
    ] {
        assert!(
            run_command(
                "powershell",
                &["-NoProfile", "-NonInteractive", "-Command", script],
                1000,
                &mut audit,
                &injector
            )
            .is_none(),
            "write/network-capable PowerShell passed allowlist: {script}"
        );
    }
    assert_eq!(audit.commands, ["reg query HKLM\\X"]);
}

#[test]
fn legitimate_query_commands_pass_allowlist() {
    let mut audit = SelfAudit::default();
    let injector: Option<Box<dyn Fn(&str, &[&str]) -> Option<String>>> =
        Some(Box::new(|_, _| Some("ok".into())));
    for (program, args) in [
        ("net", &["accounts"][..]),
        ("net", &["user"][..]),
        ("net", &["share"][..]),
        ("netsh", &["advfirewall", "show", "allprofiles"][..]),
        ("netsh", &["interface", "ip", "show", "dns"][..]),
        ("reg", &["query", r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "/v", "LimitBlankPasswordUse"][..]),
        ("powershell", &["-NoProfile", "-NonInteractive", "-Command", "$env:COMPUTERNAME"][..]),
        ("powershell", &["-NoProfile", "-NonInteractive", "-Command", "Confirm-SecureBootUEFI"][..]),
        ("powershell", &["-NoProfile", "-NonInteractive", "-Command", "Get-HotFix | Select-Object HotFixID,InstalledOn | ConvertTo-Json -Compress"][..]),
        ("powershell", &["-NoProfile", "-NonInteractive", "-Command", "(Get-ItemProperty -LiteralPath 'Registry::HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LimitBlankPasswordUse' -ErrorAction SilentlyContinue).'LimitBlankPasswordUse'"][..]),
        ("powershell", &["-NoProfile", "-NonInteractive", "-Command", "(Get-CimInstance -Namespace 'root\\rsop\\computer' -ClassName RSOP_SecuritySettingBoolean -Filter \"KeyName='PasswordComplexity'\" -ErrorAction SilentlyContinue | Sort-Object Precedence | Select-Object -First 1 -ExpandProperty Setting)"][..]),
    ] {
        assert!(run_command(program, args, 1000, &mut audit, &injector).is_some(),
            "legitimate query command blocked by allowlist: {program} {}", args.join(" "));
    }
}

#[test]
fn allowlist_contains_required_programs() {
    for p in [
        "uname",
        "ss",
        "systemctl",
        "auditpol",
        "reg",
        "wevtutil",
        "powershell",
        "docker",
        "sc",
        "net",
    ] {
        assert!(COMMAND_ALLOWLIST.contains(&p), "missing {p}");
    }
    assert!(!COMMAND_ALLOWLIST.contains(&"secedit"));
    assert!(!COMMAND_ALLOWLIST.contains(&"nslookup"));
}

#[cfg(unix)]
#[test]
fn real_allowlisted_command_runs() {
    let mut audit = SelfAudit::default();
    let none: Option<Box<dyn Fn(&str, &[&str]) -> Option<String>>> = None;
    let out = run_command("uname", &["-s"], 5000, &mut audit, &none).unwrap();
    assert!(!out.is_empty());
}
