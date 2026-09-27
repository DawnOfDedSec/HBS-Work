//! LIN-USER: users, permissions and system maintenance (CIS 6.1/6.2).

use crate::checks::{degraded, degraded_from_attempts, nok, ok, with_block};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(
        reg,
        "LIN-USER-001",
        "/etc/passwd permissions",
        "0644 root:root.",
        "Writable passwd = instant root via crafted entries.",
        "chmod 644 /etc/passwd; chown root:root.",
        High,
        "Users",
        &["CIS 6.1.2"],
        linux,
        |c| file_mode(c, "/etc/passwd", 0o644, false)
    );
    check!(
        reg,
        "LIN-USER-002",
        "/etc/passwd owned by root",
        "root:root ownership.",
        "Foreign owners can rewrite account maps.",
        "chown root:root /etc/passwd.",
        High,
        "Users",
        &["CIS 6.1.1"],
        linux,
        |c| file_owner_root(c, "/etc/passwd")
    );
    check!(
        reg,
        "LIN-USER-003",
        "/etc/shadow permissions",
        "0600 (some distros 0640 root:shadow).",
        "Readable shadow = offline hash cracking for every user.",
        "chmod 600 /etc/shadow (or distro-blessed 640 root:shadow).",
        High,
        "Users",
        &["CIS 6.1.3"],
        linux,
        shadow_mode
    );
    check!(
        reg,
        "LIN-USER-004",
        "/etc/shadow owned by root",
        "root (or root:shadow) ownership.",
        "Wrong owners can nullify or read hashes.",
        "chown root:shadow /etc/shadow.",
        High,
        "Users",
        &["CIS 6.1.4"],
        linux,
        |c| file_owner_root(c, "/etc/shadow")
    );
    check!(
        reg,
        "LIN-USER-005",
        "/etc/gshadow-* permissions",
        "0600 root:root (Debian: 640 root:shadow).",
        "Group hashes leak the same way.",
        "chmod 600 /etc/gshadow.",
        Medium,
        "Users",
        &["CIS 6.1.5-6"],
        linux,
        |c| file_mode(c, "/etc/gshadow", 0o600, true)
    );
    check!(
        reg,
        "LIN-USER-006",
        "/etc/group permissions",
        "0644 root:root.",
        "Writable group maps grant group escalation.",
        "chmod 644 /etc/group.",
        Medium,
        "Users",
        &["CIS 6.1.7-8"],
        linux,
        |c| file_mode(c, "/etc/group", 0o644, false)
    );
    check!(
        reg,
        "LIN-USER-007",
        "/etc/shadow empty passwords",
        "No user may have an empty hash field.",
        "Empty fields log in without any secret.",
        "passwd -l <user>; never blank hashes.",
        High,
        "Users",
        &["CIS 6.2.1"],
        linux,
        shadow_empty_passwords
    );
    check!(
        reg,
        "LIN-USER-008",
        "No legacy + passwd entries",
        "NIS + lines must be absent.",
        "+:: entries grant wildcard access.",
        "Remove +::* lines from passwd/group.",
        Medium,
        "Users",
        &["CIS 6.2.2"],
        linux,
        |c| no_plus_entries(c, "/etc/passwd")
    );
    check!(
        reg,
        "LIN-USER-009",
        "No legacy + shadow entries",
        "NIS + lines must be absent.",
        "Same wildcard risk for hashes.",
        "Remove +:: lines from shadow.",
        Medium,
        "Users",
        &["CIS 6.2.3"],
        linux,
        |c| no_plus_entries(c, "/etc/shadow")
    );
    check!(
        reg,
        "LIN-USER-010",
        "No legacy + group entries",
        "NIS + lines must be absent.",
        "Group wildcard escalation.",
        "Remove +:: lines from group.",
        Medium,
        "Users",
        &["CIS 6.2.4"],
        linux,
        |c| no_plus_entries(c, "/etc/group")
    );
    check!(
        reg,
        "LIN-USER-011",
        "Root is the only UID-0 account",
        "Exactly one uid 0.",
        "Extra uid-0 accounts are backdoor superusers.",
        "Demote or remove extra uid-0 accounts.",
        High,
        "Users",
        &["CIS 6.2.5"],
        linux,
        uid0_accounts
    );
    check!(
        reg,
        "LIN-USER-012",
        "No duplicate UIDs",
        "UIDs unique.",
        "Duplicate UIDs defeat attribution and auditing.",
        "Reassign colliding UIDs.",
        Medium,
        "Users",
        &["CIS 6.2.6"],
        linux,
        |c| no_dup_field(c, 2, "UID")
    );
    check!(
        reg,
        "LIN-USER-013",
        "No duplicate usernames",
        "Usernames unique.",
        "Login ambiguity breaks all accountability.",
        "Rename duplicates.",
        Medium,
        "Users",
        &["CIS 6.2.7"],
        linux,
        |c| no_dup_field(c, 0, "username")
    );
    check!(
        reg,
        "LIN-USER-014",
        "No duplicate GIDs",
        "GIDs unique.",
        "Group collisions over-grant.",
        "Fix group ids.",
        Medium,
        "Users",
        &["CIS 6.2.8"],
        linux,
        |c| no_dup_gid(c)
    );
    check!(
        reg,
        "LIN-USER-015",
        "Root PATH clean",
        "No group/world-writable or empty entries in root PATH.",
        "Poisoned root PATH plants command hijacks.",
        "Strip writable/empty/duplicate PATH entries for root.",
        Medium,
        "Users",
        &["CIS 6.2.10"],
        linux,
        root_path
    );
    check!(
        reg,
        "LIN-USER-016",
        "Home directories permissions",
        "0750 or stricter.",
        "World-readable homes leak keys/history.",
        "chmod 750 /home/<user>.",
        Medium,
        "Users",
        &["CIS 6.2.18"],
        linux,
        home_perms
    );
    check!(
        reg,
        "LIN-USER-017",
        "Dotfiles not group/world writable",
        "Users' rc files writable only by owner.",
        "Writable .bashrc = persistent code exec on next login.",
        "chmod go-w ~/.bashrc ~/.profile etc.",
        Medium,
        "Users",
        &["CIS 6.2.19"],
        linux,
        dotfile_perms
    );
    check!(
        reg,
        "LIN-USER-018",
        "No .forward/.rhosts for users",
        "Legacy trust files absent.",
        ".rhosts grants passwordless trust; .forward pipes mail to commands.",
        "Remove forward/rhosts files.",
        Medium,
        "Users",
        &["CIS 6.2.20"],
        linux,
        no_forward_rhosts
    );
    check!(
        reg,
        "LIN-USER-019",
        "Umask defaults to 027 or stricter",
        "login.defs/profile umask.",
        "Loose umask creates world-readable secrets by default.",
        "umask 027 in /etc/login.defs + profile.",
        Low,
        "Users",
        &["CIS 5.4.4"],
        linux,
        umask_check
    );
    check!(
        reg,
        "LIN-USER-020",
        "crontab and cron dirs permissions",
        "Cron files root-owned, not world-writable.",
        "Writable cron = scheduled root execution.",
        "chmod 600 crontabs; 700 cron dirs.",
        Medium,
        "Users",
        &["CIS 6.1.9-11"],
        linux,
        cron_perms
    );
}

fn linux(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Linux
}

fn file_mode(ctx: &mut ScanContext, path: &str, want: u32, debian_loose: bool) -> CheckOutcome {
    let block = crate::checks::evidence_at(ctx, path, "");
    match ctx.unix_mode(path) {
        Some(mode) => {
            let loose_ok = debian_loose && mode == 0o640;
            if mode <= want || loose_ok {
                ok(
                    format!("{path} mode {mode:o}"),
                    path.into(),
                    format!("stat -c '%a' {path}"),
                )
            } else {
                with_block(
                    nok(
                        format!("{path} mode {mode:o} (expected <= {want:o})"),
                        path.into(),
                        format!("stat -c '%a' {path}"),
                    ),
                    block,
                )
            }
        }
        None => degraded(&format!(
            "{path} metadata not readable (needs root for some files)"
        )),
    }
}

fn shadow_mode(ctx: &mut ScanContext) -> CheckOutcome {
    // Debian-family allows 0640 root:shadow
    let debian = matches!(ctx.platform.family, crate::platform::DistroFamily::Debian);
    let want = if debian { 0o640 } else { 0o600 };
    file_mode(ctx, "/etc/shadow", want, debian)
}

fn file_owner_root(ctx: &mut ScanContext, path: &str) -> CheckOutcome {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let p = ctx.path(path);
        if let Ok(md) = std::fs::metadata(p) {
            let uid = md.uid();
            let gid = md.gid();
            if uid == 0 && (gid == 0 || path.ends_with("shadow") || path.ends_with("gshadow")) {
                ok(
                    format!(
                        "{path} owned by {uid}:{gid} (root acceptable)",
                        uid = uid,
                        gid = gid
                    ),
                    path.into(),
                    format!("stat -c '%U:%G' {path}"),
                )
            } else if uid == 0 {
                ok(
                    format!("{path} owned by 0:{gid}"),
                    path.into(),
                    format!("stat -c '%U:%G' {path}"),
                )
            } else {
                nok(
                    format!("{path} NOT owned by root (uid={uid})"),
                    path.into(),
                    format!("stat -c '%U' {path}"),
                )
            }
        } else {
            degraded(&format!("{path} not statable (may need root)"))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (ctx, path);
        degraded("ownership checks run on unix hosts")
    }
}

fn shadow_text(ctx: &mut ScanContext) -> Option<String> {
    ctx.read("/etc/shadow").or_else(|| {
        // unprivileged hosts can't read shadow — that itself is good
        None
    })
}

fn shadow_empty_passwords(ctx: &mut ScanContext) -> CheckOutcome {
    match shadow_text(ctx) {
        Some(s) => {
            let empty: Vec<String> = s
                .lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    (f.len() >= 3 && (f[2].is_empty() || f[2] == "!" || f[1].is_empty() && !f[2].is_empty()))
                        .then(|| f[0].to_string())
                })
                .filter(|u| {
                    // locked accounts (! / *) are fine; truly empty is not
                    let line = s.lines().find(|l| l.starts_with(&format!("{u}:"))).unwrap_or("");
                    let hash = line.split(':').nth(1).unwrap_or("");
                    hash.is_empty()
                })
                .collect();
            if empty.is_empty() {
                ok("no empty password hashes in /etc/shadow".into(), "/etc/shadow".into(), "awk -F: '($2==\"\") {print}' /etc/shadow".into())
            } else {
                nok(format!("accounts with EMPTY passwords: {}", empty.join(", ")), "/etc/shadow".into(), "awk -F: '($2==\"\")' /etc/shadow".into())
            }
        }
        None => degraded("/etc/shadow not readable — run with --elevate to verify empty passwords (unreadable itself suggests correct perms)"),
    }
}

fn no_plus_entries(ctx: &mut ScanContext, path: &str) -> CheckOutcome {
    match ctx.read(path) {
        Some(c) => {
            let plus: Vec<&str> = c.lines().filter(|l| l.starts_with('+')).collect();
            if plus.is_empty() {
                ok(
                    format!("no legacy + entries in {path}"),
                    path.into(),
                    format!("grep '^+' {path}"),
                )
            } else {
                nok(
                    format!("legacy + entries in {path}: {}", plus.len()),
                    path.into(),
                    format!("grep '^+' {path}"),
                )
            }
        }
        None => degraded(&format!("{path} not readable")),
    }
}

fn uid0_accounts(ctx: &mut ScanContext) -> CheckOutcome {
    match ctx.read("/etc/passwd") {
        Some(c) => {
            let uid0: Vec<String> = c
                .lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    (f.len() >= 3 && f[2] == "0").then(|| f[0].to_string())
                })
                .collect();
            if uid0.len() <= 1 && uid0.first().map(|u| u == "root").unwrap_or(true) {
                ok(
                    "root is the only uid-0 account".into(),
                    "/etc/passwd".into(),
                    "awk -F: '($3==0)' /etc/passwd".into(),
                )
            } else {
                nok(
                    format!("uid-0 accounts: {}", uid0.join(", ")),
                    "/etc/passwd".into(),
                    "awk -F: '($3==0)' /etc/passwd".into(),
                )
            }
        }
        None => degraded_from_attempts(
            vec![FallbackAttempt {
                source: "/etc/passwd".into(),
                outcome: "missing".into(),
            }],
            "/etc/passwd missing",
        ),
    }
}

fn no_dup_field(ctx: &mut ScanContext, field: usize, label: &str) -> CheckOutcome {
    match ctx.read("/etc/passwd") {
        Some(c) => {
            let mut seen = std::collections::HashMap::new();
            let mut dups: Vec<String> = Vec::new();
            for line in c.lines() {
                let f: Vec<&str> = line.split(':').collect();
                if f.len() > field {
                    let e = seen.entry(f[field].to_string()).or_insert(0usize);
                    *e += 1;
                    if *e == 2 {
                        dups.push(f[field].to_string());
                    }
                }
            }
            if dups.is_empty() {
                ok(
                    format!("no duplicate {label}s"),
                    "/etc/passwd".into(),
                    format!("cut -d: -f{} /etc/passwd | sort | uniq -d", field + 1),
                )
            } else {
                nok(
                    format!("duplicate {label}s: {}", dups.join(", ")),
                    "/etc/passwd".into(),
                    "see evidence".into(),
                )
            }
        }
        None => degraded_from_attempts(
            vec![FallbackAttempt {
                source: "/etc/passwd".into(),
                outcome: "missing".into(),
            }],
            "/etc/passwd missing",
        ),
    }
}

fn no_dup_gid(ctx: &mut ScanContext) -> CheckOutcome {
    match ctx.read("/etc/group") {
        Some(c) => {
            let mut seen = std::collections::HashMap::new();
            let mut dups: Vec<String> = Vec::new();
            for line in c.lines() {
                let f: Vec<&str> = line.split(':').collect();
                if f.len() > 2 {
                    let e = seen.entry(f[2].to_string()).or_insert(0usize);
                    *e += 1;
                    if *e == 2 {
                        dups.push(f[2].to_string());
                    }
                }
            }
            if dups.is_empty() {
                ok(
                    "no duplicate GIDs".into(),
                    "/etc/group".into(),
                    "cut -d: -f3 /etc/group | sort | uniq -d".into(),
                )
            } else {
                nok(
                    format!("duplicate GIDs: {}", dups.join(", ")),
                    "/etc/group".into(),
                    "see evidence".into(),
                )
            }
        }
        None => degraded("/etc/group not readable"),
    }
}

fn root_path(ctx: &mut ScanContext) -> CheckOutcome {
    let raw = std::env::var("PATH").unwrap_or_default();
    let _ = raw;
    // Root PATH source: /etc/profile + root's profile when readable
    let mut path_entries: Vec<String> = Vec::new();
    for p in ["/etc/profile", "/root/.bash_profile", "/root/.profile"] {
        if let Some(c) = ctx.read(p) {
            for line in c.lines() {
                if let Some(v) = line.trim_start().strip_prefix("PATH=") {
                    let v = v.trim().trim_matches('"');
                    path_entries = v.split(':').map(str::to_string).collect();
                }
            }
        }
    }
    if path_entries.is_empty() {
        return degraded(
            "root PATH definition not readable — verify manually for writable entries",
        );
    }
    let mut bad = Vec::new();
    for e in &path_entries {
        if e.is_empty() {
            bad.push("(empty PATH entry)".to_string());
            continue;
        }
        if let Some(mode) = ctx.unix_mode(e) {
            if mode & 0o002 != 0 {
                bad.push(format!("{e} is world-writable"));
            } else if mode & 0o020 != 0 {
                bad.push(format!("{e} is group-writable"));
            }
        }
    }
    if bad.is_empty() {
        ok(
            format!("root PATH clean ({} entries)", path_entries.len()),
            "/etc/profile".into(),
            "echo $PATH".into(),
        )
    } else {
        nok(
            bad.join("; "),
            "/etc/profile".into(),
            "check writable dirs in root PATH".into(),
        )
    }
}

fn home_perms(ctx: &mut ScanContext) -> CheckOutcome {
    let Some(passwd) = ctx.read("/etc/passwd") else {
        return degraded("/etc/passwd not readable");
    };
    let mut bad = Vec::new();
    let mut checked = 0;
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 6 {
            continue;
        }
        let uid: u32 = f[2].parse().unwrap_or(u32::MAX);
        if uid < 1000 || f[5] == "/nonexistent" {
            continue;
        }
        if let Some(mode) = ctx.unix_mode(f[5]) {
            checked += 1;
            if mode & 0o027 != 0 {
                bad.push(format!("{} is {mode:o}", f[5]));
            }
        }
    }
    if checked == 0 {
        return degraded("no home directories statable");
    }
    if bad.is_empty() {
        ok(
            format!("{checked} home directories checked, none group/world writable"),
            "/home".into(),
            "ls -ld /home/*".into(),
        )
    } else {
        nok(bad.join("; "), "/home".into(), "ls -ld /home/*".into())
    }
}

fn dotfile_perms(ctx: &mut ScanContext) -> CheckOutcome {
    let Some(passwd) = ctx.read("/etc/passwd") else {
        return degraded("/etc/passwd not readable");
    };
    let mut bad = Vec::new();
    let mut checked = 0;
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 6 {
            continue;
        }
        let uid: u32 = f[2].parse().unwrap_or(u32::MAX);
        if uid < 1000 {
            continue;
        }
        for dot in [".bashrc", ".profile", ".bash_profile", ".kshrc", ".cshrc"] {
            let p = format!("{}/{}", f[5], dot);
            if let Some(mode) = ctx.unix_mode(&p) {
                checked += 1;
                if mode & 0o022 != 0 {
                    bad.push(format!("{p} is {mode:o}"));
                }
            }
        }
    }
    if checked == 0 {
        return degraded("no user dotfiles statable");
    }
    if bad.is_empty() {
        ok(
            format!("{checked} dotfiles checked, none group/world writable"),
            "user homes".into(),
            "ls -la ~/*".into(),
        )
    } else {
        nok(bad.join("; "), "user homes".into(), "ls -la ~/*".into())
    }
}

fn no_forward_rhosts(ctx: &mut ScanContext) -> CheckOutcome {
    let Some(passwd) = ctx.read("/etc/passwd") else {
        return degraded("/etc/passwd not readable");
    };
    let mut found = Vec::new();
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 6 {
            continue;
        }
        for name in [".forward", ".rhosts", ".netrc"] {
            let p = format!("{}/{}", f[5], name);
            if ctx.exists(&p) {
                found.push(p);
            }
        }
    }
    if found.is_empty() {
        ok(
            "no .forward/.rhosts/.netrc files".into(),
            "user homes".into(),
            "find /home -name '.forward' -o -name '.rhosts'".into(),
        )
    } else {
        nok(
            format!("legacy trust files: {}", found.join(", ")),
            "user homes".into(),
            "see evidence".into(),
        )
    }
}

fn umask_check(ctx: &mut ScanContext) -> CheckOutcome {
    let mut value = None;
    if let Some(defs) = ctx.read("/etc/login.defs") {
        value = defs.lines().map(str::trim_start).find_map(|l| {
            l.strip_prefix("UMASK")
                .and_then(|r| r.trim().split_whitespace().next().map(str::to_string))
        });
    }
    let loc = "/etc/login.defs".to_string();
    match value.as_deref() {
        Some(v @ ("027" | "077" | "022" | "072" | "026" | "017" | "027")) => {
            let strict = v == "027" || v == "077";
            if strict {
                ok(
                    format!("UMASK {v}"),
                    loc,
                    "grep UMASK /etc/login.defs".into(),
                )
            } else {
                nok(
                    format!("UMASK {v} (expected 027/077 for stricter defaults)"),
                    loc,
                    "grep UMASK /etc/login.defs".into(),
                )
            }
        }
        Some(v) => nok(
            format!("UMASK {v} is permissive"),
            loc,
            "grep UMASK /etc/login.defs".into(),
        ),
        None => degraded("UMASK not set in login.defs (shell defaults apply)"),
    }
}

fn cron_perms(ctx: &mut ScanContext) -> CheckOutcome {
    let mut bad = Vec::new();
    let mut checked = 0;
    for p in [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ] {
        if let Some(mode) = ctx.unix_mode(p) {
            checked += 1;
            if mode & 0o022 != 0 {
                bad.push(format!("{p} is {mode:o}"));
            }
        }
    }
    if checked == 0 {
        return degraded("cron paths not statable (not installed?)");
    }
    if bad.is_empty() {
        ok(
            format!("{checked} cron paths checked"),
            "/etc/cron*".into(),
            "ls -ld /etc/cron*".into(),
        )
    } else {
        nok(
            bad.join("; "),
            "/etc/cron*".into(),
            "ls -ld /etc/cron*".into(),
        )
    }
}
