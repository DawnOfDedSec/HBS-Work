use hbs_extractor::checks::{evidence_at, register_all};
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::model::{RegisteredCheck, Status};
use hbs_extractor::platform::{detect, DistroFamily, Os};

fn linux_ctx(root: &str) -> ScanContext {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Debian;
    ScanContext::new(p, false)
        .with_root_prefix(root)
        .with_injector(Box::new(|_, _| None))
}

#[test]
fn evidence_block_pins_line_col_and_redacts() {
    let mut ctx = linux_ctx("tests/fixtures/ssh-weak");
    let b = evidence_at(&mut ctx, "/etc/ssh/sshd_config", "PermitRootLogin").expect("block found");
    assert_eq!(b.path, "/etc/ssh/sshd_config");
    assert_eq!(b.line, 1);
    assert_eq!(b.col, 1);
    assert!(b.context.len() <= 7);
    assert_eq!(b.target_index as usize + 1, b.line as usize);
    // redacted context must not leak secrets in adjacent lines
    assert!(b.context.iter().all(|l| !l.contains("$6$")));
}

#[test]
fn evidence_block_column_is_char_accurate() {
    let mut ctx = linux_ctx("tests/fixtures/ssh-weak");
    let b = evidence_at(&mut ctx, "/etc/ssh/sshd_config", "yes").expect("found");
    // 'PermitRootLogin yes' — 'yes' starts at char 17
    assert_eq!(b.col, 17, "col was {}", b.col);
}

#[test]
fn ssh_check_result_carries_evidence_block() {
    let mut ctx = linux_ctx("tests/fixtures/ssh-weak");
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut reg);
    let subset: Vec<RegisteredCheck> = reg
        .into_iter()
        .filter(|c| c.tc.id == "LIN-SSH-001")
        .collect();
    let out = run_all(&subset, &mut ctx).remove(0);
    assert_eq!(out.status, Status::NonCompliant);
    assert_eq!(
        out.evidence_blocks.len(),
        1,
        "ssh_kv must attach the pinpoint block"
    );
    assert_eq!(out.evidence_blocks[0].path, "/etc/ssh/sshd_config");
    assert_eq!(out.evidence_blocks[0].line, 1);
}
