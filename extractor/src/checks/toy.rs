//! Seed module proving the registry pattern end-to-end. Replaced by
//! real catalog modules in Phase 2; the toy check is never applicable
//! on real hosts (`applies` is always false) but keeps the registry
//! non-empty during core development.

use crate::model::RegisteredCheck;

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    reg.push(RegisteredCheck {
        tc: crate::model::Testcase {
            id: "GEN-TOY-001",
            title: "Registry self-test",
            description: "Seed entry proving the catalog builds; never runs on hosts.",
            impact: "None.",
            recommendation: "None.",
            severity: crate::model::Severity::Informational,
            category: "SelfTest",
            references: &[],
        },
        applies: |_| false,
        run: |_| unreachable!("toy check must never run"),
    });
}
