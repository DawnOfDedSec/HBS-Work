//! Compile-time testcase registry macro. Every catalog module uses
//! `check!` to push its entries; IDs are asserted unique by the
//! registry integration test.

/// Register one testcase.
///
/// ```ignore
/// check!(reg, "LIN-SSH-001", "title", "description", "impact",
///        "recommendation", Medium, "SSH", &["CIS 5.2.8"],
///        |p| p.os == Os::Linux, ssh_permit_root_login);
/// ```
#[macro_export]
macro_rules! check {
    ($reg:expr, $id:literal, $title:literal, $desc:literal, $impact:literal, $rec:literal, $sev:ident, $cat:literal, $refs:expr, $applies:expr, $run:expr) => {
        $reg.push($crate::model::RegisteredCheck {
            tc: $crate::model::Testcase {
                id: $id,
                title: $title,
                description: $desc,
                impact: $impact,
                recommendation: $rec,
                severity: $crate::model::Severity::$sev,
                category: $cat,
                references: $refs,
            },
            applies: $applies,
            run: $run,
        });
    };
}
