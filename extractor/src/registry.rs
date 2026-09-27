//! Compile-time testcase registry macro. Every catalog module uses
//! `check!` to push its entries; IDs are asserted unique by the
//! registry integration test.

/// Register one testcase (no admin rights required).
///
/// ```ignore
/// check!(reg, "LIN-SSH-001", "title", "description", "impact",
///        "recommendation", Medium, "SSH", &["CIS 5.2.8"],
///        |p| p.os == Os::Linux, ssh_permit_root_login);
/// ```
#[macro_export]
macro_rules! check {
    ($reg:expr, $id:literal, $title:literal, $desc:literal, $impact:literal, $rec:literal, $sev:ident, $cat:literal, $refs:expr, $applies:expr, $run:expr) => {
        $crate::check_admin!(
            $reg, $id, $title, $desc, $impact, $rec, $sev, $cat, $refs, false, $applies, $run
        );
    };
}

/// Register a testcase that requires admin/root rights to reach full
/// depth. When the scan runs unprivileged, the engine skips it with an
/// explicit "requires elevation" reason instead of running degraded.
#[macro_export]
macro_rules! check_admin {
    ($reg:expr, $id:literal, $title:literal, $desc:literal, $impact:literal, $rec:literal, $sev:ident, $cat:literal, $refs:expr, $applies:expr, $run:expr) => {
        $crate::check_admin!(
            $reg, $id, $title, $desc, $impact, $rec, $sev, $cat, $refs, true, $applies, $run
        );
    };
    ($reg:expr, $id:literal, $title:literal, $desc:literal, $impact:literal, $rec:literal, $sev:ident, $cat:literal, $refs:expr, $admin:literal, $applies:expr, $run:expr) => {
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
            admin: $admin,
            run: $run,
        });
    };
}
