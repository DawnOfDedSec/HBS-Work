use std::collections::BTreeMap;

use hbs_extractor::checks::windows::user_rights::{
    evaluate_user_right, SidAccount, UserRightMap, USER_RIGHT_CHECKS,
};
use hbs_extractor::checks::windows;
use hbs_extractor::model::Status;

const ADMINISTRATORS: &str = "S-1-5-32-544";
const SYSTEM: &str = "S-1-5-18";
const LOCAL_SERVICE: &str = "S-1-5-19";
const NETWORK_SERVICE: &str = "S-1-5-20";
const GUESTS: &str = "S-1-5-32-546";
const EVERYONE: &str = "S-1-1-0";

fn account(sid: &str, name: &str) -> SidAccount {
    SidAccount {
        sid: sid.into(),
        name: name.into(),
    }
}

fn good_rights() -> UserRightMap {
    BTreeMap::from([
        ("SeDebugPrivilege".into(), vec![account(ADMINISTRATORS, "BUILTIN\\Administrators")]),
        ("SeTcbPrivilege".into(), vec![]),
        (
            "SeAssignPrimaryTokenPrivilege".into(),
            vec![account(ADMINISTRATORS, "BUILTIN\\Administrators"), account(SYSTEM, "NT AUTHORITY\\SYSTEM")],
        ),
        (
            "SeIncreaseQuotaPrivilege".into(),
            vec![account(ADMINISTRATORS, "BUILTIN\\Administrators"), account(SYSTEM, "NT AUTHORITY\\SYSTEM")],
        ),
        ("SeRemoteShutdownPrivilege".into(), vec![account(ADMINISTRATORS, "BUILTIN\\Administrators")]),
        ("SeNetworkLogonRight".into(), vec![account(ADMINISTRATORS, "BUILTIN\\Administrators")]),
        ("SeInteractiveLogonRight".into(), vec![account(ADMINISTRATORS, "BUILTIN\\Administrators")]),
        ("SeDenyNetworkLogonRight".into(), vec![account(GUESTS, "BUILTIN\\Guests")]),
        ("SeDenyInteractiveLogonRight".into(), vec![account(GUESTS, "BUILTIN\\Guests")]),
        ("SeCreatePagefilePrivilege".into(), vec![account(ADMINISTRATORS, "BUILTIN\\Administrators")]),
        ("SeLockMemoryPrivilege".into(), vec![]),
        (
            "SeCreateGlobalPrivilege".into(),
            vec![
                account(ADMINISTRATORS, "BUILTIN\\Administrators"),
                account(SYSTEM, "NT AUTHORITY\\SYSTEM"),
                account(LOCAL_SERVICE, "NT AUTHORITY\\LOCAL SERVICE"),
                account(NETWORK_SERVICE, "NT AUTHORITY\\NETWORK SERVICE"),
            ],
        ),
        ("SeProfileSingleProcessPrivilege".into(), vec![account(ADMINISTRATORS, "BUILTIN\\Administrators")]),
        ("SeMachineAccountPrivilege".into(), vec![]),
        ("SeSyncAgentPrivilege".into(), vec![]),
        ("SeEnableDelegationPrivilege".into(), vec![]),
    ])
}

#[test]
fn registers_sixteen_stable_user_right_ids() {
    let mut registry = Vec::new();
    windows::user_rights::register(&mut registry);
    assert_eq!(
        registry.iter().map(|check| check.tc.id).collect::<Vec<_>>(),
        (1..=16)
            .map(|number| format!("WIN-UR-{number:03}"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn portable_sid_map_passes_all_sixteen_requirements() {
    let rights = good_rights();
    for def in USER_RIGHT_CHECKS {
        let accounts = rights.get(def.right).expect("fixture covers every right");
        let outcome = evaluate_user_right(def, Ok(accounts));
        assert_eq!(outcome.status, Status::Compliant, "{}: {}", def.id, outcome.evidence);
    }
}

#[test]
fn unexpected_or_missing_assignments_fail_each_requirement_kind() {
    let bad = account(EVERYONE, "Everyone");
    for def in USER_RIGHT_CHECKS {
        let accounts = match def.id {
            "WIN-UR-008" | "WIN-UR-009" => Vec::new(),
            _ => vec![bad.clone()],
        };
        let outcome = evaluate_user_right(def, Ok(&accounts));
        assert_eq!(outcome.status, Status::NonCompliant, "{}: {}", def.id, outcome.evidence);
    }
}

#[test]
fn sid_evaluation_is_independent_of_localized_account_names() {
    let localized_admin = [account(ADMINISTRATORS, "VORDEFINIERT\\Administratoren")];
    let outcome = evaluate_user_right(&USER_RIGHT_CHECKS[0], Ok(&localized_admin));
    assert_eq!(outcome.status, Status::Compliant, "{}", outcome.evidence);

    let localized_guest = [account(GUESTS, "BUILTIN\\Invités")];
    let outcome = evaluate_user_right(&USER_RIGHT_CHECKS[7], Ok(&localized_guest));
    assert_eq!(outcome.status, Status::Compliant, "{}", outcome.evidence);
}

#[test]
fn access_denied_and_unsupported_degrade_never_error() {
    for reason in ["LsaOpenPolicy: access denied", "unsupported platform"] {
        for def in USER_RIGHT_CHECKS {
            let outcome = evaluate_user_right(def, Err(reason));
            assert_eq!(outcome.status, Status::DegradedPartial, "{}", def.id);
            assert_ne!(outcome.status, Status::Error);
            assert!(outcome.evidence.contains(reason), "{}", outcome.evidence);
            assert_eq!(outcome.fallback_log.len(), 1);
        }
    }
}
