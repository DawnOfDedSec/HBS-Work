//! Windows-only tests for the native, in-process registry/account
//! helpers. These read stable, harmless OS keys and never mutate state.
#![cfg(windows)]

use hbs_extractor::checks::windows::native_accounts;
use hbs_extractor::checks::windows::native_reg::{
    native_reg_dword, native_reg_enum_subkeys, native_reg_enum_subkeys_view,
    native_reg_enum_values, native_reg_sz, RegView,
};

const CURRENT_VERSION: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";

#[test]
fn native_reg_sz_reads_stable_product_version() {
    // ProductName and CurrentVersion are present on every supported
    // Windows build and are harmless to read.
    let product = native_reg_sz(CURRENT_VERSION, "ProductName")
        .or_else(|| native_reg_sz(CURRENT_VERSION, "CurrentVersion"))
        .expect("ProductName or CurrentVersion must be readable");
    assert!(!product.trim().is_empty(), "empty product string");
}

#[test]
fn native_reg_dword_reads_stable_build_number() {
    // CurrentMajorVersionNumber is a REG_DWORD on Windows 10/Server 2016+.
    let major = native_reg_dword(CURRENT_VERSION, "CurrentMajorVersionNumber")
        .expect("CurrentMajorVersionNumber must be readable");
    assert!(major >= 6, "unexpected major version {major}");
}

#[test]
fn native_reg_enum_subkeys_and_values_are_non_empty() {
    let subkeys = native_reg_enum_subkeys(CURRENT_VERSION).expect("enumerate subkeys");
    assert!(
        subkeys
            .iter()
            .any(|s| s.eq_ignore_ascii_case("ProfileList")),
        "ProfileList expected among {subkeys:?}"
    );

    let values = native_reg_enum_values(CURRENT_VERSION).expect("enumerate values");
    assert!(
        values
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("CurrentVersion")),
        "CurrentVersion expected among {values:?}"
    );
}

#[test]
fn native_reg_supports_both_registry_views() {
    // HKLM\SOFTWARE exists in both the native and WOW6432Node views.
    for view in [RegView::Default, RegView::Wow64_32, RegView::Wow64_64] {
        let subkeys = native_reg_enum_subkeys_view(r"HKLM\SOFTWARE", view)
            .unwrap_or_else(|| panic!("HKLM\\SOFTWARE unreadable in {view:?}"));
        assert!(!subkeys.is_empty(), "no subkeys in {view:?}");
    }
}

#[test]
fn native_reg_ifeo_key_is_enumerable() {
    // WIN-TH-015 depends on being able to enumerate IFEO natively.
    let subkeys = native_reg_enum_subkeys(
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    );
    assert!(subkeys.is_some(), "IFEO key must be enumerable");
}

#[test]
fn native_reg_failures_return_none_never_panic() {
    assert!(native_reg_sz(r"HKLM\SOFTWARE\NoSuchKeyHbsTest", "x").is_none());
    assert!(native_reg_dword(r"HKLM\SOFTWARE\NoSuchKeyHbsTest", "x").is_none());
    assert!(native_reg_enum_subkeys(r"HKLM\SOFTWARE\NoSuchKeyHbsTest").is_none());
    assert!(native_reg_enum_values(r"HKLM\SOFTWARE\NoSuchKeyHbsTest").is_none());
    // Unsupported hive root.
    assert!(native_reg_sz(r"HKCR\Somewhere", "x").is_none());
    // A DWORD value read as a string must not fabricate a string.
    assert!(native_reg_sz(CURRENT_VERSION, "CurrentMajorVersionNumber").is_none());
}

#[test]
fn native_accounts_enumerate_local_principals() {
    // The local SAM always has at least one user and several groups.
    let users = native_accounts::native_enum_local_users();
    assert!(users.is_some(), "NetUserEnum must succeed on Windows");
    let groups = native_accounts::native_enum_local_groups();
    assert!(
        groups.is_some(),
        "NetLocalGroupEnum must succeed on Windows"
    );
}
