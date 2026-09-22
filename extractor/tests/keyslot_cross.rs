//! Cross-language agreement: the TypeScript dashboard patcher
//! (`dashboard/server/patcher.ts`) emits `fixtures/keyslot-ts-patched.bin`;
//! the Rust extractor must parse it into identical field values. Regenerate
//! with the command in Task 45 of the plan.

use hbs_extractor::keyslot::{check_expiry, locate_unique, parse, SLOT_LEN};

#[test]
fn parses_typescript_patched_slot() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/keyslot-ts-patched.bin");
    let Ok(bin) = std::fs::read(path) else {
        eprintln!("TS fixture absent; skipping cross-language check");
        return;
    };
    let off = locate_unique(&bin).expect("exactly one slot");
    assert_eq!(off, 32);
    let slot = parse(&bin[off..off + SLOT_LEN]).expect("Rust parses TS-patched slot");
    assert_eq!(slot.key_id, 7);
    assert_eq!(slot.campaign_id, std::array::from_fn(|i| 0xa0 + i as u8));
    assert_eq!(slot.extractor_id, std::array::from_fn(|i| 0xb0 + i as u8));
    assert_eq!(slot.recipient_pub, std::array::from_fn(|i| 0xc0 + i as u8));
    assert_eq!(slot.issued_at_unix, 1_700_000_000);
    assert_eq!(slot.expiry_unix, 4_102_444_800);
    assert!(check_expiry(&slot).is_ok());
}
