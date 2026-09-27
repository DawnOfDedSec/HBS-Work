use hbs_extractor::keyslot::{
    check_expiry, hex_id, locate, locate_unique, parse, placeholder_bytes, read_own_slot, SLOT_LEN,
    SLOT_MAGIC,
};

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Independent fixture builder: builds a fully valid slot for the given
/// timestamps with the exact spec §4.6 layout (zero flags/reserved/pad).
fn slot_bytes(issued_at: u64, expiry: u64) -> Vec<u8> {
    let mut buf = placeholder_bytes().to_vec();
    buf[8..10].copy_from_slice(&1u16.to_le_bytes()); // slot_version
    buf[10..12].copy_from_slice(&0u16.to_le_bytes()); // flags
    buf[12..14].copy_from_slice(&3u16.to_le_bytes()); // key_id
    buf[14..16].copy_from_slice(&0u16.to_le_bytes()); // reserved u16
    buf[16..32].copy_from_slice(&[0xAA; 16]); // campaign_id
    buf[32..48].copy_from_slice(&[0xBB; 16]); // extractor_id
    buf[48..56].copy_from_slice(&expiry.to_le_bytes());
    buf[56..64].copy_from_slice(&issued_at.to_le_bytes());
    buf[64..96].copy_from_slice(&[0xCC; 32]); // recipient_pub
    for b in buf[96..480].iter_mut() {
        *b = 0; // zero pad
    }
    let digest = sha256(&buf[0..480]);
    buf[480..512].copy_from_slice(&digest);
    buf
}

fn valid_slot(expiry: u64) -> Vec<u8> {
    slot_bytes(1_700_000_000, expiry)
}

/// Recompute the checksum after mutating a fixture so structural checks
/// (not the checksum) are exercised.
fn reseal(buf: &mut [u8]) {
    let digest = sha256(&buf[0..480]);
    buf[480..512].copy_from_slice(&digest);
}

#[test]
fn placeholder_shape_is_right() {
    let p = placeholder_bytes();
    assert_eq!(p.len(), SLOT_LEN);
    assert_eq!(&p[0..8], SLOT_MAGIC);
    assert!(p[8..480].iter().all(|&b| b == 0xAA));
    assert!(p[480..512].iter().all(|&b| b == 0));
}

#[test]
fn placeholder_is_rejected_as_not_issued() {
    let err = parse(&placeholder_bytes()).unwrap_err();
    assert!(err.to_string().contains("not issued"), "got: {err}");
}

#[test]
fn valid_slot_parses() {
    let buf = valid_slot(4_102_444_800); // 2100-01-01
    let slot = parse(&buf).unwrap();
    assert_eq!(slot.key_id, 3);
    assert_eq!(slot.campaign_id, [0xAA; 16]);
    assert_eq!(slot.extractor_id, [0xBB; 16]);
    assert_eq!(slot.recipient_pub, [0xCC; 32]);
    assert_eq!(slot.expiry_unix, 4_102_444_800);
    assert!(check_expiry(&slot).is_ok());
}

#[test]
fn corrupted_slot_fails_checksum() {
    let mut buf = valid_slot(4_102_444_800);
    buf[64] ^= 0xff; // flip a pubkey byte without recomputing sha
    let err = parse(&buf).unwrap_err();
    assert!(err.to_string().contains("checksum"), "got: {err}");
}

#[test]
fn expired_slot_reports_expired() {
    // Valid ordering (issued_at < expiry) but entirely in the past.
    let buf = slot_bytes(1_600_000_000, 1_700_000_000);
    let slot = parse(&buf).unwrap();
    let err = check_expiry(&slot).unwrap_err();
    assert!(err.contains("expired"), "got: {err}");
}

#[test]
fn nonzero_flags_rejected() {
    let mut buf = valid_slot(4_102_444_800);
    buf[10] = 1;
    reseal(&mut buf);
    let err = parse(&buf).unwrap_err();
    assert!(err.to_string().contains("flags"), "got: {err}");
}

#[test]
fn nonzero_reserved_u16_rejected() {
    let mut buf = valid_slot(4_102_444_800);
    buf[14] = 1;
    reseal(&mut buf);
    let err = parse(&buf).unwrap_err();
    assert!(err.to_string().contains("reserved"), "got: {err}");
}

#[test]
fn nonzero_reserved_pad_byte_rejected() {
    let mut buf = valid_slot(4_102_444_800);
    buf[200] = 0x01;
    reseal(&mut buf);
    let err = parse(&buf).unwrap_err();
    assert!(err.to_string().contains("reserved pad"), "got: {err}");
}

#[test]
fn nil_identities_and_key_rejected() {
    for (range, label) in [
        (16..32, "campaign_id"),
        (32..48, "extractor_id"),
        (64..96, "public key"),
    ] {
        let mut buf = valid_slot(4_102_444_800);
        for b in buf[range].iter_mut() {
            *b = 0;
        }
        reseal(&mut buf);
        let err = parse(&buf).unwrap_err();
        assert!(
            err.to_string().contains("nil") && err.to_string().contains(label),
            "{label}: got: {err}"
        );
    }
}

#[test]
fn issued_at_must_precede_expiry() {
    for (issued_at, expiry) in [
        (1_700_000_000u64, 1_700_000_000u64),
        (1_700_000_001, 1_700_000_000),
    ] {
        let buf = slot_bytes(issued_at, expiry);
        let err = parse(&buf).unwrap_err();
        assert!(err.to_string().contains("before expiry"), "got: {err}");
    }
}

#[test]
fn locate_unique_requires_exactly_one_slot() {
    assert!(locate_unique(&[0u8; 128])
        .unwrap_err()
        .to_string()
        .contains("not found"));

    let one = {
        let mut bin = vec![0u8; 256];
        bin.extend_from_slice(&valid_slot(4_102_444_800));
        bin
    };
    let off = locate_unique(&one).expect("one slot");
    assert_eq!(&one[off..off + 8], SLOT_MAGIC);

    let two = {
        let mut bin = one.clone();
        bin.extend_from_slice(&valid_slot(4_102_444_800));
        bin
    };
    assert!(locate_unique(&two)
        .unwrap_err()
        .to_string()
        .contains("multiple"));
}

#[test]
fn locate_finds_slot_in_a_fake_binary() {
    let mut bin = vec![0u8; 1024];
    let slot = valid_slot(4_102_444_800);
    bin.extend_from_slice(&slot);
    bin.extend_from_slice(&[0x00; 64]);
    let off = locate(&bin).expect("slot must be found");
    assert_eq!(&bin[off..off + 8], SLOT_MAGIC);
}

#[test]
fn own_test_binary_has_no_slot() {
    let err = read_own_slot().unwrap_err();
    // The cargo test binary was never issued by a dashboard.
    assert!(err.to_string().contains("keyslot") || err.to_string().contains("not found"));
}

#[test]
fn hex_id_formats_uuid_style() {
    let id = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 1, 2, 3, 4, 5, 6, 7, 8,
    ];
    assert_eq!(hex_id(&id), "12345678-9abc-def0-0102-030405060708");
}
