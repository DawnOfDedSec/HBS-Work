use hbs_extractor::keyslot::{
    check_expiry, hex_id, locate, parse, placeholder_bytes, read_own_slot, SLOT_MAGIC, SLOT_LEN,
};

fn valid_slot(expiry: i64) -> Vec<u8> {
    let mut buf = placeholder_bytes().to_vec();
    buf[8..10].copy_from_slice(&1u16.to_le_bytes()); // slot_version
    buf[12..14].copy_from_slice(&3u16.to_le_bytes()); // key_id
    for (i, b) in [0xAAu8; 16].iter().enumerate() {
        buf[16 + i] = *b; // campaign_id
    }
    for (i, b) in [0xBBu8; 16].iter().enumerate() {
        buf[32 + i] = *b; // extractor_id
    }
    buf[48..56].copy_from_slice(&(expiry as u64).to_le_bytes());
    buf[56..64].copy_from_slice(&1_700_000_000u64.to_le_bytes()); // issued_at
    for (i, b) in [0xCCu8; 32].iter().enumerate() {
        buf[64 + i] = *b; // recipient_pub
    }
    for b in buf[96..480].iter_mut() {
        *b = 0; // zero pad
    }
    let digest = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(&buf[0..480]);
        let out: [u8; 32] = h.finalize().into();
        out
    };
    buf[480..512].copy_from_slice(&digest);
    buf
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
    let buf = valid_slot(1); // long past
    let slot = parse(&buf).unwrap();
    let err = check_expiry(&slot).unwrap_err();
    assert!(err.contains("expired"), "got: {err}");
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
    let id = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(hex_id(&id), "12345678-9abc-def0-0102-030405060708");
}
