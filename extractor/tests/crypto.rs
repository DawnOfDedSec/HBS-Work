use hbs_extractor::crypto::{seal, unseal, FORMAT_VERSION, HEADER_LEN, MAGIC};

const PRIV: [u8; 32] = [0x41; 32];
const EXTRACTOR_ID: [u8; 16] = [0x5A; 16];
// derived once via x25519 keypair with private = 0x41*32
fn recipient() -> ([u8; 32], [u8; 32]) {
    let sk = x25519_dalek::StaticSecret::from(PRIV);
    let pk = x25519_dalek::PublicKey::from(&sk);
    (PRIV, *pk.as_bytes())
}

fn seal_to(pub_b: &[u8; 32], key_id: u16, suite: u8, pt: &[u8]) -> Vec<u8> {
    seal(pt, pub_b, key_id, &EXTRACTOR_ID, suite).unwrap()
}

#[test]
fn roundtrip_suite0_chacha() {
    let (priv_b, pub_b) = recipient();
    let pt = br#"{"schemaVersion":1,"scan":{"hostname":"web01"}}"#;
    let env = seal_to(&pub_b, 7, 0, pt);
    assert_eq!(&env[0..4], MAGIC);
    assert_eq!(&env[4..6], &FORMAT_VERSION.to_le_bytes());
    assert_eq!(env[6], 0u8);
    let out = unseal(&env, &priv_b).unwrap();
    assert_eq!(out, pt);
}

#[test]
fn roundtrip_suite1_aes() {
    let (priv_b, pub_b) = recipient();
    let pt = "unicode ✓ 日本語 payload".as_bytes();
    let env = seal_to(&pub_b, 1, 1, pt);
    assert_eq!(env[6], 1u8);
    assert_eq!(unseal(&env, &priv_b).unwrap(), pt);
}

#[test]
fn empty_plaintext_roundtrip() {
    let (priv_b, pub_b) = recipient();
    let env = seal_to(&pub_b, 1, 0, b"");
    assert_eq!(unseal(&env, &priv_b).unwrap(), b"");
}

#[test]
fn header_layout_is_93_bytes_per_spec() {
    let (priv_b, pub_b) = recipient();
    let env = seal_to(&pub_b, 0x0102, 0, b"payload");
    assert!(env.len() >= HEADER_LEN);
    assert_eq!(&env[0..4], b"HBS2"); // magic
    assert_eq!(&env[4..6], &2u16.to_le_bytes()); // format version
    assert_eq!(env[6], 0); // suite
    assert_eq!(&env[7..9], &[0x02, 0x01]); // key_id u16 LE
    assert_eq!(&env[9..25], &EXTRACTOR_ID); // extractor_id
    let scan_id = &env[25..41];
    assert_eq!(scan_id.len(), 16);
    // nonce at 73..85 random, ct_len at 85..93
    let ct_len = u64::from_le_bytes(env[85..93].try_into().unwrap()) as usize;
    assert_eq!(env.len(), HEADER_LEN + ct_len);
    let _ = priv_b;
}

#[test]
fn tampered_ciphertext_fails() {
    let (priv_b, pub_b) = recipient();
    let mut env = seal_to(&pub_b, 2, 0, b"secret report");
    let last = env.len() - 1;
    env[last] ^= 0x01;
    assert!(unseal(&env, &priv_b).is_err());
}

#[test]
fn tampered_header_aad_fails() {
    let (priv_b, pub_b) = recipient();
    // Every header byte is AAD; flipping any routing field must fail.
    for off in [4, 5, 6, 7, 8, 9, 20, 24, 25, 35, 40, 85, 92] {
        let mut env = seal_to(&pub_b, 2, 0, b"secret report");
        env[off] ^= 0xff;
        assert!(
            unseal(&env, &priv_b).is_err(),
            "tamper at offset {off} not detected"
        );
    }
}

#[test]
fn tampered_extractor_id_rejected() {
    let (priv_b, pub_b) = recipient();
    let mut env = seal_to(&pub_b, 2, 0, b"secret report");
    env[9] ^= 0x01; // first extractor_id byte
    assert!(unseal(&env, &priv_b).is_err());
}

#[test]
fn wrong_extractor_id_at_seal_fails_open_detection() {
    // Envelope sealed with one issuance id must not decrypt when the
    // HKDF info differs - simulate via direct header swap from another
    // envelope sealed with a different extractor_id.
    let (priv_b, pub_b) = recipient();
    let other_id: [u8; 16] = [0x11; 16];
    let e1 = seal(b"report A", &pub_b, 3, &EXTRACTOR_ID, 0).unwrap();
    let e2 = seal(b"report B", &pub_b, 3, &other_id, 0).unwrap();
    // swap extractor_id fields (9..25)
    let mut mixed = e1.clone();
    mixed[9..25].copy_from_slice(&e2[9..25]);
    assert!(
        unseal(&mixed, &priv_b).is_err(),
        "extractor_id swap must break auth"
    );
}

#[test]
fn truncated_and_bad_magic_fail() {
    let (priv_b, pub_b) = recipient();
    let env = seal_to(&pub_b, 1, 0, b"payload");
    let short = &env[..92];
    let err = unseal(short, &priv_b).unwrap_err();
    assert!(err.to_string().contains("header"), "got: {err}");
    let mut bad = env.clone();
    bad[0] = b'X';
    assert!(unseal(&bad, &priv_b).is_err());
}

#[test]
fn key_id_round_trips() {
    let (priv_b, pub_b) = recipient();
    let env = seal_to(&pub_b, 0xBEEF, 0, b"k");
    // key_id is u16 LE at offset 7
    assert_eq!(env[7], 0xEF);
    assert_eq!(env[8], 0xBE);
    assert!(unseal(&env, &priv_b).is_ok());
}
