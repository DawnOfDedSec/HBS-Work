use hbs_extractor::crypto::{derive_key, seal, unseal};

const PRIV: [u8; 32] = [0x41; 32];
// derived once via x25519 keypair with private = 0x41*32
fn recipient() -> ([u8; 32], [u8; 32]) {
    let sk = x25519_dalek::StaticSecret::from(PRIV);
    let pk = x25519_dalek::PublicKey::from(&sk);
    (PRIV, *pk.as_bytes())
}

#[test]
fn roundtrip_suite0_chacha() {
    let (priv_b, pub_b) = recipient();
    let pt = br#"{"schemaVersion":1,"scan":{"hostname":"web01"}}"#;
    let env = seal(pt, &pub_b, 7, 0).unwrap();
    assert_eq!(&env[0..4], b"HBS1");
    assert_eq!(env[6], 0u8);
    let out = unseal(&env, &priv_b).unwrap();
    assert_eq!(out, pt);
}

#[test]
fn roundtrip_suite1_aes() {
    let (priv_b, pub_b) = recipient();
    let pt = "unicode ✓ 日本語 payload".as_bytes();
    let env = seal(pt, &pub_b, 1, 1).unwrap();
    assert_eq!(env[6], 1u8);
    assert_eq!(unseal(&env, &priv_b).unwrap(), pt);
}

#[test]
fn empty_plaintext_roundtrip() {
    let (priv_b, pub_b) = recipient();
    let env = seal(b"", &pub_b, 1, 0).unwrap();
    assert_eq!(unseal(&env, &priv_b).unwrap(), b"");
}

#[test]
fn tampered_ciphertext_fails() {
    let (priv_b, pub_b) = recipient();
    let mut env = seal(b"secret report", &pub_b, 2, 0).unwrap();
    let last = env.len() - 1;
    env[last] ^= 0x01;
    assert!(unseal(&env, &priv_b).is_err());
}

#[test]
fn tampered_header_fails() {
    let (priv_b, pub_b) = recipient();
    let mut env = seal(b"secret report", &pub_b, 2, 0).unwrap();
    env[9] ^= 0xff; // scan_id byte -> salt change -> key mismatch
    assert!(unseal(&env, &priv_b).is_err());
    let mut env2 = seal(b"x", &pub_b, 2, 0).unwrap();
    env2[6] = 1; // suite flip -> info change -> key mismatch
    assert!(unseal(&env2, &priv_b).is_err());
}

#[test]
fn truncated_and_bad_magic_fail() {
    let (priv_b, pub_b) = recipient();
    let env = seal(b"payload", &pub_b, 1, 0).unwrap();
    let short = &env[..76];
    let err = unseal(short, &priv_b).unwrap_err();
    assert!(err.to_string().contains("header"), "got: {err}");
    let mut bad = env.clone();
    bad[0] = b'X';
    assert!(unseal(&bad, &priv_b).is_err());
}

#[test]
fn key_id_round_trips() {
    let (priv_b, pub_b) = recipient();
    let env = seal(b"k", &pub_b, 0xBEEF, 0).unwrap();
    // key_id is u16 LE at offset 7
    assert_eq!(env[7], 0xEF);
    assert_eq!(env[8], 0xBE);
    assert!(unseal(&env, &priv_b).is_ok());
}
