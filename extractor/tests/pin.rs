//! Pinned cross-language HKDF vector. The same value must come out of
//! the TypeScript side (dashboard/server/envelope.test.ts) - this
//! constant is the contract between the two implementations.

#[test]
fn derive_key_pinned_vector() {
    let ikm = [0x11u8; 32];
    let mut salt = Vec::new();
    salt.extend_from_slice(&[0x22u8; 16]);
    salt.extend_from_slice(&[0x33u8; 32]);
    let info = b"HBS-report-v1\x00\x00\x00";
    let k = hbs_extractor::crypto::derive_key(&ikm, &salt, info);
    assert_eq!(
        hex::encode(k),
        "f11ac5e201e20e4b71a104aa58b3924a25ad0b1a256a15d4692992d831b73736"
    );
}
