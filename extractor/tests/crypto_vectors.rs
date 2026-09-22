//! Generates the cross-language crypto fixtures consumed by the
//! dashboard's envelope test (Task 44). Run `cargo test --test
//! crypto_vectors` after changing the envelope; the committed JSON is
//! the contract.

use hbs_extractor::crypto::{seal, unseal};
use sha2::Digest;
use x25519_dalek::{PublicKey, StaticSecret};

fn sha256_hex(data: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(data);
    let d: [u8; 32] = h.finalize().into();
    hex::encode(d)
}

struct Vector {
    name: &'static str,
    suite: u8,
    key_id: u16,
    extractor_id: [u8; 16],
    priv_bytes: [u8; 32],
    plaintext: Vec<u8>,
    large: bool,
}

const VEC_EXTRACTOR_ID: [u8; 16] = [0xA5; 16];

fn build_vectors() -> Vec<Vector> {
    vec![
        Vector {
            name: "suite0-basic",
            suite: 0,
            key_id: 7,
            extractor_id: VEC_EXTRACTOR_ID,
            priv_bytes: [0x41; 32],
            plaintext: br#"{"schemaVersion":1,"scan":{"hostname":"vec-host-01"}}"#.to_vec(),
            large: false,
        },
        Vector {
            name: "suite1-basic",
            suite: 1,
            key_id: 9,
            extractor_id: VEC_EXTRACTOR_ID,
            priv_bytes: [0x42; 32],
            plaintext: b"unicode \xe2\x9c\x93 report body".to_vec(),
            large: false,
        },
        Vector {
            name: "suite0-empty",
            suite: 0,
            key_id: 1,
            extractor_id: VEC_EXTRACTOR_ID,
            priv_bytes: [0x43; 32],
            plaintext: Vec::new(),
            large: false,
        },
        Vector {
            name: "suite0-large-1mb",
            suite: 0,
            key_id: 2,
            extractor_id: VEC_EXTRACTOR_ID,
            priv_bytes: [0x44; 32],
            plaintext: vec![b'x'; 1024 * 1024],
            large: true,
        },
    ]
}

#[test]
fn generate_and_verify_vectors() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures");
    std::fs::create_dir_all(dir).unwrap();
    let mut vectors = serde_json::json!([]);
    for v in build_vectors() {
        let sk = StaticSecret::from(v.priv_bytes);
        let pk = PublicKey::from(&sk);
        let env = seal(
            &v.plaintext,
            pk.as_bytes(),
            v.key_id,
            &v.extractor_id,
            v.suite,
        )
        .expect("seal");
        let out = unseal(&env, &v.priv_bytes).expect("roundtrip");
        assert_eq!(out, v.plaintext, "vector {} must round-trip", v.name);

        if v.large {
            std::fs::write(format!("{}/vector-{}.hbs", dir, v.name), &env).unwrap();
        }
        let entry = serde_json::json!({
            "name": v.name,
            "suite": v.suite,
            "keyId": v.key_id,
            "extractorIdHex": hex::encode(v.extractor_id),
            "recipientPrivHex": hex::encode(v.priv_bytes),
            "recipientPubHex": hex::encode(pk.as_bytes()),
            "envelopeHex": if v.large { None } else { Some(hex::encode(&env)) },
            "envelopeSha256": sha256_hex(&env),
            "plaintextHex": if v.large { None } else { Some(hex::encode(&v.plaintext)) },
            "plaintextSha256": sha256_hex(&v.plaintext),
            "large": v.large,
            "envelopeLen": env.len(),
        });
        vectors.as_array_mut().unwrap().push(entry);
    }
    std::fs::write(
        format!("{}/crypto-vectors.json", dir),
        serde_json::to_string_pretty(&vectors).unwrap(),
    )
    .unwrap();
}
