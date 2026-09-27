//! One-time reviewed generator for legacy v1 (HBS1) ingest fixtures.
//!
//! The extractor only issues v2 envelopes now. The dashboard keeps a bounded
//! v1 migration route, so these immutable expected bytes let the TypeScript
//! `envelope.ts` parser prove it can still open real v1 reports - including
//! suite 0 (ChaCha20-Poly1305, the extractor's historical default), which
//! `node:crypto` in Bun cannot produce.
//!
//! This is an example target, never compiled into the shipped binary, so it
//! is not a production v1 sealer. Run once:
//!   cd extractor && cargo run --example gen_v1_vectors
//! and commit `fixtures/legacy-v1-vectors.json`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

fn derive(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let h = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    h.expand(info, &mut out).expect("32-byte okm");
    out
}

fn seal(
    plaintext: &[u8],
    recipient_priv: &[u8; 32],
    eph_priv: &[u8; 32],
    scan_id: &[u8; 16],
    nonce: &[u8; 12],
    key_id: u16,
    suite: u8,
) -> Vec<u8> {
    let recipient_pub = PublicKey::from(&StaticSecret::from(*recipient_priv));
    let eph = StaticSecret::from(*eph_priv);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&recipient_pub);

    let mut salt = Vec::with_capacity(48);
    salt.extend_from_slice(scan_id);
    salt.extend_from_slice(eph_pub.as_bytes());
    let mut info = Vec::from(&b"HBS-report-v1"[..]);
    info.push(suite);
    info.extend_from_slice(&key_id.to_le_bytes());
    let key = derive(shared.as_bytes(), &salt, &info);

    let compressed = zstd::stream::encode_all(plaintext, 3).expect("zstd compress");
    let ct = match suite {
        0 => {
            let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
            cipher
                .encrypt(
                    nonce.into(),
                    Payload {
                        msg: &compressed,
                        aad: &[],
                    },
                )
                .expect("chacha encrypt")
        }
        1 => {
            let cipher =
                aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&key));
            cipher
                .encrypt(
                    nonce.into(),
                    Payload {
                        msg: &compressed,
                        aad: &[],
                    },
                )
                .expect("aes encrypt")
        }
        other => panic!("unknown suite {other}"),
    };

    let mut env = Vec::with_capacity(77 + ct.len());
    env.extend_from_slice(b"HBS1");
    env.extend_from_slice(&1u16.to_le_bytes());
    env.push(suite);
    env.extend_from_slice(&key_id.to_le_bytes());
    env.extend_from_slice(scan_id);
    env.extend_from_slice(eph_pub.as_bytes());
    env.extend_from_slice(nonce);
    env.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    env.extend_from_slice(&ct);
    env
}

fn main() {
    use serde_json::json;

    let recipient_priv = [0x41u8; 32];
    let recipient_pub = PublicKey::from(&StaticSecret::from(recipient_priv));
    let eph_priv = [0x33u8; 32];
    let scan_id: [u8; 16] = std::array::from_fn(|i| (i + 1) as u8);
    let nonce: [u8; 12] = std::array::from_fn(|i| 0xf0 - i as u8);

    let report = serde_json::to_vec(&json!({
        "schemaVersion": 1,
        "scan": { "extractorId": "a5a5a5a5-a5a5-a5a5-a5a5-a5a5a5a5a5a5", "keyId": 5 },
        "results": [{ "id": "GEN-INV-001", "status": "Compliant" }],
    }))
    .expect("report json");

    let entries: [(&str, u8, u16, Vec<u8>); 2] = [
        ("v1-suite0-legacy", 0, 5, report),
        (
            "v1-suite1-unicode",
            1,
            9,
            "legacy ✓ ünïcode report".as_bytes().to_vec(),
        ),
    ];

    let vectors: Vec<serde_json::Value> = entries
        .iter()
        .map(|(name, suite, key_id, plaintext)| {
            let envelope = seal(
                plaintext,
                &recipient_priv,
                &eph_priv,
                &scan_id,
                &nonce,
                *key_id,
                *suite,
            );
            json!({
                "name": name,
                "suite": suite,
                "keyId": key_id,
                "recipientPrivHex": hex::encode(recipient_priv),
                "recipientPubHex": hex::encode(recipient_pub.as_bytes()),
                "ephemeralPrivHex": hex::encode(eph_priv),
                "plaintextHex": hex::encode(plaintext),
                "envelopeHex": hex::encode(&envelope),
            })
        })
        .collect();

    let out =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/legacy-v1-vectors.json");
    std::fs::write(
        &out,
        format!("{}\n", serde_json::to_string_pretty(&vectors).unwrap()),
    )
    .expect("write fixtures");
    println!(
        "wrote {} legacy v1 vectors to {}",
        vectors.len(),
        out.display()
    );
}
