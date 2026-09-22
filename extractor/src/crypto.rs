//! Sealed-report envelope: X25519 + HKDF-SHA256 + AEAD (ChaCha20-
//! Poly1305 suite 0, AES-256-GCM suite 1) over zstd-compressed JSON,
//! exactly per the byte layout in the plan's Global Constraints.

use aes_gcm::aead::{Aead, KeyInit as _, Payload};
use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAGIC: &[u8; 4] = b"HBS1";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 77;
pub const SUITE_CHACHA20POLY1305: u8 = 0;
pub const SUITE_AES256GCM: u8 = 1;
const INFO_PREFIX: &[u8] = b"HBS-report-v1";

fn info_bytes(suite: u8, key_id: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(INFO_PREFIX.len() + 3);
    v.extend_from_slice(INFO_PREFIX);
    v.push(suite);
    v.extend_from_slice(&key_id.to_le_bytes());
    v
}

/// HKDF-SHA256(ikm, salt, info) -> 32 bytes. Deterministic — the
/// cross-language test vector pins its output.
pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let h = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    h.expand(info, &mut okm).expect("32-byte output is valid");
    okm
}

/// Public key corresponding to a private key (test/dev helper).
pub fn pubkey_of(priv_bytes: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(*priv_bytes);
    *PublicKey::from(&sk).as_bytes()
}

/// Seal `plaintext` (uncompressed report JSON) to `recipient_pub`.
pub fn seal(plaintext: &[u8], recipient_pub: &[u8; 32], key_id: u16, suite: u8) -> Result<Vec<u8>> {
    let eph = StaticSecret::random_from_rng(getrandom_impl());
    let eph_pub = PublicKey::from(&eph);
    let recipient = PublicKey::from(*recipient_pub);
    let shared = eph.diffie_hellman(&recipient);

    let mut scan_id = [0u8; 16];
    fill_random(&mut scan_id);
    let mut nonce_bytes = [0u8; 12];
    fill_random(&mut nonce_bytes);

    let mut salt = Vec::with_capacity(16 + 32);
    salt.extend_from_slice(&scan_id);
    salt.extend_from_slice(eph_pub.as_bytes());
    let key = derive_key(shared.as_bytes(), &salt, &info_bytes(suite, key_id));

    let compressed = zstd::stream::encode_all(plaintext, 3).context("zstd compress")?;
    let ct = match suite {
        SUITE_CHACHA20POLY1305 => {
            let c = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
            c.encrypt(&nonce_bytes.into(), Payload { msg: &compressed, aad: &[] })
                .map_err(|_| anyhow!("chacha20poly1305 encrypt failed"))?
        }
        SUITE_AES256GCM => {
            let c = aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&key));
            c.encrypt(&nonce_bytes.into(), Payload { msg: &compressed, aad: &[] })
                .map_err(|_| anyhow!("aes-gcm encrypt failed"))?
        }
        other => bail!("unknown suite {other}"),
    };

    let mut env = Vec::with_capacity(HEADER_LEN + ct.len());
    env.extend_from_slice(MAGIC);
    env.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    env.push(suite);
    env.extend_from_slice(&key_id.to_le_bytes());
    env.extend_from_slice(&scan_id);
    env.extend_from_slice(eph_pub.as_bytes());
    env.extend_from_slice(&nonce_bytes);
    env.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    env.extend_from_slice(&ct);
    Ok(env)
}

/// Open an envelope with the recipient's private key. Used by tests
/// and vector generation; the extractor binary itself never decrypts.
pub fn unseal(envelope: &[u8], recipient_priv: &[u8; 32]) -> Result<Vec<u8>> {
    if envelope.len() < HEADER_LEN {
        bail!("envelope header too short: {} bytes (need {HEADER_LEN})", envelope.len());
    }
    if &envelope[0..4] != MAGIC {
        bail!("bad magic: not an HBS envelope");
    }
    let version = u16::from_le_bytes([envelope[4], envelope[5]]);
    if version != FORMAT_VERSION {
        bail!("unsupported envelope version {version}");
    }
    let suite = envelope[6];
    let key_id = u16::from_le_bytes([envelope[7], envelope[8]]);
    let scan_id = &envelope[9..25];
    let eph_pub: [u8; 32] = envelope[25..57].try_into().expect("32 bytes");
    let nonce_bytes: [u8; 12] = envelope[57..69].try_into().expect("12 bytes");
    let ct_len = u64::from_le_bytes(envelope[69..77].try_into().unwrap()) as usize;
    if envelope.len() < HEADER_LEN + ct_len {
        bail!("envelope truncated: ciphertext shorter than declared length");
    }
    let ct = &envelope[HEADER_LEN..HEADER_LEN + ct_len];

    let sk = StaticSecret::from(*recipient_priv);
    let shared = sk.diffie_hellman(&PublicKey::from(eph_pub));
    let mut salt = Vec::with_capacity(48);
    salt.extend_from_slice(scan_id);
    salt.extend_from_slice(&eph_pub);
    let key = derive_key(shared.as_bytes(), &salt, &info_bytes(suite, key_id));

    let compressed = match suite {
        SUITE_CHACHA20POLY1305 => {
            let c = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
            c.decrypt(&nonce_bytes.into(), Payload { msg: ct, aad: &[] })
                .map_err(|_| anyhow!("decryption failed (wrong key or tampered data)"))?
        }
        SUITE_AES256GCM => {
            let c = aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&key));
            c.decrypt(&nonce_bytes.into(), Payload { msg: ct, aad: &[] })
                .map_err(|_| anyhow!("decryption failed (wrong key or tampered data)"))?
        }
        other => bail!("unknown suite {other}"),
    };
    zstd::stream::decode_all(&compressed[..]).context("zstd decompress")
}

// x25519-dalek 2.x wants a CryptoRngCore; getrandom's OsRng adapts.
struct GetRandomRng;
impl rand_core::CryptoRng for GetRandomRng {}
impl rand_core::RngCore for GetRandomRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        fill_random(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        fill_random(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_random(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        fill_random(dest);
        Ok(())
    }
}

fn getrandom_impl() -> GetRandomRng {
    GetRandomRng
}

fn fill_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("system RNG is available");
}
