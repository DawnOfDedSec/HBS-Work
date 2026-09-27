//! Sealed-report envelope: X25519 + HKDF-SHA256 + AEAD (ChaCha20-
//! Poly1305 suite 0, AES-256-GCM suite 1) over zstd-compressed JSON,
//! per design spec §4.5 (`.hbs` v2): 93-byte header, entire header as
//! AEAD AAD, extractor_id routing identity in header and HKDF info.

use aes_gcm::aead::{Aead, KeyInit as _, Payload};
use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAGIC: &[u8; 4] = b"HBS2";
pub const FORMAT_VERSION: u16 = 2;
pub const HEADER_LEN: usize = 93;
pub const SUITE_CHACHA20POLY1305: u8 = 0;
pub const SUITE_AES256GCM: u8 = 1;

const INFO_PREFIX: &[u8] = b"HBS-report-v2";
const EXTRACTOR_ID_LEN: usize = 16;
const SCAN_ID_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const EPH_PUB_LEN: usize = 32;
const CT_LEN_FIELD_LEN: usize = 8;

// Header field offsets per spec §4.5.
const OFF_FORMAT: usize = 4;
const OFF_SUITE: usize = 6;
const OFF_KEY_ID: usize = 7;
const OFF_EXTRACTOR_ID: usize = 9;
const OFF_SCAN_ID: usize = 25;
const OFF_EPH_PUB: usize = 41;
const OFF_NONCE: usize = 73;
const OFF_CT_LEN: usize = 85;

/// HKDF `info` per spec §4.5: `"HBS-report-v2" || suite || key_id_le || extractor_id`.
fn info_bytes(suite: u8, key_id: u16, extractor_id: &[u8; 16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(INFO_PREFIX.len() + 3 + EXTRACTOR_ID_LEN);
    v.extend_from_slice(INFO_PREFIX);
    v.push(suite);
    v.extend_from_slice(&key_id.to_le_bytes());
    v.extend_from_slice(extractor_id);
    v
}

/// HKDF-SHA256(ikm, salt, info) -> 32 bytes. Deterministic - the
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

/// Header fields parsed out of a sealed envelope.
pub struct Header<'a> {
    pub suite: u8,
    pub key_id: u16,
    pub extractor_id: &'a [u8; EXTRACTOR_ID_LEN],
    pub scan_id: &'a [u8; SCAN_ID_LEN],
    pub eph_pub: &'a [u8; EPH_PUB_LEN],
    pub nonce: &'a [u8; NONCE_LEN],
}

/// Parse and validate the 93-byte v2 header. Returns the fields plus
/// the ciphertext slice.
fn parse(envelope: &[u8]) -> Result<(Header<'_>, &[u8])> {
    if envelope.len() < HEADER_LEN {
        bail!(
            "envelope header too short: {} bytes (need {HEADER_LEN})",
            envelope.len()
        );
    }
    if &envelope[0..4] != MAGIC {
        bail!("bad magic: not an HBS2 envelope");
    }
    let version = u16::from_le_bytes([envelope[OFF_FORMAT], envelope[OFF_FORMAT + 1]]);
    if version != FORMAT_VERSION {
        bail!("unsupported envelope version {version}");
    }
    let suite = envelope[OFF_SUITE];
    if suite != SUITE_CHACHA20POLY1305 && suite != SUITE_AES256GCM {
        bail!("unknown suite {suite}");
    }
    let hdr = Header {
        suite,
        key_id: u16::from_le_bytes([envelope[OFF_KEY_ID], envelope[OFF_KEY_ID + 1]]),
        extractor_id: envelope[OFF_EXTRACTOR_ID..OFF_EXTRACTOR_ID + EXTRACTOR_ID_LEN]
            .try_into()
            .expect("16 bytes"),
        scan_id: envelope[OFF_SCAN_ID..OFF_SCAN_ID + SCAN_ID_LEN]
            .try_into()
            .expect("16 bytes"),
        eph_pub: envelope[OFF_EPH_PUB..OFF_EPH_PUB + EPH_PUB_LEN]
            .try_into()
            .expect("32 bytes"),
        nonce: envelope[OFF_NONCE..OFF_NONCE + NONCE_LEN]
            .try_into()
            .expect("12 bytes"),
    };
    let ct_len = u64::from_le_bytes(
        envelope[OFF_CT_LEN..OFF_CT_LEN + CT_LEN_FIELD_LEN]
            .try_into()
            .unwrap(),
    ) as usize;
    if envelope.len() < HEADER_LEN + ct_len {
        bail!("envelope truncated: ciphertext shorter than declared length");
    }
    Ok((hdr, &envelope[HEADER_LEN..HEADER_LEN + ct_len]))
}

/// Seal `plaintext` (uncompressed report JSON) to `recipient_pub`.
///
/// `extractor_id` is the issuance's unique 16-byte routing identity; it
/// is authenticated via the header AAD and mixed into the HKDF info.
pub fn seal(
    plaintext: &[u8],
    recipient_pub: &[u8; 32],
    key_id: u16,
    extractor_id: &[u8; 16],
    suite: u8,
) -> Result<Vec<u8>> {
    let eph = StaticSecret::random_from_rng(getrandom_impl());
    let eph_pub = PublicKey::from(&eph);
    let recipient = PublicKey::from(*recipient_pub);
    let shared = eph.diffie_hellman(&recipient);

    let mut scan_id = [0u8; SCAN_ID_LEN];
    fill_random(&mut scan_id);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    fill_random(&mut nonce_bytes);

    let mut salt = Vec::with_capacity(SCAN_ID_LEN + EPH_PUB_LEN);
    salt.extend_from_slice(&scan_id);
    salt.extend_from_slice(eph_pub.as_bytes());
    let key = derive_key(
        shared.as_bytes(),
        &salt,
        &info_bytes(suite, key_id, extractor_id),
    );

    let compressed = zstd::stream::encode_all(plaintext, 3).context("zstd compress")?;

    // Both specified AEAD suites append a 16-byte authentication tag,
    // so final ciphertext length is known before authenticating header.
    let ct_len = compressed
        .len()
        .checked_add(16)
        .ok_or_else(|| anyhow!("ciphertext length overflow"))?;
    let mut env = Vec::with_capacity(HEADER_LEN + ct_len);
    env.extend_from_slice(MAGIC);
    env.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    env.push(suite);
    env.extend_from_slice(&key_id.to_le_bytes());
    env.extend_from_slice(extractor_id);
    env.extend_from_slice(&scan_id);
    env.extend_from_slice(eph_pub.as_bytes());
    env.extend_from_slice(&nonce_bytes);
    env.extend_from_slice(&(ct_len as u64).to_le_bytes());
    debug_assert_eq!(env.len(), HEADER_LEN);
    let aad = &env[..HEADER_LEN];

    let ct = match suite {
        SUITE_CHACHA20POLY1305 => {
            let c = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
            c.encrypt(
                &nonce_bytes.into(),
                Payload {
                    msg: &compressed,
                    aad,
                },
            )
            .map_err(|_| anyhow!("chacha20poly1305 encrypt failed"))?
        }
        SUITE_AES256GCM => {
            let c = aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&key));
            c.encrypt(
                &nonce_bytes.into(),
                Payload {
                    msg: &compressed,
                    aad,
                },
            )
            .map_err(|_| anyhow!("aes-gcm encrypt failed"))?
        }
        other => bail!("unknown suite {other}"),
    };
    debug_assert_eq!(ct.len(), ct_len);
    env.extend_from_slice(&ct);
    Ok(env)
}

/// Open an envelope with the recipient's private key. Used by tests
/// and vector generation; the extractor binary itself never decrypts.
pub fn unseal(envelope: &[u8], recipient_priv: &[u8; 32]) -> Result<Vec<u8>> {
    let (hdr, ct) = parse(envelope)?;

    let sk = StaticSecret::from(*recipient_priv);
    let shared = sk.diffie_hellman(&PublicKey::from(*hdr.eph_pub));
    let mut salt = Vec::with_capacity(SCAN_ID_LEN + EPH_PUB_LEN);
    salt.extend_from_slice(hdr.scan_id);
    salt.extend_from_slice(hdr.eph_pub);
    let key = derive_key(
        shared.as_bytes(),
        &salt,
        &info_bytes(hdr.suite, hdr.key_id, hdr.extractor_id),
    );

    // AAD = entire header, bytes 0..93 (spec §4.5).
    let aad = &envelope[..HEADER_LEN];
    let nonce = chacha20poly1305::Nonce::from_slice(hdr.nonce);
    let compressed = match hdr.suite {
        SUITE_CHACHA20POLY1305 => {
            let c = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
            c.decrypt(nonce, Payload { msg: ct, aad })
                .map_err(|_| anyhow!("decryption failed (wrong key or tampered data)"))?
        }
        SUITE_AES256GCM => {
            let c = aes_gcm::Aes256Gcm::new(aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&key));
            c.decrypt(nonce, Payload { msg: ct, aad })
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
