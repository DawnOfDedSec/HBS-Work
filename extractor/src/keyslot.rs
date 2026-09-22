//! Binary keyslot: the 512-byte placeholder inside every extractor
//! build that the dashboard patches with the issuance's public key and
//! metadata (layout: Global Constraints). The extractor locates its
//! own slot at startup and refuses to run when unissued or expired.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

pub const SLOT_MAGIC: &[u8; 8] = b"HBSKSLOT";
pub const SLOT_LEN: usize = 512;

/// The placeholder static compiled into the binary. Referenced by
/// [`read_own_slot`] so the linker can never strip it.
#[used]
pub static KEY_SLOT_PLACEHOLDER: [u8; SLOT_LEN] = {
    let mut s = [0u8; SLOT_LEN];
    let mut i = 0;
    while i < 8 {
        s[i] = SLOT_MAGIC[i];
        i += 1;
    }
    while i < 480 {
        s[i] = 0xAA;
        i += 1;
    }
    // bytes 480..512 stay zero: unissued marker
    s
};

#[derive(Clone, Debug, PartialEq)]
pub struct SlotData {
    pub key_id: u16,
    pub campaign_id: [u8; 16],
    pub extractor_id: [u8; 16],
    pub expiry_unix: u64,
    pub issued_at_unix: u64,
    pub recipient_pub: [u8; 32],
}

/// Bytes the placeholder takes in a fresh build (test helper + build
/// verification).
pub fn placeholder_bytes() -> [u8; SLOT_LEN] {
    KEY_SLOT_PLACEHOLDER
}

/// Find the slot offset inside a binary image, if present.
pub fn locate(bin: &[u8]) -> Option<usize> {
    bin.windows(8).position(|w| w == SLOT_MAGIC)
}

/// Parse and validate a 512-byte slot.
///
/// Validation order follows spec §4.6: magic, placeholder marker, version,
/// flags, reserved fields, non-nil identities/key, timestamp ordering, then
/// the integrity checksum. Structural errors are reported before checksum so
/// operators get the actionable cause; the checksum is corruption detection,
/// never authenticity.
pub fn parse(buf: &[u8]) -> Result<SlotData> {
    if buf.len() < SLOT_LEN {
        bail!("keyslot too short: {} bytes", buf.len());
    }
    if &buf[0..8] != SLOT_MAGIC {
        bail!("keyslot magic mismatch");
    }
    let sha_field: [u8; 32] = buf[480..512].try_into().unwrap();
    if sha_field.iter().all(|&b| b == 0) {
        bail!("binary not issued by a dashboard (placeholder keyslot)");
    }
    let slot_version = u16::from_le_bytes([buf[8], buf[9]]);
    if slot_version != 1 {
        bail!("unsupported keyslot version {slot_version}");
    }
    let flags = u16::from_le_bytes([buf[10], buf[11]]);
    if flags != 0 {
        bail!("keyslot flags must be zero (got {flags})");
    }
    let reserved = u16::from_le_bytes([buf[14], buf[15]]);
    if reserved != 0 {
        bail!("keyslot reserved field must be zero (got {reserved})");
    }
    if buf[96..480].iter().any(|&b| b != 0) {
        bail!("keyslot reserved pad must be zero");
    }
    let campaign_id: [u8; 16] = buf[16..32].try_into().unwrap();
    if campaign_id.iter().all(|&b| b == 0) {
        bail!("keyslot campaign_id is nil");
    }
    let extractor_id: [u8; 16] = buf[32..48].try_into().unwrap();
    if extractor_id.iter().all(|&b| b == 0) {
        bail!("keyslot extractor_id is nil");
    }
    let recipient_pub: [u8; 32] = buf[64..96].try_into().unwrap();
    if recipient_pub.iter().all(|&b| b == 0) {
        bail!("keyslot recipient public key is nil");
    }
    let expiry_unix = u64::from_le_bytes(buf[48..56].try_into().unwrap());
    let issued_at_unix = u64::from_le_bytes(buf[56..64].try_into().unwrap());
    if issued_at_unix >= expiry_unix {
        bail!(
            "keyslot issued_at ({issued_at_unix}) must be before expiry ({expiry_unix})"
        );
    }
    let digest: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(&buf[0..480]);
        h.finalize().into()
    };
    if digest != sha_field {
        bail!("keyslot checksum mismatch (corrupted or tampered)");
    }
    Ok(SlotData {
        key_id: u16::from_le_bytes([buf[12], buf[13]]),
        campaign_id,
        extractor_id,
        expiry_unix,
        issued_at_unix,
        recipient_pub,
    })
}

/// Refuse to run past the engagement expiry embedded at issue time.
pub fn check_expiry(slot: &SlotData) -> std::result::Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now > slot.expiry_unix {
        return Err(format!(
            "extractor expired on {} (now {}): ask the auditor for a fresh download",
            slot.expiry_unix, now
        ));
    }
    Ok(())
}

/// Find the offset of the one real keyslot. The magic literal also appears in
/// code (the `SLOT_MAGIC` constant), so a raw occurrence count is wrong: a
/// candidate only counts if its 512-byte region is a pristine placeholder
/// (zero checksum) or parses as a valid issued slot. Zero or multiple real
/// slots are fatal.
pub fn locate_unique(bin: &[u8]) -> Result<usize> {
    let mut candidates: Vec<usize> = Vec::new();
    let mut start = 0usize;
    while start + SLOT_MAGIC.len() <= bin.len() {
        match bin[start..].windows(SLOT_MAGIC.len()).position(|w| w == SLOT_MAGIC) {
            Some(rel) => {
                let off = start + rel;
                if off + SLOT_LEN <= bin.len() {
                    let region = &bin[off..off + SLOT_LEN];
                    let placeholder = region[480..512].iter().all(|&b| b == 0);
                    if placeholder || parse(region).is_ok() {
                        candidates.push(off);
                    }
                }
                start = off + 1;
            }
            None => break,
        }
    }
    match candidates.len() {
        0 => bail!("keyslot not found in binary"),
        1 => Ok(candidates[0]),
        _ => bail!("multiple keyslots found in binary; refusing to run"),
    }
}

/// Read this executable's own keyslot. Own-binary read is deliberately
/// NOT capped at MAX_READ (the slot may sit several MB into the file)
/// and is not an evidence read: it never touches the target system.
pub fn read_own_slot() -> Result<SlotData> {
    let exe = std::env::current_exe().context("locate own executable")?;
    let bin = std::fs::read(&exe).with_context(|| format!("read own binary {}", exe.display()))?;
    let off = locate_unique(&bin)?;
    parse(&bin[off..off + SLOT_LEN])
}

/// uuid-style formatting: 8-4-4-4-12.
pub fn hex_id(id: &[u8; 16]) -> String {
    let h = hex::encode(id);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}
