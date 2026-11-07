//! seccfg partition parsing, validation, and the 0x03 unlock write.
//!
//! # Layout (verified against MagicOS 7.1 and 9 dumps)
//! ```text
//! 0x00  u32 LE magic "MMMM" (0x4D4D4D4D)
//! 0x04  u32 LE 4            (header type / V4 marker)
//! 0x08  u32 LE 0x3c         (header length, 60)
//! 0x0c  u32 LE lock state    (0x01 locked, 0x03 unlocked)
//! 0x10  padding
//! 0x18  u32 LE magic "EEEE" (authenticated region marker)
//! 0x1c  40 bytes of device-authenticated hash / random material
//! ```
//!
//! # Important caveat
//! On this device family seccfg is V4: the 40-byte authenticated region is a
//! device-authenticated hash. A raw hex-edit of only the state d is **not**
//! the proven path (the proven path was the MTK DA with the hardware V4 hash
//! method). This module therefore patches only the state field, preserves every
//! other byte, and always reports that the authenticated region is untouched.

use crate::model::SeccfgInfo;

pub const MAGIC_MMMM: u32 = 0x4D4D_4D4D;
pub const MAGIC_EEEE: u32 = 0x4545_4545;
pub const STATE_LOCKED: u32 = 0x01;
pub const STATE_UNLOCKED: u32 = 0x03;
const STATE_OFFSET: usize = 0x0c;
const HEADER_LEN: usize = 0x3c;

fn u32_le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

pub fn state_label(state: u32) -> String {
    match state {
        STATE_LOCKED => "LOCKED (0x01)".to_string(),
        STATE_UNLOCKED => "UNLOCKED (0x03)".to_string(),
        s => format!("unknown (0x{s:02x})"),
    }
}

/// Parse and validate a seccfg image. Tolerant: reports validity rather than
/// failing hard, so read-only analysis still yields useful info on odd dumps.
pub fn parse(data: &[u8]) -> Result<SeccfgInfo, String> {
    if data.len() < 0x40 {
        return Err(format!("seccfg image too small ({} bytes)", data.len()));
    }
    let magic = u32_le(data, 0);
    if magic != MAGIC_MMMM {
        return Err(format!(
            "not a seccfg image: magic 0x{:08x} (expected MMMM)",
            magic
        ));
    }
    let header_len = u32_le(data, 8);
    let state = u32_le(data, STATE_OFFSET);
    let auth_magic = u32_le(data, 0x18);
    let valid = header_len == HEADER_LEN as u32 && auth_magic == MAGIC_EEEE;
    Ok(SeccfgInfo {
        valid,
        state,
        state_label: state_label(state),
        header_len,
        auth_magic: format!("0x{auth_magic:08x}"),
    })
}

#[derive(Debug, Clone)]
pub enum SeccfgPatch {
    /// State was 0x01; now 0x03.
    Patched(Vec<u8>),
    /// Already 0x03; nothing to do.
    AlreadyUnlocked,
}

/// Produce the patched (unlocked) seccfg image.
///
/// Only the state word at 0x0c changes. The authenticated region is preserved
/// byte-for-byte; callers must surface that this is not the proven V4 path.
pub fn patch_unlock(data: &[u8]) -> Result<SeccfgPatch, String> {
    let info = parse(data)?;
    if !info.valid {
        return Err(format!(
            "seccfg header invalid (header_len=0x{:x}, auth_magic={}): refusing to patch",
            info.header_len, info.auth_magic
        ));
    }
    match info.state {
        STATE_UNLOCKED => Ok(SeccfgPatch::AlreadyUnlocked),
        STATE_LOCKED => {
            let mut out = data.to_vec();
            out[STATE_OFFSET..STATE_OFFSET + 4].copy_from_slice(&STATE_UNLOCKED.to_le_bytes());
            Ok(SeccfgPatch::Patched(out))
        }
        s => Err(format!(
            "seccfg state 0x{s:02x} not in {{0x01, 0x03}}: refusing to guess"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name))
            .unwrap_or_else(|e| panic!("fixture {} missing: {}", name, e))
    }

    #[test]
    fn parses_locked() {
        let data = fixture("seccfg_locked.bin");
        let i = parse(&data).unwrap();
        assert!(i.valid);
        assert_eq!(i.state, STATE_LOCKED);
        assert_eq!(i.auth_magic, "0x45454545");
    }

    #[test]
    fn parses_unlocked() {
        let data = fixture("seccfg_unlocked.bin");
        let i = parse(&data).unwrap();
        assert!(i.valid);
        assert_eq!(i.state, STATE_UNLOCKED);
    }

    #[test]
    fn patch_locked_to_unlocked_preserves_auth_region() {
        let data = fixture("seccfg_locked.bin");
        match patch_unlock(&data).unwrap() {
            SeccfgPatch::Patched(out) => {
                assert_eq!(u32_le(&out, STATE_OFFSET), STATE_UNLOCKED);
                // Everything except the state word is byte-identical.
                let mut expect = data.clone();
                expect[STATE_OFFSET..STATE_OFFSET + 4]
                    .copy_from_slice(&STATE_UNLOCKED.to_le_bytes());
                assert_eq!(out, expect);
            }
            SeccfgPatch::AlreadyUnlocked => panic!("expected patch"),
        }
    }

    #[test]
    fn patch_already_unlocked_is_noop() {
        let data = fixture("seccfg_unlocked.bin");
        assert!(matches!(
            patch_unlock(&data).unwrap(),
            SeccfgPatch::AlreadyUnlocked
        ));
    }

    #[test]
    fn rejects_non_seccfg() {
        assert!(parse(&[0u8; 256]).is_err());
    }
}
