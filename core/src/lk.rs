//! MediaTek LK container parsing, firmware fingerprinting, and the fb-unlock
//! patch.
//!
//! # Container layout (verified against MagicOS 7.1 and MagicOS 9 images)
//! ```text
//! 0x000  u32 LE magic 0x58881688  (MTK blob marker)
//! 0x004  u32 LE blob payload length (code + header2 padding)
//! 0x008  8-byte ASCII id ("lk\0")
//! 0x010  header2 padding (mostly 0xff)
//! 0x030  u32 LE magic 0x58891689  (header2 marker), version 0x200, flags
//! 0x200  raw Thumb-2 code begins (load base = 0x48200000)
//! ```
//! The patch offset recorded in `lk-unlock-patch.json` is a *file* offset, so
//! payload offset = file offset - 0x200.
//!
//! # Known unlock patches (fb unlockstate)
//! Both patches force the cached Honor user-unlocked FB field (+0x104) to 1 by
//! replacing the 4-byte init that stored 0 with one that stores 1:
//! - MagicOS 7.1: file offset 0x403c4  `ff f7 b2 ff` -> `01 20 00 bf`
//! - MagicOS 9:   file offset 0x4acc0  `05 46 40 b3` -> `01 25 00 bf`

use crate::model::{FpVariant, LkHeader, LkIdentity, PatchRecipe};
use sha2::{Digest, Sha256};

pub const MTK_BLOB_MAGIC: u32 = 0x5888_1688;
pub const MTK_HEADER2_MAGIC: u32 = 0x5889_1689;
pub const PAYLOAD_OFFSET: usize = 0x200;
pub const SITE_LEN: usize = 4;

const SIG_71: &[u8] = &[
    0xff, 0xf7, 0xb2, 0xff, 0x05, 0x46, 0x80, 0xb1, 0xc4, 0xf8, 0x04, 0x51,
];
const SIG_9: &[u8] = &[
    0xff, 0xf7, 0xae, 0xff, 0x05, 0x46, 0x40, 0xb3, 0xc4, 0xf8, 0x04, 0x51,
];
const SIG_71_PATCHED: &[u8] = &[
    0x01, 0x20, 0x00, 0xbf, 0x05, 0x46, 0x80, 0xb1, 0xc4, 0xf8, 0x04, 0x51,
];
const SIG_9_PATCHED: &[u8] = &[
    0xff, 0xf7, 0xae, 0xff, 0x01, 0x25, 0x00, 0xbf, 0xc4, 0xf8, 0x04, 0x51,
];

/// LDY-AN00 (Magic8 Pro Air, MT6993) stock container pin, from the
/// upstream honor-ldy-an00-lk-unlock recipe.
pub const LDY_STOCK_SHA256: &str =
    "4a2758f3da93142b08059f140c02fd8c4540ff98890081d3e4475f28c9f28f67";
pub const LDY_STOCK_SIZE: usize = 7_976_720;
pub const LDY_PATCHED_SHA256: &str =
    "a2d1c3a7f0afcc87c19fff5daceed5e92b3f15b9a3306f088045f211c654dfc6";
pub const LDY_PATCHED_SIZE: usize = 7_976_800;
pub const LDY_ANCHOR_OFFSET: usize = 0x156a4;
/// The stock anchor instruction at `0x156a4` is `bl` (`b8 ff ff 97`).
pub const LDY_ANCHOR: [u8; 4] = [0xb8, 0xff, 0xff, 0x97];

/// The eight AArch64 instruction patches from the upstream recipe.
/// (raw file offset, replacement bytes)
pub const LDY_PATCHES: [(usize, &[u8]); 8] = [
    (0x156a4, &[0x20, 0x00, 0x80, 0x52]), // mov w0, #1
    (0x156d8, &[0x7f, 0x0e, 0x01, 0xb9]), // str w31, [x19, #0x10c]? (recipe)
    (0x15910, &[0x14, 0x00, 0x00, 0x14]), // b (skip)
    (0x1259d0, &[0x1f, 0x81, 0x0d, 0xb9]),
    (0xf0d04, &[0x81, 0x00, 0x80, 0x52]),
    (0x138e7c, &[0xe2, 0x03, 0x08, 0xaa]),
    (0x17d10, &[0x0d, 0x00, 0x00, 0x14]),
    (0x24d44, &[0x03, 0x00, 0x80, 0x52]),
];
/// Known patch recipes, keyed by variant.
/// Known single-site patch recipes. LDY-AN00 is not represented here: it uses
/// a multi-site + cert-bypass path handled by `patch_ldy`.
pub fn recipe(variant: FpVariant) -> PatchRecipe {
    match variant {
        FpVariant::Magicos71 => PatchRecipe {
            variant,
            site_offset: 0x403c4,
            expected_before: [0xff, 0xf7, 0xb2, 0xff],
            replace_with: [0x01, 0x20, 0x00, 0xbf],
            signature: SIG_71,
            sig_site_rel: 0,
        },
        FpVariant::Magicos9 => PatchRecipe {
            variant,
            site_offset: 0x4acc0,
            expected_before: [0x05, 0x46, 0x40, 0xb3],
            replace_with: [0x01, 0x25, 0x00, 0xbf],
            signature: SIG_9,
            sig_site_rel: 4,
        },
        FpVariant::Magicos10Ldy => PatchRecipe {
            variant,
            site_offset: 0,
            expected_before: [0; 4],
            replace_with: [0; 4],
            signature: &[],
            sig_site_rel: 0,
        },
    }
}

pub fn all_recipes() -> [PatchRecipe; 2] {
    [recipe(FpVariant::Magicos71), recipe(FpVariant::Magicos9)]
}

pub fn u32_le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Parse the MTK blob header of an LK image. Performs magic/identity/size
/// sanity checks; does not trust any single field alone.
pub fn parse_header(data: &[u8]) -> Result<LkHeader, String> {
    if data.len() < PAYLOAD_OFFSET + 64 {
        return Err(format!(
            "image too small for an LK container ({} bytes)",
            data.len()
        ));
    }
    if u32_le(data, 0) != MTK_BLOB_MAGIC {
        return Err(format!(
            "not an MTK blob: magic 0x{:08x} (expected 0x{:08x})",
            u32_le(data, 0),
            MTK_BLOB_MAGIC
        ));
    }
    let blob_len = u32_le(data, 4);
    if blob_len == 0 || blob_len as usize > data.len() + 0x10 {
        return Err(format!(
            "suspicious blob length 0x{:x} for image of {} bytes",
            blob_len,
            data.len()
        ));
    }
    let id = String::from_utf8_lossy(&data[8..16])
        .trim_end_matches('\0')
        .to_string();
    if !id.eq_ignore_ascii_case("lk") {
        return Err(format!("blob id is {:?}, not \"lk\"", id));
    }
    if u32_le(data, 0x30) != MTK_HEADER2_MAGIC {
        return Err(format!(
            "header2 marker missing at 0x30: 0x{:08x}",
            u32_le(data, 0x30)
        ));
    }
    Ok(LkHeader {
        blob_len,
        id,
        header2_magic: u32_le(data, 0x30),
        payload_offset: PAYLOAD_OFFSET,
        image_len: data.len(),
    })
}

/// Locate a signature in the code payload, returning the file offset of the
/// patch site inside it.
fn find_site(data: &[u8], sig: &[u8], sig_site_rel: usize) -> Option<usize> {
    if data.len() < PAYLOAD_OFFSET + sig.len() {
        return None;
    }
    let start = PAYLOAD_OFFSET;
    let end = data.len() - sig.len();
    let mut i = start;
    while i <= end {
        if &data[i..i + sig.len()] == sig {
            return Some(i + sig_site_rel);
        }
        i += 1;
    }
    None
}

/// Identify an LK image's firmware family and patch state.
pub fn identify(data: &[u8]) -> LkIdentity {
    for r in all_recipes() {
        if let Some(site) = find_site(data, r.signature, r.sig_site_rel) {
            let at_site = &data[site..site + SITE_LEN];
            if at_site == r.expected_before {
                return LkIdentity::Original(r.variant);
            }
            if at_site == r.replace_with {
                return LkIdentity::Patched(r.variant);
            }
        }
        // Some builds ship already-patched (or the patched sig differs in a
        // byte that is not the first four; check separately).
        let patched_sig = match r.variant {
            FpVariant::Magicos71 => SIG_71_PATCHED,
            FpVariant::Magicos9 => SIG_9_PATCHED,
            FpVariant::Magicos10Ldy => continue,
        };
        if let Some(site) = find_site(data, patched_sig, r.sig_site_rel) {
            if &data[site..site + SITE_LEN] == r.replace_with {
                return LkIdentity::Patched(r.variant);
            }
        }
    }
    // LDY-AN00 special case: identified by exact stock size + anchor bytes.
    if data.len() == LDY_STOCK_SIZE
        && data.get(LDY_ANCHOR_OFFSET..LDY_ANCHOR_OFFSET + 4) == Some(&LDY_ANCHOR[..])
    {
        return LkIdentity::Original(FpVariant::Magicos10Ldy);
    }
    if data.len() == LDY_PATCHED_SIZE {
        let h = sha256(data);
        if h == LDY_PATCHED_SHA256 {
            return LkIdentity::Patched(FpVariant::Magicos10Ldy);
        }
    }
    LkIdentity::Unknown
}

/// Candidate unlock-init site hint for unknown builds. The fb store pattern
/// `str r5, [r4, #4]` (`c4 f8 04 51`) is a reliable anchor in the unlock
/// init on MTK LK images. We report every occurrence with its surrounding
/// bytes so a contributor can derive a new fingerprint.
pub fn hint_fingerprint(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if data.len() < PAYLOAD_OFFSET + 4 {
        return out;
    }
    let start = PAYLOAD_OFFSET;
    let mut i = start;
    while i + 4 <= data.len() {
        if &data[i..i + 4] == &[0xc4, 0xf8, 0x04, 0x51] {
            out.push(i);
            i += 4;
        } else {
            i += 1;
        }
    }
    out
}

/// Outcome of a patch operation.
#[derive(Debug, Clone)]
pub struct PatchOutcome {
    pub variant: FpVariant,
    pub site_offset: usize,
    pub before: [u8; 4],
    pub after: [u8; 4],
    pub already_patched: bool,
    /// The modified image (identical to input when `already_patched`).
    pub data: Vec<u8>,
    pub sha256_after: String,
}

pub fn sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Patch an LK image for the given variant.
///
/// Safety: the site bytes are verified against `expected_before`; any
/// mismatch aborts with an error (the image is not what the recipe expects).
pub fn patch(data: &[u8], variant: FpVariant) -> Result<PatchOutcome, String> {
    if variant == FpVariant::Magicos10Ldy {
        return patch_ldy(data);
    }
    // Parse first so we never patch a non-LK file.
    parse_header(data)?;
    let r = recipe(variant);

    let identity = identify(data);
    match identity {
        LkIdentity::Patched(v) if v == variant => {
            return Ok(PatchOutcome {
                variant,
                site_offset: r.site_offset,
                before: r.expected_before,
                after: r.replace_with,
                already_patched: true,
                data: data.to_vec(),
                sha256_after: sha256(data),
            });
        }
        LkIdentity::Original(v) if v == variant => {}
        _ => {
            return Err(format!(
                "refusing to patch: image is not an unpatched {} build (identified as {:?})",
                variant.label(),
                identity
            ));
        }
    }

    // Double-check with the anchored search, not just the recipe constant, so
    // that a build with the same site offset but different code fails safely.
    let site = find_site(data, r.signature, r.sig_site_rel)
        .ok_or_else(|| "patch site signature not found in image".to_string())?;
    if &data[site..site + SITE_LEN] != r.expected_before {
        return Err(format!(
            "patch site @0x{:x} does not match expected original {:?} (got {:?}) - \
             wrong build, refusing",
            site,
            r.expected_before,
            &data[site..site + SITE_LEN]
        ));
    }

    let mut out = data.to_vec();
    out[site..site + SITE_LEN].copy_from_slice(&r.replace_with);
    let sha256_after = sha256(&out);
    Ok(PatchOutcome {
        variant,
        site_offset: site,
        before: r.expected_before,
        after: r.replace_with,
        already_patched: false,
        data: out,
        sha256_after,
    })
}

/// Patch an LK image after auto-identifying its firmware. Unknown builds are
/// rejected.
pub fn patch_auto(data: &[u8]) -> Result<PatchOutcome, String> {
    match identify(data) {
        LkIdentity::Original(v) => patch(data, v),
        LkIdentity::Patched(v) => patch(data, v),
        LkIdentity::Unknown => Err(
            "unsupported firmware build: no known LK patch signature found in this image. \
             To support it, add a fingerprint to lk.rs (all_recipes) with its site bytes \
             and a golden test; the tool refuses to guess."
                .to_string(),
        ),
    }
}

/// Patch an LDY-AN00 image: apply the eight instruction patches, then run the
/// CERT2 hash-override bypass on every partition whose cert2 no longer
/// matches. Verifies the resulting image against the pinned output hash.
pub fn patch_ldy(data: &[u8]) -> Result<PatchOutcome, String> {
    if data.len() != LDY_STOCK_SIZE {
        return Err(format!(
            "LDY stock image must be exactly {LDY_STOCK_SIZE} bytes (got {})",
            data.len()
        ));
    }
    let h = sha256(data);
    if h != LDY_STOCK_SHA256 {
        return Err(format!(
            "LDY stock SHA-256 mismatch: got {h}, expected {LDY_STOCK_SHA256}"
        ));
    }
    if data.get(LDY_ANCHOR_OFFSET..LDY_ANCHOR_OFFSET + 4) != Some(&LDY_ANCHOR[..]) {
        return Err("LDY anchor instruction missing at 0x156a4".into());
    }

    let mut out = data.to_vec();
    let mut sites = Vec::new();
    for &(off, repl) in &LDY_PATCHES {
        if off + repl.len() > out.len() {
            return Err(format!("LDY patch at 0x{off:x} out of range"));
        }
        sites.push((off, out[off..off + repl.len()].to_vec(), repl.to_vec()));
        out[off..off + repl.len()].copy_from_slice(repl);
    }

    // CERT2 hash-override bypass.
    let mut image =
        crate::cert::Image::parse(&out).map_err(|e| format!("LDY container parse failed: {e}"))?;
    let mut signed = Vec::new();
    for part in image.partitions.iter_mut() {
        let Some(cert2) = part.cert2().cloned() else {
            continue;
        };
        let (hh, ih) = part.compute_hashes();
        if !crate::cert::cert2_matches(&cert2.data, &hh, &ih) {
            let ov = crate::cert::cert2_override(&cert2.data, &hh, &ih)?;
            crate::cert::set_cert2_data(&mut part.certs[1], ov);
            signed.push(part.header.name.clone());
        }
    }
    if !signed.is_empty() {
        out = image.rebuild();
    }

    if out.len() != LDY_PATCHED_SIZE {
        return Err(format!(
            "LDY patched image must be {LDY_PATCHED_SIZE} bytes (got {})",
            out.len()
        ));
    }
    let out_hash = sha256(&out);
    if out_hash != LDY_PATCHED_SHA256 {
        return Err(format!(
            "LDY patched SHA-256 mismatch: got {out_hash}, expected {LDY_PATCHED_SHA256}"
        ));
    }

    let (first_off, first_before, first_after) = sites.remove(0);
    let mut before4 = [0u8; 4];
    let mut after4 = [0u8; 4];
    before4.copy_from_slice(&first_before[..4]);
    after4.copy_from_slice(&first_after[..4]);
    Ok(PatchOutcome {
        variant: FpVariant::Magicos10Ldy,
        site_offset: first_off,
        before: before4,
        after: after4,
        already_patched: false,
        data: out,
        sha256_after: out_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        ))
        .unwrap_or_else(|e| panic!("fixture {} missing: {}", name, e))
    }

    #[test]
    fn parses_71_header() {
        let data = fixture("lk_71_a_original.bin");
        let h = parse_header(&data).unwrap();
        assert_eq!(h.id, "lk");
        assert_eq!(h.blob_len, 0x2048a4);
        assert_eq!(h.payload_offset, 0x200);
    }

    #[test]
    fn parses_9_header() {
        let data = fixture("lk_9_a_original.bin");
        let h = parse_header(&data).unwrap();
        assert_eq!(h.id, "lk");
        assert_eq!(h.blob_len, 0x2501c0);
    }

    #[test]
    fn rejects_non_lk() {
        let garbage = vec![0u8; 8192];
        assert!(parse_header(&garbage).is_err());
    }

    #[test]
    fn identifies_71_original_and_patched() {
        let orig = fixture("lk_71_a_original.bin");
        let patched = fixture("lk_71_a_patched.bin");
        assert_eq!(identify(&orig), LkIdentity::Original(FpVariant::Magicos71));
        assert_eq!(
            identify(&patched),
            LkIdentity::Patched(FpVariant::Magicos71)
        );
    }

    #[test]
    fn identifies_9_original_and_patched() {
        let orig = fixture("lk_9_a_original.bin");
        let patched = fixture("lk_9_a_patched.bin");
        assert_eq!(identify(&orig), LkIdentity::Original(FpVariant::Magicos9));
        assert_eq!(identify(&patched), LkIdentity::Patched(FpVariant::Magicos9));
    }

    #[test]
    fn patch_71_matches_known_patched_image() {
        let orig = fixture("lk_71_a_original.bin");
        let known = fixture("lk_71_a_patched.bin");
        let out = patch(&orig, FpVariant::Magicos71).unwrap();
        assert!(!out.already_patched);
        assert_eq!(out.site_offset, 0x403c4);
        assert_eq!(out.after, [0x01, 0x20, 0x00, 0xbf]);
        assert_eq!(
            out.data, known,
            "patched image must be byte-identical to the proven lk-patched.bin"
        );
        assert_eq!(
            out.sha256_after,
            "b40207b4d7a0ca1ce0c553cb9e8bf747020007ea303497308ec3ead1f5b24d2d"
        );
    }

    #[test]
    fn patch_9_matches_known_patched_image() {
        let orig = fixture("lk_9_a_original.bin");
        let known = fixture("lk_9_a_patched.bin");
        let out = patch(&orig, FpVariant::Magicos9).unwrap();
        assert!(!out.already_patched);
        assert_eq!(out.site_offset, 0x4acc0);
        assert_eq!(out.after, [0x01, 0x25, 0x00, 0xbf]);
        assert_eq!(out.data, known);
        assert_eq!(
            out.sha256_after,
            "ec2867329c58f1d8dade8d3eb89c9a86688e27d0e2b4a1e75a95b53b6c1f0ef5"
        );
    }

    #[test]
    fn double_patch_is_idempotent() {
        let orig = fixture("lk_71_a_original.bin");
        let once = patch(&orig, FpVariant::Magicos71).unwrap();
        let twice = patch(&once.data, FpVariant::Magicos71).unwrap();
        assert!(twice.already_patched);
        assert_eq!(twice.data, once.data);
    }

    #[test]
    fn refuses_wrong_variant_patch() {
        let orig71 = fixture("lk_71_a_original.bin");
        // Patching a 7.1 image with the 9 recipe must fail.
        assert!(patch(&orig71, FpVariant::Magicos9).is_err());
    }

    #[test]
    fn auto_patch_unknown_rejected() {
        let garbage = vec![0x11u8; 100_000];
        assert!(patch_auto(&garbage).is_err());
    }

    #[test]
    fn ldy_recipe_constants_sane() {
        assert!(LDY_STOCK_SIZE < LDY_PATCHED_SIZE);
        assert!(LDY_ANCHOR_OFFSET + 4 <= LDY_STOCK_SIZE);
        for &(off, repl) in &LDY_PATCHES {
            assert!(
                off + repl.len() <= LDY_STOCK_SIZE,
                "patch @0x{off:x} out of range"
            );
            assert_eq!(repl.len(), 4, "LDY patch @0x{off:x} must be 4 bytes");
        }
        assert_eq!(LDY_PATCHES.len(), 8);
        assert_eq!(LDY_PATCHES[0].0, LDY_ANCHOR_OFFSET);
    }

    #[test]
    fn identifies_ldy_stock_by_size_and_anchor() {
        let mut data = vec![0u8; LDY_STOCK_SIZE];
        data[LDY_ANCHOR_OFFSET..LDY_ANCHOR_OFFSET + 4].copy_from_slice(&LDY_ANCHOR);
        assert_eq!(
            identify(&data),
            LkIdentity::Original(FpVariant::Magicos10Ldy)
        );
    }

    #[test]
    fn rejects_wrong_size_ldy() {
        let data = vec![0u8; LDY_STOCK_SIZE - 1];
        assert_eq!(identify(&data), LkIdentity::Unknown);
    }
}
