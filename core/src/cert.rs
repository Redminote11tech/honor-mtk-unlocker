//! MediaTek LK image container parsing/serialization and the CERT2
//! hash-override bypass.
//!
//! This is a faithful Rust port of the pinned upstream logic:
//! - `liblk` (R0rt1z2) for container/partition parsing and hashing
//! - `lk-unlock` (georgiynesterov) `build_bypass_cert2_override` for the
//!   certificate bypass
//!
//! # Container layout
//! The LK image is a sequence of 512-byte partition headers
//! (`0x58881688` magic), followed by data, padding to the partition
//! alignment, then certificate partitions (cert1/cert2) owned by the
//! preceding data partition.
//!
//! # Hash override
//! After patching data, the embedded cert2 hashes no longer match. The
//! override prepends a context-specific `[0]` DER block advertising the new
//! hashes, followed by the original certificate. The verifier accepts the
//! override block's hashes.

use sha2::{Digest, Sha256};

pub const MAGIC: u32 = 0x5888_1688;
pub const EXT_MAGIC: u32 = 0x5889_1689;
pub const HEADER_SIZE: usize = 512;
pub const IMAGE_HASH_ALIGNMENT: usize = 16;

#[derive(Debug, Clone)]
pub struct Header {
    pub magic: u32,
    pub dsize: u32,
    pub name: String,
    pub maddr: u32,
    pub mode: u32,
    pub ext_magic: u32,
    pub hdr_size: u32,
    pub hdr_version: u32,
    pub image_type: [u8; 4],
    pub image_list_end: u32,
    pub alignment: u32,
    pub dsize_extend: u32,
    pub maddr_extend: u32,
    pub raw: [u8; HEADER_SIZE],
}

impl Header {
    pub fn parse(raw: &[u8]) -> Result<Header, String> {
        if raw.len() < HEADER_SIZE {
            return Err("header too short".into());
        }
        let magic = u32_le(raw, 0);
        if magic != MAGIC {
            return Err(format!("invalid magic 0x{magic:08x}"));
        }
        let ext_magic = u32_le(raw, 0x30);
        let dsize = u32_le(raw, 4);
        let dsize_extend = u32_le(raw, 0x48);
        let data_size = if ext_magic == EXT_MAGIC {
            ((dsize_extend as u64) << 32) | dsize as u64
        } else {
            dsize as u64
        };
        if data_size > 0x1000_0000 {
            return Err(format!("data_size implausible: 0x{data_size:x}"));
        }
        let name_end = raw[8..40].iter().position(|&b| b == 0).unwrap_or(32);
        let name = String::from_utf8_lossy(&raw[8..8 + name_end]).to_string();
        let mut rawarr = [0u8; HEADER_SIZE];
        rawarr.copy_from_slice(&raw[..HEADER_SIZE]);
        Ok(Header {
            magic,
            dsize,
            name,
            maddr: u32_le(raw, 0x28),
            mode: u32_le(raw, 0x2c),
            ext_magic,
            hdr_size: u32_le(raw, 0x34),
            hdr_version: u32_le(raw, 0x38),
            image_type: [raw[0x3c], raw[0x3d], raw[0x3e], raw[0x3f]],
            image_list_end: u32_le(raw, 0x40),
            alignment: u32_le(raw, 0x44),
            dsize_extend,
            maddr_extend: u32_le(raw, 0x4c),
            raw: rawarr,
        })
    }

    pub fn is_extended(&self) -> bool {
        self.ext_magic == EXT_MAGIC
    }

    pub fn size(&self) -> usize {
        if self.is_extended() {
            self.hdr_size as usize
        } else {
            HEADER_SIZE
        }
    }

    pub fn data_size(&self) -> u64 {
        if self.is_extended() {
            ((self.dsize_extend as u64) << 32) | self.dsize as u64
        } else {
            self.dsize as u64
        }
    }

    pub fn alignment(&self) -> usize {
        if self.is_extended() {
            self.alignment as usize
        } else {
            8
        }
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        self.raw
    }
}

fn u32_le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[derive(Debug, Clone)]
pub struct Partition {
    pub header: Header,
    pub data: Vec<u8>,
    pub certs: Vec<Partition>,
    pub end_offset: usize,
}

impl Partition {
    pub fn from_bytes(contents: &[u8], offset: usize) -> Result<Partition, String> {
        let start = if contents.len() >= 4 && &contents[..4] == b"BFBF" {
            0x4040
        } else {
            0
        };
        let header = Header::parse(&contents[start..start + HEADER_SIZE])?;
        let header_size = header.size();
        let data_size = header.data_size() as usize;
        let mut end = offset + header_size + data_size;
        let alignment = header.alignment();
        if alignment > 0 && end % alignment != 0 {
            end += alignment - (end % alignment);
        }
        if header_size + data_size > contents.len() {
            return Err("partition data out of bounds".into());
        }
        let data = contents[header_size..header_size + data_size].to_vec();
        Ok(Partition {
            header,
            data,
            certs: Vec::new(),
            end_offset: end,
        })
    }

    pub fn cert2(&self) -> Option<&Partition> {
        self.certs.get(1)
    }

    pub fn compute_hashes(&self) -> ([u8; 32], [u8; 32]) {
        let header_hash = Sha256::digest(self.header.to_bytes());
        let mut data = self.data.clone();
        let pad =
            (IMAGE_HASH_ALIGNMENT - (data.len() % IMAGE_HASH_ALIGNMENT)) % IMAGE_HASH_ALIGNMENT;
        data.extend(std::iter::repeat(0u8).take(pad));
        let data_hash = Sha256::digest(&data);
        let mut hh = [0u8; 32];
        let mut ih = [0u8; 32];
        hh.copy_from_slice(&header_hash);
        ih.copy_from_slice(&data_hash);
        (hh, ih)
    }

    pub fn matches_cert2(&self) -> Option<bool> {
        let c2 = self.cert2()?;
        let (hh, ih) = self.compute_hashes();
        match override_hashes(&c2.data) {
            Some((chh, cih)) => Some(chh == hh && cih == ih),
            None => None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.header.to_bytes().to_vec();
        out.extend_from_slice(&self.data);
        let alignment = self.header.alignment();
        if alignment > 0 && self.data.len() % alignment != 0 {
            let pad = alignment - (self.data.len() % alignment);
            out.extend(std::iter::repeat(0u8).take(pad));
        }
        for cert in &self.certs {
            out.extend_from_slice(&cert.to_bytes());
        }
        out
    }
}

pub struct Image {
    pub partitions: Vec<Partition>,
}

impl Image {
    pub fn parse(contents: &[u8]) -> Result<Image, String> {
        let mut partitions: Vec<Partition> = Vec::new();
        let mut offset = 0usize;
        let mut _last_name = String::new();
        while offset < contents.len() {
            let part = match Partition::from_bytes(&contents[offset..], offset) {
                Ok(p) => p,
                Err(_) => break,
            };
            let end_offset = part.end_offset;
            let is_ext = part.header.is_extended();
            let list_end = part.header.image_list_end;
            if part.header.magic != MAGIC {
                break;
            }
            if part.header.name.starts_with("cert") {
                let last = partitions.last_mut().ok_or("cert before partition")?;
                last.certs.push(part);
            } else {
                _last_name = part.header.name.clone();
                partitions.push(part);
            }
            if is_ext && list_end == 1 {
                break;
            }
            offset = end_offset;
            if offset >= contents.len() {
                break;
            }
        }
        Ok(Image { partitions })
    }

    pub fn rebuild(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.partitions.is_empty() {
            return out;
        }
        let mut parts = self.partitions.clone();
        for p in parts.iter_mut() {
            p.header.image_list_end = 0;
            for c in p.certs.iter_mut() {
                c.header.image_list_end = 0;
            }
        }
        let last = parts.last_mut().unwrap();
        if let Some(last_cert) = last.certs.last_mut() {
            last_cert.header.image_list_end = 1;
        } else {
            last.header.image_list_end = 1;
        }
        for p in &parts {
            out.extend_from_slice(&p.to_bytes());
        }
        out
    }
}

/// Minimal DER length encoding (used for the override container).
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let body = len.to_be_bytes();
        let skip = body.iter().position(|&b| b != 0).unwrap_or(body.len() - 1);
        let mut out = vec![0x80 | (body.len() - skip) as u8];
        out.extend_from_slice(&body[skip..]);
        out
    }
}

/// DER-encode a BIT STRING with zero unused bits (used for the hashes).
fn der_bitstring(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0x03];
    out.extend(der_len(bytes.len() + 1));
    out.push(0x00);
    out.extend_from_slice(bytes);
    out
}

/// Walk the DER SEQUENCE children of `raw` and return the encoding of the
/// child at the given zero-based index.
fn child_tlv(raw: &[u8], index: usize) -> Option<Vec<u8>> {
    let mut off = 0usize;
    let mut cur = 0usize;
    while off < raw.len() {
        let _tag = raw[off];
        let mut p = off + 1;
        if p >= raw.len() {
            return None;
        }
        // length
        let l0 = raw[p];
        p += 1;
        let len = if l0 < 0x80 {
            l0 as usize
        } else {
            let n = (l0 & 0x7f) as usize;
            if n == 0 || p + n > raw.len() {
                return None;
            }
            let mut v = 0usize;
            for &b in &raw[p..p + n] {
                v = (v << 8) | b as usize;
            }
            p += n;
            v
        };
        if p + len > raw.len() {
            return None;
        }
        if cur == index {
            return Some(raw[off..p + len].to_vec());
        }
        cur += 1;
        off = p + len;
    }
    None
}

/// Strip the leading TLV header of a DER value and return its contents.
fn der_contents(raw: &[u8]) -> Option<&[u8]> {
    if raw.is_empty() {
        return None;
    }
    let mut p = 1usize;
    if p >= raw.len() {
        return None;
    }
    let l0 = raw[p];
    p += 1;
    let len = if l0 < 0x80 {
        l0 as usize
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || p + n > raw.len() {
            return None;
        }
        let mut v = 0usize;
        for &b in &raw[p..p + n] {
            v = (v << 8) | b as usize;
        }
        p += n;
        v
    };
    if p + len > raw.len() {
        return None;
    }
    Some(&raw[p..p + len])
}

/// Extract the two hash OIDs from a cert2 (children 13 and 9) and the hashes
/// (children 14 and 10).
///
/// liblk indexes `decoded[0]`, where `decoded` is the outer SEQUENCE and
/// `decoded[0]` is the inner TBS certificate SEQUENCE. So we descend two
/// levels: outer contents -> child 0 (TBS) -> its contents -> index children.
fn override_hashes(cert2: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let outer = der_contents(cert2)?;
    let tbs_tlv = child_tlv(outer, 0)?;
    let tbs = der_contents(&tbs_tlv)?;
    let header_hash_tlv = child_tlv(tbs, 14)?;
    let image_hash_tlv = child_tlv(tbs, 10)?;
    let mut hh = [0u8; 32];
    let mut ih = [0u8; 32];
    // BIT STRING content is [unused_bits byte][hash...]
    hh.copy_from_slice(&header_hash_tlv[3..35]);
    ih.copy_from_slice(&image_hash_tlv[3..35]);
    Some((hh, ih))
}

/// Build the CERT2 hash-override block (context `[0]`).
pub fn build_hash_override_block(
    cert2: &[u8],
    header_hash: &[u8; 32],
    image_hash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let outer = der_contents(cert2).ok_or("not a DER SEQUENCE")?;
    let tbs_tlv = child_tlv(outer, 0).ok_or("TBS missing")?;
    let tbs = der_contents(&tbs_tlv).ok_or("TBS contents missing")?;
    let header_oid = child_tlv(tbs, 13).ok_or("header OID missing")?;
    let image_oid = child_tlv(tbs, 9).ok_or("image OID missing")?;
    let mut content = Vec::new();
    content.extend_from_slice(&header_oid);
    content.extend(der_bitstring(header_hash));
    content.extend_from_slice(&image_oid);
    content.extend(der_bitstring(image_hash));
    let mut out = vec![0xa0];
    out.extend(der_len(content.len()));
    out.extend(content);
    Ok(out)
}

/// Replace a cert2 partition's data and update its header data-size field.
pub fn set_cert2_data(partition: &mut Partition, data: Vec<u8>) {
    partition.data = data.clone();
    let len = data.len() as u32;
    partition.header.dsize = len;
    partition.header.dsize_extend = 0;
    // Update the raw header bytes at the dsize offset (0x04).
    partition.header.raw[0x04..0x08].copy_from_slice(&len.to_le_bytes());
}

/// Check whether a cert2's embedded hashes match the given partition hashes.
pub fn cert2_matches(cert2: &[u8], header_hash: &[u8; 32], image_hash: &[u8; 32]) -> bool {
    match override_hashes(cert2) {
        Some((hh, ih)) => hh == *header_hash && ih == *image_hash,
        None => false,
    }
}

/// Apply the override bypass to a cert2 partition's data.
pub fn cert2_override(
    cert2: &[u8],
    header_hash: &[u8; 32],
    image_hash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let block = build_hash_override_block(cert2, header_hash, image_hash)?;
    let mut out = block;
    out.extend_from_slice(cert2);
    Ok(out)
}

pub fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
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
    fn parses_lk9_container() {
        let data = fixture("lk_9_a_original.bin");
        let img = Image::parse(&data).unwrap();
        assert!(img.partitions.iter().any(|p| p.header.name == "lk"));
        let lk = img
            .partitions
            .iter()
            .find(|p| p.header.name == "lk")
            .unwrap();
        assert!(lk.cert2().is_some(), "lk must have cert2");
    }

    #[test]
    fn cert2_override_matches_oracle_vector() {
        // Golden vector captured from upstream liblk + lk-unlock.
        let data = fixture("lk_9_a_original.bin");
        let img = Image::parse(&data).unwrap();
        let lk = img
            .partitions
            .iter()
            .find(|p| p.header.name == "lk")
            .unwrap();
        let c2 = lk.cert2().unwrap().data.clone();
        let (hh, ih) = lk.compute_hashes();
        let got = cert2_override(&c2, &hh, &ih).unwrap();
        let expect = std::fs::read("/tmp/vec_override.bin").unwrap();
        assert_eq!(got, expect, "override must be byte-identical to upstream");
        assert_eq!(got.len(), 1098);
    }

    #[test]
    fn full_patch_reproduces_oracle() {
        // Oracle reference produced from the byte-flipped image by upstream.
        let flipped = std::fs::read("/tmp/lk9_flip.bin").unwrap();
        let img = Image::parse(&flipped).unwrap();
        let mut img = img;
        let (hh, ih) = {
            let lk = img
                .partitions
                .iter()
                .find(|p| p.header.name == "lk")
                .unwrap();
            lk.compute_hashes()
        };
        {
            let lk = img
                .partitions
                .iter_mut()
                .find(|p| p.header.name == "lk")
                .unwrap();
            let c2 = lk.cert2().unwrap().data.clone();
            let ov = cert2_override(&c2, &hh, &ih).unwrap();
            set_cert2_data(&mut lk.certs[1], ov);
        }
        let rebuilt = img.rebuild();
        let expect = std::fs::read("/tmp/lk9_patched_oracle.bin").unwrap();
        assert_eq!(rebuilt, expect, "rebuilt image must match upstream oracle");
    }
}
