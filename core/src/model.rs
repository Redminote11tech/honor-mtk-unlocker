//! Shared data types.

use serde::{Deserialize, Serialize};

/// A partition discovered on the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionInfo {
    pub name: String,
    pub block_path: String,
    /// True when the name matches a known bootloader/security partition we care about.
    pub recognized: bool,
}

impl PartitionInfo {
    pub fn kind(&self) -> PartitionKind {
        if self.name.starts_with("lk") {
            PartitionKind::Lk
        } else if self.name.contains("seccfg") {
            PartitionKind::Seccfg
        } else if self.name.starts_with("boot") || self.name.starts_with("recovery") {
            PartitionKind::BootImage
        } else {
            PartitionKind::Other
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionKind {
    Lk,
    Seccfg,
    BootImage,
    Other,
}

/// Result of parsing an MTK blob container (LK / preloader family).
#[derive(Debug, Clone)]
pub struct LkHeader {
    pub blob_len: u32,
    pub id: String,
    pub header2_magic: u32,
    pub payload_offset: usize,
    pub image_len: usize,
}

/// Firmware family of an LK image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FpVariant {
    /// MagicOS 7.1 (CRT-N31 7.1.0.157 C431E2R2P2) style init.
    Magicos71,
    /// MagicOS 9 / Android 15 (9.0.0.202 C431E9R2P3) style init.
    Magicos9,
}

impl FpVariant {
    pub fn label(self) -> &'static str {
        match self {
            FpVariant::Magicos71 => "MagicOS 7.1 (fb-unlock init @ 0x403c4)",
            FpVariant::Magicos9 => "MagicOS 9 (fb-unlock init @ 0x4acc0)",
        }
    }
}

/// Identification result for an LK image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LkIdentity {
    /// Original, unpatched firmware of the given variant.
    Original(FpVariant),
    /// Already carries the unlock patch.
    Patched(FpVariant),
    /// Unknown build — never patch without re-deriving the fingerprint.
    Unknown,
}

/// The patch recipe for a single known firmware variant.
#[derive(Debug, Clone)]
pub struct PatchRecipe {
    pub variant: FpVariant,
    /// File offset of the 4-byte patch site.
    pub site_offset: usize,
    /// Bytes that must be present at `site_offset` in an unpatched image.
    pub expected_before: [u8; 4],
    /// Replacement bytes.
    pub replace_with: [u8; 4],
    /// Byte signature used to locate the site (anchored so that the patched
    /// site bytes are at `site_offset` when `sig_site_rel` is added to the
    /// match position).
    pub signature: &'static [u8],
    /// Offset inside `signature` where the patch site starts.
    pub sig_site_rel: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccfgInfo {
    pub valid: bool,
    pub state: u32,
    pub state_label: String,
    pub header_len: u32,
    pub auth_magic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub serial: String,
    pub model: String,
    pub product: String,
    pub sdk: String,
    pub abi: String,
    pub slot: String,
    pub flash_locked: Option<String>,
    pub verified_boot_state: Option<String>,
    pub supported: bool,
    /// True when the boot reports an unlocked flash/bootloader (`ro.boot.flash.locked=0`).
    pub bootloader_unlocked: Option<bool>,
    /// True when a live uid-0 channel is available.
    pub root_present: bool,
    /// `ro.board.platform` (for example mt6833).
    pub platform: String,
    /// `ro.soc.model` (for example MT6833).
    pub soc_model: String,
    /// True when the SoC is MediaTek (platform starts with mt, or soc model
    /// contains MT). Snapdragon and others are rejected.
    pub is_mtk: bool,
}

/// Convenience hex helpers (kept tiny; `hex` crate used for formatting).
pub fn hex_str(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
