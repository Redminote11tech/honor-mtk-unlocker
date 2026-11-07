//! On-device partition discovery, reads, writes, and readback verification.
//! All block I/O happens through the root command channel (`dd` + base64).

use crate::device::RootSession;
use crate::model::PartitionInfo;
use base64::Engine;

pub const BLOCK_SIZE: u64 = 4096;

/// Discover block partitions. Prefers `/dev/block/by-name/`; falls back to a
/// scan of `/dev/block/` for known bootloader/security names.
pub fn discover(session: &RootSession) -> Result<Vec<PartitionInfo>, String> {
    let byname_dir = std::env::var("HONOR_BYNAME_DIR").unwrap_or_else(|_| "/dev/block/by-name".to_string());
    let byname = session.exec(&format!(
        "for f in {byname_dir}/*; do b=$(basename $f); t=$(readlink -f $f); \
         [ -e \"$t\" ] && echo \"$b $t\"; done"
    ))?;

    let mut out = Vec::new();
    for line in byname.lines() {
        let mut it = line.split_whitespace();
        if let (Some(name), Some(path)) = (it.next(), it.next()) {
            out.push(PartitionInfo {
                name: name.to_string(),
                block_path: path.to_string(),
                recognized: is_recognized(name),
            });
        }
        if out.len() >= 512 {
            break;
        }
    }
    if out.is_empty() {
        // Fallback: scan block devices for names of interest.
        let scan = session.exec(
            "find /dev/block -maxdepth 2 \\( -name 'lk*' -o -name 'seccfg*' \
             -o -name 'boot*' -o -name 'recovery*' \\) -type b 2>/dev/null",
        )?;
        for line in scan.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let name = line.rsplit('/').next().unwrap_or("").to_string();
            out.push(PartitionInfo {
                name: name.clone(),
                block_path: line.to_string(),
                recognized: is_recognized(&name),
            });
        }
    }
    Ok(out)
}

fn is_recognized(name: &str) -> bool {
    name.starts_with("lk") || name.contains("seccfg") || name.starts_with("boot")
        || name.starts_with("recovery")
}

pub fn resolve_by_name(session: &RootSession, name: &str) -> Result<String, String> {
    let parts = discover(session)?;
    parts
        .into_iter()
        .find(|p| p.name == name)
        .map(|p| p.block_path)
        .ok_or_else(|| format!("partition '{name}' not found on device"))
}

/// Chunk size for channel I/O. A single base64 argument must stay far below
/// the Linux per-argument limit (MAX_ARG_STRLEN = 128 KiB) — 90 KiB raw
/// payload arrives as a ~123 KiB argument, leaving headroom.
pub const CHUNK_BYTES: u64 = 48 * 1024;
/// Read `blocks` 4096-byte blocks from a block device through the root
/// channel, in bounded chunks.
pub fn read_blocks(session: &RootSession, path: &str, blocks: u64) -> Result<Vec<u8>, String> {
    let total = blocks * BLOCK_SIZE;
    let mut out = Vec::with_capacity(total as usize);
    let mut done: u64 = 0;
    while done < total {
        let take = (total - done).min(CHUNK_BYTES);
        let skip_blocks = done / BLOCK_SIZE;
        let take_blocks = (take + BLOCK_SIZE - 1) / BLOCK_SIZE;
        let cmd = format!(
            "dd if={path} bs={BLOCK_SIZE} skip={skip_blocks} count={take_blocks} \
             2>/dev/null | base64 -w0"
        );
        let b64 = session.exec(&cmd)?;
        let b64 = b64.split_whitespace().collect::<Vec<_>>().join("");
        if b64.is_empty() {
            if done == 0 {
                return Err(format!("read of {path} returned zero bytes"));
            }
            break; // end of file (short partition)
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| format!("base64 decode of partition read failed: {e}"))?;
        if bytes.is_empty() {
            break;
        }
        out.extend_from_slice(&bytes);
        done += bytes.len() as u64;
    }
    Ok(out)
}


/// Determine partition size in bytes. Tries blockdev, stat, then wc -c.
fn partition_size(session: &RootSession, path: &str) -> u64 {
    for probe in [
        format!("blockdev --getsize64 {path} 2>/dev/null"),
        format!("stat -c%s {path} 2>/dev/null"),
        format!("wc -c < {path} 2>/dev/null"),
    ] {
        if let Ok(s) = session.exec(&probe) {
            if let Ok(n) = s.trim().parse::<u64>() {
                if n > 0 {
                    return n;
                }
            }
        }
    }
    0
}

/// Read a whole partition to its full size (capped for safety).
pub fn read_partition(session: &RootSession, path: &str, max_mb: u64) -> Result<Vec<u8>, String> {
    let total = partition_size(session, path);
    let cap = max_mb * 1024 * 1024;
    let blocks = if total == 0 {
        (cap / BLOCK_SIZE).max(1)
    } else {
        (total.min(cap) + BLOCK_SIZE - 1) / BLOCK_SIZE
    };
    read_blocks(session, path, blocks)
}

/// Write bytes to a block device through the root channel, in bounded chunks.
pub fn write_bytes(session: &RootSession, path: &str, data: &[u8]) -> Result<(), String> {
    let mut offset: usize = 0;
    while offset < data.len() {
        let end = (offset + CHUNK_BYTES as usize).min(data.len());
        let chunk = &data[offset..end];
        let b64 = base64::engine::general_purpose::STANDARD.encode(chunk);
        let redirect = if offset == 0 { ">" } else { ">>" };
        let marker = if offset == 0 { "WROTE" } else { "APPENDED" };
        let cmd = format!(
            "printf '%s' '{b64}' | base64 -d {redirect} {path} && echo {marker}"
        );
        let out = session.exec(&cmd)?;
        if !out.contains(marker) {
            return Err(format!(
                "write to {path} at 0x{offset:x} did not confirm ({marker}; out: {out})"
            ));
        }
        offset = end;
    }
    Ok(())
}

/// Read back and compare SHA-256 of a written partition.
pub fn verify_readback(
    session: &RootSession,
    path: &str,
    expected_sha: &str,
    blocks: u64,
) -> Result<bool, String> {
    let data = read_blocks(session, path, blocks)?;
    let sha = crate::lk::sha256(&data);
    Ok(sha == expected_sha)
}
