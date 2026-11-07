//! Unlock orchestration: analyze, back up, patch, write, and verify.
//!
//! Order is fixed: seccfg first (when it needs a change), then LK slot A, then
//! LK slot B. Every write is preceded by saving the original to `outdir` and
//! followed by a readback hash check.

use crate::device::RootSession;
use crate::lk::{self, PatchOutcome};
use crate::model::FpVariant;
use crate::model::LkIdentity;
use crate::partition;
use crate::seccfg::{self, SeccfgPatch};
use serde::Serialize;
use std::path::Path;

pub const LK_A_NAME: &str = "lk_a";
pub const LK_B_NAME: &str = "lk_b";
pub const SECCFG_NAME: &str = "seccfg";

#[derive(Debug, Clone)]
pub enum ProgressEvent {
    Stage { stage: String, message: String },
    Log { level: String, message: String },
}

pub type ProgressFn = dyn Fn(ProgressEvent) + Send + Sync;

#[derive(Debug, Serialize)]
pub struct UnlockPlan {
    pub seccfg: SeccfgPlan,
    pub lk_a: LkPlan,
    pub lk_b: LkPlan,
    pub steps: Vec<String>,
    pub warnings: Vec<String>,
    pub proceed: bool,
    pub why_not: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SeccfgPlan {
    pub present: bool,
    pub state: Option<u32>,
    pub state_label: String,
    pub valid: bool,
    pub needs_write: bool,
}

#[derive(Debug, Serialize)]
pub struct LkPlan {
    pub present: bool,
    pub identity: String,
    pub variant: Option<String>,
    pub site_offset: Option<String>,
    pub needs_patch: bool,
    pub already_patched: bool,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct UnlockReport {
    pub plan: UnlockPlan,
    pub backups: Vec<String>,
    pub writes: Vec<String>,
    pub readback_ok: bool,
    pub notes: Vec<String>,
}

fn lk_plan(data: &[u8]) -> LkPlan {
    let sha = lk::sha256(data);
    match lk::identify(data) {
        LkIdentity::Original(v) => {
            let r = lk::recipe(v);
            LkPlan {
                present: true,
                identity: "original".into(),
                variant: Some(v.label().into()),
                site_offset: Some(format!("0x{:x}", r.site_offset)),
                needs_patch: true,
                already_patched: false,
                sha256: sha,
            }
        }
        LkIdentity::Patched(v) => LkPlan {
            present: true,
            identity: "patched".into(),
            variant: Some(v.label().into()),
            site_offset: None,
            needs_patch: false,
            already_patched: true,
            sha256: sha,
        },
        LkIdentity::Unknown => LkPlan {
            present: true,
            identity: "unknown".into(),
            variant: None,
            site_offset: None,
            needs_patch: false,
            already_patched: false,
            sha256: sha,
        },
    }
}

fn read_opt(
    session: &RootSession,
    name: &str,
    max_mb: u64,
) -> Result<Option<(String, Vec<u8>)>, String> {
    match partition::resolve_by_name(session, name) {
        Ok(path) => {
            let data = partition::read_partition(session, &path, max_mb)?;
            Ok(Some((path, data)))
        }
        Err(_) => Ok(None),
    }
}

/// Read-only analysis. Never writes. Returns a plan describing exactly what an
/// unlock would do.
pub fn plan(
    session: &RootSession,
    _outdir: &Path,
    progress: &ProgressFn,
) -> Result<UnlockPlan, String> {
    progress(ProgressEvent::Stage {
        stage: "analyze".into(),
        message: "Reading seccfg and LK slots (read-only)".into(),
    });

    let seccfg = read_opt(session, SECCFG_NAME, 8)?;
    let seccfg_plan = match seccfg {
        None => SeccfgPlan {
            present: false,
            state: None,
            state_label: "missing".into(),
            valid: false,
            needs_write: false,
        },
        Some((_, data)) => match seccfg::parse(&data) {
            Ok(info) => SeccfgPlan {
                present: true,
                state: Some(info.state),
                state_label: info.state_label.clone(),
                valid: info.valid,
                needs_write: info.state == seccfg::STATE_LOCKED && info.valid,
            },
            Err(e) => SeccfgPlan {
                present: true,
                state: None,
                state_label: format!("parse error: {e}"),
                valid: false,
                needs_write: false,
            },
        },
    };

    let (lk_a, lk_b) = match (read_opt(session, LK_A_NAME, 4)?, read_opt(session, LK_B_NAME, 4)?) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            return Err(
                "could not locate both lk_a and lk_b partitions; cannot plan unlock".to_string(),
            );
        }
    };
    let lk_a_plan = lk_plan(&lk_a.1);
    let lk_b_plan = lk_plan(&lk_b.1);

    let mut steps = Vec::new();
    let mut warnings = Vec::new();
    let mut why_not = Vec::new();

    if seccfg_plan.present {
        if !seccfg_plan.valid {
            why_not.push("seccfg header is invalid; not writing it".into());
        } else if seccfg_plan.needs_write {
            steps.push(
                "write seccfg state 0x01 -> 0x03 (state word only; authenticated hash region \
                 preserved)"
                    .into(),
            );
            warnings.push(
                "seccfg is V4: the trailing device-authenticated hash is NOT regenerated by this \
                 tool. On 7.1 the proven write used the MTK DA hardware hash. If the bootloader \
                 validates that region, this write will be ignored — the LK patch is the \
                 effective unlock."
                    .into(),
            );
        } else {
            steps.push("seccfg already 0x03 (unlocked) — no write needed".into());
        }
    } else {
        why_not.push("seccfg partition not found".into());
    }

    for (name, plan) in [("lk_a", &lk_a_plan), ("lk_b", &lk_b_plan)] {
        match plan.identity.as_str() {
            "original" => {
                steps.push(format!(
                    "patch {name} at {} (fb unlockstate)", plan.variant.clone().unwrap_or_default()
                ));
            }
            "patched" => {
                steps.push(format!("{name} already patched — no write needed"));
            }
            _ => why_not.push(format!("{name} is an unknown build; cannot patch safely")),
        }
    }

    if lk_a_plan.identity == "unknown" || lk_b_plan.identity == "unknown" {
        why_not.push(
            "LK firmware build not recognized (no known patch signature). Add a fingerprint for \
             this build before unlocking."
                .into(),
        );
    }
    if !lk_a_plan.present || !lk_b_plan.present {
        why_not.push("LK slots missing".into());
    }

    let proceed = why_not.is_empty();
    Ok(UnlockPlan {
        seccfg: seccfg_plan,
        lk_a: lk_a_plan,
        lk_b: lk_b_plan,
        steps,
        warnings,
        proceed,
        why_not,
    })
}

fn save(outdir: &Path, name: &str, data: &[u8]) -> Result<String, String> {
    std::fs::create_dir_all(outdir).map_err(|e| format!("cannot create outdir: {e}"))?;
    let path = outdir.join(name);
    std::fs::write(&path, data).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path.display().to_string())
}

/// Execute the unlock. Re-validates everything immediately before each write.
pub fn execute(
    session: &RootSession,
    outdir: &Path,
    progress: &ProgressFn,
) -> Result<UnlockReport, String> {
    let p = plan(session, outdir, progress)?;
    if !p.proceed {
        return Err(format!(
            "unlock plan cannot proceed: {}",
            p.why_not.join("; ")
        ));
    }

    let mut backups = Vec::new();
    let mut writes = Vec::new();
    let mut notes = Vec::new();

    // --- seccfg ---
    let (seccfg_path, seccfg_data) = read_opt(session, SECCFG_NAME, 8)?
        .ok_or("seccfg disappeared during unlock")?;
    backups.push(save(outdir, "seccfg-original.bin", &seccfg_data)?);
    if p.seccfg.needs_write {
        progress(ProgressEvent::Stage {
            stage: "write-seccfg".into(),
            message: "Writing seccfg state 0x01 -> 0x03".into(),
        });
        match seccfg::patch_unlock(&seccfg_data)? {
            SeccfgPatch::Patched(patched) => {
                partition::write_bytes(session, &seccfg_path, &patched)?;
                writes.push("seccfg".into());
                let ok = partition::verify_readback(
                    session,
                    &seccfg_path,
                    &lk::sha256(&patched),
                    2048,
                )?;
                if !ok {
                    return Err("seccfg readback mismatch after write — restore backups".into());
                }
                notes.push("seccfg write verified by readback".into());
            }
            SeccfgPatch::AlreadyUnlocked => {}
        }
    }

    // --- LK slots ---
    for (name, slot) in [("lk_a", LK_A_NAME), ("lk_b", LK_B_NAME)] {
        let (path, data) = read_opt(session, slot, 4)?.ok_or("LK slot disappeared")?;
        backups.push(save(outdir, &format!("{name}-original.bin"), &data)?);

        let plan = lk_plan(&data);
        if plan.already_patched {
            continue;
        }
        if plan.identity != "original" {
            return Err(format!("{name} not patchable: {}", plan.identity));
        }
        let variant = match plan.variant.as_deref() {
            Some(v) if v.starts_with("MagicOS 7.1") => FpVariant::Magicos71,
            Some(v) if v.starts_with("MagicOS 9") => FpVariant::Magicos9,
            _ => return Err(format!("{name}: unsupported variant")),
        };

        progress(ProgressEvent::Stage {
            stage: format!("write-{name}"),
            message: format!("Patching and writing {name} (fb unlockstate)"),
        });

        let PatchOutcome {
            data: patched,
            sha256_after,
            ..
        } = lk::patch(&data, variant)?;

        partition::write_bytes(session, &path, &patched)?;
        writes.push(name.into());
        let ok = partition::verify_readback(session, &path, &sha256_after, 1024)?;
        if !ok {
            return Err(format!("{name} readback mismatch after write — restore backups"));
        }
        notes.push(format!("{name} write verified by readback ({sha256_after})"));
    }

    Ok(UnlockReport {
        plan: p,
        backups,
        writes,
        readback_ok: true,
        notes,
    })
}
