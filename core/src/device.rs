//! Device identification and the DFRoot temproot session (the Rust mirror of
//! `shareable-root/root.sh`).
//!
//! The DFRoot exploit cannot be triggered from a shell: the user must tap
//! "LAUNCH ROOT" in the app. Everything else on the host side is automated:
//! clearing the `persist.log.tag` gate, installing the APK, launching the app,
//! then waiting for the uid-0 command channel at
//! `/data/local/tmp/cmd` <-> `/data/local/tmp/out`.

use crate::adb::Adb;
use crate::model::DeviceInfo;
use std::thread;
use std::time::Duration;

pub const DFROOT_PKG: &str = "df.root";
pub const CMD_FILE: &str = "/data/local/tmp/cmd";
pub const OUT_FILE: &str = "/data/local/tmp/out";
pub const MAX_READY_WAIT_S: u64 = 300;

#[derive(Debug)]
pub struct RootSession {
    pub adb: Adb,
    pub serial: String,
}


/// Overridable for hermetic tests (HONOR_CMD_FILE / HONOR_OUT_FILE).
pub fn cmd_file() -> String {
    std::env::var("HONOR_CMD_FILE").unwrap_or_else(|_| CMD_FILE.to_string())
}

pub fn out_file() -> String {
    std::env::var("HONOR_OUT_FILE").unwrap_or_else(|_| OUT_FILE.to_string())
}

/// Model check: Honor 90 Lite is CRT-NX1 / CRT-N31 / HNCRT-M2 (builds begin
/// with CRT-N).
pub fn is_honor90_lite(model: &str) -> bool {
    let m = model.to_ascii_uppercase();
    m.starts_with("CRT-N") || m.starts_with("HNCRT-M") || m.contains("90 LITE")
}

pub fn collect_device_info(adb: &Adb, serial: &str) -> Result<DeviceInfo, String> {
    let prop = |k: &str| adb.getprop(k).unwrap_or_default();
    let model = prop("ro.product.model");
    let product = prop("ro.product.device");
    let sdk = prop("ro.build.version.sdk");
    let abi = prop("ro.product.cpu.abi");
    let slot = prop("ro.boot.slot_suffix");
    Ok(DeviceInfo {
        serial: serial.to_string(),
        model: model.clone(),
        product,
        sdk,
        abi,
        slot: slot.trim_start_matches('_').to_string(),
        flash_locked: Some(prop("ro.boot.flash.locked")),
        verified_boot_state: Some(prop("ro.boot.verifiedbootstate")),
        supported: is_honor90_lite(&model),
        bootloader_unlocked: None,
        root_present: false,
    })
}
/// Prepare the DFRoot channel: clear the gate, install the APK if missing,
/// launch the app. Does not wait for root.
pub fn prepare_dfroot(adb: &Adb, serial: &str, apk_path: &str) -> Result<RootSession, String> {
    let s = RootSession {
        adb: adb.clone(),
        serial: serial.to_string(),
    };

    // 1. clear the DFRoot gate; it refuses when persist.log.tag starts with 'S'.
    s.adb.setprop("persist.log.tag", "V").map_err(|e| {
        format!("could not set persist.log.tag (DFRoot gate): {e}")
    })?;
    let tag = s.adb.getprop("persist.log.tag")?;
    if tag.trim().to_ascii_uppercase().starts_with('S') {
        return Err(format!(
            "persist.log.tag={tag}: DFRoot will refuse; set it to a non-S value"
        ));
    }

    // 2. install DFRoot if missing.
    if !s.adb.is_package_installed(DFROOT_PKG)? {
        s.adb.install_apk(apk_path)?;
    }

    // 3. launch the app (user must tap LAUNCH ROOT).
    let launcher = s.adb.resolve_launcher(DFROOT_PKG)?;
    s.adb.start_launcher(&launcher)?;
    s.adb.shell(&format!("rm -f {} {}", out_file(), cmd_file()))?;
    Ok(s)
}

/// Wait until the DFRoot channel answers with uid=0(root).
pub fn wait_for_root(session: &RootSession, deadline_secs: u64) -> Result<(), String> {
    let probe = format!("root_ready_{}", rand_suffix());
    let cmdline = format!("id; echo {probe}");
    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        cmdline.as_bytes(),
    );
    session
        .adb
        .shell(&format!("echo {b64} | base64 -d > {}", cmd_file()))?;

    let mut last_out = String::new();
    for _ in 0..deadline_secs {
        let ls = session
            .adb
            .shell(&format!("ls {} 2>/dev/null", out_file()))
            .unwrap_or_default();
        if ls.trim() == out_file() {
            let out = session.adb.shell(&format!("cat {}", out_file())).unwrap_or_default();
            last_out = out.clone();
            if out.contains("uid=0(root)") {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err(format!(
        "root channel never reached uid=0. Did you tap 'LAUNCH ROOT' in DFRoot? \
         last reply: {}",
        last_out.trim()
    ))
}

impl RootSession {
    /// Bring up the DFRoot channel. Returns once `uid=0(root)` is confirmed.
    pub fn bring_up(adb: Adb, serial: String, apk_path: &str) -> Result<RootSession, String> {
        let s = prepare_dfroot(&adb, &serial, apk_path)?;
        wait_for_root(&s, MAX_READY_WAIT_S)?;
        Ok(s)
    }

    /// Run a single command through the root channel and return its stdout.
    pub fn exec(&self, cmd: &str) -> Result<String, String> {
        self.adb.shell(&format!("rm -f {}", out_file()))?;
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            cmd.as_bytes(),
        );
        self.adb
            .shell(&format!("echo {b64} | base64 -d > {}", cmd_file()))?;
        for _ in 0..60 {
            let ls = self
                .adb
                .shell(&format!("ls {} 2>/dev/null", out_file()))
                .unwrap_or_default();
            if ls.trim() == out_file() {
                let out = self.adb.shell(&format!("cat {}", out_file()))?;
                return Ok(out.replace("\r\n", "\n").trim_end().to_string());
            }
            thread::sleep(Duration::from_secs(1));
        }
        Err("timed out waiting for root channel output".to_string())
    }

    pub fn is_root(&self) -> bool {
        self.exec("id").map(|o| o.contains("uid=0(root)")).unwrap_or(false)
    }
}

fn rand_suffix() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    n % 1_000_000
}
