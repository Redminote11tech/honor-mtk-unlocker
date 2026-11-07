//! Thin wrapper around the platform `adb` binary.
//!
//! The binary is resolved from the `ADB` environment variable first, then the
//! `PATH`. Everything is process-spawned, so the host never needs anything but
//! a stock adb from platform-tools.

use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct Adb {
    pub bin: PathBuf,
}

pub fn default_adb_bin() -> PathBuf {
    if let Ok(v) = std::env::var("ADB") {
        if !v.trim().is_empty() {
            return PathBuf::from(v);
        }
    }
    PathBuf::from("adb")
}

impl Adb {
    pub fn new(bin: PathBuf) -> Self {
        Adb { bin }
    }

    pub fn default() -> Self {
        Adb::new(default_adb_bin())
    }

    fn run(&self, args: &[&str]) -> Result<String, String> {
        #[cfg(debug_assertions)]
        if let Some(a1) = args.get(1) {
            if a1.len() > 90_000 {
                eprintln!("[adb-size] cmd len {}", a1.len());
            }
        }
        let out = Command::new(&self.bin)
            .args(args)
            .output()
            .map_err(|e| format!("failed to run {}: {}", self.bin.display(), e))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            return Err(format!(
                "adb {:?} failed ({}): {} {}",
                args,
                out.status,
                stderr,
                stdout
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }
    /// Debug helper (examples only).
    pub fn run_devices_debug(&self) -> Result<String, String> {
        self.run(&["devices"])
    }

    fn run_bytes(&self, args: &[&str]) -> Result<Vec<u8>, String> {
        let out = Command::new(&self.bin)
            .args(args)
            .output()
            .map_err(|e| format!("failed to run {}: {}", self.bin.display(), e))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(format!("adb {:?} failed ({}): {}", args, out.status, stderr));
        }
        Ok(out.stdout)
    }

    /// Serial of the single connected device, if exactly one is present.
    pub fn single_device(&self) -> Result<String, String> {
        let out = self.run(&["devices"])?;
        let mut serials = Vec::new();
        for line in out.lines().skip(1) {
            let mut it = line.split_whitespace();
            if let (Some(s), Some(state)) = (it.next(), it.next()) {
                if state == "device" {
                    serials.push(s.to_string());
                }
            }
        }
        match serials.len() {
            1 => Ok(serials.remove(0)),
            0 => Err("no device in adb mode; plug in and enable USB debugging".to_string()),
            n => Err(format!("multiple devices connected ({n}); connect exactly one")),
        }
    }

    pub fn shell(&self, cmd: &str) -> Result<String, String> {
        let out = self.run(&["shell", cmd])?;
        Ok(out.replace("\r\n", "\n"))
    }

    pub fn shell_bytes(&self, cmd: &str) -> Result<Vec<u8>, String> {
        self.run_bytes(&["shell", cmd])
    }

    pub fn getprop(&self, key: &str) -> Result<String, String> {
        Ok(self.shell(&format!("getprop {key}"))?.trim().to_string())
    }

    pub fn setprop(&self, key: &str, val: &str) -> Result<(), String> {
        self.shell(&format!("setprop {key} {val}"))?;
        Ok(())
    }

    pub fn is_package_installed(&self, pkg: &str) -> Result<bool, String> {
        let out = self.shell(&format!("pm list packages {pkg}"))?;
        Ok(out.contains(&format!("package:{pkg}")))
    }

    pub fn install_apk(&self, apk_path: &str) -> Result<(), String> {
        self.run(&["install", "-r", apk_path])?;
        Ok(())
    }

    /// Resolve the launcher activity for a package, e.g. `com.example/.Main`.
    pub fn resolve_launcher(&self, pkg: &str) -> Result<String, String> {
        let out = self.shell(&format!(
            "cmd package resolve-activity --brief -c android.intent.category.LAUNCHER {pkg}"
        ))?;
        let last = out.lines().filter(|l| l.contains('/')).last();
        match last {
            Some(l) if l.contains(pkg) => Ok(l.trim().to_string()),
            _ => Err(format!("could not resolve DFRoot launcher for {pkg}")),
        }
    }

    pub fn start_launcher(&self, component: &str) -> Result<(), String> {
        self.shell(&format!(
            "am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -n {component}"
        ))?;
        Ok(())
    }
}
