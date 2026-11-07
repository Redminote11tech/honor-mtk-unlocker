//! Newline-delimited JSON protocol between the Flutter UI and the Rust core.
//!
//! Requests (UI -> core):
//! ```json
//! {"id":1,"cmd":"check","args":{}}
//! ```
//! Responses (core -> UI):
//! ```json
//! {"id":1,"ok":true,"result":{...}}
//! {"id":1,"ok":false,"error":"..."}
//! ```
//! Async events (core -> UI):
//! ```json
//! {"event":"log","level":"info","message":"..."}
//! {"event":"progress","stage":"...","message":"..."}
//! ```

use crate::adb::Adb;
use crate::device::{collect_device_info, RootSession};
use crate::lk;
use crate::partition;
use crate::seccfg;
use crate::unlock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::json;
use std::io::{BufRead, Write};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Request {
    id: u64,
    cmd: String,
    #[serde(default)]
    args: Value,
}

fn make_response(id: u64, ok: bool, result: Option<Value>, error: Option<String>) -> Value {
    let mut v = serde_json::Map::new();
    v.insert("id".into(), Value::from(id));
    v.insert("ok".into(), Value::from(ok));
    if let Some(r) = result {
        v.insert("result".into(), r);
    }
    if let Some(e) = error {
        v.insert("error".into(), Value::from(e));
    }
    Value::Object(v)
}

struct Server {
    adb: Adb,
    session: Option<RootSession>,
    outdir: PathBuf,
}

#[derive(Serialize)]
struct DumpFileEntry {
    name: String,
    size: usize,
    sha256: String,
    saved_as: String,
}

#[derive(Serialize)]
struct SupportManifest {
    app_version: String,
    created_at: String,
    device: serde_json::Value,
    root_status: String,
    files: Vec<DumpFileEntry>,
    failures: Vec<serde_json::Value>,
    notes: Vec<String>,
}

fn arg_string(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn arg_u64(args: &Value, key: &str) -> Option<u64> {
    args.get(key).and_then(|v| v.as_u64())
}

fn now_iso8601() -> String {
    // Simple UTC timestamp; avoids pulling chrono for one string.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs} (unix seconds)")
}

impl Server {
    fn handle(&mut self, req: &Request) -> Value {
        let id = req.id;
        match req.cmd.as_str() {
            "ping" => make_response(
                id,
                true,
                Some(json!({"pong": true, "version": env!("CARGO_PKG_VERSION")})),
                None,
            ),
            "check" => self.cmd_check(id),
            "root" => self.cmd_root(id, arg_string(&req.args, "apk").unwrap_or_default()),
            "root_prepare" => {
                self.cmd_root_prepare(id, arg_string(&req.args, "apk").unwrap_or_default())
            }
            "root_wait" => self.cmd_root_wait(id),
            "root_status" => self.cmd_root_status(id),
            "ensure_outdir" => self.cmd_ensure_outdir(id),
            "partitions" => self.cmd_partitions(id),
            "read_partition" => {
                let name = arg_string(&req.args, "name");
                let path = arg_string(&req.args, "path");
                let out = arg_string(&req.args, "out")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.outdir.clone());
                let mb = arg_u64(&req.args, "max_mb").unwrap_or(64);
                self.cmd_read_partition(id, name, path, out, mb)
            }
            "dump_support" => {
                let root_error = arg_string(&req.args, "root_error").unwrap_or_default();
                self.cmd_dump_support(id, root_error)
            }
            "unlock_plan" => self.cmd_unlock_plan(id),
            "unlock_execute" => {
                let out = arg_string(&req.args, "out")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.outdir.clone());
                self.cmd_unlock_execute(id, out)
            }
            _ => make_response(
                id,
                false,
                None,
                Some(format!("unknown command {:?}", req.cmd)),
            ),
        }
    }

    fn session(&self) -> Result<&RootSession, String> {
        self.session
            .as_ref()
            .ok_or_else(|| "not rooted yet; run 'root' first".to_string())
    }

    fn cmd_check(&self, id: u64) -> Value {
        match self.adb.single_device() {
            Ok(serial) => match collect_device_info(&self.adb, &serial) {
                Ok(mut info) => {
                    info.bootloader_unlocked =
                        info.flash_locked.as_deref().map(|v| v.trim() == "0");
                    info.root_present = match &self.session {
                        Some(s) => s.is_root(),
                        None => self
                            .adb
                            .shell("id")
                            .map(|o| o.contains("uid=0(root)"))
                            .unwrap_or(false),
                    };
                    make_response(id, true, Some(serde_json::to_value(&info).unwrap()), None)
                }
                Err(e) => make_response(id, false, None, Some(e)),
            },
            Err(e) => make_response(id, false, None, Some(e)),
        }
    }

    fn cmd_ensure_outdir(&self, id: u64) -> Value {
        let existed = self.outdir.exists();
        match std::fs::create_dir_all(&self.outdir) {
            Ok(_) => make_response(
                id,
                true,
                Some(json!({
                    "path": self.outdir.display().to_string(),
                    "created": !existed,
                })),
                None,
            ),
            Err(e) => make_response(id, false, None, Some(format!("cannot create outdir: {e}"))),
        }
    }

    fn cmd_root_prepare(&mut self, id: u64, apk: String) -> Value {
        if apk.is_empty() {
            return make_response(id, false, None, Some("apk arg required".into()));
        }
        match self.adb.single_device() {
            Ok(serial) => match crate::device::prepare_dfroot(&self.adb, &serial, &apk) {
                Ok(session) => {
                    self.session = Some(session);
                    make_response(id, true, Some(json!({"prepared": true})), None)
                }
                Err(e) => make_response(id, false, None, Some(e)),
            },
            Err(e) => make_response(id, false, None, Some(e)),
        }
    }

    fn cmd_root_wait(&self, id: u64) -> Value {
        let session = match self.session() {
            Ok(s) => s,
            Err(e) => return make_response(id, false, None, Some(e)),
        };
        match crate::device::wait_for_root(session, 120) {
            Ok(_) => make_response(id, true, Some(json!({"root": true})), None),
            Err(e) => make_response(id, false, None, Some(e)),
        }
    }

    fn cmd_root_status(&self, id: u64) -> Value {
        let root = match &self.session {
            Some(s) => s.is_root(),
            None => false,
        };
        make_response(id, true, Some(json!({"root": root})), None)
    }

    fn cmd_root(&mut self, id: u64, apk: String) -> Value {
        if apk.is_empty() {
            return make_response(id, false, None, Some("apk arg required".into()));
        }
        match self.adb.single_device() {
            Ok(serial) => match RootSession::bring_up(self.adb.clone(), serial, &apk) {
                Ok(session) => {
                    self.session = Some(session);
                    make_response(id, true, Some(json!({"root": true})), None)
                }
                Err(e) => make_response(id, false, None, Some(e)),
            },
            Err(e) => make_response(id, false, None, Some(e)),
        }
    }

    fn cmd_partitions(&self, id: u64) -> Value {
        match self.session().and_then(|s| partition::discover(s)) {
            Ok(parts) => {
                let v = serde_json::to_value(&parts).unwrap();
                make_response(id, true, Some(json!({"partitions": v})), None)
            }
            Err(e) => make_response(id, false, None, Some(e)),
        }
    }

    fn cmd_read_partition(
        &self,
        id: u64,
        name: Option<String>,
        path: Option<String>,
        out: PathBuf,
        max_mb: u64,
    ) -> Value {
        let session = match self.session() {
            Ok(s) => s,
            Err(e) => return make_response(id, false, None, Some(e)),
        };
        let block_path = match (name.clone(), path.clone()) {
            (Some(n), _) => match partition::resolve_by_name(session, &n) {
                Ok(p) => p,
                Err(e) => return make_response(id, false, None, Some(e)),
            },
            (None, Some(p)) => p,
            (None, None) => {
                return make_response(
                    id,
                    false,
                    None,
                    Some("give 'name' or 'path'".into()),
                );
            }
        };
        let data = match partition::read_partition(session, &block_path, max_mb) {
            Ok(d) => d,
            Err(e) => return make_response(id, false, None, Some(e)),
        };
        let sha = lk::sha256(&data);

        // Save host-side copy; never expose raw bytes over the protocol.
        let fname = name.clone().unwrap_or_else(|| {
            block_path.rsplit('/').next().unwrap_or("partition").to_string()
        });
        let saved = match std::fs::create_dir_all(&out)
            .and_then(|_| std::fs::write(out.join(format!("{fname}.bin")), &data))
        {
            Ok(_) => out.join(format!("{fname}.bin")).display().to_string(),
            Err(e) => {
                return make_response(id, false, None, Some(format!("save failed: {e}")));
            }
        };

        let mut parsed = serde_json::Map::new();
        let kind = if fname.starts_with("lk") {
            "lk"
        } else if fname.contains("seccfg") {
            "seccfg"
        } else {
            "raw"
        };
        match kind {
            "lk" => match lk::parse_header(&data) {
                Ok(h) => {
                    parsed.insert("container".into(), json!({"blob_len": h.blob_len, "id": h.id}));
                    parsed.insert(
                        "identity".into(),
                        serde_json::to_value(format!("{:?}", lk::identify(&data))).unwrap(),
                    );
                }
                Err(e) => {
                    parsed.insert("error".into(), json!(e));
                }
            },
            "seccfg" => match seccfg::parse(&data) {
                Ok(i) => {
                    parsed.insert(
                        "seccfg".into(),
                        serde_json::to_value(&i).unwrap(),
                    );
                }
                Err(e) => {
                    parsed.insert("error".into(), json!(e));
                }
            },
            _ => {}
        }

        make_response(
            id,
            true,
            Some(json!({
                "name": name,
                "path": block_path,
                "bytes": data.len(),
                "sha256": sha,
                "saved_as": saved,
                "parsed": Value::Object(parsed),
            })),
            None,
        )
    }

    /// Read-only support dump for unsupported devices: seccfg, LK slots and
    /// preloader, plus a manifest with device facts. Used to file a GitHub
    /// support issue. Never writes to the device.
    fn cmd_dump_support(&self, id: u64, root_error: String) -> Value {
        let serial = match self.adb.single_device() {
            Ok(s) => s,
            Err(e) => return make_response(id, false, None, Some(e)),
        };
        let info = match collect_device_info(&self.adb, &serial) {
            Ok(i) => i,
            Err(e) => return make_response(id, false, None, Some(e)),
        };
        if !info.is_mtk {
            return make_response(
                id,
                false,
                None,
                Some("Snapdragon / non-MediaTek device detected; support dumps are only available for MTK devices".to_string()),
            );
        }

        let dir = self.outdir.join(format!("support-dump-{serial}"));
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return make_response(id, false, None, Some(format!("cannot create dump dir: {e}")));
        }

        let mut files: Vec<DumpFileEntry> = Vec::new();
        let mut failures: Vec<serde_json::Value> = Vec::new();
        let mut notes = Vec::new();

        let session = self.session.as_ref();
        if session.is_none() && root_error.is_empty() {
            notes.push("no temp root session; partitions were not readable".to_string());
        }
        if !root_error.is_empty() {
            notes.push(format!("temp root failed during this run: {root_error}"));
        }

        if let Some(sess) = session {
            let targets = [
                ("seccfg", 8u64),
                ("lk_a", 4u64),
                ("lk_b", 4u64),
                ("preloader", 8u64),
                ("efuse", 2u64), // present on some MTK builds; read-only
            ];
            for (name, mb) in targets {
                let block = if name == "preloader" {
                    crate::partition::resolve_preloader(sess)
                } else {
                    crate::partition::resolve_by_name(sess, name)
                };
                match block {
                    Ok(path) => match crate::partition::read_partition(sess, &path, mb) {
                        Ok(data) => {
                            let fname = format!("{name}.bin");
                            let dest = dir.join(&fname);
                            if let Err(e) = std::fs::write(&dest, &data) {
                                failures.push(json!({"name": name, "error":
                                    format!("save failed: {e}")}));
                                continue;
                            }
                            files.push(DumpFileEntry {
                                name: name.to_string(),
                                size: data.len(),
                                sha256: lk::sha256(&data),
                                saved_as: dest.display().to_string(),
                            });
                        }
                        Err(e) => failures.push(json!({"name": name, "error": e})),
                    },
                    Err(e) => failures.push(json!({"name": name, "error": e})),
                }
            }
        }

        let manifest = SupportManifest {
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: now_iso8601(),
            device: serde_json::to_value(&info).unwrap(),
            root_status: if root_error.is_empty() {
                if session.is_some() { "rooted".to_string() } else { "not_attempted".to_string() }
            } else {
                format!("failed: {root_error}")
            },
            files,
            failures,
            notes,
        };

        let manifest_path = dir.join("manifest.json");
        if let Err(e) = std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap()) {
            return make_response(id, false, None, Some(format!("cannot write manifest: {e}")));
        }

        make_response(
            id,
            true,
            Some(json!({
                "serial": serial,
                "model": info.model,
                "dir": dir.display().to_string(),
                "manifest": manifest_path.display().to_string(),
                "files": serde_json::to_value(&manifest.files).unwrap(),
                "failures": serde_json::to_value(&manifest.failures).unwrap(),
                "notes": serde_json::to_value(&manifest.notes).unwrap(),
                "root_status": manifest.root_status,
            })),
            None,
        )
    }

    fn cmd_unlock_plan(&self, id: u64) -> Value {
        let session = match self.session() {
            Ok(s) => s,
            Err(e) => return make_response(id, false, None, Some(e)),
        };
        let noop = |_e: unlock::ProgressEvent| {};
        match unlock::plan(session, &self.outdir, &noop) {
            Ok(plan) => make_response(id, true, Some(serde_json::to_value(&plan).unwrap()), None),
            Err(e) => make_response(id, false, None, Some(e)),
        }
    }

    fn cmd_unlock_execute(&self, id: u64, out: PathBuf) -> Value {
        let session = match self.session() {
            Ok(s) => s,
            Err(e) => return make_response(id, false, None, Some(e)),
        };
        let noop = |_e: unlock::ProgressEvent| {};
        match unlock::execute(session, &out, &noop) {
            Ok(report) => {
                make_response(id, true, Some(serde_json::to_value(&report).unwrap()), None)
            }
            Err(e) => make_response(id, false, None, Some(e)),
        }
    }
}

/// Run the JSON server loop on stdin/stdout.
pub fn serve(outdir: PathBuf) -> Result<(), String> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut server = Server {
        adb: Adb::default(),
        session: None,
        outdir,
    };
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let resp = server.handle(&req);
        let s = serde_json::to_string(&resp).unwrap();
        if writeln!(stdout, "{s}").is_err() {
            break;
        }
        stdout.flush().ok();
    }
    Ok(())
}
