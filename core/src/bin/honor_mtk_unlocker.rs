//! Honor Tool CLI. Also the sidecar process for the Flutter UI (`serve`).

use honor_core::adb::Adb;
use honor_core::device::{collect_device_info, RootSession};
use honor_core::lk;
use honor_core::model::FpVariant;
use honor_core::partition;
use honor_core::seccfg;
use honor_core::unlock;
use std::path::PathBuf;

const USAGE: &str = "\
Honor MTK Unlocker core — Honor 90 Lite (CRT-NX1) bootloader unlock helper

USAGE:
  honor_mtk_unlocker <command> [options]

COMMANDS:
  check                        detect device, identify model, report props
  root <DFRoot.apk>            bring up DFRoot temproot channel
  partitions                   list block partitions (via root channel)
  read-partition --name lk_a | --path /dev/block/<x> [--out DIR] [--mb N]
                               read partition, save host copy, parse it
  unlock-plan [--out DIR]      analyze seccfg + LK, print what unlock would do
  unlock [--out DIR]           BACKUP + PATCH + WRITE + readback verify
  parse-lk <file>              parse an LK image, print container + identity
  patch-lk <file> [--variant auto|71|9] [--out OUT]
                               patch an LK image (default --out <file>.patched)
  parse-seccfg <file> [--patch-unlock] [--out OUT]
                               parse seccfg; optionally patch state to 0x03
  serve [--out DIR]            JSON-line server (used by the Flutter UI)
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        println!("{USAGE}");
        std::process::exit(2);
    }
    let cmd = args[0].as_str();
    let rest = &args[1..];
    let res = match cmd {
        "check" => cmd_check(),
        "root" => cmd_root(rest),
        "partitions" => cmd_partitions(rest),
        "read-partition" => cmd_read_partition(rest),
        "unlock-plan" => cmd_unlock_plan(rest),
        "unlock" => cmd_unlock(rest),
        "parse-lk" => cmd_parse_lk(rest),
        "patch-lk" => cmd_patch_lk(rest),
        "parse-seccfg" => cmd_parse_seccfg(rest),
        "serve" => cmd_serve(rest),
        _ => {
            println!("unknown command: {cmd}\n{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(e) = res {
        eprintln!("[!] {e}");
        std::process::exit(1);
    }
}

fn opt<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    let i = args.iter().position(|a| a == key)?;
    args.get(i + 1).map(|s| s.as_str())
}

fn outdir(args: &[String]) -> PathBuf {
    opt(args, "--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("honor-tool-output"))
}

/// Bring up a fresh DFRoot session for a device command. The APK path comes
/// from `--apk` if present, else `HONOR_DFROOT_APK`, else `DFRoot.apk` in
/// the current directory.
fn rooted(args: &[String]) -> Result<RootSession, String> {
    let adb = Adb::default();
    let serial = adb.single_device()?;
    let apk = opt(args, "--apk")
        .map(|s| s.to_string())
        .or_else(|| std::env::var("HONOR_DFROOT_APK").ok())
        .unwrap_or_else(|| "vendor/DFRoot.apk".to_string());
    eprintln!("[*] bringing up DFRoot (tap LAUNCH ROOT on the phone)…");
    RootSession::bring_up(adb, serial, &apk)
}

fn cmd_check() -> Result<(), String> {
    let adb = Adb::default();
    let serial = adb.single_device()?;
    let info = collect_device_info(&adb, &serial)?;
    println!("serial:      {}", info.serial);
    println!("model:       {} {}", info.model, if info.supported { "(supported)" } else { "(NOT a known Honor 90 Lite)" });
    println!("product:     {}", info.product);
    println!("sdk:        {}", info.sdk);
    println!("abi:         {}", info.abi);
    println!("slot:        {}", info.slot);
    println!("flash.locked: {}", info.flash_locked.unwrap_or_default());
    println!("verifiedbootstate: {}", info.verified_boot_state.unwrap_or_default());
    if !info.supported {
        return Err(format!("unsupported model {}", info.model));
    }
    Ok(())
}

fn cmd_root(args: &[String]) -> Result<(), String> {
    let apk = args.first().ok_or("usage: honor_tool root <DFRoot.apk>")?;
    let adb = Adb::default();
    let serial = adb.single_device()?;
    println!("[*] bringing up DFRoot (tap LAUNCH ROOT on the phone)…");
    let session = RootSession::bring_up(adb, serial, apk)?;
    println!("[+] ROOT OK — uid 0 on {}", session.serial);
    println!("    id => {}", session.exec("id")?);
    Ok(())
}

fn cmd_partitions(args: &[String]) -> Result<(), String> {
    let session = rooted(args)?;
    let parts = partition::discover(&session)?;
    for p in &parts {
        println!(
            "{:<12} {:<24} {}",
            p.name,
            p.block_path,
            if p.recognized { "(recognized)" } else { "" }
        );
    }
    println!("({} partitions)", parts.len());
    Ok(())
}

fn cmd_read_partition(args: &[String]) -> Result<(), String> {
    let session = rooted(args)?;
    let out = outdir(args);
    let name = opt(args, "--name");
    let path = opt(args, "--path");
    let mb = opt(args, "--mb").and_then(|s| s.parse().ok()).unwrap_or(64);

    let block_path = match (name, path) {
        (Some(n), _) => partition::resolve_by_name(&session, n)?,
        (None, Some(p)) => p.to_string(),
        _ => return Err("need --name or --path".into()),
    };
    let data = partition::read_partition(&session, &block_path, mb)?;
    let saved = out.join(format!(
        "{}.bin",
        name.unwrap_or("partition").replace('/', "_")
    ));
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    std::fs::write(&saved, &data).map_err(|e| e.to_string())?;

    println!("path:   {block_path}");
    println!("bytes:  {}", data.len());
    println!("sha256: {}", lk::sha256(&data));
    println!("saved:  {}", saved.display());

    if let Some(n) = name {
        if n.starts_with("lk") {
            if let Ok(h) = lk::parse_header(&data) {
                println!("container: id={} blob_len=0x{:x}", h.id, h.blob_len);
            }
            println!("identity: {:?}", lk::identify(&data));
        } else if n.contains("seccfg") {
            match seccfg::parse(&data) {
                Ok(i) => println!("seccfg: valid={} state={} ({})", i.valid, i.state, i.state_label),
                Err(e) => println!("seccfg parse: {e}"),
            }
        }
    }
    Ok(())
}

fn cmd_unlock_plan(args: &[String]) -> Result<(), String> {
    let session = rooted(args)?;
    let out = outdir(args);
    let plan = unlock::plan(&session, &out, &|e| match e {
        unlock::ProgressEvent::Stage { stage, message } => {
            eprintln!("[{}] {message}", stage)
        }
        unlock::ProgressEvent::Log { level, message } => eprintln!("[{level}] {message}"),
    })?;
    println!("{}", serde_json::to_string_pretty(&plan).unwrap());
    Ok(())
}

fn cmd_unlock(args: &[String]) -> Result<(), String> {
    let session = rooted(args)?;
    let out = outdir(args);
    if opt(args, "--danger-do-it").is_none() {
        return Err(
            "refusing: this writes partitions. Pass --danger-do-it to confirm the \
             OTA/relock warnings have been read."
                .into(),
        );
    }
    let report = unlock::execute(&session, &out, &|e| match e {
        unlock::ProgressEvent::Stage { stage, message } => eprintln!("[{}] {message}", stage),
        unlock::ProgressEvent::Log { level, message } => eprintln!("[{level}] {message}"),
    })?;
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    Ok(())
}

fn cmd_parse_lk(args: &[String]) -> Result<(), String> {
    let file = args.first().ok_or("usage: honor_tool parse-lk <file>")?;
    let data = std::fs::read(file).map_err(|e| e.to_string())?;
    let h = lk::parse_header(&data)?;
    println!("file:     {file}");
    println!("blob_len: 0x{:x} ({})", h.blob_len, h.blob_len);
    println!("id:       {}", h.id);
    println!("payload at 0x{:x}", h.payload_offset);
    println!("identity: {:?}", lk::identify(&data));
    println!("sha256:   {}", lk::sha256(&data));
    Ok(())
}

fn cmd_patch_lk(args: &[String]) -> Result<(), String> {
    let file = args.first().ok_or("usage: honor_tool patch-lk <file> [--variant auto|71|9] [--out OUT]")?;
    let data = std::fs::read(file).map_err(|e| e.to_string())?;
    let variant = opt(args, "--variant").unwrap_or("auto");
    let outcome = match variant {
        "auto" => lk::patch_auto(&data)?,
        "71" => lk::patch(&data, FpVariant::Magicos71)?,
        "9" => lk::patch(&data, FpVariant::Magicos9)?,
        _ => return Err("--variant must be auto|71|9".into()),
    };
    let out_path = opt(args, "--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{file}.patched")));
    std::fs::write(&out_path, &outcome.data).map_err(|e| e.to_string())?;
    println!("variant:   {:?}", outcome.variant);
    println!("site:      0x{:x}", outcome.site_offset);
    println!("before:    {}", hex::encode(outcome.before));
    println!("after:     {}", hex::encode(outcome.after));
    println!("already_patched: {}", outcome.already_patched);
    println!("sha256:    {}", outcome.sha256_after);
    println!("out:       {}", out_path.display());
    Ok(())
}

fn cmd_parse_seccfg(args: &[String]) -> Result<(), String> {
    let file = args.first().ok_or("usage: honor_tool parse-seccfg <file> [--patch-unlock] [--out OUT]")?;
    let data = std::fs::read(file).map_err(|e| e.to_string())?;
    let info = seccfg::parse(&data)?;
    println!("valid:     {}", info.valid);
    println!("state:     {} ({})", info.state, info.state_label);
    println!("header_len: 0x{:x}", info.header_len);
    println!("auth_magic: {}", info.auth_magic);

    if opt(args, "--patch-unlock").is_some() {
        match seccfg::patch_unlock(&data)? {
            seccfg::SeccfgPatch::AlreadyUnlocked => println!("already unlocked — nothing patched"),
            seccfg::SeccfgPatch::Patched(out) => {
                let out_path = opt(args, "--out")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(format!("{file}.unlocked")));
                std::fs::write(&out_path, &out).map_err(|e| e.to_string())?;
                println!(
                    "patched state -> 0x03; sha256 {}; out {}",
                    lk::sha256(&out),
                    out_path.display()
                );
                println!("NOTE: authenticated hash region preserved (not regenerated)");
            }
        }
    }
    Ok(())
}

fn cmd_serve(args: &[String]) -> Result<(), String> {
    let out = outdir(args);
    honor_core::proto::serve(out)
}
