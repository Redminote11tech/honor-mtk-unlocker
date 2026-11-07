//! End-to-end test against a fake adb device: check -> root -> partitions ->
//! read-partition -> unlock-plan -> unlock (writes + readback). Uses real
//! firmware dumps as the device partition contents.

use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const FAKE_ADB: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/fake_adb.sh"
);

fn unique_tmp() -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("honor-e2e-{ts}"))
}

fn run(
    bin: &str,
    args: &[&str],
    sb: &Path,
    cmd_file: &Path,
    out_file: &Path,
) -> (bool, String, String) {
    let out = Command::new(bin)
        .args(args)
        .env("ADB", FAKE_ADB)
        .env("FAKE_SANDBOX", sb)
        .env("HONOR_BYNAME_DIR", sb.join("dev/block/by-name"))
        .env("HONOR_CMD_FILE", cmd_file)
        .env("HONOR_OUT_FILE", out_file)
        .env(
            "PATH",
            format!(
                "{}:{}",
                sb.join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .expect("spawn honor_tool");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn fake_device_full_flow() {
    let sb = unique_tmp();
    let dev_by_name = sb.join("dev/block/by-name");
    std::fs::create_dir_all(&dev_by_name).unwrap();
    std::fs::create_dir_all(sb.join("data/local/tmp")).unwrap();
    std::fs::create_dir_all(sb.join("bin")).unwrap();

    // Fake root `id`.
    std::fs::write(sb.join("bin/id"), "#!/usr/bin/env bash\necho uid=0(root)\n").unwrap();
    // Partition contents: real firmware dumps.
    std::fs::copy(
        format!("{FIXTURES}/lk_71_a_original.bin"),
        dev_by_name.join("lk_a"),
    )
    .unwrap();
    std::fs::copy(
        format!("{FIXTURES}/lk_71_a_original.bin"),
        dev_by_name.join("lk_b"),
    )
    .unwrap();
    std::fs::copy(
        format!("{FIXTURES}/seccfg_locked.bin"),
        dev_by_name.join("seccfg"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(sb.join("bin/id"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(FAKE_ADB, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let cmd_file = sb.join("data/local/tmp/cmd");
    let out_file = sb.join("data/local/tmp/out");
    let outdir = sb.join("out");
    let bin = env!("CARGO_BIN_EXE_honor_mtk_unlocker");


    // 1. check
    let (ok, out, _) = run(bin, &["check"], &sb, &cmd_file, &out_file);
    assert!(ok, "check failed:\n{out}");
    assert!(out.contains("CRT-NX1"), "model missing:\n{out}");
    assert!(out.contains("(supported)"), "support missing:\n{out}");

    // 2. root
    let (ok, out, _) = run(bin, &["root", "DFRoot.apk"], &sb, &cmd_file, &out_file);
    assert!(ok, "root failed:\n{out}");
    assert!(out.contains("ROOT OK"), "root not confirmed:\n{out}");

    // 3. partitions
    let (ok, out, _) = run(
        bin,
        &["partitions", "--apk", "DFRoot.apk"],
        &sb,
        &cmd_file,
        &out_file,
    );
    assert!(ok, "partitions failed:\n{out}");

    // 3b. check still passes for a supported model with an MTK platform.
    let (ok2, out2, _) = run(bin, &["check"], &sb, &cmd_file, &out_file);
    assert!(ok2, "check failed on mtk device:\n{out2}");
    assert!(out2.contains("(supported)"), "expected supported marker:\n{out2}");
    assert!(out.contains("lk_a"), "lk_a missing:\n{out}");
    assert!(out.contains("seccfg"), "seccfg missing:\n{out}");

    // 4. read-partition (LK) — parse + save
    let (ok, out, _) = run(
        bin,
        &[
            "read-partition",
            "--name",
            "lk_a",
            "--out",
            outdir.to_str().unwrap(),
            "--apk",
            "DFRoot.apk",
        ],
        &sb,
        &cmd_file,
        &out_file,
    );
    assert!(ok, "read-partition failed:\n{out}");
    assert!(out.contains("sha256:"), "no hash:\n{out}");
    assert!(out.contains("Original(Magicos71)"), "identity not parsed:\n{out}");

    // 5. unlock-plan — must proceed
    let (ok, out, err) = run(
        bin,
        &[
            "unlock-plan",
            "--out",
            outdir.to_str().unwrap(),
            "--apk",
            "DFRoot.apk",
        ],
        &sb,
        &cmd_file,
        &out_file,
    );
    assert!(ok, "unlock-plan failed:\n{out}\n{err}");
    assert!(out.contains("\"proceed\": true"), "plan not proceeded:\n{out}\n{err}");

    // 6. unlock — actually writes; then verify sandbox contents.
    let (ok, out, err) = run(
        bin,
        &[
            "unlock",
            "--out",
            outdir.to_str().unwrap(),
            "--danger-do-it",
            "--apk",
            "DFRoot.apk",
        ],
        &sb,
        &cmd_file,
        &out_file,
    );
    assert!(ok, "unlock failed:\n{out}\n{err}");
    assert!(out.contains("\"readback_ok\": true"), "readback not ok:\n{out}\n{err}");

    // lk_a / lk_b now equal the proven patched image.
    let expected = std::fs::read(format!("{FIXTURES}/lk_71_a_patched.bin")).unwrap();
    for name in ["lk_a", "lk_b"] {
        let got = std::fs::read(dev_by_name.join(name)).unwrap();
        assert_eq!(got, expected, "{name} not patched byte-identically");
    }
    // seccfg state word flipped to 0x03, auth region preserved.
    let seccfg = std::fs::read(dev_by_name.join("seccfg")).unwrap();
    assert_eq!(&seccfg[0x0c..0x10], &[0x03, 0x00, 0x00, 0x00]);
    let orig = std::fs::read(format!("{FIXTURES}/seccfg_locked.bin")).unwrap();
    let mut expect = orig.clone();
    expect[0x0c..0x10].copy_from_slice(&[0x03, 0x00, 0x00, 0x00]);
    assert_eq!(seccfg, expect, "seccfg must differ only in the state word");

    // Backups exist.
    for b in ["lk_a-original.bin", "lk_b-original.bin", "seccfg-original.bin"] {
        assert!(outdir.join(b).exists(), "backup {b} missing");
    }

    let _ = std::fs::remove_dir_all(&sb);
}
