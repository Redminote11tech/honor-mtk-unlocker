# Secure-world / TEE / seccfg evidence (2026-11-07)

Live-device read-only findings, Honor 90 Lite CRT-NX1 (MT6833), APatch root.

## Artifacts captured

| Path | Contents | Size |
|---|---|---|
| `efuse-dump/efuse.bin` | efuse GPT partition (`/dev/block/sdc12`) | 524,288 |
| `efuse-dump/nvmem/mtk-devinfo0.bin` | SoC OTP shadow via nvmem (`0x11c10000`) | 880 |
| `efuse-dump/nvmem/mt6359p-efuse.bin` | PMIC OTP shadow | 256 |
| `efuse-dump/nvmem/mtk_rtc_nvmem0.bin` | RTC nvmem | 4 |
| `tee-dump/tee_a.bin` | Trustonic secure OS partition | 4,194,304 |

## Key results

1. seccfg V4 stored hash = 32 bytes at `0x1c`; device stores ciphertext, verifies by decrypting in hardware (SEJ/HACC) and comparing to `sha256(header fields)`. Offline recompute impossible: brute-forced all usable data (150 MB-scale candidate keys: whole 512 KiB efuse partition, all nvmem dumps, header derivations, fixed SW key from mtkclient) — zero matches. mtkclient requires `sej_sec_cfg_hw_V3` (HW AES-128-CBC).

2. Normal world is completely cut off from SEJ/HACC (`sej_base=0x1000a000` for MT6833): `/dev/mem` absent; `mknod /dev/mem c 1 1` + `devmem 0x1000a000` → `No such device or address` (kernel refuses mapping), SELinux Enforcing.

3. TEE: `/dev/tc_ns_client` (Trustonic) exists; `libteec-aidl`, `teeauth`, `teecd` running; but **no seccfg TA or strings anywhere in tee_a dump**. seccfg is not a TEE service.

4. Preloader (`pl_payload.bin`) contains:
   - `[%s] img_auth_required = %x`
   - `[%s] seccfg load fail / write fail / part not found`
   - `[SEC_POLICY] lock_state = 0x%x`
   - `[TZ_SEC_CFG]`
   - `[EFUSE] idx[0x%x] verify pass / partially blown / fail`
   - `seclib_img_auth_load_sig`
   → preloader reads seccfg + efuse and decides image auth requirement.

5. LK (both builds) contains `[SEC_POLICY] lock_state(default) = 0x%x`, `seccfg`, `[SBC] image %s auth init fail/auth check fail`, `img_auth_stor` — LK also consumes seccfg state for boot policy.

6. Conclusions so far:
   - Raw seccfg state write (0x03) is kept as best-effort; device may ignore/revert it. LK patch is the effective unlock.
   - Only DA/BROM can perform authenticated seccfg write (`mtk da seccfg unlock`, HW V4 hash).
   - Preloader `img_auth_required` gate behavior is the open question; static analysis in progress (subagent).

---

# MagicOS 9 LK survey (2026-11-21)

Source: `honor-tool/core/tests/fixtures/lk_9_a_original.bin` (sha256
`91476bfab95be519c183703d4cbaa1a09dd147dc579177c05668653be3554368`). Mapping:
VA = file_offset + 0x481ffe00 (payload @ 0x200 → 0x48200000), Thumb-2.
Ghidra 12.2 headless + capstone.

## Function families

| Family | Representative functions (VA) |
|---|---|
| Boot/mode init | blob ~0x4824fe00–0x48250b50; `FUN_4824e460` builds partition table, appends cmdline, calls bootfail readers |
| Watchdog/RGU | 0x48292000–0x48292e4c (`wdt_set_timeout` 0x48292a30, `wdt_restart` 0x48292a4c, `wdt_start` 0x48292b04, emergency SWRST 0x48292d30); WDT base 0x10007000 |
| Display/LCD | lcd_kit family; logo display timeout handler `FUN_482f18b4` (reads `watchdog_time_ms`/`logo_disp_timeout_ms`) |
| Storage/partition | `FUN_4828ff54` partition I/O; GPT names listed incl. `seccfg`, `efuse`, `rrecord` absent |
| USB/fastboot | 0x48251474 area; OEM/getvar/flash dispatch |
| Security/AVB | libavb slot verify `FUN_482e6d0c` incl. rollback index; `FUN_482eabfc` "avb rollback index not match"; `lk_avb` init 0x48239e34 |
| seccfg/SEC_POLICY | NV major/bak/status block 0x482fe878–0x482fed78; **preloader-vs-boottag consistency panic `FUN_48300998`**; lock-state reporters 0x4824acd4/0x4824ad80 |
| OTP/efuse | `FUN_48235cf8` "Lock OTP partition"; `bootrom_dis_efuse` 0x4824d2c0 |
| Recovery/misc/update | misc family 0x13eb24–0x13ff60; recovery cmd writes |
| Panic/kedump/expdb | 0x48258184–0x4825fccc (panic only) |
| RTC/PMIC/charger | charger watchdog kick `FUN_482f16ac` |
| OEMinfo | API 0x48247634–0x48248d00; boot appends cmdline fields |

## bootfail_info / BootDetector (rrecord)

- Module blob 0x48266fa0–0x482681d4; reader `FUN_48257c48` reads 0x400 bytes,
  expects magic `0x5a5a5a5a` + CRC32 over first 0x38 bytes, extracts status byte
  ('1'/'3'/'5'/'6').
- Writer references partition **`rrecord`** (hidden; not in standard GPT list) and
  writes `bootfail.bfctl=%d` bootargs. Strings: "Write bootfail_info into
  rrecord", "suggest_recovery_method", "is_rollback", "flush_upper_bootfail_info".
- Failed boot writes rrecord; repeated failures can suggest/trigger recovery and
  A/B rollback (`[AB_BOOT] rollback enable, slot %s is unbootable...`).
- Physical backing of rrecord unresolved.

## Fastboot OEM surface

No classic MTK `oem unlock`/`oem get_token`/token-lock commands. Surface:
`getvar:*`, `flash: slock/slockv1/rdmode/rdmodev1/frp-erase/upauthcer/upsigndata`,
`oem` subcommands incl. `oeminforead/erase/reused*`, `lock-state info`,
`check-rootinfo`, `frp-unlock/erase`, `dump-storage rrecord`, `mrdump*`,
`usb2jtag`, `bootdetector`, `custom-stateinfo`, `key`, `lks`, etc.
Unlock flow is fb/user-lock state + FRP.

## GSI-relevant findings

1. WDT arm skip candidate: file 0x01acb8 (VA 0x4821aab8), original
   `78 f0 24 f8` (`bl 0x48292b04` = wdt_start) → `00 bf 00 bf`. Mirrors LDY
   (MT6993) patch 7/8 "bootfail watchdog control zero".
2. Secondary WDT site: 0x482501a6 (file 0x503a6), `wdt_set_timeout(30)` +
   `wdt_restart` after `movs r0,#0x1e` at 0x503a4. This is 30s, not ~10min.
3. **No literal ~10-min constant found in LK.** The ~10-min GSI reboot cadence
   is more likely kernel-side (GSI watchdog/hungtask) or BootDetector/recovery
   loop, not the LK 30s WDT.
4. Candidate patched image diff vs original: only the 4-byte fb-unlock patch at
   0x4acc0; no watchdog changes. GSI reboots persist on patched LK.
5. seccfg consistency check (`FUN_48300998`) panics on preloader-vs-LK seccfg
   mismatch; a patched LK must keep seccfg consistent.
6. AVB: LK's libavb is patchable code, but rollback index is stored in
   efuse/secure storage (hard floor) and downstream stages (preloader/kernel)
   re-check. AVB enforcement is layered; skipping LK's check alone is not
   sufficient, and hardware rollback cannot be downgraded by an LK patch.

## Suggested additional patches (GSI)

| # | File off | Original | Replacement | Purpose |
|---|---|---|---|---|
| 2 | 0x1acb8 | `78 f0 24 f8` (bl wdt_start) | `00 bf 00 bf` | disarm WDT arming on boot |
| 3 | 0x503a6 | `42 f0 43 fc` (bl wdt_set_timeout) after `movs r0,#0x1e` | nop both bl | remove 30s WDT set/restart |
| 4 | logo timeout `FUN_482f18b4` | verify `watchdog_time_ms`/`logo_disp_timeout_ms` defaults | may need DT override | avoid hard reset on slow GSI display |

BootDetector recovery autotrigger (module 0x48266fa0–0x482681d4) is a larger,
invasive lever; not proven necessary.

## Unresolved

- rrecord physical backing (hidden partition vs reserved region).
- Whether LK writes back the GPT/partition table at boot.
- Exact OEM dispatch table layout (string-derived list).
- Whether preloader accepts unsigned/patched LK at seccfg state 3 (still the
  known flash gamble; DA closed by 9 OTA).
