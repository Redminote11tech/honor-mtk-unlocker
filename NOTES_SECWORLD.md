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
