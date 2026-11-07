# Honor MTK Unlocker

Open your **Honor MediaTek** device's bootloader. Fully supported on the
**Honor 90 Lite** (MT6833), and every other Honor MTK device can produce a
read-only support dump so new firmware can be added.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-auto-blueviolet)](https://github.com/Redminote11tech/honor-mtk-unlocker/actions)

Snapdragon and other non-MediaTek devices are rejected. This tool targets
MediaTek bootloaders only.

## What it does

A guided Material 3 wizard that walks you through everything:

1. Welcome screen with a loading animation.
2. Verifies the output folder and creates it in your home directory when missing.
3. Verifies your phone is connected and is a supported Honor 90 Lite.
4. Checks if the bootloader is already unlocked. If yes, you are done.
5. Checks for temporary root. If missing, attempts temp root via DFRoot.
6. Installs DFRoot when needed, launches it, and waits for you to tap "Launch root".
7. Verifies uid 0, then dumps and parses LK and seccfg.
8. Patches LK and seccfg, verifies the patch bytes, and asks for a final confirmation with a 5 second delay.
9. Writes both partitions and verifies the written bytes by readback.
10. Tells you to reboot. Unlock takes effect after reboot.

Everything runs on your machine. The only phone requirement is USB debugging enabled.

## Why this exists

- Honor 90 Lite is a MediaTek device. Most unlock guides cover Qualcomm or older Huawei chips.
- The MT6833 LK (little kernel bootloader) is not covered by official Honor unlock tools.
- The FB lock state lives in the LK image, not only in seccfg.
- You keep the backups. The tool writes them before anything else.

## Quick start on Linux

### CachyOS / Arch package

```bash
git clone https://github.com/Redminote11tech/honor-mtk-unlocker.git
cd honor-mtk-unlocker/packaging/cachyos
./make-src.sh
makepkg -si
```

Or download a release package and install with pacman:

```bash
sudo pacman -U honor-mtk-unlocker-0.1.0-7-x86_64.pkg.tar.zst
```

Launch "Honor MTK Unlocker" from your application menu.

### Unsupported Honor MediaTek device? Dump for support

Connect the device, run the app, and choose **Dump for support**. The tool
attempts temporary root, then reads LK, seccfg and preloader and saves them
with a manifest of device facts. Open an issue on GitHub and attach the dump
folder. Preloader matters: it decides whether an unsigned or patched LK can
boot, so the risk of a hard brick can be evaluated before any patch is written
for your build.

### Full unlock wizard (Honor 90 Lite)

The supported path does everything automatically:

### Build from source

Requirements: Rust, Flutter (Linux desktop), cmake, ninja, clang, pkg-config, gtk3.

```bash
cd core
cargo build --release

cd ../ui
flutter pub get
flutter build linux --release
export HONOR_MTK_UNLOCKER_BIN=$PWD/../core/target/release/honor_mtk_unlocker
flutter run -d linux
```

### Headless CLI (same steps, no GUI)

```bash
honor_mtk_unlocker check
honor_mtk_unlocker root ./vendor/DFRoot.apk
honor_mtk_unlocker unlock --out ./backup --danger-do-it --apk ./vendor/DFRoot.apk
```
## FAQ

### Does it work on Snapdragon devices or other Honor models?

No. Snapdragon and other non-MediaTek devices are rejected at the device
check. Other Honor MediaTek devices (for example the Honor 200 Lite) are not
unlocked, but they can generate a read-only support dump, LK, seccfg and
preloader, so new firmware can be evaluated and added.


### How is seccfg revalidated after the write?

The tool reads the partition back after writing and compares its SHA-256 to
the exact bytes it intended to write. A mismatch aborts and tells you to
restore the backups. Note: seccfg on this device is V4, so the 40 byte
authenticated region is preserved but not regenerated. The readback verifies
the written bytes, not the device-authenticated hash.

### What if my build number is not listed, like 9.0.0.182?

Build numbers do not decide anything. The tool matches the actual LK bytes
against known signatures. If a build shares the same unlock init code, it is
patched and flashed. If the bytes differ, it is refused with the unsupported
firmware notice, and nothing is written.



## Supported firmware

| Build | LK patch site | Original bytes | Replacement |
|---|---|---|---|
| MagicOS 7.1 (C431E2R2P2) | 0x403c4 | ff f7 b2 ff | 01 20 00 bf |
| MagicOS 9 (C431E9R2P3) | 0x4acc0 | 05 46 40 b3 | 01 25 00 bf |

Matching is content based. The tool scans the LK payload for known signatures, so builds that share the same init code are handled automatically. Unknown builds are refused, never guessed.

The patch forces the cached FB unlockstate (+0x104) to 1. seccfg state lives at offset 0x0c: 0x01 locked, 0x03 unlocked.

## seccfg note

seccfg on this device is V4. The 40 byte authenticated region after the EEEE marker is a device-authenticated hash. This tool flips only the state word and preserves that region byte for byte. It does not regenerate the hash. The LK patch is the effective unlock.

## Safety

- Beta software. The patch may be wrong.
- The tool writes backups before every write. Keep them.
- Do not relock while a patched LK is installed.
- Do not run OTA updates while unlocked. OTA can overwrite the LK.
- There is no confirmed rescue path on some builds. A failed LK write can brick the device.

## Repository layout

```
core/       Rust core: parsing, patching, adb, wizard backend, tests
ui/         Flutter app, Material 3
packaging/  CachyOS / Arch PKGBUILD
vendor/     DFRoot.apk (third party, see below)
```

## Third party

- DFRoot.apk (vendor/) is the DirtyFrag exploit app for temporary root. It is not authored by this project. See the DFRoot project for its license.
- Approved firmware dumps in tests are used only to verify parsing and patching formats.

## Testing

```bash
cd core
cargo test
```

The test suite includes a fake adb device and real firmware dumps. It verifies that patching reproduces the proven patched images byte for byte.

## Contributing

See CONTRIBUTING.md.

## License

GPL-3.0-or-later. See LICENSE.
