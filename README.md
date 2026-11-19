# Honor MTK Unlocker

Open your **Honor MediaTek** device's bootloader. Fully supported on the
**Honor 90 Lite** (MT6833), and every other Honor MTK device can produce a
read-only support pack so new firmware can be added.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-auto-blueviolet)](https://github.com/Redminote11tech/honor-mtk-unlocker/actions)

Snapdragon and other non-MediaTek devices are rejected. This tool targets
MediaTek bootloaders only.

## How the unlock works

The unlock is **LK-only**. The tool patches the LK (little kernel bootloader)
partition on both slots. The patch changes the cached fb unlockstate so the
fastboot gate reports the FB LockState as UNLOCKED.

The same method is used by the LDY-AN00 (Magic8 Pro Air, MT6993) unlock
project: temporary root, patch the LK container, write both slots, readback
verify. No other partition is written.

The LK patch is a research modification. It changes reporting on the device.
It does not change the persistent OEM/TEE unlock record (USER LockState stays
LOCKED).

## What the tool does

A guided wizard:

1. Welcome screen with a loading animation.
2. Verifies the output folder, creates it in your home when missing.
3. Verifies your phone is connected and is a supported Honor 90 Lite.
4. Checks if the bootloader is already unlocked. If yes, you are done.
5. Checks for temporary root, and starts it via DFRoot when missing.
6. Installs DFRoot when needed, launches it, waits for you to tap "Launch root".
7. Verifies uid 0, dumps both LK slots, and parses them.
8. Patches the LK, verifies the patch bytes, and asks for final confirmation
   with a 5 second delay.
9. Writes both LK slots and verifies the written bytes by readback.
10. Tells you to reboot. Unlock takes effect after reboot.

## Supporting a new Honor MTK device (pull request)

Not supported yet? The tool can make a support pack for you:

1. Connect the device with USB debugging enabled.
2. Tap **Create support pack (PR)**.
3. The tool attempts temporary root, then dumps both LK slots and device
   identity (model, build, SoC, kernel).
4. It writes `support-pack-<serial>/` with `lk_a.bin`, `lk_b.bin`,
   `manifest.json` and `PR_TEMPLATE.md`.

Open a pull request on GitHub and attach the support folder. A contributor can
then add a fingerprint to `core/src/lk.rs` (all_recipes) and a golden test.
Unknown firmware is never guessed; it is refused until a fingerprint exists.

## Quick start on Linux

### CachyOS / Arch package

```bash
git clone https://github.com/Redminote11tech/honor-mtk-unlocker.git
cd honor-mtk-unlocker/packaging/cachyos
./make-src.sh
makepkg -si
```

Or install a release package with pacman:

```bash
sudo pacman -U honor-mtk-unlocker-0.1.0-10-x86_64.pkg.tar.zst
```

Launch "Honor MTK Unlocker" from your application menu.

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

### Headless CLI

```bash
honor_mtk_unlocker check
honor_mtk_unlocker root ./vendor/DFRoot.apk
honor_mtk_unlocker unlock --out ./backup --danger-do-it --apk ./vendor/DFRoot.apk
honor_mtk_unlocker support-pack --out ./support --apk ./vendor/DFRoot.apk
```

## Supported firmware

| Build | LK patch site | Original bytes | Replacement |
|---|---|---|---|
| MagicOS 7.1 (C431E2R2P2) | 0x403c4 | ff f7 b2 ff | 01 20 00 bf |
| MagicOS 9 (C431E9R2P3) | 0x4acc0 | 05 46 40 b3 | 01 25 00 bf |

Matching is content based. The tool scans the LK payload for known signatures,
so builds that share the same init code are handled automatically. Unknown
builds are refused, never guessed.

The patch forces the cached FB unlockstate (+0x104) to 1.

## Safety

- Beta software. The patch may be wrong.
- The tool writes backups before every write. Keep them.
- Do not relock while a patched LK is installed.
- Do not run OTA updates while unlocked. OTA can overwrite the LK.
- There is no confirmed rescue path on some builds. A failed LK write can brick
  the device.

## Repository layout

```
core/       Rust core: parsing, patching, adb, wizard backend, tests
ui/         Flutter app, Material 3
packaging/  CachyOS / Arch PKGBUILD
vendor/     DFRoot.apk (third party, see below)
```

## Third party

- DFRoot.apk (vendor/) is the DirtyFrag exploit app for temporary root. It is
  not authored by this project. See the DFRoot project for its license.
- Firmware dumps in tests are used only to verify parsing and patching formats.

## Testing

```bash
cd core
cargo test
```

The test suite includes a fake adb device and real firmware dumps. It verifies
that patching reproduces the proven patched images byte for byte.

## License

GPL-3.0-or-later. See LICENSE.
