# CachyOS / Arch package

Build and install:

```bash
cd honor-tool/packaging/cachyos
./make-src.sh            # bundle the repo into honor-mtk-unlocker-src.tar.gz
makepkg -si              # build + install (honor-mtk-unlocker-0.1.0-1-x86_64.pkg.tar.zst)
```

Then launch **Honor MTK Unlocker** from your application menu (or run
`honor-mtk-unlocker`).

Installed layout:

| Path | Purpose |
|---|---|
| `/usr/bin/honor_mtk_unlocker` | Rust CLI (also the backend the UI spawns) |
| `/usr/bin/honor-mtk-unlocker` | launcher wrapper (sets `HONOR_MTK_UNLOCKER_BIN`) |
| `/opt/honor-mtk-unlocker/` | Flutter release bundle |
| `/usr/share/applications/honor-mtk-unlocker.desktop` | menu entry |
| `/usr/share/icons/hicolor/*/apps/honor-mtk-unlocker.png` | icon |

Notes:

- Build-time deps come from the standard repos (`rust`, `flutter`, `cmake`,
  `ninja`, `clang`, `pkgconf`, `imagemagick`). The Rust crate cache is
  reused from `~/.cargo`; the Flutter build is isolated via `PUB_CACHE`.
- The desktop bundle does **not** run as root; adb access is the usual
  platform-tools setup (`adb` on PATH, USB debugging enabled, and the
  `70-honor90lite-mtk.rules` udev rules if using a device).
