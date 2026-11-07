#!/usr/bin/env bash
# Bundle the honor-tool repo into a source tarball for the PKGBUILD.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/honor-tool-src.tar.gz"
OUT="$HERE/honor-mtk-unlocker-src.tar.gz"
NAME="$(basename "$ROOT")"

tar -czf "$OUT" \
  --exclude='*/.git' \
  --exclude='*/target' \
  --exclude='*/build' \
  --exclude='*/.dart_tool' \
  --exclude='*.tar.gz' \
  --exclude='*/.flutter-plugins*' \
  --exclude='*/cachyos/src' \
  --exclude='*/cachyos/pkg' \
  -C "$ROOT/.." "$NAME"

echo "created $OUT"
tar tzf "$OUT" | wc -l | xargs echo "entries:"
