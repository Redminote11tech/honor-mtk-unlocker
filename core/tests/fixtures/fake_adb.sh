#!/usr/bin/env bash
# Hermetic fake adb used by tests/e2e_fake_dev.rs only.
#
# It emulates exactly enough of `adb` for the tool: device listing, props,
# package/launcher resolution, and the DFRoot cmd/out channel. The channel is
# emulated by executing the decoded cmd immediately (as the real DFRoot
# service would) and writing the output to `HONOR_OUT_FILE`.
set -u

MODEL="${FAKE_MODEL:-CRT-NX1}"
SERIAL="${FAKE_SERIAL:-FAKE-SERIAL-0001}"
SB="${FAKE_SANDBOX:?need FAKE_SANDBOX}"

out_file() {
  printf '%s' "${HONOR_OUT_FILE:-/data/local/tmp/out}"
}

case "${1:-}" in
  devices)
    printf 'List of devices attached\n%s\tdevice\n' "$SERIAL"
    exit 0
    ;;
  install)
    exit 0
    ;;
  shell)
    shift
    cmd="$*"
    case "$cmd" in
      getprop\ ro.product.model) echo "$MODEL"; exit 0 ;;
      getprop\ ro.product.device) echo k6833v1_64_k419; exit 0 ;;
      getprop\ ro.boot.slot_suffix) echo _a; exit 0 ;;
      getprop\ ro.build.version.sdk) echo 35; exit 0 ;;
      getprop\ ro.product.cpu.abi) echo arm64-v8a; exit 0 ;;
      getprop\ ro.boot.flash.locked) echo "${FAKE_FLASH_LOCKED:-1}"; exit 0 ;;
      getprop\ ro.boot.verifiedbootstate) echo orange; exit 0 ;;
      getprop\ persist.log.tag) echo V; exit 0 ;;
      setprop\ *) exit 0 ;;
      pm\ list\ packages\ *) echo "package:df.root"; exit 0 ;;
      cmd\ package\ resolve-activity\ *) echo "df.root/.LauncherActivity"; exit 0 ;;
      am\ start\ *) exit 0 ;;
      *)
        # DFRoot channel write: decode the inner command and run it now.
        if [[ "$cmd" == *" | base64 -d > "* ]]; then
          inner="${cmd#echo }"
          inner="${inner%% | base64 -d > *}"
          decoded="$(printf '%s' "$inner" | base64 -d 2>/dev/null)"
          export PATH="$SB/bin:$PATH"
          cd "$SB" || exit 1
          { eval "$decoded"; } > "$(out_file)" 2>&1 || true
          exit 0
        fi
        export PATH="$SB/bin:$PATH"
        cd "$SB" || exit 1
        eval "$cmd"
        exit $?
        ;;
    esac
    ;;
  *)
    exit 1
    ;;
esac
