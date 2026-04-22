#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
seabios_dir="$repo_root/galileo/seabios"
edk2_csm_dir="$repo_root/galileo/edk2/OvmfPkg/Csm/Csm16"

if [[ ! -d "$seabios_dir/.git" && ! -f "$seabios_dir/.git" ]]; then
  echo "Missing SeaBIOS submodule at $seabios_dir" >&2
  echo "Run: git submodule update --init --recursive" >&2
  exit 1
fi

"$repo_root/scripts/apply-seabios-patches.sh"

tmp_config="$(mktemp)"
trap 'rm -f "$tmp_config"' EXIT

cat > "$tmp_config" <<'CONFIG'
CONFIG_CSM=y
CONFIG_ROM_SIZE=128
CONFIG_DEBUG_LEVEL=0
CONFIG_DEBUG_SERIAL=n
CONFIG_DEBUG_SERIAL_PORT=0
CONFIG_DEBUG_COREBOOT=n
CONFIG_DEBUG_IO=n
CONFIG_DEBUG_HTTPS=n
CONFIG

make -C "$seabios_dir" PYTHON=python3 KCONFIG_ALLCONFIG="$tmp_config" alldefconfig
make -C "$seabios_dir" PYTHON=python3 -j"${JOBS:-$(nproc)}"

install -m 0644 "$seabios_dir/out/Csm16.bin" "$edk2_csm_dir/Csm16.bin"
echo "$edk2_csm_dir/Csm16.bin"
