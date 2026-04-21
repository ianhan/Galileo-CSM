#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
default_image="$repo_root/galileo/edk2/Build/Quark/DEBUG_GCC5/FV/QUARK.fd"

image="$default_image"
divisor="${TIGARD_DIVISOR:-4}"
chip=""
yes=0
backup=1
probe_only=0
verify_only=0
allow_size_mismatch=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Flash the Galileo Gen 2 8 MiB SPI BIOS image with Tigard.

Options:
  --image PATH              Firmware image to write.
                            Default: $default_image
  --divisor N               flashrom FT2232 SPI divisor. Default: $divisor
  --chip NAME               Pass an explicit flashrom chip name with -c.
  --no-backup               Skip the default pre-flash backup reads.
  --probe-only              Detect the flash chip and exit.
  --verify-only             Verify the current flash contents against the image.
  --allow-size-mismatch     Do not require an 8 MiB image.
  -y, --yes                 Do not ask for confirmation before writing.
  -h, --help                Show this help.

Tigard setup:
  - Mode switch: SPI/JTAG
  - Voltage switch: 3V3 for an unpowered Galileo, or VTGT for a powered target
  - Programmer: ft2232_spi:type=2232H,port=B,divisor=N

Galileo Gen 2 SPI flash program header:
  pin 1 VCC  -> Tigard VTGT
  pin 2 GND  -> Tigard GND
  pin 3 CS   -> Tigard CS
  pin 4 SCK  -> Tigard SCK
  pin 5 MISO -> Tigard CIPO/MISO
  pin 6 MOSI -> Tigard COPI/MOSI
  pin 7 is the missing/key pin
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      image="${2:?missing path after --image}"
      shift 2
      ;;
    --divisor)
      divisor="${2:?missing value after --divisor}"
      shift 2
      ;;
    --chip)
      chip="${2:?missing name after --chip}"
      shift 2
      ;;
    --no-backup)
      backup=0
      shift
      ;;
    --probe-only)
      probe_only=1
      shift
      ;;
    --verify-only)
      verify_only=1
      shift
      ;;
    --allow-size-mismatch)
      allow_size_mismatch=1
      shift
      ;;
    -y|--yes)
      yes=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ! command -v flashrom >/dev/null 2>&1; then
  echo "Missing flashrom. Install it first, for example: sudo apt-get install flashrom" >&2
  exit 1
fi

if [[ ! -f "$image" ]]; then
  echo "Missing firmware image: $image" >&2
  echo "Build it first with: ./scripts/build-seabios-csm.sh && ./scripts/build-quark.sh" >&2
  exit 1
fi

image_size="$(stat -c %s "$image")"
if [[ "$allow_size_mismatch" -eq 0 && "$image_size" -ne 8388608 ]]; then
  echo "Refusing to flash image with unexpected size: $image_size bytes" >&2
  echo "Expected the Galileo Gen 2 SPI BIOS image to be 8388608 bytes." >&2
  echo "Use --allow-size-mismatch only if you know this is intentional." >&2
  exit 1
fi

programmer="ft2232_spi:type=2232H,port=B,divisor=$divisor"
flashrom_args=(-p "$programmer")
if [[ -n "$chip" ]]; then
  flashrom_args+=(-c "$chip")
fi

echo "Image:      $image"
echo "Image size: $image_size bytes"
echo "Programmer: $programmer"
if [[ -n "$chip" ]]; then
  echo "Chip:       $chip"
fi
if [[ "$backup" -eq 1 ]]; then
  backup_dir="$repo_root/backups"
  backup_prefix="$backup_dir/galileo2-spi-$(date +%Y%m%d-%H%M%S)"
  echo "Backup:    ${backup_prefix}-{1,2}.bin"
else
  echo "Backup:    disabled"
fi

if [[ "$probe_only" -eq 1 ]]; then
  exec sudo flashrom "${flashrom_args[@]}"
fi

if [[ "$verify_only" -eq 1 ]]; then
  exec sudo flashrom "${flashrom_args[@]}" -v "$image"
fi

if [[ "$yes" -eq 0 ]]; then
  echo
  if [[ "$backup" -eq 1 ]]; then
    echo "This will back up, erase, rewrite, and verify the Galileo Gen 2 SPI BIOS flash."
  else
    echo "This will erase, rewrite, and verify the Galileo Gen 2 SPI BIOS flash without a backup."
  fi
  read -r -p "Type 'flash' to continue: " answer
  if [[ "$answer" != "flash" ]]; then
    echo "Aborted."
    exit 1
  fi
fi

if [[ "$backup" -eq 1 ]]; then
  mkdir -p "$backup_dir"
  sudo flashrom "${flashrom_args[@]}" -r "${backup_prefix}-1.bin"
  sudo flashrom "${flashrom_args[@]}" -r "${backup_prefix}-2.bin"
  cmp "${backup_prefix}-1.bin" "${backup_prefix}-2.bin"
fi

sudo flashrom "${flashrom_args[@]}" -w "$image"
sudo flashrom "${flashrom_args[@]}" -v "$image"
