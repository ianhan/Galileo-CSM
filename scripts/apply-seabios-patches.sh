#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
seabios_dir="$repo_root/galileo/seabios"

if [[ ! -d "$seabios_dir/.git" && ! -f "$seabios_dir/.git" ]]; then
  echo "Missing SeaBIOS submodule at $seabios_dir" >&2
  echo "Run: git submodule update --init --recursive" >&2
  exit 1
fi

shopt -s nullglob
for patch in "$repo_root"/patches/seabios/*.patch; do
  if git -C "$seabios_dir" apply --check "$patch" 2>/dev/null; then
    git -C "$seabios_dir" apply "$patch"
    echo "applied $(basename "$patch")"
  elif git -C "$seabios_dir" apply --reverse --check "$patch" 2>/dev/null; then
    echo "already applied $(basename "$patch")"
  else
    echo "patch does not apply cleanly: $patch" >&2
    exit 1
  fi
done
