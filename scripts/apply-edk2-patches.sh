#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
edk2_dir="$repo_root/galileo/edk2"

if [[ ! -d "$edk2_dir/.git" && ! -f "$edk2_dir/.git" ]]; then
  echo "Missing edk2 submodule at $edk2_dir" >&2
  echo "Run: git submodule update --init --recursive" >&2
  exit 1
fi

for patch in "$repo_root"/patches/edk2/*.patch; do
  if git -C "$edk2_dir" apply --ignore-whitespace --whitespace=nowarn --check "$patch" 2>/dev/null; then
    git -C "$edk2_dir" apply --ignore-whitespace --whitespace=nowarn "$patch"
    echo "applied $(basename "$patch")"
  elif git -C "$edk2_dir" apply --reverse --ignore-whitespace --whitespace=nowarn --check "$patch" 2>/dev/null; then
    echo "already applied $(basename "$patch")"
  else
    echo "patch does not apply cleanly: $patch" >&2
    exit 1
  fi
done
