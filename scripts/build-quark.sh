#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$repo_root/scripts/apply-edk2-patches.sh"

cd "$repo_root/galileo/edk2"
git submodule update --init --recursive

export PYTHON_COMMAND="${PYTHON_COMMAND:-python3}"
export WORKSPACE="$PWD"
export PACKAGES_PATH="$PWD:$(realpath "$repo_root/galileo/edk2-non-osi/Silicon/Intel")"
export CONF_PATH="$WORKSPACE/Conf"
export EDK_TOOLS_PATH="$WORKSPACE/BaseTools"
export EXTRA_OPTFLAGS="${EXTRA_OPTFLAGS:--Wno-error}"
export PATH="$EDK_TOOLS_PATH/BinWrappers/PosixLike:$PATH"

mkdir -p "$CONF_PATH"
for template in build_rule target tools_def; do
  if [[ ! -e "$CONF_PATH/$template.txt" ]]; then
    cp "$EDK_TOOLS_PATH/Conf/$template.template" "$CONF_PATH/$template.txt"
  fi
done

make -C BaseTools PYTHON_COMMAND="$PYTHON_COMMAND" EXTRA_OPTFLAGS="$EXTRA_OPTFLAGS"
build -a IA32 -b "${BUILD_TARGET:-DEBUG}" -t "${TOOL_CHAIN_TAG:-GCC5}" -p QuarkPlatformPkg/Quark.dsc "$@"
