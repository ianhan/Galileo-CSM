<p align="center">
  <img src="media/quake-readme.gif" alt="Quake running on Galileo">
</p>

# Galileo MS-DOS boot speed run

I used codex to rebuild something I did a long time ago - setting up the quark firmware package with CSM support so a galileo could boot MS-DOS (as long as it had a PCIe to PCI VGA adapter, or PCIe VGA adapter).
What works: dos boots
What doesn't work: keyboard support provided by BIOS works, but just like 10 years ago, I'll need to try to kerjigger something together with SMM to support keyboard i/o & irq.
This means that quake launches and runs fine but you can't use the keyboard, for example...

# Galileo CSM Workspace

This workspace is pinned to a late in-tree Quark/Galileo baseline that is still
close enough to the original platform work to be useful, but new enough to be a
practical starting point for modern GCC work. It is not pinned to the 2025
`edk2-platforms` archive/removal point.

## Submodule Pins

- `galileo/edk2`: `1df91bb772a1cf6f2709063ec120e659b2eb49fc`
  - `QuarkPlatformPkg: Remove PcdFrameworkCompatibilitySupport usage`
  - Commit date: 2019-05-09
  - This is the last Quark-specific commit before Quark moved out of `edk2`.
- `galileo/edk2-non-osi`: `596043ffb61d5f74a9eb334eaa4df683fa975c92`
  - Commit date: 2019-04-23
  - This is the matching `edk2-non-osi` snapshot immediately before the
    selected `edk2` pivot. The Quark binary package lives at
    `Silicon/Intel/QuarkSocBinPkg`.
- `galileo/seabios`: `b52ca86e094d19b58e2304417787e96b940e39c6`
  - `rel-1.17.0`
  - Commit date: 2025-06-10
  - Used to build the SeaBIOS CSM payload `Csm16.bin`.

At this date `QuarkPlatformPkg` and `QuarkSocPkg` still live directly in
`edk2`. The later `edk2-platforms` tag
`202502-before-platform-removals` is useful as an archive reference, but it is
too far removed from the original work and includes later regression risk.

The raw package import point was `b303605e1b7e113b4311daf161c6c3289350447b`
(`QuarkPlatformPkg: Add new package for Galileo boards`) on 2015-12-15. The
first Quark GCC cleanup burst ended around 2016-05-13, roughly five months
later, but that point predates the GCC5 toolchain profile, Python 3 build-script
work, and several BaseTools warning fixes. Since the goal is newer GCC, this
workspace deliberately pivots later while Quark is still in-tree.

## Patch Series

Modern-host fixes are kept as patches against the `galileo/edk2` submodule:

- `patches/edk2/0001-BaseTools-accept-ucs_2-codec-name.patch`
  - Fixes Python 3.9+ codec lookup for `ucs_2`.
- `patches/edk2/0002-QuarkPlatformPkg-relax-Werror-for-modern-GCC.patch`
  - Adds a Quark IA32 GCC build option that turns modern diagnostics into
    warnings instead of hard errors. This is a bootstrap patch for GCC 13-class
    hosts; later patches can replace it with targeted source fixes.
- `patches/edk2/0003-BaseTools-use-array-bytes-apis.patch`
  - Replaces removed Python 3.12 `array.array` string APIs with the bytes APIs.

Apply them with:

```sh
./scripts/apply-edk2-patches.sh
```

## Build Setup

From a fresh checkout:

```sh
git submodule update --init --recursive
./scripts/apply-edk2-patches.sh
./scripts/build-seabios-csm.sh
./scripts/build-quark.sh
```

The build script uses:

```sh
export PYTHON_COMMAND=python3
export WORKSPACE="$PWD/galileo/edk2"
export PACKAGES_PATH="$WORKSPACE:$(realpath galileo/edk2-non-osi/Silicon/Intel)"
export CONF_PATH="$WORKSPACE/Conf"
export EDK_TOOLS_PATH="$WORKSPACE/BaseTools"
export PATH="$EDK_TOOLS_PATH/BinWrappers/PosixLike:$PATH"
make -C BaseTools PYTHON_COMMAND=python3 EXTRA_OPTFLAGS=-Wno-error
build -a IA32 -b DEBUG -t GCC5 -p QuarkPlatformPkg/Quark.dsc
```

`GCC5` is the right EDK II toolchain family for this baseline when using a
newer host GCC.

## SeaBIOS CSM

SeaBIOS is pinned as a submodule and built in CSM mode with:

```sh
./scripts/build-seabios-csm.sh
```

The script builds `galileo/seabios/out/Csm16.bin` and installs a generated copy
at `galileo/edk2/OvmfPkg/Csm/Csm16/Csm16.bin`, which is the path consumed by
`OvmfPkg/Csm/Csm16/Csm16.inf`.
