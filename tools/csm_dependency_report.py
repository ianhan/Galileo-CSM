#!/usr/bin/env python3
"""Build a CSM-to-platform dependency report for local EDK2 trees.

The goal is to make the "what service did I forget to port?" loop explicit:
parse CSM INF metadata, scan CSM source for protocol/GUID usage, parse the
target platform DSC/FDF, then compare required services against providers that
are already in the target platform and providers available in the local trees.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import DefaultDict, Iterable


DEFAULT_CSM_MODULES = [
    "IntelFrameworkModulePkg/Csm/LegacyBiosDxe/LegacyBiosDxe.inf",
    "OvmfPkg/Csm/Csm16/Csm16.inf",
    "OvmfPkg/Csm/CsmSupportLib/CsmSupportLib.inf",
    "IntelFrameworkModulePkg/Library/LegacyBootManagerLib/LegacyBootManagerLib.inf",
    "IntelFrameworkModulePkg/Library/LegacyBootMaintUiLib/LegacyBootMaintUiLib.inf",
    "IntelFrameworkModulePkg/Csm/BiosThunk/VideoDxe/VideoDxe.inf",
    "PcAtChipsetPkg/8259InterruptControllerDxe/8259.inf",
]

EFI_SERVICE_RE = re.compile(
    r"\b(?:gBS|gRT|gDS|gST|BootServices|RuntimeServices)->"
    r"(LocateProtocol|LocateHandleBuffer|HandleProtocol|OpenProtocol|"
    r"InstallProtocolInterface|InstallMultipleProtocolInterfaces|"
    r"ReinstallProtocolInterface|UninstallProtocolInterface|"
    r"CreateEvent|CreateEventEx|SignalEvent|SetTimer|RaiseTPL|RestoreTPL)"
)
GUID_RE = re.compile(r"\bg[A-Za-z0-9_]+(?:ProtocolGuid|Guid)\b")
INF_RE = re.compile(r"([A-Za-z0-9_./$(){}+-]+\.inf)\b")
INSTALL_PROTOCOL_RE = re.compile(r"\b(?:InstallProtocolInterface|InstallMultipleProtocolInterfaces)\s*\(")

PROVIDER_MARKERS = (
    "PRODUCES",
    "PRODUCED",
    "BY_START",
    "ALWAYS_PRODUCED",
    "SOMETIMES_PRODUCES",
)
CONSUMER_MARKERS = (
    "CONSUMES",
    "CONSUMED",
    "TO_START",
    "NOTIFY",
    "ALWAYS_CONSUMED",
    "SOMETIMES_CONSUMES",
    "UNDEFINED",
)
OPTIONAL_MARKERS = ("SOMETIMES", "NOTIFY", "UNDEFINED")
HARD_MARKERS = ("CONSUMES", "TO_START", "ALWAYS_CONSUMED", "ALWAYS_CONSUMES")

MULTI_INSTANCE_PROTOCOLS = {
    "gEfiBlockIoProtocolGuid",
    "gEfiDevicePathProtocolGuid",
    "gEfiDiskInfoProtocolGuid",
    "gEfiGraphicsOutputProtocolGuid",
    "gEfiPciIoProtocolGuid",
    "gEfiSerialIoProtocolGuid",
    "gEfiSimplePointerProtocolGuid",
    "gEfiSimpleTextInProtocolGuid",
    "gEfiSioProtocolGuid",
}

SINGLETON_PROTOCOLS = {
    "gEdkiiIoMmuProtocolGuid",
    "gEfiGenericMemTestProtocolGuid",
    "gEfiHiiConfigRoutingProtocolGuid",
    "gEfiHiiDatabaseProtocolGuid",
    "gEfiLegacy8259ProtocolGuid",
    "gEfiLegacyBiosPlatformProtocolGuid",
    "gEfiLegacyBiosProtocolGuid",
    "gEfiLegacyInterruptProtocolGuid",
    "gEfiLegacyRegion2ProtocolGuid",
}

QUARK_CONTRACT_ROWS = [
    [
        "`gEfiLegacy8259ProtocolGuid`",
        "`LegacyBiosDxe` depex requires it before dispatch.",
        "`PcAtChipsetPkg/8259InterruptControllerDxe/8259.inf` matches Quark's existing PC/AT chipset package. Use that instead of the OVMF copy, and assign the PcAtChipsetPkg 8259 PCDs explicitly.",
    ],
    [
        "`gEfiLegacyRegion2ProtocolGuid`",
        "Quark already installs it from `QNCInitDxe`; OVMF `CsmSupportLib` also installs one if copied unchanged.",
        "Patch or fork `CsmSupportLib` so it does not compile, declare, or call `LegacyRegion.c`. The Quark provider must remain the only singleton provider.",
    ],
    [
        "`gEfiLegacyInterruptProtocolGuid`",
        "OVMF `LegacyInterrupt.c` only selects PIIX4/Q35 using `PcdOvmfHostBridgePciDevId`.",
        "Replace it with Quark LPC routing: bus 0, device 31, function 0, PIRQ registers `R_QNC_LPC_PIRQA_ROUT` through `R_QNC_LPC_PIRQH_ROUT`.",
    ],
    [
        "`gEfiLegacyBiosPlatformProtocolGuid` routing",
        "OVMF `PirqTableHead`, `GetRoutingTable()`, and `TranslatePirq()` encode an i440fx-style table.",
        "Derive the $PIR table from Quark ACPI: root bus D20/D21 use LNKA-LNKD, D23 uses LNKE-LNKH, LPC D31 uses LNKA, and PCIe downstream buses must be discovered at runtime.",
    ],
    [
        "`EfiGetPlatformVgaHandle`",
        "OVMF `GetSelectedVgaDeviceInfo()` searches only bus 0.",
        "Search all `PciIo` handles, or explicitly prefer the PCIe-to-PCI bridge path, so a VGA card behind PEX0/PEX1 can be selected and its legacy option ROM can run.",
    ],
    [
        "`EfiGetPlatformIsaBusHandle`",
        "`LegacySio.c` calls `GetPlatformHandle(EfiGetPlatformIsaBusHandle)` and uses `HandleBuffer[0]` before checking the returned status.",
        "Ensure the platform provider returns the Quark LPC bridge handle, or patch `LegacySio.c` to guard the failure path before connecting the ISA controller.",
    ],
    [
        "`gEdkiiIoMmuProtocolGuid`",
        "`LegacyPci.c` locates it lazily and only calls it when present.",
        "Do not add a fake IOMMU for dispatch. Absence is acceptable on Quark unless a later DMA path proves it is needed.",
    ],
    [
        "`gEfiIsaIoProtocolGuid` / `gEfiSioProtocolGuid`",
        "`LegacySio.c` probes them to fill serial, parallel, floppy, and mouse legacy inventory.",
        "They are not CSM dispatch blockers, but missing inventory can affect legacy input/device behavior. Treat this as a runtime test item, not a compile-only success.",
    ],
]

QUARK_PCD_RECOMMENDATIONS = [
    [
        "`gPcAtChipsetPkgTokenSpaceGuid.Pcd8259LegacyModeMask`",
        "`0xFFFF`",
        "Start with all legacy IRQs masked; `LegacyBiosDxe` adjusts masks when switching modes.",
    ],
    [
        "`gPcAtChipsetPkgTokenSpaceGuid.Pcd8259LegacyModeEdgeLevel`",
        "`0x0E20`",
        "OVMF CSM baseline marks IRQs 5, 9, 10, and 11 level-triggered. Quark ACPI advertises a wider possible PIRQ mask (`0xDEB8`); only widen this after validating the final routing table.",
    ],
    [
        "`gEfiIntelFrameworkModulePkgTokenSpaceGuid.PcdBiosVideoCheckVbeEnable`",
        "`TRUE`",
        "Allow `BiosVideoDxe` to use VBE from the VGA option ROM.",
    ],
    [
        "`gEfiIntelFrameworkModulePkgTokenSpaceGuid.PcdBiosVideoCheckVgaEnable`",
        "`TRUE`",
        "Keep VGA fallback enabled for old option ROMs.",
    ],
    [
        "`gEfiIntelFrameworkModulePkgTokenSpaceGuid.PcdBiosVideoSetTextVgaModeEnable`",
        "`FALSE`",
        "Keep the DEC default unless a specific card needs forced 80x25 mode at exit boot services.",
    ],
    [
        "`gEfiIntelFrameworkModulePkgTokenSpaceGuid.PcdLegacyBiosCacheLegacyRegion`",
        "`FALSE`",
        "VLV CSM platforms disable this; Quark's legacy-region provider should own the region attributes.",
    ],
    [
        "`gEfiIntelFrameworkModulePkgTokenSpaceGuid.PcdEbdaReservedMemorySize`",
        "`0x10000`",
        "Use the larger VLV CSM value rather than the smaller DEC default to leave room for option ROM bookkeeping.",
    ],
    [
        "`gEfiIntelFrameworkModulePkgTokenSpaceGuid.PcdOpromReservedMemoryBase`",
        "`0x60000`",
        "DEC default; below EBDA and below the option ROM shadow range.",
    ],
    [
        "`gEfiIntelFrameworkModulePkgTokenSpaceGuid.PcdOpromReservedMemorySize`",
        "`0x28000`",
        "DEC default; reserve low memory for option ROM execution.",
    ],
    [
        "`gEfiIntelFrameworkModulePkgTokenSpaceGuid.PcdEndOpromShadowAddress`",
        "`0xDFFFF`",
        "DEC default; leaves C0000-DFFFF for shadowed option ROMs.",
    ],
    [
        "`gEfiIntelFrameworkModulePkgTokenSpaceGuid.PcdLowPmmMemorySize`",
        "`0x10000`",
        "DEC default low PMM size.",
    ],
    [
        "`gEfiIntelFrameworkModulePkgTokenSpaceGuid.PcdHighPmmMemorySize`",
        "`0x400000`",
        "DEC default high PMM size.",
    ],
    [
        "`gEfiMdeModulePkgTokenSpaceGuid.PcdVideoHorizontalResolution` / `PcdVideoVerticalResolution`",
        "`800` / `600`",
        "Match OVMF and VLV CSM text setup defaults.",
    ],
]


def strip_comment(line: str) -> str:
    """Strip INF/DSC/FDF comments, keeping the code side."""
    for token in ("##", "#"):
        if token in line:
            line = line.split(token, 1)[0]
    return line.strip()


def comment_part(line: str) -> str:
    if "##" in line:
        return line.split("##", 1)[1].strip()
    if "#" in line:
        return line.split("#", 1)[1].strip()
    return ""


def section_base(section: str) -> str:
    return section.split(".", 1)[0].strip()


def first_field(entry: str) -> str:
    entry = strip_comment(entry)
    if not entry:
        return ""
    return re.split(r"[\s|]+", entry, 1)[0].strip()


def markdown_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    def esc(value: str) -> str:
        value = value.replace("\n", "<br>")
        return value.replace("|", "\\|")

    out = ["| " + " | ".join(headers) + " |"]
    out.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        out.append("| " + " | ".join(esc(str(v)) for v in row) + " |")
    return out


def strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


@dataclasses.dataclass(frozen=True)
class ProtocolUse:
    guid: str
    role: str
    raw_role: str
    inf: Path
    line: str


@dataclasses.dataclass
class InfInfo:
    path: Path
    package_path: str
    sections: dict[str, list[str]]
    protocols: list[ProtocolUse]
    sources: list[Path]
    source_guids: set[str]
    source_protocol_guids: set[str]
    service_calls: list[tuple[Path, int, str]]
    inferred_installed_protocols: set[str]

    def packages(self) -> set[str]:
        return {first_field(v) for v in self.sections.get("Packages", []) if first_field(v)}

    def library_classes(self) -> set[str]:
        out: set[str] = set()
        for v in self.sections.get("LibraryClasses", []):
            name = first_field(v)
            if name and name != "NULL":
                out.add(name)
        return out

    def guids(self) -> set[str]:
        return {first_field(v) for v in self.sections.get("Guids", []) if first_field(v)}

    def pcds(self) -> set[str]:
        out: set[str] = set()
        for section in ("Pcd", "PcdsFixedAtBuild", "PcdsFeatureFlag", "PcdsPatchableInModule", "PcdsDynamic", "PcdsDynamicEx"):
            out.update(first_field(v) for v in self.sections.get(section, []) if first_field(v))
        return out

    def depex_symbols(self) -> set[str]:
        text = " ".join(self.sections.get("Depex", []))
        return set(GUID_RE.findall(text))


class PackageResolver:
    def __init__(self, roots: Iterable[Path]) -> None:
        self.roots = [p.resolve() for p in roots if p.exists()]
        self.package_map: dict[str, Path] = {}
        self.inf_cache: dict[Path, InfInfo] = {}
        self._build_package_map()

    def _build_package_map(self) -> None:
        for root in self.roots:
            for dec in root.rglob("*.dec"):
                if any(part.lower() == "build" for part in dec.parts):
                    continue
                package = dec.parent.name
                self.package_map.setdefault(package, dec.parent.resolve())

    def resolve(self, value: str) -> Path | None:
        value = value.strip().replace("\\", "/")
        value = re.sub(r"^\$\(WORKSPACE\)/", "", value)
        value = re.sub(r"^\$\(PLATFORM_PACKAGE\)/", "QuarkPlatformPkg/", value)
        if not value:
            return None
        p = Path(value)
        if p.is_absolute() and p.exists():
            return p.resolve()
        first = value.split("/", 1)[0]
        if first in self.package_map:
            candidate = self.package_map[first] / value.split("/", 1)[1] if "/" in value else self.package_map[first]
            if candidate.exists():
                return candidate.resolve()
        for root in self.roots:
            candidate = root / value
            if candidate.exists():
                return candidate.resolve()
        return None

    def package_path(self, path: Path) -> str:
        path = path.resolve()
        matches: list[tuple[int, str]] = []
        for pkg, pkg_root in self.package_map.items():
            try:
                rel = path.relative_to(pkg_root)
            except ValueError:
                continue
            matches.append((len(str(pkg_root)), f"{pkg}/{rel.as_posix()}"))
        if matches:
            return max(matches)[1]
        return path.as_posix()

    def parse_inf(self, path: Path) -> InfInfo:
        path = path.resolve()
        if path in self.inf_cache:
            return self.inf_cache[path]

        sections: DefaultDict[str, list[str]] = defaultdict(list)
        section = ""
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            lines = []
        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue
            match = re.match(r"\[(.+?)\]", stripped)
            if match:
                section = section_base(match.group(1))
                continue
            if not section:
                continue
            code = strip_comment(raw)
            if code:
                sections[section].append(raw.rstrip())

        protocols = self._parse_protocols(path, sections)
        sources = self._resolve_sources(path, sections)
        source_guids, service_calls, inferred = self._scan_sources(sources)
        info = InfInfo(
            path=path,
            package_path=self.package_path(path),
            sections=dict(sections),
            protocols=protocols,
            sources=sources,
            source_guids=source_guids,
            source_protocol_guids={g for g in source_guids if g.endswith("ProtocolGuid")},
            service_calls=service_calls,
            inferred_installed_protocols=inferred,
        )
        self.inf_cache[path] = info
        return info

    def _parse_protocols(self, path: Path, sections: dict[str, list[str]]) -> list[ProtocolUse]:
        out: list[ProtocolUse] = []
        for raw in sections.get("Protocols", []):
            guid = first_field(raw)
            if not guid:
                continue
            comment = comment_part(raw).upper()
            role = "unknown"
            if any(marker in comment for marker in PROVIDER_MARKERS):
                role = "provider"
            elif any(marker in comment for marker in CONSUMER_MARKERS):
                role = "consumer"
            out.append(ProtocolUse(guid=guid, role=role, raw_role=comment, inf=path, line=raw.strip()))
        return out

    def _resolve_sources(self, inf: Path, sections: dict[str, list[str]]) -> list[Path]:
        out: list[Path] = []
        base = inf.parent
        for raw in sections.get("Sources", []):
            code = strip_comment(raw)
            if not code:
                continue
            source = code.split("|", 1)[0].strip()
            if not source or source.startswith("BIN|"):
                continue
            source = source.split()[0]
            p = base / source
            if p.exists() and p.is_file():
                out.append(p.resolve())
        return out

    def _scan_sources(self, sources: list[Path]) -> tuple[set[str], list[tuple[Path, int, str]], set[str]]:
        source_guids: set[str] = set()
        service_calls: list[tuple[Path, int, str]] = []
        inferred_installed: set[str] = set()
        for source in sources:
            if source.suffix.lower() not in {".c", ".h", ".inc", ".asl", ".vfr", ".asm", ".nasm", ".s", ".S".lower()}:
                # Keep scanning text-like source extensions above; skip binaries.
                continue
            try:
                text = source.read_text(errors="replace")
            except OSError:
                continue
            scan_text = strip_c_comments(text)
            guids = set(GUID_RE.findall(scan_text))
            source_guids.update(guids)
            lines = text.splitlines()
            for match in INSTALL_PROTOCOL_RE.finditer(scan_text):
                end = scan_text.find(";", match.start())
                if end == -1:
                    continue
                call_text = scan_text[match.start():end + 1]
                inferred_installed.update(
                    guid for guid in GUID_RE.findall(call_text) if guid.endswith("ProtocolGuid")
                )
            for lineno, line in enumerate(lines, 1):
                if line.lstrip().startswith("//"):
                    continue
                if EFI_SERVICE_RE.search(line):
                    service_calls.append((source, lineno, line.strip()))
        return source_guids, service_calls, inferred_installed


def role_strength(use: ProtocolUse, info: InfInfo) -> str:
    if use.guid in info.depex_symbols():
        return "hard-depex"
    raw = use.raw_role.upper()
    if any(marker in raw for marker in OPTIONAL_MARKERS):
        return "optional"
    if any(marker in raw for marker in HARD_MARKERS):
        return "hard"
    if use.role == "consumer":
        return "consumer"
    if use.role == "provider":
        return "provider"
    return "unknown"


def is_singleton_protocol(guid: str) -> bool:
    if guid in MULTI_INSTANCE_PROTOCOLS:
        return False
    return guid.endswith("ArchProtocolGuid") or guid in SINGLETON_PROTOCOLS


def collect_inf_references(files: list[Path], resolver: PackageResolver) -> set[Path]:
    refs: set[Path] = set()
    for fp in files:
        try:
            lines = fp.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for raw in lines:
            code = strip_comment(raw)
            if not code:
                continue
            for match in INF_RE.findall(code):
                resolved = resolver.resolve(match)
                if resolved and resolved.exists():
                    refs.add(resolved)
    return refs


def collect_dsc_packages(dsc: Path) -> set[str]:
    out: set[str] = set()
    section = ""
    try:
        lines = dsc.read_text(errors="replace").splitlines()
    except OSError:
        return out
    for raw in lines:
        stripped = raw.strip()
        match = re.match(r"\[(.+?)\]", stripped)
        if match:
            section = section_base(match.group(1))
            continue
        if section == "Packages":
            pkg = first_field(raw)
            if pkg:
                out.add(pkg)
    return out


def collect_platform_package_refs(files: list[Path]) -> set[str]:
    """Return package roots referenced by platform metadata.

    Quark.dsc does not use a conventional [Packages] section, so package
    presence has to be inferred from INF/library/include paths in the DSC/FDF.
    """
    out: set[str] = set()
    package_ref = re.compile(r"\b([A-Za-z0-9_]+Pkg)/")
    for fp in files:
        try:
            lines = fp.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for raw in lines:
            code = strip_comment(raw)
            if not code:
                continue
            out.update(package_ref.findall(code.replace("\\", "/")))
    return out


def collect_dsc_library_mappings(dsc: Path) -> dict[str, set[str]]:
    out: DefaultDict[str, set[str]] = defaultdict(set)
    section = ""
    try:
        lines = dsc.read_text(errors="replace").splitlines()
    except OSError:
        return {}
    for raw in lines:
        stripped = raw.strip()
        match = re.match(r"\[(.+?)\]", stripped)
        if match:
            section = section_base(match.group(1))
            continue
        if section == "LibraryClasses":
            code = strip_comment(raw)
            if "|" in code:
                name, path = code.split("|", 1)
                name = name.strip()
                path = path.strip()
                if name and path:
                    out[name].add(path)
    return dict(out)


def collect_library_dependency_closure(
    seed_libs: Iterable[str],
    platform_libs: dict[str, set[str]],
    resolver: PackageResolver,
) -> tuple[list[tuple[str, InfInfo]], set[str], list[tuple[str, str]]]:
    """Walk selected library classes through the platform DSC mappings.

    EDK2 library instances are INFs with their own Packages, PCDs, Protocols,
    and LibraryClasses. A selected driver can therefore gain hidden
    dependencies through the platform's chosen library instances. This closure
    is intentionally metadata-only; it does not try to emulate all DSC
    conditional scoping.
    """
    queue = list(sorted(set(seed_libs)))
    seen_classes: set[str] = set()
    seen_instances: set[Path] = set()
    instances: list[tuple[str, InfInfo]] = []
    missing: set[str] = set()
    unresolved: list[tuple[str, str]] = []

    while queue:
        lib = queue.pop(0)
        if lib in seen_classes:
            continue
        seen_classes.add(lib)

        mappings = platform_libs.get(lib, set())
        if not mappings:
            missing.add(lib)
            continue

        for mapping in sorted(mappings):
            resolved = resolver.resolve(mapping)
            if not resolved:
                unresolved.append((lib, mapping))
                continue
            info = resolver.parse_inf(resolved)
            instances.append((lib, info))
            if info.path in seen_instances:
                continue
            seen_instances.add(info.path)
            for child_lib in sorted(info.library_classes()):
                if child_lib not in seen_classes:
                    queue.append(child_lib)

    return instances, missing, unresolved


def collect_dsc_pcds(dsc: Path) -> set[str]:
    out: set[str] = set()
    section = ""
    try:
        lines = dsc.read_text(errors="replace").splitlines()
    except OSError:
        return out
    for raw in lines:
        stripped = raw.strip()
        match = re.match(r"\[(.+?)\]", stripped)
        if match:
            section = section_base(match.group(1))
            continue
        if section.startswith("Pcd"):
            pcd = first_field(raw)
            if pcd and "." in pcd:
                out.add(pcd)
    return out


def scan_all_infs(resolver: PackageResolver) -> list[InfInfo]:
    seen: set[Path] = set()
    infos: list[InfInfo] = []
    for root in resolver.roots:
        for inf in root.rglob("*.inf"):
            if any(part.lower() == "build" for part in inf.parts):
                continue
            inf = inf.resolve()
            if inf in seen:
                continue
            seen.add(inf)
            infos.append(resolver.parse_inf(inf))
    return infos


def module_label(path: Path, resolver: PackageResolver) -> str:
    return resolver.package_path(path)


def summarize_providers(infos: Iterable[InfInfo]) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, set[str]]]:
    strong: DefaultDict[str, set[str]] = defaultdict(set)
    inferred: DefaultDict[str, set[str]] = defaultdict(set)
    unknown: DefaultDict[str, set[str]] = defaultdict(set)
    for info in infos:
        for use in info.protocols:
            label = info.package_path
            if use.role == "provider":
                strong[use.guid].add(label)
            elif use.guid in info.inferred_installed_protocols:
                inferred[use.guid].add(label)
            elif use.role == "unknown":
                unknown[use.guid].add(label)
    return dict(strong), dict(inferred), dict(unknown)


def fmt_set(values: Iterable[str], limit: int = 5) -> str:
    vals = sorted(set(values))
    if not vals:
        return ""
    shown = vals[:limit]
    extra = len(vals) - len(shown)
    text = "<br>".join(f"`{v}`" for v in shown)
    if extra:
        text += f"<br>... {extra} more"
    return text


def build_report(args: argparse.Namespace) -> str:
    root = Path(args.root).resolve()
    package_roots = [
        root / args.edk2,
        root / args.edk2_platforms,
        root / args.edk2_non_osi,
    ]
    resolver = PackageResolver(package_roots)
    dsc = (root / args.platform_dsc).resolve()
    fdf = (root / args.platform_fdf).resolve()
    platform_files = [dsc, fdf]

    target_module_paths: list[Path] = []
    for item in args.csm_module:
        resolved = resolver.resolve(item)
        if not resolved:
            raise SystemExit(f"Could not resolve CSM module: {item}")
        target_module_paths.append(resolved)
    target_infos = [resolver.parse_inf(p) for p in target_module_paths]

    platform_components = collect_inf_references(platform_files, resolver)
    platform_infos = [resolver.parse_inf(p) for p in sorted(platform_components)]
    all_infos = scan_all_infs(resolver)

    all_strong, all_inferred, all_unknown = summarize_providers(all_infos)
    current_strong, current_inferred, current_unknown = summarize_providers(platform_infos)
    target_strong, target_inferred, target_unknown = summarize_providers(target_infos)

    required: DefaultDict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for info in target_infos:
        depex = info.depex_symbols()
        for guid in depex:
            if guid.endswith("ProtocolGuid"):
                required[guid].append((info.package_path, "hard-depex", "[Depex]"))
        for use in info.protocols:
            if use.role == "consumer":
                required[use.guid].append((info.package_path, role_strength(use, info), use.line))
        inf_protocols = {u.guid for u in info.protocols}
        for guid in sorted(info.source_protocol_guids - inf_protocols):
            required[guid].append((info.package_path, "source-ref", "source GUID reference"))

    rows: list[list[str]] = []
    conflict_rows: list[list[str]] = []
    provider_cache: dict[str, tuple[set[str], set[str], set[str], set[str], set[str], set[str]]] = {}
    for guid in sorted(required):
        reqs = required[guid]
        current = set(current_strong.get(guid, set())) | set(current_inferred.get(guid, set()))
        current_decl = set(current_unknown.get(guid, set())) - current
        target = set(target_strong.get(guid, set())) | set(target_inferred.get(guid, set()))
        target_decl = set(target_unknown.get(guid, set())) - target
        available = set(all_strong.get(guid, set())) | set(all_inferred.get(guid, set()))
        available_decl = set(all_unknown.get(guid, set())) - available
        provider_cache[guid] = (current, current_decl, target, target_decl, available, available_decl)
        kind_set = {r[1] for r in reqs}
        kinds = ", ".join(sorted(kind_set))
        req_by = "<br>".join(
            f"`{mod}` ({kind})" for mod, kind in sorted({(mod, kind) for mod, kind, _ in reqs})[:6]
        )
        action = ""
        if current:
            action = "already provided by Quark"
        elif current_decl:
            action = "declared in current Quark components; provider role inferred weakly"
        elif target:
            action = "provided by selected CSM additions"
        elif available:
            action = "provider exists locally; add/port it" if "hard-depex" in kind_set else "runtime/optional path; port only if exercised"
        elif target_decl:
            action = "declared by selected CSM additions; verify implementation"
        elif available_decl:
            action = "declared locally but no provider role inferred"
        else:
            action = "no local provider found" if "hard-depex" in kind_set else "no local provider found; verify if exercised"
        rows.append([
            f"`{guid}`",
            kinds,
            req_by,
            fmt_set(current) or fmt_set(current_decl) or "-",
            fmt_set(target) or fmt_set(target_decl) or "-",
            fmt_set(available) or fmt_set(available_decl) or "-",
            action,
        ])
        pre_existing_current = current - target
        if pre_existing_current and target and is_singleton_protocol(guid):
            conflict_rows.append([f"`{guid}`", fmt_set(pre_existing_current), fmt_set(target), "duplicate provider if selected CSM module is added unchanged"])

    dispatch_rows: list[list[str]] = []
    runtime_gap_rows: list[list[str]] = []
    for guid in sorted(required):
        reqs = required[guid]
        kinds = {r[1] for r in reqs}
        current, current_decl, target, target_decl, available, available_decl = provider_cache[guid]
        req_by = "<br>".join(
            f"`{mod}` ({kind})" for mod, kind in sorted({(mod, kind) for mod, kind, _ in reqs})[:6]
        )
        if "hard-depex" in kinds:
            if current:
                decision = "use existing Quark provider"
                provider = fmt_set(current)
            elif target:
                decision = "add selected CSM provider"
                provider = fmt_set(target)
            elif available:
                decision = "port local provider"
                provider = fmt_set(available)
            else:
                decision = "missing provider"
                provider = fmt_set(current_decl) or fmt_set(target_decl) or fmt_set(available_decl) or "-"
            dispatch_rows.append([f"`{guid}`", req_by, provider or "-", decision])
        elif not current and not target:
            if available:
                decision = "runtime path needs local provider if exercised"
                provider = fmt_set(available)
            elif current_decl or target_decl or available_decl:
                decision = "declared but no provider role inferred; verify if exercised"
                provider = fmt_set(current_decl) or fmt_set(target_decl) or fmt_set(available_decl)
            else:
                decision = "no provider found; verify whether this optional/runtime path matters"
                provider = "-"
            runtime_gap_rows.append([f"`{guid}`", ", ".join(sorted(kinds)), req_by, provider, decision])

    platform_packages = collect_dsc_packages(dsc)
    platform_package_refs = collect_platform_package_refs(platform_files)
    platform_libs = collect_dsc_library_mappings(dsc)
    platform_pcds = collect_dsc_pcds(dsc)

    target_packages = sorted({pkg for info in target_infos for pkg in info.packages()})
    target_libs = sorted({lib for info in target_infos for lib in info.library_classes()})
    target_pcds = sorted({pcd for info in target_infos for pcd in info.pcds()})
    library_instances, missing_library_classes, unresolved_library_mappings = collect_library_dependency_closure(
        target_libs,
        platform_libs,
        resolver,
    )

    package_rows = []
    for pkg in target_packages:
        pkg_root = pkg.split("/", 1)[0]
        explicit = "yes" if pkg in platform_packages else "no"
        referenced = "yes" if pkg_root in platform_package_refs else "no"
        package_rows.append([f"`{pkg}`", explicit, referenced])

    lib_rows = []
    for lib in target_libs:
        lib_rows.append([f"`{lib}`", fmt_set(platform_libs.get(lib, [])) or "missing in Quark DSC global LibraryClasses"])

    pcd_rows = []
    for pcd in target_pcds:
        pcd_rows.append([f"`{pcd}`", "assigned/overridden" if pcd in platform_pcds else "not assigned in Quark DSC"])

    library_instance_rows = []
    for lib, info in library_instances:
        library_instance_rows.append([f"`{lib}`", f"`{info.package_path}`"])

    library_instance_pcds = sorted({
        pcd
        for _, info in library_instances
        for pcd in info.pcds()
    })
    library_instance_pcd_rows = []
    for pcd in library_instance_pcds:
        library_instance_pcd_rows.append([
            f"`{pcd}`",
            "assigned/overridden" if pcd in platform_pcds else "not assigned in Quark DSC",
        ])

    library_instance_protocol_rows = []
    for _, info in library_instances:
        for use in info.protocols:
            if use.role != "consumer":
                continue
            guid = use.guid
            current = set(current_strong.get(guid, set())) | set(current_inferred.get(guid, set()))
            target = set(target_strong.get(guid, set())) | set(target_inferred.get(guid, set()))
            if current or target:
                continue
            available = set(all_strong.get(guid, set())) | set(all_inferred.get(guid, set()))
            library_instance_protocol_rows.append([
                f"`{guid}`",
                f"`{info.package_path}`",
                role_strength(use, info),
                fmt_set(available) or "-",
            ])

    missing_library_rows = [[f"`{lib}`"] for lib in sorted(missing_library_classes)]
    unresolved_library_rows = [[f"`{lib}`", f"`{mapping}`"] for lib, mapping in unresolved_library_mappings]

    source_guid_rows = []
    for info in target_infos:
        inf_guids = {u.guid for u in info.protocols} | info.guids() | info.depex_symbols()
        extra = sorted(info.source_guids - inf_guids)
        if extra:
            source_guid_rows.append([f"`{info.package_path}`", fmt_set(extra, limit=12)])

    service_rows = []
    for info in target_infos:
        for source, line_no, line in info.service_calls[:80]:
            try:
                rel = source.relative_to(root)
            except ValueError:
                rel = source
            service_rows.append([f"`{info.package_path}`", f"`{rel}:{line_no}`", f"`{line}`"])

    selected_provider_rows = []
    for guid in sorted(set(target_strong) | set(target_inferred) | set(target_unknown)):
        selected_provider_rows.append([
            f"`{guid}`",
            fmt_set(target_strong.get(guid, [])) or "-",
            fmt_set(target_inferred.get(guid, [])) or "-",
            fmt_set(target_unknown.get(guid, [])) or "-",
        ])

    lines: list[str] = []
    lines.append("# CSM Dependency Report")
    lines.append("")
    lines.append(f"Generated: {_dt.datetime.now().isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Platform DSC: `{dsc.relative_to(root)}`")
    lines.append(f"- Platform FDF: `{fdf.relative_to(root)}`")
    lines.append("- Package roots:")
    for r in package_roots:
        lines.append(f"  - `{r.relative_to(root)}`")
    lines.append("- Selected CSM modules:")
    for info in target_infos:
        lines.append(f"  - `{info.package_path}`")
    lines.append("")

    lines.append("## Required Protocols")
    lines.append("")
    lines.extend(markdown_table(
        ["Protocol", "Requirement", "Required by", "Current Quark provider", "Selected CSM provider", "Any local provider", "Action"],
        rows,
    ))
    lines.append("")

    lines.append("## Dispatch-Critical Port List")
    lines.append("")
    lines.append("These protocols appear in selected-module `[Depex]` expressions, so the driver will not dispatch until a provider exists.")
    lines.append("")
    lines.extend(markdown_table(["Protocol", "Required by", "Provider to use", "Decision"], dispatch_rows))
    lines.append("")

    lines.append("## Runtime/Optional Provider Gaps")
    lines.append("")
    if runtime_gap_rows:
        lines.extend(markdown_table(["Protocol", "Requirement", "Required by", "Local provider", "Decision"], runtime_gap_rows))
    else:
        lines.append("No runtime-only provider gaps detected.")
    lines.append("")

    lines.append("## Duplicate Provider Risks")
    lines.append("")
    if conflict_rows:
        lines.extend(markdown_table(["Protocol", "Current Quark provider", "Selected CSM provider", "Risk"], conflict_rows))
    else:
        lines.append("No duplicate provider risks detected between current Quark components and selected CSM modules.")
    lines.append("")

    lines.append("## Providers Added By Selected CSM Modules")
    lines.append("")
    lines.extend(markdown_table(["Protocol", "Strong provider", "Inferred provider", "Unknown declaration"], selected_provider_rows))
    lines.append("")

    lines.append("## Package Coverage")
    lines.append("")
    lines.append("Quark.dsc has no normal `[Packages]` section, so the second column records whether the package root is referenced anywhere in the platform DSC/FDF metadata.")
    lines.append("")
    lines.extend(markdown_table(["Package", "Explicit in [Packages]", "Platform references package root"], package_rows))
    lines.append("")

    lines.append("## Library Class Coverage")
    lines.append("")
    lines.extend(markdown_table(["Library class used by selected modules", "Quark DSC mapping"], lib_rows))
    lines.append("")

    lines.append("## PCD Coverage")
    lines.append("")
    lines.extend(markdown_table(["PCD referenced by selected modules", "Quark DSC assignment"], pcd_rows))
    lines.append("")

    lines.append("## Transitive Library Instance Dependencies")
    lines.append("")
    lines.append("This walks the Quark DSC library mappings used by the selected modules, then follows library classes referenced by those library instances.")
    lines.append("")
    if library_instance_rows:
        lines.extend(markdown_table(["Library class", "Resolved Quark library instance"], library_instance_rows))
    else:
        lines.append("No library instances resolved from the selected module library classes.")
    lines.append("")
    if missing_library_rows:
        lines.append("Missing transitive library class mappings:")
        lines.append("")
        lines.extend(markdown_table(["Library class"], missing_library_rows))
        lines.append("")
    if unresolved_library_rows:
        lines.append("Unresolved transitive library mappings:")
        lines.append("")
        lines.extend(markdown_table(["Library class", "Mapping"], unresolved_library_rows))
        lines.append("")
    if library_instance_pcd_rows:
        lines.append("PCDs referenced by resolved library instances:")
        lines.append("")
        lines.extend(markdown_table(["PCD", "Quark DSC assignment"], library_instance_pcd_rows))
        lines.append("")
    if library_instance_protocol_rows:
        lines.append("Protocols consumed by resolved library instances that are not provided by current Quark components or the selected CSM set:")
        lines.append("")
        lines.extend(markdown_table(["Protocol", "Library instance", "Requirement", "Any local provider"], library_instance_protocol_rows))
        lines.append("")
    else:
        lines.append("No additional unresolved protocol consumers found in the resolved library-instance closure.")
        lines.append("")

    lines.append("## Quark Platform Contract Checklist")
    lines.append("")
    lines.append("These are the service contracts that can compile cleanly while still being wrong for Quark/Galileo hardware.")
    lines.append("")
    lines.extend(markdown_table(["Contract", "Evidence", "Required action"], QUARK_CONTRACT_ROWS))
    lines.append("")

    lines.append("## CSM PCD Recommendations")
    lines.append("")
    lines.append("The CSM-related PCDs should be assigned in `Quark.dsc` instead of relying on DEC defaults or OVMF-only token spaces.")
    lines.append("")
    lines.extend(markdown_table(["PCD", "Initial value", "Reason"], QUARK_PCD_RECOMMENDATIONS))
    lines.append("")

    lines.append("## Source-Only GUID References")
    lines.append("")
    if source_guid_rows:
        lines.extend(markdown_table(["Module", "GUIDs referenced in source but not declared in that INF"], source_guid_rows))
    else:
        lines.append("No extra source-only GUID references found.")
    lines.append("")

    lines.append("## EFI Service Call Sites In Selected Sources")
    lines.append("")
    lines.extend(markdown_table(["Module", "Location", "Call"], service_rows))
    lines.append("")

    lines.append("## Quark-Specific Findings")
    lines.append("")
    if "gEfiLegacyRegion2ProtocolGuid" in required:
        current, _, target, _, _, _ = provider_cache["gEfiLegacyRegion2ProtocolGuid"]
        if target:
            lines.append("- Quark currently provides `gEfiLegacyRegion2ProtocolGuid` from `QuarkSocPkg/QuarkNorthCluster/QNCInit/Dxe/QNCInitDxe.inf`; the selected CSM set also provides it. Do not add OVMF `LegacyRegion.c` unchanged. Fork/patch `CsmSupportLib` to use the Quark provider and only install the missing CSM services.")
        elif current:
            lines.append("- Quark currently provides `gEfiLegacyRegion2ProtocolGuid` from `QuarkSocPkg/QuarkNorthCluster/QNCInit/Dxe/QNCInitDxe.inf`; the selected CSM set no longer adds a second provider.")
    if "gEfiLegacyBiosPlatformProtocolGuid" in required:
        lines.append("- `gEfiLegacyBiosPlatformProtocolGuid` is platform-specific. OVMF's implementation is a starting point, but `GetRoutingTable`, `TranslatePirq`, `PrepareToBoot`, and shadow/ROM hooks must match Quark hardware and your PCI/VGA path.")
    if "gEfiLegacy8259ProtocolGuid" in required:
        current, _, _, _, _, _ = provider_cache["gEfiLegacy8259ProtocolGuid"]
        if current:
            lines.append("- `gEfiLegacy8259ProtocolGuid` is provided by `PcAtChipsetPkg/8259InterruptControllerDxe/8259.inf`, keeping the CSM path on the PC/AT chipset package already used by Quark.")
        else:
            lines.append("- `gEfiLegacy8259ProtocolGuid` is not present in current Quark components. Prefer `PcAtChipsetPkg/8259InterruptControllerDxe/8259.inf` so the platform stays on the PC/AT chipset package already used by Quark.")
    if "gEdkiiIoMmuProtocolGuid" in required:
        lines.append("- `gEdkiiIoMmuProtocolGuid` is not in `LegacyBiosDxe`'s `[Depex]`; `LegacyPci.c` only uses it if `LocateProtocol()` succeeds. On Quark without an IOMMU, this is a runtime-optional path, not a dispatch blocker.")
    if "gEfiSioProtocolGuid" in required or "gEfiIsaIoProtocolGuid" in required:
        lines.append("- `LegacySio.c` tries ISA I/O first and SIO second to build legacy serial/floppy/parallel inventory, then returns `EFI_SUCCESS` either way. Port these providers only if that legacy device inventory is required for your boot path.")
    lines.append("- This report is exhaustive for static INF metadata and source GUID/service references in the selected modules. It cannot prove the hardware behavior behind a protocol is correct; it identifies the service surface that must be present.")
    lines.append("")

    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument("--edk2", default="galileo/edk2", help="Path to edk2 root")
    parser.add_argument("--edk2-platforms", default="galileo/edk2-platforms", help="Path to edk2-platforms root")
    parser.add_argument("--edk2-non-osi", default="galileo/edk2-non-osi", help="Path to edk2-non-osi root")
    parser.add_argument("--platform-dsc", default="galileo/edk2/QuarkPlatformPkg/Quark.dsc")
    parser.add_argument("--platform-fdf", default="galileo/edk2/QuarkPlatformPkg/Quark.fdf")
    parser.add_argument("--csm-module", action="append", default=[], help="CSM module INF package path; may be repeated")
    parser.add_argument("--output", "-o", help="Write markdown report to this path")
    args = parser.parse_args(argv)
    if not args.csm_module:
        args.csm_module = list(DEFAULT_CSM_MODULES)
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = build_report(args)
    if args.output:
        out = Path(args.output)
        out.write_text(report + "\n")
        print(out)
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
