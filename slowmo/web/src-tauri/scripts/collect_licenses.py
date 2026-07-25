#!/usr/bin/env python3
"""Generate third-party license resources for the Tenet desktop bundle."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

LICENSE_CANDIDATES = ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt")

# Shared-library filename globs per platform, used to discover the bundled
# native dependencies in --lib-dir. native-components.json's per-component
# "libraries" patterns are historically written in macOS .dylib form (e.g.
# "libtriton.dylib") since that's the only platform this manifest/script
# originally shipped for; _pattern_variants() below derives the Linux
# (.so / .so.N) and Windows (.dll, no "lib" prefix) equivalents from each
# macOS-form pattern at match time instead of requiring every entry in the
# manifest to be triplicated by hand.
LIBRARY_GLOBS = ("*.dylib", "*.so", "*.so.*", "*.dll")


def _pattern_variants(pattern: str) -> list[str]:
    """Derive the Linux/.so and Windows/.dll equivalents of a macOS-form
    fnmatch pattern (e.g. "libtriton.dylib" or "libz3.*.dylib").

    Naming conventions differ in *where* the version glob sits:
    - macOS:   libNAME[.VERSION].dylib   (version, if any, before ".dylib")
    - Linux:   libNAME.so[.VERSION]      (soname suffix: version AFTER ".so")
    - Windows: NAME.dll or libNAME.dll   (no versioned-suffix convention;
      "lib" prefix isn't standard either, so both forms are accepted since
      MSVC/MinGW builds differ)
    """
    variants = [pattern]
    if pattern.endswith(".dylib"):
        stem = pattern[: -len(".dylib")]  # e.g. "libtriton" or "libz3.*"
        base = re.sub(r"\.\*$", "", stem)  # drop a trailing version glob -> "libz3"
        variants.append(f"{stem}.so")       # unversioned: libz3.*.so (rare)
        variants.append(f"{base}.so")       # unversioned: libz3.so
        variants.append(f"{base}.so.*")     # versioned soname: libz3.so.4
        variants.append(f"{base}.dll")
        if base.startswith("lib"):
            variants.append(f"{base[3:]}.dll")
    return variants


def validate_bundled_libraries(libraries: list[str], components: list[dict[str, Any]]) -> None:
    patterns = [
        variant
        for component in components
        for pattern in component.get("libraries", [])
        for variant in _pattern_variants(pattern)
    ]
    unknown = sorted(name for name in libraries if not any(fnmatch.fnmatch(name, pattern) for pattern in patterns))
    if unknown:
        raise ValueError("Bundled libraries missing from native-components.json: " + ", ".join(unknown))


def _safe_name(name: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "-" for char in name).strip("-")


def _resolve_license(path: str, manifest_dir: Path) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = (manifest_dir / candidate).resolve()
    if not candidate.is_file():
        raise FileNotFoundError(f"Required license file not found: {candidate}")
    return candidate


def _component_is_bundled(component: dict[str, Any], libraries: list[str]) -> bool:
    """Whether `component` should be included in this platform's notices.

    Components without a "libraries" glob (QBDI, LLVM, fmt, nlohmann/json,
    ...) are statically linked or always present, so they're always bundled.
    Components *with* a "libraries" glob (Triton, YARA, Z3, OpenSSL, ...) are
    optional runtime dependencies that only ship on some platforms/build
    configs; skip them here unless the current --lib-dir actually contains a
    matching file. This matters because several such entries' license_files
    are hardcoded Homebrew absolute paths (e.g. /opt/homebrew/opt/z3/...)
    that only exist on the macOS machine that authored the manifest — trying
    to resolve them unconditionally would break license generation on Linux/
    Windows (or on a mac without those Homebrew formulae installed) even
    when the library in question isn't part of this bundle at all.
    """
    patterns = component.get("libraries")
    if not patterns:
        return True
    variants = [variant for pattern in patterns for variant in _pattern_variants(pattern)]
    return any(fnmatch.fnmatch(name, variant) for name in libraries for variant in variants)


def build_native_notices(components: list[dict[str, Any]], manifest_dir: Path, output: Path, libraries: list[str]) -> None:
    native_dir = output / "native"
    native_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        "TENET THIRD-PARTY SOFTWARE NOTICES",
        "==================================",
        "",
        "Tenet includes the following third-party components. The listed licenses",
        "apply only to those components and do not replace the Tenet Terms of Use.",
        "",
    ]
    for component in components:
        if not _component_is_bundled(component, libraries):
            continue
        name = component["name"]
        lines.append(f"{name} {component['version']} — {component['license']}")
        if attribution := component.get("attribution"):
            lines.append(f"  {attribution}")
        component_dir = native_dir / _safe_name(name)
        component_dir.mkdir(exist_ok=True)
        for index, path in enumerate(component["license_files"], start=1):
            source = _resolve_license(path, manifest_dir)
            destination_name = source.name if index == 1 else f"{index}-{source.name}"
            shutil.copyfile(source, component_dir / destination_name)
        lines.append(f"  License text: native/{_safe_name(name)}/")
        lines.append("")
    (output / "THIRD-PARTY-NOTICES.txt").write_text("\n".join(lines), encoding="utf-8")


def _run_json(command: list[str], cwd: Path) -> Any:
    result = subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def collect_npm_notices(web_dir: Path, output: Path, allowed: set[str]) -> None:
    report = _run_json(["pnpm", "licenses", "list", "--prod", "--json"], web_dir)
    unknown = sorted(
        license_id for license_id in report
        if not is_license_allowed(license_id, allowed)
    )
    if unknown:
        raise ValueError("Unapproved npm licenses: " + ", ".join(unknown))
    destination = output / "npm"
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "licenses.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = ["NPM PRODUCTION DEPENDENCIES", "===========================", ""]
    for license_id in sorted(report):
        for package in sorted(report[license_id], key=lambda item: item["name"]):
            lines.append(f"{package['name']} {', '.join(package['versions'])} — {license_id}")
    (destination / "NOTICE.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def collect_cargo_notices(src_tauri_dir: Path, output: Path, allowed: set[str]) -> None:
    metadata = _run_json(["cargo", "metadata", "--format-version", "1", "--locked", "--offline"], src_tauri_dir)
    destination = output / "cargo"
    destination.mkdir(parents=True, exist_ok=True)
    notices: list[str] = ["CARGO DEPENDENCIES", "==================", ""]
    unknown: list[str] = []

    for package in sorted(metadata["packages"], key=lambda item: (item["name"], item["version"])):
        if package["name"] == "tenet-desktop":
            continue
        license_id = package.get("license") or "UNKNOWN"
        if not is_license_allowed(license_id, allowed):
            unknown.append(f"{package['name']} ({license_id})")
            continue
        notices.append(f"{package['name']} {package['version']} — {license_id}")
        package_dir = Path(package["manifest_path"]).parent
        source = next((package_dir / name for name in LICENSE_CANDIDATES if (package_dir / name).is_file()), None)
        if source:
            target_dir = destination / f"{_safe_name(package['name'])}-{package['version']}"
            target_dir.mkdir(exist_ok=True)
            shutil.copyfile(source, target_dir / source.name)

    if unknown:
        raise ValueError("Unapproved or unknown Cargo licenses: " + ", ".join(unknown))
    (destination / "NOTICE.txt").write_text("\n".join(notices) + "\n", encoding="utf-8")


def is_license_allowed(expression: str, allowed: set[str]) -> bool:
    """Evaluate the AND/OR subset of SPDX expressions used by Cargo and pnpm.

    OR means the distributor may choose one allowed branch; AND requires every
    branch. Parentheses are handled recursively. Legacy slash-separated dual
    licenses are treated as OR.
    """
    value = expression.strip()
    if not value:
        return False
    if value.startswith("(") and value.endswith(")") and _is_wrapped(value):
        return is_license_allowed(value[1:-1], allowed)
    parts = _split_top_level(value, " OR ")
    if len(parts) > 1:
        return any(is_license_allowed(part, allowed) for part in parts)
    parts = _split_top_level(value, " AND ")
    if len(parts) > 1:
        return all(is_license_allowed(part, allowed) for part in parts)
    if "/" in value:
        return any(is_license_allowed(part, allowed) for part in value.split("/"))
    return value in allowed


def _is_wrapped(expression: str) -> bool:
    depth = 0
    for index, char in enumerate(expression):
        depth += char == "("
        depth -= char == ")"
        if depth == 0 and index != len(expression) - 1:
            return False
    return depth == 0


def _split_top_level(expression: str, operator: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    index = 0
    while index < len(expression):
        depth += expression[index] == "("
        depth -= expression[index] == ")"
        if depth == 0 and expression.startswith(operator, index):
            parts.append(expression[start:index].strip())
            index += len(operator)
            start = index
            continue
        index += 1
    parts.append(expression[start:].strip())
    return parts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--lib-dir", type=Path, required=True)
    parser.add_argument("--web-dir", type=Path, required=True)
    parser.add_argument("--src-tauri-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest_path = args.manifest.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    components = manifest["components"]
    # --lib-dir holds macOS .dylib, Linux .so[.N], or Windows .dll files
    # depending on which prepare-sidecar-*.{sh,ps1} produced it.
    libraries = sorted(
        {path.name for glob_pattern in LIBRARY_GLOBS for path in args.lib_dir.glob(glob_pattern)}
    )
    validate_bundled_libraries(libraries, components)

    if args.output.exists():
        shutil.rmtree(args.output)
    args.output.mkdir(parents=True)
    build_native_notices(components, manifest_path.parent, args.output, libraries)

    allowed = set(manifest["policy"]["allowed_licenses"])
    collect_npm_notices(args.web_dir, args.output, allowed)
    collect_cargo_notices(args.src_tauri_dir, args.output, allowed)
    shutil.copyfile(manifest_path, args.output / "native-components.json")
    print(f"Generated third-party license resources in {args.output}")


if __name__ == "__main__":
    main()
