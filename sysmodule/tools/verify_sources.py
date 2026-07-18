#!/usr/bin/env python3
"""Run formatting and static-analysis checks over WireGuard-NX-owned code."""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys


SOURCE_SUFFIXES = {".cpp", ".hpp", ".c", ".h"}
SOURCE_ROOTS = ("src", "test/host")
VENDORED_SOURCES = {
    pathlib.PurePosixPath("src/wireguard/crypto/monocypher.c"),
    pathlib.PurePosixPath("src/wireguard/crypto/monocypher.h"),
}


def owned_sources(root: pathlib.Path) -> list[pathlib.Path]:
    sources: list[pathlib.Path] = []
    for source_root in SOURCE_ROOTS:
        for path in (root / source_root).rglob("*"):
            if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
                continue
            if path.relative_to(root) in VENDORED_SOURCES:
                continue
            sources.append(path)
    return sorted(sources)


def require_tool(tool: str) -> str:
    resolved = shutil.which(tool)
    if resolved is None:
        raise RuntimeError(
            f"required tool '{tool}' was not found; set the corresponding Make variable "
            "or install the project verification prerequisites"
        )
    return resolved


def run_format_check(root: pathlib.Path, formatter: str) -> None:
    command = [
        require_tool(formatter),
        "--dry-run",
        "--Werror",
        "--style=file",
        "--fallback-style=none",
        *map(str, owned_sources(root)),
    ]
    subprocess.run(command, cwd=root, check=True)


def run_static_check(root: pathlib.Path, analyzer: str) -> None:
    source_files = [path for path in owned_sources(root) if path.suffix == ".cpp"]
    command = [
        require_tool(analyzer),
        "--quiet",
        "--enable=warning,performance,portability",
        "--error-exitcode=1",
        "--std=c++23",
        "--language=c++",
        "--inline-suppr",
        "--suppress=missingIncludeSystem",
        "-Isrc",
        "-Itest/host",
        "-Itest/host/include",
        "-I../common/include",
        *map(str, source_files),
    ]
    subprocess.run(command, cwd=root, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("format", "static"))
    parser.add_argument("--root", required=True, type=pathlib.Path)
    parser.add_argument("--formatter", default="clang-format")
    parser.add_argument("--analyzer", default="cppcheck")
    args = parser.parse_args()

    root = args.root.resolve()
    try:
        if args.check == "format":
            run_format_check(root, args.formatter)
        else:
            run_static_check(root, args.analyzer)
    except (RuntimeError, subprocess.CalledProcessError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
