#!/usr/bin/env python3
"""Run formatting and static-analysis checks over WireGuard-NX-owned code."""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys


SOURCE_SUFFIXES = {".cpp", ".hpp", ".c", ".h"}


def load_config(root: pathlib.Path, config_path: pathlib.Path) -> dict[str, list[pathlib.Path]]:
    try:
        config = json.loads((root / config_path).read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise RuntimeError(f"configuration file '{config_path}' does not exist") from error
    except json.JSONDecodeError as error:
        raise RuntimeError(f"configuration file '{config_path}' is invalid JSON: {error}") from error

    expected_keys = {"source_roots", "exclude", "include_dirs", "suppressions"}
    unexpected_keys = set(config) - expected_keys
    if unexpected_keys:
        raise RuntimeError(f"configuration file '{config_path}' has unknown keys: {', '.join(sorted(unexpected_keys))}")

    values: dict[str, list[pathlib.Path]] = {}
    for key in expected_keys:
        value = config.get(key, [])
        if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
            raise RuntimeError(f"configuration file '{config_path}' key '{key}' must be an array of paths")
        values[key] = [pathlib.Path(entry) for entry in value]
    if not values["source_roots"]:
        raise RuntimeError(f"configuration file '{config_path}' must define at least one source root")
    return values


def paths_from_arguments(root: pathlib.Path, values: list[pathlib.Path], *, must_be_within_root: bool = True) -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    for value in values:
        path = (root / value).resolve()
        if must_be_within_root:
            try:
                path.relative_to(root)
            except ValueError as error:
                raise RuntimeError(f"path '{value}' is outside repository root") from error
        paths.append(path)
    return paths


def owned_sources(root: pathlib.Path, source_roots: list[pathlib.Path], excluded_sources: set[pathlib.Path]) -> list[pathlib.Path]:
    sources: list[pathlib.Path] = []
    for source_root in source_roots:
        if not source_root.is_dir():
            raise RuntimeError(f"source root '{source_root.relative_to(root)}' does not exist")
        for path in source_root.rglob("*"):
            if path.is_file() and path.suffix in SOURCE_SUFFIXES and path not in excluded_sources:
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


def run_format_check(root: pathlib.Path, formatter: str, sources: list[pathlib.Path]) -> None:
    subprocess.run(
        [
            require_tool(formatter),
            "--dry-run",
            "--Werror",
            "--style=file",
            "--fallback-style=none",
            *map(str, sources),
        ],
        cwd=root,
        check=True,
    )


def run_static_check(
    root: pathlib.Path, analyzer: str, sources: list[pathlib.Path], include_dirs: list[pathlib.Path], suppressions: list[str]
) -> None:
    source_files = [path for path in sources if path.suffix == ".cpp"]
    subprocess.run(
        [
            require_tool(analyzer),
            "--quiet",
            "--enable=warning,performance,portability",
            "--error-exitcode=1",
            "--std=c++23",
            "--language=c++",
            "--inline-suppr",
            "--suppress=missingIncludeSystem",
            *[f"--suppress={suppression}" for suppression in suppressions],
            *[f"-I{path}" for path in include_dirs],
            *map(str, source_files),
        ],
        cwd=root,
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("format", "static"))
    parser.add_argument("--root", required=True, type=pathlib.Path)
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--formatter", default="clang-format")
    parser.add_argument("--analyzer", default="cppcheck")
    args = parser.parse_args()

    root = args.root.resolve()
    try:
        config = load_config(root, args.config)
        source_roots = paths_from_arguments(root, config["source_roots"])
        excluded_sources = set(paths_from_arguments(root, config["exclude"]))
        include_dirs = paths_from_arguments(root, config["include_dirs"], must_be_within_root=False)
        suppressions = config["suppressions"]
        sources = owned_sources(root, source_roots, excluded_sources)
        if args.check == "format":
            run_format_check(root, args.formatter, sources)
        else:
            run_static_check(root, args.analyzer, sources, include_dirs, suppressions)
    except (RuntimeError, subprocess.CalledProcessError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
