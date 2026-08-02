#!/usr/bin/env python3
"""Run formatting and static-analysis checks over WireGuard-NX-owned code."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys


SOURCE_SUFFIXES = {".cpp", ".hpp", ".c", ".h"}
TIDY_CHECKS = (
    "-*,"
    "clang-analyzer-*,"
    "-clang-analyzer-security.ArrayBound,"
    "bugprone-narrowing-conversions,"
    "bugprone-suspicious-stringview-data-usage,"
    "bugprone-use-after-move,"
    "performance-move-const-arg,"
    "performance-unnecessary-value-param"
)


def load_config(root: pathlib.Path, config_path: pathlib.Path) -> dict[str, list[str]]:
    try:
        config = json.loads((root / config_path).read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise RuntimeError(f"configuration file '{config_path}' does not exist") from error
    except json.JSONDecodeError as error:
        raise RuntimeError(f"configuration file '{config_path}' is invalid JSON: {error}") from error

    expected_keys = {
        "source_roots",
        "exclude",
        "include_dirs",
        "suppressions",
        "tidy_source_roots",
        "tidy_exclude",
        "tidy_include_dirs",
        "tidy_arguments",
    }
    unexpected_keys = set(config) - expected_keys
    if unexpected_keys:
        raise RuntimeError(f"configuration file '{config_path}' has unknown keys: {', '.join(sorted(unexpected_keys))}")

    values: dict[str, list[str]] = {}
    for key in expected_keys:
        value = config.get(key, [])
        if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
            raise RuntimeError(f"configuration file '{config_path}' key '{key}' must be an array of paths")
        values[key] = [pathlib.Path(entry) for entry in value]
    if not values["source_roots"]:
        raise RuntimeError(f"configuration file '{config_path}' must define at least one source root")
    return values


def paths_from_arguments(root: pathlib.Path, values: list[str], *, must_be_within_root: bool = True) -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    for value in values:
        path = (root / pathlib.Path(os.path.expandvars(value))).resolve()
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
            excluded = any(path == excluded_source or excluded_source in path.parents for excluded_source in excluded_sources)
            if path.is_file() and path.suffix in SOURCE_SUFFIXES and not excluded:
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


def run_tidy_check(
    root: pathlib.Path,
    tidy: str,
    sources: list[pathlib.Path],
    include_dirs: list[pathlib.Path],
    arguments: list[str],
) -> None:
    source_files = [path for path in sources if path.suffix == ".cpp"]
    if not source_files:
        raise RuntimeError("clang-tidy requires at least one C++ source file")
    subprocess.run(
        [
            require_tool(tidy),
            "--quiet",
            f"--checks={TIDY_CHECKS}",
            "--warnings-as-errors=*",
            *map(str, source_files),
            "--",
            *[os.path.expandvars(argument) for argument in arguments],
            *[f"-I{path}" for path in include_dirs],
        ],
        cwd=root,
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("format", "static", "tidy"))
    parser.add_argument("--root", required=True, type=pathlib.Path)
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--formatter", default="clang-format")
    parser.add_argument("--analyzer", default="cppcheck")
    parser.add_argument("--tidy", default="clang-tidy-21")
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
        elif args.check == "static":
            run_static_check(root, args.analyzer, sources, include_dirs, suppressions)
        else:
            tidy_source_roots = paths_from_arguments(root, config["tidy_source_roots"] or config["source_roots"])
            tidy_excluded_sources = set(paths_from_arguments(root, config["tidy_exclude"]))
            tidy_sources = owned_sources(root, tidy_source_roots, tidy_excluded_sources)
            tidy_include_dirs = paths_from_arguments(
                root,
                config["tidy_include_dirs"] or config["include_dirs"],
                must_be_within_root=False,
            )
            run_tidy_check(root, args.tidy, tidy_sources, tidy_include_dirs, config["tidy_arguments"])
    except (RuntimeError, subprocess.CalledProcessError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
