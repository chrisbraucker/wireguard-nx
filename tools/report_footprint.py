#!/usr/bin/env python3

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = REPO_ROOT / "tools/baselines/sysmodule-footprint.json"
DEFAULT_ELF = REPO_ROOT / "wg-sysmodule/out/wireguard-nx.elf"
DEFAULT_NSO = REPO_ROOT / "wg-sysmodule/out/wireguard-nx.nso"
DEFAULT_NSP = REPO_ROOT / "wg-sysmodule/out/wireguard-nx.nsp"


def find_size_tool() -> str:
    configured = os.environ.get("SIZE")
    if configured:
        return configured

    discovered = shutil.which("aarch64-none-elf-size")
    if discovered:
        return discovered

    devkitpro = os.environ.get("DEVKITPRO")
    if devkitpro:
        candidate = Path(devkitpro) / "devkitA64/bin/aarch64-none-elf-size"
        if candidate.is_file():
            return str(candidate)

    raise RuntimeError("aarch64-none-elf-size was not found")


def read_elf_metrics(elf: Path) -> dict[str, int]:
    output = subprocess.run(
        [find_size_tool(), "--format=berkeley", str(elf)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if len(output) < 2:
        raise RuntimeError(f"unexpected size output for {elf}")

    fields = output[1].split()
    if len(fields) < 3:
        raise RuntimeError(f"unexpected size row for {elf}: {output[1]}")

    text, data, bss = (int(value, 10) for value in fields[:3])
    return {
        "text": text,
        "data": data,
        "bss": bss,
        "static_total": text + data + bss,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Report sysmodule footprint against a named baseline.")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--elf", type=Path, default=DEFAULT_ELF)
    parser.add_argument("--nso", type=Path, default=DEFAULT_NSO)
    parser.add_argument("--nsp", type=Path, default=DEFAULT_NSP)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    for path in (args.baseline, args.elf, args.nso, args.nsp):
        if not path.is_file():
            print(f"missing footprint input: {path}", file=sys.stderr)
            return 2

    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    metrics = read_elf_metrics(args.elf)
    metrics["nso"] = args.nso.stat().st_size
    metrics["nsp"] = args.nsp.stat().st_size
    baseline_metrics = baseline["metrics"]
    limits = baseline.get("limits", {})

    print(
        f"FOOTPRINT baseline={baseline['name']} "
        f"revision={baseline.get('revision', 'unknown')}")
    print(f"{'metric':<14}{'current':>12}{'baseline':>12}{'delta':>12}{'limit':>12}")

    failed = False
    for name in ("text", "data", "bss", "static_total", "nso", "nsp"):
        current = metrics[name]
        previous = int(baseline_metrics[name])
        limit = limits.get(name)
        limit_text = str(limit) if limit is not None else "-"
        print(
            f"{name:<14}{current:>12}{previous:>12}"
            f"{current - previous:>+12}{limit_text:>12}")
        if limit is not None and current > int(limit):
            failed = True

    if failed:
        print("FOOTPRINT result=FAILED absolute budget exceeded", file=sys.stderr)
        return 1

    print("FOOTPRINT result=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
