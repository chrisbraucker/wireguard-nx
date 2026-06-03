#!/usr/bin/env python3

import argparse
import pathlib
import re
import struct
import subprocess
import sys


REGISTER_PATTERN = re.compile(r"\b(PC|LR|FAR|SP|ESR)\b\s*[:=]\s*(0x[0-9A-Fa-f]+)")
FATAL_MAGIC = 0x32454641  # "AFE2"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Decode Atmosphere fatal report addresses against wireguard-nx.elf"
    )
    parser.add_argument(
        "report",
        nargs="?",
        help="Path to a text fatal report to parse for PC/LR/FAR/ESR values",
    )
    parser.add_argument(
        "--elf",
        default="sysmodule/out/wireguard-nx.elf",
        help="Path to the ELF with symbols",
    )
    parser.add_argument(
        "--addr2line",
        default="aarch64-none-elf-addr2line",
        help="addr2line executable to use",
    )
    parser.add_argument(
        "--slide",
        default="0x0",
        help="Address slide/base to subtract before decoding, e.g. 0x7100000000",
    )
    parser.add_argument("--pc", help="Manual PC address override")
    parser.add_argument("--lr", help="Manual LR address override")
    parser.add_argument("--far", help="Manual FAR address override")
    return parser.parse_args()


def parse_hex(value: str) -> int:
    return int(value, 16)


def read_report(path: pathlib.Path) -> dict[str, int]:
    data = path.read_bytes()
    if len(data) >= 0x150:
        magic = struct.unpack_from("<I", data, 0x0)[0]
        if magic == FATAL_MAGIC:
            return {
                "PC": struct.unpack_from("<Q", data, 0x110)[0],
                "LR": struct.unpack_from("<Q", data, 0x100)[0],
                "SP": struct.unpack_from("<Q", data, 0x108)[0],
                "ESR": struct.unpack_from("<I", data, 0x12C)[0],
                "FAR": struct.unpack_from("<Q", data, 0x130)[0],
                "MODULE_BASE": struct.unpack_from("<Q", data, 0x118)[0],
                "ERROR_DESC": struct.unpack_from("<I", data, 0x4)[0],
            }

    registers: dict[str, int] = {}
    text = data.decode(encoding="utf-8", errors="replace")
    for name, value in REGISTER_PATTERN.findall(text):
        registers[name] = parse_hex(value)
    return registers


def decode_address(addr2line: str, elf: pathlib.Path, address: int) -> str:
    proc = subprocess.run(
        [addr2line, "-Cfpie", str(elf), hex(address)],
        capture_output=True,
        text=True,
        check=False,
    )
    output = proc.stdout.strip()
    return output if output else "<no symbol>"


def main() -> int:
    args = parse_args()
    elf = pathlib.Path(args.elf)
    if not elf.is_file():
        print(f"ELF not found: {elf}", file=sys.stderr)
        return 1

    slide = parse_hex(args.slide)
    registers: dict[str, int] = {}

    if args.report:
        report_path = pathlib.Path(args.report)
        if not report_path.is_file():
            print(f"Report not found: {report_path}", file=sys.stderr)
            return 1
        registers.update(read_report(report_path))

    for name, value in (("PC", args.pc), ("LR", args.lr), ("FAR", args.far)):
        if value:
            registers[name] = parse_hex(value)

    if not registers:
        print("No addresses found. Pass a report path or --pc/--lr.", file=sys.stderr)
        return 1

    print(f"ELF:   {elf}")
    if "MODULE_BASE" in registers and slide == 0:
        slide = registers["MODULE_BASE"]

    print(f"Slide: {hex(slide)}")
    if "ERROR_DESC" in registers:
        print(f"ERROR_DESC: {hex(registers['ERROR_DESC'])}")
    if "MODULE_BASE" in registers:
        print(f"MODULE_BASE: {hex(registers['MODULE_BASE'])}")

    for name in ("PC", "LR", "FAR", "SP", "ESR"):
        if name not in registers:
            continue

        raw = registers[name]
        print(f"{name}:  {hex(raw)}")

        if name in ("PC", "LR"):
            adjusted = raw - slide
            print(f"{name}-adjusted: {hex(adjusted)}")
            print(f"{name}-symbol:   {decode_address(args.addr2line, elf, adjusted)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
