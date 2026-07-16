#!/usr/bin/env python3

import argparse
from dataclasses import dataclass
import pathlib
import re
import struct
import subprocess
import sys


REGISTER_PATTERN = re.compile(r"\b(PC|LR|FAR|SP|ESR)\b\s*[:=]\s*(0x[0-9A-Fa-f]+)")
FATAL_MAGIC = 0x32454641  # "AFE2"
FATAL_HEADER_SIZE = 0x150
STACK_TRACE_SIZE_OFFSET = 0x140
STACK_TRACE_OFFSET = 0x150
MAX_STACK_TRACE_SIZE = 0x20


@dataclass(frozen=True)
class FatalReport:
    registers: dict[str, int]
    stack_trace: tuple[int, ...] = ()
    declared_stack_trace_size: int = 0
    warnings: tuple[str, ...] = ()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Decode addresses from an Atmosphere fatal report"
    )
    parser.add_argument(
        "report",
        nargs="?",
        help="Path to a binary or text fatal report",
    )
    parser.add_argument(
        "--elf",
        help="Optional ELF used to symbolize executable addresses",
    )
    parser.add_argument(
        "--addr2line",
        default="aarch64-none-elf-addr2line",
        help="addr2line executable to use",
    )
    parser.add_argument(
        "--slide",
        help=(
            "Address slide/base to subtract before decoding, e.g. 0x7100000000; "
            "defaults to the module base stored in a binary report"
        ),
    )
    parser.add_argument("--pc", help="Manual PC address override")
    parser.add_argument("--lr", help="Manual LR address override")
    parser.add_argument("--far", help="Manual FAR address override")
    return parser.parse_args()


def parse_hex(value: str) -> int:
    return int(value, 16)


def read_report(path: pathlib.Path) -> FatalReport:
    data = path.read_bytes()
    magic = struct.unpack_from("<I", data, 0x0)[0] if len(data) >= 4 else None
    if magic == FATAL_MAGIC:
        if len(data) < FATAL_HEADER_SIZE:
            raise ValueError(
                f"truncated binary fatal report: expected at least "
                f"{FATAL_HEADER_SIZE:#x} bytes, got {len(data):#x}"
            )

        registers = {
            "PC": struct.unpack_from("<Q", data, 0x110)[0],
            "LR": struct.unpack_from("<Q", data, 0x100)[0],
            "SP": struct.unpack_from("<Q", data, 0x108)[0],
            "ESR": struct.unpack_from("<I", data, 0x12C)[0],
            "FAR": struct.unpack_from("<Q", data, 0x130)[0],
            "MODULE_BASE": struct.unpack_from("<Q", data, 0x118)[0],
            "ERROR_DESC": struct.unpack_from("<I", data, 0x4)[0],
        }
        declared_size = struct.unpack_from("<Q", data, STACK_TRACE_SIZE_OFFSET)[0]
        available_size = (len(data) - STACK_TRACE_OFFSET) // 8
        decoded_size = min(
            declared_size,
            MAX_STACK_TRACE_SIZE,
            available_size,
        )
        stack_trace = tuple(
            struct.unpack_from("<Q", data, STACK_TRACE_OFFSET + index * 8)[0]
            for index in range(decoded_size)
        )

        warnings: list[str] = []
        if declared_size > MAX_STACK_TRACE_SIZE:
            warnings.append(
                f"stack trace declares {declared_size} frames; "
                f"clamped to format maximum {MAX_STACK_TRACE_SIZE}"
            )
        if declared_size > available_size:
            warnings.append(
                f"stack trace declares {declared_size} frames, but only "
                f"{available_size} are present"
            )

        return FatalReport(
            registers=registers,
            stack_trace=stack_trace,
            declared_stack_trace_size=declared_size,
            warnings=tuple(warnings),
        )

    registers: dict[str, int] = {}
    text = data.decode(encoding="utf-8", errors="replace")
    for name, value in REGISTER_PATTERN.findall(text):
        registers[name] = parse_hex(value)
    return FatalReport(registers=registers)


def decode_address(addr2line: str, elf: pathlib.Path, address: int) -> str:
    try:
        proc = subprocess.run(
            [addr2line, "-Cfpie", str(elf), hex(address)],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        return f"<unable to run {addr2line}: {error}>"

    output = proc.stdout.strip()
    if proc.returncode != 0:
        detail = proc.stderr.strip() or f"exit status {proc.returncode}"
        return f"<addr2line failed: {detail}>"
    return output if output else "<no symbol>"


def print_executable_address(
    label: str,
    raw: int,
    slide: int,
    addr2line: str,
    elf: pathlib.Path | None,
) -> None:
    print(f"{label}: {hex(raw)}")
    if raw < slide:
        print(f"{label}-adjusted: <address below slide>")
        return

    adjusted = raw - slide
    print(f"{label}-adjusted: {hex(adjusted)}")
    if elf is not None:
        print(f"{label}-symbol: {decode_address(addr2line, elf, adjusted)}")


def main() -> int:
    args = parse_args()
    elf = pathlib.Path(args.elf) if args.elf else None
    if elf is not None and not elf.is_file():
        print(f"ELF not found: {elf}", file=sys.stderr)
        return 1

    slide = parse_hex(args.slide) if args.slide is not None else None
    registers: dict[str, int] = {}
    stack_trace: tuple[int, ...] = ()
    declared_stack_trace_size = 0

    if args.report:
        report_path = pathlib.Path(args.report)
        if not report_path.is_file():
            print(f"Report not found: {report_path}", file=sys.stderr)
            return 1
        try:
            report = read_report(report_path)
        except ValueError as error:
            print(f"Failed to parse report: {error}", file=sys.stderr)
            return 1
        registers.update(report.registers)
        stack_trace = report.stack_trace
        declared_stack_trace_size = report.declared_stack_trace_size
        for warning in report.warnings:
            print(f"Warning: {warning}", file=sys.stderr)

    for name, value in (("PC", args.pc), ("LR", args.lr), ("FAR", args.far)):
        if value:
            registers[name] = parse_hex(value)

    if not registers and not stack_trace:
        print("No addresses found. Pass a report path or --pc/--lr.", file=sys.stderr)
        return 1

    if elf is not None:
        print(f"ELF:   {elf}")
    if slide is None:
        slide = 0
    if "MODULE_BASE" in registers and args.slide is None:
        slide = registers["MODULE_BASE"]

    print(f"Slide: {hex(slide)}")
    if "ERROR_DESC" in registers:
        print(f"ERROR_DESC: {hex(registers['ERROR_DESC'])}")
    if "MODULE_BASE" in registers:
        print(f"MODULE_BASE: {hex(registers['MODULE_BASE'])}")

    for name in ("PC", "LR", "FAR", "SP", "ESR"):
        if name not in registers:
            continue

        if name in ("PC", "LR"):
            print_executable_address(
                name,
                registers[name],
                slide,
                args.addr2line,
                elf,
            )
        else:
            print(f"{name}: {hex(registers[name])}")

    if declared_stack_trace_size or stack_trace:
        print(f"STACK_TRACE_SIZE: {declared_stack_trace_size}")
        print(f"STACK_TRACE_DECODED: {len(stack_trace)}")
        for index, address in enumerate(stack_trace):
            print_executable_address(
                f"STACK_TRACE[{index:02d}]",
                address,
                slide,
                args.addr2line,
                elf,
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
