#!/usr/bin/env python3

import argparse
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / "tools/baselines/sysmodule-stack-chains.json"
DEFAULT_STACK_DIR = REPO_ROOT / "wg-sysmodule/build"
DEFAULT_MODULE_JSON = REPO_ROOT / "wg-sysmodule/res/module.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check target compiler stack usage and known callback chains.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--stack-dir", type=Path, default=DEFAULT_STACK_DIR)
    parser.add_argument("--module-json", type=Path, default=DEFAULT_MODULE_JSON)
    return parser.parse_args()


def read_stack_usage(stack_dir: Path) -> list[tuple[str, int, str]]:
    records: list[tuple[str, int, str]] = []
    for path in sorted(stack_dir.rglob("*.su")):
        for line_number, raw_line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(),
                start=1):
            fields = raw_line.rsplit("\t", 2)
            if len(fields) != 3:
                raise RuntimeError(
                    f"malformed stack-usage row {path}:{line_number}: {raw_line}")
            descriptor, size_text, qualifier = fields
            try:
                size = int(size_text, 10)
            except ValueError as error:
                raise RuntimeError(
                    f"invalid stack size {path}:{line_number}: {size_text}") from error
            records.append((descriptor, size, qualifier))
    if not records:
        raise RuntimeError(f"no .su files found below {stack_dir}")
    return records


def find_frame(
    records: list[tuple[str, int, str]],
    matcher: str,
) -> tuple[str, int, str]:
    matches = [record for record in records if matcher in record[0]]
    if len(matches) != 1:
        raise RuntimeError(
            f"stack matcher {matcher!r} selected {len(matches)} rows; expected one")
    return matches[0]


def main() -> int:
    args = parse_args()
    for path in (args.config, args.module_json):
        if not path.is_file():
            print(f"missing stack input: {path}", file=sys.stderr)
            return 2

    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        module = json.loads(args.module_json.read_text(encoding="utf-8"))
        records = read_stack_usage(args.stack_dir)
        configured_stack = int(config["thread_stack_bytes"])
        module_stack = int(module["main_thread_stack_size"], 0)
        if module_stack != configured_stack:
            raise RuntimeError(
                f"module main stack is {module_stack}, expected {configured_stack}")

        frame_limit = int(config["individual_frame_limit"])
        oversized = [
            (descriptor, size)
            for descriptor, size, _ in records
            if size > frame_limit
        ]
        if oversized:
            for descriptor, size in oversized:
                print(
                    f"STACK frame=FAILED bytes={size} function={descriptor}",
                    file=sys.stderr)
            return 1

        minimum_margin = int(config["minimum_margin"])
        failed = False
        for chain in config["chains"]:
            total = 0
            details = []
            for frame in chain["frames"]:
                descriptor, size, qualifier = find_frame(records, frame["match"])
                if qualifier != "static":
                    raise RuntimeError(
                        f"non-static stack estimate for {descriptor}: {qualifier}")
                total += size
                details.append(f"{frame['label']}={size}")

            margin = configured_stack - total
            result = "PASS" if margin >= minimum_margin else "FAILED"
            print(
                f"STACK chain={chain['name']} bytes={total} "
                f"stack={configured_stack} margin={margin} result={result}")
            print(f"  {'; '.join(details)}")
            failed = failed or margin < minimum_margin

        print(
            f"STACK frames={len(records)} limit={frame_limit} "
            f"result={'FAILED' if failed else 'PASS'}")
        return 1 if failed else 0
    except (KeyError, TypeError, ValueError, RuntimeError) as error:
        print(f"stack check failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
