#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ftplib
import json
from pathlib import Path, PurePosixPath
import sys


REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports"
SYSMODULE_META = REPO_ROOT / "sysmodule" / "res" / "module.json"
SYSMODULE_NSP = REPO_ROOT / "sysmodule" / "out" / "wireguard-nx.nsp"
OVERLAY_OVL = REPO_ROOT / "overlay" / "out" / "wireguard-nx.ovl"
MANAGER_NRO = REPO_ROOT / "manager" / "out" / "wireguard-nx.nro"


def load_title_id() -> str:
    with SYSMODULE_META.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return str(data["program_id"]).removeprefix("0x").upper()


TITLE_ID = load_title_id()

REMOTE_SYSMODULE = PurePosixPath(f"/sdmc:/atmosphere/contents/{TITLE_ID}/exefs.nsp")
REMOTE_OVERLAY = PurePosixPath("/sdmc:/switch/.overlays/wireguard-nx.ovl")
REMOTE_MANAGER = PurePosixPath("/sdmc:/switch/wireguard-nx.nro")
REMOTE_FATAL_DIR = PurePosixPath("/sdmc:/atmosphere/fatal_errors")
REMOTE_LOG_DIR = PurePosixPath("/sdmc:/atmosphere/logs")
REMOTE_LOG_FILE = REMOTE_LOG_DIR / "wgnx-sysmodule.log"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Push WireGuard-NX artifacts to a Switch over FTP and fetch logs/fatal reports.",
        epilog="Pull actions and general flags use upper case shorthands, push actions lower case.",
    )
    parser.add_argument("host", help="FTP host or IP address")
    parser.add_argument("port", type=int, help="FTP port")
    parser.add_argument("--user", default="anonymous", help="FTP username")
    parser.add_argument("--password", default="", help="FTP password")
    parser.add_argument("--timeout", type=float, default=10.0, help="FTP timeout in seconds")

    parser.add_argument("-s", "--push-sysmodule", action="store_true", help="Upload sysmodule NSP to Atmosphere contents")
    parser.add_argument("-o", "--push-overlay", action="store_true", help="Upload overlay OVL to /switch/.overlay/")
    parser.add_argument("-m", "--push-manager", action="store_true", help="Upload manager NRO to /switch/")
    parser.add_argument("-F", "--pull-fatals", action="store_true", help="Download all files from /atmosphere/fatal_errors/")
    parser.add_argument("-L", "--pull-log", action="store_true", help="Download the WireGuard sysmodule log")
    parser.add_argument("-A", "--all", action="store_true", help="Run every push and pull action")
    parser.add_argument(
        "--clean",
        action="store_true",
        help="When pulling files, delete the remote copy after a successful download",
    )

    parser.add_argument(
        "--reports-dir",
        default=str(REPORTS_DIR),
        help="Local directory for downloaded logs and fatal reports",
    )

    args = parser.parse_args()
    if args.all:
        args.push_sysmodule = True
        args.push_overlay = True
        args.push_manager = True
        args.pull_fatals = True
        args.pull_log = True

    if not any((
        args.push_sysmodule,
        args.push_overlay,
        args.push_manager,
        args.pull_fatals,
        args.pull_log,
    )):
        parser.error("select at least one action flag, or use --all")

    return args


def ensure_remote_dirs(ftp: ftplib.FTP, remote_path: PurePosixPath) -> None:
    current = PurePosixPath("/")
    for part in remote_path.parent.parts:
        if part == "/":
            continue
        current /= part
        try:
            ftp.mkd(str(current))
        except ftplib.error_perm as exc:
            message = str(exc)
            if not message.startswith("550"):
                raise


def upload_file(ftp: ftplib.FTP, local_path: Path, remote_path: PurePosixPath) -> None:
    if not local_path.is_file():
        raise FileNotFoundError(f"local file not found: {local_path}")

    ensure_remote_dirs(ftp, remote_path)
    with local_path.open("rb") as handle:
        ftp.storbinary(f"STOR {remote_path}", handle)
    print(f"uploaded {local_path.relative_to(REPO_ROOT)} -> {remote_path}")


def download_file(ftp: ftplib.FTP, remote_path: PurePosixPath, local_path: Path, *, delete_remote: bool = False) -> None:
    local_path.parent.mkdir(parents=True, exist_ok=True)
    with local_path.open("wb") as handle:
        ftp.retrbinary(f"RETR {remote_path}", handle.write)
    print(f"downloaded {remote_path} -> {local_path}")
    if delete_remote:
        ftp.delete(str(remote_path))
        print(f"deleted remote {remote_path}")


def list_remote_files(ftp: ftplib.FTP, remote_dir: PurePosixPath) -> list[str]:
    files: list[str] = []
    ftp.retrlines(f"NLST {remote_dir}", files.append)
    return files


def pull_fatals(ftp: ftplib.FTP, reports_dir: Path, *, delete_remote: bool = False) -> None:
    try:
        remote_entries = list_remote_files(ftp, REMOTE_FATAL_DIR)
    except ftplib.error_perm as exc:
        if str(exc).startswith("550"):
            print(f"no remote fatal reports in {REMOTE_FATAL_DIR}")
            return
        raise

    for entry in remote_entries:
        remote_path = REMOTE_FATAL_DIR / PurePosixPath(entry)
        local_path = reports_dir / remote_path.name
        download_file(ftp, remote_path, local_path, delete_remote=delete_remote)


def pull_log(ftp: ftplib.FTP, reports_dir: Path, *, delete_remote: bool = False) -> None:
    download_file(ftp, REMOTE_LOG_FILE, reports_dir / REMOTE_LOG_FILE.name, delete_remote=delete_remote)


def main() -> int:
    args = parse_args()
    reports_dir = Path(args.reports_dir).resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)

    with ftplib.FTP() as ftp:
        ftp.connect(args.host, args.port, timeout=args.timeout)
        ftp.login(args.user, args.password)

        if args.push_sysmodule:
            upload_file(ftp, SYSMODULE_NSP, REMOTE_SYSMODULE)
        if args.push_overlay:
            upload_file(ftp, OVERLAY_OVL, REMOTE_OVERLAY)
        if args.push_manager:
            upload_file(ftp, MANAGER_NRO, REMOTE_MANAGER)
        if args.pull_fatals:
            pull_fatals(ftp, reports_dir, delete_remote=args.clean)
        if args.pull_log:
            pull_log(ftp, reports_dir, delete_remote=args.clean)

    return 0


if __name__ == "__main__":
    sys.exit(main())
