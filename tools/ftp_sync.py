#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ftplib
import json
from pathlib import Path, PurePosixPath
import sys


REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports"
SYSMODULE_META = REPO_ROOT / "wg-sysmodule" / "res" / "module.json"
SYSMODULE_NSP = REPO_ROOT / "wg-sysmodule" / "out" / "wireguard-nx.nsp"
MITM_SYSMODULE_META = REPO_ROOT / "mitm-sysmodule" / "res" / "module.json"
MITM_SYSMODULE_NSP = REPO_ROOT / "mitm-sysmodule" / "out" / "wgnx-mitm.nsp"
OVERLAY_OVL = REPO_ROOT / "overlay" / "out" / "wireguard-nx.ovl"
MANAGER_NRO = REPO_ROOT / "manager" / "out" / "wireguard-nx.nro"


def load_title_id(meta_path: Path) -> str:
    with meta_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return str(data["program_id"]).removeprefix("0x").upper()


SYSMODULE_TITLE_ID = load_title_id(SYSMODULE_META)
MITM_SYSMODULE_TITLE_ID = load_title_id(MITM_SYSMODULE_META)

REMOTE_SYSMODULE = PurePosixPath(f"sdmc:/atmosphere/contents/{SYSMODULE_TITLE_ID}/exefs.nsp")
REMOTE_MITM_SYSMODULE = PurePosixPath(f"sdmc:/atmosphere/contents/{MITM_SYSMODULE_TITLE_ID}/exefs.nsp")
REMOTE_OVERLAY = PurePosixPath("sdmc:/switch/.overlays/wireguard-nx.ovl")
REMOTE_MANAGER = PurePosixPath("sdmc:/switch/wireguard-nx.nro")

REMOTE_FATAL_ERROR_DIR = PurePosixPath("sdmc:/atmosphere/fatal_errors")
REMOTE_FATAL_REPORT_DIR = PurePosixPath("sdmc:/atmosphere/fatal_reports")
REMOTE_CRASH_DIR = PurePosixPath("sdmc:/atmosphere/crash_reports")
REMOTE_ERPT_DIR = PurePosixPath("sdmc:/atmosphere/erpt_reports")

REMOTE_LOG_DIR = PurePosixPath("sdmc:/wgnx")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Push WireGuard-NX artifacts to a Switch over FTP and fetch logs and reports.",
        epilog="Pull actions and general flags use upper case shorthands, push actions lower case.",
    )
    parser.add_argument("host", help="FTP host or IP address")
    parser.add_argument("port", type=int, help="FTP port")
    parser.add_argument("--user", default="anonymous", help="FTP username")
    parser.add_argument("--password", default="", help="FTP password")
    parser.add_argument("--timeout", type=float, default=10.0, help="FTP timeout in seconds")

    parser.add_argument("-s", "--push-sysmodule", action="store_true", help="Upload sysmodule NSP to Atmosphere contents")
    parser.add_argument("-i", "--push-mitm-sysmodule", action="store_true", help="Upload MITM sysmodule NSP to Atmosphere contents")
    parser.add_argument("-o", "--push-overlay", action="store_true", help="Upload overlay OVL to /switch/.overlays/")
    parser.add_argument("-m", "--push-manager", action="store_true", help="Upload manager NRO to /switch/")
    parser.add_argument("-F", "--pull-fatal-errors", action="store_true", help="Download all files from /atmosphere/fatal_errors/")
    parser.add_argument("-R", "--pull-fatal-reports", action="store_true", help="Download all files from /atmosphere/fatal_reports/")
    parser.add_argument("-E", "--pull-erpt-reports", action="store_true", help="Download all files from /atmosphere/erpt_reports/")
    parser.add_argument("-C", "--pull-crashes", action="store_true", help="Download all files from /atmosphere/crash_reports/")
    parser.add_argument("-L", "--pull-logs", action="store_true", help="Download all files from sdmc:/wgnx/ recursively")
    parser.add_argument("-A", "--all", action="store_true", help="Run every push and pull action")
    parser.add_argument(
        "--clean",
        action="store_true",
        help="When pulling files, delete the remote copy after a successful download",
    )

    parser.add_argument(
        "--reports-dir",
        default=str(REPORTS_DIR),
        help="Local directory for downloaded logs and reports; existing local files are not otherwise cleaned",
    )

    args = parser.parse_args()
    if args.all:
        args.push_sysmodule = True
        args.push_mitm_sysmodule = True
        args.push_overlay = True
        args.push_manager = True
        args.pull_fatal_errors = True
        args.pull_fatal_reports = True
        args.pull_erpt_reports = True
        args.pull_crashes = True
        args.pull_logs = True

    if not any((
        args.push_sysmodule,
        args.push_mitm_sysmodule,
        args.push_overlay,
        args.push_manager,
        args.pull_fatal_errors,
        args.pull_fatal_reports,
        args.pull_erpt_reports,
        args.pull_crashes,
        args.pull_logs,
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
            if not str(exc).startswith("550"):
                raise


def upload_file(ftp: ftplib.FTP, local_path: Path, remote_path: PurePosixPath) -> None:
    if not local_path.is_file():
        raise FileNotFoundError(f"local file not found: {local_path}")

    ensure_remote_dirs(ftp, remote_path)
    with local_path.open("rb") as handle:
        ftp.storbinary(f"STOR {remote_path}", handle)
    print(f"uploaded {local_path.relative_to(REPO_ROOT)} -> {remote_path}")


def download_file(
    ftp: ftplib.FTP,
    remote_path: PurePosixPath,
    local_path: Path,
    *,
    delete_remote: bool = False,
) -> bool:
    local_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = local_path.with_name(f".{local_path.name}.part")
    try:
        with temporary_path.open("wb") as handle:
            ftp.retrbinary(f"RETR {remote_path}", handle.write)
    except ftplib.error_perm as exc:
        temporary_path.unlink(missing_ok=True)
        if str(exc).startswith("550"):
            print(f"'{remote_path}' unavailable, skipping.")
            return False
        raise

    temporary_path.replace(local_path)
    print(f"downloaded {remote_path} -> {local_path}")
    if delete_remote:
        try:
            ftp.delete(str(remote_path))
            print(f"deleted remote {remote_path}")
        except ftplib.error_perm as exc:
            if not str(exc).startswith("550"):
                raise
            print(f"'{remote_path}' already absent after download.")
    return True


def list_remote_files(ftp: ftplib.FTP, remote_dir: PurePosixPath) -> list[str]:
    files: list[str] = []
    try:
        ftp.retrlines(f"NLST {remote_dir}", files.append)
    except ftplib.error_temp:
        pass
    except ftplib.error_perm as exc:
        if not str(exc).startswith("550"):
            raise
    return files


def normalize_remote_entry(remote_dir: PurePosixPath, entry: str) -> PurePosixPath:
    remote_path = PurePosixPath(entry)
    if remote_path == remote_dir:
        return remote_path
    if remote_path.is_absolute():
        return remote_path
    return remote_dir / remote_path


def list_remote_entries(ftp: ftplib.FTP, remote_dir: PurePosixPath) -> list[PurePosixPath]:
    return [normalize_remote_entry(remote_dir, entry) for entry in list_remote_files(ftp, remote_dir)]


def is_remote_dir(ftp: ftplib.FTP, remote_path: PurePosixPath) -> bool:
    current_dir = ftp.pwd()
    try:
        ftp.cwd(str(remote_path))
    except ftplib.error_perm:
        return False
    finally:
        ftp.cwd(current_dir)
    return True


def remote_dir_exists(ftp: ftplib.FTP, remote_path: PurePosixPath) -> bool:
    return is_remote_dir(ftp, remote_path)


def pull_remote_tree(
    ftp: ftplib.FTP,
    remote_dir: PurePosixPath,
    local_dir: Path,
    *,
    delete_remote: bool = False,
) -> int:
    downloaded = 0

    for remote_path in list_remote_entries(ftp, remote_dir):
        if remote_path == remote_dir:
            continue

        if is_remote_dir(ftp, remote_path):
            child_downloaded = pull_remote_tree(
                ftp,
                remote_path,
                local_dir / remote_path.name,
                delete_remote=delete_remote,
            )
            downloaded += child_downloaded
            if delete_remote:
                try:
                    ftp.rmd(str(remote_path))
                    print(f"deleted remote {remote_path}")
                except ftplib.error_perm:
                    pass
            continue

        local_dir.mkdir(parents=True, exist_ok=True)
        if download_file(ftp, remote_path, local_dir / remote_path.name, delete_remote=delete_remote):
            downloaded += 1

    return downloaded


def pull_path(ftp: ftplib.FTP, path: PurePosixPath, reports_dir: Path, *, delete_remote: bool = False) -> None:
    if not remote_dir_exists(ftp, path):
        print(f"'{path}' absent, skipping.")
        return

    downloaded = pull_remote_tree(
        ftp,
        path,
        reports_dir / path.name,
        delete_remote=delete_remote,
    )
    if downloaded == 0:
        print(f"'{path}' empty, skipping.")


def main() -> int:
    args = parse_args()
    reports_dir = Path(args.reports_dir).resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)

    with ftplib.FTP() as ftp:
        ftp.connect(args.host, args.port, timeout=args.timeout)
        ftp.login(args.user, args.password)

        if args.push_sysmodule:
            upload_file(ftp, SYSMODULE_NSP, REMOTE_SYSMODULE)
        if args.push_mitm_sysmodule:
            upload_file(ftp, MITM_SYSMODULE_NSP, REMOTE_MITM_SYSMODULE)
        if args.push_overlay:
            upload_file(ftp, OVERLAY_OVL, REMOTE_OVERLAY)
        if args.push_manager:
            upload_file(ftp, MANAGER_NRO, REMOTE_MANAGER)
        if args.pull_fatal_errors:
            pull_path(ftp, REMOTE_FATAL_ERROR_DIR, reports_dir, delete_remote=args.clean)
        if args.pull_fatal_reports:
            pull_path(ftp, REMOTE_FATAL_REPORT_DIR, reports_dir, delete_remote=args.clean)
        if args.pull_erpt_reports:
            pull_path(ftp, REMOTE_ERPT_DIR, reports_dir, delete_remote=args.clean)
        if args.pull_crashes:
            pull_path(ftp, REMOTE_CRASH_DIR, reports_dir, delete_remote=args.clean)
        if args.pull_logs:
            pull_path(ftp, REMOTE_LOG_DIR, reports_dir, delete_remote=args.clean)

    return 0


if __name__ == "__main__":
    sys.exit(main())
