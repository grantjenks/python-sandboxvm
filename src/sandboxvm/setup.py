"""Initialize sandboxvm runtime assets.

Usage:
    python -m sandboxvm.setup
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .preflight import RUNTIME_SCHEMA_VERSION, find_qemu_system_binary
from .runtime_paths import (
    base_image_path,
    default_persistent_disk_path,
    disks_dir,
    get_app_dir,
    images_dir,
    runtime_metadata_path,
)

DEFAULT_BASE_IMAGE_URL = (
    "https://cloud-images.ubuntu.com/minimal/releases/noble/release/"
    "ubuntu-24.04-minimal-cloudimg-amd64.img"
)


def install_hint() -> str:
    """Return an install command hint for QEMU."""
    if sys.platform == "darwin":
        return "brew install qemu"
    if sys.platform.startswith("linux"):
        return "Install qemu via apt/dnf/pacman, e.g. `sudo apt-get install qemu-system-x86 qemu-utils`."
    if sys.platform in {"win32", "cygwin"}:
        return "winget install -e --id SoftwareFreedomConservancy.QEMU"
    return "Install QEMU and ensure `qemu-img` and `qemu-system-*` are on PATH."


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Set up local sandboxvm runtime files.")
    parser.add_argument(
        "--app-dir",
        help="Override sandboxvm app directory (defaults to platform app data location).",
    )
    parser.add_argument(
        "--base-image-url",
        default=DEFAULT_BASE_IMAGE_URL,
        help=(
            "Cloud image URL used to initialize `images/base.qcow2` "
            f"(default: {DEFAULT_BASE_IMAGE_URL})."
        ),
    )
    parser.add_argument(
        "--persistent-disk-mb",
        type=int,
        default=1024,
        help="Size in MB for `disks/default.qcow2` if created (default: 1024).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Recreate base and default disk even if they already exist.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Non-interactive mode. Fails if QEMU is missing.",
    )
    return parser.parse_args(argv)


def _ensure_positive(name: str, value: int) -> None:
    if value <= 0:
        raise SystemExit(f"{name} must be positive, got: {value}")


def _ensure_qemu_available(non_interactive: bool) -> tuple[str, str]:
    qemu_img = shutil.which("qemu-img")
    qemu_system = find_qemu_system_binary()
    if qemu_img and qemu_system and "x86_64" in Path(qemu_system).name.lower():
        return qemu_img, qemu_system

    print("QEMU is not available on PATH.")
    print(f"Install hint: {install_hint()}")
    print("sandboxvm currently requires `qemu-system-x86_64`.")

    if non_interactive:
        raise SystemExit("QEMU missing in non-interactive mode; cannot continue.")

    input("Install QEMU, then press Enter to retry checks (Ctrl+C to abort): ")
    qemu_img = shutil.which("qemu-img")
    qemu_system = find_qemu_system_binary()
    if qemu_img and qemu_system and "x86_64" in Path(qemu_system).name.lower():
        return qemu_img, qemu_system

    raise SystemExit("QEMU is still missing. Install QEMU and rerun `python -m sandboxvm.setup`.")


def _create_qcow2(path: Path, size_mb: int, qemu_img_binary: str, force: bool) -> None:
    if path.exists():
        if not force:
            print(f"exists: {path} (skipping)")
            return
        path.unlink()

    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"creating: {path} ({size_mb} MB)")
    subprocess.run(
        [qemu_img_binary, "create", "-f", "qcow2", str(path), f"{size_mb}M"],
        check=True,
    )


def _download_file(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as response:
        with tempfile.NamedTemporaryFile(delete=False, dir=destination.parent) as tmp:
            shutil.copyfileobj(response, tmp)
            temp_path = Path(tmp.name)
    temp_path.replace(destination)


def _initialize_base_image(
    *,
    path: Path,
    base_image_url: str,
    qemu_img_binary: str,
    force: bool,
) -> None:
    if path.exists() and not force:
        print(f"exists: {path} (skipping)")
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    download_path = path.with_suffix(path.suffix + ".download")
    converted_path = path.with_suffix(path.suffix + ".new")
    for candidate in (download_path, converted_path):
        if candidate.exists():
            candidate.unlink()

    print(f"downloading: {base_image_url}")
    _download_file(base_image_url, download_path)

    try:
        print(f"converting: {download_path} -> {path}")
        subprocess.run(
            [qemu_img_binary, "convert", "-O", "qcow2", str(download_path), str(converted_path)],
            check=True,
        )
        if path.exists():
            path.unlink()
        converted_path.replace(path)
    finally:
        for candidate in (download_path, converted_path):
            if candidate.exists():
                candidate.unlink()


def _write_metadata(
    app_dir: Path,
    qemu_img_binary: str,
    qemu_system_binary: str,
    base_image_url: str,
    persistent_disk_mb: int,
) -> None:
    metadata = {
        "schema": RUNTIME_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "app_dir": str(app_dir),
        "base_image": str(base_image_path(app_dir)),
        "default_persistent_disk": str(default_persistent_disk_path(app_dir)),
        "guest_arch": "x86_64",
        "base_image_url": base_image_url,
        "persistent_disk_mb": persistent_disk_mb,
        "qemu_img_binary": qemu_img_binary,
        "qemu_system_binary": qemu_system_binary,
    }
    metadata_path = runtime_metadata_path(app_dir)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"wrote: {metadata_path}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    _ensure_positive("persistent-disk-mb", args.persistent_disk_mb)

    app_dir = get_app_dir(args.app_dir)
    print(f"sandboxvm app dir: {app_dir}")

    qemu_img_binary, qemu_system_binary = _ensure_qemu_available(non_interactive=args.yes)

    images_dir(app_dir).mkdir(parents=True, exist_ok=True)
    disks_dir(app_dir).mkdir(parents=True, exist_ok=True)
    _initialize_base_image(
        path=base_image_path(app_dir),
        base_image_url=args.base_image_url,
        qemu_img_binary=qemu_img_binary,
        force=args.force,
    )
    _create_qcow2(
        path=default_persistent_disk_path(app_dir),
        size_mb=args.persistent_disk_mb,
        qemu_img_binary=qemu_img_binary,
        force=args.force,
    )
    _write_metadata(
        app_dir=app_dir,
        qemu_img_binary=qemu_img_binary,
        qemu_system_binary=qemu_system_binary,
        base_image_url=args.base_image_url,
        persistent_disk_mb=args.persistent_disk_mb,
    )

    print("")
    print("sandboxvm runtime setup complete.")
    print("Startup can now assume runtime assets exist in the sandboxvm app dir.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
