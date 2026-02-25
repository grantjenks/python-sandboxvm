"""Runtime path helpers for sandboxvm."""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_DIR_ENV = "SANDBOXVM_HOME"
APP_DIR_NAME = "sandboxvm"


def get_app_dir(app_dir: str | Path | None = None) -> Path:
    """Return sandboxvm app data directory.

    Priority order:
    1) explicit ``app_dir`` argument
    2) ``SANDBOXVM_HOME`` environment variable
    3) platform default app data directory
    """
    if app_dir is not None:
        return Path(app_dir).expanduser().resolve()

    override = os.environ.get(APP_DIR_ENV)
    if override:
        return Path(override).expanduser().resolve()

    if sys.platform == "darwin":
        return (Path.home() / "Library" / "Application Support" / APP_DIR_NAME).resolve()

    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return (Path(appdata) / APP_DIR_NAME).resolve()
        return (Path.home() / "AppData" / "Roaming" / APP_DIR_NAME).resolve()

    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        return (Path(xdg_data_home).expanduser() / APP_DIR_NAME).resolve()
    return (Path.home() / ".local" / "share" / APP_DIR_NAME).resolve()


def images_dir(app_dir: str | Path | None = None) -> Path:
    return get_app_dir(app_dir) / "images"


def disks_dir(app_dir: str | Path | None = None) -> Path:
    return get_app_dir(app_dir) / "disks"


def base_image_path(app_dir: str | Path | None = None) -> Path:
    return images_dir(app_dir) / "base.qcow2"


def kernel_image_path(app_dir: str | Path | None = None) -> Path:
    return images_dir(app_dir) / "kernel"


def initramfs_image_path(app_dir: str | Path | None = None) -> Path:
    return images_dir(app_dir) / "rootfs-initramfs.cpio.gz"


def default_persistent_disk_path(app_dir: str | Path | None = None) -> Path:
    return disks_dir(app_dir) / "default.qcow2"


def runtime_metadata_path(app_dir: str | Path | None = None) -> Path:
    return get_app_dir(app_dir) / "runtime.json"
