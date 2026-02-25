from __future__ import annotations

import json
from pathlib import Path

import sandboxvm.preflight as preflight
from sandboxvm.runtime_paths import (
    default_persistent_disk_path,
    disks_dir,
    images_dir,
    initramfs_image_path,
    kernel_image_path,
    runtime_metadata_path,
)


def test_check_runtime_reports_missing_assets(monkeypatch, tmp_path: Path) -> None:
    app_dir = tmp_path / "runtime"
    monkeypatch.setattr(preflight, "find_qemu_system_binary", lambda: None)
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)

    result = preflight.check_runtime(app_dir)

    assert not result.ok
    assert "qemu-img" in result.missing_executables
    assert images_dir(app_dir) in result.missing_paths
    assert kernel_image_path(app_dir) in result.missing_paths
    assert initramfs_image_path(app_dir) in result.missing_paths
    assert default_persistent_disk_path(app_dir) in result.missing_paths


def test_check_runtime_ok_when_assets_exist(monkeypatch, tmp_path: Path) -> None:
    app_dir = tmp_path / "runtime"
    images_dir(app_dir).mkdir(parents=True)
    disks_dir(app_dir).mkdir(parents=True)
    kernel_image_path(app_dir).touch()
    initramfs_image_path(app_dir).touch()
    default_persistent_disk_path(app_dir).touch()
    runtime_metadata_path(app_dir).write_text(
        json.dumps(
            {
                "schema": preflight.RUNTIME_SCHEMA_VERSION,
                "guest_arch": "x86_64",
                "runtime_kind": "distroless-python-initramfs",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(preflight, "find_qemu_system_binary", lambda: "/usr/bin/qemu-system-x86_64")
    monkeypatch.setattr(preflight.shutil, "which", lambda name: "/usr/bin/qemu-img")

    result = preflight.check_runtime(app_dir)

    assert result.ok
    assert not result.missing_paths
    assert not result.missing_executables
    assert not result.metadata_errors


def test_check_runtime_rejects_old_metadata_schema(monkeypatch, tmp_path: Path) -> None:
    app_dir = tmp_path / "runtime"
    images_dir(app_dir).mkdir(parents=True)
    disks_dir(app_dir).mkdir(parents=True)
    kernel_image_path(app_dir).touch()
    initramfs_image_path(app_dir).touch()
    default_persistent_disk_path(app_dir).touch()
    runtime_metadata_path(app_dir).write_text(
        json.dumps(
            {
                "schema": 1,
                "guest_arch": "x86_64",
                "runtime_kind": "distroless-python-initramfs",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(preflight, "find_qemu_system_binary", lambda: "/usr/bin/qemu-system-x86_64")
    monkeypatch.setattr(preflight.shutil, "which", lambda name: "/usr/bin/qemu-img")

    result = preflight.check_runtime(app_dir)

    assert not result.ok
    assert result.metadata_errors


def test_assert_runtime_ready_points_to_setup(monkeypatch, tmp_path: Path) -> None:
    app_dir = tmp_path / "runtime"
    monkeypatch.setattr(preflight, "find_qemu_system_binary", lambda: None)
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)

    try:
        preflight.assert_runtime_ready(app_dir)
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected RuntimeError")

    assert "python -m sandboxvm.setup" in message
