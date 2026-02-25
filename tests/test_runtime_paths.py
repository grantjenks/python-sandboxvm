from __future__ import annotations

from pathlib import Path

from sandboxvm.runtime_paths import (
    APP_DIR_ENV,
    base_image_path,
    default_persistent_disk_path,
    get_app_dir,
    runtime_metadata_path,
)


def test_get_app_dir_uses_argument(tmp_path: Path) -> None:
    explicit = tmp_path / "explicit-dir"
    assert get_app_dir(explicit) == explicit.resolve()


def test_get_app_dir_uses_env_override(monkeypatch, tmp_path: Path) -> None:
    override = tmp_path / "override-dir"
    monkeypatch.setenv(APP_DIR_ENV, str(override))
    assert get_app_dir() == override.resolve()


def test_default_paths_are_under_app_dir(tmp_path: Path) -> None:
    app_dir = tmp_path / "app"
    assert base_image_path(app_dir) == (app_dir / "images" / "base.qcow2").resolve()
    assert default_persistent_disk_path(app_dir) == (
        app_dir / "disks" / "default.qcow2"
    ).resolve()
    assert runtime_metadata_path(app_dir) == (app_dir / "runtime.json").resolve()
