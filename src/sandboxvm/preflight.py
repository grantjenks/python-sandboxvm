"""Runtime preflight checks."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from .runtime_paths import (
    base_image_path,
    default_persistent_disk_path,
    disks_dir,
    get_app_dir,
    images_dir,
    runtime_metadata_path,
)


def qemu_system_candidates() -> tuple[str, ...]:
    """Return candidate qemu-system executable names."""
    if os.name == "nt":
        return (
            "qemu-system-x86_64.exe",
            "qemu-system-aarch64.exe",
            "qemu-system-x86_64",
            "qemu-system-aarch64",
        )
    return ("qemu-system-x86_64", "qemu-system-aarch64")


def find_qemu_system_binary() -> str | None:
    """Locate qemu-system executable on PATH."""
    for candidate in qemu_system_candidates():
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


@dataclass(frozen=True)
class RuntimeCheckResult:
    app_dir: Path
    qemu_img_binary: str | None
    qemu_system_binary: str | None
    missing_paths: list[Path]

    @property
    def missing_executables(self) -> list[str]:
        names: list[str] = []
        if self.qemu_img_binary is None:
            names.append("qemu-img")
        if self.qemu_system_binary is None:
            names.extend(qemu_system_candidates())
        return names

    @property
    def ok(self) -> bool:
        return not self.missing_executables and not self.missing_paths


def check_runtime(app_dir: str | Path | None = None) -> RuntimeCheckResult:
    """Check that runtime prerequisites exist."""
    resolved_app_dir = get_app_dir(app_dir)
    required_paths = [
        images_dir(resolved_app_dir),
        disks_dir(resolved_app_dir),
        base_image_path(resolved_app_dir),
        default_persistent_disk_path(resolved_app_dir),
        runtime_metadata_path(resolved_app_dir),
    ]
    missing_paths = [path for path in required_paths if not path.exists()]
    return RuntimeCheckResult(
        app_dir=resolved_app_dir,
        qemu_img_binary=shutil.which("qemu-img"),
        qemu_system_binary=find_qemu_system_binary(),
        missing_paths=missing_paths,
    )


def assert_runtime_ready(app_dir: str | Path | None = None) -> None:
    """Raise RuntimeError when runtime prerequisites are missing."""
    result = check_runtime(app_dir)
    if result.ok:
        return

    lines = ["sandboxvm runtime is not ready.", ""]
    if result.missing_executables:
        lines.append("Missing executables:")
        for name in result.missing_executables:
            lines.append(f"- {name}")
        lines.append("")

    if result.missing_paths:
        lines.append("Missing runtime paths:")
        for path in result.missing_paths:
            lines.append(f"- {path}")
        lines.append("")

    lines.append("Run `python -m sandboxvm.setup` to initialize the runtime.")
    raise RuntimeError("\n".join(lines))
