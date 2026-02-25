"""Runtime preflight checks."""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .runtime_paths import (
    base_image_path,
    default_persistent_disk_path,
    disks_dir,
    get_app_dir,
    images_dir,
    runtime_metadata_path,
)

RUNTIME_SCHEMA_VERSION = 2


def qemu_system_candidates() -> tuple[str, ...]:
    """Return candidate qemu-system executable names."""
    if os.name == "nt":
        return ("qemu-system-x86_64.exe", "qemu-system-x86_64")
    return ("qemu-system-x86_64",)


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
    metadata_errors: list[str]
    runtime_metadata: dict[str, Any] | None

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
        return not self.missing_executables and not self.missing_paths and not self.metadata_errors


def _read_runtime_metadata(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    if not path.exists():
        return None, []

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"Could not parse runtime metadata: {exc}"]

    if not isinstance(raw, dict):
        return None, ["Runtime metadata must be a JSON object."]

    errors: list[str] = []
    schema = raw.get("schema")
    if schema != RUNTIME_SCHEMA_VERSION:
        errors.append(
            f"Runtime metadata schema must be {RUNTIME_SCHEMA_VERSION}, got: {schema!r}."
        )

    guest_arch = raw.get("guest_arch")
    if guest_arch != "x86_64":
        errors.append(f"Runtime guest_arch must be 'x86_64', got: {guest_arch!r}.")

    return raw, errors


def check_runtime(app_dir: str | Path | None = None) -> RuntimeCheckResult:
    """Check that runtime prerequisites exist."""
    resolved_app_dir = get_app_dir(app_dir)
    metadata_path = runtime_metadata_path(resolved_app_dir)
    required_paths = [
        images_dir(resolved_app_dir),
        disks_dir(resolved_app_dir),
        base_image_path(resolved_app_dir),
        default_persistent_disk_path(resolved_app_dir),
        metadata_path,
    ]
    missing_paths = [path for path in required_paths if not path.exists()]
    runtime_metadata, metadata_errors = _read_runtime_metadata(metadata_path)
    return RuntimeCheckResult(
        app_dir=resolved_app_dir,
        qemu_img_binary=shutil.which("qemu-img"),
        qemu_system_binary=find_qemu_system_binary(),
        missing_paths=missing_paths,
        metadata_errors=metadata_errors,
        runtime_metadata=runtime_metadata,
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

    if result.metadata_errors:
        lines.append("Runtime metadata issues:")
        for issue in result.metadata_errors:
            lines.append(f"- {issue}")
        lines.append("")

    lines.append("Run `python -m sandboxvm.setup` to initialize the runtime.")
    raise RuntimeError("\n".join(lines))
