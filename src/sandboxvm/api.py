"""Minimal API primitives."""

from __future__ import annotations

from dataclasses import dataclass

from .preflight import assert_runtime_ready


@dataclass
class SandboxConfig:
    memory_mb: int = 512
    persistent_disk_mb: int = 1024
    network_enabled: bool = False


class Sandbox:
    """Minimal sandbox shell.

    Full VM launch and command execution are intentionally deferred.
    """

    def __init__(self, config: SandboxConfig | None = None, *, skip_preflight: bool = False):
        self.config = config or SandboxConfig()
        if not skip_preflight:
            assert_runtime_ready()

    def __enter__(self) -> "Sandbox":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def run(self, command: str, timeout_s: float | None = None) -> None:
        raise NotImplementedError("VM command execution is not implemented yet.")
