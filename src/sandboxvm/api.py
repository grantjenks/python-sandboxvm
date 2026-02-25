"""Public API primitives."""

from __future__ import annotations

import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from time import monotonic

_MIN_MEMORY_MB = 100
_MAX_MEMORY_MB = 4096
_MIN_PERSISTENT_DISK_MB = 100
_MAX_PERSISTENT_DISK_MB = 10240


@dataclass
class NetworkConfig:
    enabled: bool = False

    def validate(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("`network.enabled` must be a bool.")


@dataclass
class SandboxConfig:
    memory_mb: int = 512
    persistent_disk_mb: int = 1024
    network: NetworkConfig = field(default_factory=NetworkConfig)

    def validate(self) -> None:
        if not isinstance(self.memory_mb, int):
            raise ValueError("`memory_mb` must be an int.")
        if not _MIN_MEMORY_MB <= self.memory_mb <= _MAX_MEMORY_MB:
            raise ValueError(
                f"`memory_mb` must be in [{_MIN_MEMORY_MB}, {_MAX_MEMORY_MB}], "
                f"got: {self.memory_mb}"
            )
        if not isinstance(self.persistent_disk_mb, int):
            raise ValueError("`persistent_disk_mb` must be an int.")
        if not _MIN_PERSISTENT_DISK_MB <= self.persistent_disk_mb <= _MAX_PERSISTENT_DISK_MB:
            raise ValueError(
                "`persistent_disk_mb` must be in "
                f"[{_MIN_PERSISTENT_DISK_MB}, {_MAX_PERSISTENT_DISK_MB}], "
                f"got: {self.persistent_disk_mb}"
            )
        if not isinstance(self.network, NetworkConfig):
            raise ValueError("`network` must be a `NetworkConfig`.")
        self.network.validate()


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class Sandbox:
    """Minimal sandbox shell.

    This execution path intentionally uses a local subprocess backend so the
    package API is usable cross-platform while VM orchestration is implemented.
    """

    def __init__(self, config: SandboxConfig | None = None, *, skip_preflight: bool = False):
        self.config = config or SandboxConfig()
        self.config.validate()
        self.skip_preflight = skip_preflight

    def __enter__(self) -> "Sandbox":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def run(self, command: str, timeout_s: float | None = None) -> RunResult:
        if not isinstance(command, str) or not command.strip():
            raise ValueError("`command` must be a non-empty string.")
        if timeout_s is not None and timeout_s <= 0:
            raise ValueError("`timeout_s` must be positive when provided.")

        argv = _resolve_python_executable(_split_command(command))
        started = monotonic()

        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout_s,
            )
            return RunResult(
                exit_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )
        except subprocess.TimeoutExpired as exc:
            timeout_message = f"Command timed out after {timeout_s} second(s)."
            stderr = _coerce_text(exc.stderr)
            if stderr:
                stderr = f"{stderr.rstrip()}\n{timeout_message}\n"
            else:
                stderr = f"{timeout_message}\n"
            return RunResult(
                exit_code=124,
                stdout=_coerce_text(exc.stdout),
                stderr=stderr,
                timed_out=True,
            )
        except FileNotFoundError as exc:
            elapsed = monotonic() - started
            return RunResult(
                exit_code=127,
                stdout="",
                stderr=f"{exc}\nCommand failed after {elapsed:.3f} second(s).\n",
            )


def _split_command(command: str) -> list[str]:
    try:
        parts = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ValueError(f"Invalid command string: {exc}") from exc
    if not parts:
        raise ValueError("`command` must not be empty after parsing.")
    return parts


def _resolve_python_executable(argv: list[str]) -> list[str]:
    executable = argv[0]
    if shutil.which(executable):
        return argv

    # Allow POSIX-style `python3` commands to run on Windows CI where only
    # `python` may be on PATH by falling back to the current interpreter.
    if executable.lower().startswith("python"):
        resolved = list(argv)
        resolved[0] = sys.executable
        return resolved
    return argv


def _coerce_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value
