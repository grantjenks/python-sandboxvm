"""Public API primitives."""

from __future__ import annotations

import base64
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .preflight import assert_runtime_ready, check_runtime
from .runtime_paths import (
    default_persistent_disk_path,
    get_app_dir,
    initramfs_image_path,
    kernel_image_path,
)

_MIN_MEMORY_MB = 100
_MAX_MEMORY_MB = 4096
_MIN_PERSISTENT_DISK_MB = 100
_MAX_PERSISTENT_DISK_MB = 10240

_STDOUT_BEGIN = "__SANDBOXVM_STDOUT_BEGIN__"
_STDOUT_END = "__SANDBOXVM_STDOUT_END__"
_STDERR_BEGIN = "__SANDBOXVM_STDERR_BEGIN__"
_STDERR_END = "__SANDBOXVM_STDERR_END__"
_EXIT_CODE_PREFIX = "__SANDBOXVM_EXIT_CODE__"
_TIMED_OUT_PREFIX = "__SANDBOXVM_TIMED_OUT__"

_BOOT_TIMEOUT_S = 120.0
_POST_COMMAND_GRACE_S = 10.0


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
    """Command runner backed by a disposable QEMU VM."""

    def __init__(
        self,
        config: SandboxConfig | None = None,
        *,
        app_dir: str | Path | None = None,
        skip_preflight: bool = False,
    ):
        self.config = config or SandboxConfig()
        self.config.validate()
        self.app_dir = get_app_dir(app_dir)
        if not skip_preflight:
            assert_runtime_ready(self.app_dir)

    def __enter__(self) -> "Sandbox":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def run(self, command: str, timeout_s: float | None = None) -> RunResult:
        if not isinstance(command, str) or not command.strip():
            raise ValueError("`command` must be a non-empty string.")
        if timeout_s is not None and timeout_s <= 0:
            raise ValueError("`timeout_s` must be positive when provided.")

        runtime = check_runtime(self.app_dir)
        if not runtime.ok:
            assert_runtime_ready(self.app_dir)
        if runtime.qemu_system_binary is None:
            assert_runtime_ready(self.app_dir)

        qemu_args = self._build_qemu_args(
            qemu_system_binary=runtime.qemu_system_binary,
            command=command,
            timeout_s=timeout_s,
        )
        host_timeout_s = _BOOT_TIMEOUT_S + _POST_COMMAND_GRACE_S
        if timeout_s is not None:
            host_timeout_s += timeout_s

        try:
            completed = subprocess.run(
                qemu_args,
                capture_output=True,
                check=False,
                text=True,
                timeout=host_timeout_s,
            )
        except subprocess.TimeoutExpired as exc:
            return RunResult(
                exit_code=124,
                stdout="",
                stderr=(
                    "VM execution timed out before producing a result.\n"
                    f"{_coerce_text(exc.stdout)}\n{_coerce_text(exc.stderr)}"
                ),
                timed_out=True,
            )

        parsed = _parse_run_result(f"{completed.stdout}\n{completed.stderr}")
        if parsed is None:
            return RunResult(
                exit_code=125,
                stdout="",
                stderr=(
                    "VM did not return structured execution markers.\n"
                    "This usually indicates a boot or guest init failure.\n"
                    f"qemu return code: {completed.returncode}\n"
                    f"{completed.stdout}\n{completed.stderr}"
                ),
            )
        return parsed

    def _build_qemu_args(
        self,
        *,
        qemu_system_binary: str,
        command: str,
        timeout_s: float | None,
    ) -> list[str]:
        cmd_b64 = base64.urlsafe_b64encode(command.encode("utf-8")).decode("ascii")
        append = [
            "console=ttyS0",
            "panic=1",
            "quiet",
            f"sandbox_cmd_b64={cmd_b64}",
        ]
        if timeout_s is not None:
            append.append(f"sandbox_timeout={timeout_s:.6f}")

        args = [
            qemu_system_binary,
            "-machine",
            "pc,accel=tcg",
            "-cpu",
            "max",
            "-smp",
            "1",
            "-m",
            str(self.config.memory_mb),
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            "stdio",
            "-no-reboot",
            "-kernel",
            str(kernel_image_path(self.app_dir)),
            "-initrd",
            str(initramfs_image_path(self.app_dir)),
            "-append",
            " ".join(append),
            "-drive",
            f"if=virtio,format=qcow2,file={default_persistent_disk_path(self.app_dir)}",
            "-device",
            "virtio-rng-pci",
        ]
        if self.config.network.enabled:
            args.extend(["-nic", "user,model=virtio-net-pci"])
        else:
            args.extend(["-nic", "none"])
        return args


def _parse_run_result(raw_output: str) -> RunResult | None:
    normalized = raw_output.replace("\r\n", "\n")
    stdout_b64 = _extract_block(normalized, _STDOUT_BEGIN, _STDOUT_END)
    stderr_b64 = _extract_block(normalized, _STDERR_BEGIN, _STDERR_END)
    exit_code = _extract_int_marker(normalized, _EXIT_CODE_PREFIX)
    timed_out_flag = _extract_int_marker(normalized, _TIMED_OUT_PREFIX)
    if stdout_b64 is None or stderr_b64 is None or exit_code is None or timed_out_flag is None:
        return None
    return RunResult(
        exit_code=exit_code,
        stdout=_decode_b64(stdout_b64),
        stderr=_decode_b64(stderr_b64),
        timed_out=bool(timed_out_flag),
    )


def _extract_block(text: str, begin: str, end: str) -> str | None:
    match = re.search(
        re.escape(begin) + r"\n(.*?)\n" + re.escape(end),
        text,
        flags=re.DOTALL,
    )
    if not match:
        return None
    return match.group(1).strip()


def _extract_int_marker(text: str, prefix: str) -> int | None:
    match = re.search(re.escape(prefix) + r"(-?\d+)", text)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _decode_b64(value: str) -> str:
    if not value:
        return ""
    try:
        data = base64.b64decode(value, validate=True)
    except Exception:
        return ""
    return data.decode("utf-8", errors="replace")


def _coerce_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value
