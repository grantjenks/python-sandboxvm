"""Public API primitives."""

from __future__ import annotations

import base64
import collections
import functools
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import uuid
from collections.abc import Sequence
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

_BOOT_TIMEOUT_S = 120.0
_BOOT_ATTEMPT_FALLBACK_TIMEOUT_S = 30.0
_POST_COMMAND_GRACE_S = 10.0
_DEFAULT_COMMAND_TIMEOUT_S = 60.0
_TRANSFER_TIMEOUT_S = 120.0
_QEMU_HELP_TIMEOUT_S = 5.0
_SHUTDOWN_TIMEOUT_S = 10.0
_CONTROL_CONNECT_TIMEOUT_S = 15.0

_REQ_PREFIX = "__SANDBOXVM_REQ__"
_RESP_PREFIX = "__SANDBOXVM_RESP__"
_READY_PREFIX = "__SANDBOXVM_READY__"
_FRAME_PREFIXES = (_READY_PREFIX, _RESP_PREFIX, _REQ_PREFIX)


@dataclass(frozen=True)
class _LaunchPlan:
    machine: str
    accel: str

    @property
    def label(self) -> str:
        return f"{self.machine}/{self.accel}"


@dataclass
class _GuestState:
    process: subprocess.Popen[str]
    control_socket: socket.socket
    control_reader: io.TextIOBase
    control_writer: io.TextIOBase
    reader_thread: threading.Thread
    qemu_log_thread: threading.Thread
    messages: queue.Queue[tuple[str, dict[str, object] | None]]
    recent_logs: collections.deque[str]
    launch: _LaunchPlan


# Imported lazily after _GuestState typing to avoid reordering lint churn.
import queue  # noqa: E402  # isort: skip


@functools.lru_cache(maxsize=8)
def _qemu_help_text(qemu_system_binary: str, topic: str) -> str:
    try:
        completed = subprocess.run(
            [qemu_system_binary, topic, "help"],
            capture_output=True,
            check=False,
            text=True,
            timeout=_QEMU_HELP_TIMEOUT_S,
        )
    except Exception:
        return ""
    return f"{completed.stdout}\n{completed.stderr}"


@functools.lru_cache(maxsize=8)
def _available_accelerators(qemu_system_binary: str) -> tuple[str, ...]:
    text = _qemu_help_text(qemu_system_binary, "-accel").lower()
    known = ("kvm", "hvf", "whpx", "hax", "tcg")
    available = [name for name in known if re.search(rf"\b{name}\b", text)]
    if not available:
        return ("tcg",)
    return tuple(available)


@functools.lru_cache(maxsize=8)
def _supports_microvm_machine(qemu_system_binary: str) -> bool:
    text = _qemu_help_text(qemu_system_binary, "-machine").lower()
    return bool(re.search(r"^\s*microvm(?:\s|$)", text, flags=re.MULTILINE))


def _preferred_accelerators_for_platform(platform: str) -> tuple[str, ...]:
    if platform.startswith("linux"):
        return ("kvm", "tcg")

    # Host accelerators are opt-in on macOS/Windows to keep default behavior
    # deterministic across local shells and CI runners.
    host_accel_opt_in = os.environ.get("SANDBOXVM_USE_HOST_ACCEL") == "1"
    if platform == "darwin":
        return ("hvf", "tcg") if host_accel_opt_in else ("tcg", "hvf")
    if platform in {"win32", "cygwin"}:
        return ("whpx", "tcg") if host_accel_opt_in else ("tcg", "whpx")
    return ("tcg",)


def _pick_accelerator(*, platform: str, available: set[str]) -> str:
    for candidate in _preferred_accelerators_for_platform(platform):
        if candidate in available:
            return candidate
    if "tcg" in available:
        return "tcg"
    return "tcg"


def _build_launch_plans(
    *,
    platform: str,
    available_accelerators: set[str],
    supports_microvm: bool,
) -> list[_LaunchPlan]:
    preferred = _pick_accelerator(platform=platform, available=available_accelerators)

    plans: list[_LaunchPlan] = []
    if supports_microvm and platform.startswith("linux") and preferred in {"kvm", "tcg"}:
        plans.append(_LaunchPlan(machine="microvm", accel=preferred))

    plans.append(_LaunchPlan(machine="pc", accel=preferred))

    if preferred != "tcg":
        if supports_microvm and platform.startswith("linux"):
            plans.append(_LaunchPlan(machine="microvm", accel="tcg"))
        plans.append(_LaunchPlan(machine="pc", accel="tcg"))

    deduped: list[_LaunchPlan] = []
    seen: set[tuple[str, str]] = set()
    for plan in plans:
        key = (plan.machine, plan.accel)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(plan)
    return deduped


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
    duration_s: float | None = None


@dataclass(frozen=True)
class TransferResult:
    bytes_transferred: int
    files_transferred: int
    duration_s: float | None = None


class Sandbox:
    """Command runner backed by a disposable QEMU VM session."""

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

        self._state: _GuestState | None = None
        self._request_lock = threading.Lock()

    def __enter__(self) -> "Sandbox":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
        return None

    @property
    def is_running(self) -> bool:
        return self._state is not None and self._state.process.poll() is None

    def start(self, *, timeout_s: float | None = None) -> None:
        if self.is_running:
            return

        runtime = check_runtime(self.app_dir)
        if not runtime.ok:
            assert_runtime_ready(self.app_dir)
        if runtime.qemu_system_binary is None:
            assert_runtime_ready(self.app_dir)

        qemu_system_binary = runtime.qemu_system_binary
        launch_plans = _build_launch_plans(
            platform=sys.platform,
            available_accelerators=set(_available_accelerators(qemu_system_binary)),
            supports_microvm=_supports_microvm_machine(qemu_system_binary),
        )

        errors: list[str] = []
        for index, launch in enumerate(launch_plans):
            try:
                state = self._spawn_guest_process(
                    qemu_system_binary=qemu_system_binary,
                    launch=launch,
                )
            except Exception as exc:
                errors.append(f"{launch.label}: {exc}")
                continue
            attempt_timeout = _boot_timeout_for_attempt(
                attempt=index,
                total_attempts=len(launch_plans),
                requested_timeout_s=timeout_s,
            )
            try:
                self._wait_for_ready(state, timeout_s=attempt_timeout)
                self._state = state
                return
            except Exception as exc:
                errors.append(f"{launch.label}: {exc}")
                self._close_state(state, force=True)

        lines = ["Failed to boot sandbox VM."]
        if errors:
            lines.append("")
            lines.append("Launch attempts:")
            lines.extend(f"- {item}" for item in errors)
        raise RuntimeError("\n".join(lines))

    def stop(self, *, timeout_s: float | None = None) -> None:
        state = self._state
        if state is None:
            return
        self._state = None
        self._close_state(
            state,
            force=False,
            timeout_s=_SHUTDOWN_TIMEOUT_S if timeout_s is None else timeout_s,
        )

    def run(
        self,
        command: str | Sequence[str],
        *,
        timeout_s: float | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        stdin: str | bytes | None = None,
    ) -> RunResult:
        command_payload = _normalize_command_payload(command)
        if timeout_s is not None and timeout_s <= 0:
            raise ValueError("`timeout_s` must be positive when provided.")
        if cwd is not None and (not isinstance(cwd, str) or not cwd.strip()):
            raise ValueError("`cwd` must be a non-empty string when provided.")

        stdin_b64: str | None = None
        if stdin is not None:
            if isinstance(stdin, str):
                stdin_bytes = stdin.encode("utf-8")
            elif isinstance(stdin, bytes):
                stdin_bytes = stdin
            else:
                raise ValueError("`stdin` must be `str` or `bytes` when provided.")
            stdin_b64 = base64.b64encode(stdin_bytes).decode("ascii")

        payload: dict[str, object] = {
            "action": "run",
            "command": command_payload,
        }
        if timeout_s is not None:
            payload["timeout_s"] = float(timeout_s)
        if cwd is not None:
            payload["cwd"] = cwd
        if env is not None:
            payload["env"] = _validate_env(env)
        if stdin_b64 is not None:
            payload["stdin_b64"] = stdin_b64

        try:
            result = self._request(
                payload,
                timeout_s=_command_wait_timeout(timeout_s),
            )
        except TimeoutError as exc:
            return RunResult(
                exit_code=124,
                stdout="",
                stderr=str(exc),
                timed_out=True,
            )
        except Exception as exc:
            return RunResult(
                exit_code=125,
                stdout="",
                stderr=str(exc),
            )

        return RunResult(
            exit_code=_coerce_int(result.get("exit_code"), default=125),
            stdout=_decode_b64(result.get("stdout_b64", "")),
            stderr=_decode_b64(result.get("stderr_b64", "")),
            timed_out=bool(result.get("timed_out", False)),
            duration_s=_coerce_float_or_none(result.get("duration_s")),
        )

    def put_bytes(
        self,
        data: bytes,
        guest_path: str,
        *,
        mode: int = 0o644,
        overwrite: bool = True,
    ) -> TransferResult:
        if not isinstance(data, bytes):
            raise ValueError("`data` must be bytes.")

        result = self._request(
            {
                "action": "write_file",
                "path": guest_path,
                "data_b64": base64.b64encode(data).decode("ascii"),
                "mode": int(mode),
                "overwrite": bool(overwrite),
            },
            timeout_s=_TRANSFER_TIMEOUT_S,
        )
        return _transfer_result_from_payload(result)

    def get_bytes(self, guest_path: str, *, max_bytes: int | None = None) -> bytes:
        result = self._request(
            {
                "action": "read_file",
                "path": guest_path,
                "max_bytes": max_bytes,
            },
            timeout_s=_TRANSFER_TIMEOUT_S,
        )
        return _decode_b64_to_bytes(result.get("data_b64", ""))

    def put_file(
        self,
        host_path: str | Path,
        guest_path: str,
        *,
        mode: int | None = None,
        overwrite: bool = True,
    ) -> TransferResult:
        source = Path(host_path)
        data = source.read_bytes()
        effective_mode = mode if mode is not None else (source.stat().st_mode & 0o777)
        return self.put_bytes(data, guest_path, mode=effective_mode, overwrite=overwrite)

    def get_file(
        self,
        guest_path: str,
        host_path: str | Path,
        *,
        overwrite: bool = True,
    ) -> TransferResult:
        result = self._request(
            {
                "action": "read_file",
                "path": guest_path,
                "max_bytes": None,
            },
            timeout_s=_TRANSFER_TIMEOUT_S,
        )

        destination = Path(host_path)
        if destination.exists() and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing path: {destination}")

        destination.parent.mkdir(parents=True, exist_ok=True)
        data = _decode_b64_to_bytes(result.get("data_b64", ""))
        destination.write_bytes(data)
        mode = _coerce_int(result.get("mode"), default=0o644)
        try:
            destination.chmod(mode)
        except OSError:
            pass

        return TransferResult(
            bytes_transferred=len(data),
            files_transferred=1,
            duration_s=_coerce_float_or_none(result.get("duration_s")),
        )

    def put_dir(
        self,
        host_dir: str | Path,
        guest_dir: str,
        *,
        overwrite: bool = True,
    ) -> TransferResult:
        source_dir = Path(host_dir)
        if not source_dir.is_dir():
            raise NotADirectoryError(source_dir)

        with io.BytesIO() as buffer:
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                archive.add(source_dir, arcname=".")
            tar_bytes = buffer.getvalue()

        result = self._request(
            {
                "action": "extract_tar",
                "path": guest_dir,
                "tar_b64": base64.b64encode(tar_bytes).decode("ascii"),
                "overwrite": bool(overwrite),
            },
            timeout_s=_TRANSFER_TIMEOUT_S,
        )
        return _transfer_result_from_payload(result)

    def get_dir(
        self,
        guest_dir: str,
        host_dir: str | Path,
        *,
        overwrite: bool = True,
    ) -> TransferResult:
        result = self._request(
            {
                "action": "archive_dir",
                "path": guest_dir,
            },
            timeout_s=_TRANSFER_TIMEOUT_S,
        )

        destination = Path(host_dir)
        if destination.exists():
            if not overwrite:
                raise FileExistsError(f"Refusing to overwrite existing path: {destination}")
            if destination.is_dir():
                shutil.rmtree(destination)
            else:
                destination.unlink()
        destination.mkdir(parents=True, exist_ok=True)

        tar_bytes = _decode_b64_to_bytes(result.get("tar_b64", ""))
        _safe_extract_tar_bytes(tar_bytes, destination)

        return TransferResult(
            bytes_transferred=len(tar_bytes),
            files_transferred=_coerce_int(result.get("files_transferred"), default=0),
            duration_s=_coerce_float_or_none(result.get("duration_s")),
        )

    def _request(self, payload: dict[str, object], *, timeout_s: float) -> dict[str, object]:
        if not self.is_running:
            self.start()

        state = self._state
        if state is None:
            raise RuntimeError("Sandbox VM is not running.")

        request_id = str(payload.get("id") or uuid.uuid4().hex)
        payload["id"] = request_id

        with self._request_lock:
            self._send_payload(state, payload)
            response = self._wait_for_response(state, request_id=request_id, timeout_s=timeout_s)

        if response.get("ok") is not True:
            message = str(response.get("error", "unknown guest error"))
            raise RuntimeError(f"Guest request failed: {message}")

        result = response.get("result", {})
        if not isinstance(result, dict):
            return {}
        return result

    def _spawn_guest_process(self, *, qemu_system_binary: str, launch: _LaunchPlan) -> _GuestState:
        serial_port = _allocate_loopback_port()
        args = self._build_qemu_args(
            qemu_system_binary=qemu_system_binary,
            launch=launch,
            serial_endpoint=f"tcp:127.0.0.1:{serial_port},server=on,wait=on",
        )
        process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        messages: queue.Queue[tuple[str, dict[str, object] | None]] = queue.Queue()
        recent_logs: collections.deque[str] = collections.deque(maxlen=200)

        qemu_log_thread = threading.Thread(
            target=self._qemu_log_loop,
            args=(process, recent_logs),
            daemon=True,
        )
        qemu_log_thread.start()

        control_socket = self._connect_control_socket(
            port=serial_port,
            process=process,
            recent_logs=recent_logs,
        )
        control_reader = control_socket.makefile(
            "r",
            encoding="utf-8",
            newline="\n",
            errors="replace",
        )
        control_writer = control_socket.makefile(
            "w",
            encoding="utf-8",
            newline="\n",
        )

        thread = threading.Thread(
            target=self._reader_loop,
            args=(control_reader, messages, recent_logs),
            daemon=True,
        )
        thread.start()

        return _GuestState(
            process=process,
            control_socket=control_socket,
            control_reader=control_reader,
            control_writer=control_writer,
            reader_thread=thread,
            qemu_log_thread=qemu_log_thread,
            messages=messages,
            recent_logs=recent_logs,
            launch=launch,
        )

    @staticmethod
    def _qemu_log_loop(
        process: subprocess.Popen[str],
        recent_logs: collections.deque[str],
    ) -> None:
        if process.stdout is None:
            return
        for raw_line in process.stdout:
            line = _sanitize_serial_line(raw_line)
            if line:
                recent_logs.append(line)

    @staticmethod
    def _connect_control_socket(
        *,
        port: int,
        process: subprocess.Popen[str],
        recent_logs: collections.deque[str],
    ) -> socket.socket:
        deadline = time.monotonic() + _CONTROL_CONNECT_TIMEOUT_S
        while True:
            if process.poll() is not None:
                raise RuntimeError(
                    "VM exited before control channel was ready.\n"
                    + ("\n".join(recent_logs) if recent_logs else "(no guest logs captured)")
                )
            try:
                connection = socket.create_connection(("127.0.0.1", port), timeout=0.5)
                connection.settimeout(None)
                return connection
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Timed out connecting to VM control channel.")
                time.sleep(0.05)

    @staticmethod
    def _reader_loop(
        control_reader: io.TextIOBase,
        messages: queue.Queue[tuple[str, dict[str, object] | None]],
        recent_logs: collections.deque[str],
    ) -> None:
        try:
            for raw_line in control_reader:
                line = _sanitize_serial_line(raw_line)
                parsed_any = False
                for payload in _extract_framed_payloads(line, prefix=_READY_PREFIX):
                    messages.put(("ready", payload))
                    parsed_any = True
                for payload in _extract_framed_payloads(line, prefix=_RESP_PREFIX):
                    messages.put(("response", payload))
                    parsed_any = True

                if parsed_any:
                    continue
                if line:
                    recent_logs.append(line)
        except Exception as exc:
            recent_logs.append(f"(control channel read error: {exc})")
        finally:
            messages.put(("eof", None))

    def _wait_for_ready(self, state: _GuestState, *, timeout_s: float) -> None:
        deadline = time.monotonic() + timeout_s
        while True:
            if state.process.poll() is not None:
                raise RuntimeError(
                    "VM exited before signaling readiness.\n"
                    + self._format_recent_logs(state)
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for guest readiness signal.")

            try:
                kind, payload = state.messages.get(timeout=remaining)
            except queue.Empty:
                continue

            if kind == "ready":
                return
            if kind == "eof":
                raise RuntimeError(
                    "VM control channel closed before readiness signal.\n"
                    + self._format_recent_logs(state)
                )
            if kind == "response":
                continue
            if payload is None:
                continue

    def _wait_for_response(
        self,
        state: _GuestState,
        *,
        request_id: str,
        timeout_s: float,
    ) -> dict[str, object]:
        deadline = time.monotonic() + timeout_s
        while True:
            if state.process.poll() is not None:
                raise RuntimeError(
                    "VM process exited unexpectedly while waiting for response.\n"
                    + self._format_recent_logs(state)
                )

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timed out waiting for guest response to request {request_id}."
                )

            try:
                kind, payload = state.messages.get(timeout=remaining)
            except queue.Empty:
                continue

            if kind == "response" and isinstance(payload, dict):
                if str(payload.get("id", "")) == request_id:
                    return payload
                continue

            if kind == "eof":
                raise RuntimeError(
                    "VM control channel closed while waiting for response.\n"
                    + self._format_recent_logs(state)
                )

    def _send_payload(self, state: _GuestState, payload: dict[str, object]) -> None:
        line = _REQ_PREFIX + _encode_json_payload(payload) + "\n"
        try:
            state.control_writer.write(line)
            state.control_writer.flush()
        except Exception as exc:
            raise RuntimeError(f"Failed to send guest request: {exc}") from exc

    def _format_recent_logs(self, state: _GuestState) -> str:
        if not state.recent_logs:
            return "(no guest logs captured)"
        return "\n".join(state.recent_logs)

    def _close_state(
        self,
        state: _GuestState,
        *,
        force: bool,
        timeout_s: float = _SHUTDOWN_TIMEOUT_S,
    ) -> None:
        with self._request_lock:
            process = state.process
            if not force and process.poll() is None:
                try:
                    shutdown_payload = {
                        "id": uuid.uuid4().hex,
                        "action": "shutdown",
                    }
                    self._send_payload(state, shutdown_payload)
                    self._wait_for_response(
                        state,
                        request_id=str(shutdown_payload["id"]),
                        timeout_s=min(timeout_s, 5.0),
                    )
                except Exception:
                    pass

            if process.poll() is None:
                try:
                    process.wait(timeout=timeout_s)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=2.0)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2.0)

        try:
            state.control_writer.close()
        except Exception:
            pass
        try:
            state.control_reader.close()
        except Exception:
            pass
        try:
            state.control_socket.close()
        except Exception:
            pass
        if process.stdout is not None:
            process.stdout.close()

        if state.reader_thread.is_alive():
            state.reader_thread.join(timeout=1.0)
        if state.qemu_log_thread.is_alive():
            state.qemu_log_thread.join(timeout=1.0)

    def _build_qemu_args(
        self,
        *,
        qemu_system_binary: str,
        launch: _LaunchPlan,
        serial_endpoint: str = "stdio",
    ) -> list[str]:
        append = [
            "console=ttyS0",
            "panic=1",
            "quiet",
        ]

        common = [
            qemu_system_binary,
            "-machine",
            f"{launch.machine},accel={launch.accel}",
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
            serial_endpoint,
            "-no-reboot",
            "-kernel",
            str(kernel_image_path(self.app_dir)),
            "-initrd",
            str(initramfs_image_path(self.app_dir)),
            "-append",
            " ".join(append),
        ]

        if launch.machine == "microvm":
            args = [
                *common,
                "-nodefaults",
                "-no-user-config",
                "-drive",
                (
                    "id=persistent,if=none,format=qcow2,file="
                    f"{default_persistent_disk_path(self.app_dir)}"
                ),
                "-device",
                "virtio-blk-device,drive=persistent",
                "-device",
                "virtio-rng-device",
            ]
            if self.config.network.enabled:
                args.extend(
                    [
                        "-netdev",
                        "user,id=net0",
                        "-device",
                        "virtio-net-device,netdev=net0",
                    ]
                )
            return args

        args = [
            *common,
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


def _boot_timeout_for_attempt(
    *,
    attempt: int,
    total_attempts: int,
    requested_timeout_s: float | None,
) -> float:
    if requested_timeout_s is not None:
        return requested_timeout_s
    if attempt < total_attempts - 1:
        return min(_BOOT_TIMEOUT_S, _BOOT_ATTEMPT_FALLBACK_TIMEOUT_S)
    return _BOOT_TIMEOUT_S


def _normalize_command_payload(command: str | Sequence[str]) -> str | list[str]:
    if isinstance(command, str):
        if not command.strip():
            raise ValueError("`command` must be a non-empty string.")
        return command

    if isinstance(command, Sequence):
        parts = list(command)
        if not parts:
            raise ValueError("`command` sequence must be non-empty.")
        if any(not isinstance(part, str) or not part for part in parts):
            raise ValueError("`command` sequence entries must be non-empty strings.")
        return parts

    raise ValueError("`command` must be a `str` or sequence of strings.")


def _validate_env(env: dict[str, str]) -> dict[str, str]:
    if not isinstance(env, dict):
        raise ValueError("`env` must be a mapping of string keys to string values.")
    normalized: dict[str, str] = {}
    for key, value in env.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("`env` must be a mapping of string keys to string values.")
        normalized[key] = value
    return normalized


def _command_wait_timeout(timeout_s: float | None) -> float:
    return _POST_COMMAND_GRACE_S + (timeout_s if timeout_s is not None else _DEFAULT_COMMAND_TIMEOUT_S)


def _allocate_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        return int(listener.getsockname()[1])


def _encode_json_payload(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _decode_json_payload(value: str) -> dict[str, object] | None:
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _sanitize_serial_line(raw_line: str) -> str:
    stripped = raw_line.strip("\r\n")
    if not stripped:
        return ""
    cleaned = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", stripped)
    return "".join(ch for ch in cleaned if " " <= ch <= "~")


def _extract_framed_payloads(line: str, *, prefix: str) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    if not line:
        return payloads

    start = 0
    while True:
        index = line.find(prefix, start)
        if index < 0:
            break
        payload_start = index + len(prefix)
        next_prefixes = [
            pos
            for marker in _FRAME_PREFIXES
            if (pos := line.find(marker, payload_start)) >= 0
        ]
        payload_end = min(next_prefixes) if next_prefixes else len(line)
        payload = _decode_json_payload(line[payload_start:payload_end].strip())
        if payload is not None:
            payloads.append(payload)
        start = payload_start
    return payloads


def _decode_b64(value: object) -> str:
    try:
        return _decode_b64_to_bytes(value).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _decode_b64_to_bytes(value: object) -> bytes:
    if not isinstance(value, str) or not value:
        return b""
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:
        return b""


def _coerce_int(value: object, *, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except Exception:
        return default


def _coerce_float_or_none(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)  # type: ignore[arg-type]
    except Exception:
        return None


def _transfer_result_from_payload(payload: dict[str, object]) -> TransferResult:
    return TransferResult(
        bytes_transferred=_coerce_int(payload.get("bytes_transferred"), default=0),
        files_transferred=_coerce_int(payload.get("files_transferred"), default=0),
        duration_s=_coerce_float_or_none(payload.get("duration_s")),
    )


def _safe_extract_tar_bytes(data: bytes, destination: Path) -> None:
    base = destination.resolve()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        members = archive.getmembers()
        for member in members:
            target = (destination / member.name).resolve()
            if target != base and not target.is_relative_to(base):
                raise RuntimeError(f"Refusing to extract unsafe member: {member.name}")
        extract_kwargs: dict[str, object] = {"path": destination}
        if sys.version_info >= (3, 12):
            extract_kwargs["filter"] = "data"
        archive.extractall(**extract_kwargs)
