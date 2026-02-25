"""Initialize sandboxvm runtime assets.

Usage:
    python -m sandboxvm.setup
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .preflight import RUNTIME_SCHEMA_VERSION, find_qemu_system_binary
from .runtime_paths import (
    default_persistent_disk_path,
    disks_dir,
    get_app_dir,
    images_dir,
    initramfs_image_path,
    kernel_image_path,
    runtime_metadata_path,
)

DEFAULT_DISTROLESS_IMAGE_REF = "gcr.io/distroless/python3-debian12:latest"
DEFAULT_LINUXKIT_KERNEL_IMAGE_REF = "docker.io/linuxkit/kernel:6.6.71"
_DEFAULT_TIMEOUT_S = 120


@dataclass(frozen=True)
class ImageReference:
    registry: str
    repository: str
    reference: str

    @property
    def display(self) -> str:
        return f"{self.registry}/{self.repository}:{self.reference}"


@dataclass(frozen=True)
class ManifestDescriptor:
    digest: str
    media_type: str


@dataclass
class RootfsMetadata:
    modes: dict[str, int] = field(default_factory=dict)
    mtimes: dict[str, int] = field(default_factory=dict)
    symlinks: dict[str, str] = field(default_factory=dict)


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
        "--distroless-image",
        default=DEFAULT_DISTROLESS_IMAGE_REF,
        help=(
            "OCI image reference used as rootfs source for the initramfs "
            f"(default: {DEFAULT_DISTROLESS_IMAGE_REF})."
        ),
    )
    parser.add_argument(
        "--kernel-image",
        default=DEFAULT_LINUXKIT_KERNEL_IMAGE_REF,
        help=(
            "OCI image reference used to source the Linux kernel binary "
            f"(default: {DEFAULT_LINUXKIT_KERNEL_IMAGE_REF})."
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
        help="Recreate kernel/initramfs and default disk even if they already exist.",
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


def _write_metadata(
    app_dir: Path,
    qemu_img_binary: str,
    qemu_system_binary: str,
    distroless_image: str,
    kernel_image: str,
    persistent_disk_mb: int,
) -> None:
    metadata = {
        "schema": RUNTIME_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "app_dir": str(app_dir),
        "runtime_kind": "distroless-python-initramfs",
        "kernel_image": str(kernel_image_path(app_dir)),
        "initramfs_image": str(initramfs_image_path(app_dir)),
        "default_persistent_disk": str(default_persistent_disk_path(app_dir)),
        "guest_arch": "x86_64",
        "distroless_image": distroless_image,
        "kernel_source_image": kernel_image,
        "persistent_disk_mb": persistent_disk_mb,
        "qemu_img_binary": qemu_img_binary,
        "qemu_system_binary": qemu_system_binary,
    }
    metadata_path = runtime_metadata_path(app_dir)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"wrote: {metadata_path}")


def _parse_image_reference(value: str) -> ImageReference:
    text = value.strip()
    if not text:
        raise ValueError("image reference cannot be empty")

    if "@" in text:
        base, reference = text.rsplit("@", 1)
    else:
        slash = text.rfind("/")
        colon = text.rfind(":")
        if colon > slash:
            base = text[:colon]
            reference = text[colon + 1 :]
        else:
            base = text
            reference = "latest"

    if "/" not in base:
        registry = "index.docker.io"
        repository = f"library/{base}"
    else:
        first, rest = base.split("/", 1)
        if "." in first or ":" in first or first == "localhost":
            registry = first
            repository = rest
        else:
            registry = "index.docker.io"
            repository = base

    if not reference:
        reference = "latest"
    if registry == "docker.io":
        registry = "registry-1.docker.io"
    if registry == "index.docker.io":
        registry = "registry-1.docker.io"
    return ImageReference(registry=registry, repository=repository, reference=reference)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _remember_mode(
    metadata: RootfsMetadata,
    rel: Path,
    *,
    mode_type: int,
    perm: int,
    mtime: int,
) -> None:
    key = rel.as_posix()
    metadata.modes[key] = mode_type | (perm & 0o7777)
    metadata.mtimes[key] = mtime


def _clear_metadata_path(metadata: RootfsMetadata, rel: Path) -> None:
    key = rel.as_posix()
    child_prefix = f"{key}/"
    for name in list(metadata.modes):
        if name == key or name.startswith(child_prefix):
            metadata.modes.pop(name, None)
            metadata.mtimes.pop(name, None)
            metadata.symlinks.pop(name, None)


def _clear_metadata_children(metadata: RootfsMetadata, rel: Path) -> None:
    key = rel.as_posix()
    prefix = "" if key in {"", "."} else f"{key}/"
    for name in list(metadata.modes):
        if (not prefix) or name.startswith(prefix):
            metadata.modes.pop(name, None)
            metadata.mtimes.pop(name, None)
            metadata.symlinks.pop(name, None)


def _apply_whiteout(root: Path, target: Path, metadata: RootfsMetadata) -> None:
    try:
        rel = target.relative_to(root)
        _clear_metadata_path(metadata, rel)
    except ValueError:
        pass
    if target.is_symlink() or target.is_file():
        target.unlink(missing_ok=True)
        return
    if target.is_dir():
        shutil.rmtree(target, ignore_errors=True)


def _safe_rel(path: str) -> Path | None:
    posix = PurePosixPath(path)
    if path in {"", ".", "./"}:
        return None
    if posix.is_absolute():
        return None
    parts = []
    for part in posix.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            return None
        parts.append(part)
    if not parts:
        return None
    return Path(*parts)


def _looks_executable_path(rel: Path) -> bool:
    text = rel.as_posix()
    return text.startswith("bin/") or text.startswith("usr/bin/") or text.startswith("usr/sbin/")


def _default_file_perm(rel: Path) -> int:
    if _looks_executable_path(rel):
        return 0o755
    return 0o644


def _extract_layer_tar(layer_bytes: bytes, root: Path, metadata: RootfsMetadata) -> None:
    with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as archive:
        for member in archive:
            rel = _safe_rel(member.name)
            if rel is None:
                continue

            target = root / rel
            base_name = rel.name
            parent = target.parent

            if base_name.startswith(".wh."):
                if base_name == ".wh..wh..opq":
                    _clear_metadata_children(metadata, rel.parent)
                    if parent.exists():
                        for child in parent.iterdir():
                            _apply_whiteout(root, child, metadata)
                else:
                    removed = parent / base_name[len(".wh.") :]
                    _apply_whiteout(root, removed, metadata)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            mtime = int(member.mtime if member.mtime is not None else 0)

            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(member.mode or 0o755)
                _remember_mode(
                    metadata,
                    rel,
                    mode_type=stat.S_IFDIR,
                    perm=member.mode or 0o755,
                    mtime=mtime,
                )
                continue

            if member.issym():
                _apply_whiteout(root, target, metadata)
                metadata.symlinks[rel.as_posix()] = member.linkname
                _remember_mode(
                    metadata,
                    rel,
                    mode_type=stat.S_IFLNK,
                    perm=member.mode or 0o777,
                    mtime=mtime,
                )
                continue

            if member.islnk():
                raw_link = member.linkname.lstrip("/")
                link_rel = _safe_rel(raw_link)
                if link_rel is None:
                    continue
                link_target = root / link_rel
                _apply_whiteout(root, target, metadata)
                link_key = link_rel.as_posix()
                if link_key in metadata.symlinks:
                    metadata.symlinks[rel.as_posix()] = metadata.symlinks[link_key]
                    _remember_mode(
                        metadata,
                        rel,
                        mode_type=stat.S_IFLNK,
                        perm=member.mode or 0o777,
                        mtime=mtime,
                    )
                    continue
                if link_target.exists():
                    if link_target.is_file():
                        target.write_bytes(link_target.read_bytes())
                        link_mode = metadata.modes.get(link_key)
                        perm = (
                            (link_mode & 0o7777)
                            if link_mode is not None
                            else (member.mode or (link_target.stat().st_mode & 0o7777))
                        )
                        if not perm:
                            perm = _default_file_perm(rel)
                        target.chmod(perm)
                        _remember_mode(
                            metadata,
                            rel,
                            mode_type=stat.S_IFREG,
                            perm=perm,
                            mtime=mtime,
                        )
                continue

            if member.isfile():
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                with handle:
                    data = handle.read()
                _apply_whiteout(root, target, metadata)
                target.write_bytes(data)
                perm = member.mode or _default_file_perm(rel)
                target.chmod(perm)
                _remember_mode(
                    metadata,
                    rel,
                    mode_type=stat.S_IFREG,
                    perm=perm,
                    mtime=mtime,
                )


def _parse_www_authenticate(header: str) -> dict[str, str]:
    prefix = "Bearer "
    if not header.startswith(prefix):
        raise RuntimeError(f"Unsupported auth scheme: {header!r}")
    params: dict[str, str] = {}
    for key, value in re.findall(r'(\w+)="([^"]+)"', header[len(prefix) :]):
        params[key] = value
    return params


def _http_get_bytes(
    *,
    url: str,
    headers: dict[str, str],
    timeout_s: int = _DEFAULT_TIMEOUT_S,
) -> tuple[bytes, dict[str, str], int]:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout_s) as response:
        return response.read(), dict(response.headers.items()), response.status


def _oci_request(
    *,
    ref: ImageReference,
    path: str,
    accept: str | None,
    token: str | None,
) -> tuple[bytes, dict[str, str]]:
    url = f"https://{ref.registry}/v2/{ref.repository}/{path.lstrip('/')}"
    headers = {"User-Agent": "sandboxvm-setup/0.1"}
    if accept:
        headers["Accept"] = accept
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        data, response_headers, _ = _http_get_bytes(url=url, headers=headers)
        return data, response_headers
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise
        auth_header = exc.headers.get("WWW-Authenticate")
        if not auth_header:
            raise RuntimeError("Registry requires auth but did not provide WWW-Authenticate header.")
        params = _parse_www_authenticate(auth_header)
        realm = params.get("realm")
        if not realm:
            raise RuntimeError(f"Registry auth challenge missing realm: {auth_header!r}")

        query = {}
        if "service" in params:
            query["service"] = params["service"]
        if "scope" in params:
            query["scope"] = params["scope"]
        token_url = realm
        if query:
            token_url = f"{realm}?{urllib.parse.urlencode(query)}"

        token_data, _, _ = _http_get_bytes(
            url=token_url,
            headers={"User-Agent": "sandboxvm-setup/0.1"},
        )
        payload = json.loads(token_data.decode("utf-8"))
        bearer = payload.get("token") or payload.get("access_token")
        if not bearer:
            raise RuntimeError(f"Failed to obtain registry token from: {token_url}")

        headers["Authorization"] = f"Bearer {bearer}"
        data, response_headers, _ = _http_get_bytes(url=url, headers=headers)
        return data, response_headers


def _select_platform_manifest(index_data: bytes) -> ManifestDescriptor:
    payload = json.loads(index_data.decode("utf-8"))
    manifests = payload.get("manifests")
    if not isinstance(manifests, list):
        raise RuntimeError("OCI index is missing `manifests` list.")

    for item in manifests:
        if not isinstance(item, dict):
            continue
        platform = item.get("platform")
        if not isinstance(platform, dict):
            continue
        if platform.get("os") == "linux" and platform.get("architecture") == "amd64":
            digest = item.get("digest")
            media_type = item.get("mediaType")
            if isinstance(digest, str) and isinstance(media_type, str):
                return ManifestDescriptor(digest=digest, media_type=media_type)

    raise RuntimeError("No linux/amd64 entry found in image index.")


def _load_manifest(ref: ImageReference) -> tuple[dict[str, Any], str]:
    accept = ", ".join(
        [
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ]
    )
    data, headers = _oci_request(ref=ref, path=f"manifests/{ref.reference}", accept=accept, token=None)
    media_type = headers.get("Content-Type", "").split(";", 1)[0].strip()

    if media_type in {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }:
        desc = _select_platform_manifest(data)
        data, headers = _oci_request(ref=ref, path=f"manifests/{desc.digest}", accept=desc.media_type, token=None)
        media_type = headers.get("Content-Type", "").split(";", 1)[0].strip()

    if media_type not in {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }:
        raise RuntimeError(f"Unsupported image manifest media type: {media_type!r}")

    manifest = json.loads(data.decode("utf-8"))
    if not isinstance(manifest, dict):
        raise RuntimeError("Manifest payload must be a JSON object.")
    return manifest, media_type


def _download_blob(ref: ImageReference, digest: str) -> bytes:
    if not digest.startswith("sha256:"):
        raise RuntimeError(f"Unsupported digest: {digest}")
    data, _ = _oci_request(ref=ref, path=f"blobs/{digest}", accept=None, token=None)
    actual = f"sha256:{_sha256(data)}"
    if actual != digest:
        raise RuntimeError(f"Digest mismatch for {digest}: got {actual}")
    return data


def _build_rootfs_from_image(ref: ImageReference, destination: Path) -> RootfsMetadata:
    manifest, _ = _load_manifest(ref)
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        raise RuntimeError("Image manifest has no layers.")

    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    metadata = RootfsMetadata()

    for layer in layers:
        if not isinstance(layer, dict):
            continue
        digest = layer.get("digest")
        if not isinstance(digest, str):
            continue
        media_type = layer.get("mediaType", "")
        if media_type and "tar" not in media_type and "+gzip" not in media_type and "+zstd" not in media_type:
            continue

        layer_bytes = _download_blob(ref, digest)
        _extract_layer_tar(layer_bytes, destination, metadata)
    return metadata


def _extract_kernel_from_image(ref: ImageReference, destination: Path) -> None:
    manifest, _ = _load_manifest(ref)
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        raise RuntimeError("Kernel image manifest has no layers.")

    for layer in layers:
        if not isinstance(layer, dict):
            continue
        digest = layer.get("digest")
        if not isinstance(digest, str):
            continue
        layer_bytes = _download_blob(ref, digest)
        with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as archive:
            for member in archive:
                rel = _safe_rel(member.name)
                if rel is None:
                    continue
                if rel.as_posix() != "kernel":
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                with handle:
                    destination.write_bytes(handle.read())
                destination.chmod(0o755)
                return

    raise RuntimeError("Could not locate `kernel` file in kernel source image.")


def _ensure_root_layout(root: Path, metadata: RootfsMetadata) -> None:
    created_at = int(datetime.now(timezone.utc).timestamp())
    for name in ("dev", "proc", "sys", "tmp", "var", "run", "etc"):
        path = root / name
        path.mkdir(parents=True, exist_ok=True)
        _remember_mode(
            metadata,
            Path(name),
            mode_type=stat.S_IFDIR,
            perm=0o755,
            mtime=created_at,
        )
    (root / "tmp").chmod(0o1777)
    _remember_mode(
        metadata,
        Path("tmp"),
        mode_type=stat.S_IFDIR,
        perm=0o1777,
        mtime=created_at,
    )


def _guest_init_program() -> str:
    return """#!/usr/bin/python3
import base64
import ctypes
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import time

REQ_PREFIX = "__SANDBOXVM_REQ__"
RESP_PREFIX = "__SANDBOXVM_RESP__"
READY_PREFIX = "__SANDBOXVM_READY__"


def _mount_virtual_filesystems() -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        mount = libc.mount
        mount.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_ulong,
            ctypes.c_char_p,
        ]
        mount.restype = ctypes.c_int
    except Exception:
        return

    specs = [
        (b"devtmpfs", b"/dev", b"devtmpfs"),
        (b"proc", b"/proc", b"proc"),
        (b"sysfs", b"/sys", b"sysfs"),
        (b"tmpfs", b"/run", b"tmpfs"),
    ]
    for source, target, fstype in specs:
        try:
            os.makedirs(target.decode("ascii"), exist_ok=True)
        except Exception:
            pass
        try:
            mount(source, target, fstype, 0, None)
        except Exception:
            pass


def _encode_payload(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _decode_payload(value: str) -> dict:
    raw = base64.b64decode(value.encode("ascii"), validate=True)
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("payload must decode to a JSON object")
    return payload


def _emit(prefix: str, payload: dict) -> None:
    print(prefix + _encode_payload(payload), flush=True)


def _emit_response(request_id: str, *, ok: bool, result: dict | None = None, error: str | None = None) -> None:
    payload: dict = {
        "id": request_id,
        "ok": ok,
    }
    if ok:
        payload["result"] = result or {}
    else:
        payload["error"] = error or "unknown guest error"
    _emit(RESP_PREFIX, payload)


def _configure_serial_stdin() -> None:
    try:
        import termios

        fd = sys.stdin.fileno()
        attrs = termios.tcgetattr(fd)
        attrs[3] &= ~getattr(termios, "ECHO", 0)
        attrs[3] &= ~getattr(termios, "ECHONL", 0)
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
    except Exception:
        pass


def _safe_guest_path(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("path must be a non-empty string")
    normalized = os.path.normpath(value)
    if not normalized.startswith("/"):
        normalized = os.path.normpath(os.path.join("/workspace", normalized))
    return normalized


def _decode_data_field(value: object) -> bytes:
    if not isinstance(value, str):
        return b""
    return base64.b64decode(value.encode("ascii"), validate=True)


def _encode_data_field(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _count_files(path: str) -> int:
    total = 0
    for _, _, files in os.walk(path):
        total += len(files)
    return total


def _handle_run(req: dict) -> dict:
    command = req.get("command")
    if isinstance(command, str):
        stripped = command.strip()
        if not stripped:
            raise ValueError("`command` must be a non-empty string")
        if os.path.exists("/bin/sh"):
            run_target = stripped
            shell = True
        else:
            run_target = shlex.split(stripped)
            if not run_target:
                raise ValueError("`command` must be a non-empty string")
            shell = False
    elif isinstance(command, list) and command and all(isinstance(item, str) for item in command):
        run_target = command
        shell = False
    else:
        raise ValueError("`command` must be a non-empty string or list of strings")

    timeout_value = req.get("timeout_s")
    timeout = None if timeout_value is None else float(timeout_value)

    cwd = req.get("cwd")
    resolved_cwd = None if cwd is None else _safe_guest_path(cwd)

    env_map = os.environ.copy()
    custom_env = req.get("env")
    if custom_env is not None:
        if not isinstance(custom_env, dict):
            raise ValueError("`env` must be a JSON object")
        for key, value in custom_env.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError("`env` entries must be string->string")
            env_map[key] = value

    stdin_data = _decode_data_field(req.get("stdin_b64"))

    kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "input": stdin_data,
        "timeout": timeout,
        "check": False,
        "cwd": resolved_cwd,
        "env": env_map,
    }
    if shell:
        kwargs["shell"] = True
        kwargs["executable"] = "/bin/sh"
    else:
        kwargs["shell"] = False

    started = time.monotonic()
    try:
        completed = subprocess.run(run_target, **kwargs)
        exit_code = int(completed.returncode)
        stdout_data = completed.stdout or b""
        stderr_data = completed.stderr or b""
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stdout_data = exc.stdout or b""
        stderr_data = exc.stderr or b""
        timed_out = True

    duration_s = time.monotonic() - started
    return {
        "exit_code": exit_code,
        "stdout_b64": _encode_data_field(stdout_data),
        "stderr_b64": _encode_data_field(stderr_data),
        "timed_out": timed_out,
        "duration_s": duration_s,
    }


def _handle_write_file(req: dict) -> dict:
    path = _safe_guest_path(req.get("path"))
    data = _decode_data_field(req.get("data_b64"))
    overwrite = bool(req.get("overwrite", True))
    mode = int(req.get("mode", 0o644))

    if os.path.exists(path) and not overwrite:
        raise FileExistsError(path)

    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    started = time.monotonic()
    with open(path, "wb") as handle:
        handle.write(data)
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    duration_s = time.monotonic() - started
    return {
        "bytes_transferred": len(data),
        "files_transferred": 1,
        "duration_s": duration_s,
    }


def _handle_read_file(req: dict) -> dict:
    path = _safe_guest_path(req.get("path"))
    max_bytes_value = req.get("max_bytes")
    max_bytes = None if max_bytes_value is None else int(max_bytes_value)

    started = time.monotonic()
    with open(path, "rb") as handle:
        data = handle.read()
    if max_bytes is not None and len(data) > max_bytes:
        raise ValueError(f"file exceeds max_bytes ({len(data)} > {max_bytes})")
    mode = 0o644
    try:
        mode = int(os.stat(path).st_mode & 0o777)
    except OSError:
        pass
    duration_s = time.monotonic() - started
    return {
        "data_b64": _encode_data_field(data),
        "mode": mode,
        "bytes_transferred": len(data),
        "files_transferred": 1,
        "duration_s": duration_s,
    }


def _safe_extract_tar(data: bytes, destination: str) -> int:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        members = archive.getmembers()
        base = os.path.abspath(destination)
        for member in members:
            candidate = os.path.abspath(os.path.join(base, member.name))
            if candidate != base and not candidate.startswith(base + os.sep):
                raise ValueError(f"unsafe tar member path: {member.name}")
        archive.extractall(path=destination)
    return _count_files(destination)


def _handle_extract_tar(req: dict) -> dict:
    path = _safe_guest_path(req.get("path"))
    tar_data = _decode_data_field(req.get("tar_b64"))
    overwrite = bool(req.get("overwrite", True))

    started = time.monotonic()
    if overwrite and os.path.exists(path):
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)
    os.makedirs(path, exist_ok=True)
    files = _safe_extract_tar(tar_data, path)
    duration_s = time.monotonic() - started
    return {
        "bytes_transferred": len(tar_data),
        "files_transferred": files,
        "duration_s": duration_s,
    }


def _handle_archive_dir(req: dict) -> dict:
    path = _safe_guest_path(req.get("path"))
    if not os.path.isdir(path):
        raise NotADirectoryError(path)

    started = time.monotonic()
    with io.BytesIO() as buffer:
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            archive.add(path, arcname=".")
        tar_data = buffer.getvalue()
    duration_s = time.monotonic() - started
    return {
        "tar_b64": _encode_data_field(tar_data),
        "bytes_transferred": len(tar_data),
        "files_transferred": _count_files(path),
        "duration_s": duration_s,
    }


def _handle_request(req: dict) -> tuple[dict, bool]:
    action = req.get("action")
    if action == "run":
        return _handle_run(req), False
    if action == "write_file":
        return _handle_write_file(req), False
    if action == "read_file":
        return _handle_read_file(req), False
    if action == "extract_tar":
        return _handle_extract_tar(req), False
    if action == "archive_dir":
        return _handle_archive_dir(req), False
    if action == "shutdown":
        return {"status": "shutting_down"}, True
    raise ValueError(f"unsupported action: {action!r}")


def _power_off() -> None:
    try:
        os.sync()
    except Exception:
        pass
    try:
        os.reboot(getattr(os, "RB_POWER_OFF", 0x4321FEDC))
    except Exception:
        pass
    try:
        with open("/proc/sysrq-trigger", "wb", buffering=0) as handle:
            handle.write(b"o")
    except Exception:
        pass
    os._exit(0)


def main() -> int:
    _mount_virtual_filesystems()
    _configure_serial_stdin()
    os.makedirs("/workspace", exist_ok=True)
    _emit(READY_PREFIX, {"protocol": 1})

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line.startswith(REQ_PREFIX):
            continue
        encoded = line[len(REQ_PREFIX) :]

        request_id = ""
        should_shutdown = False
        try:
            req = _decode_payload(encoded)
            request_id = str(req.get("id", ""))
            result, should_shutdown = _handle_request(req)
            _emit_response(request_id, ok=True, result=result)
        except Exception as exc:
            _emit_response(request_id, ok=False, error=str(exc))

        if should_shutdown:
            break

    _power_off()


if __name__ == "__main__":
    sys.exit(main())
"""


def _write_file(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def _encode_cpio_header(
    *,
    ino: int,
    mode: int,
    uid: int,
    gid: int,
    nlink: int,
    mtime: int,
    filesize: int,
    devmajor: int,
    devminor: int,
    rdevmajor: int,
    rdevminor: int,
    namesize: int,
) -> bytes:
    fields = [
        "070701",
        f"{ino:08x}",
        f"{mode:08x}",
        f"{uid:08x}",
        f"{gid:08x}",
        f"{nlink:08x}",
        f"{mtime:08x}",
        f"{filesize:08x}",
        f"{devmajor:08x}",
        f"{devminor:08x}",
        f"{rdevmajor:08x}",
        f"{rdevminor:08x}",
        f"{namesize:08x}",
        "00000000",
    ]
    return "".join(fields).encode("ascii")


def _pad4(buffer: bytearray) -> None:
    padding = (-len(buffer)) % 4
    if padding:
        buffer.extend(b"\0" * padding)


def _cpio_add_entry(
    archive: bytearray,
    *,
    name: str,
    mode: int,
    mtime: int,
    data: bytes,
) -> None:
    header = _encode_cpio_header(
        ino=0,
        mode=mode,
        uid=0,
        gid=0,
        nlink=1,
        mtime=mtime,
        filesize=len(data),
        devmajor=0,
        devminor=0,
        rdevmajor=0,
        rdevminor=0,
        namesize=len(name.encode("utf-8")) + 1,
    )
    archive.extend(header)
    archive.extend(name.encode("utf-8") + b"\0")
    _pad4(archive)
    archive.extend(data)
    _pad4(archive)


def _build_initramfs(root: Path, destination: Path, metadata: RootfsMetadata) -> None:
    entries = set(metadata.modes)
    for path in root.rglob("*"):
        entries.add(path.relative_to(root).as_posix())
    ordered_entries = sorted(entries)

    archive = bytearray()
    for rel in ordered_entries:
        rel_path = Path(rel)
        target = root / rel_path
        mode = metadata.modes.get(rel)
        mtime = metadata.mtimes.get(rel, 0)

        if rel in metadata.symlinks:
            _cpio_add_entry(
                archive,
                name=rel,
                mode=mode or (stat.S_IFLNK | 0o777),
                mtime=mtime,
                data=metadata.symlinks[rel].encode("utf-8"),
            )
            continue

        if target.is_dir():
            _cpio_add_entry(
                archive,
                name=rel,
                mode=mode or (stat.S_IFDIR | 0o755),
                mtime=mtime,
                data=b"",
            )
            continue

        if target.is_file():
            if mode is None:
                host_perm = target.stat().st_mode & 0o7777
                if host_perm == 0:
                    host_perm = _default_file_perm(rel_path)
                if (host_perm & 0o111) == 0 and _looks_executable_path(rel_path):
                    host_perm |= 0o555
                mode = stat.S_IFREG | host_perm
            _cpio_add_entry(
                archive,
                name=rel,
                mode=mode,
                mtime=mtime,
                data=target.read_bytes(),
            )
            continue

    _cpio_add_entry(
        archive,
        name="TRAILER!!!",
        mode=stat.S_IFREG | 0o644,
        mtime=int(datetime.now(timezone.utc).timestamp()),
        data=b"",
    )

    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as raw_handle:
        with gzip.GzipFile(fileobj=raw_handle, mode="wb", mtime=0) as gzip_handle:
            gzip_handle.write(archive)


def _build_runtime_assets(
    *,
    app_dir: Path,
    distroless_image_ref: str,
    kernel_image_ref: str,
    force: bool,
) -> None:
    kernel_path = kernel_image_path(app_dir)
    initramfs_path = initramfs_image_path(app_dir)

    if kernel_path.exists() and initramfs_path.exists() and not force:
        print(f"exists: {kernel_path} (skipping)")
        print(f"exists: {initramfs_path} (skipping)")
        return

    distroless_ref = _parse_image_reference(distroless_image_ref)
    kernel_ref = _parse_image_reference(kernel_image_ref)

    with tempfile.TemporaryDirectory(prefix="sandboxvm-build-") as temp_dir:
        temp_root = Path(temp_dir)
        rootfs = temp_root / "rootfs"

        print(f"pulling rootfs from: {distroless_ref.display}")
        metadata = _build_rootfs_from_image(distroless_ref, rootfs)

        _ensure_root_layout(rootfs, metadata)
        init_path = rootfs / "init"
        _write_file(init_path, _guest_init_program().encode("utf-8"), mode=0o755)
        init_rel = Path("init")
        _remember_mode(
            metadata,
            init_rel,
            mode_type=stat.S_IFREG,
            perm=0o755,
            mtime=int(datetime.now(timezone.utc).timestamp()),
        )
        metadata.symlinks.pop(init_rel.as_posix(), None)

        print(f"building initramfs: {initramfs_path}")
        _build_initramfs(rootfs, initramfs_path, metadata)

        print(f"pulling kernel from: {kernel_ref.display}")
        _extract_kernel_from_image(kernel_ref, kernel_path)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    _ensure_positive("persistent-disk-mb", args.persistent_disk_mb)

    app_dir = get_app_dir(args.app_dir)
    print(f"sandboxvm app dir: {app_dir}")

    qemu_img_binary, qemu_system_binary = _ensure_qemu_available(non_interactive=args.yes)

    images_dir(app_dir).mkdir(parents=True, exist_ok=True)
    disks_dir(app_dir).mkdir(parents=True, exist_ok=True)

    _build_runtime_assets(
        app_dir=app_dir,
        distroless_image_ref=args.distroless_image,
        kernel_image_ref=args.kernel_image,
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
        distroless_image=args.distroless_image,
        kernel_image=args.kernel_image,
        persistent_disk_mb=args.persistent_disk_mb,
    )

    print("")
    print("sandboxvm runtime setup complete.")
    print("Startup can now assume runtime assets exist in the sandboxvm app dir.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
