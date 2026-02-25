# sandboxvm

`sandboxvm` is a Python package for running untrusted code inside a disposable VM powered by QEMU.

The design target is:

- Python-first API for local and server-side use.
- Strong default isolation with network disabled by default.
- Configurable memory (`100 MB` to `4096 MB`).
- Configurable persistent disk (`100 MB` to `10240 MB`) separate from the base image.
- Optional networking with explicit host and bandwidth controls.
- Packaged and distributed on PyPI as a pure-Python package.
- QEMU stays a system dependency and is not bundled in wheels.
- Reference base image kept under `250 MB` (compressed download target).

---

## Status

This repository is currently in planning/bootstrap stage.

This README is the initial design spec and implementation plan.

---

## Problem Statement

Most Python sandboxes either:

- run untrusted code in-process or in containers with weak defaults, or
- require users to separately install and configure hypervisors.

`sandboxvm` aims to provide a batteries-included Python interface that boots isolated VMs with sane security defaults and reproducible runtime behavior.

---

## Core Principles

- Isolation first: untrusted code executes in a VM, not on the host.
- Explicit privileges: networking, persistence, and resources are opt-in and bounded.
- Reproducibility: a pinned base image and documented QEMU version range.
- Simple API: one primary entrypoint with composable config objects.
- Operational clarity: deterministic cleanup, explicit timeouts, structured results.

---

## User-Facing API (Draft)

```python
from sandboxvm import Sandbox, SandboxConfig, NetworkConfig

cfg = SandboxConfig(
    memory_mb=512,
    persistent_disk_mb=1024,
    network=NetworkConfig(
        enabled=False,
    ),
)

with Sandbox(cfg) as vm:
    result = vm.run("python3 -c 'print(42)'", timeout_s=5)
    print(result.exit_code)
    print(result.stdout)
    print(result.stderr)
```

Session behavior:

- entering `with Sandbox(...)` boots one VM session,
- repeated `vm.run(...)` calls execute inside that same live guest,
- exiting the context shuts the guest down.

File transfer helpers:

- `vm.put_bytes(...)`, `vm.get_bytes(...)`
- `vm.put_file(...)`, `vm.get_file(...)`
- `vm.put_dir(...)`, `vm.get_dir(...)`

### Planned API Objects

- `SandboxConfig`
- `NetworkConfig`
- `RunResult`
- `Sandbox`

### Planned Validation Rules

- `memory_mb`: integer in `[100, 4096]`.
- `persistent_disk_mb`: integer in `[100, 10240]`.
- `timeout_s`: positive number with hard max.
- `network.enabled`: defaults to `False`.

---

## Runtime Architecture

### Runtime Assets

- `images/kernel`: Linux kernel used for guest boot (`qemu -kernel`).
- `images/rootfs-initramfs.cpio.gz`: distroless Python root filesystem plus guest init.
- `disks/default.qcow2`: persistent disk reserved for future stateful workflows.

### Boot + Execution Model

- Host launcher starts QEMU with validated resource limits.
- Guest boots minimal Linux image with a small command agent.
- Command payload is sent to guest agent through a controlled channel.
- Guest returns `stdout`, `stderr`, `exit_code`, and timing metadata.
- Host tears down VM and garbage-collects ephemeral artifacts.

### Isolation Boundaries

- Host process isolation with dedicated unprivileged account.
- VM boundary for untrusted code execution.
- cgroup constraints for CPU and memory accounting.
- No host filesystem mounts into guest by default.

---

## Networking Model

Networking is disabled by default.

When enabled:

- VM is attached to a dedicated virtual network path.
- Host allowlist is required (domain/IP policy).
- DNS resolution is controlled and policy-enforced.
- Egress and ingress bandwidth limits are applied.

### Planned Controls

- `enabled`: `bool` (default `False`).
- `allowed_hosts`: list of domains/IPs.
- `max_egress_kbps`: integer limit.
- `max_ingress_kbps`: integer limit.

### Enforcement Approach (Linux-first)

- net namespace or equivalent per-VM isolation.
- nftables/ipset for host policy.
- `tc` for bandwidth shaping.

---

## Packaging Strategy

The project ships as a Python package only:

- `sandboxvm`: Python API and orchestration.

Runtime components are external:

- QEMU binaries are installed by the user or host image.
- base images are managed outside wheels (`sandboxvm` bootstrap/download flow or user-provided path).

This keeps Python wheels small and avoids redistributing GPL-covered QEMU binaries.

### Base Image Size Budget

- Reference base image target: under `250 MB` compressed.
- CI should fail image build if size exceeds threshold.
- Images are stripped to minimal package set and services.

## Installing QEMU (System Dependency)

Install QEMU on the host before using `sandboxvm`.

### macOS (Homebrew)

```bash
brew install qemu
```

### Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y qemu-system-x86 qemu-utils
```

### Fedora/RHEL

```bash
sudo dnf install -y qemu-system-x86 qemu-img
```

### Arch Linux

```bash
sudo pacman -S --needed qemu-full
```

### Windows (winget)

```powershell
winget install -e --id SoftwareFreedomConservancy.QEMU
```

## Initialize Runtime Assets

After installing QEMU, run:

```bash
python3 -m sandboxvm.setup
```

This command:

- selects a platform-appropriate `sandboxvm` app directory,
- creates `images/` and `disks/` folders,
- pulls a distroless Python image and assembles `images/rootfs-initramfs.cpio.gz`,
- pulls a Linux kernel image and writes `images/kernel`,
- creates `disks/default.qcow2`,
- writes runtime metadata (`runtime.json`).

Startup behavior:

- `sandboxvm` assumes these assets exist in the app directory.
- if assets are missing, preflight errors should instruct the user to rerun `python -m sandboxvm.setup`.

Launch behavior:

- Linux launch prefers `microvm` and will use `kvm` automatically when available, falling back to `tcg`.
- macOS/Windows default to `tcg` for reliability; set `SANDBOXVM_USE_HOST_ACCEL=1` to opt in to `hvf`/`whpx` probing.

---

## PyPI Distribution Policy

Goal: publish a single pure-Python wheel plus source distribution for each release.

Practical interpretation:

- Build and publish one universal `py3-none-any` wheel for `sandboxvm`.
- Publish an `sdist` alongside the wheel.
- Do not bundle QEMU or VM images in wheel artifacts.
- Perform runtime preflight checks and return clear errors when required host dependencies are missing.

This keeps release artifacts simple, small, and licensing boundaries clean.

### Runtime Platform Support Policy

- `sandboxvm` is installable wherever wheels are published.
- Runtime support is officially declared per platform/arch based on tested QEMU availability and isolation features.
- Linux is first-class target for full feature support (including tighter network controls).
- macOS and Windows support may have reduced capability depending on host primitives.

---

## Security Model

### Threat Model (Initial)

- Untrusted guest code may attempt privilege escalation, host access, or network abuse.
- Host user account and host kernel are in scope for protection.
- Side channels and speculative attacks are acknowledged but out of initial scope.

### Baseline Hardening

- Unprivileged launcher process.
- Minimal guest image and disabled unnecessary services.
- Strict timeout and kill semantics.
- No default network path.
- Resource limits and process accounting with cgroups.
- Structured audit logs for launch config and command metadata.

### Non-Goals (Initial)

- Defending against malicious host kernel modules.
- Protecting against physical side-channel attackers.
- Multi-tenant cloud hardening parity on day one.

---

## Roadmap

1. Bootstrap repository structure and Python package skeleton.
2. Implement config models and validation logic.
3. Build minimal Linux image and guest command agent.
4. Implement QEMU launcher with run lifecycle and cleanup.
5. Add persistent disk creation/attachment flow.
6. Add timeout handling, cancellation, and robust teardown.
7. Add optional network mode with allowlist and bandwidth limits.
8. Add integration tests that run real commands inside guest VMs.
9. Add build/publish pipeline (`uv build` and `uv publish`).
10. Expand GitHub Actions matrix tests and include optional QEMU integration jobs.
11. Add base-image size gates and compatibility checks.
12. Publish pre-release builds to TestPyPI, then PyPI.

---

## Repository Layout (Proposed)

```text
python-sandboxvm/
  .github/
    workflows/
      test.yml
  README.md
  pyproject.toml
  src/
    sandboxvm/
      __init__.py
      __main__.py
      api.py
      preflight.py
      runtime_paths.py
      setup.py
  images/
    build-image.sh
    files/
  tests/
    test_preflight.py
    test_runtime_paths.py
```

---

## Testing Strategy

- Unit tests for config validation and command construction.
- Integration tests for boot/run/timeout/teardown behavior.
- Negative tests for resource and network policy violations.
- GitHub Actions matrix tests across Linux/macOS/Windows and supported Python versions.
- Preflight tests for missing/invalid QEMU dependencies.
- Size-budget tests for reference base images.

---

## Open Design Decisions

- QEMU version policy (minimum supported version vs tested version range).
- Base image distribution strategy (download URL, checksum signing, mirror policy).
- Whether persistent disk identity is caller-managed path or package-managed handle (current preference: package-managed handle).
- How to expose advanced controls without bloating core API surface (current preference: keep API surface minimal).

---

## License and Compliance

`sandboxvm` is intended to use `Apache-2.0` for project code.

QEMU is intentionally not bundled or redistributed by this package.

Compliance plan:

- distribute only Python code in `sandboxvm` wheels.
- require users/hosts to install QEMU separately (for example via `brew` or `apt`).
- clearly document QEMU as an external system dependency in install docs and runtime errors.
- if reference guest images are distributed by this project, provide separate licensing and attribution for those image contents.

If the distribution model ever changes to bundle QEMU binaries, the project must add GPL distribution compliance steps before release.

---

## Immediate Next Step

Build the first runnable API surface on top of setup/preflight:

- add `SandboxConfig` and `Sandbox` primitives,
- call runtime preflight at startup,
- implement no-network command execution flow,
- add one end-to-end integration test gated behind locally installed QEMU.
