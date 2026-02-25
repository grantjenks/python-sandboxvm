from __future__ import annotations

import pytest

import sandboxvm.api as api
from sandboxvm import NetworkConfig, Sandbox, SandboxConfig


def test_config_rejects_out_of_range_values() -> None:
    with pytest.raises(ValueError, match="memory_mb"):
        SandboxConfig(memory_mb=99).validate()

    with pytest.raises(ValueError, match="persistent_disk_mb"):
        SandboxConfig(persistent_disk_mb=10241).validate()


def test_network_config_requires_bool() -> None:
    cfg = NetworkConfig(enabled=False)
    cfg.enabled = "nope"  # type: ignore[assignment]
    with pytest.raises(ValueError, match="network.enabled"):
        cfg.validate()


def test_run_rejects_empty_command_before_runtime_checks() -> None:
    vm = Sandbox(SandboxConfig(), skip_preflight=True)
    with pytest.raises(ValueError, match="command"):
        vm.run("   ")


def test_run_rejects_non_positive_timeout_before_runtime_checks() -> None:
    vm = Sandbox(SandboxConfig(), skip_preflight=True)
    with pytest.raises(ValueError, match="timeout_s"):
        vm.run("python3 -c 'print(42)'", timeout_s=0)


def test_build_launch_plans_prefers_microvm_on_linux() -> None:
    plans = api._build_launch_plans(
        platform="linux",
        available_accelerators={"kvm", "tcg"},
        supports_microvm=True,
    )
    assert [(plan.machine, plan.accel) for plan in plans] == [
        ("microvm", "kvm"),
        ("pc", "kvm"),
        ("microvm", "tcg"),
        ("pc", "tcg"),
    ]


def test_build_launch_plans_prefers_platform_accel_on_macos() -> None:
    plans = api._build_launch_plans(
        platform="darwin",
        available_accelerators={"hvf", "tcg"},
        supports_microvm=True,
    )
    assert [(plan.machine, plan.accel) for plan in plans] == [("pc", "tcg")]


def test_build_launch_plans_opt_in_host_accel(monkeypatch) -> None:
    monkeypatch.setenv("SANDBOXVM_USE_HOST_ACCEL", "1")
    plans = api._build_launch_plans(
        platform="darwin",
        available_accelerators={"hvf", "tcg"},
        supports_microvm=True,
    )
    assert [(plan.machine, plan.accel) for plan in plans] == [
        ("pc", "hvf"),
        ("pc", "tcg"),
    ]


def test_build_qemu_args_for_microvm() -> None:
    vm = Sandbox(skip_preflight=True)
    args = vm._build_qemu_args(
        qemu_system_binary="/usr/bin/qemu-system-x86_64",
        launch=api._LaunchPlan(machine="microvm", accel="tcg"),
    )
    assert "-nodefaults" in args
    assert "-no-user-config" in args
    assert "virtio-blk-device,drive=persistent" in args
    assert "virtio-rng-device" in args
    assert "-nic" not in args


def test_build_qemu_args_for_pc() -> None:
    vm = Sandbox(skip_preflight=True)
    args = vm._build_qemu_args(
        qemu_system_binary="/usr/bin/qemu-system-x86_64",
        launch=api._LaunchPlan(machine="pc", accel="tcg"),
    )
    assert "virtio-rng-pci" in args
    assert "-nic" in args


def test_normalize_command_payload_supports_sequence() -> None:
    assert api._normalize_command_payload(["python3", "-c", "print(42)"]) == [
        "python3",
        "-c",
        "print(42)",
    ]


def test_normalize_command_payload_rejects_invalid_sequence() -> None:
    with pytest.raises(ValueError, match="sequence"):
        api._normalize_command_payload([])  # type: ignore[arg-type]
