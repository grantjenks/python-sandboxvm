from __future__ import annotations

import pytest

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
    with Sandbox(SandboxConfig(), skip_preflight=True) as vm:
        with pytest.raises(ValueError, match="command"):
            vm.run("   ")


def test_run_rejects_non_positive_timeout_before_runtime_checks() -> None:
    with Sandbox(SandboxConfig(), skip_preflight=True) as vm:
        with pytest.raises(ValueError, match="timeout_s"):
            vm.run("python3 -c 'print(42)'", timeout_s=0)
