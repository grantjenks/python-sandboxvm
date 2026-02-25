from __future__ import annotations

import pytest

from sandboxvm import NetworkConfig, Sandbox, SandboxConfig


def test_example_code_runs() -> None:
    cfg = SandboxConfig(
        memory_mb=512,
        persistent_disk_mb=1024,
        network=NetworkConfig(
            enabled=False,
        ),
    )

    with Sandbox(cfg) as vm:
        result = vm.run("python3 -c 'print(42)'", timeout_s=5)

    assert result.exit_code == 0
    assert result.stdout.strip() == "42"
    assert result.stderr == ""


def test_timeout_returns_result() -> None:
    with Sandbox(SandboxConfig()) as vm:
        result = vm.run('python3 -c "import time; time.sleep(10)"', timeout_s=0.01)

    assert result.timed_out
    assert result.exit_code == 124
    assert "timed out" in result.stderr.lower()


def test_config_rejects_out_of_range_values() -> None:
    with pytest.raises(ValueError, match="memory_mb"):
        SandboxConfig(memory_mb=99).validate()

    with pytest.raises(ValueError, match="persistent_disk_mb"):
        SandboxConfig(persistent_disk_mb=10241).validate()


def test_run_requires_non_empty_command() -> None:
    with Sandbox(SandboxConfig()) as vm:
        with pytest.raises(ValueError, match="command"):
            vm.run("   ")
