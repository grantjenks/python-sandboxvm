from __future__ import annotations

import subprocess
import sys
import textwrap


def test_user_snippet_runs_verbatim() -> None:
    snippet = textwrap.dedent(
        """
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
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", snippet],
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "0\n42\n\n\n"
    assert completed.stderr == ""
