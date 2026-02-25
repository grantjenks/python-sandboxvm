from __future__ import annotations

from pathlib import Path

import os

import pytest

from sandboxvm import Sandbox

pytestmark = pytest.mark.integration


def _ensure_enabled() -> None:
    if os.environ.get("SANDBOXVM_RUN_VM_TESTS") != "1":
        pytest.skip("integration test disabled; set SANDBOXVM_RUN_VM_TESTS=1")


def test_context_manager_reuses_single_vm_session() -> None:
    _ensure_enabled()

    with Sandbox() as vm:
        first = vm.run(
            "python3 -c 'open(\"/tmp/session-state.txt\", \"w\").write(\"persisted\")'",
            timeout_s=5,
        )
        second = vm.run(
            "python3 -c 'print(open(\"/tmp/session-state.txt\").read())'",
            timeout_s=5,
        )

        assert first.exit_code == 0, first.stderr
        assert second.exit_code == 0, second.stderr
        assert second.stdout.strip() == "persisted"
        assert vm.is_running

    assert not vm.is_running


def test_file_transfer_round_trip(tmp_path: Path) -> None:
    _ensure_enabled()

    local_input = tmp_path / "input.txt"
    local_input.write_text("hello from host\n", encoding="utf-8")

    tree_dir = tmp_path / "tree"
    (tree_dir / "sub").mkdir(parents=True)
    (tree_dir / "sub" / "file.txt").write_text("payload", encoding="utf-8")

    with Sandbox() as vm:
        transfer = vm.put_file(local_input, "/workspace/input.txt")
        assert transfer.files_transferred == 1

        upper = vm.run(
            "python3 -c 'print(open(\"/workspace/input.txt\", \"r\", encoding=\"utf-8\").read().strip().upper())'",
            timeout_s=5,
        )
        assert upper.exit_code == 0, upper.stderr
        assert upper.stdout.strip() == "HELLO FROM HOST"

        vm.put_bytes(b"raw-bytes", "/workspace/raw.bin")
        raw = vm.get_bytes("/workspace/raw.bin")
        assert raw == b"raw-bytes"

        put_dir = vm.put_dir(tree_dir, "/workspace/upload")
        assert put_dir.files_transferred >= 1

        read_uploaded = vm.run(
            "python3 -c 'print(open(\"/workspace/upload/sub/file.txt\", \"r\", encoding=\"utf-8\").read())'",
            timeout_s=5,
        )
        assert read_uploaded.exit_code == 0, read_uploaded.stderr
        assert read_uploaded.stdout.strip() == "payload"

        write_guest_output = vm.run(
            "python3 -c '"
            "import pathlib; "
            "root = pathlib.Path(\"/workspace/out\"); "
            "root.mkdir(parents=True, exist_ok=True); "
            "(root / \"result.txt\").write_text(\"done\", encoding=\"utf-8\")'",
            timeout_s=5,
        )
        assert write_guest_output.exit_code == 0, write_guest_output.stderr

        local_output_file = tmp_path / "result.txt"
        pulled_file = vm.get_file("/workspace/out/result.txt", local_output_file)
        assert pulled_file.files_transferred == 1
        assert local_output_file.read_text(encoding="utf-8") == "done"

        local_output_dir = tmp_path / "outdir"
        pulled_dir = vm.get_dir("/workspace/out", local_output_dir)
        assert pulled_dir.files_transferred >= 1
        assert (local_output_dir / "result.txt").read_text(encoding="utf-8") == "done"
