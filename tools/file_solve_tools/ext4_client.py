"""Bounded read-only ext4 evidence collection through debugfs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from tools.file_solve_tools.external_process import resolve_tool, run_external_tool


Ext4Operation = Literal["stats", "deleted_inodes", "journal", "inode_contents"]
_OPERATIONS = {"stats", "deleted_inodes", "journal", "inode_contents"}


def run_ext4_analysis(
    image_path: str | Path,
    *,
    operation: Ext4Operation,
    inode: int | None = None,
    debugfs_path: str | Path | None = None,
    timeout: float = 45.0,
) -> dict[str, Any]:
    """Run one fixed read-only debugfs operation against an ext4 image."""
    target = Path(image_path).resolve()
    if not target.is_file():
        raise FileNotFoundError(f"ext4 image does not exist or is not a file: {target}")
    if operation not in _OPERATIONS:
        raise ValueError(f"Unsupported ext4 operation: {operation}")
    commands = {
        "stats": "stats",
        "deleted_inodes": "lsdel",
        "journal": "logdump -a",
    }
    if operation == "inode_contents":
        if not isinstance(inode, int) or not 1 <= inode <= 2**32 - 1:
            raise ValueError("inode_contents requires a positive inode number")
        commands[operation] = f"cat <{inode}>"

    executable = resolve_tool(
        configured_path=debugfs_path,
        environment_variable="DEBUGFS_PATH",
        candidates=("debugfs", "debugfs.exe"),
    )
    result = run_external_tool(
        [executable, "-R", commands[operation], str(target)],
        timeout=timeout,
        cwd=target.parent,
    )
    return {
        "operation": operation,
        "inode": inode if operation == "inode_contents" else None,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "output_truncated": result.output_truncated,
    }
