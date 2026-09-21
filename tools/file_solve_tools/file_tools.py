"""File-analysis tools with a common result contract.

These helpers are intentionally independent of the LLM and challenge solver.
The future solver loop can select one validated ``FileToolRequest``, execute
it, and use its JSON-safe ``FileToolResult`` as evidence for its next choice.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from tools.flags import extract_flag
from tools.file_solve_tools.audio_client import run_audio_analysis
from tools.file_solve_tools.cyberchef_client import run_cyberchef_analysis
from tools.file_solve_tools.ext4_client import run_ext4_analysis
from tools.file_solve_tools.gdb_client import run_gdb_analysis
from tools.file_solve_tools.ghidra_client import run_ghidra_analysis
from tools.file_solve_tools.wireshark_client import run_wireshark_analysis


MAX_INSPECT_BYTES = 64 * 1024
MAX_STRINGS = 100
_PRINTABLE_STRING = re.compile(rb"[ -~]{4,}")
_TOOLS = frozenset({"inspect", "audio", "ext4", "gdb", "wireshark", "ghidra", "cyberchef"})


@dataclass(frozen=True)
class FileToolRequest:
    """One validated tool choice made by a future file-solving agent."""

    tool: str
    artifact_path: str
    arguments: Mapping[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if self.tool not in _TOOLS:
            raise ValueError(f"Unsupported file tool: {self.tool}")
        if not isinstance(self.artifact_path, str) or not self.artifact_path.strip():
            raise ValueError("artifact_path must be a non-empty string")
        if not isinstance(self.arguments, Mapping):
            raise TypeError("arguments must be a mapping")


@dataclass(frozen=True)
class FileToolResult:
    """JSON-safe evidence returned by one file-tool invocation."""

    tool: str
    artifact_path: str
    status: str
    output: Mapping[str, Any]
    artifact_paths: tuple[str, ...] = ()
    flag: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "artifact_path": self.artifact_path,
            "status": self.status,
            "output": dict(self.output),
            "artifact_paths": list(self.artifact_paths),
            "flag": self.flag,
        }


def _existing_file(value: str) -> Path:
    path = Path(value).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Artifact does not exist or is not a file: {path}")
    return path


def _file_kind(data: bytes) -> str:
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return "wav"
    if data.startswith(b"\xd4\xc3\xb2\xa1") or data.startswith(b"\xa1\xb2\xc3\xd4"):
        return "pcap"
    return "unknown"


def inspect_artifact(artifact_path: str, *, max_bytes: int = MAX_INSPECT_BYTES) -> FileToolResult:
    """Return bounded metadata, magic, printable strings, and a text preview."""
    if not isinstance(max_bytes, int) or not 1 <= max_bytes <= MAX_INSPECT_BYTES:
        raise ValueError(f"max_bytes must be between 1 and {MAX_INSPECT_BYTES}")
    path = _existing_file(artifact_path)
    with path.open("rb") as artifact:
        data = artifact.read(max_bytes)
    strings = [match.group().decode("ascii", errors="replace") for match in _PRINTABLE_STRING.finditer(data)]
    strings = strings[:MAX_STRINGS]
    text_preview = data.decode("utf-8", errors="replace")[:max_bytes]
    flag = extract_flag(text_preview)
    return FileToolResult(
        tool="inspect",
        artifact_path=str(path),
        status="ok",
        output={
            "size": path.stat().st_size,
            "inspected_bytes": len(data),
            "sha256_prefix": hashlib.sha256(data).hexdigest(),
            "kind": _file_kind(data),
            "printable_strings": strings,
            "text_preview": text_preview,
        },
        flag=flag,
    )


def execute_file_tool(
    request: FileToolRequest,
    *,
    chal_ID: int,
) -> FileToolResult:
    """Execute one request and return errors as structured evidence.

    This is the single dispatch point the future LLM loop should call after it
    has parsed and validated its proposed action.
    """
    try:
        request.validate()
        if request.tool == "inspect":
            return inspect_artifact(request.artifact_path, **dict(request.arguments))
        if request.tool == "audio":
            output = run_audio_analysis(request.artifact_path, **dict(request.arguments))
        elif request.tool == "ext4":
            output = run_ext4_analysis(request.artifact_path, **dict(request.arguments))
        elif request.tool == "gdb":
            output = run_gdb_analysis(request.artifact_path, **dict(request.arguments))
        elif request.tool == "wireshark":
            output = run_wireshark_analysis(request.artifact_path, **dict(request.arguments))
        elif request.tool == "cyberchef":
            output = run_cyberchef_analysis(request.artifact_path, **dict(request.arguments))
        else:
            output = run_ghidra_analysis(request.artifact_path, **dict(request.arguments))
        evidence = "\n".join(
            str(output.get(key, "")) for key in ("report", "stdout", "stderr")
        )
        return FileToolResult(
            tool=request.tool,
            artifact_path=str(_existing_file(request.artifact_path)),
            status="error" if output.get("returncode", 0) != 0 else "ok",
            output=output,
            flag=output.get("flag") or extract_flag(evidence),
        )
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        return FileToolResult(
            tool=request.tool,
            artifact_path=request.artifact_path,
            status="error",
            output={"error": str(exc)},
        )
