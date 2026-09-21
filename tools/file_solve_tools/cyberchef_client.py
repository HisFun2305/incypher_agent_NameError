"""Bounded local CyberChef Node.js API access for file artifacts."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from tools.file_solve_tools.external_process import resolve_tool, run_external_tool
from tools.flags import extract_flag, extract_flag_from_json


MAX_INPUT_BYTES = 40 * 1024
MAX_RECIPE_BYTES = 16 * 1024
_RUNNER_DIRECTORY = Path(__file__).resolve().parent / "cyberchef_runner"
_RUNNER_SCRIPT = _RUNNER_DIRECTORY / "index.cjs"


class CyberChefError(RuntimeError):
    """A local CyberChef Node.js operation could not complete safely."""


def _flag_from_payload(payload: dict[str, Any]) -> str | None:
    """Recognize flags in JSON output or a bounded base64-encoded byte result."""
    flag = extract_flag_from_json(payload)
    if flag:
        return flag
    result = payload.get("result")
    if not isinstance(result, dict) or result.get("encoding") != "base64":
        return None
    value = result.get("value")
    if not isinstance(value, str):
        return None
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
    except ValueError:
        return None
    return extract_flag(decoded)


def _artifact_bytes(path: Path) -> bytes:
    if not path.is_file():
        raise FileNotFoundError(f"Artifact does not exist or is not a file: {path}")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise CyberChefError(f"Artifact exceeds the {MAX_INPUT_BYTES}-byte CyberChef input limit")
    return path.read_bytes()


def run_cyberchef_analysis(
    artifact_path: str | Path,
    *,
    recipe: str | dict[str, Any] | list[Any],
    node_path: str | Path | None = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Bake bounded artifact bytes through a locally installed CyberChef package.

    The CyberChef Node.js API accepts buffers and compatible saved-recipe JSON.
    This wrapper does not make network requests and requires Node.js plus the
    local ``cyberchef`` npm package installed beside this module's Node.js runner.
    """
    target = Path(artifact_path).resolve()
    data = _artifact_bytes(target)
    try:
        recipe_size = len(json.dumps(recipe).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise TypeError("recipe must be JSON-serializable") from exc
    if recipe_size > MAX_RECIPE_BYTES:
        raise ValueError(f"recipe exceeds the {MAX_RECIPE_BYTES}-byte limit")
    executable = resolve_tool(
        configured_path=node_path,
        environment_variable="CYBERCHEF_NODE_PATH",
        candidates=("node", "node.exe"),
    )
    request = json.dumps(
        {"input_b64": base64.b64encode(data).decode("ascii"), "recipe": recipe}
    ).encode("utf-8")
    process = run_external_tool(
        [executable, str(_RUNNER_SCRIPT)],
        timeout=timeout,
        cwd=_RUNNER_DIRECTORY,
        input_data=request,
    )
    if process.returncode != 0:
        raise CyberChefError(process.stderr or "CyberChef Node.js recipe failed")
    try:
        payload = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise CyberChefError("CyberChef Node.js API returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise CyberChefError("CyberChef Node.js API returned an invalid result")
    return {
        "recipe": recipe,
        "response": payload,
        "output_truncated": process.output_truncated,
        "flag": _flag_from_payload(payload),
    }
