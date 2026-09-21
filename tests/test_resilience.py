"""Offline resilience tests for indefinite, evidence-gated CTF execution."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import agent
from tools import context
from tools.context import append_context_list, get_context, solver_progress, store_context, update_context
from tools.ctfd_api import ChallengeFileDownloadError, download_challenge_files
from tools.llm_router import LLMResponseError, _call_with_retry, _completion_content
from tools.llm_router import OpenRouterUnavailableError, call_openai


class ContextProgressTests(unittest.TestCase):
    """Verify scheduler bookkeeping cannot create artificial progress."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "context.sqlite3"
        self.path_patch = patch.object(context, "CONTEXT_DB_PATH", self.database_path)
        self.path_patch.start()

    def tearDown(self) -> None:
        self.path_patch.stop()
        self.temporary_directory.cleanup()

    def test_solver_progress_ignores_retry_metadata_but_tracks_artifacts(self) -> None:
        store_context({"name": "Harmless", "file_paths": ["first.bin"]}, 7)
        before = solver_progress(7)
        update_context({"solver_scheduler": {"stagnation_count": 9}}, 7)
        append_context_list([{"error": "temporary"}], "solver_errors", 7)
        append_context_list([{"event": "unsolved"}], "port_attempts", 7)
        self.assertEqual(before, solver_progress(7))
        update_context({"file_paths": ["first.bin", "derived.txt"]}, 7)
        self.assertNotEqual(before, solver_progress(7))

    def test_solver_progress_ignores_rev_attempt_narratives_but_tracks_observations(self) -> None:
        store_context(
            {
                "name": "Harmless",
                "rev_reconnaissance": [{"sha256": "artifact-hash"}],
                "rev_input_observations": [{"input": "test", "response": "same"}],
            },
            11,
        )
        before = solver_progress(11)
        append_context_list(
            [{"pass": 1, "outcome": "no_flag"}], "rev_solver_passes", 11
        )
        append_context_list(
            [{"pass": 1, "description": "Repeated static work."}],
            "rev_attempt_summaries",
            11,
        )
        self.assertEqual(before, solver_progress(11))
        append_context_list(
            [{"input": "test", "response": "new concrete response"}],
            "rev_input_observations",
            11,
        )
        self.assertNotEqual(before, solver_progress(11))

    def test_solver_progress_queries_all_read_only_sources_and_skips_failed_ones(self) -> None:
        store_context({"name": "Harmless"}, 10)
        queried: list[int] = []

        def first_source(chal_id: int) -> dict[str, object]:
            queried.append(chal_id)
            return {"artifact": "one"}

        def second_source(chal_id: int) -> dict[str, object]:
            queried.append(chal_id)
            return {"artifact": "two"}

        def failing_source(_chal_id: int) -> dict[str, object]:
            raise RuntimeError("harmless fixture failure")

        fingerprint = solver_progress(
            10,
            (("first", first_source), ("second", second_source), ("failing", failing_source)),
        )
        self.assertTrue(fingerprint.startswith("sha256:"))
        self.assertEqual(queried, [10, 10])

    @patch("agent.random.uniform", return_value=0.0)
    @patch("agent.time.time", return_value=100.0)
    def test_scheduler_increases_stagnation_without_a_retry_limit(self, _time, _jitter) -> None:
        store_context({"name": "Harmless"}, 8)
        agent._schedule_retry(8, made_progress=False)
        first = get_context(8)["solver_scheduler"]
        agent._schedule_retry(8, made_progress=False)
        second = get_context(8)["solver_scheduler"]
        self.assertEqual(first["stagnation_count"], 1)
        self.assertEqual(second["stagnation_count"], 2)
        self.assertGreater(second["next_attempt_at"], first["next_attempt_at"])


class DownloadResilienceTests(unittest.TestCase):
    """Verify a harmless partial CTF download remains usable and retryable."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.path_patch = patch.object(context, "CONTEXT_DB_PATH", self.root / "context.sqlite3")
        self.download_patch = patch("tools.ctfd_api.CHALLENGE_DOWNLOAD_DIR", self.root / "downloads")
        self.path_patch.start()
        self.download_patch.start()

    def tearDown(self) -> None:
        self.download_patch.stop()
        self.path_patch.stop()
        self.temporary_directory.cleanup()

    @patch("tools.ctfd_api._client.download")
    def test_partial_downloads_are_atomic_and_errors_are_persisted(self, download) -> None:
        store_context({"file_links": ["/good.bin", "/missing.bin"]}, 9)
        download.side_effect = [b"harmless-content", RuntimeError("offline fixture failure")]
        with self.assertRaises(ChallengeFileDownloadError) as raised:
            download_challenge_files("Harmless", 9)
        self.assertEqual(len(raised.exception.downloaded_paths), 1)
        downloaded = Path(raised.exception.downloaded_paths[0])
        self.assertEqual(downloaded.read_bytes(), b"harmless-content")
        self.assertFalse(any(self.root.rglob("*.part")))
        self.assertEqual(len(get_context(9)["file_download_errors"]), 1)

    @patch("tools.ctfd_api._mark_elf_executable")
    @patch("tools.ctfd_api._client.download", return_value=b"\x7fELFharmless-fixture")
    def test_completed_elf_download_is_marked_executable(self, download, mark_executable) -> None:
        store_context({"file_links": ["/challenge.bin"]}, 10)
        downloaded = download_challenge_files("Harmless", 10)
        self.assertEqual(len(downloaded), 1)
        mark_executable.assert_called_once()
        path, content = mark_executable.call_args.args
        self.assertEqual(path, Path(downloaded[0]))
        self.assertEqual(content, b"\x7fELFharmless-fixture")


class LLMResponseTests(unittest.TestCase):
    """Validate malformed completions become bounded retryable failures."""

    def test_empty_completion_is_rejected(self) -> None:
        response = type("Response", (), {"choices": []})()
        with self.assertRaises(LLMResponseError):
            _completion_content(response)

    @patch("tools.llm_router.time.sleep")
    def test_malformed_completion_error_is_retried(self, sleep) -> None:
        attempts = iter([LLMResponseError("bad fixture"), "usable completion"])

        def operation() -> str:
            result = next(attempts)
            if isinstance(result, Exception):
                raise result
            return result

        self.assertEqual(_call_with_retry(operation, max_attempts=2), "usable completion")
        sleep.assert_called_once()

    @patch("tools.llm_router.call_soclaas")
    @patch("tools.llm_router._complete", return_value="openrouter result")
    @patch("tools.llm_router._get_openrouter_client", return_value=object())
    def test_openrouter_is_preferred_over_soclaas(self, _client, complete, fallback) -> None:
        self.assertEqual(call_openai("harmless", chal_ID=1, max_attempts=1), "openrouter result")
        complete.assert_called_once()
        fallback.assert_not_called()

    @patch("tools.llm_router.call_soclaas", return_value="soclaas result")
    @patch(
        "tools.llm_router._get_openrouter_client",
        side_effect=OpenRouterUnavailableError("missing fixture key"),
    )
    def test_soclaas_is_used_only_after_openrouter_is_unavailable(self, _client, fallback) -> None:
        self.assertEqual(call_openai("harmless", chal_ID=1, max_attempts=1), "soclaas result")
        fallback.assert_called_once()
if __name__ == "__main__":
    unittest.main()
