"""Preflight endpoint-check ordering tests."""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from tools import preflight


class PreflightEndpointTests(unittest.TestCase):
    def test_soclaas_endpoint_check_follows_openrouter_checks(self) -> None:
        events: list[str] = []

        def check_openrouter() -> bool:
            events.append("openrouter")
            return True

        def check_soclaas() -> bool:
            events.append("soclaas")
            return False

        with (
            patch.dict(os.environ, {"OPENROUTER_API_KEY": "fixture"}, clear=False),
            patch("builtins.input", return_value="y"),
            patch("tools.preflight.check_openrouter_model", side_effect=check_openrouter),
            patch("tools.preflight.check_soclaas_connection", side_effect=check_soclaas),
        ):
            self.assertEqual(preflight.main(), 2)

        self.assertEqual(events, ["openrouter", "soclaas"])


if __name__ == "__main__":
    unittest.main()
