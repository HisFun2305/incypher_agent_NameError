"""API, challenge-connectivity, context, file, and SQLite preflight checks.

Run with: ``python -m tools.preflight``.
"""

from __future__ import annotations

from builtins import print as terminal_print
import os
import sqlite3
import sys
from pathlib import Path
from urllib.parse import urlparse

import tools.config  # Load repository-local credentials before reading them.
from tools.send_logs import send_logs
from tools.context import (
    CONTEXT_DB_PATH,
    get_chal_file_path,
    get_context,
    update_context,
)
from tools.ctfd_api import (
    PLATFORM_URL,
    connect_challenge_tcp,
    download_challenge_files,
    get_challenge_url,
    get_challenges,
    prepare_challenge_context,
)
from tools.llm_router import (
    OPENROUTER_MODEL,
    call_openrouter,
    list_openai_models,
)


def print(*values: object, **kwargs: object) -> None:
    """Send preflight status remotely, then always display it in the terminal."""
    try:
        send_logs(*values, **kwargs)
    except Exception:
        # A portal issue must not hide local diagnostics or stop preflight.
        pass
    terminal_print(*values, **kwargs)


def _stored_challenge_type(challenge_id: int) -> str:
    """Return a validated challenge type from prepared context."""
    context = get_context(challenge_id)
    if context is None:
        raise ValueError("challenge context was not prepared")
    challenge_type = context.get("challenge_type")
    if challenge_type not in {"file", "url", "tcp"}:
        raise ValueError(f"invalid stored challenge type: {challenge_type!r}")
    return str(challenge_type)


def check_soclaas_connection() -> bool:
    """Verify the OpenAI-compatible gateway credentials without invoking a model."""
    api_key = os.getenv("SOCLAAS_API_KEY")
    base_url = os.getenv("SOCLAAS_BASE_URL")
    if not api_key or not base_url:
        print("[-] SOCLAAS_API_KEY or SOCLAAS_BASE_URL is not set.")
        return False

    print(f"[*] Testing SOCLAas API access at {base_url}")
    try:
        models = list_openai_models(max_attempts=1)
    except Exception as exc:
        print(f"[-] SOCLAas API access failed: {exc}")
        return False

    print(f"[+] SOCLAas API access succeeded: {len(models)} model(s) available.")
    return True


def check_openrouter_model() -> bool:
    """Verify direct access to the configured Claude Sonnet 4 model."""
    if not os.getenv("OPENROUTER_API_KEY"):
        print("[*] OPENROUTER_API_KEY is not set; skipping the OpenRouter model check.")
        return True
    print(f"[*] Testing direct OpenRouter access for {OPENROUTER_MODEL}...")
    try:
        response = call_openrouter("Reply with exactly OK.", max_attempts=1)
    except Exception as exc:
        print(f"[-] OpenRouter model check failed for {OPENROUTER_MODEL}: {exc}")
        return False
    if not response:
        print(f"[-] OpenRouter model check returned no content for {OPENROUTER_MODEL}.")
        return False
    print(f"[+] OpenRouter model check succeeded: {OPENROUTER_MODEL}.")
    return True


def check_challenge_url_connection(challenges: list[dict]) -> bool:
    """Verify that a challenge URL can be deployed or entered manually."""
    print("[*] Testing challenge URL connection...")
    for challenge in challenges:
        challenge_name = str(challenge.get("name", "unnamed"))
        try:
            challenge_id = int(challenge.get("id")) #type: ignore
            if _stored_challenge_type(challenge_id) != "url":
                continue
            challenge_url = get_challenge_url(challenge_id)
        except (TypeError, ValueError) as exc:
            print(f"[-] Challenge URL connection failed for {challenge_name}: {exc}")
            continue
        except Exception as exc:
            print(f"[-] Could not connect to challenge URL for {challenge_name}: {exc}")
            continue

        parsed = urlparse(challenge_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            print(f"[-] Challenge URL is not a valid HTTP(S) URL: {challenge_url}")
            continue
        print(f"[+] Challenge URL connection succeeded for [{challenge_id}] {challenge_name}.")
        return True

    print("[-] No challenge URL connection succeeded.")
    return False


def check_challenge_tcp_connection(challenges: list[dict]) -> bool:
    """Verify one TCP challenge connection identified from its detail fields."""
    print("[*] Looking for a TCP challenge to verify connection...")
    tcp_challenge_found = False
    for challenge in challenges:
        challenge_name = str(challenge.get("name", "unnamed"))
        try:
            challenge_id = int(challenge.get("id")) #type: ignore
            if _stored_challenge_type(challenge_id) != "tcp":
                continue
        except (TypeError, ValueError) as exc:
            print(f"[-] Skipping challenge with invalid details: {challenge_name}: {exc}")
            continue
        except Exception as exc:
            print(f"[-] Could not retrieve details for {challenge_name}: {exc}")
            continue

        tcp_challenge_found = True

        try:
            connection = connect_challenge_tcp(challenge_id)
            connection.close()
        except Exception as exc:
            print(f"[-] TCP connection failed for [{challenge_id}] {challenge_name}: {exc}")
            continue

        print(f"[+] TCP connection succeeded for [{challenge_id}] {challenge_name}.")
        return True

    if not tcp_challenge_found:
        print("[+] No TCP challenge was identified; skipping TCP connection verification.")
        return True
    print("[-] No advertised TCP challenge connection succeeded.")
    return False


def check_context_retrieval(challenges: list[dict]) -> bool:
    """Verify that prepared challenge data can be retrieved from context."""
    print("[*] Testing stored challenge-context retrieval...")
    for challenge in challenges:
        challenge_name = str(challenge.get("name", "unnamed"))
        try:
            challenge_id = int(challenge.get("id")) #type: ignore
            if _stored_challenge_type(challenge_id) != "file":
                continue
        except (TypeError, ValueError) as exc:
            print(f"[-] Skipping challenge with invalid details: {challenge_name}: {exc}")
            continue

        try:
            context = get_context(challenge_id)
            if context is None:
                raise ValueError("prepared context was not found")
            required_fields = {"name", "description", "challenge_type", "file_links"}
            missing_fields = required_fields.difference(context)
            if missing_fields:
                raise ValueError(
                    f"prepared context is missing: {', '.join(sorted(missing_fields))}"
                )
        except Exception as exc:
            print(f"[-] Context retrieval failed for [{challenge_id}] {challenge_name}: {exc}")
            continue
        print(f"[+] Context retrieval succeeded for [{challenge_id}] {challenge_name}.")
        return True

    print("[-] No prepared challenge context could be retrieved.")
    return False


def check_challenge_file_download(challenges: list[dict]) -> bool:
    """Verify challenge-file downloading against the first available file asset.

    Challenges without API ``files`` links are skipped. A platform with no file
    challenges is still a successful preflight, because there is no file asset
    available to test.
    """
    print("[*] Looking for a challenge file to verify downloading...")
    for challenge in challenges:
        challenge_name = str(challenge.get("name", "unnamed"))
        try:
            challenge_id = int(challenge.get("id")) #type: ignore
        except (TypeError, ValueError) as exc:
            print(f"[-] Skipping challenge with invalid details: {challenge_name}: {exc}")
            continue
        except Exception as exc:
            print(f"[-] Could not retrieve details for {challenge_name}: {exc}")
            continue

        try:
            downloaded_paths = download_challenge_files(challenge_name, challenge_id)
        except Exception as exc:
            print(f"[-] Challenge file download failed for [{challenge_id}] {challenge_name}: {exc}")
            return False

        if not downloaded_paths:
            continue
        missing_paths = [path for path in downloaded_paths if not Path(path).is_file()]
        if missing_paths:
            print(f"[-] Download reported missing file(s): {', '.join(missing_paths)}")
            return False

        update_context(
            {"file_path": downloaded_paths[0], "file_paths": downloaded_paths},
            challenge_id,
        )
        stored_primary_path = get_chal_file_path(challenge_id)
        stored_context = get_context(challenge_id) or {}
        if stored_primary_path != downloaded_paths[0]:
            print(f"[-] Primary file-path retrieval failed for [{challenge_id}] {challenge_name}.")
            return False
        if stored_context.get("file_paths") != downloaded_paths:
            print(f"[-] File-list retrieval failed for [{challenge_id}] {challenge_name}.")
            return False
        print(
            f"[+] Challenge file download and retrieval succeeded for [{challenge_id}] "
            f"{challenge_name}: {len(downloaded_paths)} file(s)."
        )
        return True

    print("[+] No challenge files were available to test; skipping download verification.")
    return True


def check_context_sqlite_connection() -> bool:
    """Verify a direct connection to the local SQLite context database."""
    print("[*] Testing local context SQLite connection...")
    try:
        CONTEXT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(CONTEXT_DB_PATH) as connection:
            connection.execute("SELECT 1").fetchone()
    except Exception as exc:
        print(f"[-] Context SQLite connection failed: {exc}")
        return False
    print("[+] Context SQLite connection succeeded.")
    return True


def main() -> int:
    """Run the supported endpoint, connectivity, and storage checks."""
    if os.getenv("OPENROUTER_API_KEY"):
        if input("OpenRouter API key is set. Do you want to check Claude Sonnet 4? (y/n): ").strip().lower() == "y":
            if not check_openrouter_model():
                return 2
    if not check_soclaas_connection():
        return 2

    if not os.getenv("CTFD_API_TOKEN"):
        print("[-] CTFD_API_TOKEN is not set; cannot authenticate to the platform.")
        return 2

    print(f"[*] Testing read-only access to {PLATFORM_URL}/api/v1/challenges")
    try:
        challenges = get_challenges()
    except Exception as exc:
        print(f"[-] Platform access failed: {exc}")
        return 1

    if not challenges:
        print("[-] No challenges returned. Check PLATFORM_URL, CTFD_API_TOKEN, and challenge visibility.")
        return 1

    print(f"[+] Platform access succeeded: {len(challenges)} challenge(s) returned.")
    prepared_challenges: list[dict] = []
    for challenge in challenges:
        challenge_id = challenge.get("id", "unknown")
        name = challenge.get("name", "unnamed")
        category = challenge.get("category", "uncategorized")
        value = challenge.get("value", "unknown")
        print(f"    [{challenge_id}] {name} | category={category} | value={value}")
        try:
            normalized_id = int(challenge_id)
            context = prepare_challenge_context(normalized_id, str(name))
        except (TypeError, ValueError) as exc:
            print(f"[-] Skipping challenge with invalid details: {name}: {exc}")
            continue
        except Exception as exc:
            print(f"[-] Could not prepare challenge context for {name}: {exc}")
            continue
        print(f"        classified as {context['challenge_type']}")
        prepared_challenges.append(challenge)

    if not prepared_challenges:
        print("[-] No challenge details could be prepared.")
        return 1
    challenges = prepared_challenges

    if not check_context_retrieval(challenges):
        return 1
    if not check_challenge_url_connection(challenges):
        return 1
    if not check_challenge_tcp_connection(challenges):
        return 1
    if not check_challenge_file_download(challenges):
        return 1
    if not check_context_sqlite_connection():
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
