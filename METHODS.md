# Method reference

This guide describes the repository's public workflow methods. Challenge IDs
are integers: non-negative values identify CTFd challenges, while negative
values are reserved for shared workflow context.

## Agent orchestration

### `agent.py`

- `main()` fetches each challenge detail record once, prepares its JSON context,
  downloads file assets when needed, and delegates to the matching solver. An
  exact flag returned by a solver is submitted to CTFd before the challenge is
  considered complete; explicitly rejected submissions are retried.
- `_delegate(challenge_type, chal_ID)` selects the web, port, or file solver
  and accepts only an exact `INCYPHER{...}` flag string.

## Persistent context

### `tools/context.py`

All context records are JSON dictionaries stored in the local SQLite database.

- `store_context(context, chal_ID)` replaces an entire record.
- `get_context(chal_ID)` returns the record dictionary, or `None` when absent.
- `update_context(context, chal_ID)` shallow-merges fields into an existing
  record; matching keys are replaced.
- `append_context_list(values, field, chal_ID, unique=False)` atomically appends
  JSON values to a list field.
- `store_artifact_paths(filepaths, chal_ID)` records unique generated paths in
  `converted_file_paths`.
- `delete_context(chal_ID)` removes one record if it exists.
- `store_name(name, chal_ID)` and `get_name(chal_ID)` manage the `name` field.
- `store_chal_file_path(filepath, chal_ID)` and
  `get_chal_file_path(chal_ID)` manage the primary `file_path` field.

## CTFd platform access

### `tools/ctfd_api.py`

- `CTFdClient` owns the authenticated HTTP session, timeout, JSON decoding, and
  status handling shared by all CTFd requests.
- `get_challenges()` returns the visible CTFd challenge summaries.
- `get_challenge_details(challenge_id)` returns one CTFd detail object.
- `prepare_challenge_context(challenge_id, listed_name)` fetches details once
  and stores the normalized name, description, type, and file links.
- `extract_challenge_description(challenge_id)` returns `(name, description)`.
- `identify_challenge_type(challenge_id, details=None)` returns `file`, `url`, or
  `tcp` for either raw API details or normalized stored context. Downloadable
  files take priority. Web categories, HTTP(S) targets, and explicit SSTI/Jinja
  descriptions denote URL challenges; remaining challenges are TCP.
- `download_challenge_files(challenge_name, challenge_id)` downloads the file
  links in stored context and returns their local absolute paths.
- `get_challenge_url(challenge_id)` returns the deployed URL or asks for a
  manually deployed URL when the Docker platform is unavailable.
- `connect_challenge_tcp(challenge_id, timeout=15)` opens a TCP socket to a
  deployed instance or a manually supplied `nc HOST PORT` endpoint through the
  platform `solver.connect` adapter.
- `deploy_instance(challenge_id)` requests a CTFd container deployment.
- `submit_flag(challenge_id, flag)` submits a candidate flag to CTFd.

## LLM access

### `tools/llm_router.py`

- `call_openai(prompt, require_deep_reasoning=False, *, max_attempts=3)` sends a
  text chat request using the `default` alias, or `coding` when deeper reasoning
  is requested. Transient connection errors and HTTP 408, 429, 500, 502, 503,
  and 504 responses are retried with bounded exponential backoff.
- `call_multimodal_openai(prompt, image_paths, model_name='qwen3-vl:32b')`
  sends prompt text and local JPEG, PNG, GIF, or WebP images as data URLs to a
  vision-capable chat model using the same retry policy.
- `list_openai_models(max_attempts=3)` lists model IDs through that same client
  and retry path; preflight uses this instead of constructing another client.

## File conversion

### `tools/converter.py`

- `convert_audio_file(audio_path, conversion_type, output_path=None, *,
  chal_ID)` converts a SoundFile-readable mono or stereo audio file into a PNG.
  Stereo input is down-mixed to mono. Use `1` for a spectrogram or `2` for a
  waveform. With no destination supplied, it writes a descriptive PNG beside
  the source audio, records its absolute path in `converted_file_paths` in the
  supplied challenge context, and returns that path.
- `extract_zip_archive(archive_path, *, chal_ID, output_directory=None)` safely
  extracts a ZIP archive and records every extracted file in
  `converted_file_paths`. It rejects path traversal, symbolic links, more than
  1,000 files, more than 512 MiB of uncompressed content, and existing output
  files that would otherwise be overwritten.

## File-solver tools

### `tools/file_solve_tools/file_tools.py`

- `FileToolRequest` and `FileToolResult` provide the JSON-safe action and
  evidence contract for the file-solving agent.
- `execute_file_tool(request, chal_ID)` dispatches one bounded `inspect`,
  `gdb`, `wireshark`, `ghidra`, or `cyberchef` action and returns success or
  error evidence without invoking an LLM. ZIP extraction, audio conversion,
  and local executable interaction remain in `converter.py` and
  `executable_client.py`.
- `inspect` returns bounded metadata, magic identification, printable strings,
  a UTF-8 preview, and an exact flag when present.
- `run_gdb_analysis()` runs only fixed non-interactive GDB operations:
  executable metadata, functions, variables, or one symbol disassembly.
- `run_wireshark_analysis()` uses Wireshark's `tshark` CLI for a protocol
  hierarchy, TCP/UDP conversation, or bounded packet-field report.
- `run_ghidra_analysis()` imports a binary into a temporary Ghidra headless
  project and returns a bounded summary, function, or defined-string report.
- `run_cyberchef_analysis()` bakes bounded artifact bytes through the local
  CyberChef Node.js API and returns its JSON-safe result. It requires Node.js
  and the dependency declared beside its runner in
  `tools/file_solve_tools/cyberchef_runner/package.json`, not an API URL.

### `tools/file_chal.py`

- `file_chal_solver(chal_ID)` runs at most 20 LLM-selected, validated actions
  per invocation. Every action result is written immediately to
  `file_tool_results` and `file_solver_state` in the challenge JSON context;
  the next LLM turn receives that evidence. It returns an observed flag, a
  terminal planning failure, or `None` after its 20-action limit so the outer
  orchestrator can schedule another attempt.
- `analyze_image` is a solver action for JPEG, PNG, GIF, and WebP artifacts.
  It sends one selected local image plus a bounded question to the configured
  vision-capable model and stores its textual analysis as durable evidence.
- `run_executable` is available for workspace-local ELF and PE file artifacts
  only after every discovered ZIP archive has been expanded. The file solver
  records successful ZIP extractions, then registers exact executable paths in
  `allowed_executables` and marks them executable for the remote solver
  container. It supports stateful `start`, `send`, `receive`, and `close`
  operations for one solver invocation; each result contains a logical session
  handle and bounded transcript evidence. The existing process bounds still
  apply: the session lifetime defaults to 180 seconds and can be configured
  with `FILE_SOLVER_EXECUTABLE_SESSION_SECONDS` from 15 to 600 seconds, while
  each read remains capped at 15 seconds. All live sessions close when that
  invocation exits.

## Web challenge workflow

### `tools/web_chal.py`

- `web_chal_solver(chal_ID)` reads stored context, identifies a web subtype,
  and runs the implemented subtype workflow.
- `identify_web_subtype(chal_ID)` asks the LLM to choose the currently
  supported `SSTI` subtype or `UNKNOWN`.
- `_solve_ssti(chal_ID)` discovers a form, submits the current SSTI probes,
  stores bounded responses in shared web context, and extracts a flag when one
  appears.

### `tools/web_solve_tools/webpage_access_helpers.py`

- `get_form_json(challenge_url, context, session, chal_ID)` returns a cached
  validated form schema when available; otherwise discovers, validates, and
  stores the first usable form.
- `submit_form(form_schema, values, session)` performs one or multiple GET or
  POST form submissions.
- `validate_form_json(form_schema, session, test_variables)` submits safe test
  values and accepts HTTP responses in the 2xx or 3xx range.
- `extract_flag(text)` is imported from `tools/flags.py` and returns the first
  exact, case-sensitive `INCYPHER{...}` value in a response.

### `tools/flags.py`

- `extract_flag(text)` is the shared flag recognizer used by orchestration,
  web response analysis, and the TCP solver.

## HTTP and TCP helpers

### `tools/http_client.py`

- `create_session()` returns a cookie-preserving `requests` session with proxy
  environment variables disabled.
- `same_origin_url(base_url, path)` resolves a path and rejects cross-origin
  destinations.
- `interact_http(session, base_url, method, path, params, data, timeout)` sends
  a bounded same-origin GET or form-encoded POST request.
- `request_json(session, base_url, method, path, params, json_body, timeout)`
  sends a same-origin GET or JSON-encoded POST and returns a decoded JSON object
  or array.
- `graphql_query(session, base_url, query, variables, path, operation_name,
  timeout)` posts a GraphQL operation and returns the full response object,
  including any GraphQL `errors` entries.

### `tools/tcp_client.py` and `solver.py`

- `connect_tcp(ip, port, team_key)` is the single adapter around
  `solver.connect`.
- `interact_tcp(ip, port, team_key, payload=None)` opens a platform TCP
  connection, optionally sends one line, then returns the first response.
- `solver.connect(ip, port, team_key)` is currently a local mock because the
  platform helper library is unavailable. Replace the mock when that helper is
  supplied; callers do not need to change.

## Solver placeholders

### `tools/port_chal.py` and `tools/file_chal.py`

- `port_chal_solver(chal_ID)` connects, asks the LLM for one input, records an
  unsuccessful attempt atomically, and returns an observed valid flag.
- `file_chal_solver(chal_ID)` inventories downloaded artifacts, safely expands
  ZIP files, creates waveform and spectrogram PNGs for supported audio, and
  can ask the vision-capable model to analyze JPEG, PNG, GIF, or WebP evidence.
  It returns control after 20 actions without an observed flag. Workspace-local
  ELF/PE artifacts are automatically allowlisted for `ExecutableClient` only
  after every discovered ZIP archive is expanded, including nested archives;
  shell and network access are not implicit.

## Preflight

### `tools/preflight.py`

- `check_soclaas_connection()` verifies gateway credentials with a read-only
  model-list request.
- `check_challenge_url_connection(challenges)` and
  `check_challenge_tcp_connection(challenges)` attempt one suitable challenge
  connection while continuing past individual failures.
- `check_context_retrieval(challenges)` verifies that normalized challenge
  fields can be read from stored context.
- `check_challenge_file_download(challenges)` verifies one downloadable file
  asset and retrieves its stored primary path and complete path list.
- `check_context_sqlite_connection()` opens SQLite directly and performs a
  minimal query.
- `main()` runs the checks in order and returns a process exit code.

## Constrained executable interaction

`tools/executable_client.py` exposes local-only process interaction for
authorized CTF artifacts. After all discovered ZIP archives are expanded, the
file solver automatically builds its workspace-local executable allowlist from
ELF/PE artifacts, including ZIP extractions. It supports bounded byte/line
send and receive operations,
timeouts, lifecycle control, and redacted transcripts.  Receive-related
errors expose ``partial_data`` and send-related errors expose
``attempted_data``; the same evidence is retained in the transcript before an
error is raised.  It deliberately does
not expose shell execution, caller-controlled environments or working
directories, networking, serial devices, SSH, interactive mode, debugger
attachment, or process-memory operations.

## Resilient execution loop

`agent.py` keeps each challenge in an unbounded retry queue until an exact
flag is returned. Failures are isolated per challenge. `solver_progress()`
queries every registered solver's read-only progress snapshot and creates a
stable hash of durable evidence while excluding retry metadata and error logs;
unchanged evidence increases a capped exponential backoff with jitter, while
new evidence resets it. `SolverBinding` keeps each solver's `solve()` method
separate from its `progress()` method, so the orchestrator has no solver-
specific state logic. Challenge-file downloads stage each asset in a temporary
file and atomically replace the destination only after the download completes.

## LLM routing

`tools/llm_router.py` tries OpenRouter before SOCLAAS when
`OPENROUTER_API_KEY` is configured. Every OpenRouter request currently uses
`anthropic/claude-sonnet-4`; SOCLAAS remains the fallback when OpenRouter is
unavailable.

`tools.preflight.check_openrouter_model()` directly probes Claude Sonnet 4 when
`OPENROUTER_API_KEY` is configured.
