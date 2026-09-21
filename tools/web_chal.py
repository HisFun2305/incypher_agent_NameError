"""Orchestration for URL-based CTF challenges."""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit, urlunsplit

import requests

from tools.context import get_chal_file_path, get_context
from tools.ctfd_api import get_challenge_url
from tools.flags import extract_flag, extract_flag_from_json
from tools.http_client import create_session, interact_http
from tools.llm_router import call_openai
from tools.send_logs import send_logs as print
from tools.web_solve_tools.graphql_workflow import (
    GraphQLOperation,
    find_graphql_endpoint,
    run_graphql_operations_at_endpoint,
)
from tools.web_solve_tools.session_auth_workflow import (
    discover_session_surface,
    run_session_actions,
    validate_session_action,
)
from tools.web_solve_tools.webpage_access_helpers import get_form_json, submit_form
from tools.web_solve_tools.web_context import (
    WEB_CONTEXT_ID,
    append_web_node,
    attempted_test_keys,
    get_web_context,
    has_recent_evidence_stall,
    pruned_web_context,
    reset_web_context,
    upsert_web_node,
)
from tools.web_solve_tools.ssti_evidence import analyze_ssti_response


WEB_CHALLENGE_SUBTYPES = ("SSTI", "GRAPHQL", "SESSION_AUTH")
SSTI_PHASES = ("discovery", "confirmation", "filter_mapping", "capability_mapping", "retrieval")
QUERY_CANDIDATE_FIELDS = ("name", "value", "query", "q", "search", "input", "message")
MAX_QUERY_CANDIDATES = 10
MAX_QUERY_DISCOVERY_PAGE_CHARS = 4000
_QUERY_FIELD_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
GRAPHQL_PHASES = (
    "root_field_discovery",
    "selection_discovery",
    "argument_discovery",
    "state_transition",
    "retrieval",
)
MAX_SSTI_ITERATIONS = 50
MAX_SSTI_TESTS_PER_ITERATION = 10
MAX_SSTI_NO_PROGRESS_ITERATIONS = 3
MAX_GRAPHQL_ITERATIONS = 50
MAX_GRAPHQL_OPERATIONS_PER_ITERATION = 4
MAX_GRAPHQL_NO_PROGRESS_ITERATIONS = 3
SESSION_AUTH_PHASES = (
    "route_discovery",
    "identifier_discovery",
    "authorization_analysis",
    "session_analysis",
    "retrieval",
)
MAX_SESSION_AUTH_ITERATIONS = 30
MAX_SESSION_ACTIONS_PER_ITERATION = 8
MAX_SESSION_AUTH_NO_PROGRESS_ITERATIONS = 3


def _extract_response_flag(response: requests.Response) -> str | None:
    """Extract a flag from a JSON response, falling back to response text."""
    try:
        payload = response.json()
    except requests.exceptions.JSONDecodeError:
        payload = None
    if isinstance(payload, (dict, list)):
        flag = extract_flag_from_json(payload)
        if flag:
            return flag
    return extract_flag(response.text)


def _parse_graphql_plan(raw_plan: str) -> dict[str, object]:
    """Parse one bounded, evidence-driven GraphQL CTF operation plan."""
    cleaned = raw_plan.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    plan = json.loads(cleaned)
    if not isinstance(plan, dict):
        raise ValueError("GraphQL LLM plan must be a JSON object")

    phase = plan.get("phase")
    hypothesis = plan.get("hypothesis")
    operations = plan.get("operations")
    advance_when = plan.get("advance_when")
    fallback = plan.get("fallback")
    if phase not in GRAPHQL_PHASES:
        raise ValueError(f"GraphQL plan phase must be one of {GRAPHQL_PHASES}")
    if not isinstance(hypothesis, str) or not hypothesis.strip():
        raise ValueError("GraphQL plan hypothesis must be a non-empty string")
    if not isinstance(operations, list) or not all(
        isinstance(operation, dict) for operation in operations
    ):
        raise ValueError("GraphQL plan operations must be a list of objects")
    if not isinstance(advance_when, str) or not isinstance(fallback, str):
        raise ValueError("GraphQL plan advance_when and fallback must be strings")

    normalized_operations: list[dict[str, object]] = []
    for operation in operations:
        query = operation.get("query")
        variables = operation.get("variables", {})
        operation_name = operation.get("operation_name")
        purpose = operation.get("purpose")
        if not isinstance(query, str) or not query.strip():
            raise ValueError("GraphQL operation query must be a non-empty string")
        if not isinstance(variables, dict):
            raise ValueError("GraphQL operation variables must be an object")
        if operation_name is not None and (
            not isinstance(operation_name, str) or not operation_name.strip()
        ):
            raise ValueError("GraphQL operation_name must be a non-empty string or null")
        if not isinstance(purpose, str) or not purpose.strip():
            raise ValueError("GraphQL operation purpose must be a non-empty string")
        GraphQLOperation(
            query=query,
            variables=variables,
            operation_name=operation_name,
        )
        normalized_operations.append(
            {
                "query": query,
                "variables": variables,
                "operation_name": operation_name,
                "purpose": purpose,
            }
        )

    return {
        "phase": phase,
        "hypothesis": hypothesis,
        "operations": normalized_operations,
        "advance_when": advance_when,
        "fallback": fallback,
    }


def _ask_for_graphql_plan(chal_ID: int, endpoint: str) -> dict[str, object]:
    """Ask for the next small, evidence-gated GraphQL CTF operation set."""
    challenge_context = get_context(chal_ID) or {}
    workflow_context = pruned_web_context(chal_ID)
    prompt = f"""You are solving an explicitly authorized, isolated CTF web challenge.

The confirmed same-origin GraphQL endpoint is {endpoint!r}. Use only the
challenge context and recorded GraphQL responses below. Treat response facts,
validator suggestions, returned object fields, and exact flag matches as
evidence; treat every other claim as a hypothesis.

Choose one phase: root_field_discovery, selection_discovery,
argument_discovery, state_transition, or retrieval. Start with the smallest
read-only query that can distinguish hypotheses. You may use a mutation only
when the challenge description and prior evidence support a specific CTF state
transition; do not guess credentials, access unrelated systems, scan hosts, or
perform destructive actions. Do not repeat an operation already represented in
the workflow context. Stop planning immediately once an exact INCYPHER{{...}}
flag is returned.

Return JSON only in exactly this shape:
{{
  "phase": "one allowed phase",
  "hypothesis": "short evidence-based hypothesis",
  "operations": [{{
    "query": "a complete GraphQL query or evidence-supported mutation",
    "variables": {{}},
    "operation_name": "optional named operation or null",
    "purpose": "the observable fact this harmless CTF operation distinguishes"
  }}],
  "advance_when": "observable condition for changing phase",
  "fallback": "next evidence-gated action if the condition is absent"
}}

Provide at most {MAX_GRAPHQL_OPERATIONS_PER_ITERATION} operations. Keep each
operation and explanation concise. Do not provide chain-of-thought.

Challenge ID: {chal_ID}
Challenge context:
{json.dumps(challenge_context, sort_keys=True)}

Pruned web workflow context:
{json.dumps(workflow_context, sort_keys=True)}
"""
    return _parse_graphql_plan(
        call_openai(prompt, require_deep_reasoning=True, chal_ID=chal_ID)
    )


def identify_web_subtype(chal_ID: int) -> str:
    """Classify a web challenge from its stored context using the configured LLM.

    The returned value is always one of ``WEB_CHALLENGE_SUBTYPES`` or
    ``"UNKNOWN"``. Keeping the output constrained makes it safe for the
    dispatcher to grow with additional subtype-specific workflows later.
    """
    challenge_context = get_context(chal_ID) or {}
    web_context = pruned_web_context(chal_ID)
    prompt = f"""You are classifying a web CTF challenge for a workflow dispatcher.

Read the challenge context below and identify its subtype. Supported subtypes
are SSTI (server-side template injection), GRAPHQL (a GraphQL API using
queries or mutations), and SESSION_AUTH (session-bound authorization,
object-access control, or a suspected signed-session weakness). Return exactly
one token: SSTI, GRAPHQL, SESSION_AUTH, or UNKNOWN. Do not explain your answer.

Challenge ID: {chal_ID}
Challenge context:
{json.dumps(challenge_context, sort_keys=True)}

Previously collected web workflow context:
{json.dumps(web_context, sort_keys=True)}
"""
    try:
        answer = call_openai(prompt, chal_ID=chal_ID).strip().upper()
    except Exception as exc:
        print(f"[web] Challenge {chal_ID} subtype classification failed: {exc}")
        return "UNKNOWN"

    # Accept harmless formatting from the model while still enforcing the
    # preset vocabulary used by the dispatcher.
    match = next((subtype for subtype in WEB_CHALLENGE_SUBTYPES if subtype in answer), None)
    return match or "UNKNOWN"


def _parse_session_auth_plan(raw_plan: str) -> dict[str, object]:
    """Parse a bounded LLM plan for session-bound authorization testing."""
    cleaned = raw_plan.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    plan = json.loads(cleaned)
    if not isinstance(plan, dict):
        raise ValueError("Session-auth LLM plan must be a JSON object")

    phase = plan.get("phase")
    hypothesis = plan.get("hypothesis")
    actions = plan.get("actions")
    advance_when = plan.get("advance_when")
    fallback = plan.get("fallback")
    if phase not in SESSION_AUTH_PHASES:
        raise ValueError(f"Session-auth plan phase must be one of {SESSION_AUTH_PHASES}")
    if not isinstance(hypothesis, str) or not hypothesis.strip():
        raise ValueError("Session-auth plan hypothesis must be a non-empty string")
    if not isinstance(actions, list) or not all(isinstance(action, dict) for action in actions):
        raise ValueError("Session-auth plan actions must be a list of objects")
    if not isinstance(advance_when, str) or not isinstance(fallback, str):
        raise ValueError("Session-auth plan advance_when and fallback must be strings")
    return {
        "phase": phase,
        "hypothesis": hypothesis,
        "actions": [validate_session_action(action) for action in actions],
        "advance_when": advance_when,
        "fallback": fallback,
    }


def _ask_for_session_auth_plan(chal_ID: int, surface: dict[str, object]) -> dict[str, object]:
    """Ask for small, evidence-gated requests against a CTF auth boundary."""
    challenge_context = get_context(chal_ID) or {}
    workflow_context = pruned_web_context(chal_ID)
    prompt = f"""You are solving an explicitly authorized, isolated CTF web challenge.

The challenge may involve session-bound authorization. A session cookie can be
a normal authorization mechanism; its presence alone does not prove a forgery
or an access-control flaw. Work from observed routes, responses, identifiers,
and cookie metadata. Do not guess credentials, crack signing keys, modify raw
cookie values, access another origin, scan hosts, or use destructive requests.

Choose one phase: route_discovery, identifier_discovery,
authorization_analysis, session_analysis, or retrieval. Propose the smallest
set of requests that distinguishes hypotheses. You may use GET or POST only.
A GET-only range probe is allowed only when prior evidence explicitly shows an
identifier pattern and a bounded contiguous range; it can contain at most 100
values and must stop on the first specified status code.

Return JSON only in exactly this shape:
{{
  "phase": "one allowed phase",
  "hypothesis": "short evidence-based hypothesis",
  "actions": [
    {{
      "kind": "request",
      "method": "GET",
      "path": "/same-origin-path",
      "params": {{}},
      "data": {{}},
      "purpose": "observable fact this request distinguishes"
    }}
  ],
  "advance_when": "observable condition for changing phase",
  "fallback": "next evidence-gated action if the condition is absent"
}}

For a range probe, replace the action object with:
{{
  "kind": "range_probe",
  "path_template": "/track/PP-{{value}}&{{value}}&",
  "start": 1,
  "end": 100,
  "stop_status": 200,
  "purpose": "why the evidenced range is worth checking"
}}

Do not include hidden chain-of-thought or a fixed exploit recipe.

Challenge context:
{json.dumps(challenge_context, sort_keys=True)}

Observed landing-page session surface (cookie values intentionally omitted):
{json.dumps(surface, sort_keys=True)}

Pruned web workflow context:
{json.dumps(workflow_context, sort_keys=True)}
"""
    return _parse_session_auth_plan(
        call_openai(prompt, require_deep_reasoning=True)
    )


def _parse_ssti_plan(raw_plan: str, form_fields: dict[str, object]) -> dict[str, object]:
    """Parse and validate one machine-readable LLM test plan."""
    cleaned = raw_plan.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    plan = json.loads(cleaned)
    if not isinstance(plan, dict):
        raise ValueError("SSTI LLM plan must be a JSON object")

    phase = plan.get("phase")
    hypothesis = plan.get("hypothesis", "")
    tests = plan.get("tests", [])
    advance_when = plan.get("advance_when", "")
    fallback = plan.get("fallback", "")
    if phase not in SSTI_PHASES:
        raise ValueError(f"SSTI plan phase must be one of {SSTI_PHASES}")
    if not isinstance(hypothesis, str) or not hypothesis.strip():
        raise ValueError("SSTI plan hypothesis must be a non-empty string")
    if not isinstance(tests, list) or not all(isinstance(test, dict) for test in tests):
        raise ValueError("SSTI plan tests must be a list of objects")
    if not isinstance(advance_when, str) or not isinstance(fallback, str):
        raise ValueError("SSTI plan advance_when and fallback must be strings")

    normalized_tests: list[dict[str, object]] = []
    for test in tests:
        field = test.get("field")
        if not isinstance(field, str) or field not in form_fields:
            raise ValueError(f"SSTI plan references unknown form field: {field!r}")
        if "value" not in test:
            raise ValueError(f"SSTI plan has no value for field: {field}")
        purpose = test.get("purpose", "")
        expected_signals = test.get("expected_signals", [])
        expected_output = test.get("expected_output")
        if not isinstance(purpose, str) or not purpose.strip():
            raise ValueError(f"SSTI plan test purpose must be a non-empty string: {field}")
        if not isinstance(expected_signals, list) or not all(isinstance(signal, str) for signal in expected_signals):
            raise ValueError(f"SSTI plan expected_signals must be a list of strings: {field}")
        if expected_output is not None and not isinstance(expected_output, str):
            raise ValueError(f"SSTI plan expected_output must be a string when supplied: {field}")
        normalized_tests.append(
            {
                "field": field,
                "value": test["value"],
                "purpose": purpose,
                "expected_signals": expected_signals,
                "expected_output": expected_output,
            }
        )
    return {
        "phase": phase,
        "hypothesis": hypothesis,
        "tests": normalized_tests,
        "advance_when": advance_when,
        "fallback": fallback,
    }


def _parse_query_field_candidates(raw_response: str) -> list[str]:
    """Validate a small LLM-proposed set of URL query parameter names."""
    cleaned = raw_response.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    value = json.loads(cleaned)
    if not isinstance(value, dict) or not isinstance(value.get("field_names"), list):
        raise ValueError("Query candidate response must contain a field_names list")
    return [
        name
        for name in value["field_names"]
        if isinstance(name, str) and _QUERY_FIELD_PATTERN.fullmatch(name)
    ]


def _discover_query_probe_schema(
    chal_ID: int,
    challenge_url: str,
    session: requests.Session,
) -> dict[str, object]:
    """Build a bounded GET-query input schema when a page has no usable form."""
    initial_response = interact_http(session, challenge_url, method="GET", path="")
    initial_response.raise_for_status()
    challenge_context = get_context(chal_ID) or {}
    prompt = f"""Identify likely URL query parameter names for an authorized web CTF.

The page has no usable HTML form. Suggest only parameter names that could be
useful for benign SSTI discovery probes. Derive names from the challenge
description and initial response where possible. Do not suggest payloads,
exploit chains, paths, or parameter values.

Return JSON only:
{{"field_names": ["short_parameter_name"]}}

Challenge context:
{json.dumps(challenge_context, sort_keys=True)}

Initial response excerpt:
{initial_response.text[:MAX_QUERY_DISCOVERY_PAGE_CHARS]}
"""
    try:
        suggested = _parse_query_field_candidates(call_openai(prompt, chal_ID=chal_ID))
    except Exception as exc:
        print(f"[web][SSTI] Query-field discovery failed: {exc}")
        suggested = []

    fields = list(dict.fromkeys((*QUERY_CANDIDATE_FIELDS, *suggested)))
    parsed = urlsplit(initial_response.url)
    base_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    return {
        "url": base_url,
        "method": "GET",
        "fields": {field: "" for field in fields[:MAX_QUERY_CANDIDATES]},
        "input_surface": "query",
    }


def _get_ssti_input_schema(
    chal_ID: int,
    challenge_url: str,
    web_context: dict[str, object],
    session: requests.Session,
) -> dict[str, object]:
    """Prefer validated form inputs, then fall back to URL query parameters."""
    try:
        schema = get_form_json(
            challenge_url,
            context=web_context,
            session=session,
            chal_ID=chal_ID,
        )
        return {**schema, "input_surface": "form"}
    except ValueError as exc:
        print(f"[web][SSTI] No usable form; probing URL query parameters instead: {exc}")
        return _discover_query_probe_schema(chal_ID, challenge_url, session)


def _ask_for_ssti_plan(chal_ID: int, form_schema: dict[str, object]) -> dict[str, object]:
    """Ask the LLM for the next field/value tests from a pruned branch."""
    challenge_context = get_context(chal_ID) or {}
    workflow_context = pruned_web_context(chal_ID)
    input_surface = str(form_schema.get("input_surface", "form"))
    prompt = f"""You are iteratively solving a web CTF challenge.

Use the challenge context, form schema, and recorded observations to choose
the next smallest set of experiments. Treat observations as facts and every
other claim as a hypothesis. Do not assume a template engine, programming
language semantics, filter mechanism, exposed capability, or flag location.

Choose one evidence-gated phase: discovery (locate possible evaluation),
confirmation (verify an observed effect), filter_mapping (isolate one input
constraint at a time), capability_mapping (learn only capabilities supported
by evidence), or retrieval (only when evidence supports a target). Prefer
tests that distinguish hypotheses. A rejection response can be useful evidence;
do not repeat an already submitted field/value pair.

Input surface: {input_surface}. The listed schema fields are the only allowed
input names. For a query surface, each test sends a same-origin GET request
with one query parameter. In discovery, prefer compact benign canary probes
and controls. A small arithmetic template-style canary may be appropriate when
the observed challenge supports that syntax; only claim evaluation when the
observed output supports it.

Return JSON only, with exactly this shape:
{{
  "phase": "one allowed phase",
  "hypothesis": "short evidence-based hypothesis",
  "tests": [{{
    "field": "field_name",
    "value": "value_to_submit",
    "purpose": "what this distinguishes",
    "expected_signals": ["observable result categories"],
    "expected_output": "optional literal output expected from a harmless probe"
  }}],
  "advance_when": "observable condition for changing phase",
  "fallback": "next action if the condition is absent"
}}

The field values must use form field names from the schema. Keep all text
concise. Do not include hidden chain-of-thought or a fixed exploit recipe.

Challenge context:
{json.dumps(challenge_context, sort_keys=True)}

Form schema:
{json.dumps(form_schema, sort_keys=True)}

Pruned workflow context:
{json.dumps(workflow_context, sort_keys=True)}
"""
    return _parse_ssti_plan(
        call_openai(prompt, require_deep_reasoning=True, chal_ID=chal_ID),
        form_schema.get("fields", {}), #type: ignore
    )


def _solve_ssti(chal_ID: int) -> str | None:
    """Iteratively choose, submit, and record SSTI field/value tests."""
    web_context = get_web_context(chal_ID)
    challenge_url = get_challenge_url(chal_ID)
    session = create_session()
    form_schema = _get_ssti_input_schema(chal_ID, challenge_url, web_context, session)
    print(f"[web][SSTI] Input schema: {json.dumps(form_schema, sort_keys=True)}")
    fields = form_schema.get("fields", {})
    if not isinstance(fields, dict) or not fields:
        raise ValueError("The SSTI input schema contains no fields")
    input_surface = str(form_schema.get("input_surface", "form"))

    for iteration in range(1, MAX_SSTI_ITERATIONS + 1):
        plan = _ask_for_ssti_plan(chal_ID, form_schema)
        tests = plan["tests"]
        assert isinstance(tests, list)
        attempted = attempted_test_keys(chal_ID)
        tests = [
            test for test in tests
            if json.dumps([test.get("field"), test.get("value")], sort_keys=True) not in attempted
        ]
        plan["tests"] = tests
        if len(tests) > MAX_SSTI_TESTS_PER_ITERATION:
            print(
                f"[web][SSTI] Iteration {iteration} suggested {len(tests)} tests; "
                f"capping at {MAX_SSTI_TESTS_PER_ITERATION}."
            )
            tests = tests[:MAX_SSTI_TESTS_PER_ITERATION]
            plan["tests"] = tests
        branch = pruned_web_context(chal_ID)["active_branch"]
        branch_summary = [
            {
                "id": node.get("id"),
                "inference": node.get("inference"),
                "status": node.get("status"),
            }
            for node in branch
        ]
        print(f"[web][SSTI] Iteration {iteration} reasoning branch:")
        print(json.dumps(branch_summary, sort_keys=True))
        print(f"[web][SSTI] Iteration {iteration} phase: {plan['phase']}")
        print(f"[web][SSTI] Iteration {iteration} hypothesis: {plan['hypothesis']}")
        print(
            f"[web][SSTI] Iteration {iteration} advance condition: {plan['advance_when']}"
        )
        print(
            f"[web][SSTI] Iteration {iteration} input test fields: "
            f"{json.dumps(tests, sort_keys=True)}"
        )
        overrides = [{test["field"]: test["value"]} for test in tests]
        if not overrides:
            append_web_node(
                chal_ID,
                parent_id=get_web_context(chal_ID)["active_node_id"],
                inference=str(plan["hypothesis"]),
                field_vars_to_test=tests,
                responses=[],
                subsequent_steps=[str(plan["fallback"])],
                phase=str(plan["phase"]),
                input_surface=input_surface,
                status="stalled",
            )
            return None

        responses = submit_form(form_schema, values=overrides, session=session)
        if not isinstance(responses, list):
            raise TypeError("Repeated SSTI submission did not return response list")

        response_records = []
        for test, payload, response in zip(tests, overrides, responses):
            observation = analyze_ssti_response(
                payload,
                response.status_code,
                response.text,
                expected_output=test.get("expected_output") if isinstance(test.get("expected_output"), str) else None,
            )
            response_records.append(
                {
                    "field": payload,
                    "status_code": response.status_code,
                    "url": response.url,
                    "text": response.text[:4000],
                    **observation,
                }
            )
        flag = next(
            (found for response in responses if (found := _extract_response_flag(response))),
            None,
        )
        evidence = [item for record in response_records for item in record["evidence"]]
        append_web_node(
            chal_ID,
            parent_id=get_web_context(chal_ID)["active_node_id"],
            inference=str(plan["hypothesis"]),
            field_vars_to_test=tests,
            responses=response_records,
            subsequent_steps=[str(plan["advance_when"]), str(plan["fallback"])],
            phase=str(plan["phase"]),
            evidence=evidence,
            input_surface=input_surface,
            status="flag_found" if flag else "active",
        )
        if flag:
            return flag
        if has_recent_evidence_stall(chal_ID, MAX_SSTI_NO_PROGRESS_ITERATIONS):
            print(f"[web][SSTI] Stopping after {MAX_SSTI_NO_PROGRESS_ITERATIONS} no-progress iterations.")
            stopped_context = get_web_context(chal_ID)
            stopped_node = stopped_context["nodes"][stopped_context["active_node_id"]]
            stopped_node["status"] = "no_progress"
            upsert_web_node(chal_ID, stopped_node)
            return None
    final_context = get_web_context(chal_ID)
    final_node = final_context["nodes"][final_context["active_node_id"]]
    final_node["status"] = "iteration_limit"
    upsert_web_node(chal_ID, final_node)
    return None


def _solve_session_auth(
    chal_ID: int,
    *,
    challenge_url: str | None = None,
    session: requests.Session | None = None,
    surface: dict[str, object] | None = None,
    initial_responses: list[requests.Response] | None = None,
) -> str | None:
    """Iteratively investigate a same-origin session authorization boundary."""
    url = challenge_url or get_challenge_url(chal_ID)
    http = session or create_session()
    if surface is None or initial_responses is None:
        surface, initial_responses = discover_session_surface(http, url)
        landing_flag = next(
            (found for response in initial_responses if (found := _extract_response_flag(response))),
            None,
        )
        surface_evidence = [
            f"Observed route: {route}"
            for route in surface.get("routes", [])
            if isinstance(route, str)
        ]
        surface_evidence.extend(
            f"Observed cookie metadata for: {cookie.get('name')}"
            for cookie in surface.get("cookies", [])
            if isinstance(cookie, dict) and isinstance(cookie.get("name"), str)
        )
        append_web_node(
            chal_ID,
            parent_id=get_web_context(chal_ID)["active_node_id"],
            inference="Collected initial same-origin routes and session cookie metadata.",
            field_vars_to_test=[{"method": "GET", "path": "/"}],
            responses=[
                {
                    "field": {"method": "GET", "path": "/"},
                    "status_code": response.status_code,
                    "url": response.url,
                    "text": response.text[:4000],
                }
                for response in initial_responses
            ],
            subsequent_steps=["Choose the smallest route or identifier test supported by this surface."],
            phase="route_discovery",
            evidence=surface_evidence,
            status="flag_found" if landing_flag else "active",
        )
        if landing_flag:
            return landing_flag

    for iteration in range(1, MAX_SESSION_AUTH_ITERATIONS + 1):
        plan = _ask_for_session_auth_plan(chal_ID, surface)
        actions = plan["actions"]
        assert isinstance(actions, list)
        if len(actions) > MAX_SESSION_ACTIONS_PER_ITERATION:
            print(
                f"[web][SESSION_AUTH] Iteration {iteration} suggested {len(actions)} "
                f"actions; capping at {MAX_SESSION_ACTIONS_PER_ITERATION}."
            )
            actions = actions[:MAX_SESSION_ACTIONS_PER_ITERATION]
        if not actions:
            append_web_node(
                chal_ID,
                parent_id=get_web_context(chal_ID)["active_node_id"],
                inference=str(plan["hypothesis"]),
                field_vars_to_test=[],
                responses=[],
                subsequent_steps=[str(plan["fallback"])],
                phase=str(plan["phase"]),
                status="stalled",
            )
            return None

        records, responses = run_session_actions(http, url, actions)
        response_records = [
            {
                "field": record.get("action"),
                "status_code": record.get("status_code"),
                "url": record.get("url"),
                "text": record.get("text", ""),
                "attempts": record.get("attempts"),
                "matched": record.get("matched"),
            }
            for record in records
        ]
        evidence = [
            f"{record.get('action', {}).get('kind', 'request')} returned "
            f"status {record.get('status_code')}"
            for record in records
            if isinstance(record.get("action"), dict)
        ]
        flag = next(
            (found for response in responses if (found := _extract_response_flag(response))),
            None,
        )
        append_web_node(
            chal_ID,
            parent_id=get_web_context(chal_ID)["active_node_id"],
            inference=str(plan["hypothesis"]),
            field_vars_to_test=actions,
            responses=response_records,
            subsequent_steps=[str(plan["advance_when"]), str(plan["fallback"])],
            phase=str(plan["phase"]),
            evidence=evidence,
            status="flag_found" if flag else "active",
        )
        if flag:
            return flag
        if has_recent_evidence_stall(chal_ID, MAX_SESSION_AUTH_NO_PROGRESS_ITERATIONS):
            print(
                "[web][SESSION_AUTH] Stopping after "
                f"{MAX_SESSION_AUTH_NO_PROGRESS_ITERATIONS} no-progress iterations."
            )
            stopped_context = get_web_context(chal_ID)
            stopped_node = stopped_context["nodes"][stopped_context["active_node_id"]]
            stopped_node["status"] = "no_progress"
            upsert_web_node(chal_ID, stopped_node)
            return None

    final_context = get_web_context(chal_ID)
    final_node = final_context["nodes"][final_context["active_node_id"]]
    final_node["status"] = "iteration_limit"
    upsert_web_node(chal_ID, final_node)
    return None


def _graphql_response_records(
    plan_operations: list[dict[str, object]],
    operation_run: object,
) -> tuple[list[dict[str, object]], list[str]]:
    """Convert bounded GraphQL results into compact web-context observations."""
    results = getattr(operation_run, "results", ())
    records: list[dict[str, object]] = []
    evidence: list[str] = []
    for result in results:
        analysis = getattr(result, "analysis", {})
        payload = getattr(result, "payload", {})
        executed_operation = getattr(result, "operation", None)
        if (
            not isinstance(analysis, dict)
            or not isinstance(payload, dict)
            or not isinstance(executed_operation, GraphQLOperation)
        ):
            continue
        planned = next(
            (
                candidate
                for candidate in plan_operations
                if candidate["query"] == executed_operation.query
                and candidate["variables"] == executed_operation.variables
                and candidate["operation_name"] == executed_operation.operation_name
            ),
            None,
        )
        purpose = planned["purpose"] if planned is not None else "Executed CTF operation"
        response_evidence = analysis.get("evidence", [])
        if isinstance(response_evidence, list):
            evidence.extend(item for item in response_evidence if isinstance(item, str))
        records.append(
            {
                "field": {
                    "query": executed_operation.query,
                    "variables": executed_operation.variables,
                    "operation_name": executed_operation.operation_name,
                },
                "purpose": purpose,
                "classification": analysis.get("classification"),
                "fingerprint": analysis.get("fingerprint"),
                "suggestions": analysis.get("suggestions", []),
                "required_arguments": analysis.get("required_arguments", []),
                "returned_facts": analysis.get("returned_facts", []),
                "text": json.dumps(payload, ensure_ascii=False, sort_keys=True)[:4000],
                "evidence": response_evidence,
            }
        )
    return records, list(dict.fromkeys(evidence))


def _solve_graphql(chal_ID: int) -> str | None:
    """Run an evidence-gated GraphQL workflow against one authorized CTF URL."""
    challenge_url = get_challenge_url(chal_ID)
    session = create_session()
    probe_result = find_graphql_endpoint(session, challenge_url)
    if probe_result is None:
        append_web_node(
            chal_ID,
            parent_id=get_web_context(chal_ID)["active_node_id"],
            inference="No same-origin GraphQL endpoint was confirmed by the read-only probe.",
            field_vars_to_test=[],
            responses=[],
            subsequent_steps=["Stop this GraphQL workflow without sending planned operations."],
            phase="root_field_discovery",
            status="endpoint_not_found",
        )
        return None

    probe_analysis = probe_result.analysis
    append_web_node(
        chal_ID,
        parent_id=get_web_context(chal_ID)["active_node_id"],
        inference="The same-origin endpoint returned a structurally valid GraphQL response.",
        field_vars_to_test=[
            {
                "query": probe_result.operation.query,
                "variables": probe_result.operation.variables,
                "operation_name": probe_result.operation.operation_name,
            }
        ],
        responses=[
            {
                "field": {"query": probe_result.operation.query},
                "classification": probe_analysis.get("classification"),
                "text": json.dumps(probe_result.payload, ensure_ascii=False, sort_keys=True)[:4000],
                "evidence": probe_analysis.get("evidence", []),
            }
        ],
        subsequent_steps=["Plan the smallest evidence-gated GraphQL operations."],
        phase="root_field_discovery",
        evidence=probe_analysis.get("evidence", []),
    )

    for iteration in range(1, MAX_GRAPHQL_ITERATIONS + 1):
        plan = _ask_for_graphql_plan(chal_ID, probe_result.endpoint)
        planned_operations = plan["operations"]
        assert isinstance(planned_operations, list)
        if len(planned_operations) > MAX_GRAPHQL_OPERATIONS_PER_ITERATION:
            print(
                f"[web][GRAPHQL] Iteration {iteration} suggested "
                f"{len(planned_operations)} operations; capping at "
                f"{MAX_GRAPHQL_OPERATIONS_PER_ITERATION}."
            )
            planned_operations = planned_operations[:MAX_GRAPHQL_OPERATIONS_PER_ITERATION]
        if not planned_operations:
            append_web_node(
                chal_ID,
                parent_id=get_web_context(chal_ID)["active_node_id"],
                inference=str(plan["hypothesis"]),
                field_vars_to_test=[],
                responses=[],
                subsequent_steps=[str(plan["fallback"])],
                phase=str(plan["phase"]),
                status="stalled",
            )
            return None

        operations = [
            GraphQLOperation(
                query=str(operation["query"]),
                variables=operation["variables"],  # type: ignore[arg-type]
                operation_name=operation["operation_name"],  # type: ignore[arg-type]
            )
            for operation in planned_operations
        ]
        operation_run = run_graphql_operations_at_endpoint(
            session,
            probe_result.endpoint,
            operations,
        )
        response_records, evidence = _graphql_response_records(
            planned_operations,
            operation_run,
        )
        print(
            f"[web][GRAPHQL] Iteration {iteration}: phase={plan['phase']} "
            f"stop_reason={operation_run.stop_reason}"
        )
        append_web_node(
            chal_ID,
            parent_id=get_web_context(chal_ID)["active_node_id"],
            inference=str(plan["hypothesis"]),
            field_vars_to_test=planned_operations,
            responses=response_records,
            subsequent_steps=[str(plan["advance_when"]), str(plan["fallback"])],
            phase=str(plan["phase"]),
            evidence=evidence,
            status="flag_found" if operation_run.flag else "active",
        )
        if operation_run.flag:
            return operation_run.flag
        if has_recent_evidence_stall(chal_ID, MAX_GRAPHQL_NO_PROGRESS_ITERATIONS):
            stopped_context = get_web_context(chal_ID)
            stopped_node = stopped_context["nodes"][stopped_context["active_node_id"]]
            stopped_node["status"] = "no_progress"
            upsert_web_node(chal_ID, stopped_node)
            return None

    final_context = get_web_context(chal_ID)
    final_node = final_context["nodes"][final_context["active_node_id"]]
    final_node["status"] = "iteration_limit"
    upsert_web_node(chal_ID, final_node)
    return None


def _run_passive_web_discovery(
    chal_ID: int,
) -> tuple[str, requests.Session, dict[str, object], list[requests.Response], str | None]:
    """Collect the bounded initial surface used for evidence-based dispatch."""
    challenge_url = get_challenge_url(chal_ID)
    session = create_session()
    surface, responses = discover_session_surface(session, challenge_url)
    evidence = [
        f"Observed route: {route}"
        for route in surface.get("routes", [])
        if isinstance(route, str)
    ]
    evidence.extend(
        f"Observed cookie metadata for: {cookie.get('name')}"
        for cookie in surface.get("cookies", [])
        if isinstance(cookie, dict) and isinstance(cookie.get("name"), str)
    )
    append_web_node(
        chal_ID,
        parent_id=get_web_context(chal_ID)["active_node_id"],
        inference="Bounded passive discovery collected same-origin routes and cookie metadata.",
        field_vars_to_test=[{"method": "GET", "path": "initial passive discovery"}],
        responses=[
            {
                "field": {"method": "GET", "path": response.url},
                "status_code": response.status_code,
                "url": response.url,
                "text": response.text[:4000],
            }
            for response in responses
        ],
        subsequent_steps=["Classify from observed routes, responses, and cookie metadata."],
        phase="route_discovery",
        evidence=evidence,
    )
    flag = next(
        (found for response in responses if (found := _extract_response_flag(response))),
        None,
    )
    return challenge_url, session, surface, responses, flag


def web_chal_progress(chal_ID: int) -> dict[str, object]:
    """Return observed web-workflow evidence without running or resetting it."""
    context = get_context(WEB_CONTEXT_ID) or {}
    if context.get("challenge_id") != chal_ID:
        return {
            "form_schema": None,
            "active_node_id": None,
            "node_count": 0,
            "observations": [],
            "evidence": [],
        }

    nodes = context.get("nodes", {})
    observations: list[dict[str, object]] = []
    evidence: list[str] = []
    if isinstance(nodes, dict):
        for node in nodes.values():
            if not isinstance(node, dict):
                continue
            for item in node.get("evidence", []):
                if isinstance(item, str) and item not in evidence:
                    evidence.append(item)
            for response in node.get("responses", []):
                if not isinstance(response, dict):
                    continue
                observation = {
                    key: response[key]
                    for key in ("field", "status_code", "url", "classification", "fingerprint")
                    if key in response
                }
                text = response.get("text")
                if isinstance(text, str):
                    observation["text"] = text[:600]
                if observation and observation not in observations:
                    observations.append(observation)

    return {
        "form_schema": context.get("form_schema"),
        "active_node_id": context.get("active_node_id"),
        "node_count": len(nodes) if isinstance(nodes, dict) else 0,
        "observations": observations,
        "evidence": evidence,
    }


def web_chal_solver(chal_ID: int) -> str | None:
    """Classify a web challenge, then dispatch to its subtype workflow."""
    reset_web_context(chal_ID)
    context = get_context(chal_ID)
    print(f"[web] Challenge {chal_ID} context: {context!r}")
    print(f"[web] Challenge {chal_ID} file path: {get_chal_file_path(chal_ID)!r}")

    try:
        challenge_url, session, surface, initial_responses, flag = _run_passive_web_discovery(
            chal_ID
        )
        if flag:
            return flag
        subtype = identify_web_subtype(chal_ID)
        print(f"[web] Challenge {chal_ID} subtype after passive discovery: {subtype}")
        if subtype not in WEB_CHALLENGE_SUBTYPES:
            print(f"[web] No workflow is implemented for subtype {subtype}.")
            return None
        if subtype == "SSTI":
            return _solve_ssti(chal_ID)
        if subtype == "GRAPHQL":
            return _solve_graphql(chal_ID)
        return _solve_session_auth(
            chal_ID,
            challenge_url=challenge_url,
            session=session,
            surface=surface,
            initial_responses=initial_responses,
        )
    except (requests.RequestException, ValueError, TypeError) as exc:
        print(f"[web] Challenge {chal_ID} {subtype} workflow failed: {exc}")
    return None   
