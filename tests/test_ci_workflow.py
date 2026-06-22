"""Hermetic self-validation test for .github/workflows/ci.yml.

Pure file-parse only: no DB, no network, no Anthropic, no cloud SDKs.
Does not use pool / make_tenant / make_tenant_with_key from conftest.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_workflow() -> dict[str, Any]:
    """Parse and return the workflow YAML as a dict."""
    return yaml.safe_load(WORKFLOW.read_text())


def _get_triggers(data: dict[str, Any]) -> Any:
    """Return the triggers value, handling PyYAML YAML 1.1 `on` → True quirk."""
    return data.get("on", data.get(True))


def _all_services(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a flat list of every service dict across all jobs."""
    services: list[dict[str, Any]] = []
    for job in data.get("jobs", {}).values():
        for svc in (job.get("services") or {}).values():
            services.append(svc)
    return services


def _all_steps(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a flat list of every step dict across all jobs."""
    steps: list[dict[str, Any]] = []
    for job in data.get("jobs", {}).values():
        steps.extend(job.get("steps") or [])
    return steps


def _all_run_text(data: dict[str, Any]) -> str:
    """Concatenate every step's `run` text across all jobs (absent → empty string)."""
    parts: list[str] = []
    for step in _all_steps(data):
        parts.append(step.get("run") or "")
    return "\n".join(parts)


def _service_has_healthcheck(svc: dict[str, Any]) -> bool:
    """Return True if the service declares a Postgres healthcheck in either form."""
    options = svc.get("options") or ""
    if "--health-cmd" in options and "pg_isready" in options:
        return True
    healthcheck = svc.get("healthcheck") or {}
    test = healthcheck.get("test") or ""
    if isinstance(test, list):
        test = " ".join(test)
    return "pg_isready" in test


# ---------------------------------------------------------------------------
# R1: Workflow file exists
# ---------------------------------------------------------------------------


def test_r1_workflow_file_exists() -> None:
    """R1 / AC1: .github/workflows/ci.yml must exist."""
    assert WORKFLOW.is_file(), f"Workflow file not found at {WORKFLOW}"


# ---------------------------------------------------------------------------
# R2: Valid YAML mapping
# ---------------------------------------------------------------------------


def test_r2_valid_yaml_mapping() -> None:
    """R2 / AC1: File must parse as valid YAML and the top-level value must be a mapping."""
    data = _load_workflow()
    assert isinstance(data, dict), (
        f"Expected top-level YAML to be a mapping (dict), got {type(data).__name__}"
    )


# ---------------------------------------------------------------------------
# R3: pull_request trigger present
# ---------------------------------------------------------------------------


def test_r3_pull_request_trigger_present() -> None:
    """R3 / AC3: Triggers must include pull_request."""
    data = _load_workflow()
    triggers = _get_triggers(data)
    assert triggers is not None, "No triggers found under 'on' key"
    # triggers may be a dict (mapping form) or a list
    if isinstance(triggers, dict):
        assert "pull_request" in triggers, (
            f"'pull_request' trigger not found in triggers mapping: {list(triggers.keys())}"
        )
    else:
        assert "pull_request" in triggers, (
            f"'pull_request' trigger not found in triggers list: {triggers}"
        )


# ---------------------------------------------------------------------------
# R4: push trigger present with non-empty single-branch branches restriction
# ---------------------------------------------------------------------------


def test_r4_push_trigger_present() -> None:
    """R4 / AC4: Triggers must include push."""
    data = _load_workflow()
    triggers = _get_triggers(data)
    assert triggers is not None, "No triggers found under 'on' key"
    if isinstance(triggers, dict):
        assert "push" in triggers, (
            f"'push' trigger not found in triggers mapping: {list(triggers.keys())}"
        )
    else:
        assert "push" in triggers, (
            f"'push' trigger not found in triggers list: {triggers}"
        )


def test_r4_push_has_nonempty_branches_restriction() -> None:
    """R4 / AC4: The push trigger must carry a non-empty branches restriction.

    A list-form `on: [push, pull_request]` cannot carry branches; spec mandates the
    mapping shape for push so that a single default-branch filter is present.
    """
    data = _load_workflow()
    triggers = _get_triggers(data)
    assert isinstance(triggers, dict), (
        "Triggers must use the mapping form so push can carry a branches restriction; "
        f"got type {type(triggers).__name__}"
    )
    push_config = triggers.get("push")
    assert push_config is not None, "push trigger is missing or null"
    assert isinstance(push_config, dict), (
        f"push trigger config must be a mapping, got {type(push_config).__name__}"
    )
    branches = push_config.get("branches")
    assert branches, (
        "push trigger must have a non-empty branches restriction; "
        f"got branches={branches!r}"
    )
    assert len(branches) >= 1, (
        f"push.branches must contain at least one branch name; got {branches}"
    )


# ---------------------------------------------------------------------------
# R5: A service uses the apache/age image
# ---------------------------------------------------------------------------


def test_r5_service_uses_apache_age_image() -> None:
    """R5 / AC5: At least one service image must contain 'apache/age'."""
    data = _load_workflow()
    services = _all_services(data)
    assert services, "No services found across any job"
    images = [svc.get("image", "") for svc in services]
    assert any("apache/age" in img for img in images), (
        f"No service image contains 'apache/age'; found: {images}"
    )


def test_r5_age_service_postgres_env() -> None:
    """AC5: The apache/age service must have the correct POSTGRES_* env values."""
    data = _load_workflow()
    age_services = [
        svc for svc in _all_services(data) if "apache/age" in (svc.get("image") or "")
    ]
    assert age_services, "No apache/age service found"
    for svc in age_services:
        env = svc.get("env") or {}
        assert env.get("POSTGRES_USER") == "postgres", (
            f"POSTGRES_USER must be 'postgres'; got {env.get('POSTGRES_USER')!r}"
        )
        assert env.get("POSTGRES_PASSWORD") == "postgres", (
            f"POSTGRES_PASSWORD must be 'postgres'; got {env.get('POSTGRES_PASSWORD')!r}"
        )
        assert env.get("POSTGRES_DB") == "infra_twin", (
            f"POSTGRES_DB must be 'infra_twin'; got {env.get('POSTGRES_DB')!r}"
        )


def test_r5_age_service_port_mapping() -> None:
    """AC6: The apache/age service must map port 5433:5432 (host:container)."""
    data = _load_workflow()
    age_services = [
        svc for svc in _all_services(data) if "apache/age" in (svc.get("image") or "")
    ]
    assert age_services, "No apache/age service found"
    for svc in age_services:
        ports = svc.get("ports") or []
        port_strings = [str(p) for p in ports]
        assert any("5433:5432" in p for p in port_strings), (
            f"Service must map 5433:5432; got ports: {ports}"
        )


# ---------------------------------------------------------------------------
# R6: The apache/age service declares a Postgres healthcheck
# ---------------------------------------------------------------------------


def test_r6_age_service_has_healthcheck() -> None:
    """R6 / AC7: The apache/age service must declare a healthcheck referencing pg_isready."""
    data = _load_workflow()
    age_services = [
        svc for svc in _all_services(data) if "apache/age" in (svc.get("image") or "")
    ]
    assert age_services, "No apache/age service found"
    for svc in age_services:
        assert _service_has_healthcheck(svc), (
            "apache/age service must declare a healthcheck containing '--health-cmd' and "
            f"'pg_isready' in options (or 'pg_isready' in healthcheck.test); "
            f"got options={svc.get('options')!r}, healthcheck={svc.get('healthcheck')!r}"
        )


def test_r6_age_service_options_contains_health_cmd() -> None:
    """AC7 (options string form): options must contain --health-cmd."""
    data = _load_workflow()
    age_services = [
        svc for svc in _all_services(data) if "apache/age" in (svc.get("image") or "")
    ]
    assert age_services, "No apache/age service found"
    for svc in age_services:
        options = svc.get("options") or ""
        # Accept either options string or healthcheck map
        healthcheck = svc.get("healthcheck") or {}
        hc_test = healthcheck.get("test") or ""
        if isinstance(hc_test, list):
            hc_test = " ".join(hc_test)
        has_options_form = "--health-cmd" in options
        has_map_form = "pg_isready" in hc_test
        assert has_options_form or has_map_form, (
            f"Service must declare healthcheck via options '--health-cmd' or healthcheck.test; "
            f"options={options!r}"
        )


# ---------------------------------------------------------------------------
# R7: Job invokes migrate gate
# ---------------------------------------------------------------------------


def test_r7_migrate_step_present() -> None:
    """R7 / AC9: A step run must contain 'infra_twin.db.migrate' or 'make migrate'."""
    data = _load_workflow()
    run_text = _all_run_text(data)
    assert ("infra_twin.db.migrate" in run_text) or ("make migrate" in run_text), (
        "No step run text contains 'infra_twin.db.migrate' or 'make migrate';\n"
        f"concatenated run text:\n{run_text}"
    )


# ---------------------------------------------------------------------------
# R8: Job invokes pytest gate
# ---------------------------------------------------------------------------


def test_r8_pytest_step_present() -> None:
    """R8 / AC9: A step run must contain 'pytest' or 'make test'."""
    data = _load_workflow()
    run_text = _all_run_text(data)
    assert ("pytest" in run_text) or ("make test" in run_text), (
        "No step run text contains 'pytest' or 'make test';\n"
        f"concatenated run text:\n{run_text}"
    )


# ---------------------------------------------------------------------------
# R9: No hardcoded secrets / long-lived credentials
# ---------------------------------------------------------------------------


def test_r9_no_secrets_expression() -> None:
    """R9 / AC10: Raw file text must not contain '${{ secrets.'."""
    raw = WORKFLOW.read_text()
    assert "${{ secrets." not in raw, (
        "Workflow must not use ${{ secrets.* }} expressions"
    )


def test_r9_no_anthropic_api_key() -> None:
    """R9 / AC10: Raw file text must not contain 'ANTHROPIC_API_KEY'."""
    raw = WORKFLOW.read_text()
    assert "ANTHROPIC_API_KEY" not in raw, (
        "Workflow must not reference ANTHROPIC_API_KEY"
    )


def test_r9_no_aws_access_key_id() -> None:
    """R9 / AC10: Raw file text must not contain 'AWS_ACCESS_KEY_ID'."""
    raw = WORKFLOW.read_text()
    assert "AWS_ACCESS_KEY_ID" not in raw, (
        "Workflow must not reference AWS_ACCESS_KEY_ID"
    )


def test_r9_no_aws_secret_access_key() -> None:
    """R9 / AC10: Raw file text must not contain 'AWS_SECRET_ACCESS_KEY'."""
    raw = WORKFLOW.read_text()
    assert "AWS_SECRET_ACCESS_KEY" not in raw, (
        "Workflow must not reference AWS_SECRET_ACCESS_KEY"
    )


def test_r9_no_aws_session_token() -> None:
    """R9 / AC10: Raw file text must not contain 'AWS_SESSION_TOKEN'."""
    raw = WORKFLOW.read_text()
    assert "AWS_SESSION_TOKEN" not in raw, (
        "Workflow must not reference AWS_SESSION_TOKEN"
    )


# ---------------------------------------------------------------------------
# AC8: Job-level env values are exact DSN strings
# ---------------------------------------------------------------------------


def test_ac8_admin_database_url_exact() -> None:
    """AC8: ADMIN_DATABASE_URL must be exactly 'postgresql://postgres:postgres@localhost:5433/infra_twin'."""
    data = _load_workflow()
    for job_id, job in data.get("jobs", {}).items():
        env = job.get("env") or {}
        if "ADMIN_DATABASE_URL" in env:
            assert env["ADMIN_DATABASE_URL"] == "postgresql://postgres:postgres@localhost:5433/infra_twin", (
                f"Job '{job_id}' ADMIN_DATABASE_URL mismatch: {env['ADMIN_DATABASE_URL']!r}"
            )
            return
    raise AssertionError("ADMIN_DATABASE_URL not set in any job-level env")


def test_ac8_database_url_exact() -> None:
    """AC8: DATABASE_URL must be exactly 'postgresql://app:app@localhost:5433/infra_twin'."""
    data = _load_workflow()
    for job_id, job in data.get("jobs", {}).items():
        env = job.get("env") or {}
        if "DATABASE_URL" in env:
            assert env["DATABASE_URL"] == "postgresql://app:app@localhost:5433/infra_twin", (
                f"Job '{job_id}' DATABASE_URL mismatch: {env['DATABASE_URL']!r}"
            )
            return
    raise AssertionError("DATABASE_URL not set in any job-level env")


# ---------------------------------------------------------------------------
# AC9: Step ordering — migrate strictly before pytest
# ---------------------------------------------------------------------------


def test_ac9_migrate_before_pytest_ordering() -> None:
    """AC9 / E4: The migrate step must appear strictly before the pytest step in every job."""
    data = _load_workflow()
    for job_id, job in data.get("jobs", {}).items():
        steps = job.get("steps") or []
        migrate_idx: int | None = None
        pytest_idx: int | None = None
        for i, step in enumerate(steps):
            run_text = step.get("run") or ""
            if ("infra_twin.db.migrate" in run_text or "make migrate" in run_text):
                if migrate_idx is None:
                    migrate_idx = i
            if ("pytest" in run_text or "make test" in run_text):
                if pytest_idx is None:
                    pytest_idx = i
        if migrate_idx is not None and pytest_idx is not None:
            assert migrate_idx < pytest_idx, (
                f"Job '{job_id}': migrate step (index {migrate_idx}) must come before "
                f"pytest step (index {pytest_idx})"
            )


def test_ac9_checkout_step_present() -> None:
    """AC9: At least one step must use actions/checkout."""
    data = _load_workflow()
    steps = _all_steps(data)
    uses_values = [step.get("uses") or "" for step in steps]
    assert any("actions/checkout" in u for u in uses_values), (
        f"No step uses 'actions/checkout'; found uses: {uses_values}"
    )


def test_ac9_setup_uv_step_present() -> None:
    """AC9: At least one step must use astral-sh/setup-uv (or similar uv installer)."""
    data = _load_workflow()
    steps = _all_steps(data)
    uses_values = [step.get("uses") or "" for step in steps]
    assert any("setup-uv" in u for u in uses_values), (
        f"No step uses a setup-uv action; found uses: {uses_values}"
    )


def test_ac9_uv_sync_step_present() -> None:
    """AC9: A step run must contain 'uv sync'."""
    data = _load_workflow()
    run_text = _all_run_text(data)
    assert "uv sync" in run_text, (
        "No step run text contains 'uv sync';\n"
        f"concatenated run text:\n{run_text}"
    )


# ---------------------------------------------------------------------------
# E1 regression: on-key boolean quirk handled correctly
# ---------------------------------------------------------------------------


def test_e1_on_key_boolean_quirk_handled() -> None:
    """E1: _get_triggers must return a non-None value (handles True-key quirk)."""
    data = _load_workflow()
    triggers = _get_triggers(data)
    assert triggers is not None, (
        "Triggers resolved to None — YAML 'on:' key may have parsed as boolean True "
        "and lookup failed. data keys: " + str(list(data.keys()))
    )


# ---------------------------------------------------------------------------
# E2: on uses the mapping form (required for push branches filter)
# ---------------------------------------------------------------------------


def test_e2_triggers_use_mapping_form() -> None:
    """E2: The triggers must use the YAML mapping form, not a bare list."""
    data = _load_workflow()
    triggers = _get_triggers(data)
    assert isinstance(triggers, dict), (
        f"Triggers must be a mapping (dict) to support push.branches; got {type(triggers).__name__}"
    )


# ---------------------------------------------------------------------------
# E8: Steps without `run` yield empty string (regression guard)
# ---------------------------------------------------------------------------


def test_e8_steps_without_run_do_not_raise() -> None:
    """E8: Concatenating run text must not raise even when steps lack a 'run' key."""
    data = _load_workflow()
    # This must not raise; if it does the helper is broken
    run_text = _all_run_text(data)
    assert isinstance(run_text, str)


# ---------------------------------------------------------------------------
# AC2 guard: test file itself must not import DB/network dependencies
# (Check by inspecting this module's own namespace, not the global sys.modules
#  which conftest.py legitimately populates with psycopg etc.)
# ---------------------------------------------------------------------------


def test_ac2_no_db_network_imports_in_this_module() -> None:
    """AC2: Confirm this module's own source imports no DB/network packages.

    We inspect the source text rather than sys.modules because pytest loads
    conftest.py before this module and conftest legitimately imports psycopg;
    sys.modules therefore contains psycopg regardless of what this file imports.

    We use AST parsing to check actual import nodes, not substring matching, so
    the list of forbidden names inside this function body does not self-trigger.
    """
    import ast

    source = Path(__file__).read_text()
    tree = ast.parse(source)

    forbidden_modules = {"psycopg", "boto3", "anthropic", "httpx"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top not in forbidden_modules, (
                    f"test_ci_workflow.py must not import '{alias.name}'; "
                    "this module must be hermetic (no DB/network dependencies)"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0]
                assert top not in forbidden_modules, (
                    f"test_ci_workflow.py must not import from '{node.module}'; "
                    "this module must be hermetic (no DB/network dependencies)"
                )

    # Also confirm none of the conftest fixture names appear as injected parameters
    import re
    conftest_fixtures = ["pool", "make_tenant", "make_tenant_with_key"]
    for fixture in conftest_fixtures:
        pattern = rf"def test_\w+\([^)]*\b{re.escape(fixture)}\b"
        assert not re.search(pattern, source), (
            f"test_ci_workflow.py must not inject the conftest fixture '{fixture}'"
        )
