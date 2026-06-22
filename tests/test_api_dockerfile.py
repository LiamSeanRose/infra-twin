"""Hermetic self-validation test for the root Dockerfile and .dockerignore.

Pure file-parse only: no DB, no network, no Anthropic, no cloud SDKs.
Does not use pool / make_tenant / make_tenant_with_key from conftest.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO_ROOT / "Dockerfile"
DOCKERIGNORE = REPO_ROOT / ".dockerignore"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _Directive(NamedTuple):
    name: str   # upper-cased keyword, e.g. "FROM", "USER"
    value: str  # everything after the keyword on that logical line


def _parse_dockerfile() -> tuple[str, list[_Directive]]:
    """Return (raw_text, list_of_directives).

    Logical lines are produced by:
    1. Stripping blank lines and lines whose first non-space character is '#'.
    2. Joining trailing-backslash line continuations into one logical line.
    Each logical line is split on the first whitespace run to get (name, value).
    Parser directives (lines before the first instruction, e.g. `# syntax=…`)
    are comments and are already stripped by rule 1.
    """
    raw = DOCKERFILE.read_text()
    physical_lines = raw.splitlines()

    # Resolve backslash line continuations.
    logical_lines: list[str] = []
    buf: list[str] = []
    for line in physical_lines:
        stripped = line.rstrip()
        # Strip inline comment — only if not inside quotes (good enough for Dockerfile)
        comment_pos = stripped.find(" #")
        if comment_pos != -1:
            stripped = stripped[:comment_pos].rstrip()
        if stripped.endswith("\\"):
            buf.append(stripped[:-1])
        else:
            buf.append(stripped)
            joined = " ".join(buf).strip()
            buf = []
            if joined and not joined.startswith("#"):
                logical_lines.append(joined)

    if buf:
        joined = " ".join(buf).strip()
        if joined and not joined.startswith("#"):
            logical_lines.append(joined)

    directives: list[_Directive] = []
    for line in logical_lines:
        parts = line.split(None, 1)
        if len(parts) == 2:
            directives.append(_Directive(parts[0].upper(), parts[1]))
        elif len(parts) == 1:
            directives.append(_Directive(parts[0].upper(), ""))

    return raw, directives


def _cmd_entrypoint_text(directives: list[_Directive]) -> str:
    """Concatenate all CMD and ENTRYPOINT values as a single string for searching."""
    parts: list[str] = []
    for d in directives:
        if d.name in ("CMD", "ENTRYPOINT"):
            parts.append(d.value)
    return " ".join(parts)


def _all_from_lines(directives: list[_Directive]) -> list[str]:
    return [d.value for d in directives if d.name == "FROM"]


def _all_user_directives(directives: list[_Directive]) -> list[str]:
    return [d.value.strip() for d in directives if d.name == "USER"]


def _all_expose_directives(directives: list[_Directive]) -> list[str]:
    return [d.value.strip() for d in directives if d.name == "EXPOSE"]


# ---------------------------------------------------------------------------
# AC1: Dockerfile exists at repo root
# ---------------------------------------------------------------------------


def test_dockerfile_exists() -> None:
    """AC1: Dockerfile must exist as a file at the repo root."""
    assert DOCKERFILE.is_file(), f"Dockerfile not found at {DOCKERFILE}"


# ---------------------------------------------------------------------------
# AC2: .dockerignore exists at repo root
# ---------------------------------------------------------------------------


def test_dockerignore_exists() -> None:
    """AC2: .dockerignore must exist as a file at the repo root."""
    assert DOCKERIGNORE.is_file(), f".dockerignore not found at {DOCKERIGNORE}"


# ---------------------------------------------------------------------------
# AC3: Multi-stage (>= 2 FROM instructions)
# ---------------------------------------------------------------------------


def test_multistage() -> None:
    """AC3 / E13: Dockerfile must have at least 2 FROM instructions (multi-stage)."""
    _, directives = _parse_dockerfile()
    from_lines = _all_from_lines(directives)
    assert len(from_lines) >= 2, (
        f"Expected >= 2 FROM instructions for a multi-stage build; found {len(from_lines)}: "
        f"{from_lines}"
    )


# ---------------------------------------------------------------------------
# AC4: At least one FROM tag contains '3.12'
# ---------------------------------------------------------------------------


def test_python_312_base() -> None:
    """AC4 / E14: At least one FROM image tag must contain '3.12'."""
    _, directives = _parse_dockerfile()
    from_lines = _all_from_lines(directives)
    assert any("3.12" in line for line in from_lines), (
        f"No FROM instruction references a '3.12' image; found: {from_lines}"
    )


# ---------------------------------------------------------------------------
# AC5: Uses uv sync with --frozen or --locked; no pip install for deps
# ---------------------------------------------------------------------------


def test_uses_uv_sync_frozen() -> None:
    """AC5 / E3: Dockerfile must call 'uv sync' with '--frozen' or '--locked'."""
    raw, _ = _parse_dockerfile()
    assert "uv sync" in raw, "Dockerfile does not contain 'uv sync'"
    assert "--frozen" in raw or "--locked" in raw, (
        "Dockerfile calls 'uv sync' but neither '--frozen' nor '--locked' is present; "
        "the sync must be pinned to the lockfile for reproducibility"
    )


def test_no_pip_install_for_deps() -> None:
    """AC5 / E3: Dockerfile must not use 'pip install' for workspace dependencies.

    Note: pip install is allowed for the uv bootstrap itself (e.g. pip install uv==...),
    but must not be the mechanism used to install the workspace/application dependencies.
    The spec requires 'uv sync --frozen' for the workspace sync; a raw 'pip install .' or
    'pip install -r requirements' would bypass the lockfile.
    """
    raw, _ = _parse_dockerfile()
    # Detect patterns like: pip install -r requirements*.txt  OR  pip install . OR pip install packages/
    # The uv bootstrap (pip install "uv==...") is permitted.
    forbidden_patterns = [
        r"pip\s+install\s+(?!.*uv==)(?!.*\"uv==)(?!.*'uv==).*requirements",
        r"pip\s+install\s+\.",
    ]
    for pattern in forbidden_patterns:
        assert not re.search(pattern, raw), (
            f"Dockerfile contains a forbidden pip install pattern '{pattern}'; "
            "workspace deps must be installed via 'uv sync --frozen'"
        )


# ---------------------------------------------------------------------------
# AC6: Runtime stage USER is non-root (E6, E7, E12)
# ---------------------------------------------------------------------------


def test_runtime_user_non_root() -> None:
    """AC6 / E6 / E7 / E12: At least one USER directive must exist; the LAST one must not be root or 0."""
    _, directives = _parse_dockerfile()
    users = _all_user_directives(directives)
    assert users, "Dockerfile has no USER directive; the runtime process must run as non-root"
    last_user = users[-1]
    assert last_user.lower() != "root", (
        f"The last USER directive is 'root'; must be a non-root user"
    )
    assert last_user != "0", (
        f"The last USER directive is '0' (numeric root); must be a non-root user"
    )


# ---------------------------------------------------------------------------
# AC7: CMD/ENTRYPOINT contains factory app reference
# ---------------------------------------------------------------------------


def test_cmd_runs_uvicorn_factory() -> None:
    """AC7: CMD/ENTRYPOINT must reference 'infra_twin.api.app:create_app' and '--factory'."""
    _, directives = _parse_dockerfile()
    cmd_text = _cmd_entrypoint_text(directives)
    assert "infra_twin.api.app:create_app" in cmd_text, (
        f"CMD/ENTRYPOINT does not contain 'infra_twin.api.app:create_app'; got: {cmd_text!r}"
    )
    assert "--factory" in cmd_text, (
        f"CMD/ENTRYPOINT does not contain '--factory'; got: {cmd_text!r}"
    )


# ---------------------------------------------------------------------------
# AC8: CMD/ENTRYPOINT has --host 0.0.0.0 --port 8000 and no --reload (E4, E5)
# ---------------------------------------------------------------------------


def test_cmd_no_reload() -> None:
    """AC8 / E4: CMD/ENTRYPOINT must NOT contain '--reload'."""
    _, directives = _parse_dockerfile()
    cmd_text = _cmd_entrypoint_text(directives)
    assert "--reload" not in cmd_text, (
        f"CMD/ENTRYPOINT must not contain '--reload' in production; got: {cmd_text!r}"
    )


def test_cmd_has_host_binding() -> None:
    """AC8 / E5: CMD/ENTRYPOINT must bind --host 0.0.0.0 so the container is reachable."""
    _, directives = _parse_dockerfile()
    cmd_text = _cmd_entrypoint_text(directives)
    assert "--host" in cmd_text, (
        f"CMD/ENTRYPOINT is missing '--host'; got: {cmd_text!r}"
    )
    assert "0.0.0.0" in cmd_text, (
        f"CMD/ENTRYPOINT does not bind to '0.0.0.0'; got: {cmd_text!r}"
    )


def test_cmd_has_port_8000() -> None:
    """AC8: CMD/ENTRYPOINT must include '--port' and '8000'."""
    _, directives = _parse_dockerfile()
    cmd_text = _cmd_entrypoint_text(directives)
    assert "--port" in cmd_text, (
        f"CMD/ENTRYPOINT is missing '--port'; got: {cmd_text!r}"
    )
    assert "8000" in cmd_text, (
        f"CMD/ENTRYPOINT does not specify port 8000; got: {cmd_text!r}"
    )


# ---------------------------------------------------------------------------
# AC9: EXPOSE 8000 (E15)
# ---------------------------------------------------------------------------


def test_exposes_port_8000() -> None:
    """AC9 / E15: An EXPOSE directive must list port 8000, matching CMD --port 8000."""
    _, directives = _parse_dockerfile()
    expose_values = _all_expose_directives(directives)
    assert expose_values, "Dockerfile has no EXPOSE directive"
    # EXPOSE value may be "8000", "8000/tcp", "8000 9000", etc.
    assert any("8000" in v for v in expose_values), (
        f"No EXPOSE directive includes port 8000; found: {expose_values}"
    )


# ---------------------------------------------------------------------------
# AC10: No baked DATABASE_URL / ADMIN_DATABASE_URL (E8)
# ---------------------------------------------------------------------------


def test_no_baked_database_url() -> None:
    """AC10 / E8: Dockerfile must not bake DATABASE_URL= or ADMIN_DATABASE_URL= values."""
    raw, _ = _parse_dockerfile()
    # Check for ENV or ARG assignment patterns with non-empty values
    assert "DATABASE_URL=" not in raw, (
        "Dockerfile contains 'DATABASE_URL=' — database connection strings must "
        "not be baked into any image layer; supply via runtime environment"
    )
    assert "ADMIN_DATABASE_URL=" not in raw, (
        "Dockerfile contains 'ADMIN_DATABASE_URL=' — database connection strings must "
        "not be baked into any image layer; supply via runtime environment"
    )


def test_no_baked_postgresql_dsn() -> None:
    """AC10 / E8: Dockerfile must contain no 'postgresql://' literal."""
    raw, _ = _parse_dockerfile()
    assert "postgresql://" not in raw, (
        "Dockerfile contains a 'postgresql://' literal — DSNs must never be baked "
        "into an image layer"
    )


# ---------------------------------------------------------------------------
# AC11: No baked credentials (E8)
# ---------------------------------------------------------------------------


def test_no_baked_credentials() -> None:
    """AC11 / E8: Dockerfile must not bake any API keys or AWS credentials."""
    raw, _ = _parse_dockerfile()
    forbidden = [
        "ANTHROPIC_API_KEY=",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ]
    for token in forbidden:
        assert token not in raw, (
            f"Dockerfile contains '{token}' — credentials must never be baked "
            "into an image layer; supply via runtime environment"
        )


# ---------------------------------------------------------------------------
# AC12: No COPY/ADD of .env files (E8)
# ---------------------------------------------------------------------------


def test_no_copy_env_file() -> None:
    """AC12 / E8: No COPY or ADD instruction must reference a .env source."""
    _, directives = _parse_dockerfile()
    copy_add_values = [
        d.value for d in directives if d.name in ("COPY", "ADD")
    ]
    for val in copy_add_values:
        # Tokenise the instruction value; the source tokens come before the
        # last token (destination).  We check ALL tokens for safety.
        tokens = val.split()
        for token in tokens:
            # Strip flags like --from=builder, --chown=...
            if token.startswith("--"):
                continue
            assert not re.search(r"(^|/|\./)\.env(\.|$|/)", token), (
                f"COPY/ADD instruction references a .env file source: '{token}' "
                f"(full value: '{val}'); .env files must not be baked into the image"
            )


# ---------------------------------------------------------------------------
# AC13: .dockerignore excludes .git
# ---------------------------------------------------------------------------


def test_dockerignore_excludes_git() -> None:
    """AC13: .dockerignore must have a line that excludes '.git'."""
    lines = [l.strip() for l in DOCKERIGNORE.read_text().splitlines()]
    non_comment = [l for l in lines if l and not l.startswith("#")]
    assert ".git" in non_comment, (
        f"'.git' not found as a standalone exclusion in .dockerignore; "
        f"found non-comment lines: {non_comment}"
    )


# ---------------------------------------------------------------------------
# AC14: .dockerignore excludes .env* (E9)
# ---------------------------------------------------------------------------


def test_dockerignore_excludes_env() -> None:
    """AC14 / E9: .dockerignore must exclude .env files via .env*, .env+.env.*, or **/.env*."""
    lines = {l.strip() for l in DOCKERIGNORE.read_text().splitlines()}
    non_comment = {l for l in lines if l and not l.startswith("#")}

    # Accept any of the allowed patterns:
    covers_env_star = ".env*" in non_comment
    covers_env_and_dotstar = (".env" in non_comment and ".env.*" in non_comment)
    covers_glob = any(re.match(r"\*\*/\.env\*?", p) for p in non_comment)

    assert covers_env_star or covers_env_and_dotstar or covers_glob, (
        ".dockerignore must exclude .env files; acceptable patterns: '.env*', "
        "'.env' + '.env.*', or '**/.env*'. "
        f"Found non-comment lines: {sorted(non_comment)}"
    )


# ---------------------------------------------------------------------------
# AC15: .dockerignore excludes apps/web/node_modules (E2)
# ---------------------------------------------------------------------------


def test_dockerignore_excludes_web_node_modules() -> None:
    """AC15 / E2: .dockerignore must exclude 'apps/web/node_modules' or '**/node_modules'."""
    raw = DOCKERIGNORE.read_text()
    lines = {l.strip() for l in raw.splitlines()}
    non_comment = {l for l in lines if l and not l.startswith("#")}

    exact_match = "apps/web/node_modules" in non_comment
    glob_match = any("node_modules" in l and "**" in l for l in non_comment)

    assert exact_match or glob_match, (
        "'.dockerignore' must exclude 'apps/web/node_modules' (exact) or a pattern "
        "like '**/node_modules'; "
        f"found non-comment lines: {sorted(non_comment)}"
    )


# ---------------------------------------------------------------------------
# AC16: This module is hermetic — no DB/network imports, no conftest fixtures
# ---------------------------------------------------------------------------


def test_module_is_hermetic() -> None:
    """AC16: Confirm this module's own source imports no DB/network packages.

    We inspect the source text rather than sys.modules because pytest loads
    conftest.py before this module and conftest legitimately imports psycopg;
    sys.modules therefore contains psycopg regardless of what this file imports.

    We use AST parsing to check actual import nodes, not substring matching, so
    the list of forbidden names inside this function body does not self-trigger.
    """
    source = Path(__file__).read_text()
    tree = ast.parse(source)

    forbidden_modules = {"psycopg", "boto3", "anthropic", "httpx"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top not in forbidden_modules, (
                    f"test_api_dockerfile.py must not import '{alias.name}'; "
                    "this module must be hermetic (no DB/network dependencies)"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0]
                assert top not in forbidden_modules, (
                    f"test_api_dockerfile.py must not import from '{node.module}'; "
                    "this module must be hermetic (no DB/network dependencies)"
                )

    conftest_fixtures = ["pool", "make_tenant", "make_tenant_with_key"]
    for fixture in conftest_fixtures:
        pattern = rf"def test_\w+\([^)]*\b{re.escape(fixture)}\b"
        assert not re.search(pattern, source), (
            f"test_api_dockerfile.py must not inject the conftest fixture '{fixture}'"
        )
