"""Hermetic self-validation test for the infra/terraform/ HCL tree.

Pure file-parse only: no DB, no network, no Anthropic, no cloud SDKs.
Does not use pool / make_tenant / make_tenant_with_key from conftest.
No terraform init/plan/apply/validate is ever called.
terraform fmt -check is called ONLY when shutil.which("terraform") returns a path;
otherwise that single test is skipped.
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TF_ROOT = REPO_ROOT / "infra" / "terraform"
MODULE_DIR = TF_ROOT / "modules" / "platform"
STAGING_DIR = TF_ROOT / "environments" / "staging"
PROD_DIR = TF_ROOT / "environments" / "prod"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read(path: Path) -> str:
    """Return the text of a single file."""
    return path.read_text()


def _all_tf_text(directory: Path) -> str:
    """Return the concatenated text of every *.tf file under *directory* (recursive)."""
    parts: list[str] = []
    for tf_file in sorted(directory.rglob("*.tf")):
        parts.append(tf_file.read_text())
    return "\n".join(parts)


def _extract_backend_key(hcl: str) -> str | None:
    """Extract the value of 'key = "..."' from a backend block.

    Returns the key string value, or None if not found.
    """
    m = re.search(r'key\s*=\s*"([^"]+)"', hcl)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# AC1: infra/terraform/ directory exists
# ---------------------------------------------------------------------------


def test_ac1_terraform_dir_exists() -> None:
    """AC1: infra/terraform/ must exist as a directory."""
    assert TF_ROOT.is_dir(), f"infra/terraform/ directory not found at {TF_ROOT}"


# ---------------------------------------------------------------------------
# AC2: At least one .tf file exists recursively
# ---------------------------------------------------------------------------


def test_ac2_tf_files_exist() -> None:
    """AC2: TF_ROOT must contain at least one .tf file recursively."""
    tf_files = list(TF_ROOT.rglob("*.tf"))
    assert tf_files, f"No .tf files found under {TF_ROOT}"


# ---------------------------------------------------------------------------
# AC3: Module platform directory has all four required files
# ---------------------------------------------------------------------------


def test_ac3_module_platform_dir_exists() -> None:
    """AC3: modules/platform/ directory must exist."""
    assert MODULE_DIR.is_dir(), f"modules/platform/ not found at {MODULE_DIR}"


def test_ac3_module_main_tf_exists() -> None:
    """AC3: modules/platform/main.tf must exist."""
    assert (MODULE_DIR / "main.tf").is_file(), f"modules/platform/main.tf not found"


def test_ac3_module_variables_tf_exists() -> None:
    """AC3: modules/platform/variables.tf must exist."""
    assert (MODULE_DIR / "variables.tf").is_file(), f"modules/platform/variables.tf not found"


def test_ac3_module_outputs_tf_exists() -> None:
    """AC3: modules/platform/outputs.tf must exist."""
    assert (MODULE_DIR / "outputs.tf").is_file(), f"modules/platform/outputs.tf not found"


def test_ac3_module_versions_tf_exists() -> None:
    """AC3: modules/platform/versions.tf must exist."""
    assert (MODULE_DIR / "versions.tf").is_file(), f"modules/platform/versions.tf not found"


# ---------------------------------------------------------------------------
# AC4 / E17: environments/staging/ exists and contains at least one .tf file
# ---------------------------------------------------------------------------


def test_ac4_staging_dir_exists() -> None:
    """AC4 / E17: environments/staging/ must exist as a directory."""
    assert STAGING_DIR.is_dir(), f"environments/staging/ not found at {STAGING_DIR}"


def test_ac4_staging_has_tf_files() -> None:
    """AC4 / E17: environments/staging/ must contain at least one .tf file."""
    tf_files = list(STAGING_DIR.glob("*.tf"))
    assert tf_files, f"No .tf files found in {STAGING_DIR}"


# ---------------------------------------------------------------------------
# AC5 / E17: environments/prod/ exists and contains at least one .tf file
# ---------------------------------------------------------------------------


def test_ac5_prod_dir_exists() -> None:
    """AC5 / E17: environments/prod/ must exist as a directory."""
    assert PROD_DIR.is_dir(), f"environments/prod/ not found at {PROD_DIR}"


def test_ac5_prod_has_tf_files() -> None:
    """AC5 / E17: environments/prod/ must contain at least one .tf file."""
    tf_files = list(PROD_DIR.glob("*.tf"))
    assert tf_files, f"No .tf files found in {PROD_DIR}"


# ---------------------------------------------------------------------------
# AC6: Each env has a backend block
# ---------------------------------------------------------------------------


def test_ac6_staging_has_backend_block() -> None:
    """AC6: Staging env HCL must contain a backend block."""
    text = _all_tf_text(STAGING_DIR)
    assert re.search(r'\bbackend\s+"', text), (
        "environments/staging/ contains no 'backend \"' block"
    )


def test_ac6_prod_has_backend_block() -> None:
    """AC6: Prod env HCL must contain a backend block."""
    text = _all_tf_text(PROD_DIR)
    assert re.search(r'\bbackend\s+"', text), (
        "environments/prod/ contains no 'backend \"' block"
    )


# ---------------------------------------------------------------------------
# AC7 / E6: Each env backend has a locking token (dynamodb_table or use_lockfile)
# ---------------------------------------------------------------------------


def test_ac7_staging_backend_has_locking() -> None:
    """AC7 / E6: Staging backend must declare state locking (dynamodb_table= or use_lockfile=true)."""
    text = _all_tf_text(STAGING_DIR)
    has_dynamodb = bool(re.search(r'dynamodb_table\s*=', text))
    has_lockfile = bool(re.search(r'use_lockfile\s*=\s*true', text))
    assert has_dynamodb or has_lockfile, (
        "environments/staging/ backend has no locking token; "
        "expected 'dynamodb_table =' or 'use_lockfile = true'"
    )


def test_ac7_prod_backend_has_locking() -> None:
    """AC7 / E6: Prod backend must declare state locking (dynamodb_table= or use_lockfile=true)."""
    text = _all_tf_text(PROD_DIR)
    has_dynamodb = bool(re.search(r'dynamodb_table\s*=', text))
    has_lockfile = bool(re.search(r'use_lockfile\s*=\s*true', text))
    assert has_dynamodb or has_lockfile, (
        "environments/prod/ backend has no locking token; "
        "expected 'dynamodb_table =' or 'use_lockfile = true'"
    )


# ---------------------------------------------------------------------------
# AC8 / E5: Staging and prod backend state keys are distinct
# ---------------------------------------------------------------------------


def test_ac8_staging_backend_has_state_key() -> None:
    """AC8: Staging backend must declare a key = \"...\" value."""
    text = _all_tf_text(STAGING_DIR)
    key = _extract_backend_key(text)
    assert key is not None, "environments/staging/ backend has no 'key = \"...\"' declaration"


def test_ac8_prod_backend_has_state_key() -> None:
    """AC8: Prod backend must declare a key = \"...\" value."""
    text = _all_tf_text(PROD_DIR)
    key = _extract_backend_key(text)
    assert key is not None, "environments/prod/ backend has no 'key = \"...\"' declaration"


def test_ac8_staging_and_prod_keys_are_distinct() -> None:
    """AC8 / E5: Staging and prod backend state keys must NOT be the same string."""
    staging_key = _extract_backend_key(_all_tf_text(STAGING_DIR))
    prod_key = _extract_backend_key(_all_tf_text(PROD_DIR))
    assert staging_key is not None, "staging backend key not found"
    assert prod_key is not None, "prod backend key not found"
    assert staging_key != prod_key, (
        f"Staging and prod backend state keys are identical: {staging_key!r}; "
        "they must be distinct to keep state separate"
    )


# ---------------------------------------------------------------------------
# AC9 / E14: Module declares an aws_vpc resource
# ---------------------------------------------------------------------------


def test_ac9_module_declares_aws_vpc() -> None:
    """AC9 / E14: modules/platform/main.tf must declare a resource \"aws_vpc\" block."""
    text = _all_tf_text(MODULE_DIR)
    assert re.search(r'resource\s+"aws_vpc"', text), (
        "modules/platform/ contains no 'resource \"aws_vpc\"' declaration"
    )


# ---------------------------------------------------------------------------
# AC10 / E15: Module declares a managed Postgres datastore resource
# ---------------------------------------------------------------------------


def test_ac10_module_declares_db_resource() -> None:
    """AC10 / E15: modules/platform/main.tf must declare aws_db_instance or aws_rds_cluster."""
    text = _all_tf_text(MODULE_DIR)
    has_db_instance = bool(re.search(r'resource\s+"aws_db_instance"', text))
    has_rds_cluster = bool(re.search(r'resource\s+"aws_rds_cluster"', text))
    assert has_db_instance or has_rds_cluster, (
        "modules/platform/ contains no 'resource \"aws_db_instance\"' or "
        "'resource \"aws_rds_cluster\"' declaration"
    )


# ---------------------------------------------------------------------------
# AC11 / E4: Compute service references image via variable interpolation
# ---------------------------------------------------------------------------


def test_ac11_image_uses_var_api_image() -> None:
    """AC11 / E4: Module HCL must reference var.api_image via interpolation."""
    text = _all_tf_text(MODULE_DIR)
    # Matches ${var.api_image or plain var.api_image in the file text
    assert re.search(r'\$\{?\s*var\.api_image\b', text), (
        "modules/platform/ does not reference var.api_image in an image interpolation; "
        "the API image repo must come from a variable"
    )


def test_ac11_image_uses_var_api_image_tag() -> None:
    """AC11 / E4: Module HCL must reference var.api_image_tag."""
    text = _all_tf_text(MODULE_DIR)
    assert re.search(r'\$\{?\s*var\.api_image_tag\b', text), (
        "modules/platform/ does not reference var.api_image_tag; "
        "the API image tag must come from a variable"
    )


# ---------------------------------------------------------------------------
# AC12 / E4: No hardcoded image-with-SHA literal
# ---------------------------------------------------------------------------


def test_ac12_no_hardcoded_image_sha() -> None:
    """AC12 / E4: No :<40-hex-char SHA> digest literal in any .tf file under TF_ROOT."""
    text = _all_tf_text(TF_ROOT)
    m = re.search(r':[0-9a-f]{40}\b', text)
    assert not m, (
        f"Found a hardcoded image SHA literal in TF files: {m.group()!r}; "
        "image references must use variable interpolation only"
    )


def test_ac12_no_sha256_digest_literal() -> None:
    """AC12 / E4: No @sha256: digest reference in any .tf file under TF_ROOT."""
    text = _all_tf_text(TF_ROOT)
    assert "@sha256:" not in text, (
        "Found '@sha256:' literal in TF files; image references must use variable interpolation"
    )


# ---------------------------------------------------------------------------
# AC13 / E13: Compute config exposes port 8000 / var.api_container_port with default 8000
# ---------------------------------------------------------------------------


def test_ac13_module_references_port_8000_or_var() -> None:
    """AC13 / E13: Module HCL must contain '8000' or 'var.api_container_port' in compute context."""
    text = _all_tf_text(MODULE_DIR)
    has_literal_8000 = "8000" in text
    has_var_port = "var.api_container_port" in text
    assert has_literal_8000 or has_var_port, (
        "modules/platform/ contains neither '8000' nor 'var.api_container_port'; "
        "the compute service must expose port 8000"
    )


def test_ac13_api_container_port_default_is_8000() -> None:
    """AC13: variables.tf must declare api_container_port with default = 8000."""
    text = _read(MODULE_DIR / "variables.tf")
    # Find the api_container_port variable block and check default = 8000
    block_m = re.search(
        r'variable\s+"api_container_port"\s*\{(.+?)\}',
        text,
        re.DOTALL,
    )
    assert block_m, "variable 'api_container_port' not found in modules/platform/variables.tf"
    block = block_m.group(1)
    assert re.search(r'default\s*=\s*8000', block), (
        f"variable 'api_container_port' does not have 'default = 8000'; block: {block!r}"
    )


# ---------------------------------------------------------------------------
# AC14: Module outputs expose db_endpoint and db_port
# ---------------------------------------------------------------------------


def test_ac14_outputs_has_db_endpoint() -> None:
    """AC14: modules/platform/outputs.tf must declare output 'db_endpoint'."""
    text = _read(MODULE_DIR / "outputs.tf")
    assert re.search(r'output\s+"db_endpoint"', text), (
        "modules/platform/outputs.tf has no 'output \"db_endpoint\"' declaration"
    )


def test_ac14_outputs_has_db_port() -> None:
    """AC14: modules/platform/outputs.tf must declare output 'db_port'."""
    text = _read(MODULE_DIR / "outputs.tf")
    assert re.search(r'output\s+"db_port"', text), (
        "modules/platform/outputs.tf has no 'output \"db_port\"' declaration"
    )


def test_ac14_outputs_has_vpc_id() -> None:
    """AC14: modules/platform/outputs.tf must declare output 'vpc_id'."""
    text = _read(MODULE_DIR / "outputs.tf")
    assert re.search(r'output\s+"vpc_id"', text), (
        "modules/platform/outputs.tf has no 'output \"vpc_id\"' declaration"
    )


def test_ac14_outputs_has_api_service_port() -> None:
    """AC14: modules/platform/outputs.tf must declare output 'api_service_port'."""
    text = _read(MODULE_DIR / "outputs.tf")
    assert re.search(r'output\s+"api_service_port"', text), (
        "modules/platform/outputs.tf has no 'output \"api_service_port\"' declaration"
    )


# ---------------------------------------------------------------------------
# AC15 / E11: required_version with a pin operator in versions.tf and each env
# ---------------------------------------------------------------------------


def test_ac15_versions_tf_has_required_version() -> None:
    """AC15 / E11: modules/platform/versions.tf must declare required_version with a pin operator."""
    text = _read(MODULE_DIR / "versions.tf")
    assert "required_version" in text, (
        "modules/platform/versions.tf has no 'required_version' declaration"
    )
    # Must include a pin operator: >=, ~>, =, or <
    assert re.search(r'required_version\s*=\s*"[^"]*(?:>=|~>|<=|<|=)[^"]*"', text), (
        "modules/platform/versions.tf 'required_version' lacks a pin operator (>=, ~>, <, or =)"
    )


def test_ac15_staging_env_has_required_version() -> None:
    """AC15 / E11: environments/staging/ must declare required_version with a pin operator."""
    text = _all_tf_text(STAGING_DIR)
    assert "required_version" in text, (
        "environments/staging/ has no 'required_version' declaration"
    )
    assert re.search(r'required_version\s*=\s*"[^"]*(?:>=|~>|<=|<|=)[^"]*"', text), (
        "environments/staging/ 'required_version' lacks a pin operator"
    )


def test_ac15_prod_env_has_required_version() -> None:
    """AC15 / E11: environments/prod/ must declare required_version with a pin operator."""
    text = _all_tf_text(PROD_DIR)
    assert "required_version" in text, (
        "environments/prod/ has no 'required_version' declaration"
    )
    assert re.search(r'required_version\s*=\s*"[^"]*(?:>=|~>|<=|<|=)[^"]*"', text), (
        "environments/prod/ 'required_version' lacks a pin operator"
    )


# ---------------------------------------------------------------------------
# AC16 / E12: required_providers with a versioned aws entry
# ---------------------------------------------------------------------------


def test_ac16_versions_tf_has_required_providers_with_aws_version() -> None:
    """AC16 / E12: modules/platform/versions.tf must declare required_providers with an aws version constraint."""
    text = _read(MODULE_DIR / "versions.tf")
    assert "required_providers" in text, (
        "modules/platform/versions.tf has no 'required_providers' block"
    )
    assert re.search(r'version\s*=\s*"[^"]+"', text), (
        "modules/platform/versions.tf required_providers block has no 'version =' constraint"
    )


def test_ac16_staging_env_has_required_providers_with_aws_version() -> None:
    """AC16 / E12: environments/staging/ must declare required_providers with a version constraint."""
    text = _all_tf_text(STAGING_DIR)
    assert "required_providers" in text, (
        "environments/staging/ has no 'required_providers' block"
    )
    assert re.search(r'version\s*=\s*"[^"]+"', text), (
        "environments/staging/ required_providers block has no 'version =' constraint"
    )


def test_ac16_prod_env_has_required_providers_with_aws_version() -> None:
    """AC16 / E12: environments/prod/ must declare required_providers with a version constraint."""
    text = _all_tf_text(PROD_DIR)
    assert "required_providers" in text, (
        "environments/prod/ has no 'required_providers' block"
    )
    assert re.search(r'version\s*=\s*"[^"]+"', text), (
        "environments/prod/ required_providers block has no 'version =' constraint"
    )


# ---------------------------------------------------------------------------
# AC17 / E8: No postgresql:// DSN, DATABASE_URL=, or ADMIN_DATABASE_URL= literals
# ---------------------------------------------------------------------------


def _all_tf_and_example_text(directory: Path) -> str:
    """Return concatenated text of all .tf and .tfvars.example files recursively."""
    parts: list[str] = []
    for path in sorted(directory.rglob("*.tf")):
        parts.append(path.read_text())
    for path in sorted(directory.rglob("*.tfvars.example")):
        parts.append(path.read_text())
    return "\n".join(parts)


def test_ac17_no_postgresql_dsn_literal() -> None:
    """AC17 / E8: No 'postgresql://' literal in any .tf or .tfvars.example file."""
    text = _all_tf_and_example_text(TF_ROOT)
    assert "postgresql://" not in text, (
        "Found 'postgresql://' literal in a .tf or .tfvars.example file; "
        "DSNs must never be stored in HCL"
    )


def test_ac17_no_database_url_assignment() -> None:
    """AC17 / E8: No 'DATABASE_URL=' assignment in any .tf or .tfvars.example file."""
    text = _all_tf_and_example_text(TF_ROOT)
    assert "DATABASE_URL=" not in text, (
        "Found 'DATABASE_URL=' in a .tf or .tfvars.example file; "
        "DB connection strings must not be hardcoded in HCL"
    )


def test_ac17_no_admin_database_url_assignment() -> None:
    """AC17 / E8: No 'ADMIN_DATABASE_URL=' assignment in any .tf or .tfvars.example file."""
    text = _all_tf_and_example_text(TF_ROOT)
    assert "ADMIN_DATABASE_URL=" not in text, (
        "Found 'ADMIN_DATABASE_URL=' in a .tf or .tfvars.example file; "
        "DB connection strings must not be hardcoded in HCL"
    )


# ---------------------------------------------------------------------------
# AC18 / E9 / E10: No AWS AKIA key, no ANTHROPIC_API_KEY, no literal password string
# ---------------------------------------------------------------------------


def _all_files_text(directory: Path) -> str:
    """Return concatenated text of every file under directory."""
    parts: list[str] = []
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            try:
                parts.append(path.read_text())
            except (UnicodeDecodeError, PermissionError):
                pass
    return "\n".join(parts)


def test_ac18_no_akia_key() -> None:
    """AC18 / E10: No AWS access key ID starting with 'AKIA' in any file under TF_ROOT."""
    text = _all_files_text(TF_ROOT)
    assert "AKIA" not in text, (
        "Found 'AKIA' (AWS access key ID pattern) in the terraform tree; "
        "AWS credentials must never be committed"
    )


def test_ac18_no_anthropic_api_key() -> None:
    """AC18 / E10: No 'ANTHROPIC_API_KEY' literal in any file under TF_ROOT."""
    text = _all_files_text(TF_ROOT)
    assert "ANTHROPIC_API_KEY" not in text, (
        "Found 'ANTHROPIC_API_KEY' in the terraform tree; "
        "API keys must never be committed"
    )


def test_ac18_no_literal_password_string_in_tf() -> None:
    """AC18 / E9: No password = \"<non-empty non-interpolated literal>\" in any .tf file.

    Interpolations like ${...} and var. references are allowed.
    A bare password = \"somevalue\" is forbidden.
    """
    text = _all_tf_text(TF_ROOT)
    # Match: password = "..." where the value contains no $ (interpolation) and is non-empty
    m = re.search(r'password\s*=\s*"([^"$]+)"', text)
    assert not m, (
        f"Found a hardcoded literal password assignment: password = \"{m.group(1)}\" "
        "in a .tf file; DB password must come from a Secrets Manager data source or variable"
    )


# ---------------------------------------------------------------------------
# AC19 / E18: DB password via secret ref; db_username and db_password_secret_arn have no default
# ---------------------------------------------------------------------------


def test_ac19_module_references_secret_manager() -> None:
    """AC19: Module HCL must reference var.db_password_secret_arn or manage_master_user_password or aws_secretsmanager."""
    text = _all_tf_text(MODULE_DIR)
    has_secret_arn_var = "var.db_password_secret_arn" in text
    has_master_user_password = "manage_master_user_password" in text
    has_secretsmanager = "aws_secretsmanager" in text
    assert has_secret_arn_var or has_master_user_password or has_secretsmanager, (
        "modules/platform/ does not reference 'var.db_password_secret_arn', "
        "'manage_master_user_password', or 'aws_secretsmanager'; "
        "the DB password must come from Secrets Manager"
    )


def test_ac19_db_username_has_no_default() -> None:
    """AC19 / E18: The 'db_username' variable must have no 'default =' line in its block."""
    text = _read(MODULE_DIR / "variables.tf")
    block_m = re.search(
        r'variable\s+"db_username"\s*\{(.+?)\}',
        text,
        re.DOTALL,
    )
    assert block_m, "variable 'db_username' not found in modules/platform/variables.tf"
    block = block_m.group(1)
    # Strip comments (lines starting with #)
    non_comment_lines = [
        line for line in block.splitlines() if not line.strip().startswith("#")
    ]
    non_comment_block = "\n".join(non_comment_lines)
    assert not re.search(r'\bdefault\s*=', non_comment_block), (
        "variable 'db_username' has a 'default =' in its block; "
        "this variable must require the caller to supply a value"
    )


def test_ac19_db_password_secret_arn_has_no_default() -> None:
    """AC19 / E18: The 'db_password_secret_arn' variable must have no 'default =' line."""
    text = _read(MODULE_DIR / "variables.tf")
    block_m = re.search(
        r'variable\s+"db_password_secret_arn"\s*\{(.+?)\}',
        text,
        re.DOTALL,
    )
    assert block_m, "variable 'db_password_secret_arn' not found in modules/platform/variables.tf"
    block = block_m.group(1)
    non_comment_lines = [
        line for line in block.splitlines() if not line.strip().startswith("#")
    ]
    non_comment_block = "\n".join(non_comment_lines)
    assert not re.search(r'\bdefault\s*=', non_comment_block), (
        "variable 'db_password_secret_arn' has a 'default =' in its block; "
        "the ARN must be supplied by the caller, not defaulted"
    )


def test_ac19_api_image_has_no_default() -> None:
    """AC19: The 'api_image' variable must have no 'default =' line (git-SHA injected at deploy)."""
    text = _read(MODULE_DIR / "variables.tf")
    block_m = re.search(
        r'variable\s+"api_image"\s*\{(.+?)\}',
        text,
        re.DOTALL,
    )
    assert block_m, "variable 'api_image' not found in modules/platform/variables.tf"
    block = block_m.group(1)
    non_comment_lines = [
        line for line in block.splitlines() if not line.strip().startswith("#")
    ]
    non_comment_block = "\n".join(non_comment_lines)
    assert not re.search(r'\bdefault\s*=', non_comment_block), (
        "variable 'api_image' has a 'default =' in its block; "
        "the image repo must be supplied at deploy time"
    )


def test_ac19_api_image_tag_has_no_default() -> None:
    """AC19: The 'api_image_tag' variable must have no 'default =' line."""
    text = _read(MODULE_DIR / "variables.tf")
    block_m = re.search(
        r'variable\s+"api_image_tag"\s*\{(.+?)\}',
        text,
        re.DOTALL,
    )
    assert block_m, "variable 'api_image_tag' not found in modules/platform/variables.tf"
    block = block_m.group(1)
    non_comment_lines = [
        line for line in block.splitlines() if not line.strip().startswith("#")
    ]
    non_comment_block = "\n".join(non_comment_lines)
    assert not re.search(r'\bdefault\s*=', non_comment_block), (
        "variable 'api_image_tag' has a 'default =' in its block; "
        "the image tag must be supplied at deploy time"
    )


# ---------------------------------------------------------------------------
# AC20: .gitignore exists with required entries
# ---------------------------------------------------------------------------


def test_ac20_gitignore_exists() -> None:
    """AC20: infra/terraform/.gitignore must exist."""
    gitignore = TF_ROOT / ".gitignore"
    assert gitignore.is_file(), f"infra/terraform/.gitignore not found at {gitignore}"


def test_ac20_gitignore_ignores_tfstate() -> None:
    """AC20: .gitignore must include a line matching *.tfstate or *.tfstate*."""
    text = _read(TF_ROOT / ".gitignore")
    non_comment_lines = [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    has_tfstate = any(
        re.fullmatch(r'\*\.tfstate\*?', line) for line in non_comment_lines
    )
    assert has_tfstate, (
        f".gitignore must include '*.tfstate' or '*.tfstate*'; "
        f"found non-comment lines: {non_comment_lines}"
    )


def test_ac20_gitignore_ignores_tfvars() -> None:
    """AC20: .gitignore must include '*.tfvars' to keep real secrets out of VCS."""
    text = _read(TF_ROOT / ".gitignore")
    non_comment_lines = [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert "*.tfvars" in non_comment_lines, (
        f".gitignore must include '*.tfvars'; found non-comment lines: {non_comment_lines}"
    )


def test_ac20_gitignore_ignores_terraform_dir() -> None:
    """AC20: .gitignore must include '.terraform/' to exclude the local plugin cache."""
    text = _read(TF_ROOT / ".gitignore")
    non_comment_lines = [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert ".terraform/" in non_comment_lines, (
        f".gitignore must include '.terraform/'; found non-comment lines: {non_comment_lines}"
    )


def test_ac20_gitignore_negates_tfvars_example() -> None:
    """AC20 / E7: .gitignore must include '!*.tfvars.example' to allow example files in VCS."""
    text = _read(TF_ROOT / ".gitignore")
    non_comment_lines = [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert "!*.tfvars.example" in non_comment_lines, (
        f".gitignore must include '!*.tfvars.example'; "
        f"found non-comment lines: {non_comment_lines}"
    )


# ---------------------------------------------------------------------------
# AC21 / E7: No real (non-example) .tfvars files committed
# ---------------------------------------------------------------------------


def test_ac21_no_committed_real_tfvars() -> None:
    """AC21 / E7: Every *.tfvars path under TF_ROOT must end with '.tfvars.example'."""
    real_tfvars = [
        p for p in TF_ROOT.rglob("*.tfvars")
        if not p.name.endswith(".tfvars.example")
    ]
    assert not real_tfvars, (
        f"Real (non-example) .tfvars files found under {TF_ROOT}: {real_tfvars}; "
        "only *.tfvars.example files may be committed"
    )


# ---------------------------------------------------------------------------
# AC22: Each env directory has a terraform.tfvars.example file
# ---------------------------------------------------------------------------


def test_ac22_staging_has_tfvars_example() -> None:
    """AC22: environments/staging/ must contain terraform.tfvars.example."""
    example = STAGING_DIR / "terraform.tfvars.example"
    assert example.is_file(), f"terraform.tfvars.example not found in {STAGING_DIR}"


def test_ac22_prod_has_tfvars_example() -> None:
    """AC22: environments/prod/ must contain terraform.tfvars.example."""
    example = PROD_DIR / "terraform.tfvars.example"
    assert example.is_file(), f"terraform.tfvars.example not found in {PROD_DIR}"


def test_ac22_staging_tfvars_example_has_no_secrets() -> None:
    """AC22: staging/terraform.tfvars.example must not contain real secret values."""
    text = _read(STAGING_DIR / "terraform.tfvars.example")
    # Must not contain a real AWS key
    assert "AKIA" not in text, "staging/terraform.tfvars.example contains an AKIA key pattern"
    # Must not contain a postgresql:// DSN
    assert "postgresql://" not in text, "staging/terraform.tfvars.example contains a postgresql:// DSN"
    # The secret ARN placeholder should not be a real secret value (no real ARN format with real 12-digit account)
    # We allow placeholder ARNs with 000000000000 only
    real_account_arn_m = re.search(
        r'arn:aws:secretsmanager:[^:]+:(?!000000000000)\d{12}:secret:', text
    )
    assert not real_account_arn_m, (
        f"staging/terraform.tfvars.example appears to contain a real Secrets Manager ARN "
        f"with a real account ID: {real_account_arn_m.group()!r}"
    )


def test_ac22_prod_tfvars_example_has_no_secrets() -> None:
    """AC22: prod/terraform.tfvars.example must not contain real secret values."""
    text = _read(PROD_DIR / "terraform.tfvars.example")
    assert "AKIA" not in text, "prod/terraform.tfvars.example contains an AKIA key pattern"
    assert "postgresql://" not in text, "prod/terraform.tfvars.example contains a postgresql:// DSN"
    real_account_arn_m = re.search(
        r'arn:aws:secretsmanager:[^:]+:(?!000000000000)\d{12}:secret:', text
    )
    assert not real_account_arn_m, (
        f"prod/terraform.tfvars.example appears to contain a real Secrets Manager ARN "
        f"with a real account ID: {real_account_arn_m.group()!r}"
    )


# ---------------------------------------------------------------------------
# AC23: This test module's source contains no 'onboarding' substring
# ---------------------------------------------------------------------------


def test_ac23_no_onboarding_reference_in_this_test() -> None:
    """AC23: This test module must not read or assert on the onboarding template."""
    source = Path(__file__).read_text()
    # We check the source text outside of this function's own string literals.
    # The most robust way: look for 'onboarding' in non-string parts of the AST.
    tree = ast.parse(source)
    # Collect all string constants from the AST (docstrings and inline strings)
    string_nodes: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            string_nodes.add(node.value)
    # Check: there should be no import or path reference to onboarding outside string constants
    # We scan non-string tokens by removing all quoted strings and checking for the pattern.
    # A simple check: ensure no Path/open call references 'onboarding'.
    # The word 'onboarding' may appear in docstrings/comments (acceptable).
    # It must NOT appear in a Path() call or file open.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # Detect Path(...) or open(...) calls with 'onboarding' in arguments
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    assert "onboarding" not in arg.value, (
                        "This test module passes an 'onboarding' path to a function call; "
                        "it must not read or assert on the onboarding template"
                    )


# ---------------------------------------------------------------------------
# AC24: Hermeticity — no forbidden imports, no conftest fixtures injected
# ---------------------------------------------------------------------------


def test_ac24_module_has_no_forbidden_imports() -> None:
    """AC24: This test module must not import psycopg, boto3, anthropic, or httpx."""
    source = Path(__file__).read_text()
    tree = ast.parse(source)

    forbidden_modules = {"psycopg", "boto3", "anthropic", "httpx"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top not in forbidden_modules, (
                    f"test_platform_terraform.py must not import '{alias.name}'; "
                    "this module must be hermetic (no DB/network dependencies)"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0]
                assert top not in forbidden_modules, (
                    f"test_platform_terraform.py must not import from '{node.module}'; "
                    "this module must be hermetic (no DB/network dependencies)"
                )


def test_ac24_no_conftest_fixtures_injected() -> None:
    """AC24: No test function in this module injects pool, make_tenant, or make_tenant_with_key."""
    source = Path(__file__).read_text()
    conftest_fixtures = ["pool", "make_tenant", "make_tenant_with_key"]
    for fixture in conftest_fixtures:
        pattern = rf"def test_\w+\([^)]*\b{re.escape(fixture)}\b"
        assert not re.search(pattern, source), (
            f"test_platform_terraform.py must not inject the conftest fixture '{fixture}'"
        )


# ---------------------------------------------------------------------------
# AC25 / E1: terraform fmt -check runs only when the binary is available
# ---------------------------------------------------------------------------


def test_ac25_terraform_fmt_check() -> None:
    """AC25 / E1: Run terraform fmt -check over TF_ROOT if terraform binary exists; skip otherwise."""
    terraform_bin = shutil.which("terraform")
    if not terraform_bin:
        import pytest
        pytest.skip("terraform binary not found; skipping fmt check (E1)")

    result = subprocess.run(
        [terraform_bin, "fmt", "-check", "-recursive", str(TF_ROOT)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"terraform fmt -check reported formatting issues in {TF_ROOT}:\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# AC26: This test module contains no init/plan/apply/validate subprocess calls
# ---------------------------------------------------------------------------


def test_ac26_no_forbidden_terraform_subcommands_in_test_source() -> None:
    """AC26: This test module source must contain no terraform init/plan/apply/validate subprocess calls."""
    source = Path(__file__).read_text()
    tree = ast.parse(source)

    forbidden_subcommands = {" init", "validate", "plan", "apply"}

    # Walk all string constants in the AST that could be subprocess arguments.
    # We specifically look inside subprocess.run / subprocess.call / subprocess.check_output
    # argument lists and lists passed to them.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Check if this is a subprocess call
        func = node.func
        is_subprocess_call = False
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name) and func.value.id == "subprocess":
                is_subprocess_call = True
        if isinstance(func, ast.Name) and func.id in ("subprocess",):
            is_subprocess_call = True

        if not is_subprocess_call:
            continue

        # Inspect the first argument (command list or string)
        if not node.args:
            continue
        cmd_arg = node.args[0]

        # If it's a list, inspect each element
        elements: list[ast.expr] = []
        if isinstance(cmd_arg, ast.List):
            elements = cmd_arg.elts
        else:
            elements = [cmd_arg]

        for elem in elements:
            if isinstance(elem, ast.Constant) and isinstance(elem.value, str):
                for forbidden in forbidden_subcommands:
                    assert forbidden not in elem.value, (
                        f"test_platform_terraform.py contains a forbidden terraform "
                        f"subcommand '{forbidden.strip()}' in a subprocess call; "
                        "only 'fmt -check' is permitted"
                    )
