"""Tests for the Customer AWS onboarding read-only IAM role artifact.

Covers all acceptance criteria from the spec:

  Template structural checks (AC 1-6):
  - infra-twin-readonly-role.yaml exists and parses via yaml.safe_load
  - AWSTemplateFormatVersion == "2010-09-09"
  - Parameters keys: TrusterAccountId, TrusterRoleArn, ExternalId, RoleName, Path
  - Exactly one AWS::IAM::Role resource
  - Trust statement: sts:AssumeRole, Principal.AWS ref, StringEquals sts:ExternalId
  - Outputs block exporting role ARN

  Package / pyproject structural checks (AC 7-10):
  - packages/onboarding/ has pyproject.toml with name, pyyaml dep, no infra-twin-* dep
  - [tool.hatch.build.targets.wheel] packages == ["src/infra_twin"]
  - Root pyproject.toml has infra-twin-onboarding in deps and sources
  - apps/api/pyproject.toml has infra-twin-onboarding in deps and sources

  READONLY_ACTIONS purity (AC 11-15):
  - from infra_twin.onboarding import READONLY_ACTIONS, render_aws_cloudformation succeeds
  - isinstance(READONLY_ACTIONS, (tuple, frozenset))
  - set(READONLY_ACTIONS) equals exact set from spec §4.1
  - No wildcard in any action; verb starts with Describe/Get/List only
  - No mutating verb in any action

  render_aws_cloudformation behavior (AC 16-22):
  - Returns str that yaml.safe_load parses to dict
  - Trust stmt: sts:ExternalId, Principal.AWS == ":root" form
  - truster_role_arn wins: Principal.AWS == role ARN
  - Permission Action set equals set(READONLY_ACTIONS)
  - No mutating/wildcard action in rendered document
  - Committed template action set equals set(READONLY_ACTIONS)
  - ValueError on empty external_id and on no truster args

  Edge cases (spec §5):
  - EC 1: empty/whitespace external_id -> ValueError
  - EC 2: both truster args None/empty -> ValueError
  - EC 3: both truster args supplied -> role_arn wins
  - EC 4: truster_account_id with whitespace is stripped
  - EC 5: rendered document round-trips via yaml.safe_load
  - EC 6: committed YAML template parses via yaml.safe_load without error
  - EC 7: committed template trust policy has truster principal ref + sts:ExternalId
  - EC 8: rendered trust policy has baked truster principal + sts:ExternalId == external_id
  - EC 9: rendered permission Action list as a set equals set(READONLY_ACTIONS)
  - EC 10: no mutating/wildcard actions (parsed, not raw text; Resource:"*" is allowed)
  - EC 17: INFRA_TWIN_AWS_TRUSTER_ROLE_ARN set -> principal is role ARN
  - EC 18: only account id set -> principal is arn:...:root
  - EC 22: READONLY_ACTIONS is immutable (tuple or frozenset)
  - EC 23: render determinism — identical args produce identical output
  - EC 24: role_name/path defaults and custom values honored

  Endpoint (AC 23-29):
  - EC 11: GET /onboarding/aws-cloudformation, no auth -> 401
  - EC 12: invalid key -> 401
  - EC 13: viewer key + truster env -> 200
  - EC 14: editor key + truster env -> 200
  - EC 15: response Content-Type starts with text/yaml; body is raw document
  - EC 15: sts:ExternalId == calling tenant_id; two tenants get different ExternalIds
  - EC 16: neither truster env var -> 503 "AWS onboarding is not configured"

  .env.example and misc (AC 30):
  - .env.example has commented INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID and ROLE_ARN
"""

from __future__ import annotations

import pathlib
from uuid import UUID

import psycopg
import pytest
import yaml
from fastapi.testclient import TestClient

from infra_twin.api import create_app
from infra_twin.db.api_keys import IssuedKey, Role, provision_tenant
from infra_twin.db.config import admin_dsn

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_TEMPLATE_PATH = _REPO_ROOT / "infra" / "onboarding" / "aws" / "infra-twin-readonly-role.yaml"
_ONBOARDING_PYPROJECT = _REPO_ROOT / "packages" / "onboarding" / "pyproject.toml"
_ROOT_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_API_PYPROJECT = _REPO_ROOT / "apps" / "api" / "pyproject.toml"
_ENV_EXAMPLE = _REPO_ROOT / ".env.example"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth(api_key: str) -> dict:
    return {"Authorization": f"Bearer {api_key}"}


def _make_viewer_key(name: str) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.viewer)
    return issued.tenant_id, issued.plaintext


def _make_editor_key(name: str) -> tuple[UUID, str]:
    with psycopg.connect(admin_dsn()) as conn:
        issued: IssuedKey = provision_tenant(conn, name, role=Role.editor)
    return issued.tenant_id, issued.plaintext


def _get_permission_statement(rendered_doc: dict) -> dict:
    """Extract the permission statement from the rendered CloudFormation doc."""
    role_props = rendered_doc["Resources"]["InfraTwinReadOnlyRole"]["Properties"]
    policies = role_props["Policies"]
    stmt = policies[0]["PolicyDocument"]["Statement"][0]
    return stmt


def _get_trust_statement(rendered_doc: dict) -> dict:
    """Extract the trust policy statement from the rendered CloudFormation doc."""
    role_props = rendered_doc["Resources"]["InfraTwinReadOnlyRole"]["Properties"]
    return role_props["AssumeRolePolicyDocument"]["Statement"][0]


def _get_template_trust_statement(template_doc: dict) -> dict:
    """Extract the trust policy statement from the committed template."""
    role_resource = None
    for _name, res in template_doc["Resources"].items():
        if res.get("Type") == "AWS::IAM::Role":
            role_resource = res
            break
    assert role_resource is not None
    return role_resource["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]


def _get_template_permission_actions(template_doc: dict) -> list[str]:
    """Extract the permission actions list from the committed template."""
    role_resource = None
    for _name, res in template_doc["Resources"].items():
        if res.get("Type") == "AWS::IAM::Role":
            role_resource = res
            break
    assert role_resource is not None
    policies = role_resource["Properties"]["Policies"]
    return policies[0]["PolicyDocument"]["Statement"][0]["Action"]


# ===========================================================================
# Template structural checks (AC 1-6)
# ===========================================================================


def test_ac1_template_file_exists():
    """AC 1: infra/onboarding/aws/infra-twin-readonly-role.yaml exists."""
    assert _TEMPLATE_PATH.exists(), f"Template file not found: {_TEMPLATE_PATH}"


def test_ac1_template_parses_via_yaml_safe_load():
    """AC 1: yaml.safe_load of template contents returns a dict."""
    text = _TEMPLATE_PATH.read_text()
    doc = yaml.safe_load(text)
    assert isinstance(doc, dict), f"Expected dict from yaml.safe_load; got {type(doc)}"


def test_ac2_template_format_version():
    """AC 2: AWSTemplateFormatVersion == '2010-09-09'."""
    doc = yaml.safe_load(_TEMPLATE_PATH.read_text())
    assert doc.get("AWSTemplateFormatVersion") == "2010-09-09", (
        f"Expected AWSTemplateFormatVersion '2010-09-09'; got {doc.get('AWSTemplateFormatVersion')!r}"
    )


def test_ac3_template_has_truster_account_id_parameter():
    """AC 3: Parameters contains TrusterAccountId."""
    doc = yaml.safe_load(_TEMPLATE_PATH.read_text())
    params = doc.get("Parameters", {})
    assert "TrusterAccountId" in params, "Parameters must contain TrusterAccountId"


def test_ac3_template_has_truster_role_arn_parameter():
    """AC 3: Parameters contains TrusterRoleArn."""
    doc = yaml.safe_load(_TEMPLATE_PATH.read_text())
    params = doc.get("Parameters", {})
    assert "TrusterRoleArn" in params, "Parameters must contain TrusterRoleArn"


def test_ac3_template_has_external_id_parameter():
    """AC 3: Parameters contains ExternalId."""
    doc = yaml.safe_load(_TEMPLATE_PATH.read_text())
    params = doc.get("Parameters", {})
    assert "ExternalId" in params, "Parameters must contain ExternalId"


def test_ac3_template_has_role_name_parameter():
    """AC 3: Parameters contains RoleName."""
    doc = yaml.safe_load(_TEMPLATE_PATH.read_text())
    params = doc.get("Parameters", {})
    assert "RoleName" in params, "Parameters must contain RoleName"


def test_ac3_template_has_path_parameter():
    """AC 3: Parameters contains Path."""
    doc = yaml.safe_load(_TEMPLATE_PATH.read_text())
    params = doc.get("Parameters", {})
    assert "Path" in params, "Parameters must contain Path"


def test_ac4_template_has_exactly_one_iam_role_resource():
    """AC 4: Exactly one AWS::IAM::Role resource in the template."""
    doc = yaml.safe_load(_TEMPLATE_PATH.read_text())
    resources = doc.get("Resources", {})
    iam_roles = [
        name for name, res in resources.items()
        if res.get("Type") == "AWS::IAM::Role"
    ]
    assert len(iam_roles) == 1, (
        f"Expected exactly one AWS::IAM::Role; found {len(iam_roles)}: {iam_roles}"
    )


def test_ac5_template_trust_statement_has_sts_assume_role():
    """AC 5: Trust statement Action contains sts:AssumeRole."""
    doc = yaml.safe_load(_TEMPLATE_PATH.read_text())
    stmt = _get_template_trust_statement(doc)
    action = stmt.get("Action", "")
    # Action can be a string or list
    if isinstance(action, list):
        assert "sts:AssumeRole" in action, f"sts:AssumeRole not in action list: {action}"
    else:
        assert action == "sts:AssumeRole", f"Expected sts:AssumeRole; got {action!r}"


def test_ac5_template_trust_statement_has_principal_aws():
    """AC 5: Trust statement has Principal.AWS referencing a truster parameter."""
    doc = yaml.safe_load(_TEMPLATE_PATH.read_text())
    stmt = _get_template_trust_statement(doc)
    principal = stmt.get("Principal", {})
    assert "AWS" in principal, f"Expected Principal.AWS in trust statement; got {principal}"
    # The value is a CloudFormation expression (dict with Fn::If, Ref, etc.) — not None/empty
    principal_aws = principal["AWS"]
    assert principal_aws is not None, "Principal.AWS must not be None"


def test_ac5_template_trust_statement_has_string_equals_sts_external_id():
    """AC 5: Trust statement Condition.StringEquals has sts:ExternalId entry (non-empty)."""
    doc = yaml.safe_load(_TEMPLATE_PATH.read_text())
    stmt = _get_template_trust_statement(doc)
    condition = stmt.get("Condition", {})
    assert "StringEquals" in condition, f"Condition.StringEquals missing; got {condition}"
    string_equals = condition["StringEquals"]
    assert "sts:ExternalId" in string_equals, (
        f"sts:ExternalId missing from StringEquals; got {string_equals}"
    )
    external_id_val = string_equals["sts:ExternalId"]
    assert external_id_val is not None, "sts:ExternalId value must not be None"
    # The value should be a Ref to ExternalId parameter (not an empty string)
    if isinstance(external_id_val, str):
        assert external_id_val.strip() != "", "sts:ExternalId value must not be empty string"


def test_ac6_template_has_outputs_with_role_arn():
    """AC 6: Template has Outputs block that exports the role ARN."""
    doc = yaml.safe_load(_TEMPLATE_PATH.read_text())
    outputs = doc.get("Outputs", {})
    assert outputs, "Template must have an Outputs block"
    # Find an output that references GetAtt or .Arn for the role
    found_arn_output = False
    for _output_name, output_val in outputs.items():
        val = output_val.get("Value", {})
        # Long-form: {"Fn::GetAtt": [..., "Arn"]} or {"Fn::Sub": "...${...}.Arn..."}
        if isinstance(val, dict):
            if "Fn::GetAtt" in val:
                get_att = val["Fn::GetAtt"]
                if isinstance(get_att, list) and len(get_att) == 2 and get_att[1] == "Arn":
                    found_arn_output = True
            elif "Fn::Sub" in val:
                sub_val = val["Fn::Sub"]
                if isinstance(sub_val, str) and "Arn" in sub_val:
                    found_arn_output = True
        elif isinstance(val, str) and "Arn" in val:
            found_arn_output = True
    assert found_arn_output, (
        f"No Outputs entry found that references the role ARN via Fn::GetAtt/Fn::Sub; "
        f"got Outputs: {outputs}"
    )


# ===========================================================================
# Package / pyproject structural checks (AC 7-10)
# ===========================================================================


def test_ac7_onboarding_pyproject_exists():
    """AC 7: packages/onboarding/pyproject.toml exists."""
    assert _ONBOARDING_PYPROJECT.exists(), (
        f"packages/onboarding/pyproject.toml not found: {_ONBOARDING_PYPROJECT}"
    )


def test_ac7_onboarding_pyproject_name_is_infra_twin_onboarding():
    """AC 7: packages/onboarding/pyproject.toml declares name = 'infra-twin-onboarding'."""
    text = _ONBOARDING_PYPROJECT.read_text()
    assert 'name = "infra-twin-onboarding"' in text or "name = 'infra-twin-onboarding'" in text, (
        f"Expected name = 'infra-twin-onboarding' in pyproject.toml; not found"
    )


def test_ac7_onboarding_pyproject_has_pyyaml_dependency():
    """AC 7: packages/onboarding/pyproject.toml has pyyaml in dependencies."""
    text = _ONBOARDING_PYPROJECT.read_text()
    assert "pyyaml" in text.lower(), (
        "Expected 'pyyaml' in packages/onboarding/pyproject.toml dependencies"
    )


def test_ac7_onboarding_pyproject_has_no_infra_twin_star_dependency():
    """AC 7: packages/onboarding/pyproject.toml has no infra-twin-* dependency (leaf package)."""
    text = _ONBOARDING_PYPROJECT.read_text()
    # Check the dependencies section does not reference other infra-twin-* packages
    import tomllib
    with open(_ONBOARDING_PYPROJECT, "rb") as f:
        data = tomllib.load(f)
    deps = data.get("project", {}).get("dependencies", [])
    for dep in deps:
        assert not dep.startswith("infra-twin-"), (
            f"packages/onboarding must not depend on other infra-twin-* packages; found: {dep!r}"
        )


def test_ac8_onboarding_pyproject_wheel_packages():
    """AC 8: [tool.hatch.build.targets.wheel] packages == ['src/infra_twin']."""
    import tomllib
    with open(_ONBOARDING_PYPROJECT, "rb") as f:
        data = tomllib.load(f)
    wheel_packages = (
        data.get("tool", {})
        .get("hatch", {})
        .get("build", {})
        .get("targets", {})
        .get("wheel", {})
        .get("packages", [])
    )
    assert wheel_packages == ["src/infra_twin"], (
        f"Expected packages = ['src/infra_twin']; got {wheel_packages!r}"
    )


def test_ac9_root_pyproject_has_infra_twin_onboarding_in_dependencies():
    """AC 9: Root pyproject.toml lists infra-twin-onboarding in [project].dependencies."""
    import tomllib
    with open(_ROOT_PYPROJECT, "rb") as f:
        data = tomllib.load(f)
    deps = data.get("project", {}).get("dependencies", [])
    assert "infra-twin-onboarding" in deps, (
        f"infra-twin-onboarding not found in root pyproject.toml dependencies; got {deps}"
    )


def test_ac9_root_pyproject_has_infra_twin_onboarding_in_sources():
    """AC 9: Root pyproject.toml lists infra-twin-onboarding in [tool.uv.sources] with workspace=true."""
    import tomllib
    with open(_ROOT_PYPROJECT, "rb") as f:
        data = tomllib.load(f)
    sources = data.get("tool", {}).get("uv", {}).get("sources", {})
    assert "infra-twin-onboarding" in sources, (
        f"infra-twin-onboarding not found in root pyproject.toml [tool.uv.sources]; got {list(sources.keys())}"
    )
    entry = sources["infra-twin-onboarding"]
    assert entry.get("workspace") is True, (
        f"infra-twin-onboarding source must have workspace=true; got {entry}"
    )


def test_ac10_api_pyproject_has_infra_twin_onboarding_in_dependencies():
    """AC 10: apps/api/pyproject.toml lists infra-twin-onboarding in dependencies."""
    import tomllib
    with open(_API_PYPROJECT, "rb") as f:
        data = tomllib.load(f)
    deps = data.get("project", {}).get("dependencies", [])
    assert "infra-twin-onboarding" in deps, (
        f"infra-twin-onboarding not found in apps/api/pyproject.toml dependencies; got {deps}"
    )


def test_ac10_api_pyproject_has_infra_twin_onboarding_in_sources():
    """AC 10: apps/api/pyproject.toml lists infra-twin-onboarding in [tool.uv.sources]."""
    import tomllib
    with open(_API_PYPROJECT, "rb") as f:
        data = tomllib.load(f)
    sources = data.get("tool", {}).get("uv", {}).get("sources", {})
    assert "infra-twin-onboarding" in sources, (
        f"infra-twin-onboarding not found in apps/api/pyproject.toml [tool.uv.sources]; "
        f"got {list(sources.keys())}"
    )


# ===========================================================================
# Import and READONLY_ACTIONS checks (AC 11-15)
# ===========================================================================


def test_ac11_import_readonly_actions():
    """AC 11: from infra_twin.onboarding import READONLY_ACTIONS succeeds."""
    from infra_twin.onboarding import READONLY_ACTIONS  # noqa: F401


def test_ac11_import_render_aws_cloudformation():
    """AC 11: from infra_twin.onboarding import render_aws_cloudformation succeeds."""
    from infra_twin.onboarding import render_aws_cloudformation  # noqa: F401


def test_ac12_readonly_actions_is_tuple_or_frozenset():
    """AC 12: isinstance(READONLY_ACTIONS, (tuple, frozenset)) is True."""
    from infra_twin.onboarding import READONLY_ACTIONS
    assert isinstance(READONLY_ACTIONS, (tuple, frozenset)), (
        f"READONLY_ACTIONS must be a tuple or frozenset; got {type(READONLY_ACTIONS)}"
    )


def test_ac12_readonly_actions_immutable_cannot_append():
    """EC 22: READONLY_ACTIONS is immutable — attempting .append raises AttributeError."""
    from infra_twin.onboarding import READONLY_ACTIONS
    with pytest.raises(AttributeError):
        READONLY_ACTIONS.append("iam:DeleteUser")  # type: ignore[attr-defined]


def test_ac13_readonly_actions_exact_set():
    """AC 13: set(READONLY_ACTIONS) equals the exact set from spec §4.1."""
    from infra_twin.onboarding import READONLY_ACTIONS

    expected = {
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "rds:DescribeDBInstances",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "iam:ListRoles",
        "iam:ListUsers",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "eks:ListClusters",
        "eks:DescribeCluster",
        "sts:GetCallerIdentity",
    }
    actual = set(READONLY_ACTIONS)
    assert actual == expected, (
        f"READONLY_ACTIONS does not match expected set.\n"
        f"  Missing: {expected - actual}\n"
        f"  Extra:   {actual - expected}"
    )


def test_ac14_readonly_actions_no_wildcards():
    """AC 14: No action in READONLY_ACTIONS contains '*'."""
    from infra_twin.onboarding import READONLY_ACTIONS
    for action in READONLY_ACTIONS:
        assert "*" not in action, (
            f"Action {action!r} contains wildcard '*'; wildcards are forbidden"
        )


def test_ac14_readonly_actions_verb_starts_with_allowed_prefix():
    """AC 14: Every action's verb (after ':') starts with Describe, Get, or List."""
    from infra_twin.onboarding import READONLY_ACTIONS
    allowed_prefixes = ("Describe", "Get", "List")
    for action in READONLY_ACTIONS:
        assert ":" in action, f"Action {action!r} missing ':' separator"
        verb = action.split(":", 1)[1]
        assert verb.startswith(allowed_prefixes), (
            f"Action {action!r} has verb {verb!r} which does not start with "
            f"one of {allowed_prefixes}"
        )


def test_ac15_readonly_actions_no_mutating_verbs():
    """AC 15: No action in READONLY_ACTIONS starts with a mutating verb."""
    from infra_twin.onboarding import READONLY_ACTIONS
    forbidden_prefixes = (
        "Create", "Put", "Delete", "Update", "Modify", "Write",
        "Attach", "Detach", "Add", "Remove", "Set", "Run", "Start",
        "Stop", "Terminate", "Reboot", "Associate", "Disassociate",
        "Authorize", "Revoke", "Tag", "Untag",
    )
    for action in READONLY_ACTIONS:
        verb = action.split(":", 1)[1]
        for prefix in forbidden_prefixes:
            assert not verb.startswith(prefix), (
                f"Action {action!r} has mutating verb {verb!r} starting with {prefix!r}"
            )


# ===========================================================================
# render_aws_cloudformation behavior (AC 16-22)
# ===========================================================================


def test_ac16_render_returns_str():
    """AC 16: render_aws_cloudformation returns a str."""
    from infra_twin.onboarding import render_aws_cloudformation
    result = render_aws_cloudformation(
        external_id="t", truster_account_id="123456789012"
    )
    assert isinstance(result, str), f"Expected str; got {type(result)}"


def test_ac16_render_parses_via_yaml_safe_load():
    """AC 16: render_aws_cloudformation output parses via yaml.safe_load into a dict."""
    from infra_twin.onboarding import render_aws_cloudformation
    result = render_aws_cloudformation(
        external_id="t", truster_account_id="123456789012"
    )
    doc = yaml.safe_load(result)
    assert isinstance(doc, dict), f"Expected dict from yaml.safe_load; got {type(doc)}"


def test_ac17_render_trust_statement_external_id():
    """AC 17: Rendered trust statement Condition.StringEquals['sts:ExternalId'] == 't'."""
    from infra_twin.onboarding import render_aws_cloudformation
    result = render_aws_cloudformation(
        external_id="t", truster_account_id="123456789012"
    )
    doc = yaml.safe_load(result)
    stmt = _get_trust_statement(doc)
    condition = stmt["Condition"]["StringEquals"]
    assert condition.get("sts:ExternalId") == "t", (
        f"sts:ExternalId must equal 't'; got {condition.get('sts:ExternalId')!r}"
    )


def test_ac17_render_trust_principal_account_id_root_form():
    """AC 17: Rendered trust statement Principal.AWS == 'arn:aws:iam::123456789012:root' when truster_account_id given."""
    from infra_twin.onboarding import render_aws_cloudformation
    result = render_aws_cloudformation(
        external_id="t", truster_account_id="123456789012"
    )
    doc = yaml.safe_load(result)
    stmt = _get_trust_statement(doc)
    principal_aws = stmt["Principal"]["AWS"]
    assert principal_aws == "arn:aws:iam::123456789012:root", (
        f"Principal.AWS must be ':root' form; got {principal_aws!r}"
    )


def test_ac18_render_trust_principal_uses_role_arn():
    """AC 18: When truster_role_arn supplied, Principal.AWS == role ARN."""
    from infra_twin.onboarding import render_aws_cloudformation
    role_arn = "arn:aws:iam::123456789012:role/itw"
    result = render_aws_cloudformation(
        external_id="t", truster_role_arn=role_arn
    )
    doc = yaml.safe_load(result)
    stmt = _get_trust_statement(doc)
    principal_aws = stmt["Principal"]["AWS"]
    assert principal_aws == role_arn, (
        f"Principal.AWS must equal truster_role_arn {role_arn!r}; got {principal_aws!r}"
    )


def test_ec3_both_truster_args_role_arn_wins():
    """EC 3: When both truster_account_id and truster_role_arn are supplied, role_arn wins."""
    from infra_twin.onboarding import render_aws_cloudformation
    role_arn = "arn:aws:iam::111111111111:role/preferred"
    result = render_aws_cloudformation(
        external_id="x",
        truster_account_id="999999999999",
        truster_role_arn=role_arn,
    )
    doc = yaml.safe_load(result)
    stmt = _get_trust_statement(doc)
    principal_aws = stmt["Principal"]["AWS"]
    assert principal_aws == role_arn, (
        f"truster_role_arn must win when both supplied; got {principal_aws!r}"
    )


def test_ac19_render_permission_action_set_equals_readonly_actions():
    """AC 19: Rendered permission statement Action list as a set equals set(READONLY_ACTIONS)."""
    from infra_twin.onboarding import READONLY_ACTIONS, render_aws_cloudformation
    result = render_aws_cloudformation(
        external_id="t", truster_account_id="123456789012"
    )
    doc = yaml.safe_load(result)
    stmt = _get_permission_statement(doc)
    rendered_actions = set(stmt["Action"])
    assert rendered_actions == set(READONLY_ACTIONS), (
        f"Rendered Action set does not match READONLY_ACTIONS.\n"
        f"  Missing: {set(READONLY_ACTIONS) - rendered_actions}\n"
        f"  Extra:   {rendered_actions - set(READONLY_ACTIONS)}"
    )


def test_ac20_rendered_actions_no_wildcards():
    """AC 20: Rendered permission actions contain no wildcard ('*')."""
    from infra_twin.onboarding import render_aws_cloudformation
    result = render_aws_cloudformation(
        external_id="t", truster_account_id="123456789012"
    )
    doc = yaml.safe_load(result)
    stmt = _get_permission_statement(doc)
    for action in stmt["Action"]:
        assert "*" not in action, (
            f"Rendered action {action!r} contains wildcard '*'; forbidden"
        )


def test_ac20_rendered_resource_star_is_allowed():
    """AC 20: Resource: '*' in the rendered document does NOT trigger wildcard action check."""
    from infra_twin.onboarding import render_aws_cloudformation
    result = render_aws_cloudformation(
        external_id="t", truster_account_id="123456789012"
    )
    doc = yaml.safe_load(result)
    stmt = _get_permission_statement(doc)
    # Resource: "*" should be present and is allowed per spec
    assert stmt.get("Resource") == "*", (
        f"Expected Resource: '*' in permission statement; got {stmt.get('Resource')!r}"
    )


def test_ac20_rendered_actions_no_mutating_verbs():
    """AC 20: No rendered action has a mutating verb."""
    from infra_twin.onboarding import render_aws_cloudformation
    forbidden_prefixes = (
        "Create", "Put", "Delete", "Update", "Modify", "Write",
        "Attach", "Detach", "Add", "Remove", "Set", "Run", "Start",
        "Stop", "Terminate", "Reboot", "Associate", "Disassociate",
        "Authorize", "Revoke", "Tag", "Untag",
    )
    result = render_aws_cloudformation(
        external_id="t", truster_account_id="123456789012"
    )
    doc = yaml.safe_load(result)
    stmt = _get_permission_statement(doc)
    for action in stmt["Action"]:
        verb = action.split(":", 1)[1]
        for prefix in forbidden_prefixes:
            assert not verb.startswith(prefix), (
                f"Rendered action {action!r} has mutating verb starting with {prefix!r}"
            )


def test_ac21_committed_template_actions_equal_readonly_actions():
    """AC 21: Committed template's permission action set equals set(READONLY_ACTIONS)."""
    from infra_twin.onboarding import READONLY_ACTIONS
    doc = yaml.safe_load(_TEMPLATE_PATH.read_text())
    template_actions = _get_template_permission_actions(doc)
    assert set(template_actions) == set(READONLY_ACTIONS), (
        f"Committed template action set does not match READONLY_ACTIONS.\n"
        f"  Missing from template: {set(READONLY_ACTIONS) - set(template_actions)}\n"
        f"  Extra in template:     {set(template_actions) - set(READONLY_ACTIONS)}"
    )


def test_ac21_committed_template_actions_no_wildcards():
    """AC 21 extra: Committed template has no wildcard actions."""
    doc = yaml.safe_load(_TEMPLATE_PATH.read_text())
    actions = _get_template_permission_actions(doc)
    for action in actions:
        assert "*" not in action, (
            f"Committed template action {action!r} contains wildcard '*'"
        )


def test_ac21_committed_template_actions_no_mutating_verbs():
    """AC 21 extra: Committed template has no mutating verbs in its action list."""
    forbidden_prefixes = (
        "Create", "Put", "Delete", "Update", "Modify", "Write",
        "Attach", "Detach", "Add", "Remove", "Set", "Run", "Start",
        "Stop", "Terminate", "Reboot", "Associate", "Disassociate",
        "Authorize", "Revoke", "Tag", "Untag",
    )
    doc = yaml.safe_load(_TEMPLATE_PATH.read_text())
    actions = _get_template_permission_actions(doc)
    for action in actions:
        verb = action.split(":", 1)[1]
        for prefix in forbidden_prefixes:
            assert not verb.startswith(prefix), (
                f"Committed template action {action!r} has mutating verb starting with {prefix!r}"
            )


def test_ac22_render_raises_value_error_on_empty_external_id():
    """AC 22 / EC 1: render_aws_cloudformation raises ValueError when external_id is empty."""
    from infra_twin.onboarding import render_aws_cloudformation
    with pytest.raises(ValueError):
        render_aws_cloudformation(external_id="", truster_account_id="123456789012")


def test_ac22_render_raises_value_error_on_whitespace_external_id():
    """AC 22 / EC 1: render_aws_cloudformation raises ValueError on whitespace-only external_id."""
    from infra_twin.onboarding import render_aws_cloudformation
    with pytest.raises(ValueError):
        render_aws_cloudformation(external_id="   ", truster_account_id="123456789012")


def test_ac22_render_raises_value_error_with_no_truster():
    """AC 22 / EC 2: render_aws_cloudformation raises ValueError when neither truster arg is given."""
    from infra_twin.onboarding import render_aws_cloudformation
    with pytest.raises(ValueError):
        render_aws_cloudformation(external_id="t")


def test_ec2_render_raises_value_error_both_truster_args_empty():
    """EC 2: ValueError when both truster_account_id and truster_role_arn are empty strings."""
    from infra_twin.onboarding import render_aws_cloudformation
    with pytest.raises(ValueError):
        render_aws_cloudformation(
            external_id="t",
            truster_account_id="",
            truster_role_arn="",
        )


def test_ec2_render_raises_value_error_both_truster_args_none():
    """EC 2: ValueError when both truster args are explicitly None."""
    from infra_twin.onboarding import render_aws_cloudformation
    with pytest.raises(ValueError):
        render_aws_cloudformation(
            external_id="t",
            truster_account_id=None,
            truster_role_arn=None,
        )


def test_ec4_whitespace_account_id_treated_as_empty():
    """EC 4: truster_account_id of only whitespace -> ValueError (treated as empty)."""
    from infra_twin.onboarding import render_aws_cloudformation
    with pytest.raises(ValueError):
        render_aws_cloudformation(
            external_id="t",
            truster_account_id="   ",
        )


def test_ec4_whitespace_account_id_with_role_arn_uses_role_arn():
    """EC 4: whitespace account_id with valid role_arn still uses the role_arn."""
    from infra_twin.onboarding import render_aws_cloudformation
    role_arn = "arn:aws:iam::123456789012:role/itw"
    result = render_aws_cloudformation(
        external_id="t",
        truster_account_id="   ",
        truster_role_arn=role_arn,
    )
    doc = yaml.safe_load(result)
    stmt = _get_trust_statement(doc)
    assert stmt["Principal"]["AWS"] == role_arn


def test_ec5_rendered_document_round_trips():
    """EC 5: yaml.safe_load(render_aws_cloudformation(...)) returns dict with trust policy, sts:ExternalId, action list."""
    from infra_twin.onboarding import READONLY_ACTIONS, render_aws_cloudformation
    result = render_aws_cloudformation(
        external_id="round-trip-id", truster_account_id="123456789012"
    )
    doc = yaml.safe_load(result)
    assert isinstance(doc, dict)

    # Trust policy is parseable
    stmt = _get_trust_statement(doc)
    assert stmt["Condition"]["StringEquals"]["sts:ExternalId"] == "round-trip-id"

    # Action list is parseable
    perm_stmt = _get_permission_statement(doc)
    assert set(perm_stmt["Action"]) == set(READONLY_ACTIONS)


def test_ec23_render_determinism():
    """EC 23: render_aws_cloudformation with identical args produces byte-identical output."""
    from infra_twin.onboarding import render_aws_cloudformation
    kwargs = dict(external_id="det-test", truster_account_id="123456789012")
    result1 = render_aws_cloudformation(**kwargs)
    result2 = render_aws_cloudformation(**kwargs)
    assert result1 == result2, "render_aws_cloudformation must be deterministic"


def test_ec24_render_default_role_name():
    """EC 24: When role_name is omitted, DEFAULT_ROLE_NAME is applied in the rendered doc."""
    from infra_twin.onboarding import DEFAULT_ROLE_NAME, render_aws_cloudformation
    result = render_aws_cloudformation(
        external_id="t", truster_account_id="123456789012"
    )
    doc = yaml.safe_load(result)
    role_props = doc["Resources"]["InfraTwinReadOnlyRole"]["Properties"]
    assert role_props.get("RoleName") == DEFAULT_ROLE_NAME, (
        f"Expected RoleName == {DEFAULT_ROLE_NAME!r}; got {role_props.get('RoleName')!r}"
    )


def test_ec24_render_custom_role_name():
    """EC 24: When role_name is provided, it appears in the rendered doc."""
    from infra_twin.onboarding import render_aws_cloudformation
    result = render_aws_cloudformation(
        external_id="t",
        truster_account_id="123456789012",
        role_name="MyCustomRole",
    )
    doc = yaml.safe_load(result)
    role_props = doc["Resources"]["InfraTwinReadOnlyRole"]["Properties"]
    assert role_props.get("RoleName") == "MyCustomRole", (
        f"Expected RoleName == 'MyCustomRole'; got {role_props.get('RoleName')!r}"
    )


def test_ec24_render_default_path():
    """EC 24: When path is omitted, DEFAULT_ROLE_PATH is applied in the rendered doc."""
    from infra_twin.onboarding import DEFAULT_ROLE_PATH, render_aws_cloudformation
    result = render_aws_cloudformation(
        external_id="t", truster_account_id="123456789012"
    )
    doc = yaml.safe_load(result)
    role_props = doc["Resources"]["InfraTwinReadOnlyRole"]["Properties"]
    assert role_props.get("Path") == DEFAULT_ROLE_PATH, (
        f"Expected Path == {DEFAULT_ROLE_PATH!r}; got {role_props.get('Path')!r}"
    )


def test_ec24_render_custom_path():
    """EC 24: When path is provided, it appears in the rendered doc."""
    from infra_twin.onboarding import render_aws_cloudformation
    result = render_aws_cloudformation(
        external_id="t",
        truster_account_id="123456789012",
        path="/custom/",
    )
    doc = yaml.safe_load(result)
    role_props = doc["Resources"]["InfraTwinReadOnlyRole"]["Properties"]
    assert role_props.get("Path") == "/custom/", (
        f"Expected Path == '/custom/'; got {role_props.get('Path')!r}"
    )


def test_render_aws_template_format_version():
    """Rendered doc has AWSTemplateFormatVersion == '2010-09-09'."""
    from infra_twin.onboarding import render_aws_cloudformation
    result = render_aws_cloudformation(
        external_id="t", truster_account_id="123456789012"
    )
    doc = yaml.safe_load(result)
    assert doc.get("AWSTemplateFormatVersion") == "2010-09-09"


def test_render_has_outputs_block():
    """Rendered doc has an Outputs block."""
    from infra_twin.onboarding import render_aws_cloudformation
    result = render_aws_cloudformation(
        external_id="t", truster_account_id="123456789012"
    )
    doc = yaml.safe_load(result)
    assert "Outputs" in doc, "Rendered CloudFormation doc must have Outputs block"


# ===========================================================================
# Endpoint tests (AC 23-29)
# ===========================================================================


def test_endpoint_no_auth_returns_401(pool):
    """AC 23 / EC 11: GET /onboarding/aws-cloudformation with no auth header -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/onboarding/aws-cloudformation")
    assert resp.status_code == 401, (
        f"Expected 401 without auth header; got {resp.status_code}"
    )


def test_endpoint_no_auth_detail_missing_api_key(pool):
    """EC 11: 401 detail is 'missing API key' when Authorization absent."""
    client = TestClient(create_app(pool=pool))
    resp = client.get("/onboarding/aws-cloudformation")
    assert resp.json().get("detail") == "missing API key", (
        f"Expected detail 'missing API key'; got {resp.json()}"
    )


def test_endpoint_invalid_key_returns_401(pool):
    """EC 12: GET /onboarding/aws-cloudformation with invalid/unknown key -> 401."""
    client = TestClient(create_app(pool=pool))
    resp = client.get(
        "/onboarding/aws-cloudformation",
        headers={"Authorization": "Bearer itw_bogus.invalidsecret"},
    )
    assert resp.status_code == 401, (
        f"Expected 401 for invalid key; got {resp.status_code}"
    )


def test_endpoint_viewer_key_with_truster_env_returns_200(pool, monkeypatch):
    """AC 24 / EC 13: viewer key + truster env configured -> 200."""
    monkeypatch.setenv("INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID", "123456789012")
    _, viewer_key = _make_viewer_key("ob-viewer-200")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/onboarding/aws-cloudformation", headers=_auth(viewer_key))
    assert resp.status_code == 200, (
        f"Expected 200 for viewer key with truster env; got {resp.status_code}"
    )


def test_endpoint_editor_key_with_truster_env_returns_200(pool, monkeypatch):
    """AC 25 / EC 14: editor key + truster env configured -> 200."""
    monkeypatch.setenv("INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID", "123456789012")
    _, editor_key = _make_editor_key("ob-editor-200")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/onboarding/aws-cloudformation", headers=_auth(editor_key))
    assert resp.status_code == 200, (
        f"Expected 200 for editor key with truster env; got {resp.status_code}"
    )


def test_endpoint_content_type_is_text_yaml(pool, monkeypatch):
    """AC 24 / EC 15: Response Content-Type starts with 'text/yaml'."""
    monkeypatch.setenv("INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID", "123456789012")
    _, viewer_key = _make_viewer_key("ob-content-type")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/onboarding/aws-cloudformation", headers=_auth(viewer_key))
    assert resp.status_code == 200
    content_type = resp.headers.get("content-type", "")
    assert content_type.startswith("text/yaml"), (
        f"Response Content-Type must start with 'text/yaml'; got {content_type!r}"
    )


def test_endpoint_body_is_raw_yaml_document(pool, monkeypatch):
    """EC 15: Response body is raw YAML document with top-level AWSTemplateFormatVersion key."""
    monkeypatch.setenv("INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID", "123456789012")
    _, viewer_key = _make_viewer_key("ob-body-raw")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/onboarding/aws-cloudformation", headers=_auth(viewer_key))
    assert resp.status_code == 200
    doc = yaml.safe_load(resp.text)
    assert isinstance(doc, dict), "Response body must parse as a YAML dict"
    assert "AWSTemplateFormatVersion" in doc, (
        "Top-level AWSTemplateFormatVersion key must be present in response body"
    )


def test_endpoint_external_id_equals_tenant_id(pool, monkeypatch):
    """AC 26 / EC 15: Response sts:ExternalId equals the calling tenant's tenant_id."""
    monkeypatch.setenv("INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID", "123456789012")
    tenant_id, viewer_key = _make_viewer_key("ob-ext-id-match")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/onboarding/aws-cloudformation", headers=_auth(viewer_key))
    assert resp.status_code == 200
    doc = yaml.safe_load(resp.text)
    stmt = _get_trust_statement(doc)
    external_id = stmt["Condition"]["StringEquals"]["sts:ExternalId"]
    assert external_id == str(tenant_id), (
        f"sts:ExternalId must equal tenant_id {str(tenant_id)!r}; got {external_id!r}"
    )


def test_endpoint_two_tenants_different_external_ids(pool, monkeypatch):
    """AC 27 / EC 15: Two different tenants receive templates with different ExternalIds."""
    monkeypatch.setenv("INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID", "123456789012")
    tenant_a, key_a = _make_viewer_key("ob-two-tenants-a")
    tenant_b, key_b = _make_viewer_key("ob-two-tenants-b")
    client = TestClient(create_app(pool=pool))

    resp_a = client.get("/onboarding/aws-cloudformation", headers=_auth(key_a))
    resp_b = client.get("/onboarding/aws-cloudformation", headers=_auth(key_b))

    assert resp_a.status_code == 200
    assert resp_b.status_code == 200

    doc_a = yaml.safe_load(resp_a.text)
    doc_b = yaml.safe_load(resp_b.text)

    ext_id_a = _get_trust_statement(doc_a)["Condition"]["StringEquals"]["sts:ExternalId"]
    ext_id_b = _get_trust_statement(doc_b)["Condition"]["StringEquals"]["sts:ExternalId"]

    assert ext_id_a == str(tenant_a), (
        f"Tenant A's ExternalId must equal tenant_id {str(tenant_a)!r}; got {ext_id_a!r}"
    )
    assert ext_id_b == str(tenant_b), (
        f"Tenant B's ExternalId must equal tenant_id {str(tenant_b)!r}; got {ext_id_b!r}"
    )
    assert ext_id_a != ext_id_b, (
        f"Two different tenants must receive different ExternalIds; "
        f"got A={ext_id_a!r}, B={ext_id_b!r}"
    )


def test_endpoint_two_tenants_same_action_list(pool, monkeypatch):
    """EC 15: Two different tenants receive templates with identical action lists."""
    from infra_twin.onboarding import READONLY_ACTIONS
    monkeypatch.setenv("INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID", "123456789012")
    _, key_a = _make_viewer_key("ob-actions-a")
    _, key_b = _make_viewer_key("ob-actions-b")
    client = TestClient(create_app(pool=pool))

    resp_a = client.get("/onboarding/aws-cloudformation", headers=_auth(key_a))
    resp_b = client.get("/onboarding/aws-cloudformation", headers=_auth(key_b))

    assert resp_a.status_code == 200
    assert resp_b.status_code == 200

    doc_a = yaml.safe_load(resp_a.text)
    doc_b = yaml.safe_load(resp_b.text)

    actions_a = set(_get_permission_statement(doc_a)["Action"])
    actions_b = set(_get_permission_statement(doc_b)["Action"])

    assert actions_a == actions_b == set(READONLY_ACTIONS), (
        "Both tenants must receive the same action list equal to READONLY_ACTIONS"
    )


def test_endpoint_no_truster_env_returns_503(pool, monkeypatch):
    """AC 28 / EC 16: With valid key but no truster env vars -> 503."""
    monkeypatch.delenv("INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("INFRA_TWIN_AWS_TRUSTER_ROLE_ARN", raising=False)
    _, viewer_key = _make_viewer_key("ob-503-no-truster")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/onboarding/aws-cloudformation", headers=_auth(viewer_key))
    assert resp.status_code == 503, (
        f"Expected 503 when no truster env var is set; got {resp.status_code}"
    )


def test_endpoint_no_truster_env_503_detail(pool, monkeypatch):
    """AC 28 / EC 16: 503 detail is 'AWS onboarding is not configured'."""
    monkeypatch.delenv("INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("INFRA_TWIN_AWS_TRUSTER_ROLE_ARN", raising=False)
    _, viewer_key = _make_viewer_key("ob-503-detail")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/onboarding/aws-cloudformation", headers=_auth(viewer_key))
    assert resp.status_code == 503
    assert resp.json().get("detail") == "AWS onboarding is not configured", (
        f"Expected detail 'AWS onboarding is not configured'; got {resp.json()}"
    )


def test_ec17_truster_role_arn_env_used_as_principal(pool, monkeypatch):
    """EC 17: INFRA_TWIN_AWS_TRUSTER_ROLE_ARN set -> rendered principal is role ARN."""
    role_arn = "arn:aws:iam::999999999999:role/infra-twin-svc"
    monkeypatch.setenv("INFRA_TWIN_AWS_TRUSTER_ROLE_ARN", role_arn)
    monkeypatch.delenv("INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID", raising=False)
    _, viewer_key = _make_viewer_key("ob-role-arn-env")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/onboarding/aws-cloudformation", headers=_auth(viewer_key))
    assert resp.status_code == 200
    doc = yaml.safe_load(resp.text)
    stmt = _get_trust_statement(doc)
    principal = stmt["Principal"]["AWS"]
    assert principal == role_arn, (
        f"Expected principal {role_arn!r} from ROLE_ARN env; got {principal!r}"
    )


def test_ec18_only_account_id_env_yields_root_principal(pool, monkeypatch):
    """EC 18: Only INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID set -> rendered principal is ':root'."""
    monkeypatch.setenv("INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID", "111222333444")
    monkeypatch.delenv("INFRA_TWIN_AWS_TRUSTER_ROLE_ARN", raising=False)
    _, viewer_key = _make_viewer_key("ob-account-id-env")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/onboarding/aws-cloudformation", headers=_auth(viewer_key))
    assert resp.status_code == 200
    doc = yaml.safe_load(resp.text)
    stmt = _get_trust_statement(doc)
    principal = stmt["Principal"]["AWS"]
    assert principal == "arn:aws:iam::111222333444:root", (
        f"Expected ':root' form principal; got {principal!r}"
    )


def test_endpoint_role_arn_env_wins_over_account_id_env(pool, monkeypatch):
    """EC 17: When both env vars set, ROLE_ARN wins over ACCOUNT_ID."""
    role_arn = "arn:aws:iam::111111111111:role/preferred"
    monkeypatch.setenv("INFRA_TWIN_AWS_TRUSTER_ROLE_ARN", role_arn)
    monkeypatch.setenv("INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID", "999999999999")
    _, viewer_key = _make_viewer_key("ob-both-env-role-arn-wins")
    client = TestClient(create_app(pool=pool))
    resp = client.get("/onboarding/aws-cloudformation", headers=_auth(viewer_key))
    assert resp.status_code == 200
    doc = yaml.safe_load(resp.text)
    stmt = _get_trust_statement(doc)
    principal = stmt["Principal"]["AWS"]
    assert principal == role_arn, (
        f"ROLE_ARN env should win; expected {role_arn!r}, got {principal!r}"
    )


def test_endpoint_uses_read_permission_dependency():
    """AC 29: The endpoint is registered with require_permission('read') dependency (_read = _read)."""
    # Verify by inspecting the source code that the route uses _read
    import inspect
    from infra_twin.api import app as _app_module
    src = inspect.getsource(_app_module)
    assert "get_aws_cloudformation" in src, "Handler get_aws_cloudformation not found in app.py"
    assert "tenant: UUID = _read" in src, (
        "Endpoint must use 'tenant: UUID = _read' (Depends(require_permission('read')))"
    )


# ===========================================================================
# .env.example checks (AC 30)
# ===========================================================================


def test_ac30_env_example_has_truster_account_id():
    """AC 30: .env.example contains INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID (commented)."""
    text = _ENV_EXAMPLE.read_text()
    assert "INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID" in text, (
        ".env.example must contain INFRA_TWIN_AWS_TRUSTER_ACCOUNT_ID"
    )


def test_ac30_env_example_has_truster_role_arn():
    """AC 30: .env.example contains INFRA_TWIN_AWS_TRUSTER_ROLE_ARN (commented)."""
    text = _ENV_EXAMPLE.read_text()
    assert "INFRA_TWIN_AWS_TRUSTER_ROLE_ARN" in text, (
        ".env.example must contain INFRA_TWIN_AWS_TRUSTER_ROLE_ARN"
    )
