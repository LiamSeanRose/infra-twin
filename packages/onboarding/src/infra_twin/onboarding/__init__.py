"""Customer onboarding artifacts: least-privilege read-only IAM role rendering."""

from __future__ import annotations

from infra_twin.onboarding.aws import (
    DEFAULT_ROLE_NAME,
    DEFAULT_ROLE_PATH,
    READONLY_ACTIONS,
    render_aws_cloudformation,
)

__all__ = [
    "READONLY_ACTIONS",
    "DEFAULT_ROLE_NAME",
    "DEFAULT_ROLE_PATH",
    "render_aws_cloudformation",
]
