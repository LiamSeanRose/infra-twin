"""Pydantic v2 request/response models for the SCIM 2.0 /scim/v2/Users surface.

These models live under apps/api only and are not a shared package.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, field_validator


class ScimUserCreateBody(BaseModel):
    """SCIM User create/replace request body."""

    schemas: list[str] | None = None              # accepted and ignored
    userName: str
    externalId: str | None = None
    active: bool = True
    roles: list[dict] | None = None               # first entry's 'value' mapped to Role

    @field_validator("userName")
    @classmethod
    def user_name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("userName must not be empty or whitespace")
        return v


# Alias: PUT uses the same shape as create.
ScimUserPutBody = ScimUserCreateBody


class ScimPatchOp(BaseModel):
    op: str
    path: str | None = None
    value: bool | dict | str | None = None


class ScimPatchBody(BaseModel):
    schemas: list[str] | None = None
    Operations: list[ScimPatchOp]


class ScimTokenBody(BaseModel):
    """Body for POST /tenants/{tenant_id}/scim-token."""

    name: str | None = None
