"""OIDC ID-token verification for infra-twin.

Routing scheme
--------------
A value extracted from ``Authorization: Bearer <value>`` is routed as follows:

1. If ``value`` starts with ``itw_`` (the KEY_PREFIX from api_keys): route to
   the existing API-key path.  ``looks_like_jwt`` returns False for these.
2. Else if ``value`` has exactly two '.' separators and none of the three
   segments (header, payload, signature) is empty: route to the OIDC path.
   ``looks_like_jwt`` returns True.
3. Else: route to the API-key path (non-JWT junk gets API-key error messages).

``verify_oidc_token`` performs NO network call of its own.  All key material
is supplied via the injectable ``key_resolver`` callable so tests can pass
in-process keys without any network stack.

No raw token, claim payload, or signature is ever logged, returned in an HTTP
response body, or persisted to the database.  ``OidcError`` messages describe
the failure class only — never the token value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from uuid import UUID

import jwt

from infra_twin.db.api_keys import KEY_PREFIX, Role

# ---------------------------------------------------------------------------
# Algorithm-family guards (algorithm-confusion prevention)
# ---------------------------------------------------------------------------

# Maps each supported algorithm to the key-type family it requires.
# Asymmetric algorithms require a typed key object from the cryptography
# library; symmetric algorithms require bytes or str (HMAC secret).
# This mapping is used to narrow the active allow-list to only algorithms
# that are structurally compatible with the resolved key's runtime type,
# making it impossible for a token to cross algorithm families even if the
# caller passes a broad allow-list.
_ASYMMETRIC_ALGS: frozenset[str] = frozenset({
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
    "EdDSA",
})
_SYMMETRIC_ALGS: frozenset[str] = frozenset({"HS256", "HS384", "HS512"})


def _algorithms_for_key(key: object, requested: list[str]) -> list[str]:
    """Return the subset of *requested* algorithms compatible with *key*'s type.

    Raises OidcError if the intersection is empty (key type incompatible with
    every requested algorithm) or if the key is an asymmetric private key
    (we never accept private keys for verification).

    Rules:
    - ``bytes`` or ``str`` -> HMAC family (HS256/384/512).
    - cryptography ``RSAPublicKey`` -> RS*/PS* family.
    - cryptography ``EllipticCurvePublicKey`` -> ES* family.
    - cryptography ``Ed25519PublicKey`` / ``Ed448PublicKey`` -> EdDSA.
    - Any asymmetric *private* key -> rejected (must not verify with private key).
    - Anything else (e.g. a PyJWT ``PyJWK`` wrapper or an opaque object) ->
      accepted as-is; PyJWT itself will reject incompatible alg/key combos.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, padding  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric.rsa import (
            RSAPublicKey, RSAPrivateKey,
        )
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicKey, EllipticCurvePrivateKey,
        )
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey, Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.asymmetric.ed448 import (
            Ed448PublicKey, Ed448PrivateKey,
        )
        _have_crypto = True
    except ImportError:
        _have_crypto = False

    if isinstance(key, (bytes, str)):
        # HMAC secret: restrict to symmetric algorithms.
        compatible = [a for a in requested if a in _SYMMETRIC_ALGS]
        if not compatible:
            raise OidcError("HMAC key is not compatible with any requested algorithm")
        return compatible

    if _have_crypto:
        # Reject private keys — verification must use public keys only.
        private_types = (RSAPrivateKey, EllipticCurvePrivateKey, Ed25519PrivateKey, Ed448PrivateKey)
        if isinstance(key, private_types):
            raise OidcError("key resolution returned a private key; verification requires a public key")

        if isinstance(key, RSAPublicKey):
            compatible = [a for a in requested if a in {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}]
            if not compatible:
                raise OidcError("RSA public key is not compatible with any requested algorithm")
            return compatible

        if isinstance(key, EllipticCurvePublicKey):
            compatible = [a for a in requested if a in {"ES256", "ES384", "ES512"}]
            if not compatible:
                raise OidcError("EC public key is not compatible with any requested algorithm")
            return compatible

        if isinstance(key, (Ed25519PublicKey, Ed448PublicKey)):
            compatible = [a for a in requested if a == "EdDSA"]
            if not compatible:
                raise OidcError("EdDSA public key is not compatible with any requested algorithm")
            return compatible

    # Unknown key type (e.g. PyJWK wrapper): pass the full list and let
    # PyJWT enforce alg/key compatibility at decode time.
    return requested


@dataclass(frozen=True)
class ResolvedOidcPrincipal:
    tenant_id: UUID
    role: Role
    subject: str   # OIDC subject used for SCIM deactivation lookup (sub > email > preferred_username)


class OidcError(Exception):
    """Raised on any OIDC verification or claim-mapping failure.

    Carries NO raw token material, claim bytes, or signature fragments.
    """


# Injectable signing-key seam.
# Signature: (issuer: str, kid: str | None) -> key-material accepted by PyJWT.
# Tests pass a resolver that returns key material without any network call.
# Production wires a JWKS fetcher behind this callable.
KeyResolver = Callable[[str, "str | None"], object]


def looks_like_jwt(token: str) -> bool:
    """Return True iff token looks like a JWT and is NOT an API key.

    A token is considered a JWT candidate when ALL of:
    - It does NOT start with KEY_PREFIX (``itw_``).
    - It contains exactly two '.' characters.
    - None of the three dot-separated segments (header, payload, signature)
      is empty.

    This check is deliberately cheap; cryptographic validity is left to PyJWT.
    """
    if token.startswith(KEY_PREFIX):
        return False
    parts = token.split(".")
    if len(parts) != 3:
        return False
    return all(p != "" for p in parts)


def verify_oidc_token(
    token: str,
    *,
    find_config,                          # callable(issuer, audience) -> TenantIdpConfig | None
    key_resolver: KeyResolver,
    algorithms: list[str] | None = None,
    leeway_seconds: int = 0,
) -> ResolvedOidcPrincipal:
    """Offline-verify an OIDC ID token and map it to a ResolvedOidcPrincipal.

    Raises OidcError on any failure; never returns a partial principal.

    Steps:
    1. Read unverified iss, aud, kid from the token header/payload.
    2. Look up the active tenant_idp_config for (iss, aud).
    3. Resolve signing-key material via key_resolver(iss, kid).
    4. Fully verify the token with PyJWT (signature, exp, iat, nbf, iss, aud).
    5. Map the role_claim value through role_claim_map; fall back to default_role.
    6. Return ResolvedOidcPrincipal(tenant_id, role).

    No network call is performed inside this function.
    """
    if algorithms is None:
        algorithms = ["RS256", "HS256"]

    # ------------------------------------------------------------------
    # Step 1: read unverified header + payload
    # ------------------------------------------------------------------
    try:
        header = jwt.get_unverified_header(token)
    except jwt.exceptions.PyJWTError as exc:
        raise OidcError("token header could not be decoded") from exc

    try:
        unverified_claims = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=algorithms,
        )
    except jwt.exceptions.PyJWTError as exc:
        raise OidcError("token payload could not be decoded") from exc

    iss = unverified_claims.get("iss")
    aud = unverified_claims.get("aud")
    kid: str | None = header.get("kid")

    if not iss or not isinstance(iss, str):
        raise OidcError("token is missing a valid 'iss' claim")
    if not aud or (not isinstance(aud, (str, list))):
        raise OidcError("token is missing a valid 'aud' claim")

    # Normalise audience: PyJWT accepts a string audience; if aud is a list
    # we extract the single element we expect the config to match.
    if isinstance(aud, list):
        aud_for_lookup = aud[0] if len(aud) == 1 else ",".join(sorted(aud))
    else:
        aud_for_lookup = aud

    # ------------------------------------------------------------------
    # Step 2: find the active tenant config
    # ------------------------------------------------------------------
    cfg = find_config(iss, aud_for_lookup)
    if cfg is None:
        raise OidcError("no active IdP configuration for issuer/audience")

    # ------------------------------------------------------------------
    # Step 3: resolve signing-key material (no network call in this fn)
    # ------------------------------------------------------------------
    try:
        key = key_resolver(cfg.issuer, kid)
    except OidcError:
        raise
    except Exception as exc:
        raise OidcError("key resolution failed") from exc

    # Narrow the algorithm allow-list to only those compatible with the
    # resolved key's runtime type.  This prevents algorithm-confusion
    # attacks regardless of what the caller passed as `algorithms`.
    effective_algorithms = _algorithms_for_key(key, algorithms)

    # ------------------------------------------------------------------
    # Step 4: full cryptographic verification via PyJWT
    # ------------------------------------------------------------------
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=effective_algorithms,
            audience=cfg.audience,
            issuer=cfg.issuer,
            leeway=leeway_seconds,
            options={"require": ["exp", "iat"]},
        )
    except jwt.exceptions.PyJWTError as exc:
        raise OidcError("token verification failed") from exc

    # ------------------------------------------------------------------
    # Step 5: map role claim
    # ------------------------------------------------------------------
    raw_role = claims.get(cfg.role_claim)
    mapped_role = cfg.default_role
    if raw_role is not None:
        raw_str = str(raw_role)
        mapped_value = cfg.role_claim_map.get(raw_str)
        if mapped_value is not None:
            try:
                mapped_role = Role(mapped_value)
            except ValueError:
                # mapped value is not a valid Role — fall back to default
                mapped_role = cfg.default_role

    # ------------------------------------------------------------------
    # Step 5b: resolve OIDC subject for SCIM deactivation lookup.
    # Precedence: sub > email > preferred_username (first non-empty wins).
    # The value is stored on the principal and used only for a
    # tenant-scoped DB lookup; it is never logged or echoed back.
    # ------------------------------------------------------------------
    subject: str = ""
    for claim_name in ("sub", "email", "preferred_username"):
        val = claims.get(claim_name)
        if val and isinstance(val, str) and val.strip():
            subject = val
            break

    # ------------------------------------------------------------------
    # Step 6: return principal
    # ------------------------------------------------------------------
    return ResolvedOidcPrincipal(tenant_id=cfg.tenant_id, role=mapped_role, subject=subject)
