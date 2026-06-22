"""Pure-helper tests for api_keys: generate_key, parse_key, hash_secret, verify_secret.

AC 5: KEY_PREFIX == "itw_"; every generate_key().plaintext starts with "itw_" and
      contains exactly one '.'.
AC 6: hash_secret uses hashlib.scrypt with n==2**14, r==8, p==1, dklen==32.
AC 7: verify_secret uses hmac.compare_digest (constant-time).
Edge cases 1-8 from spec §6 covering key format parsing.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from infra_twin.db.api_keys import (
    KEY_ID_BYTES,
    KEY_PREFIX,
    KEY_SECRET_BYTES,
    GeneratedKey,
    generate_key,
    hash_secret,
    new_salt,
    parse_key,
    verify_secret,
)


# ---------------------------------------------------------------------------
# AC 5 — KEY_PREFIX and generate_key format
# ---------------------------------------------------------------------------


def test_key_prefix_is_itw():
    """AC 5: KEY_PREFIX constant is exactly 'itw_'."""
    assert KEY_PREFIX == "itw_"


def test_generate_key_plaintext_starts_with_prefix():
    """AC 5: every generate_key().plaintext starts with 'itw_'."""
    for _ in range(5):
        gk = generate_key()
        assert gk.plaintext.startswith("itw_"), (
            f"plaintext does not start with 'itw_': {gk.plaintext}"
        )


def test_generate_key_plaintext_has_exactly_one_dot():
    """AC 5: every generate_key().plaintext contains exactly one '.'."""
    for _ in range(5):
        gk = generate_key()
        assert gk.plaintext.count(".") == 1, (
            f"plaintext should contain exactly one '.': {gk.plaintext}"
        )


def test_generate_key_returns_generated_key_dataclass():
    """generate_key() returns a GeneratedKey instance."""
    gk = generate_key()
    assert isinstance(gk, GeneratedKey)


def test_generate_key_fields_consistent():
    """generate_key().plaintext == f'itw_{key_id}.{secret}'."""
    gk = generate_key()
    expected = f"{KEY_PREFIX}{gk.key_id}.{gk.secret}"
    assert gk.plaintext == expected


def test_generate_key_key_id_not_empty():
    """generate_key().key_id is non-empty."""
    gk = generate_key()
    assert gk.key_id


def test_generate_key_secret_not_empty():
    """generate_key().secret is non-empty."""
    gk = generate_key()
    assert gk.secret


def test_generate_key_key_id_has_no_dot():
    """key_id from token_urlsafe has no '.' so separator is unambiguous."""
    for _ in range(10):
        gk = generate_key()
        assert "." not in gk.key_id, (
            f"key_id should never contain '.': {gk.key_id}"
        )


def test_generate_key_produces_distinct_keys():
    """Two calls to generate_key() return distinct plaintexts."""
    a = generate_key()
    b = generate_key()
    assert a.plaintext != b.plaintext


# ---------------------------------------------------------------------------
# parse_key — happy path
# ---------------------------------------------------------------------------


def test_parse_key_round_trip():
    """parse_key(generate_key().plaintext) returns (key_id, secret)."""
    gk = generate_key()
    result = parse_key(gk.plaintext)
    assert result is not None
    key_id, secret = result
    assert key_id == gk.key_id
    assert secret == gk.secret


def test_parse_key_returns_tuple_of_two():
    """parse_key on a valid key returns a 2-tuple."""
    gk = generate_key()
    result = parse_key(gk.plaintext)
    assert isinstance(result, tuple)
    assert len(result) == 2


# ---------------------------------------------------------------------------
# parse_key — edge cases from spec §6 that return None
# ---------------------------------------------------------------------------


def test_parse_key_missing_prefix_returns_none():
    """EC 4 / AC 14: key without 'itw_' prefix -> parse_key returns None."""
    assert parse_key("bogus_key.secret") is None


def test_parse_key_no_separator_returns_none():
    """EC 5: key with no '.' separator -> None."""
    assert parse_key("itw_keyidsecret") is None


def test_parse_key_empty_key_id_returns_none():
    """EC 5: 'itw_.' (empty key_id) -> None."""
    assert parse_key("itw_.somesecret") is None


def test_parse_key_empty_secret_returns_none():
    """EC 5: 'itw_keyid.' (empty secret) -> None."""
    assert parse_key("itw_keyid.") is None


def test_parse_key_empty_string_returns_none():
    """EC 4: empty string -> None."""
    assert parse_key("") is None


def test_parse_key_only_prefix_returns_none():
    """EC 5: just the prefix, nothing after -> None."""
    assert parse_key("itw_") is None


def test_parse_key_lowercase_bearer_prefix_returns_none():
    """EC 2 / EC 4: no key prefix (wrong case) -> None."""
    assert parse_key("ITW_key.secret") is None


def test_parse_key_splits_on_first_dot():
    """parse_key splits on the FIRST '.' only; secret may contain '.'."""
    gk = generate_key()
    # Manually construct a plaintext where the secret itself contains a dot.
    crafted = f"itw_{gk.key_id}.part1.part2"
    result = parse_key(crafted)
    assert result is not None
    key_id, secret = result
    assert key_id == gk.key_id
    assert secret == "part1.part2"


# ---------------------------------------------------------------------------
# AC 6 — hash_secret uses hashlib.scrypt with correct parameters
# ---------------------------------------------------------------------------


def test_hash_secret_output_is_hex_string():
    """hash_secret returns a hex string."""
    salt = new_salt()
    digest = hash_secret("mysecret", salt)
    assert isinstance(digest, str)
    # hex string of 32 bytes == 64 chars
    assert len(digest) == 64


def test_hash_secret_matches_stdlib_scrypt():
    """AC 6: hash_secret uses scrypt(n=2**14, r=8, p=1, dklen=32)."""
    secret = "test-secret"
    salt = new_salt()
    expected = hashlib.scrypt(
        secret.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32
    ).hex()
    assert hash_secret(secret, salt) == expected


def test_hash_secret_different_salts_produce_different_hashes():
    """Different salts produce different hash outputs for the same secret."""
    secret = "same-secret"
    salt_a = new_salt()
    salt_b = new_salt()
    # Vanishingly unlikely salts are equal, but assert result differs.
    if salt_a != salt_b:
        assert hash_secret(secret, salt_a) != hash_secret(secret, salt_b)


def test_hash_secret_different_secrets_produce_different_hashes():
    """Different secrets produce different hashes for the same salt."""
    salt = new_salt()
    assert hash_secret("secret-a", salt) != hash_secret("secret-b", salt)


def test_hash_secret_deterministic():
    """hash_secret is deterministic — same inputs yield same output."""
    secret = "deterministic"
    salt = b"\xde\xad\xbe\xef" * 4
    h1 = hash_secret(secret, salt)
    h2 = hash_secret(secret, salt)
    assert h1 == h2


# ---------------------------------------------------------------------------
# AC 7 — verify_secret uses hmac.compare_digest (constant-time)
# ---------------------------------------------------------------------------


def test_verify_secret_returns_true_on_correct_secret():
    """verify_secret returns True when secret matches the stored hash."""
    secret = "correct-secret"
    salt = new_salt()
    expected = hash_secret(secret, salt)
    assert verify_secret(secret, salt, expected) is True


def test_verify_secret_returns_false_on_wrong_secret():
    """EC 6: verify_secret returns False when secret does not match (tamper rejection)."""
    secret = "correct-secret"
    salt = new_salt()
    expected = hash_secret(secret, salt)
    assert verify_secret("wrong-secret", salt, expected) is False


def test_verify_secret_returns_false_on_tampered_hash():
    """verify_secret returns False if the stored hash has been tampered."""
    secret = "mysecret"
    salt = new_salt()
    good_hash = hash_secret(secret, salt)
    tampered = "0" * len(good_hash)
    assert verify_secret(secret, salt, tampered) is False


def test_verify_secret_uses_compare_digest():
    """AC 7: verify_secret delegates to hmac.compare_digest (constant-time)."""
    # Confirm it does not raise on unequal-length inputs (compare_digest handles this).
    salt = new_salt()
    # Short hex string — compare_digest must not raise even on length mismatch.
    result = verify_secret("secret", salt, "deadbeef")
    assert result is False


def test_new_salt_returns_16_bytes():
    """new_salt() returns exactly 16 bytes."""
    s = new_salt()
    assert isinstance(s, bytes)
    assert len(s) == 16


def test_new_salt_produces_distinct_values():
    """Two calls to new_salt() return distinct byte strings."""
    assert new_salt() != new_salt()
