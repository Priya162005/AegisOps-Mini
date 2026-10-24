"""Authentication helpers: salted PBKDF2 password hashing and role permissions."""
from __future__ import annotations

import hashlib
import hmac
import secrets

ITERATIONS = 150_000
ROLES = ["viewer", "operator", "admin"]
PERMISSIONS = {
    "viewer": {"view"},
    "operator": {"view", "operate", "approve"},
    "admin": {"view", "operate", "approve", "admin"},
}
MAX_FAILED_ATTEMPTS = 5
MIN_PASSWORD_LENGTH = 8

# Demo accounts created on first start (change them in Administration).
DEFAULT_USERS = [
    ("admin", "Admin@123", "admin", "System Administrator"),
    ("operator", "Operator@123", "operator", "On-call Operator"),
    ("viewer", "Viewer@123", "viewer", "Read-only Auditor"),
]


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return digest.hex(), salt.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    digest, _ = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(digest, hash_hex)


def can(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, set())
