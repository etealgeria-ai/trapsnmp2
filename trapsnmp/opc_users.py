"""OPC UA username token policy."""

from __future__ import annotations

import re
import secrets

from asyncua.crypto.permission_rules import User, UserRole

_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
USER_POLICY = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"


class PasswordUsers:
    """Anonymous stays allowed. A username must match a saved password.

    On an open channel the password is encrypted with Basic256Sha256 and the
    server certificate. A SignAndEncrypt channel already hides it.
    """

    def __init__(self) -> None:
        self.passwords: dict[str, str] = {"trapsnmp": "trapsnmp"}

    def get_user(self, _iserver, username: str | None = None, password: str | None = None, certificate=None):
        if not username:
            return User(role=UserRole.User)
        expected = self.passwords.get(username)
        if expected is None or not _same_secret(expected, password):
            return None
        return User(role=UserRole.User, name=username)

    def add(self, name: str, password: str) -> None:
        name = (name or "").strip()
        if not _NAME.fullmatch(name):
            raise ValueError("User name must be 1–32 letters, numbers, dot, underscore, or dash.")
        if not isinstance(password, str) or len(password) < 8 or len(password) > 64:
            raise ValueError("Password must be 8–64 characters.")
        self.passwords[name] = password

    def remove(self, name: str) -> None:
        if name not in self.passwords:
            raise ValueError("Unknown user.")
        if len(self.passwords) == 1:
            raise ValueError("Keep at least one OPC UA user.")
        del self.passwords[name]

    def names(self) -> list[str]:
        return sorted(self.passwords)


def _same_secret(expected: str, offered) -> bool:
    try:
        left = expected.encode("utf-8")
        right = offered.encode("utf-8") if isinstance(offered, str) else bytes(offered or b"")
    except Exception:
        return False
    if len(left) != len(right):
        return False
    return secrets.compare_digest(left, right)
