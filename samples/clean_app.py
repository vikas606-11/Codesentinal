"""A small, clean module: CodeSentinel should report no findings and score 100."""
import hashlib
import secrets
from pathlib import Path


def new_salt() -> bytes:
    return secrets.token_bytes(16)


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()


def read_lines(path: str) -> list[str]:
    try:
        return Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
