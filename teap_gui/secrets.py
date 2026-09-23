"""Encryption at rest for RADIUS shared secrets and certificate private keys.

The key comes from TEAP_GUI_KEY. When unset, one is generated and written to
the data directory on first run, and the file is the thing to protect —
anyone who can read it can read every stored secret.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_KEY_ENV = "TEAP_GUI_KEY"
_KEY_FILE = "secret.key"
_fernet: Fernet | None = None


def _load_key(data_dir: Path) -> bytes:
    env = os.environ.get(_KEY_ENV)
    if env:
        return env.encode()
    path = data_dir / _KEY_FILE
    if path.exists():
        return path.read_bytes()
    key = Fernet.generate_key()
    data_dir.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    path.chmod(0o600)
    return key


def init(data_dir: Path) -> None:
    global _fernet
    _fernet = Fernet(_load_key(data_dir))


def encrypt(plaintext: str) -> str:
    if _fernet is None:
        raise RuntimeError("teap_gui.secrets.init() must be called first")
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    if _fernet is None:
        raise RuntimeError("teap_gui.secrets.init() must be called first")
    try:
        return _fernet.decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("stored secret cannot be decrypted — wrong or rotated "
                         f"{_KEY_ENV}") from exc
