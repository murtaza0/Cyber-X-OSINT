import hashlib
import hmac
import os
import base64
from cryptography.fernet import Fernet, InvalidToken
from .config import settings, STORAGE_DIR

_KEY_FILE = STORAGE_DIR / ".credential.key"

def _load_key() -> bytes:
    configured = settings.credential_encryption_key.strip()
    if configured:
        try:
            key = configured.encode("ascii")
            Fernet(key)
            return key
        except Exception as exc:
            raise RuntimeError("CREDENTIAL_ENCRYPTION_KEY must be a valid Fernet key") from exc
    if os.getenv("VERCEL", "").lower() in {"1", "true", "yes"}:
        # Stable fallback across serverless instances; set a dedicated key in production.
        if not settings.api_token:
            raise RuntimeError("Set CREDENTIAL_ENCRYPTION_KEY in Vercel environment variables")
        key = base64.urlsafe_b64encode(hashlib.sha256(("cyberx-credential-key:" + settings.api_token).encode()).digest())
        return key
    if _KEY_FILE.exists():
        key = _KEY_FILE.read_bytes().strip()
        Fernet(key)
        try:
            os.chmod(_KEY_FILE, 0o600)
        except OSError:
            pass
        return key
    key = Fernet.generate_key()
    try:
        fd = os.open(_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        key = _KEY_FILE.read_bytes().strip()
        Fernet(key)
        return key
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
    return key

_FERNET = Fernet(_load_key())

def encrypt_secret(value: str) -> str:
    if not value:
        raise ValueError("Password cannot be empty")
    return _FERNET.encrypt(value.encode("utf-8")).decode("ascii")

def decrypt_secret(value: str) -> str:
    try:
        return _FERNET.decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise ValueError("Credential could not be decrypted; check the encryption key") from exc

def verify_api_token(provided: str | None) -> bool:
    expected = settings.api_token
    if not expected or not provided:
        return False
    return hmac.compare_digest(hashlib.sha256(provided.encode()).digest(), hashlib.sha256(expected.encode()).digest())
