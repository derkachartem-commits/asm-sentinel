import hmac
import os
import secrets
import time

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("ASM_DATA_DIR", os.path.join(BASE_DIR, "data"))
COOKIE_NAME = "asm_session"
SESSION_MAX_AGE = 12 * 3600


def _load_secret() -> str:
    env = os.environ.get("ASM_SECRET")
    if env:
        return env
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, "secret.key")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            value = f.read().strip()
        if value:
            return value
    value = secrets.token_urlsafe(48)
    with open(path, "w", encoding="utf-8") as f:
        f.write(value)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return value


SECRET = _load_secret()
SERIALIZER = URLSafeTimedSerializer(SECRET, salt="asm-sentinel-session")
ADMIN_PASSWORD = os.environ.get("ASM_ADMIN_PASSWORD", "changeme")

_failures: dict[str, list[float]] = {}


def password_ok(candidate: str) -> bool:
    return hmac.compare_digest(candidate.encode(), ADMIN_PASSWORD.encode())


def make_session() -> str:
    return SERIALIZER.dumps({"u": "admin", "csrf": secrets.token_hex(16)})


def read_session(token: str | None) -> dict | None:
    if not token:
        return None
    try:
        data = SERIALIZER.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    if not isinstance(data, dict) or data.get("u") != "admin":
        return None
    return data


def login_allowed(ip: str) -> bool:
    cutoff = time.time() - 300
    attempts = [t for t in _failures.get(ip, []) if t > cutoff]
    _failures[ip] = attempts
    return len(attempts) < 6


def note_failure(ip: str) -> None:
    _failures.setdefault(ip, []).append(time.time())


def clear_failures(ip: str) -> None:
    _failures.pop(ip, None)
