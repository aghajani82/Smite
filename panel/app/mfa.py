"""RFC 6238 authenticator verification, encrypted secrets, and one-time recovery codes.

Never log TOTP secrets, provisioning URIs, or recovery codes.
Secrets are encrypted using a key derived from the deployment's SECRET_KEY;
rotating that key requires an explicit MFA re-enrollment procedure.
"""
import base64
import hashlib
import hmac
import io
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


def mfa_configured() -> bool:
    key = settings.secret_key
    return len(key) >= 32 and key != "changeme-secret-key-change-in-production"


def _fernet() -> Fernet:
    if not mfa_configured():
        raise ValueError("Configure a strong SECRET_KEY before enabling two-factor authentication")
    digest = hashlib.sha256(("smite-mfa-encryption-v1:" + settings.secret_key).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def seal_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode("ascii")).decode("ascii")


def open_secret(sealed: str) -> str:
    try:
        return _fernet().decrypt(sealed.encode("ascii")).decode("ascii")
    except (InvalidToken, ValueError) as exc:
        raise ValueError("Authenticator secret could not be decrypted") from exc


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def provisioning_uri(username: str, secret: str) -> str:
    label = quote("Smite:" + username, safe="")
    return f"otpauth://totp/{label}?secret={secret}&issuer=Smite&algorithm=SHA1&digits=6&period=30"


def local_qr_data_uri(uri: str) -> str:
    """Encode an authenticator QR completely inside the Panel process.

    The TOTP secret must never be sent to a remote QR image service, CDN,
    logging endpoint, or unauthenticated route. The caller serves it only
    from the password-confirmed MFA enrollment API with no-store headers.
    SVG generation embeds QR geometry, not executable HTML.
    """
    import qrcode
    import qrcode.image.svg

    stream = io.BytesIO()
    qr = qrcode.make(
        uri,
        image_factory=qrcode.image.svg.SvgPathImage,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        border=4,
        box_size=8,
    )
    qr.save(stream)
    return "data:image/svg+xml;base64," + base64.b64encode(stream.getvalue()).decode("ascii")


def totp(secret: str, counter: int) -> str:
    raw = base64.b32decode(secret + "=" * ((-len(secret)) % 8), casefold=True)
    signature = hmac.new(raw, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = signature[-1] & 15
    value = (struct.unpack(">I", signature[offset:offset + 4])[0] & 0x7fffffff) % 1_000_000
    return f"{value:06d}"


def matching_step(secret: str, code: str, last_step: int | None = None, now: float | None = None) -> int | None:
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    current = int(time.time() if now is None else now) // 30
    for step in (current - 1, current, current + 1):
        if step >= 0 and (last_step is None or step > last_step):
            if hmac.compare_digest(totp(secret, step), code):
                return step
    return None


def create_recovery_codes() -> list[str]:
    # 80 bits/code; show each code once, never persist plaintext.
    return ["-".join((lambda s: [s[i:i + 4] for i in range(0, 20, 4)])(secrets.token_hex(10).upper()))
            for _ in range(10)]


def recovery_digest(code: str) -> str:
    normalized = code.strip().upper().replace("-", "").replace(" ", "")
    return hmac.new(
        hashlib.sha256(("smite-recovery-v1:" + settings.secret_key).encode()).digest(),
        normalized.encode("ascii", errors="ignore"),
        hashlib.sha256,
    ).hexdigest()
