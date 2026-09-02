import base64
import os
from collections.abc import Callable
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sqlalchemy_encrypted_field.exceptions import NotConfiguredError, SecretDecryptError

# The stored envelope, byte-exact:
#
#   version[1] || salt[16] || nonce[12] || ciphertext[n] || tag[16]
#
# The salt derives this envelope's AES key (HKDF over a configured master key —
# the master never touches a cipher directly, and a fresh key per envelope
# makes nonce reuse a non-concern); AES-GCM returns ciphertext with the tag
# appended. The AAD names the owning scope — ``table.column`` for encrypted
# columns — so a blob can't be replayed anywhere else.
_ENVELOPE_V1 = b"\x01"
_SALT_LEN = 16
_NONCE_LEN = 12
_HEADER_LEN = 1 + _SALT_LEN + _NONCE_LEN

DEFAULT_INFO = b"sqlalchemy-encrypted-field-v1"

_source: Callable[[], str] | None = None
_info: bytes = DEFAULT_INFO


def validate_keys(value: str) -> str:
    # Comma-separated base64 32-byte master keys: the first encrypts, every key
    # decrypts — rotation is prepending a fresh key, stored rows keep
    # decrypting under the old one. Blank segments are config noise, dropped;
    # none left, or a malformed one, is refused: a keyless process could
    # neither store nor use a secret. Errors never echo the value, because they
    # surface in boot logs.
    segments = [segment.strip() for segment in str(value).split(",") if segment.strip()]
    if not segments:
        raise ValueError("set at least one base64-encoded 32-byte key")
    for segment in segments:
        try:
            key = base64.b64decode(segment, validate=True)
        except ValueError as error:
            raise ValueError("keys must be base64-encoded") from error
        if len(key) != 32:
            raise ValueError("keys must decode to 32 bytes")
    return ",".join(segments)


def configure(keys: str | Callable[[], str], *, info: bytes = DEFAULT_INFO) -> None:
    """Set the master keys every encrypted column uses.

    ``keys`` is a comma-separated list of base64-encoded 32-byte keys, or a
    callable returning one. The first key encrypts; every key decrypts, so
    rotation is prepending a fresh key and dropping the old one once no row
    needs it. Pass a callable when the keys come from settings that can be
    reloaded — it is consulted on each operation, not captured here.

    ``info`` is the HKDF info string mixed into every envelope's key
    derivation. Changing it makes existing envelopes undecryptable, so set it
    once, before the first write, and never again.
    """
    global _source, _info
    _source = keys if callable(keys) else _fixed(validate_keys(keys))
    _info = info


def _fixed(value: str) -> Callable[[], str]:
    return lambda: value


@lru_cache
def _parse(raw: str) -> tuple[bytes, ...]:
    return tuple(base64.b64decode(segment) for segment in validate_keys(raw).split(","))


def _master_keys() -> tuple[bytes, ...]:
    if _source is None:
        raise NotConfiguredError()
    return _parse(_source())


def _derive_key(master: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=salt, info=_info).derive(master)


def encrypt(plaintext: bytes, aad: str) -> bytes:
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(_derive_key(_master_keys()[0], salt)).encrypt(
        nonce, plaintext, aad.encode()
    )
    return _ENVELOPE_V1 + salt + nonce + ciphertext


def decrypt(envelope: bytes, aad: str) -> bytes:
    # No structural checks: the GCM tag authenticates ciphertext + AAD, so a
    # truncated, garbled, or foreign envelope fails the same way a wrong key
    # does (a mangled nonce raises ValueError instead of InvalidTag) — every
    # unreadable shape is the one named error.
    salt = envelope[1 : 1 + _SALT_LEN]
    nonce = envelope[1 + _SALT_LEN : _HEADER_LEN]
    ciphertext = envelope[_HEADER_LEN:]
    for master in _master_keys():
        try:
            return AESGCM(_derive_key(master, salt)).decrypt(nonce, ciphertext, aad.encode())
        except (InvalidTag, ValueError):
            continue
    raise SecretDecryptError()
