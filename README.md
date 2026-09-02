# sqlalchemy-encrypted-field

Encrypted column types for SQLAlchemy. Secrets are ciphertext at rest, plaintext
only where you ask for it.

```python
from sqlalchemy_encrypted_field import EncryptedTextField, configure

configure(os.environ["SQLALCHEMY_ENCRYPTED_FIELD_KEYS"])


class Server(Base):
    __tablename__ = "servers"

    id: Mapped[int] = mapped_column(primary_key=True)
    token = EncryptedTextField(default="")


session.add(Server(token="sk-live-..."))
session.commit()

server.token  # Secret(<redacted>)
server.token.decrypt()  # "sk-live-..."
```

## What it does differently

**Every envelope is bound to its column.** The associated data is the owning
`table.column`, so ciphertext copied from one column into another fails to
decrypt. Without this, anyone with write access to the database can move a
low-value token into a high-value column, or one tenant's row into another's,
without ever touching a key.

**Key rotation has no flag day.** The key setting is a comma-separated list.
The first key encrypts, every key decrypts. Rotating means prepending a new key
and dropping the old one once nothing needs it, with no downtime and no bulk
re-encryption.

**Loading a row never decrypts it.** Reads hand back a `Secret`, not a string.
Decryption happens only where `decrypt()` is called, and `repr()` is redacted,
so a logged row or a stack trace cannot leak the value.

**Failures are named.** A dropped key raises `SecretDecryptError`, whose message
points at the key configuration rather than a bare crypto traceback. Using a
column before `configure()` raises `NotConfiguredError` instead of silently
storing plaintext.

## Install

```bash
pip install sqlalchemy-encrypted-field
```

Requires Python 3.11+, SQLAlchemy 2.0+. Tested on 3.11 through 3.14.

## Fields

| Field | Assign | Read back |
| --- | --- | --- |
| `EncryptedTextField()` | `str` | `Secret`, use `.decrypt() -> str` |
| `EncryptedBytesField()` | `bytes` | `SecretBytes`, use `.decrypt() -> bytes` |
| `EncryptedJsonField()` | `dict` | `SecretsMapping`, a lazily-decrypting dict |

All three store `LargeBinary` and are NOT NULL. Empty values (`""`, `b""`) are
stored as empty bytes with no envelope, so a missing secret costs no crypto and
needs no key.

`SecretsMapping` tracks in-place writes, so `row.data["token"] = "new"` marks
the column dirty and persists on flush. Reach for it when a secret is genuinely
a mapping; a single value belongs in an `EncryptedTextField`.

Assigning a loaded `Secret` to a different column re-encrypts it under that
column's associated data, so moving a value between columns works.

## Keys

Generate one:

```bash
python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

`configure()` takes that string, or a comma-separated list of them. It also
takes a callable returning the string, which is consulted on every operation.
Use the callable form when keys come from settings that can be reloaded at
runtime.

```python
configure(lambda: settings.secrets_key)
```

`validate_keys(value)` is exposed separately so the same rules can run inside
your own settings validation and fail at startup. A malformed or absent key is
always an error, never a fallback to plaintext. Validation errors never echo the
key material, because they end up in logs.

## Envelope

```
version[1] || salt[16] || nonce[12] || ciphertext[n] || tag[16]
```

AES-256-GCM. The salt derives a per-envelope key with HKDF-SHA256 over the
configured master key, so the master never reaches a cipher directly and nonce
reuse across envelopes is not a concern. The `table.column` string is the
associated data.

`configure(..., info=b"...")` overrides the HKDF info string. The default suits
new projects. Set it only to keep reading envelopes written by an existing
store that used a different one, and never change it once data exists, because
it is part of the key derivation.

## What it is not

This encrypts values so that a database dump, a backup, or a replica is not a
pile of readable credentials. It does not protect against an attacker who can
read your process memory or your key.

## License

MIT
