class SecretDecryptError(Exception):
    # A stored secret exists but none of the configured keys decrypt it — the
    # usual cause is a key dropped from the configured list while rows still
    # encrypted under it existed. Named so a delivery failure points at the
    # key config, not a bare crypto traceback.
    def __init__(self) -> None:
        super().__init__(
            "A stored secret could not be decrypted with any configured key. "
            "If a key was rotated out, prepend the current key with it again; "
            "otherwise re-enter the secret."
        )


class NotConfiguredError(Exception):
    # Reading or writing an encrypted column before configure() ran. Loud,
    # because the alternative is a process that silently cannot serve secrets.
    def __init__(self) -> None:
        super().__init__(
            "No encryption keys are configured. Call "
            "sqlalchemy_encrypted_field.configure(keys) during startup, before "
            "any encrypted column is read or written."
        )
