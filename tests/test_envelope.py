import base64

import pytest

from sqlalchemy_encrypted_field import (
    NotConfiguredError,
    SecretDecryptError,
    configure,
    utils,
    validate_keys,
)
from tests.conftest import key

# An envelope written by the first release under the key and AAD below, with the
# default HKDF info. It must stay readable forever: any change to the envelope
# layout, the derivation, or the default info string breaks this test, which is
# the point — stored data outlives the code that wrote it.
_PINNED_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
_PINNED_AAD = "notes.token"
_PINNED_ENVELOPE = base64.b64decode(
    "AWzfyRJJUCiv1mg5EZ6ZmC5HpkpOjh0xFs2anXrai6o2uJwyJn/65KjGdXRMyM5d/Wawg2qxVl1B"
)


def test_round_trip():
    assert utils.decrypt(utils.encrypt(b"value", "t.c"), "t.c") == b"value"


def test_pinned_envelope_still_decrypts():
    configure(_PINNED_KEY)

    assert utils.decrypt(_PINNED_ENVELOPE, _PINNED_AAD) == b"pinned-value"


def test_envelope_is_bound_to_its_aad():
    envelope = utils.encrypt(b"value", "table.one")

    with pytest.raises(SecretDecryptError):
        utils.decrypt(envelope, "table.two")


def test_ciphertext_never_contains_the_plaintext():
    assert b"value" not in utils.encrypt(b"value", "t.c")


def test_every_envelope_uses_a_fresh_salt_and_nonce():
    first, second = utils.encrypt(b"value", "t.c"), utils.encrypt(b"value", "t.c")

    assert first[:29] != second[:29]


def test_prepended_key_still_decrypts():
    # Rotation is prepend-only: new writes use the first key; rows written
    # under an older key keep decrypting as long as it stays in the list.
    old = key()
    configure(old)
    envelope = utils.encrypt(b"value", "t.c")

    configure(f"{key()},{old}")

    assert utils.decrypt(envelope, "t.c") == b"value"


def test_dropped_key_raises_the_named_error():
    envelope = utils.encrypt(b"value", "t.c")
    configure(key())

    with pytest.raises(SecretDecryptError, match="rotated out"):
        utils.decrypt(envelope, "t.c")


@pytest.mark.parametrize("garbled", [b"", b"\x01ab", b"\x01" + b"x" * 60])
def test_garbled_envelope_raises_the_named_error(garbled):
    # No structural pre-checks in decrypt: GCM authentication (and the
    # ValueError a mangled nonce raises) fold every unreadable shape into the
    # one named error.
    with pytest.raises(SecretDecryptError):
        utils.decrypt(garbled, "t.c")


def test_changed_info_makes_old_envelopes_unreadable():
    # The guard rail behind configure()'s warning: info is part of the key
    # derivation, so changing it after the first write loses the data.
    envelope = utils.encrypt(b"value", "t.c")
    configure(utils._source(), info=b"other")

    with pytest.raises(SecretDecryptError):
        utils.decrypt(envelope, "t.c")


def test_a_callable_key_source_is_consulted_per_operation():
    keys = [key()]
    configure(lambda: keys[0])
    envelope = utils.encrypt(b"value", "t.c")

    keys[0] = key()

    with pytest.raises(SecretDecryptError):
        utils.decrypt(envelope, "t.c")


def test_use_before_configure_is_refused(monkeypatch):
    monkeypatch.setattr(utils, "_source", None)

    with pytest.raises(NotConfiguredError, match="configure"):
        utils.encrypt(b"value", "t.c")


@pytest.mark.parametrize("broken", ["", ",", " , "])
def test_a_keyless_configuration_is_refused(broken):
    with pytest.raises(ValueError, match="at least one"):
        configure(broken)


@pytest.mark.parametrize(
    ("broken", "message"),
    [("not-base64!!", "base64"), (base64.b64encode(b"short").decode(), "32 bytes")],
)
def test_a_malformed_key_is_refused(broken, message):
    with pytest.raises(ValueError, match=message):
        configure(broken)


def test_validation_never_echoes_the_key():
    # A half-valid list fails validation, and the failure surfaces in boot
    # logs — it must not echo the valid segment.
    good = key()

    with pytest.raises(ValueError) as error:
        validate_keys(f"{good},not-base64!!")

    assert good not in str(error.value)


def test_validation_drops_blank_segments():
    good = key()

    assert validate_keys(f" {good} ,, ") == good
