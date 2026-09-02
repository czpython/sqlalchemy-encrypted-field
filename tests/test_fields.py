import pytest
from sqlalchemy import select, text

from sqlalchemy_encrypted_field import SecretDecryptError, configure, utils
from tests.conftest import Note, Other, key

_TOKEN = "lin_secret_value"


def test_stored_text_is_ciphertext_and_reads_restore_it(session):
    session.add(Note(name="one", token=_TOKEN))
    session.commit()

    blob = session.execute(text("SELECT token FROM notes")).scalar_one()
    assert _TOKEN.encode() not in blob
    session.expunge_all()
    assert session.execute(select(Note)).scalar_one().token.decrypt() == _TOKEN


def test_stored_bytes_round_trip(session):
    session.add(Note(name="one", payload=b"\x00binary\xff"))
    session.commit()
    session.expunge_all()

    assert session.execute(select(Note)).scalar_one().payload.decrypt() == b"\x00binary\xff"


def test_loaded_secrets_are_lazy_and_redacted(session):
    # Loading and logging a row never touches key material — decryption happens
    # only on decrypt(), and repr leaks nothing either way.
    session.add(Note(name="one", token=_TOKEN, payload=b"p"))
    session.commit()
    session.expunge_all()

    note = session.execute(select(Note)).scalar_one()
    configure(key())

    assert repr(note.token) == "Secret(<redacted>)"
    assert str(note.token) == "Secret(<redacted>)"
    assert repr(note.payload) == "SecretBytes(<redacted>)"
    with pytest.raises(SecretDecryptError):
        note.token.decrypt()


def test_empty_value_needs_no_key(session):
    # "" stores as empty bytes — presence checks and decrypt() of an absent
    # secret never touch key material, proven by unsetting the key first.
    session.add(Note(name="one", token="", payload=b""))
    session.commit()
    session.expunge_all()

    assert session.execute(text("SELECT token FROM notes")).scalar_one() == b""
    note = session.execute(select(Note)).scalar_one()
    utils._source = None

    assert not note.token
    assert note.token.decrypt() == ""
    assert not note.payload
    assert note.payload.decrypt() == b""


def test_ciphertext_is_bound_to_its_column(session):
    # An envelope can't be replayed into another encrypted column, in this
    # table or any other.
    session.add_all([Note(name="one", token=_TOKEN), Other(id=1, token="other")])
    session.commit()
    session.execute(text("UPDATE others SET token = (SELECT token FROM notes)"))
    session.commit()
    session.expunge_all()

    with pytest.raises(SecretDecryptError):
        session.execute(select(Other)).scalar_one().token.decrypt()


def test_a_secret_moved_between_columns_re_encrypts(session):
    # Assigning a loaded Secret to another column stores it under that
    # column's AAD, so the value survives the move.
    session.add(Note(name="one", token=_TOKEN))
    session.commit()
    session.expunge_all()

    session.add(Other(id=1, token=session.execute(select(Note)).scalar_one().token))
    session.commit()
    session.expunge_all()

    assert session.execute(select(Other)).scalar_one().token.decrypt() == _TOKEN


@pytest.mark.parametrize(("column", "value"), [("token", 123), ("payload", "not-bytes")])
def test_wrong_type_assignment_is_rejected(session, column, value):
    note = Note(name="one")
    setattr(note, column, value)
    session.add(note)

    with pytest.raises(Exception, match="takes a str|takes bytes"):
        session.flush()


def test_json_mapping_round_trips_as_ciphertext(session):
    session.add(Note(name="one", data={"token": _TOKEN, "extra": "x"}))
    session.commit()

    blob = session.execute(text("SELECT data FROM notes")).scalar_one()
    assert _TOKEN.encode() not in blob
    session.expunge_all()
    note = session.execute(select(Note)).scalar_one()
    assert note.data["token"] == _TOKEN
    assert repr(note.data) == "SecretsMapping(<redacted>)"


def test_json_in_place_write_persists(session):
    # Writing one key of the mapping must mark the column dirty on its own
    # (the Mutable wiring) and survive the flush.
    session.add(Note(name="one", data={"token": "old"}))
    session.commit()
    session.expunge_all()

    note = session.execute(select(Note)).scalar_one()
    note.data["token"] = "new"
    session.commit()
    session.expunge_all()

    assert session.execute(select(Note)).scalar_one().data["token"] == "new"


def test_json_defaults_to_an_empty_mapping(session):
    session.add(Note(name="one"))
    session.commit()
    session.expunge_all()

    assert dict(session.execute(select(Note)).scalar_one().data) == {}


def test_json_non_dict_assignment_is_rejected():
    note = Note(name="one")

    with pytest.raises(ValueError, match="dict"):
        note.data = "plaintext"
