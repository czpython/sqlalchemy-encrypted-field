import base64
import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from sqlalchemy_encrypted_field import (
    EncryptedBytesField,
    EncryptedJsonField,
    EncryptedTextField,
    configure,
    utils,
)


def key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


class Base(DeclarativeBase):
    pass


class Note(Base):
    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(default="")
    token = EncryptedTextField(default="")
    payload = EncryptedBytesField(default=b"")
    data = EncryptedJsonField()


class Other(Base):
    # A second table with an encrypted column, so a test can prove an envelope
    # cannot be replayed across columns.
    __tablename__ = "others"

    id: Mapped[int] = mapped_column(primary_key=True)
    token = EncryptedTextField(default="")


@pytest.fixture(autouse=True)
def reset_configuration():
    # configure() writes module globals; every test starts from a known key and
    # leaves nothing behind for the next one.
    configure(key())
    yield
    utils._source, utils._info = None, utils.DEFAULT_INFO
    utils._parse.cache_clear()


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
