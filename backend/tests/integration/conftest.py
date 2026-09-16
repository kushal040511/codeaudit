import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import docker
import pytest
from alembic.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from docker.errors import DockerException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

from alembic import command
from app.config import get_settings

if TYPE_CHECKING:
    from tests.github_fakes import FakeGitHub

BACKEND_DIR = Path(__file__).parents[2]


def _prepare_database() -> None:
    """Recreate the test database and migrate it to head (this exercises the migration)."""
    url = make_url(get_settings().database_url)
    admin = create_engine(
        url.set(database="postgres"),
        isolation_level="AUTOCOMMIT",
        connect_args={"connect_timeout": 3},
    )
    try:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)'))
            conn.execute(text(f'CREATE DATABASE "{url.database}"'))
    finally:
        admin.dispose()
    command.upgrade(Config(str(BACKEND_DIR / "alembic.ini")), "head")


def _prepare_bucket() -> None:
    from app.core.storage import get_s3_client

    s3 = get_s3_client()
    bucket = get_settings().s3_bucket_uploads
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError:
        s3.create_bucket(Bucket=bucket)


def _prepare_docker() -> None:
    settings = get_settings()
    client = docker.from_env(version="auto")
    try:
        client.ping()
        for image in (
            settings.semgrep_image,
            settings.bandit_image,
            settings.ruff_image,
            settings.osv_scanner_image,
        ):
            try:
                client.images.get(image)
            except docker.errors.ImageNotFound:
                client.images.pull(image)
    finally:
        client.close()


@pytest.fixture(scope="session")
def database() -> None:
    """A freshly migrated test database, or skip."""
    try:
        _prepare_database()
    except SQLAlchemyError as exc:
        pytest.skip(f"Postgres unavailable: {exc}")


@pytest.fixture(scope="session")
def integration_env(database: None) -> None:
    """Postgres + MinIO (docker compose stack) and a Docker daemon, or skip."""
    try:
        _prepare_bucket()
    except (BotoCoreError, ClientError) as exc:
        pytest.skip(f"Object storage unavailable: {exc}")
    try:
        _prepare_docker()
    except DockerException as exc:
        pytest.skip(f"Docker unavailable: {exc}")


@pytest.fixture
def client(integration_env: None) -> Iterator[TestClient]:
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def api(database: None) -> Iterator[TestClient]:
    """API client for read endpoints; needs only the database."""
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------- GitHub


@pytest.fixture
def fake_github() -> Iterator["FakeGitHub"]:
    """An in-memory GitHub; every GitHub request in the app goes to it."""
    from app.services.github import client as github_client
    from tests.github_fakes import FakeGitHub

    fake = FakeGitHub()
    github_client.set_transport_override(fake.transport)
    yield fake
    github_client.set_transport_override(None)


@pytest.fixture
def redis_clean() -> None:
    from redis.exceptions import RedisError

    from app.core.redis_client import get_redis

    try:
        redis = get_redis()
        for key in redis.scan_iter("codeaudit:ratelimit:*"):
            redis.delete(key)
    except RedisError as exc:
        pytest.skip(f"Redis unavailable: {exc}")


class SignedIn:
    """A user signed in through a session cookie, with a GitHub identity."""

    def __init__(self, client: TestClient, user_id: "uuid.UUID", csrf: str, login: str, token: str):
        self.client = client
        self.user_id = user_id
        self.csrf = csrf
        self.login = login
        self.token = token

    @property
    def headers(self) -> dict[str, str]:
        return {"X-CSRF-Token": self.csrf}


SignIn = Callable[..., SignedIn]


@pytest.fixture
def sign_in(database: None, redis_clean: None, fake_github: "FakeGitHub") -> Iterator[SignIn]:
    """sign_in(login, scopes=...) -> SignedIn with its own TestClient."""
    from app.core.db import SessionLocal
    from app.main import app
    from app.models import GitHubIdentity, User
    from app.services.auth.crypto import encrypt_token
    from app.services.auth.sessions import SESSION_COOKIE, create_session

    clients: list[TestClient] = []
    counter = iter(range(10_000, 20_000))

    def make(login: str, scopes: tuple[str, ...] = ("public_repo", "read:user")) -> SignedIn:
        user_number = next(counter)
        token = f"gho_{login}_{uuid.uuid4().hex}"
        fake_github.add_user(login, token, user_id=user_number)
        with SessionLocal() as db:
            user = User(id=uuid.uuid4(), display_name=login)
            db.add(user)
            db.add(
                GitHubIdentity(
                    user_id=user.id,
                    github_user_id=int(uuid.uuid4().int % 10**12),
                    login=login,
                    access_token_encrypted=encrypt_token(token),
                    scopes=sorted(scopes),
                )
            )
            db.commit()
            secret, session = create_session(db, user)
            client = TestClient(app)
            client.cookies.set(SESSION_COOKIE, secret)
            clients.append(client)
            return SignedIn(client, user.id, session.csrf_token, login, token)

    yield make
    for client in clients:
        client.close()
