from collections.abc import Iterator
from pathlib import Path

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
    client = docker.from_env(version="auto")
    try:
        client.ping()
        client.images.get(get_settings().semgrep_image)
    except docker.errors.ImageNotFound:
        client.images.pull(get_settings().semgrep_image)
    finally:
        client.close()


@pytest.fixture(scope="session")
def integration_env() -> None:
    """Postgres + MinIO (docker compose stack) and a Docker daemon, or skip."""
    try:
        _prepare_database()
    except SQLAlchemyError as exc:
        pytest.skip(f"Postgres unavailable: {exc}")
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
