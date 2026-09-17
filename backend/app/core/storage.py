import io
from functools import lru_cache
from pathlib import Path
from typing import BinaryIO

import boto3
from boto3.s3.transfer import TransferConfig
from botocore.client import BaseClient
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.config import MB, get_settings
from app.core.errors import AnalysisError, TransientInfraError

# Multipart transfers: files are streamed in 8 MB parts, never loaded whole.
_TRANSFER_CONFIG = TransferConfig(
    multipart_threshold=8 * MB,
    multipart_chunksize=8 * MB,
    max_concurrency=4,
)


class StorageError(Exception):
    """Base class for object storage failures."""


class StorageUnavailableError(StorageError, TransientInfraError):
    """Storage unreachable, timing out, or returning 5xx."""


class StorageObjectNotFoundError(StorageError, AnalysisError):
    """The requested object does not exist."""


@lru_cache
def get_s3_client() -> BaseClient:
    """S3-compatible client (MinIO locally; any S3-compatible store in prod)."""
    settings = get_settings()
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint_url,
        region_name=settings.s3_region,
        aws_access_key_id=settings.s3_access_key_id,
        aws_secret_access_key=settings.s3_secret_access_key.get_secret_value(),
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            connect_timeout=3,
            retries={"max_attempts": 3},
        ),
    )


def _translate(exc: BotoCoreError | ClientError, key: str) -> StorageError:
    if isinstance(exc, ClientError):
        code = str(exc.response.get("Error", {}).get("Code", ""))
        status = int(exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0))
        if code in {"404", "NoSuchKey", "NoSuchBucket"}:
            return StorageObjectNotFoundError(f"Object not found in storage: {key}")
        if status >= 500:
            return StorageUnavailableError(f"Object storage error ({code or status})")
        return StorageError(f"Object storage request failed ({code or status})")
    return StorageUnavailableError(f"Object storage unavailable: {type(exc).__name__}")


def upload_fileobj(fileobj: BinaryIO, key: str, content_type: str) -> None:
    try:
        get_s3_client().upload_fileobj(
            fileobj,
            get_settings().s3_bucket_uploads,
            key,
            ExtraArgs={"ContentType": content_type},
            Config=_TRANSFER_CONFIG,
        )
    except (BotoCoreError, ClientError) as exc:
        raise _translate(exc, key) from exc


def upload_bytes(key: str, data: bytes, content_type: str) -> None:
    upload_fileobj(io.BytesIO(data), key, content_type)


def get_bytes(key: str, max_bytes: int = 64 * 1024 * 1024) -> bytes:
    try:
        response = get_s3_client().get_object(Bucket=get_settings().s3_bucket_uploads, Key=key)
        if int(response.get("ContentLength") or 0) > max_bytes:
            raise StorageError(f"Object {key} is larger than {max_bytes} bytes")
        return bytes(response["Body"].read(max_bytes))
    except (BotoCoreError, ClientError) as exc:
        raise _translate(exc, key) from exc


def download_file(key: str, dest: Path) -> None:
    try:
        get_s3_client().download_file(
            get_settings().s3_bucket_uploads, key, str(dest), Config=_TRANSFER_CONFIG
        )
    except (BotoCoreError, ClientError) as exc:
        raise _translate(exc, key) from exc


def delete_object(key: str) -> None:
    try:
        get_s3_client().delete_object(Bucket=get_settings().s3_bucket_uploads, Key=key)
    except (BotoCoreError, ClientError) as exc:
        raise _translate(exc, key) from exc


def check_storage() -> None:
    """Raise if the uploads bucket is unreachable."""
    get_s3_client().head_bucket(Bucket=get_settings().s3_bucket_uploads)
