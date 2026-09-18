#!/usr/bin/env bash
# Restore a snapshot made by snapshot.sh into the running stack (replaces the database).
set -euo pipefail
cd "$(dirname "$0")/../.."
src=${1:-demo/snapshot}
docker compose exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner' < "$src/codeaudit.pgdump"
docker compose exec -T worker python -c '
import sys, tarfile
from app.config import get_settings
from app.core.storage import get_s3_client
s = get_settings(); c = get_s3_client()
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as tar:
    for member in tar:
        if member.isfile():
            c.put_object(Bucket=s.s3_bucket_uploads, Key=member.name, Body=tar.extractfile(member).read())
' < "$src/uploads.tar"
cp "$src/state.json" demo/state.json 2>/dev/null || true
docker compose restart api worker >/dev/null
echo "restored from $src"
