#!/usr/bin/env bash
# Save the seeded demo state (Postgres + the MinIO uploads bucket) so it can be
# restored on a machine with no network: scripts/demo/restore.sh demo/snapshot.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${1:-demo/snapshot}
mkdir -p "$out"
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$out/codeaudit.pgdump"
docker compose exec -T worker python -c '
import io, sys, tarfile
from app.config import get_settings
from app.core.storage import get_s3_client
s = get_settings(); c = get_s3_client()
with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as tar:
    for page in c.get_paginator("list_objects_v2").paginate(Bucket=s.s3_bucket_uploads):
        for obj in page.get("Contents", []):
            data = c.get_object(Bucket=s.s3_bucket_uploads, Key=obj["Key"])["Body"].read()
            info = tarfile.TarInfo(obj["Key"]); info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
' > "$out/uploads.tar"
cp demo/state.json "$out/state.json" 2>/dev/null || true
ls -lh "$out"
