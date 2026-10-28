#!/bin/sh
set -eu
if [ "${1#-}" != "$1" ]; then
    set -- postgres "$@"
fi
if [ "$1" = postgres ] && [ -s "$PGDATA/PG_VERSION" ]; then
    runtime=$(cat "$PGDATA/.ssdc-runtime-family" 2>/dev/null || true)
    if [ "$runtime" != alpine-musl-pg17-v1 ]; then
        echo "Refusing an unverified database volume. Keep the previous database image and perform a logical dump/restore into a new volume; see docs/DATABASE_IMAGE_MIGRATION.md." >&2
        exit 1
    fi
fi
exec /usr/local/bin/docker-entrypoint.sh "$@"
