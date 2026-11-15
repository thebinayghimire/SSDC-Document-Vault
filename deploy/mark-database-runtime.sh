#!/bin/sh
# Only the official fresh-cluster initialization invokes this hook.
set -eu
printf '%s\n' alpine-musl-pg17-v1 > "$PGDATA/.ssdc-runtime-family"
chmod 0600 "$PGDATA/.ssdc-runtime-family"
