#!/bin/sh
set -eu
: "${PORTAL_HOST:?Set canonical PORTAL_HOST}"
: "${HTTPS_PORT:=443}"
: "${MAX_UPLOAD_BYTES:=26214400}"
case "$PORTAL_HOST" in *[!a-zA-Z0-9.-]*|'') echo 'Invalid canonical host' >&2; exit 1;; esac
case "$HTTPS_PORT" in *[!0-9]*|'') echo 'Invalid HTTPS port' >&2; exit 1;; esac
case "$MAX_UPLOAD_BYTES" in *[!0-9]*|'') echo 'Invalid upload byte limit' >&2; exit 1;; esac
[ "$HTTPS_PORT" -ge 1 ] && [ "$HTTPS_PORT" -le 65535 ]
[ "$MAX_UPLOAD_BYTES" -ge 1 ] && [ "$MAX_UPLOAD_BYTES" -le 104857600 ]
export REQUEST_BODY_BYTES=$((MAX_UPLOAD_BYTES + 1048576))
export HTTPS_AUTHORITY="$PORTAL_HOST"
if [ "$HTTPS_PORT" != 443 ]; then export HTTPS_AUTHORITY="$PORTAL_HOST:$HTTPS_PORT"; fi
envsubst '${PORTAL_HOST} ${HTTPS_AUTHORITY} ${REQUEST_BODY_BYTES}' < /etc/nginx/templates/portal.conf.template > /etc/nginx/conf.d/default.conf
exec nginx -g 'daemon off;'
