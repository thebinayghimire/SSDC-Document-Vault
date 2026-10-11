#!/bin/sh
set -eu
# Both processes run as the unprivileged clamav identity. No service writes config.
if [ ! -f /var/lib/clamav/main.cvd ]; then
    freshclam --foreground --stdout
fi
freshclam --daemon --foreground --stdout --checks=12 &
updater=$!
clamd --foreground &
scanner=$!
trap 'kill "$updater" "$scanner" 2>/dev/null || true; wait || true' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
while kill -0 "$updater" 2>/dev/null && kill -0 "$scanner" 2>/dev/null; do
    sleep 2
done
exit 1
