#!/bin/sh
set -eu
test "$(printf 'PING\n' | nc -w 2 127.0.0.1 3310)" = PONG
