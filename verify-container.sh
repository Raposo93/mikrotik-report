#!/bin/sh

set -eu

image_name=${1:-mikrotik-report:test}

docker build --pull --tag "$image_name" .
docker run --rm "$image_name" --help >/dev/null

user_id=$(docker run --rm --entrypoint id "$image_name" -u)
if [ "$user_id" != "10001" ]; then
    echo "container runs as unexpected user ID: $user_id" >&2
    exit 1
fi

default_command=$(docker image inspect --format '{{join .Config.Cmd " "}}' "$image_name")
if [ "$default_command" != "run" ]; then
    echo "container has unexpected default command: $default_command" >&2
    exit 1
fi

stop_signal=$(docker image inspect --format '{{.Config.StopSignal}}' "$image_name")
if [ "$stop_signal" != "SIGTERM" ]; then
    echo "container has unexpected stop signal: $stop_signal" >&2
    exit 1
fi

docker run --rm --entrypoint python3 "$image_name" -c \
    'from pathlib import Path; path = Path("/var/lib/mikrotik-report/probe"); path.write_text("ok"); path.unlink()'
docker run --rm --entrypoint sh "$image_name" -c \
    'test ! -e /app/.env && test ! -d /app/tests'
