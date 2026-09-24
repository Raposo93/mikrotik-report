#!/bin/sh

set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

MIKROTIK_REPORT_ENV_FILE="$project_dir/.env.example" \
    docker compose --project-directory "$project_dir" \
        --file "$project_dir/compose.example.yaml" config --quiet
