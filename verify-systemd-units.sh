#!/bin/sh

set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
verification_dir=$(mktemp -d "${TMPDIR:-/tmp}/mikrotik-report-systemd.XXXXXX")
trap 'rm -rf -- "$verification_dir"' EXIT HUP INT TERM

for unit in "$project_dir"/*.service.example "$project_dir"/*.timer.example; do
    filename=${unit##*/}
    cp -- "$unit" "$verification_dir/${filename%.example}"
done

systemd-analyze verify "$verification_dir"/*
