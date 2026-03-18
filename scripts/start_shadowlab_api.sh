#!/usr/bin/env sh
set -eu

export SHADOWLAB_HOST="${SHADOWLAB_HOST:-0.0.0.0}"
export SHADOWLAB_PORT="${SHADOWLAB_PORT:-8000}"

python app.py
