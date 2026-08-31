#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
api_pid=""

cleanup() {
  if [[ -n "$api_pid" ]]; then
    kill "$api_pid" 2>/dev/null || true
    wait "$api_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

if [[ ! -d "$project_dir/dashboard/node_modules" ]]; then
  npm --prefix "$project_dir/dashboard" install
fi

cd "$project_dir"
uv run h1dr4-attackgraph-dashboard &
api_pid=$!
npm --prefix "$project_dir/dashboard" run dev
