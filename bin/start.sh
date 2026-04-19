#!/usr/bin/env bash
# claude-whatsapp start.sh — arranca el plugin en foreground con bun
set -euo pipefail

export PATH="$HOME/.bun/bin:$PATH"

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../" && pwd)"
cd "$PLUGIN_DIR"

echo "[$(date -Iseconds)] [INFO] claude-whatsapp start.sh: plugin dir=$PLUGIN_DIR"
echo "[$(date -Iseconds)] [INFO] Installing dependencies..."
bun install --no-summary

echo "[$(date -Iseconds)] [INFO] Starting server..."
exec bun server.ts
