#!/bin/bash
# Cleans up old ZAP session files, then brings the stack up.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSIONS_DIR="$SCRIPT_DIR/zap-sessions"
LOG="$HOME/zap-cleanup.log"

{
  echo "=== $(date) (start.sh) ==="
  if [ -d "$SESSIONS_DIR" ]; then
    # ponytail: same session-group logic as /etc/cron.daily/zap-cleanup —
    # protect whatever was touched most recently, delete the rest if >1 day old.
    newest=$(find "$SESSIONS_DIR" -mindepth 1 -maxdepth 1 -printf '%T@ %f\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
    protected="${newest%%.*}"
    echo "Protected (active) session base: ${protected:-none}"
    find "$SESSIONS_DIR" -mindepth 1 -maxdepth 1 -mtime +1 ! -name "${protected}*" -print -exec rm -rf {} +
  else
    echo "Sessions dir not found, skipping"
  fi
  echo
} >> "$LOG" 2>&1

cd "$SCRIPT_DIR"
docker compose up -d
