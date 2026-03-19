#!/usr/bin/env bash
set -euo pipefail

SESSION_NAME="${1:-ecox2vpn}"

if screen -list | grep -q "[.]${SESSION_NAME}[[:space:]]"; then
  screen -S "${SESSION_NAME}" -X quit
  echo "stopped screen session: ${SESSION_NAME}"
else
  echo "screen session '${SESSION_NAME}' not found"
fi

