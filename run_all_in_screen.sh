#!/usr/bin/env bash
set -euo pipefail

SESSION_NAME="${1:-ecox2vpn}"
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

if ! command -v screen >/dev/null 2>&1; then
  echo "screen is not installed"
  exit 1
fi

if screen -list | grep -q "[.]${SESSION_NAME}[[:space:]]"; then
  echo "screen session '${SESSION_NAME}' already exists"
  echo "attach: screen -r ${SESSION_NAME}"
  exit 0
fi

CMD="cd '${ROOT_DIR}' && source venv/bin/activate && \
python bot/webapp.py >/tmp/ecox2vpn-webapp.log 2>&1 & \
python bot/bot.py >/tmp/ecox2vpn-bot.log 2>&1 & \
wait"

screen -dmS "${SESSION_NAME}" bash -lc "${CMD}"

echo "started in one screen session: ${SESSION_NAME}"
echo "attach: screen -r ${SESSION_NAME}"
echo "logs:"
echo "  tail -f /tmp/ecox2vpn-webapp.log"
echo "  tail -f /tmp/ecox2vpn-bot.log"

