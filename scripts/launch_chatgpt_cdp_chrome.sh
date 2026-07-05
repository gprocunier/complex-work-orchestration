#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Launch a ChatGPT browser profile for CWO ChatGPT Pro master review.

This helper starts Chrome through systemd --user on Wayland with a localhost
Chrome DevTools Protocol port. It avoids exec-owned visible Chrome processes
that are reaped when the launcher exits.

Usage:
  scripts/launch_chatgpt_cdp_chrome.sh [options]

Options:
  --unit NAME           systemd unit name (default: cwo-chatgpt-chrome)
  --profile PATH        Chrome user-data-dir (default: ~/.local/share/cwo/chatgpt-master-reviewer-profile)
  --port PORT           localhost CDP port (default: 9222)
  --chrome PATH         Chrome binary (default: auto-detect google-chrome-stable/google-chrome/chromium)
  --url URL             page to open (default: https://chatgpt.com/)
  --config PATH         browser config path (default: ~/.config/cwo/chatgpt-browser.json)
  --write-config        write a safe localhost-CDP config for chatgpt_browser_review.py
  --replace             stop the named unit before launching it
  --stop                stop the named unit and exit
  --status              print unit and CDP port status and exit
  --dry-run             print the systemd-run command without launching
  -h, --help            show this help

Typical flow:
  scripts/launch_chatgpt_cdp_chrome.sh --write-config
  python3 scripts/chatgpt_browser_review.py --packet master-plan-review-packet.json --confirm-only --json
  python3 scripts/chatgpt_browser_review.py --packet master-plan-review-packet.json --json
EOF
}

quote_cmd() {
  printf '%q ' "$@"
  printf '\n'
}

detect_chrome() {
  if [[ -n "${CWO_CHROME_BIN:-}" ]]; then
    printf '%s\n' "$CWO_CHROME_BIN"
    return
  fi
  for candidate in google-chrome-stable google-chrome chromium chromium-browser; do
    if command -v "$candidate" >/dev/null 2>&1; then
      command -v "$candidate"
      return
    fi
  done
  printf 'ERROR: could not find Chrome; set --chrome or CWO_CHROME_BIN\n' >&2
  exit 1
}

runtime_dir() {
  if [[ -n "${XDG_RUNTIME_DIR:-}" ]]; then
    printf '%s\n' "$XDG_RUNTIME_DIR"
  else
    printf '/run/user/%s\n' "$(id -u)"
  fi
}

discover_xauthority() {
  if [[ -n "${XAUTHORITY:-}" ]]; then
    printf '%s\n' "$XAUTHORITY"
    return
  fi
  local dir
  dir="$(runtime_dir)"
  local match
  match="$(find "$dir" -maxdepth 1 -type f -name 'xauth_*' -print -quit 2>/dev/null || true)"
  if [[ -n "$match" ]]; then
    printf '%s\n' "$match"
  fi
}

status() {
  local unit="$1"
  local port="$2"
  systemctl --user --no-pager --full status "${unit}.service" || true
  ss -ltnp "sport = :${port}" || true
}

write_config() {
  local config_path="$1"
  local port="$2"
  local dir
  dir="$(dirname "$config_path")"
  mkdir -p "$dir"
  local tmp
  tmp="$(mktemp "${dir}/chatgpt-browser.XXXXXX")"
  cat >"$tmp" <<EOF
{
  "connect_over_cdp_url": "http://127.0.0.1:${port}",
  "model_label": "ChatGPT Pro 5.5",
  "reasoning_label": "Extended Reasoning",
  "require_model_confirmation": true,
  "max_prompt_chars": 50000,
  "local_clipboard_fallback": true,
  "selectors": {
    "model_label_confirmation_selector": "[data-testid='composer-intelligence-picker-content']",
    "reasoning_label_confirmation_selector": "[data-testid='composer-intelligence-picker-content']"
  }
}
EOF
  chmod 600 "$tmp"
  mv "$tmp" "$config_path"
  chmod 600 "$config_path"
  printf 'Wrote %s\n' "$config_path"
}

UNIT="${CWO_CHATGPT_CHROME_UNIT:-cwo-chatgpt-chrome}"
PROFILE="${CWO_CHATGPT_CHROME_PROFILE:-$HOME/.local/share/cwo/chatgpt-master-reviewer-profile}"
PORT="${CWO_CHATGPT_CDP_PORT:-9222}"
CHROME=""
URL="${CWO_CHATGPT_URL:-https://chatgpt.com/}"
CONFIG_PATH="${CWO_CHATGPT_BROWSER_CONFIG:-$HOME/.config/cwo/chatgpt-browser.json}"
WRITE_CONFIG=0
REPLACE=0
STOP=0
STATUS=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --unit)
      UNIT="$2"
      shift 2
      ;;
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
    --chrome)
      CHROME="$2"
      shift 2
      ;;
    --url)
      URL="$2"
      shift 2
      ;;
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --write-config)
      WRITE_CONFIG=1
      shift
      ;;
    --replace)
      REPLACE=1
      shift
      ;;
    --stop)
      STOP=1
      shift
      ;;
    --status)
      STATUS=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'ERROR: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

PROFILE="$(realpath -m "$PROFILE")"
CONFIG_PATH="$(realpath -m "$CONFIG_PATH")"

if [[ "$STOP" -eq 1 ]]; then
  systemctl --user stop "${UNIT}.service" || true
  exit 0
fi

if [[ "$STATUS" -eq 1 ]]; then
  status "$UNIT" "$PORT"
  exit 0
fi

if ! command -v systemd-run >/dev/null 2>&1; then
  printf 'ERROR: systemd-run is required for this launcher\n' >&2
  exit 1
fi

if [[ -z "$CHROME" ]]; then
  CHROME="$(detect_chrome)"
fi

if [[ "$WRITE_CONFIG" -eq 1 ]]; then
  write_config "$CONFIG_PATH" "$PORT"
fi

if [[ "$REPLACE" -eq 1 ]]; then
  systemctl --user stop "${UNIT}.service" || true
fi

if systemctl --user --quiet is-active "${UNIT}.service"; then
  printf 'ERROR: %s.service is already active. Use --status, --stop, or --replace.\n' "$UNIT" >&2
  exit 1
fi

if ss -ltn "sport = :${PORT}" | awk 'NR > 1 {found=1} END {exit found ? 0 : 1}'; then
  printf 'ERROR: localhost port %s is already listening. Pick --port or stop the existing owner.\n' "$PORT" >&2
  exit 1
fi

mkdir -p "$PROFILE"

RUNTIME_DIR="$(runtime_dir)"
DISPLAY_VALUE="${DISPLAY:-:0}"
WAYLAND_DISPLAY_VALUE="${WAYLAND_DISPLAY:-wayland-0}"
DBUS_VALUE="${DBUS_SESSION_BUS_ADDRESS:-unix:path=${RUNTIME_DIR}/bus}"
XAUTHORITY_VALUE="$(discover_xauthority || true)"

env_args=(
  "--setenv=DISPLAY=${DISPLAY_VALUE}"
  "--setenv=WAYLAND_DISPLAY=${WAYLAND_DISPLAY_VALUE}"
  "--setenv=XDG_RUNTIME_DIR=${RUNTIME_DIR}"
  "--setenv=DBUS_SESSION_BUS_ADDRESS=${DBUS_VALUE}"
  "--setenv=XDG_SESSION_TYPE=wayland"
)
if [[ -n "$XAUTHORITY_VALUE" ]]; then
  env_args+=("--setenv=XAUTHORITY=${XAUTHORITY_VALUE}")
fi

cmd=(
  systemd-run
  --user
  "--unit=${UNIT}"
  "--description=CWO ChatGPT Pro CDP Chrome"
  --collect
  "${env_args[@]}"
  "$CHROME"
  --remote-debugging-address=127.0.0.1
  "--remote-debugging-port=${PORT}"
  "--user-data-dir=${PROFILE}"
  --no-first-run
  --ozone-platform=wayland
  --enable-features=UseOzonePlatform
  --disable-features=Vulkan
  --disable-vulkan
  --new-window
  "$URL"
)

if [[ "$DRY_RUN" -eq 1 ]]; then
  quote_cmd "${cmd[@]}"
  printf 'Config path: %s\n' "$CONFIG_PATH"
  exit 0
fi

"${cmd[@]}"
printf 'Launched %s.service with CDP at http://127.0.0.1:%s\n' "$UNIT" "$PORT"
printf 'Use CWO_CHATGPT_BROWSER_CONFIG=%s for chatgpt_browser_review.py\n' "$CONFIG_PATH"
