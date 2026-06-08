#!/usr/bin/env bash
set -euo pipefail

SKILL_NAME="complex-work-orchestration"
DEFAULT_BEADS_COPR="greg-at-redhat/beads"
BEADS_COPR="${BEADS_COPR:-$DEFAULT_BEADS_COPR}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"

ASSUME_YES=0
DRY_RUN=0
CODEX_HOME_OVERRIDE="${CODEX_HOME:-}"
SKILLS_DIR_OVERRIDE="${CODEX_SKILLS_DIR:-}"

say() {
  printf '%s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Install the complex-work-orchestration Codex skill.

Usage:
  ./scripts/install.sh [options]

Options:
  --skills-dir PATH   Install into this Codex skills directory.
  --codex-home PATH   Use PATH as CODEX_HOME and install into PATH/skills.
  -y, --yes           Accept detected/default paths without prompting.
  --dry-run           Print what would happen without copying files.
  -h, --help          Show this help.

Environment:
  CODEX_SKILLS_DIR    Preferred skills directory override.
  CODEX_HOME          Codex home directory; defaults to $HOME/.codex.
  BEADS_COPR          COPR owner/project to show when bd is missing on RPM hosts.
USAGE
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --skills-dir)
        [ "$#" -ge 2 ] || die "--skills-dir requires a path"
        SKILLS_DIR_OVERRIDE="$2"
        shift 2
        ;;
      --skills-dir=*)
        SKILLS_DIR_OVERRIDE="${1#*=}"
        shift
        ;;
      --codex-home)
        [ "$#" -ge 2 ] || die "--codex-home requires a path"
        CODEX_HOME_OVERRIDE="$2"
        shift 2
        ;;
      --codex-home=*)
        CODEX_HOME_OVERRIDE="${1#*=}"
        shift
        ;;
      -y|--yes)
        ASSUME_YES=1
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
        die "unknown argument: $1"
        ;;
    esac
  done
}

is_interactive() {
  [ "$ASSUME_YES" -eq 0 ] && [ -t 0 ] && [ -t 1 ]
}

detect_codex_home() {
  if [ -n "$CODEX_HOME_OVERRIDE" ]; then
    printf '%s\n' "$CODEX_HOME_OVERRIDE"
  elif [ -d "$HOME/.codex" ]; then
    printf '%s\n' "$HOME/.codex"
  else
    printf '%s\n' "$HOME/.codex"
  fi
}

detect_skills_dir() {
  local codex_home="$1"

  if [ -n "$SKILLS_DIR_OVERRIDE" ]; then
    printf '%s\n' "$SKILLS_DIR_OVERRIDE"
  elif [ -n "${CODEX_SKILLS_DIR:-}" ]; then
    printf '%s\n' "$CODEX_SKILLS_DIR"
  elif [ -d "$codex_home/skills" ]; then
    printf '%s\n' "$codex_home/skills"
  else
    printf '%s\n' "$codex_home/skills"
  fi
}

prompt_path() {
  local detected="$1"
  local reply

  if ! is_interactive; then
    printf '%s\n' "$detected"
    return 0
  fi

  printf '\n' >&2
  printf '%s\n' "Detected Codex skills directory:" >&2
  printf '  %s\n' "$detected" >&2
  printf 'Install there? Press Enter to accept, or type another skills directory: ' >&2
  read -r reply
  if [ -n "$reply" ]; then
    printf '%s\n' "$reply"
  else
    printf '%s\n' "$detected"
  fi
}

confirm() {
  local prompt="$1"
  local reply

  if ! is_interactive; then
    return 0
  fi

  printf '%s [Y/n]: ' "$prompt"
  read -r reply
  case "$reply" in
    ""|y|Y|yes|YES)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

copy_item() {
  local target_dir="$1"
  local item="$2"

  if [ ! -e "$SOURCE_DIR/$item" ]; then
    return 0
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    say "Would copy: $item -> $target_dir/$item"
    return 0
  fi

  rm -rf -- "${target_dir:?}/$item"
  cp -R -- "$SOURCE_DIR/$item" "$target_dir/$item"
}

install_skill() {
  local skills_dir="$1"
  local target_dir="$skills_dir/$SKILL_NAME"
  local items="README.md SKILL.md agents assets references scripts"

  say ""
  say "Install plan:"
  say "  Source: $SOURCE_DIR"
  say "  Skills directory: $skills_dir"
  say "  Target: $target_dir"

  if [ -d "$target_dir" ] && [ "$(cd -- "$target_dir" && pwd -P)" = "$SOURCE_DIR" ]; then
    say "Skill is already installed in place: $target_dir"
    return 0
  fi

  if [ -e "$target_dir" ]; then
    confirm "Target already exists and will be replaced. Continue?" || die "installation cancelled"
  else
    confirm "Proceed with installation?" || die "installation cancelled"
  fi

  if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p -- "$target_dir"
  else
    say "Dry run: no files will be copied."
  fi

  for item in $items; do
    copy_item "$target_dir" "$item"
  done

  if [ "$DRY_RUN" -eq 1 ]; then
    say "Dry run complete. Skill would be installed at: $target_dir"
  else
    say "Installed skill: $target_dir"
  fi
}

validate_skill() {
  local skills_dir="$1"
  local target_dir="$skills_dir/$SKILL_NAME"
  local codex_home
  local validator

  codex_home="$(cd -- "$skills_dir/.." 2>/dev/null && pwd -P || printf '%s\n' "${CODEX_HOME_OVERRIDE:-$HOME/.codex}")"
  validator="${SKILL_VALIDATOR:-$codex_home/skills/.system/skill-creator/scripts/quick_validate.py}"

  if [ "$DRY_RUN" -eq 1 ]; then
    say "Validation skipped during dry run."
    return 0
  fi

  if [ ! -r "$validator" ]; then
    say "Validation skipped; skill validator was not found at: $validator"
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 "$validator" "$target_dir"
  else
    say "Validation skipped; python3 is not available."
  fi
}

check_beads() {
  if command -v bd >/dev/null 2>&1; then
    say "Beads CLI found: $(command -v bd)"
    (bd version || bd --version || true) 2>/dev/null | sed 's/^/  /'
    return 0
  fi

  say "Beads CLI (bd) was not found."
  say "This is a warning, not an install failure; the skill can still run with Markdown handoff state."

  if is_rpm_host; then
    say "For Fedora or EPEL systems, install Beads from your configured package source."
    if [ "$BEADS_COPR" = "$DEFAULT_BEADS_COPR" ]; then
      say "If you do not have your own Beads package, you can use the public COPR:"
      say "  sudo dnf copr enable $BEADS_COPR"
    elif [ -n "$BEADS_COPR" ]; then
      say "To use your configured COPR:"
      say "  sudo dnf copr enable $BEADS_COPR"
    fi
    say "  sudo dnf install beads"
    say "Then verify:"
    say "  bd version"
  else
    say "This does not look like a Fedora/RPM host, so the COPR command may not apply."
    say "Install Beads by the method appropriate for this system, or proceed without Beads durability."
  fi
}

is_rpm_host() {
  if command -v dnf >/dev/null 2>&1 || command -v rpm >/dev/null 2>&1; then
    return 0
  fi

  if [ -r "$OS_RELEASE_FILE" ]; then
    case "$(sed -n 's/^ID_LIKE=//p; s/^ID=//p' "$OS_RELEASE_FILE" | tr -d '\"')" in
      *fedora*|*rhel*|*centos*|*rocky*|*alma*|*suse*)
        return 0
        ;;
    esac
  fi

  return 1
}

main() {
  local codex_home
  local detected_skills_dir
  local skills_dir

  parse_args "$@"

  codex_home="$(detect_codex_home)"
  detected_skills_dir="$(detect_skills_dir "$codex_home")"

  say "Autodetected Codex home: $codex_home"
  skills_dir="$(prompt_path "$detected_skills_dir")"

  install_skill "$skills_dir"
  validate_skill "$skills_dir"
  check_beads

  if [ "$DRY_RUN" -eq 1 ]; then
    say "Interaction brief would be: $skills_dir/$SKILL_NAME/assets/interaction.html"
  else
    say "Interaction brief: $skills_dir/$SKILL_NAME/assets/interaction.html"
  fi
}

main "$@"
