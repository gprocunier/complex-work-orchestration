#!/usr/bin/env bash
set -euo pipefail

SKILL_NAME="complex-work-orchestration"
PUBLIC_BEADS_COPR="greg-at-redhat/beads"
BEADS_COPR="${BEADS_COPR:-}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"

ASSUME_YES=0
DRY_RUN=0
UNINSTALL=0
CODEX_HOME_OVERRIDE="${CODEX_HOME:-}"
SKILLS_DIR_OVERRIDE="${CODEX_SKILLS_DIR:-}"
INSTALL_STAGE_DIR=""

say() {
  printf '%s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

valid_copr_ref() {
  case "$1" in
    (*[!A-Za-z0-9_.@/-]*|*//*|/*|*/|*/*/*|'')
      return 1
      ;;
    (*/*)
      return 0
      ;;
    (*)
      return 1
      ;;
  esac
}

print_copr_command() {
  local copr_ref="$1"

  if valid_copr_ref "$copr_ref"; then
    say "  sudo dnf copr enable '$copr_ref'"
  else
    say "Configured BEADS_COPR contains unsupported characters; not printing a copy-paste COPR command."
  fi
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
  --uninstall         Move the installed skill to a backup outside skills/ and leave no active install.
  -h, --help          Show this help.

Environment:
  CODEX_SKILLS_DIR    Preferred skills directory override.
  CODEX_HOME          Codex home directory; defaults to $HOME/.codex.
  BEADS_COPR          Optional COPR owner/project to show when bd is missing on RPM hosts.
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
      --uninstall)
        UNINSTALL=1
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

  cp -R -- "$SOURCE_DIR/$item" "$target_dir/$item"
}

cleanup_install_stage() {
  if [ -n "$INSTALL_STAGE_DIR" ] && [ -e "$INSTALL_STAGE_DIR" ]; then
    rm -rf -- "$INSTALL_STAGE_DIR"
  fi
}

backup_root_for_skills_dir() {
  local skills_dir="$1"
  local parent_dir

  parent_dir="$(cd -- "$(dirname -- "$skills_dir")" 2>/dev/null && pwd -P || dirname -- "$skills_dir")"
  printf '%s\n' "$parent_dir/skill-backups"
}

backup_path_for_skill() {
  local skills_dir="$1"
  local backup_root

  backup_root="$(backup_root_for_skills_dir "$skills_dir")"
  printf '%s/%s.prev.%s.%s\n' "$backup_root" "$SKILL_NAME" "$(date +%Y%m%d-%H%M%S)" "$$"
}

install_skill() {
  local skills_dir="$1"
  local target_dir="$skills_dir/$SKILL_NAME"
  local backup_root
  local prev_dir
  local backed_up=0
  local items="README.md LICENSE SKILL.md AGENTS.md VERSION CHANGELOG.md agents policy templates experts references schemas examples docs scripts"

  backup_root="$(backup_root_for_skills_dir "$skills_dir")"
  prev_dir="$(backup_path_for_skill "$skills_dir")"

  say ""
  say "Install plan:"
  say "  Source: $SOURCE_DIR"
  say "  Skills directory: $skills_dir"
  say "  Target: $target_dir"
  say "  Backup directory: $backup_root"

  if [ -d "$target_dir" ] && [ "$(cd -- "$target_dir" && pwd -P)" = "$SOURCE_DIR" ]; then
    say "Skill is already installed in place: $target_dir"
    return 0
  fi

  if [ -e "$target_dir" ]; then
    confirm "Target already exists and will be replaced. Continue?" || die "installation cancelled"
  else
    confirm "Proceed with installation?" || die "installation cancelled"
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    say "Dry run: no files will be copied."
    say "Would create staging install under: $skills_dir"
    if [ -e "$target_dir" ]; then
      say "Would move existing install to backup: $prev_dir"
    fi
    say "Would activate staged install at: $target_dir"
    for item in $items; do
      copy_item "$skills_dir/.${SKILL_NAME}.stage.XXXXXX" "$item"
    done
    say "Dry run complete. Skill would be installed at: $target_dir"
    return 0
  fi

  mkdir -p -- "$skills_dir"
  mkdir -p -- "$backup_root"
  INSTALL_STAGE_DIR="$(mktemp -d "${skills_dir}/.${SKILL_NAME}.stage.XXXXXX")"
  trap cleanup_install_stage EXIT

  for item in $items; do
    copy_item "$INSTALL_STAGE_DIR" "$item"
  done

  if [ -e "$target_dir" ]; then
    mv -- "$target_dir" "$prev_dir"
    backed_up=1
  fi

  if ! mv -- "$INSTALL_STAGE_DIR" "$target_dir"; then
    if [ "$backed_up" -eq 1 ] && [ ! -e "$target_dir" ]; then
      mv -- "$prev_dir" "$target_dir" || die "activation failed and rollback from $prev_dir failed"
    fi
    die "could not activate staged install at $target_dir"
  fi
  INSTALL_STAGE_DIR=""

  if [ "$backed_up" -eq 1 ]; then
    say "Previous install moved to backup: $prev_dir"
  fi
  say "Installed skill: $target_dir"
}

uninstall_skill() {
  local skills_dir="$1"
  local target_dir="$skills_dir/$SKILL_NAME"
  local backup_root
  local prev_dir

  backup_root="$(backup_root_for_skills_dir "$skills_dir")"
  prev_dir="$(backup_path_for_skill "$skills_dir")"

  say ""
  say "Uninstall plan:"
  say "  Target: $target_dir"
  say "  Backup: $prev_dir"

  if [ -d "$target_dir" ] && [ "$(cd -- "$target_dir" && pwd -P)" = "$SOURCE_DIR" ]; then
    die "refusing to uninstall the source checkout in place: $target_dir"
  fi

  if [ ! -e "$target_dir" ]; then
    say "Skill is not installed at: $target_dir"
    return 0
  fi

  confirm "Move installed skill to backup and leave no active install?" || die "uninstall cancelled"

  if [ "$DRY_RUN" -eq 1 ]; then
    say "Dry run: no files will be moved."
    say "Would remove existing backup if present: $prev_dir"
    say "Would move: $target_dir -> $prev_dir"
    return 0
  fi

  mkdir -p -- "$backup_root"
  mv -- "$target_dir" "$prev_dir"
  say "Uninstalled skill; backup kept at: $prev_dir"
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

check_installed_skill_drift() {
  local skills_dir="$1"
  local checker="$SOURCE_DIR/scripts/check_installed_skill.py"

  if [ ! -r "$checker" ]; then
    say "Installed-skill drift check skipped; checker was not found at: $checker"
    return 0
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    say "Installed-skill drift check skipped; python3 is not available."
    return 0
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    python3 "$checker" --skills-dir "$skills_dir"
  else
    python3 "$checker" --skills-dir "$skills_dir" --write-manifest --check
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
    if [ -n "$BEADS_COPR" ]; then
      say "To use your configured COPR:"
      print_copr_command "$BEADS_COPR"
    else
      say "If you need a public example COPR, verify it fits your environment first:"
      print_copr_command "$PUBLIC_BEADS_COPR"
    fi
    say "  sudo dnf install beads"
    say "Then verify:"
    say "  bd version"
  else
    say "This does not look like a Fedora/RPM host, so the COPR command may not apply."
    say "Use an upstream-supported Beads install channel, then verify bd:"
    say "  brew install beads"
    say "  curl -fsSL https://raw.githubusercontent.com/gastownhall/beads/main/scripts/install.sh | bash"
    say "  bd version"
    say "Upstream install guide: https://gastownhall.github.io/beads/"
    say "You can proceed without Beads, but CWO will be limited to reduced-durability Markdown handoff state."
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

  if [ "$UNINSTALL" -eq 1 ]; then
    uninstall_skill "$skills_dir"
    return 0
  fi

  install_skill "$skills_dir"
  validate_skill "$skills_dir"
  check_installed_skill_drift "$skills_dir"
  check_beads

  if [ "$DRY_RUN" -eq 1 ]; then
    say "Contractor brief would be: $skills_dir/$SKILL_NAME/references/contractor-brief.md"
    say "Routing policy would be: $skills_dir/$SKILL_NAME/policy/routing-policy.yaml"
  else
    say "Contractor brief: $skills_dir/$SKILL_NAME/references/contractor-brief.md"
    say "Routing policy: $skills_dir/$SKILL_NAME/policy/routing-policy.yaml"
  fi
}

main "$@"
