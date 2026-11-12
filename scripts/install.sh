#!/usr/bin/env bash
set -euo pipefail

SKILL_NAME="complex-work-orchestration"
PUBLIC_BEADS_COPR="greg-at-redhat/beads"
BEADS_COPR="${BEADS_COPR:-}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
CHECKER="$SOURCE_DIR/scripts/check_installed_skill.py"
PROJECTION="policy/install-projection.yaml"
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"

ASSUME_YES=0
DRY_RUN=0
UNINSTALL=0
CODEX_HOME_OVERRIDE="${CODEX_HOME:-}"
SKILLS_DIR_OVERRIDE="${CODEX_SKILLS_DIR:-}"
INSTALL_STAGE_DIR=""
ACTIVATION_TARGET=""
ACTIVATION_BACKUP=""

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

Interrupted installs:
  The files are copied into a staging directory in the skills directory and
  verified before anything active changes. The existing install is then moved
  to the backup directory and the staged copy is moved into place. If the
  installer fails or receives INT, TERM or HUP between those two moves, it
  moves the previous install back before exiting. If it is killed without a
  chance to run (SIGKILL, power loss) in that window, no install is active:
  the previous install is intact in the backup directory, and the verified
  staged copy is left as .complex-work-orchestration.stage.* in the skills
  directory. To recover, rerun the installer (it reports the leftover staging
  directory) or move the backup back to the target, then delete the leftover
  staging directory once no other install is running.
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

require_python() {
  command -v python3 >/dev/null 2>&1 || die "python3 is required to read the installed projection ($PROJECTION)"
}

# The installed projection is policy/install-projection.yaml; the checker validates the source
# against it and lists what to install, so the installer and the drift check copy and hash the
# same files. A missing required entry, a symbolic link or a special file is an error.
projection_list() {
  python3 -B "$CHECKER" --source-dir "$SOURCE_DIR" "$1"
}

copy_projection() {
  local stage_dir="$1"
  local directories="$2"
  local files="$3"
  local relative

  # Declared directories are created on their own, so a required directory with no files is
  # still installed (and the checker verifies its presence).
  while IFS= read -r relative; do
    [ -n "$relative" ] || continue
    mkdir -p -- "$stage_dir/$relative"
  done <<EOF_DIRECTORIES
$directories
EOF_DIRECTORIES

  while IFS= read -r relative; do
    [ -n "$relative" ] || continue
    case "$relative" in
      (*/*) mkdir -p -- "$stage_dir/${relative%/*}" ;;
    esac
    cp -- "$SOURCE_DIR/$relative" "$stage_dir/$relative"
  done <<EOF_FILES
$files
EOF_FILES
}

cleanup_install_stage() {
  if [ -n "$INSTALL_STAGE_DIR" ] && [ -e "$INSTALL_STAGE_DIR" ]; then
    rm -rf -- "$INSTALL_STAGE_DIR"
  fi
}

# Between moving the previous install to its backup and activating the stage, no install is
# active. Any exit in that window (an error, or INT, TERM or HUP through the traps below) moves
# the previous install back. SIGKILL cannot be trapped; see "Interrupted installs" in usage.
restore_previous_install() {
  if [ -n "$ACTIVATION_BACKUP" ] && [ -e "$ACTIVATION_BACKUP" ] && [ ! -e "$ACTIVATION_TARGET" ]; then
    if ! mv -- "$ACTIVATION_BACKUP" "$ACTIVATION_TARGET"; then
      printf 'error: could not restore the previous install; it is kept at %s\n' "$ACTIVATION_BACKUP" >&2
      ACTIVATION_BACKUP=""
      return 1
    fi
    printf 'Restored the previous install at %s\n' "$ACTIVATION_TARGET" >&2
  fi
  ACTIVATION_BACKUP=""
  return 0
}

on_install_exit() {
  restore_previous_install || true
  cleanup_install_stage
}

warn_leftover_stages() {
  local skills_dir="$1"
  local stale

  for stale in "$skills_dir/.$SKILL_NAME.stage."*; do
    [ -d "$stale" ] || continue
    say "  Warning: staging directory left by an interrupted install (not active; delete it once no other install is running): $stale"
  done
}

backup_root_for_skills_dir() {
  local skills_dir="$1"
  local parent_dir

  if ! parent_dir="$(cd -- "$(dirname -- "$skills_dir")" 2>/dev/null && pwd -P)"; then
    parent_dir="$(dirname -- "$skills_dir")"
  fi
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
  local entries
  local directories
  local files
  local entry

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

  entries="$(projection_list --list-entries)" || die "source does not satisfy the installed projection ($PROJECTION); nothing was installed"
  directories="$(projection_list --list-directories)" || die "source does not satisfy the installed projection ($PROJECTION); nothing was installed"
  files="$(projection_list --list-files)" || die "source does not satisfy the installed projection ($PROJECTION); nothing was installed"
  say "  Projection: $SOURCE_DIR/$PROJECTION ($(printf '%s\n' "$files" | grep -c .) files)"
  warn_leftover_stages "$skills_dir"

  if [ -e "$target_dir" ]; then
    confirm "Target already exists and will be replaced. Continue?" || die "installation cancelled"
  else
    confirm "Proceed with installation?" || die "installation cancelled"
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    say "Dry run: no files will be copied."
    say "Would create staging install under: $skills_dir"
    say "Would verify the staged install against the projection before activating it"
    if [ -e "$target_dir" ]; then
      say "Would move existing install to backup: $prev_dir"
    fi
    say "Would activate staged install at: $target_dir"
    while IFS= read -r entry; do
      say "Would copy: $entry -> $skills_dir/.${SKILL_NAME}.stage.XXXXXX/$entry"
    done <<EOF_ENTRIES
$entries
EOF_ENTRIES
    say "Dry run complete. Skill would be installed at: $target_dir"
    return 0
  fi

  mkdir -p -- "$skills_dir"
  mkdir -p -- "$backup_root"
  INSTALL_STAGE_DIR="$(mktemp -d "${skills_dir}/.${SKILL_NAME}.stage.XXXXXX")"
  trap on_install_exit EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  copy_projection "$INSTALL_STAGE_DIR" "$directories" "$files"

  # Verify and record the staged copy before activation, so the active install is only ever
  # replaced by a tree that matches the projection, and its install record lands with it.
  say "Verifying staged install against the installed projection:"
  if ! python3 -B "$CHECKER" --source-dir "$SOURCE_DIR" --installed-dir "$INSTALL_STAGE_DIR" --write-manifest --check; then
    die "staged install does not match the installed projection; nothing was activated"
  fi

  if [ -e "$target_dir" ]; then
    ACTIVATION_TARGET="$target_dir"
    ACTIVATION_BACKUP="$prev_dir"
    mv -- "$target_dir" "$prev_dir"
    backed_up=1
  fi

  if ! mv -- "$INSTALL_STAGE_DIR" "$target_dir"; then
    restore_previous_install || die "activation failed and rollback from $prev_dir failed"
    die "could not activate staged install at $target_dir"
  fi
  ACTIVATION_BACKUP=""
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

  if [ "$DRY_RUN" -eq 1 ]; then
    python3 -B "$CHECKER" --source-dir "$SOURCE_DIR" --skills-dir "$skills_dir"
  else
    python3 -B "$CHECKER" --source-dir "$SOURCE_DIR" --skills-dir "$skills_dir" --check
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

  require_python
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
