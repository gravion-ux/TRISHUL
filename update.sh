#!/usr/bin/env bash
#
# TRISHUL updater — controlled and non-destructive.
#
# Why this script backs up first: an update must never leave a host without a
# working configuration. The backup intentionally contains configuration only:
# data/ (the SQLite database and the generated admin credentials) and .env files
# are excluded, so no secret is ever copied into a backup.
#
# Tool upgrades are opt-in (--tools) because rebuilding httpx, nuclei and ffuf
# takes time and changes the exact binary version used for evidence.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
BACKUP_ROOT="${ROOT_DIR}/backups"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="${BACKUP_ROOT}/${STAMP}"
GOPATH_DIR="${HOME}/go"
GO_BIN_DIR="${GOPATH_DIR}/bin"

WITH_TOOLS=0
WITH_FRONTEND=1

usage() {
  cat <<'EOF'
TRISHUL updater — refreshes an existing installation without destroying state.

Usage:
  ./update.sh [options]

Options:
  --tools                Also rebuild the Go tools (httpx, nuclei, ffuf) from
                         source at the latest version. Off by default because
                         tool upgrades change the binaries used for evidence.
  --no-frontend          Skip the frontend dependency install and dashboard
                         build.
  -h, --help             Show this help text and exit.

Steps, in order:
  1. Back up config/ to backups/<UTC timestamp>/ (no secrets: data/ and .env
     files are excluded).
  2. Upgrade pip and requirements.txt inside .venv.
  3. Optionally rebuild the Go tools (--tools).
  4. Refresh the nuclei templates.
  5. Rebuild the frontend (unless --no-frontend).
  6. Run the migration step (migrations are also applied automatically when
     the API starts).
  7. Run the health check and print a ready/missing summary.

If any step fails the script stops and prints rollback instructions.
EOF
}

log() { printf '[*] %s\n' "$*"; }
ok() { printf '[ok] %s\n' "$*"; }
warn() { printf '[!!] %s\n' "$*" >&2; }

# rollback_note explains how to get back to the pre-update state. It is printed
# for every failure, because an interrupted update must always leave the user
# with a documented way back.
rollback_note() {
  printf '\n'
  warn "The update did not complete."
  warn "Rollback: restore the configuration backup with:"
  warn "  cp -a '${BACKUP_DIR}/config' '${ROOT_DIR}/config'"
  warn "Python dependencies were not downgraded automatically; re-run './install.sh' to rebuild .venv."
  warn "Scan data in data/ was not modified by this script."
}

die() {
  printf '[xx] %s\n' "$*" >&2
  rollback_note
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tools)
      WITH_TOOLS=1
      shift
      ;;
    --no-frontend)
      WITH_FRONTEND=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '[xx] Unknown option: %s\n\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

on_error() {
  local exit_code=$?
  local line="$1"
  rollback_note
  warn "Failed with exit code ${exit_code} (line ${line})."
  exit "${exit_code}"
}
trap 'on_error ${LINENO}' ERR

backup_config() {
  log "Backing up the configuration to ${BACKUP_DIR}"
  mkdir -p "${BACKUP_DIR}"
  if [[ -d "${ROOT_DIR}/config" ]]; then
    cp -a "${ROOT_DIR}/config" "${BACKUP_DIR}/config"
    ok "Configuration backed up (data/ and .env files are excluded by design)."
  else
    warn "No config/ directory found — there is nothing to back up."
  fi
}

upgrade_python() {
  if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    die "No virtual environment at ${VENV_DIR}. Run ./install.sh first."
  fi

  # shellcheck source=/dev/null
  source "${VENV_DIR}/bin/activate"

  log "Upgrading pip..."
  python -m pip install --upgrade pip

  if [[ -f "${ROOT_DIR}/requirements.txt" ]]; then
    log "Upgrading the Python dependencies..."
    python -m pip install --upgrade -r "${ROOT_DIR}/requirements.txt"
  else
    warn "requirements.txt was not found — the Python dependencies were not upgraded."
  fi
}

update_go_tools() {
  if [[ "${WITH_TOOLS}" -eq 0 ]]; then
    log "Skipping the Go tool update (pass --tools to enable it)."
    return 0
  fi
  if ! command -v go >/dev/null 2>&1; then
    warn "The Go toolchain is missing — the tools were not updated. Install golang and re-run with --tools."
    return 0
  fi

  export GOPATH="${GOPATH_DIR}"
  export PATH="${GO_BIN_DIR}:${PATH}"
  mkdir -p "${GO_BIN_DIR}"

  local package
  for package in \
    "github.com/projectdiscovery/httpx/cmd/httpx" \
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei" \
    "github.com/ffuf/ffuf/v2"; do
    log "Rebuilding ${package}..."
    # A tool build failure must not leave the update half-applied: the error
    # trap handles it and the backup is still intact.
    go install "${package}@latest"
  done
  ok "Go tools updated"
}

refresh_nuclei_templates() {
  if ! command -v nuclei >/dev/null 2>&1; then
    warn "nuclei is not installed — the templates were not refreshed."
    return 0
  fi
  log "Refreshing the nuclei templates..."
  nuclei -ut
  ok "Nuclei templates refreshed"
}

rebuild_frontend() {
  if [[ "${WITH_FRONTEND}" -eq 0 ]]; then
    log "Skipping the frontend rebuild (--no-frontend)."
    return 0
  fi
  if [[ ! -d "${ROOT_DIR}/frontend" ]]; then
    warn "frontend/ was not found — the dashboard rebuild was skipped."
    return 0
  fi
  if ! command -v npm >/dev/null 2>&1; then
    warn "npm was not found — the dashboard rebuild was skipped. The API and CLI are unaffected."
    return 0
  fi

  log "Installing the frontend dependencies..."
  (cd "${ROOT_DIR}/frontend" && npm install)
  log "Rebuilding the dashboard..."
  (cd "${ROOT_DIR}/frontend" && npm run build)
  ok "Dashboard rebuilt"
}

run_migrations() {
  log "Applying database migrations..."
  if [[ ! -d "${ROOT_DIR}/migrations" ]]; then
    warn "No migrations/ directory was found — nothing to apply."
    return 0
  fi

  # The migration entry point is resolved at runtime so the updater keeps
  # working if the backend moves it. Migrations are also applied automatically
  # when the API starts, so a missing entry point is a warning, not a failure.
  local candidate
  for candidate in "backend.app.core.migrations" "backend.app.migrations"; do
    if python -c "import importlib; importlib.import_module('${candidate}')" >/dev/null 2>&1; then
      if python -m "${candidate}"; then
        ok "Migrations applied via ${candidate}"
        return 0
      fi
      warn "The migration entry point '${candidate}' failed — migrations will be applied automatically when the API starts."
      return 0
    fi
  done

  warn "No migration entry point was found — migrations are applied automatically when the API starts."
}

health_check() {
  local -a ready=()
  local -a missing=()
  local -a required_tools=(httpx nuclei ffuf nmap)
  local tool

  log "Running the health check..."

  for tool in "${required_tools[@]}"; do
    if command -v "${tool}" >/dev/null 2>&1; then
      ready+=("tool ${tool} ($(command -v "${tool}"))")
    else
      missing+=("tool ${tool} is not installed")
    fi
  done

  if [[ -x "${VENV_DIR}/bin/python" ]]; then
    ready+=("python environment (${VENV_DIR})")
  else
    missing+=("python environment (${VENV_DIR})")
  fi

  if [[ -d "${ROOT_DIR}/data" ]]; then
    ready+=("data/")
  else
    missing+=("data/")
  fi

  if [[ "${WITH_FRONTEND}" -eq 0 ]]; then
    log "Frontend: skipped by request (--no-frontend)"
  elif [[ -d "${ROOT_DIR}/frontend/dist" ]]; then
    ready+=("dashboard bundle (frontend/dist)")
  else
    missing+=("dashboard bundle (frontend/dist)")
  fi

  if command -v curl >/dev/null 2>&1; then
    if curl -fsS --max-time 3 http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
      ready+=("API is answering on http://127.0.0.1:8000/api/health")
    else
      log "The API is not running yet. Start it with: python -m backend.app.main"
    fi
  fi

  # The application's own health report is the authoritative check: it knows
  # about the tool versions, the edition and the AI reachability.
  if [[ -x "${VENV_DIR}/bin/python" && -f "${ROOT_DIR}/cli/trishul.py" ]]; then
    log "Running the TRISHUL self-check (trishul --health)..."
    if "${VENV_DIR}/bin/python" "${ROOT_DIR}/cli/trishul.py" --health; then
      ready+=("trishul --health reports the installation as ready")
    else
      warn "trishul --health reports that the installation is not ready — see the report above."
    fi
  fi

  printf '\n'
  printf 'TRISHUL update summary\n'
  printf -- '------------------------\n'
  printf 'Ready:\n'
  if [[ ${#ready[@]} -eq 0 ]]; then
    printf '  (nothing yet)\n'
  else
    local item
    for item in "${ready[@]}"; do
      printf '  + %s\n' "${item}"
    done
  fi
  printf 'Missing / optional:\n'
  if [[ ${#missing[@]} -eq 0 ]]; then
    printf '  (nothing)\n'
  else
    local item
    for item in "${missing[@]}"; do
      printf '  - %s\n' "${item}"
    done
  fi
  printf '\nConfiguration backup: %s\n' "${BACKUP_DIR}"
}

main() {
  log "Updating TRISHUL in ${ROOT_DIR}"
  backup_config
  upgrade_python
  update_go_tools
  refresh_nuclei_templates
  rebuild_frontend
  run_migrations
  health_check
  ok "TRISHUL update finished. The previous configuration is kept in ${BACKUP_DIR}."
}

main "$@"
