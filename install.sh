#!/usr/bin/env bash
#
# TRISHUL installer for Kali Linux, Debian and Ubuntu.
#
# Why this script is written the way it is:
#   * TRISHUL drives four real external binaries (httpx, nuclei, ffuf, nmap) that
#     are not bundled with the source tree, so the installer provisions the tool
#     chain as well as the Python environment and the dashboard.
#   * Network failures are common on locked-down hosts. Every optional step is
#     therefore non-fatal: the installer warns, keeps going, and the health
#     check at the end reports exactly what is ready and what is missing.
#   * Re-running the installer must be safe, so each step inspects existing state
#     before it changes anything.
#
# The script never hardcodes credentials and never clones a GitHub repository as
# a runtime data source.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
BIN_DIR="${HOME}/.local/bin"
LAUNCHER_PATH="${BIN_DIR}/trishul"
GOPATH_DIR="${HOME}/go"
GO_BIN_DIR="${GOPATH_DIR}/bin"
DEFAULT_OLLAMA_MODEL="llama3.1:8b"

WITH_LOCAL=0
WITH_FRONTEND=1
OLLAMA_MODEL=""
OLLAMA_MODEL_REQUESTED=0

usage() {
  cat <<'EOF'
TRISHUL installer — prepares TRISHUL on Kali Linux, Debian or Ubuntu.

Usage:
  ./install.sh [options]

Options:
  --local                Prepare TRISHUL LOCAL. When Ollama is installed and
                         running, this additionally offers to pull an Ollama
                         model so the AI works offline straight away.
  --ollama-model MODEL   Model to pull for --local (default: llama3.1:8b).
                         Providing this value also implies --local and pulls
                         the model without an interactive prompt.
  --no-frontend          Skip the frontend dependency install and dashboard
                         build. Use this on hosts that only run the API/CLI.
  -h, --help             Show this help text and exit.

What the installer does:
  1. Installs system packages (python3, python3-venv, python3-pip, git, curl,
     wget, nmap, golang, nodejs, npm) with apt, and ffuf when apt has it.
  2. Builds httpx, nuclei and ffuf from source with Go.
  3. Creates .venv, upgrades pip and installs requirements.txt.
  4. Installs the ~/.local/bin/trishul launcher.
  5. Creates data/, reports/ and plugins/.
  6. Downloads the nuclei templates.
  7. Installs and builds the frontend (unless --no-frontend).
  8. Runs a health check and prints a ready/missing summary.

The installer is idempotent: running it again on a configured host refreshes
only what is missing or stale.
EOF
}

log() { printf '[*] %s\n' "$*"; }
ok() { printf '[ok] %s\n' "$*"; }
warn() { printf '[!!] %s\n' "$*" >&2; }
die() { printf '[xx] %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local)
      WITH_LOCAL=1
      shift
      ;;
    --ollama-model)
      if [[ $# -lt 2 ]]; then
        die "--ollama-model requires a model name (for example: --ollama-model llama3.1:8b)"
      fi
      OLLAMA_MODEL="$2"
      OLLAMA_MODEL_REQUESTED=1
      WITH_LOCAL=1
      shift 2
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

# run_root runs a command as root. Using a function keeps the sudo invocation
# correctly quoted for shellcheck and avoids assuming the host has sudo.
run_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    return 1
  fi
}

install_system_packages() {
  local packages=(python3 python3-venv python3-pip git curl wget nmap golang nodejs npm)

  if ! command -v apt-get >/dev/null 2>&1; then
    warn "apt-get was not found. Install these packages manually: ${packages[*]}"
    return 0
  fi

  log "Refreshing apt package lists..."
  if ! run_root apt-get update; then
    warn "apt-get update failed (network or repository problem). Continuing."
  fi

  log "Installing system packages: ${packages[*]}"
  if ! run_root apt-get install -y "${packages[@]}"; then
    warn "apt-get install failed for one or more packages. Continuing; check the health summary at the end."
  fi
}

install_ffuf_from_apt() {
  if command -v ffuf >/dev/null 2>&1; then
    ok "ffuf is already installed"
    return 0
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    return 0
  fi
  log "Installing ffuf from apt..."
  if run_root apt-get install -y ffuf; then
    ok "ffuf installed from apt"
  else
    warn "ffuf is not available in apt on this host — it will be built from source with Go instead."
  fi
}

install_go_tool() {
  local package="$1"
  local label="$2"
  local status=0

  if ! command -v go >/dev/null 2>&1; then
    warn "The Go toolchain is missing — cannot install ${label}. Install golang and re-run this script."
    return 0
  fi

  log "Building ${label} from source (${package})..."
  # A failed build must never abort the install: the health check reports it.
  go install "${package}@latest" || status=$?
  if [[ "${status}" -ne 0 ]]; then
    warn "${label} was not installed (network or build failure). Fix it later with: go install ${package}@latest"
    return 0
  fi
  ok "${label} installed"
}

setup_go_environment() {
  export GOPATH="${GOPATH_DIR}"
  export PATH="${GO_BIN_DIR}:${PATH}"
  mkdir -p "${GO_BIN_DIR}"

  # Persist the Go bin directory for interactive shells, exactly once, so the
  # tools stay callable after the installer exits.
  local rc_file="${HOME}/.bashrc"
  if [[ -f "${rc_file}" ]] && grep -qF 'HOME/go/bin' "${rc_file}"; then
    return 0
  fi
  {
    printf '\n# Added by the TRISHUL installer: Go tool binaries (httpx, nuclei, ffuf).\n'
    printf 'export PATH="$HOME/go/bin:$PATH"\n'
  } >> "${rc_file}"
}

setup_python_environment() {
  if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 was not found. The virtual environment and the CLI cannot be set up."
    return 0
  fi

  if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    log "Creating the virtual environment at ${VENV_DIR}..."
    if ! python3 -m venv "${VENV_DIR}"; then
      warn "python3 -m venv failed. Install python3-venv and re-run this script."
      return 0
    fi
  else
    log "Reusing the existing virtual environment at ${VENV_DIR}"
  fi

  # shellcheck source=/dev/null
  source "${VENV_DIR}/bin/activate"

  log "Upgrading pip..."
  python -m pip install --upgrade pip || warn "pip could not be upgraded; continuing with the bundled version."

  if [[ -f "${ROOT_DIR}/requirements.txt" ]]; then
    log "Installing Python dependencies..."
    if ! python -m pip install -r "${ROOT_DIR}/requirements.txt"; then
      warn "Installing requirements.txt failed. Re-run this script once the network is reachable."
    fi
  else
    warn "requirements.txt was not found at ${ROOT_DIR}/requirements.txt — Python dependencies were not installed."
  fi
}

install_launcher() {
  mkdir -p "${BIN_DIR}"
  cat > "${LAUNCHER_PATH}" <<EOF
#!/usr/bin/env bash
# TRISHUL launcher — activates the project virtualenv and runs the CLI.
set -euo pipefail
TRISHUL_ROOT="${ROOT_DIR}"
export GOPATH="\${HOME}/go"
export PATH="\${GOPATH}/bin:\${PATH}"
if [[ -d "\${TRISHUL_ROOT}/.venv" ]]; then
  # shellcheck source=/dev/null
  source "\${TRISHUL_ROOT}/.venv/bin/activate"
fi
cd "\${TRISHUL_ROOT}"
exec python "\${TRISHUL_ROOT}/cli/trishul.py" "\$@"
EOF
  chmod +x "${LAUNCHER_PATH}"
  ok "Installed the launcher at ${LAUNCHER_PATH}"
}

create_directories() {
  mkdir -p "${ROOT_DIR}/data" "${ROOT_DIR}/reports" "${ROOT_DIR}/plugins"
  ok "Created data/, reports/ and plugins/"
}

prime_nuclei_templates() {
  if ! command -v nuclei >/dev/null 2>&1; then
    warn "nuclei is not installed — the template set was not downloaded."
    return 0
  fi
  log "Downloading the nuclei templates..."
  # Template downloads depend on the network and must never abort the install.
  nuclei -ut || warn "Could not download the nuclei templates. Fix it later with: nuclei -ut"
}

build_frontend() {
  if [[ "${WITH_FRONTEND}" -eq 0 ]]; then
    log "Skipping the frontend build (--no-frontend)."
    return 0
  fi
  if [[ ! -d "${ROOT_DIR}/frontend" ]]; then
    warn "frontend/ was not found — the dashboard build was skipped."
    return 0
  fi
  if ! command -v npm >/dev/null 2>&1; then
    warn "npm was not found — the dashboard build was skipped. The API and CLI are unaffected."
    return 0
  fi

  log "Installing the frontend dependencies..."
  if ! (cd "${ROOT_DIR}/frontend" && npm install); then
    warn "npm install failed — the dashboard build was skipped. The API and CLI are unaffected."
    return 0
  fi

  log "Building the dashboard..."
  if ! (cd "${ROOT_DIR}/frontend" && npm run build); then
    warn "npm run build failed — the dashboard bundle is missing. The API and CLI still work."
    return 0
  fi
  ok "Dashboard built in frontend/dist"
}

setup_local_models() {
  if [[ "${WITH_LOCAL}" -eq 0 ]]; then
    return 0
  fi

  if ! command -v ollama >/dev/null 2>&1; then
    warn "Ollama is not installed. Install it from https://ollama.com/download and re-run this script with --local."
    return 0
  fi
  if ! curl -fsS --max-time 5 http://localhost:11434/api/tags >/dev/null 2>&1; then
    warn "Ollama is installed but not answering on http://localhost:11434. Start it with 'ollama serve' and re-run with --local."
    return 0
  fi

  local model="${OLLAMA_MODEL}"
  if [[ "${OLLAMA_MODEL_REQUESTED}" -eq 0 ]]; then
    model="${DEFAULT_OLLAMA_MODEL}"
    if [[ -t 0 ]]; then
      printf '[?] Pull the Ollama model "%s" now? This downloads several gigabytes. [y/N] ' "${model}"
      local answer=""
      read -r answer || answer=""
      case "${answer}" in
        [yY]|[yY][eE][sS]) ;;
        *)
          log "Skipping the model pull. Pull it later with: ollama pull ${model}"
          return 0
          ;;
      esac
    else
      log "Pull the Ollama model later with: ollama pull ${model}"
      return 0
    fi
  fi

  log "Pulling the Ollama model ${model}..."
  if ollama pull "${model}"; then
    ok "Ollama model ${model} is ready."
  else
    warn "Could not pull ${model}. Pull it later with: ollama pull ${model}"
  fi
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

  if [[ -x "${LAUNCHER_PATH}" ]]; then
    ready+=("trishul launcher (${LAUNCHER_PATH})")
  else
    missing+=("trishul launcher (${LAUNCHER_PATH})")
  fi

  local directory
  for directory in data reports plugins; do
    if [[ -d "${ROOT_DIR}/${directory}" ]]; then
      ready+=("${directory}/")
    else
      missing+=("${directory}/")
    fi
  done

  if [[ "${WITH_FRONTEND}" -eq 0 ]]; then
    log "Frontend: skipped by request (--no-frontend)"
  elif [[ -d "${ROOT_DIR}/frontend/dist" ]]; then
    ready+=("dashboard bundle (frontend/dist)")
  else
    missing+=("dashboard bundle (frontend/dist)")
  fi

  if command -v curl >/dev/null 2>&1; then
    local api_response=""
    if api_response="$(curl -fsS --max-time 3 http://127.0.0.1:8000/api/health 2>/dev/null)"; then
      ready+=("API is answering on http://127.0.0.1:8000/api/health")
      printf '%s\n' "${api_response}" | head -c 1500
      printf '\n'
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
  printf 'TRISHUL installation summary\n'
  printf -- '----------------------------\n'
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
    printf '  (nothing — TRISHUL is fully provisioned)\n'
  else
    local item
    for item in "${missing[@]}"; do
      printf '  - %s\n' "${item}"
    done
  fi

  printf '\nNext steps:\n'
  printf '  1. export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"\n'
  printf '  2. source .venv/bin/activate\n'
  printf '  3. python -m backend.app.main      # API on http://localhost:8000\n'
  printf '  4. trishul example.com --mode deep # run your first authorized scan\n'
}

main() {
  log "Installing TRISHUL from ${ROOT_DIR}"
  log "Target: Kali Linux / Debian / Ubuntu (the backend and CLI also run on other POSIX hosts)"

  install_system_packages
  install_ffuf_from_apt
  setup_go_environment
  install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx" "httpx"
  install_go_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei" "nuclei"
  install_go_tool "github.com/ffuf/ffuf/v2" "ffuf"
  setup_python_environment
  install_launcher
  create_directories
  prime_nuclei_templates
  build_frontend
  setup_local_models
  health_check

  ok "TRISHUL installation finished."
}

main "$@"
