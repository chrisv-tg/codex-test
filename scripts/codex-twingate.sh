#!/usr/bin/env bash
#
# codex-twingate.sh — Twingate Linux Client (Headless Mode) for Codex Cloud environments
#
# Patterned on:
#   - Twingate-Community/ubiquiti-headless-gateway (setup.sh: validate key, install,
#     configure headless, wait for tunnel, clear errors)
#   - Twingate/github-action (signed APT repo, `twingate setup --headless -` from stdin,
#     TUN/CAP_NET_ADMIN preflight, retry-until-online)
#   - Twingate Userspace Networking (HTTP proxy mode, no TUN / no NET_ADMIN)
#
# Docs:
#   https://www.twingate.com/docs/linux-headless
#   https://www.twingate.com/docs/linux-userspace-networking
#   https://www.twingate.com/docs/services
#   https://learn.chatgpt.com/codex/environments/cloud-environments
#
# Codex Cloud wiring:
#   Install script : bash "$(git rev-parse --show-toplevel)/scripts/codex-twingate.sh" install
#                    (NO secrets; also copies itself to /usr/local/bin/codex-twingate so the
#                     published snapshot has it on PATH regardless of repo path or branch)
#   Start skill    : codex-twingate start     (reads key from env at task start)
#
# Secret input (set ONE of these as a Codex Cloud *Environment variable*, NOT a Network secret):
#   TWINGATE_SERVICE_KEY      Minified JSON service key   (jq -c . service_key.json)
#   TWINGATE_SERVICE_KEY_B64  Base64 of the JSON file     (base64 -w0 service_key.json)
#
# Optional tuning:
#   TWINGATE_MODE             auto | tun | proxy          (default: auto)
#   TWINGATE_PROXY_LISTEN     HTTP proxy bind address     (default: 127.0.0.1:9999)
#   TWINGATE_ONLINE_TIMEOUT   Seconds to wait for online  (default: 90)
#   TWINGATE_NO_PROXY_DOMAINS Comma list of private suffixes that must bypass the Codex
#                             egress proxy in TUN mode    (e.g. ".corp.example.com,10.0.0.0/8")
#
# Usage: codex-twingate.sh {install|start|status|stop}
#
set -euo pipefail
# NOTE: never enable `set -x` in this script — it would print the service key.

TG_MODE="${TWINGATE_MODE:-auto}"
TG_PROXY_LISTEN="${TWINGATE_PROXY_LISTEN:-127.0.0.1:9999}"
TG_TIMEOUT="${TWINGATE_ONLINE_TIMEOUT:-90}"
TG_NO_PROXY_DOMAINS="${TWINGATE_NO_PROXY_DOMAINS:-}"

APT_KEYRING="/usr/share/keyrings/twingate-client-keyring.gpg"
APT_LIST="/etc/apt/sources.list.d/twingate.list"
APT_REPO="https://packages.twingate.com/apt/"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '[twingate] %s\n' "$*" >&2; }
warn() { printf '[twingate] WARN: %s\n' "$*" >&2; }
die()  { printf '[twingate] ERROR: %s\n' "$*" >&2; exit 1; }

# Root / sudo detection (Codex Cloud tasks usually run as root; don't assume it).
if [[ ${EUID} -eq 0 ]]; then
  SUDO=""
  CAN_ROOT=true
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  SUDO="sudo"
  CAN_ROOT=true
else
  SUDO=""
  CAN_ROOT=false
fi

# Runtime state lives on /run (tmpfs) when possible so nothing lands in saved snapshots.
if [[ "${CAN_ROOT}" == "true" ]]; then
  STATE_DIR="/run/twingate"
else
  STATE_DIR="${XDG_RUNTIME_DIR:-/tmp}/twingate"
fi
ENV_FILE="${STATE_DIR}/env.sh"
PROXY_LOG="${STATE_DIR}/twingated-proxy.log"
PID_FILE="${STATE_DIR}/twingated-proxy.pid"

ensure_state_dir() {
  ${SUDO} mkdir -p "${STATE_DIR}"
  ${SUDO} chmod 755 "${STATE_DIR}"
}

has_systemd() { [[ -d /run/systemd/system ]]; }

# TUN mode needs /dev/net/tun AND CAP_NET_ADMIN in the bounding set (bit 12).
# Logic mirrors check_network_capabilities() in Twingate/github-action.
has_tun_caps() {
  [[ -e /dev/net/tun ]] || return 1
  local cap_bnd
  cap_bnd=$(awk '/^CapBnd:/ {print $2}' /proc/self/status 2>/dev/null || true)
  if [[ -n "${cap_bnd}" ]] && (( ((0x${cap_bnd} >> 12) & 1) != 1 )); then
    return 1
  fi
  return 0
}

# Read + validate the service key from env. Prints the JSON on stdout (caller captures it).
# Never logs the key or any field derived from private_key.
read_service_key() {
  local key=""
  if [[ -n "${TWINGATE_SERVICE_KEY:-}" ]]; then
    key="${TWINGATE_SERVICE_KEY}"
  elif [[ -n "${TWINGATE_SERVICE_KEY_B64:-}" ]]; then
    key=$(printf '%s' "${TWINGATE_SERVICE_KEY_B64}" | base64 -d 2>/dev/null) \
      || die "TWINGATE_SERVICE_KEY_B64 is not valid base64."
  else
    die "No service key found. Set TWINGATE_SERVICE_KEY (minified JSON) or TWINGATE_SERVICE_KEY_B64 as a Codex Cloud Environment variable."
  fi

  command -v jq >/dev/null 2>&1 || die "jq is required. Run '$0 install' first."
  printf '%s' "${key}" | jq -e . >/dev/null 2>&1 \
    || die "Service key is not valid JSON. Paste the output of: jq -c . service_key.json"

  local field
  for field in network service_account_id private_key key_id; do
    printf '%s' "${key}" | jq -e --arg f "${field}" 'has($f) and (.[$f] | type == "string") and (.[$f] | length > 0)' >/dev/null \
      || die "Service key is missing required field: ${field}"
  done

  # Honor expires_at if set (null = never expires).
  local expires
  expires=$(printf '%s' "${key}" | jq -r '.expires_at // empty')
  if [[ -n "${expires}" ]]; then
    local exp_epoch now_epoch
    exp_epoch=$(date -d "${expires}" +%s 2>/dev/null || echo 0)
    now_epoch=$(date +%s)
    if (( exp_epoch > 0 && exp_epoch <= now_epoch )); then
      die "Service key expired at ${expires}. Generate a new key in the Admin Console."
    fi
  fi

  printf '%s' "${key}"
}

# Non-fatal egress diagnostics. Codex Cloud egress is an allowlisted HTTP(S) proxy;
# the Twingate Client needs TCP 443 to *.twingate.com, TCP 30000-31000 to Relays, and
# outbound UDP for P2P. This tells you which path (if any) actually works.
egress_preflight() {
  local network="$1" code_proxy code_direct
  code_proxy=$(curl -sS -o /dev/null --max-time 10 -w '%{http_code}' "https://${network}/" 2>/dev/null || echo "000")
  code_direct=$(curl -sS -o /dev/null --max-time 10 --noproxy '*' -w '%{http_code}' "https://${network}/" 2>/dev/null || echo "000")
  log "Egress check to controller ${network}: via-env-proxy=${code_proxy} direct=${code_direct}"
  # 000 = no route; 403 = typically an egress-policy denial from a transparent proxy.
  if [[ "${code_direct}" == "000" || "${code_direct}" == "403" ]]; then
    warn "Direct egress to ${network} looks blocked (HTTP ${code_direct}). Codex Cloud may only allow traffic through its HTTP proxy."
    warn "The Twingate Client opens its own TLS/UDP sessions to the Controller and Relays and may not connect."
    warn "Validate with internet access set to 'All (unrestricted)' before tightening the allowlist."
  fi
}

wait_for_online() {
  local elapsed=0 status=""
  while (( elapsed < TG_TIMEOUT )); do
    status=$(twingate status 2>/dev/null || true)
    if [[ "${status}" == "online" ]]; then
      log "Twingate status: online (${elapsed}s)"
      return 0
    fi
    sleep 3
    elapsed=$(( elapsed + 3 ))
  done
  warn "Twingate did not reach 'online' within ${TG_TIMEOUT}s (last status: '${status:-unknown}')."
  return 1
}

dump_logs() {
  warn "Recent client logs:"
  if has_systemd; then
    ${SUDO} journalctl -u twingate --no-pager -n 50 2>/dev/null || true
  fi
  # Without systemd the forked daemon logs here (per Twingate/github-action).
  ${SUDO} tail -n 50 /var/log/twingated.log 2>/dev/null || true
  [[ -f "${PROXY_LOG}" ]] && tail -n 50 "${PROXY_LOG}" || true
}

write_env_file() {
  local mode="$1"
  ensure_state_dir
  {
    echo "# Generated by codex-twingate.sh — source this before reaching private Resources."
    echo "export TWINGATE_ACTIVE_MODE=${mode}"
    if [[ "${mode}" == "proxy" ]]; then
      echo "export TWINGATE_HTTP_PROXY=http://${TG_PROXY_LISTEN}"
      echo "# Route ONE command through Twingate without hijacking the Codex egress proxy:"
      echo "#   tgx curl https://internal.example.com/health"
      echo "tgx() { HTTPS_PROXY=\"\$TWINGATE_HTTP_PROXY\" https_proxy=\"\$TWINGATE_HTTP_PROXY\" HTTP_PROXY=\"\$TWINGATE_HTTP_PROXY\" http_proxy=\"\$TWINGATE_HTTP_PROXY\" NO_PROXY= no_proxy= \"\$@\"; }"
    elif [[ -n "${TG_NO_PROXY_DOMAINS}" ]]; then
      echo "# TUN mode: private names must bypass the Codex egress proxy so they hit sdwan0."
      echo "export NO_PROXY=\"\${NO_PROXY:+\$NO_PROXY,}${TG_NO_PROXY_DOMAINS}\""
      echo "export no_proxy=\"\$NO_PROXY\""
    fi
  } | ${SUDO} tee "${ENV_FILE}" >/dev/null
  ${SUDO} chmod 644 "${ENV_FILE}"
  log "Wrote ${ENV_FILE} (source it in your shell)."
}

# ---------------------------------------------------------------------------
# install — runs in the Codex Cloud *Install script*. No secrets touched here,
# because the resulting filesystem is captured when the environment is published.
# ---------------------------------------------------------------------------
cmd_install() {
  [[ "${CAN_ROOT}" == "true" ]] || die "install requires root or passwordless sudo."
  export DEBIAN_FRONTEND=noninteractive

  if [[ -n "${TWINGATE_SERVICE_KEY:-}${TWINGATE_SERVICE_KEY_B64:-}" ]]; then
    log "Service key present in env; intentionally NOT used during install (keeps it out of the snapshot)."
  fi

  log "Installing prerequisites..."
  ${SUDO} apt-get update -qq
  ${SUDO} apt-get install -y -qq curl gnupg ca-certificates jq iproute2 procps >/dev/null

  log "Adding signed Twingate APT repository (${APT_REPO})..."
  local tmp
  tmp=$(mktemp)
  curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 "${APT_REPO}gpg.key" -o "${tmp}" \
    || die "Could not download ${APT_REPO}gpg.key — add packages.twingate.com to Allowed domains."
  ${SUDO} gpg --batch --yes --no-tty --dearmor -o "${APT_KEYRING}" < "${tmp}"
  rm -f "${tmp}"
  echo "deb [signed-by=${APT_KEYRING}] ${APT_REPO} * *" | ${SUDO} tee "${APT_LIST}" >/dev/null

  ${SUDO} apt-get update -qq -o Dir::Etc::sourcelist="sources.list.d/twingate.list" \
    -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0"
  ${SUDO} apt-get install -y -qq twingate >/dev/null

  # Put this script on PATH so the Start skill never depends on cwd or the checked-out branch.
  ${SUDO} install -m 755 "$(readlink -f "$0")" /usr/local/bin/codex-twingate
  log "Installed helper: /usr/local/bin/codex-twingate"

  # Paranoia: make sure no key material is baked into the published snapshot.
  ${SUDO} rm -f /etc/twingate/service_key.json

  log "Installed: $(twingate --version 2>/dev/null | head -1 || echo 'twingate (version unknown)')"
  if has_tun_caps; then
    log "Capability check: /dev/net/tun + CAP_NET_ADMIN present -> TUN mode available."
  else
    log "Capability check: TUN unavailable -> 'start' will use userspace HTTP proxy mode."
  fi
}

# ---------------------------------------------------------------------------
# start — runs in the Codex Cloud *Start skill* at the beginning of each task.
# ---------------------------------------------------------------------------
cmd_start() {
  command -v twingate >/dev/null 2>&1 || die "Twingate is not installed in this snapshot. Check the Install script ran, then Republish the environment."

  local key network mode
  key=$(read_service_key)
  network=$(printf '%s' "${key}" | jq -r '.network')
  log "Service key validated for network ${network} (key material not printed)."

  case "${TG_MODE}" in
    tun)   mode="tun" ;;
    proxy) mode="proxy" ;;
    auto)
      if [[ "${CAN_ROOT}" == "true" ]] && has_tun_caps; then mode="tun"; else mode="proxy"; fi ;;
    *) die "TWINGATE_MODE must be auto, tun, or proxy (got '${TG_MODE}')." ;;
  esac
  if [[ "${mode}" == "tun" ]]; then
    [[ "${CAN_ROOT}" == "true" ]] || die "TUN mode requires root."
    has_tun_caps || die "TUN mode requires /dev/net/tun and CAP_NET_ADMIN (not present). Use TWINGATE_MODE=proxy."
  fi
  log "Mode: ${mode} (systemd: $(has_systemd && echo yes || echo no))"

  egress_preflight "${network}"
  ensure_state_dir

  # Idempotent: stop anything left over from a resumed task.
  twingate stop >/dev/null 2>&1 || true
  if [[ -f "${PID_FILE}" ]]; then
    ${SUDO} kill "$(cat "${PID_FILE}")" 2>/dev/null || true
    ${SUDO} rm -f "${PID_FILE}"
  fi

  if [[ "${mode}" == "tun" ]]; then
    # Key goes in via stdin — never written to a temp file, never on the command line.
    printf '%s\n' "${key}" | ${SUDO} twingate setup --headless - >/dev/null
    # With systemd this starts the unit; without it, the daemon forks and logs to /var/log/twingated.log.
    ${SUDO} twingate start >/dev/null 2>&1 || true
  else
    # Userspace HTTP proxy mode: no TUN, no NET_ADMIN; only HTTP/HTTPS (CONNECT) traffic.
    if [[ "${CAN_ROOT}" == "true" ]]; then
      printf '%s\n' "${key}" | ${SUDO} twingate setup --headless - >/dev/null
    fi
    # Log file must be writable by this shell (the redirect runs before sudo).
    ${SUDO} install -m 600 -o "$(id -u)" /dev/null "${PROXY_LOG}"
    # Bind to loopback by default so the proxy is never exposed beyond the VM.
    # TWINGATE_SERVICE_KEY is also passed via env for non-root runs (Twingate-Solutions Spacelift pattern).
    ${SUDO} env TWINGATE_SERVICE_KEY="${key}" \
      nohup twingated --http-proxy "${TG_PROXY_LISTEN}" --tun off \
      >"${PROXY_LOG}" 2>&1 &
    echo $! | ${SUDO} tee "${PID_FILE}" >/dev/null
  fi
  unset key

  if ! wait_for_online; then
    dump_logs
    die "Twingate failed to come online. See README notes on Codex egress (Allowed domains / unrestricted)."
  fi

  write_env_file "${mode}"

  log "Resources available to this Service Account:"
  twingate resources 2>/dev/null || warn "'twingate resources' unavailable in this mode/version."

  if [[ "${mode}" == "proxy" ]]; then
    log "Proxy mode: run 'source ${ENV_FILE}' then prefix commands with 'tgx', e.g. tgx curl https://<resource>"
    log "Non-HTTP protocols (Postgres/SSH) need a CONNECT bridge such as proxytunnel."
  else
    log "TUN mode: traffic to Resources routes via sdwan0. If tools use the Codex HTTP proxy, set TWINGATE_NO_PROXY_DOMAINS."
  fi
}

cmd_status() {
  twingate status 2>/dev/null || echo "not running"
  [[ -f "${ENV_FILE}" ]] && grep -E '^export TWINGATE_' "${ENV_FILE}" || true
}

cmd_stop() {
  twingate stop >/dev/null 2>&1 || ${SUDO} twingate stop >/dev/null 2>&1 || true
  if [[ -f "${PID_FILE}" ]]; then
    ${SUDO} kill "$(cat "${PID_FILE}")" 2>/dev/null || true
    ${SUDO} rm -f "${PID_FILE}"
  fi
  log "Twingate stopped."
}

case "${1:-}" in
  install) cmd_install ;;
  start)   cmd_start ;;
  status)  cmd_status ;;
  stop)    cmd_stop ;;
  *) echo "Usage: $0 {install|start|status|stop}" >&2; exit 2 ;;
esac
