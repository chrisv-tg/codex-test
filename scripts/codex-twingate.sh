#!/usr/bin/env bash
#
# codex-twingate.sh (v2) — Twingate Linux Client (Headless Mode) for Codex Cloud
#
# v2: Codex Cloud task shells were observed with NO /dev/net/tun and CapBnd=0 (empty
# capability bounding set). TUN mode is impossible there, and apt/dpkg installs may not
# work either. v2 therefore defaults to:
#   - ROOTLESS install: fetch the .deb from packages.twingate.com, verify its SHA256 against
#     the repo index, and unpack it with `dpkg-deb -x` into $HOME (no root, no apt).
#   - USERSPACE HTTP proxy mode: `twingated --http-proxy 127.0.0.1:9999 --tun off`, key read
#     from TWINGATE_SERVICE_KEY in the environment (no /etc/twingate, no setup as root).
# APT install + TUN mode remain available on privileged hosts.
# v3: $HOME can be READ-ONLY in Codex task sandboxes -> the install prefix is now the first
#     writable candidate ($TWINGATE_PREFIX, $HOME/.local/share/twingate, /tmp/twingate-pkg-<uid>),
#     `start` self-installs if the snapshot has no binaries, and the egress check no longer
#     mis-reports failures ("000000").
# v4: The .deb assumes system libs the Codex image lacks (observed: libcryptsetup.so.12).
#     Missing shared libs are now resolved rootless: a private apt state dir (no root) runs
#     `apt-get update` + `apt-get download` from the image's own signed Ubuntu/Debian sources
#     (hash-verified by apt), unpacks into the prefix, and LD_LIBRARY_PATH points at them.
#
# Docs:
#   https://www.twingate.com/docs/linux-headless
#   https://www.twingate.com/docs/linux-userspace-networking
#   https://learn.chatgpt.com/codex/environments/cloud-environments
#
# Codex Cloud wiring (path-independent):
#   Install script : bash "$(find /workspace -path '*/scripts/codex-twingate.sh' -print -quit)" install
#   Start skill    : bash "$(find /workspace -path '*/scripts/codex-twingate.sh' -print -quit)" start
#
# Secret input (Codex Cloud *Environment variable*, never a Network secret):
#   TWINGATE_SERVICE_KEY      Minified JSON service key   (jq -c . service_key.json)
#   TWINGATE_SERVICE_KEY_B64  Base64 of the JSON file     (base64 -w0 service_key.json)
#
# Optional:
#   TWINGATE_MODE             auto | tun | proxy          (default: auto)
#   TWINGATE_INSTALL_METHOD   auto | apt | rootless       (default: auto)
#   TWINGATE_PREFIX           Rootless install dir        (default: $HOME/.local/share/twingate)
#   TWINGATE_PROXY_LISTEN     HTTP proxy bind address     (default: 127.0.0.1:9999)
#   TWINGATE_ONLINE_TIMEOUT   Seconds to wait for online  (default: 90)
#   TWINGATE_TEST_URL         Optional Resource URL to probe through the proxy after start
#   TWINGATE_NO_PROXY_DOMAINS TUN mode only: private suffixes that must bypass the Codex proxy
#   TWINGATE_EXTRA_PKGS       Space-separated apt packages to unpack if soname mapping misses one
#
# Usage: codex-twingate.sh {install|start|status|stop|doctor}
#
set -euo pipefail
# NOTE: never enable `set -x` in this script — it would print the service key.

TG_MODE="${TWINGATE_MODE:-auto}"
TG_INSTALL_METHOD="${TWINGATE_INSTALL_METHOD:-auto}"
PREFIX_CANDIDATES=()
[[ -n "${TWINGATE_PREFIX:-}" ]] && PREFIX_CANDIDATES+=("${TWINGATE_PREFIX}")
[[ -n "${HOME:-}" ]] && PREFIX_CANDIDATES+=("${HOME}/.local/share/twingate")
PREFIX_CANDIDATES+=("/tmp/twingate-pkg-${EUID}")
TG_PREFIX=""   # set by pick_prefix (install) or resolve_bins (start)
TG_PROXY_LISTEN="${TWINGATE_PROXY_LISTEN:-127.0.0.1:9999}"
TG_TIMEOUT="${TWINGATE_ONLINE_TIMEOUT:-90}"
TG_TEST_URL="${TWINGATE_TEST_URL:-}"
TG_NO_PROXY_DOMAINS="${TWINGATE_NO_PROXY_DOMAINS:-}"

APT_REPO="${TWINGATE_APT_REPO:-https://packages.twingate.com/apt/}"
APT_KEYRING="/usr/share/keyrings/twingate-client-keyring.gpg"
APT_LIST="/etc/apt/sources.list.d/twingate.list"

log()  { printf '[twingate] %s\n' "$*" >&2; }
warn() { printf '[twingate] WARN: %s\n' "$*" >&2; }
die()  { printf '[twingate] ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------
cap_bnd_hex() { awk '/^CapBnd:/ {print $2}' /proc/self/status 2>/dev/null || true; }

has_cap() { # $1 = capability bit number
  local hex; hex=$(cap_bnd_hex)
  [[ -z "${hex}" ]] && return 0   # unreadable -> don't block
  (( ((0x${hex} >> $1) & 1) == 1 ))
}

# "Privileged" = uid 0 (or passwordless sudo) AND a non-empty capability set.
# uid 0 with CapBnd=0 cannot run apt reliably or create TUN interfaces.
SUDO=""
PRIVILEGED=false
if [[ ${EUID} -eq 0 ]] && has_cap 0 && has_cap 21; then          # CAP_CHOWN, CAP_SYS_ADMIN
  PRIVILEGED=true
elif [[ ${EUID} -ne 0 ]] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  SUDO="sudo"; PRIVILEGED=true
fi

has_tun_caps() { [[ -e /dev/net/tun ]] && has_cap 12; }          # CAP_NET_ADMIN
has_systemd()  { [[ -d /run/systemd/system ]]; }

STATE_DIR="/tmp/twingate-${EUID}"          # predictable, writable, never in /etc
ENV_FILE="${STATE_DIR}/env.sh"
PROXY_LOG="${STATE_DIR}/twingated.log"
PID_FILE="${STATE_DIR}/twingated.pid"
RUNTIME_DIR="${STATE_DIR}/runtime"          # XDG_RUNTIME_DIR for the rootless daemon

# Resolve binaries: rootless prefix first, then system PATH.
TG_CLI=""; TG_DAEMON=""
resolve_bins() {
  local p
  TG_CLI=""; TG_DAEMON=""
  for p in "${PREFIX_CANDIDATES[@]}"; do
    TG_DAEMON=$(find "${p}/root" -type f -name twingated -perm -u+x 2>/dev/null | head -1 || true)
    if [[ -n "${TG_DAEMON}" ]]; then
      TG_PREFIX="${p}"
      TG_CLI=$(find "${p}/root" -type f -name twingate -perm -u+x 2>/dev/null | head -1 || true)
      break
    fi
  done
  [[ -z "${TG_CLI}"    ]] && TG_CLI=$(command -v twingate  2>/dev/null || true)
  [[ -z "${TG_DAEMON}" ]] && TG_DAEMON=$(command -v twingated 2>/dev/null || true)
  compute_libpath
  return 0
}

# First candidate we can actually write to (Codex task sandboxes may mount $HOME read-only).
pick_prefix() {
  local p
  for p in "${PREFIX_CANDIDATES[@]}"; do
    if mkdir -p "${p}" 2>/dev/null && touch "${p}/.w" 2>/dev/null; then
      rm -f "${p}/.w"; TG_PREFIX="${p}"; return 0
    fi
    log "Prefix not writable, skipping: ${p}"
  done
  die "No writable install prefix. Set TWINGATE_PREFIX to a writable directory."
}

# Directories inside the prefix that hold shared libraries (bundled deps).
TG_LIBPATH=""
compute_libpath() {
  TG_LIBPATH=""
  [[ -n "${TG_PREFIX}" && -d "${TG_PREFIX}/root" ]] || return 0
  TG_LIBPATH=$(find "${TG_PREFIX}/root" \( -name '*.so' -o -name '*.so.*' \) -printf '%h\n' 2>/dev/null | sort -u | paste -sd: -)
}

tg_cli() { LD_LIBRARY_PATH="${TG_LIBPATH}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" XDG_RUNTIME_DIR="${RUNTIME_DIR}" "${TG_CLI}" "$@"; }

missing_libs() { # sonames still unresolved for the daemon + CLI
  local b
  for b in "${TG_DAEMON}" "${TG_CLI}"; do
    [[ -n "${b}" && -x "${b}" ]] || continue
    # `|| true`: ldd exits non-zero on scripts/static binaries; must not trip set -e/pipefail.
    { LD_LIBRARY_PATH="${TG_LIBPATH}" ldd "${b}" 2>/dev/null || true; } | awk '/not found/ {print $1}'
  done | sort -u
}

# Map a soname to likely Debian/Ubuntu package names (incl. 64-bit time_t "t64" renames).
#   libcryptsetup.so.12 -> libcryptsetup12 | libcryptsetup-12 | libcryptsetup12t64 | ...
soname_candidates() {
  local base="${1%%.so.*}" ver="${1#*.so.}"
  echo "${base}${ver} ${base}-${ver} ${base}${ver}t64 ${base}-${ver}t64"
}

# Fetch missing shared libraries without root, using the image's configured (signed) apt sources.
resolve_missing_libs() {
  command -v ldd >/dev/null 2>&1 || { warn "ldd unavailable; cannot check shared libraries."; return 0; }
  compute_libpath
  local missing; missing=$(missing_libs)
  [[ -z "${missing}" ]] && return 0

  command -v apt-get >/dev/null 2>&1 || die "Missing libs (${missing//$'\n'/ }) and no apt-get to fetch them."
  local aptdir="${TG_PREFIX}/apt" debdir="${TG_PREFIX}/debs"
  mkdir -p "${aptdir}/lists/partial" "${aptdir}/cache/archives/partial" "${debdir}"
  local -a aptopts=(-o "Dir::State::Lists=${aptdir}/lists" -o "Dir::Cache=${aptdir}/cache"
                    -o "Debug::NoLocking=1" -o "APT::Sandbox::User=$(id -un)")
  log "Fetching apt indexes rootless (private state in ${aptdir})..."
  apt-get "${aptopts[@]}" update -qq >/dev/null 2>&1 \
    || warn "apt-get update reported errors (often an unrelated third-party source); continuing."

  local round so cand got prev=""
  for cand in ${TWINGATE_EXTRA_PKGS:-}; do
    ( cd "${debdir}" && apt-get "${aptopts[@]}" download -qq "${cand}" >/dev/null 2>&1 ) \
      && log "  extra package <- ${cand}" || warn "  extra package ${cand}: download failed"
  done
  for round in 1 2 3 4 5; do
    missing=$(missing_libs)
    [[ -z "${missing}" ]] && { log "All shared libraries resolved."; return 0; }
    if [[ "${missing}" == "${prev}" && -z "$(ls -A "${debdir}" 2>/dev/null)" ]]; then break; fi
    prev="${missing}"
    log "Round ${round}: missing -> $(echo "${missing}" | paste -sd' ' -)"
    for so in ${missing}; do
      got=""
      for cand in $(soname_candidates "${so}"); do
        if apt-cache "${aptopts[@]}" show "${cand}" >/dev/null 2>&1; then
          ( cd "${debdir}" && apt-get "${aptopts[@]}" download -qq "${cand}" >/dev/null 2>&1 ) && got="${cand}" && break
        fi
      done
      if [[ -n "${got}" ]]; then log "  ${so} <- ${got}"; else warn "  ${so}: no package found"; fi
    done
    local d
    for d in "${debdir}"/*.deb; do
      [[ -e "${d}" ]] || continue
      dpkg-deb -x "${d}" "${TG_PREFIX}/root" && rm -f "${d}"
    done
    compute_libpath
  done
  missing=$(missing_libs)
  [[ -z "${missing}" ]] || die "Still missing shared libraries: $(echo "${missing}" | paste -sd' ' -). Set TWINGATE_EXTRA_PKGS to the providing package(s)."
}

# ---------------------------------------------------------------------------
# Service key (never printed)
# ---------------------------------------------------------------------------
read_service_key() {
  local key=""
  if [[ -n "${TWINGATE_SERVICE_KEY:-}" ]]; then
    key="${TWINGATE_SERVICE_KEY}"
  elif [[ -n "${TWINGATE_SERVICE_KEY_B64:-}" ]]; then
    key=$(printf '%s' "${TWINGATE_SERVICE_KEY_B64}" | base64 -d 2>/dev/null) \
      || die "TWINGATE_SERVICE_KEY_B64 is not valid base64."
  else
    die "No service key in env. Set TWINGATE_SERVICE_KEY as a Codex Cloud Environment variable."
  fi
  command -v jq >/dev/null 2>&1 || die "jq is required (included in most Codex images)."
  printf '%s' "${key}" | jq -e . >/dev/null 2>&1 || die "Service key is not valid JSON (use: jq -c . key.json)."
  local f
  for f in network service_account_id private_key key_id; do
    printf '%s' "${key}" | jq -e --arg f "$f" '(.[$f]|type)=="string" and (.[$f]|length)>0' >/dev/null \
      || die "Service key is missing required field: $f"
  done
  local exp; exp=$(printf '%s' "${key}" | jq -r '.expires_at // empty')
  if [[ -n "${exp}" ]]; then
    local e; e=$(date -d "${exp}" +%s 2>/dev/null || echo 0)
    (( e > 0 && e <= $(date +%s) )) && die "Service key expired at ${exp}."
  fi
  printf '%s' "${key}"
}

egress_preflight() {
  local host="$1" via direct
  via=$(curl -s -o /dev/null --max-time 10 -w '%{http_code}' "https://${host}/" 2>/dev/null || true)
  direct=$(curl -s -o /dev/null --max-time 10 --noproxy '*' -w '%{http_code}' "https://${host}/" 2>/dev/null || true)
  via="${via:-000}"; direct="${direct:-000}"
  log "Egress to ${host}: via-env-proxy=${via} direct=${direct}"
  if [[ "${direct}" == "000" || "${direct}" == "403" ]]; then
    warn "Direct egress to ${host} looks blocked. twingated opens its own TLS/UDP sessions to the"
    warn "Controller and Relays; if only proxied HTTPS is allowed it may never come online."
    warn "twingated will inherit HTTPS_PROXY=${HTTPS_PROXY:-${https_proxy:-<unset>}} — whether it honors it is the open question."
  fi
}

# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------
deb_arch() {
  if command -v dpkg >/dev/null 2>&1; then dpkg --print-architecture; return; fi
  case "$(uname -m)" in x86_64) echo amd64 ;; aarch64|arm64) echo arm64 ;; *) uname -m ;; esac
}

install_rootless() {
  local arch idx rec filename sha tmpdeb
  arch=$(deb_arch)
  pick_prefix
  log "Rootless install (${arch}) into ${TG_PREFIX}"
  idx=$(curl -fsSL --retry 3 "${APT_REPO}Packages") \
    || die "Cannot fetch ${APT_REPO}Packages — add packages.twingate.com to Allowed domains."

  # Pick the newest 'twingate' stanza for this architecture.
  rec=$(printf '%s\n' "${idx}" | awk -v arch="${arch}" '
    BEGIN { RS=""; FS="\n" }
    {
      pkg=""; a=""; v=""; fn=""; sh=""
      for (i=1;i<=NF;i++) {
        if ($i ~ /^Package: /)      pkg=substr($i,10)
        if ($i ~ /^Architecture: /) a=substr($i,15)
        if ($i ~ /^Version: /)      v=substr($i,10)
        if ($i ~ /^Filename: /)     fn=substr($i,11)
        if ($i ~ /^SHA256: /)       sh=substr($i,9)
      }
      if (pkg=="twingate" && (a==arch || a=="all")) print v "\t" fn "\t" sh
    }' | sort -V -k1,1 | tail -1)
  [[ -n "${rec}" ]] || die "No 'twingate' package for ${arch} in the repo index."
  IFS=$'\t' read -r _ filename sha <<<"${rec}"
  filename="${filename#./}"

  tmpdeb=$(mktemp --suffix=.deb)
  curl -fsSL --retry 3 "${APT_REPO}${filename}" -o "${tmpdeb}" || die "Download failed: ${APT_REPO}${filename}"
  if [[ -n "${sha}" ]]; then
    echo "${sha}  ${tmpdeb}" | sha256sum -c --quiet - || die "SHA256 mismatch for ${filename}"
    log "SHA256 verified against repo index."
  else
    warn "Repo index has no SHA256 for ${filename}; integrity not verified."
  fi

  rm -rf "${TG_PREFIX}/root"; mkdir -p "${TG_PREFIX}/root"
  if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb -x "${tmpdeb}" "${TG_PREFIX}/root"
  else
    ( cd "${TG_PREFIX}" && ar x "${tmpdeb}" && tar -xf data.tar.* -C root && rm -f control.tar.* data.tar.* debian-binary )
  fi
  rm -f "${tmpdeb}"

  resolve_bins
  [[ -n "${TG_DAEMON}" ]] || die "twingated not found in the package payload."
  log "Daemon: ${TG_DAEMON}"
  log "CLI:    ${TG_CLI:-<not found>}"
  resolve_missing_libs
}

install_apt() {
  export DEBIAN_FRONTEND=noninteractive
  log "APT install (privileged)"
  ${SUDO} apt-get update -qq
  ${SUDO} apt-get install -y -qq curl gnupg ca-certificates jq >/dev/null
  local tmp; tmp=$(mktemp)
  curl -fsSL --retry 5 "${APT_REPO}gpg.key" -o "${tmp}"
  ${SUDO} gpg --batch --yes --no-tty --dearmor -o "${APT_KEYRING}" < "${tmp}"; rm -f "${tmp}"
  echo "deb [signed-by=${APT_KEYRING}] ${APT_REPO} * *" | ${SUDO} tee "${APT_LIST}" >/dev/null
  ${SUDO} apt-get update -qq -o Dir::Etc::sourcelist="sources.list.d/twingate.list" \
    -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0"
  ${SUDO} apt-get install -y -qq twingate >/dev/null
  ${SUDO} rm -f /etc/twingate/service_key.json
}

cmd_install() {
  [[ -n "${TWINGATE_SERVICE_KEY:-}${TWINGATE_SERVICE_KEY_B64:-}" ]] \
    && log "Service key present in env; intentionally NOT used during install."
  case "${TG_INSTALL_METHOD}" in
    apt)      install_apt ;;
    rootless) install_rootless ;;
    auto)
      if [[ "${PRIVILEGED}" == "true" ]]; then
        install_apt || { warn "APT install failed; falling back to rootless."; install_rootless; }
      else
        install_rootless
      fi ;;
    *) die "TWINGATE_INSTALL_METHOD must be auto, apt, or rootless." ;;
  esac
  resolve_bins
  log "Install complete. TUN-capable: $(has_tun_caps && echo yes || echo no). Start will use: $( [[ "${PRIVILEGED}" == true ]] && has_tun_caps && echo tun || echo proxy)"
}

# ---------------------------------------------------------------------------
# start / status / stop
# ---------------------------------------------------------------------------
wait_for_online() {
  local t=0 s=""
  while (( t < TG_TIMEOUT )); do
    s=$(tg_cli status 2>/dev/null || true)
    [[ "${s}" == "online" ]] && { log "Twingate status: online (${t}s)"; return 0; }
    if [[ -f "${PID_FILE}" ]] && ! kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
      warn "twingated exited."; return 1
    fi
    sleep 3; t=$((t+3))
  done
  warn "Not online after ${TG_TIMEOUT}s (last status: '${s:-unknown}')."; return 1
}

dump_logs() {
  warn "Last 60 log lines:"
  tail -n 60 "${PROXY_LOG}" 2>/dev/null || true
  ${SUDO} tail -n 30 /var/log/twingated.log 2>/dev/null || true
}

stop_daemon() {
  if [[ -f "${PID_FILE}" ]]; then kill "$(cat "${PID_FILE}")" 2>/dev/null || true; rm -f "${PID_FILE}"; fi
  [[ -n "${TG_CLI}" ]] && ${SUDO} "${TG_CLI}" stop >/dev/null 2>&1 || true
}

cmd_start() {
  resolve_bins
  if [[ -z "${TG_DAEMON}" ]]; then
    log "Twingate binaries not in this snapshot; installing rootless now."
    install_rootless
    resolve_bins
  fi
  [[ -n "${TG_DAEMON}" ]] || die "Twingate install failed."
  [[ -n "${TG_PREFIX}" ]] && resolve_missing_libs

  local key network mode
  key=$(read_service_key)
  network=$(printf '%s' "${key}" | jq -r '.network')
  log "Service key OK for ${network} (not printed). uid=${EUID} privileged=${PRIVILEGED} tun=$(has_tun_caps && echo yes || echo no) systemd=$(has_systemd && echo yes || echo no)"

  case "${TG_MODE}" in
    tun|proxy) mode="${TG_MODE}" ;;
    auto) if [[ "${PRIVILEGED}" == true ]] && has_tun_caps; then mode=tun; else mode=proxy; fi ;;
    *) die "TWINGATE_MODE must be auto, tun, or proxy." ;;
  esac
  [[ "${mode}" == tun ]] && { [[ "${PRIVILEGED}" == true ]] && has_tun_caps || die "TUN mode needs root + /dev/net/tun + CAP_NET_ADMIN."; }
  log "Mode: ${mode}"

  egress_preflight "${network}"
  mkdir -p "${STATE_DIR}" "${RUNTIME_DIR}"; chmod 700 "${STATE_DIR}" "${RUNTIME_DIR}"
  stop_daemon

  if [[ "${mode}" == tun ]]; then
    printf '%s\n' "${key}" | ${SUDO} "${TG_CLI}" setup --headless - >/dev/null
    ${SUDO} "${TG_CLI}" start >/dev/null 2>&1 || true
    RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run}"   # system daemon; CLI uses default socket
  else
    # Rootless userspace proxy: key via env (Twingate-Solutions Spacelift pattern), loopback-only bind.
    : > "${PROXY_LOG}"; chmod 600 "${PROXY_LOG}"
    LD_LIBRARY_PATH="${TG_LIBPATH}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
    XDG_RUNTIME_DIR="${RUNTIME_DIR}" TWINGATE_SERVICE_KEY="${key}" \
      nohup "${TG_DAEMON}" --http-proxy "${TG_PROXY_LISTEN}" --tun off >>"${PROXY_LOG}" 2>&1 &
    echo $! > "${PID_FILE}"
  fi
  unset key

  if ! wait_for_online; then dump_logs; die "Twingate failed to come online."; fi

  {
    echo "# Generated by codex-twingate.sh"
    echo "export TWINGATE_ACTIVE_MODE=${mode}"
    if [[ "${mode}" == proxy ]]; then
      echo "export TWINGATE_HTTP_PROXY=http://${TG_PROXY_LISTEN}"
      echo "tgx() { HTTPS_PROXY=\"\$TWINGATE_HTTP_PROXY\" https_proxy=\"\$TWINGATE_HTTP_PROXY\" HTTP_PROXY=\"\$TWINGATE_HTTP_PROXY\" http_proxy=\"\$TWINGATE_HTTP_PROXY\" NO_PROXY= no_proxy= \"\$@\"; }"
    elif [[ -n "${TG_NO_PROXY_DOMAINS}" ]]; then
      echo "export NO_PROXY=\"\${NO_PROXY:+\$NO_PROXY,}${TG_NO_PROXY_DOMAINS}\"; export no_proxy=\"\$NO_PROXY\""
    fi
  } > "${ENV_FILE}"
  log "Env file: ${ENV_FILE}  (source it, then: tgx curl https://<resource>)"

  tg_cli resources 2>/dev/null || warn "'twingate resources' not available in this mode."

  if [[ -n "${TG_TEST_URL}" && "${mode}" == proxy ]]; then
    local code
    code=$(curl -sS -o /dev/null --max-time 15 --noproxy '' --proxy "http://${TG_PROXY_LISTEN}" -w '%{http_code}' "${TG_TEST_URL}" 2>/dev/null || echo 000)
    log "Resource probe ${TG_TEST_URL} via Twingate proxy: HTTP ${code}"
  fi
}

cmd_status() {
  resolve_bins
  [[ -n "${TG_CLI}" ]] && tg_cli status 2>/dev/null || echo "not running"
  [[ -f "${ENV_FILE}" ]] && echo "env file: ${ENV_FILE}"
}

cmd_stop() { resolve_bins; stop_daemon; log "Twingate stopped."; }

cmd_doctor() {
  resolve_bins
  echo "uid=${EUID} privileged=${PRIVILEGED} CapBnd=$(cap_bnd_hex) tun_dev=$([[ -e /dev/net/tun ]] && echo yes || echo no) systemd=$(has_systemd && echo yes || echo no)"
  echo "daemon=${TG_DAEMON:-missing} cli=${TG_CLI:-missing} prefix=${TG_PREFIX:-<none>}"
  local p; for p in "${PREFIX_CANDIDATES[@]}"; do
    echo "prefix candidate ${p}: $( (mkdir -p "${p}" && touch "${p}/.w" && rm -f "${p}/.w") 2>/dev/null && echo writable || echo read-only)"
  done
  [[ -n "${TG_DAEMON}" ]] && echo "missing_libs=$(missing_libs | paste -sd' ' -)"
  echo "key_in_env=$([[ -n "${TWINGATE_SERVICE_KEY:-}${TWINGATE_SERVICE_KEY_B64:-}" ]] && echo yes || echo no)"
  echo "HTTPS_PROXY=${HTTPS_PROXY:-${https_proxy:-<unset>}}"
  egress_preflight "packages.twingate.com"
  if [[ -n "${TWINGATE_SERVICE_KEY:-}" ]]; then
    egress_preflight "$(printf '%s' "${TWINGATE_SERVICE_KEY}" | jq -r '.network // empty' 2>/dev/null)"
  fi
}

case "${1:-}" in
  install) cmd_install ;;
  start)   cmd_start ;;
  status)  cmd_status ;;
  stop)    cmd_stop ;;
  doctor)  cmd_doctor ;;
  *) echo "Usage: $0 {install|start|status|stop|doctor}" >&2; exit 2 ;;
esac
