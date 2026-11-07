#!/usr/bin/env bash
#
# ============================================================================
# DefenseOps - Wazuh Agent Installer Generator
# ============================================================================
# Version     : 1.3.2
# Release     : 2026-11-07
# Execution   : Run ONLY on the DefenseOps Manager server.
# Output      : <repository>/agent/output/ (excluded from Git)
# Target      : Debian/Ubuntu and RHEL-compatible Linux endpoints
#
# This generator does not inspect or modify Nginx/ModSecurity on DefenseOps.
# Brebes-WAF discovery is performed locally by install-agent.sh on the endpoint.
# Enrollment secrets are never embedded in the generated bundle.
# ============================================================================

set -Eeuo pipefail

SCRIPT_VERSION="1.3.2"
SCRIPT_RELEASE="2026-11-07"
VERSION="4.14.10"
MANAGER_PORT="1514"
REG_PORT="1515"
OUT_DIR=""
MANAGER_OVERRIDE=""

log(){ printf '[INFO] %s\n' "$*"; }
warn(){ printf '[WARN] %s\n' "$*" >&2; }
die(){ printf '[ERROR] %s\n' "$*" >&2; exit 1; }

usage(){
  cat <<'EOF'
Usage: sudo ./generate-agent-installer.sh [options]

Options:
  -m, --manager IP/FQDN    Override detected DefenseOps Manager address
  -o, --output DIR         Output directory (default: <repo>/agent/output)
  -V, --version            Show generator version
  -h, --help               Show help

The generated endpoint installer asks whether the endpoint is:
  1. Brebes-WAF
  2. Docker-PHP

Brebes-WAF Nginx and ModSecurity discovery runs on the endpoint itself.
Docker-PHP application-specific monitoring will be integrated later with
create-php-app.sh / delete-php-app.sh.
Enrollment secrets are never embedded in the bundle.
EOF
}

while (($#)); do
  case "$1" in
    -m|--manager)
      [[ $# -ge 2 ]] || die "Missing Manager address."
      MANAGER_OVERRIDE="$2"; shift 2 ;;
    -o|--output)
      [[ $# -ge 2 ]] || die "Missing output directory."
      OUT_DIR="$2"; shift 2 ;;
    -V|--version)
      printf 'DefenseOps Wazuh Agent Installer Generator v%s (%s)\n' "$SCRIPT_VERSION" "$SCRIPT_RELEASE"
      exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (use --help)." ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Run as root: sudo $0"
for cmd in ip ss awk tar sha256sum install; do
  command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
[[ -n "$OUT_DIR" ]] || OUT_DIR="${REPO_ROOT}/agent/output"

if [[ -n "$MANAGER_OVERRIDE" ]]; then
  MANAGER="$MANAGER_OVERRIDE"
else
  MANAGER="$(ip -4 route get 1.1.1.1 2>/dev/null |
    awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
fi

[[ -n "$MANAGER" ]] || die "Could not detect Manager IP. Use --manager IP/FQDN."
[[ "$MANAGER" =~ ^[A-Za-z0-9._:-]+$ ]] || die "Invalid Manager address: $MANAGER"

echo
echo "DefenseOps Agent deployment settings"
echo "  Manager address : $MANAGER"
echo "  Agent port      : ${MANAGER_PORT}/TCP"
echo "  Enrollment port : ${REG_PORT}/TCP"
echo "  Wazuh version   : ${VERSION}"
echo
read -r -p "Is this the correct DefenseOps Manager IP/address? [Y/n] " confirm
case "${confirm,,}" in
  n|no) die "Cancelled. Re-run with --manager IP/FQDN." ;;
esac

# Validate enrollment prerequisites only when the expected Manager container is
# present locally. Do not inspect, read, or copy the enrollment password.
MANAGER_CONTAINER="${WAZUH_MANAGER_CONTAINER:-defenseops-manager-wazuh.manager-1}"
if command -v docker >/dev/null 2>&1 && docker inspect "$MANAGER_CONTAINER" >/dev/null 2>&1; then
  AUTHD_PASS="$(docker exec "$MANAGER_CONTAINER" sh -c \
    'test -s /var/ossec/etc/authd.pass && echo yes || echo no' 2>/dev/null || echo no)"
  USE_PASSWORD="$(docker exec "$MANAGER_CONTAINER" sh -c \
    "grep -A12 '<auth>' /var/ossec/etc/ossec.conf | grep -m1 '<use_password>' | sed -E 's/.*>([^<]+).*/\\1/'" \
    2>/dev/null || true)"
  [[ "$AUTHD_PASS" == yes ]] || die "Manager authd.pass not found/empty in ${MANAGER_CONTAINER}."
  [[ "$USE_PASSWORD" == yes ]] || die "Manager auth config does not show use_password=yes."
else
  warn "Manager container '${MANAGER_CONTAINER}' not detected; skipping local authd prerequisite check."
fi

mkdir -p "$OUT_DIR"
chmod 0750 "$OUT_DIR"
mkdir -p "${OUT_DIR}/profiles/brebes-waf" "${OUT_DIR}/profiles/docker-php"
chmod 0750 "${OUT_DIR}/profiles" "${OUT_DIR}/profiles/brebes-waf" "${OUT_DIR}/profiles/docker-php"

TMP_CONF="$(mktemp)"
TMP_ARCHIVE=""
trap 'rm -f "$TMP_CONF" "${TMP_ARCHIVE:-}"' EXIT

cat > "$TMP_CONF" <<EOF
<ossec_config>
  <client>
    <server>
      <address>${MANAGER}</address>
      <port>${MANAGER_PORT}</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>linux</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>
  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>
</ossec_config>
EOF
install -o root -g root -m 0640 "$TMP_CONF" "${OUT_DIR}/ossec.conf"

# Endpoint-side installer. Existing vendor ossec.conf is retained. For
# Brebes-WAF, only discovered log paths and /etc/nginx FIM are added after
# backup, then validated before the Agent is started.
cat > "${OUT_DIR}/install-agent.sh" <<'INSTALLER'
#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="4.14.10"
MANAGER=""
REG_PORT="1515"
MANAGER_PORT="1514"
PROTOCOL="tcp"
CONFIG_FILE=""
AGENT_NAME=""
AGENT_GROUP=""
ENDPOINT_PROFILE=""

log(){ printf '[INFO] %s\n' "$*"; }
warn(){ printf '[WARN] %s\n' "$*" >&2; }
die(){ printf '[ERROR] %s\n' "$*" >&2; exit 1; }

usage(){
  cat <<'EOF'
Usage:
  sudo ./install-agent.sh [options]

Options:
  -m, --manager IP/FQDN    Wazuh Manager address (default: from ossec.conf)
  -n, --name NAME          Agent name (default: hostname)
  -g, --group GROUP        Existing Wazuh agent group (optional)
  -c, --config FILE        Generated ossec.conf (default: ./ossec.conf)
  -h, --help               Show help

At runtime, select Brebes-WAF or Docker-PHP.
Enrollment password is requested interactively and is never saved.
EOF
}

while (($#)); do
  case "$1" in
    -m|--manager) [[ $# -ge 2 ]] || die "Missing Manager address."; MANAGER="$2"; shift 2 ;;
    -n|--name) [[ $# -ge 2 ]] || die "Missing agent name."; AGENT_NAME="$2"; shift 2 ;;
    -g|--group) [[ $# -ge 2 ]] || die "Missing agent group."; AGENT_GROUP="$2"; shift 2 ;;
    -c|--config) [[ $# -ge 2 ]] || die "Missing config file."; CONFIG_FILE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (use --help)." ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Run as root."
command -v systemctl >/dev/null 2>&1 || die "systemd is required."
command -v curl >/dev/null 2>&1 || die "curl is required."

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ -n "$CONFIG_FILE" ]] || CONFIG_FILE="${SCRIPT_DIR}/ossec.conf"

if [[ -z "$MANAGER" && -f "$CONFIG_FILE" ]]; then
  MANAGER="$(sed -n 's:.*<address>\(.*\)</address>.*:\1:p' "$CONFIG_FILE" | head -n1)"
fi
[[ -n "$MANAGER" ]] || die "Manager address unavailable. Use --manager or provide ossec.conf."
[[ "$MANAGER" =~ ^[A-Za-z0-9._:-]+$ ]] || die "Invalid Manager address."
[[ -n "$AGENT_NAME" ]] || AGENT_NAME="$(hostname -s)"
[[ "$AGENT_NAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "Invalid agent name."

echo
echo "Select endpoint profile:"
echo "  [1] Brebes-WAF (Nginx + ModSecurity)"
echo "  [2] Docker-PHP (only Docker-PHP-managed applications)"
read -r -p "Select profile [1/2]: " profile_answer
case "$profile_answer" in
  1) ENDPOINT_PROFILE="brebes-waf" ;;
  2) ENDPOINT_PROFILE="docker-php" ;;
  *) die "Invalid profile selection. Choose 1 or 2." ;;
esac
log "Selected endpoint profile: ${ENDPOINT_PROFILE}"

# Do not replace an existing Agent installation.
if command -v dpkg-query >/dev/null 2>&1 &&
   dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null | grep -q 'install ok installed'; then
  die "wazuh-agent already installed; inspect the existing installation before proceeding."
fi
if command -v rpm >/dev/null 2>&1 && rpm -q wazuh-agent >/dev/null 2>&1; then
  die "wazuh-agent already installed; inspect the existing installation before proceeding."
fi

# Time settings are opt-in. Do not overwrite chrony/timesyncd configuration.
if command -v timedatectl >/dev/null 2>&1; then
  CURRENT_TZ="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
  echo "Current timezone: ${CURRENT_TZ:-unknown}"
  read -r -p "Change timezone to Asia/Jakarta? [y/N] " tz_answer
  case "${tz_answer,,}" in
    y|yes)
      timedatectl set-timezone Asia/Jakarta &&
        log "Timezone set to Asia/Jakarta." ||
        warn "Could not change timezone; inspect timedatectl."
      ;;
    *) log "Timezone unchanged." ;;
  esac

  NTP_STATE="$(timedatectl show -p NTP --value 2>/dev/null || true)"
  echo "Current NTP synchronization state: ${NTP_STATE:-unknown}"
  read -r -p "Enable NTP synchronization using the host's existing time-sync configuration? [y/N] " ntp_answer
  case "${ntp_answer,,}" in
    y|yes)
      timedatectl set-ntp true &&
        log "NTP synchronization enabled using the existing system provider/configuration." ||
        warn "Could not enable NTP; inspect timedatectl and the installed time-sync service."
      ;;
    *) log "NTP configuration unchanged." ;;
  esac
else
  warn "timedatectl unavailable; timezone and NTP settings were not changed."
fi

# ---------------------------------------------------------------------------
# Brebes-WAF endpoint-local discovery. nginx -T expands active include files,
# so discovery is performed on the WAF host, not on the DefenseOps generator.
# ---------------------------------------------------------------------------
declare -A NGINX_LOGS=()
declare -A MODSEC_LOGS=()
declare -A SEEN_MODSEC=()

trim_directive_value(){
  local value="$1"
  value="${value%%#*}"
  value="${value%;}"
  value="${value%\"}"; value="${value#\"}"
  value="${value%\'}"; value="${value#\'}"
  printf '%s' "$value"
}

add_log_path(){
  local target="$1" value="$2"
  [[ -n "$value" ]] || return 0
  [[ "$value" == off || "$value" == syslog:* || "$value" == pipe:* ]] && return 0
  [[ "$value" == /* ]] || return 0
  [[ "$value" == *'$'* || "$value" == *' '* ]] && return 0
  if [[ "$target" == nginx ]]; then
    NGINX_LOGS["$value"]=1
  else
    MODSEC_LOGS["$value"]=1
  fi
}

discover_modsecurity_file(){
  local initial="$1"
  local -a queue=()
  local current line directive value base expanded
  queue+=("$initial")

  while ((${#queue[@]})); do
    current="${queue[0]}"
    queue=("${queue[@]:1}")
    [[ -r "$current" && -f "$current" ]] || continue
    [[ -n "${SEEN_MODSEC[$current]:-}" ]] && continue
    SEEN_MODSEC["$current"]=1
    base="$(dirname -- "$current")"

    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      read -r directive value _ <<< "$line"
      [[ -n "${directive:-}" && -n "${value:-}" ]] || continue
      value="$(trim_directive_value "$value")"

      case "$directive" in
        SecAuditLog|SecDebugLog)
          add_log_path modsec "$value"
          ;;
        Include)
          if [[ "$value" != /* ]]; then
            value="${base}/${value}"
          fi
          if [[ "$value" == *'*'* || "$value" == *'?'* || "$value" == *'['* ]]; then
            while IFS= read -r expanded; do
              [[ -n "$expanded" && -f "$expanded" ]] && queue+=("$expanded")
            done < <(compgen -G "$value" || true)
          elif [[ -f "$value" ]]; then
            queue+=("$value")
          fi
          ;;
      esac
    done < "$current"
  done
}

discover_brebes_waf(){
  local dump_file line directive value modsec_file
  local nginx_ok=0
  command -v nginx >/dev/null 2>&1 || die "Brebes-WAF profile selected, but nginx command was not found."
  dump_file="$(mktemp)"
  if ! nginx -T >"$dump_file" 2>&1; then
    cat "$dump_file" >&2
    rm -f "$dump_file"
    die "nginx -T failed. Fix/check Nginx configuration before installing the WAF profile."
  fi
  nginx_ok=1

  # nginx -T output includes the active configuration and all expanded includes.
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    read -r directive value _ <<< "$line"
    [[ -n "${directive:-}" && -n "${value:-}" ]] || continue
    case "$directive" in
      access_log|error_log)
        value="$(trim_directive_value "$value")"
        add_log_path nginx "$value"
        ;;
      modsecurity_rules_file)
        modsec_file="$(trim_directive_value "$value")"
        [[ "$modsec_file" == /* && -r "$modsec_file" ]] &&
          discover_modsecurity_file "$modsec_file"
        ;;
    esac
  done < "$dump_file"
  rm -f "$dump_file"

  (( nginx_ok == 1 )) || die "Nginx configuration discovery failed."
  ((${#NGINX_LOGS[@]} > 0)) ||
    warn "No static Nginx access_log/error_log paths found in nginx -T output."
  ((${#MODSEC_LOGS[@]} > 0)) ||
    warn "No SecAuditLog/SecDebugLog paths found in referenced ModSecurity files."
}

# Discover before package installation, so a failed WAF inspection does not
# leave a partially installed Agent behind.
if [[ "$ENDPOINT_PROFILE" == "brebes-waf" ]]; then
  log "Reading active Nginx configuration and included ModSecurity files on this endpoint..."
  discover_brebes_waf
  log "Discovery result: ${#NGINX_LOGS[@]} Nginx log path(s), ${#MODSEC_LOGS[@]} ModSecurity log path(s)."
else
  log "Docker-PHP base profile selected."
  log "No global Docker container logs will be collected."
  log "Per-application monitoring will be registered later by create-php-app.sh."
fi

read -r -s -p "Enrollment password for DefenseOps: " REG_PASSWORD
printf '\n'
[[ -n "$REG_PASSWORD" ]] || die "Enrollment password cannot be empty."

cleanup(){
  unset REG_PASSWORD WAZUH_REGISTRATION_PASSWORD 2>/dev/null || true
}
trap cleanup EXIT

export WAZUH_MANAGER="$MANAGER"
export WAZUH_REGISTRATION_SERVER="$MANAGER"
export WAZUH_MANAGER_PORT="$MANAGER_PORT"
export WAZUH_REGISTRATION_PORT="$REG_PORT"
export WAZUH_PROTOCOL="$PROTOCOL"
export WAZUH_REGISTRATION_PASSWORD="$REG_PASSWORD"
export WAZUH_AGENT_NAME="$AGENT_NAME"
[[ -n "$AGENT_GROUP" ]] && export WAZUH_AGENT_GROUP="$AGENT_GROUP" || true

[[ -r /etc/os-release ]] || die "Cannot identify Linux distribution."
. /etc/os-release

case "${ID:-}" in
  ubuntu|debian|linuxmint|pop)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y curl gnupg apt-transport-https
    install -d -m 0755 /usr/share/keyrings
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH |
      gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg
    chmod 0644 /usr/share/keyrings/wazuh.gpg
    printf '%s\n' \
      'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' \
      > /etc/apt/sources.list.d/wazuh.list
    apt-get update
    apt-get install -y "wazuh-agent=${VERSION}-1"
    ;;
  rhel|rocky|almalinux|centos|ol|fedora|amzn)
    command -v rpm >/dev/null 2>&1 || die "rpm command not found."
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    install -d -m 0755 /etc/yum.repos.d
    cat > /etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
priority=1
EOF
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y "wazuh-agent-${VERSION}-1"
    else
      yum install -y "wazuh-agent-${VERSION}-1"
    fi
    ;;
  *)
    die "Unsupported distribution: ${ID:-unknown}. Supported: Debian/Ubuntu and RHEL-compatible."
    ;;
esac

[[ -s /var/ossec/etc/ossec.conf ]] ||
  die "Wazuh package did not create /var/ossec/etc/ossec.conf."
[[ -x /var/ossec/bin/wazuh-agentd ]] ||
  die "Wazuh Agent daemon binary not found."

# Add only profile-specific local collection config. Keep the vendor file and
# all existing settings; backup first, stage in the same directory, validate,
# then atomically activate. Restore backup on validation failure.
AGENT_CONF="/var/ossec/etc/ossec.conf"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="${AGENT_CONF}.pre-defenseops-${ENDPOINT_PROFILE}.${STAMP}"
TMP_AGENT_CONF="$(mktemp "${AGENT_CONF}.tmp.XXXXXX")"
PROFILE_BLOCK="$(mktemp)"
cleanup_files(){
  rm -f "${TMP_AGENT_CONF:-}" "${PROFILE_BLOCK:-}"
  cleanup
}
trap cleanup_files EXIT

if [[ "$ENDPOINT_PROFILE" == "brebes-waf" ]]; then
  {
    echo '<ossec_config>'
    for path in "${!NGINX_LOGS[@]}"; do
      escaped="${path//&/\\&amp;}"
      printf '  <localfile><location>%s</location><log_format>syslog</log_format></localfile>\n' "$escaped"
    done
    for path in "${!MODSEC_LOGS[@]}"; do
      escaped="${path//&/\\&amp;}"
      printf '  <localfile><location>%s</location><log_format>syslog</log_format></localfile>\n' "$escaped"
    done
    echo '  <syscheck>'
    echo '    <disabled>no</disabled>'
    echo '    <frequency>43200</frequency>'
    echo '    <scan_on_start>yes</scan_on_start>'
    echo '    <directories realtime="yes">/etc/nginx</directories>'
    echo '    <ignore type="sregex">.log$|.tmp$|.swp$</ignore>'
    echo '  </syscheck>'
    echo '</ossec_config>'
  } > "$PROFILE_BLOCK"

  cp -a "$AGENT_CONF" "$BACKUP"
  {
    cat "$AGENT_CONF"
    printf '\\n'
    cat "$PROFILE_BLOCK"
  } > "$TMP_AGENT_CONF"
  chown --reference="$AGENT_CONF" "$TMP_AGENT_CONF"
  chmod --reference="$AGENT_CONF" "$TMP_AGENT_CONF"

  systemctl stop wazuh-agent 2>/dev/null || true
  install -o "$(stat -c '%u' "$AGENT_CONF")" \\
    -g "$(stat -c '%g' "$AGENT_CONF")" \\
    -m "$(stat -c '%a' "$AGENT_CONF")" \\
    "$TMP_AGENT_CONF" "$AGENT_CONF"

  if ! /var/ossec/bin/wazuh-agentd -t; then
    warn "Wazuh Agent configuration validation failed. Restoring original configuration."
    cp -a "$BACKUP" "$AGENT_CONF"
    systemctl start wazuh-agent 2>/dev/null || true
    die "Invalid Agent configuration. Original ossec.conf restored from ${BACKUP}."
  fi

  log "Agent configuration validated."
  log "Original configuration backup: ${BACKUP}"
else
  # Docker-PHP does not collect unrelated containers or assume application
  # paths. Keep the vendor configuration intact until create-php-app.sh
  # registers concrete paths for an application it creates.
  log "Docker-PHP selected: vendor ossec.conf will remain unchanged."
fi

# Keep package version aligned with the Manager release.
if command -v apt-mark >/dev/null 2>&1; then
  apt-mark hold wazuh-agent >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  dnf versionlock add wazuh-agent >/dev/null 2>&1 ||
    warn "Could not apply DNF versionlock; manage Agent updates manually."
fi

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent
unset WAZUH_REGISTRATION_PASSWORD REG_PASSWORD
sleep 3

if systemctl is-active --quiet wazuh-agent; then
  log "Wazuh Agent service is active."
else
  systemctl --no-pager --full status wazuh-agent || true
  die "Wazuh Agent did not become active. Check /var/ossec/logs/ossec.log."
fi

log "Installed Wazuh Agent version: $(/var/ossec/bin/wazuh-agentd -V 2>&1 | head -n1 || true)"
log "Endpoint profile: ${ENDPOINT_PROFILE}"
log "Manager: ${MANAGER}:${MANAGER_PORT}/TCP; enrollment: ${MANAGER}:${REG_PORT}/TCP"
log "Agent name: ${AGENT_NAME}"
if [[ "$ENDPOINT_PROFILE" == "docker-php" ]]; then
  log "Docker-PHP application monitoring is not yet registered."
  log "It will be integrated into create-php-app.sh / delete-php-app.sh."
fi
log "Verify this endpoint appears as Active in the DefenseOps Dashboard."
INSTALLER

chown root:root "${OUT_DIR}/install-agent.sh"
chmod 0750 "${OUT_DIR}/install-agent.sh"

# Keep central profile artifacts for explicit publishing. Actual Brebes-WAF log
# paths are endpoint-local and are intentionally NOT guessed on DefenseOps.
cat > "${OUT_DIR}/profiles/brebes-waf/agent.conf" <<'PROFILE_WAF'
<!-- DefenseOps Brebes-WAF group profile.
     Nginx/ModSecurity log paths are discovered locally by install-agent.sh
     and added to the endpoint's local ossec.conf after backup and validation. -->
<agent_config os="^Linux">
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories realtime="yes">/etc/nginx</directories>
    <ignore type="sregex">.log$|.tmp$|.swp$</ignore>
  </syscheck>
</agent_config>
PROFILE_WAF
chmod 0640 "${OUT_DIR}/profiles/brebes-waf/agent.conf"

cat > "${OUT_DIR}/profiles/docker-php/agent.conf" <<'PROFILE_DOCKERPHP'
<!-- DefenseOps Docker-PHP group profile.
     No global Docker container logs or unrelated containers are monitored.
     Per-application paths will be registered by create-php-app.sh integration. -->
<agent_config os="^Linux">
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
  </syscheck>
</agent_config>
PROFILE_DOCKERPHP
chmod 0640 "${OUT_DIR}/profiles/docker-php/agent.conf"

# Publish only the two focused groups; stage and validate before replacement.
cat > "${OUT_DIR}/deploy-agent-profiles.sh" <<'DEPLOY'
#!/usr/bin/env bash
set -Eeuo pipefail
CONTAINER="${WAZUH_MANAGER_CONTAINER:-defenseops-manager-wazuh.manager-1}"
BUNDLE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GROUPS=(brebes-waf docker-php)
die(){ echo "[ERROR] $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run on DefenseOps host as root."
command -v docker >/dev/null 2>&1 || die "Docker CLI required."
docker inspect "$CONTAINER" >/dev/null 2>&1 || die "Manager container not found: $CONTAINER"
docker exec "$CONTAINER" test -x /var/ossec/bin/verify-agent-conf ||
  die "verify-agent-conf unavailable."

echo "This publishes the two DefenseOps profiles to ${CONTAINER}. Existing files are backed up."
read -r -p "Continue? [y/N] " answer
[[ "${answer,,}" == y || "${answer,,}" == yes ]] || { echo "Cancelled."; exit 0; }

STAMP="$(date +%Y%m%d-%H%M%S)"
for group in "${GROUPS[@]}"; do
  src="${BUNDLE_DIR}/profiles/${group}/agent.conf"
  [[ -s "$src" ]] || die "Missing profile: $src"
  if ! docker exec "$CONTAINER" /var/ossec/bin/agent_groups -l 2>/dev/null |
       grep -Eq "^[[:space:]]*${group}([[:space:]]|$)"; then
    docker exec "$CONTAINER" /var/ossec/bin/agent_groups -a -g "$group" -q
  fi
  dir="/var/ossec/etc/shared/${group}"
  tmp="${dir}/agent.conf.tmp.${STAMP}"
  docker exec "$CONTAINER" install -d -o wazuh -g wazuh -m 0750 "$dir"
  docker cp "$src" "${CONTAINER}:${tmp}"
  docker exec "$CONTAINER" chown wazuh:wazuh "$tmp"
  docker exec "$CONTAINER" chmod 0660 "$tmp"
  docker exec "$CONTAINER" /var/ossec/bin/verify-agent-conf -f "$tmp"
  if docker exec "$CONTAINER" test -f "${dir}/agent.conf"; then
    docker exec "$CONTAINER" cp -a "${dir}/agent.conf" "${dir}/agent.conf.bak.${STAMP}"
  fi
  docker exec "$CONTAINER" mv -f "$tmp" "${dir}/agent.conf"
  docker exec "$CONTAINER" chown wazuh:wazuh "${dir}/agent.conf"
  docker exec "$CONTAINER" chmod 0660 "${dir}/agent.conf"
  echo "[INFO] Published profile: ${group}"
done
echo "[INFO] Profiles published. Assign group membership to agents separately."
DEPLOY
chmod 0750 "${OUT_DIR}/deploy-agent-profiles.sh"

cat > "${OUT_DIR}/README.txt" <<EOF
DefenseOps Agent Deployment - Brebes-WAF & Docker-PHP
====================================================
Generator    : v${SCRIPT_VERSION} (${SCRIPT_RELEASE})
Wazuh Agent  : ${VERSION}
Manager      : ${MANAGER}
Agent port   : ${MANAGER_PORT}/TCP
Enrollment   : ${REG_PORT}/TCP

Bundle:
  install-agent.sh
  ossec.conf
  profiles/brebes-waf/agent.conf
  profiles/docker-php/agent.conf
  deploy-agent-profiles.sh

Endpoint installation:
  sudo ./install-agent.sh [--name HOSTNAME]
  Select Brebes-WAF or Docker-PHP when prompted.

Brebes-WAF:
  Discovery runs on the Brebes-WAF endpoint using nginx -T, which expands active
  Nginx include files. Referenced ModSecurity rule files and their Include
  directives are read recursively. Concrete absolute access_log/error_log,
  SecAuditLog and SecDebugLog paths are collected.
  The installer backs up /var/ossec/etc/ossec.conf, stages the updated file,
  validates it with wazuh-agentd -t, and restores the backup if validation fails.
  Nginx and ModSecurity configuration files are never modified.

Docker-PHP:
  The base profile does not collect global Docker JSON logs or unrelated
  containers. Application-specific monitoring will be integrated later with
  create-php-app.sh / delete-php-app.sh.

Time settings:
  The installer asks independently whether to change timezone to Asia/Jakarta
  and whether to enable NTP using the host's existing time-sync configuration.
  It does not overwrite chrony/timesyncd configuration files.

Security:
  Enrollment password is requested interactively and is never stored in bundle.
  Existing Agent installations are not overwritten.

Central profiles:
  Publish explicitly with sudo ./deploy-agent-profiles.sh.
  Existing shared agent.conf files are backed up before replacement.
  Assign Agent group membership separately after enrollment.
EOF
chmod 0640 "${OUT_DIR}/README.txt"

command -v tar >/dev/null 2>&1 || die "tar is required."
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required."

ARCHIVE_STAMP="$(date +%Y%m%d-%H%M%S)"
ARCHIVE_NAME="defenseops-agent-bundle-wazuh-${VERSION}-${ARCHIVE_STAMP}.tar.gz"
ARCHIVE_PATH="${OUT_DIR}/${ARCHIVE_NAME}"
CHECKSUM_PATH="${ARCHIVE_PATH}.sha256"
TMP_ARCHIVE="$(mktemp "${OUT_DIR}/.defenseops-agent-bundle.XXXXXX")"

tar -czf "$TMP_ARCHIVE" -C "$OUT_DIR" \
  install-agent.sh ossec.conf README.txt profiles deploy-agent-profiles.sh
chmod 0640 "$TMP_ARCHIVE"
mv -f "$TMP_ARCHIVE" "$ARCHIVE_PATH"
TMP_ARCHIVE=""

(
  cd "$OUT_DIR"
  sha256sum "$ARCHIVE_NAME" > "${ARCHIVE_NAME}.sha256"
)
chmod 0640 "$CHECKSUM_PATH"

log "Deployment bundle generated:"
printf '  Output  : %s\n' "$OUT_DIR"
printf '  Archive : %s\n' "$ARCHIVE_PATH"
printf '  SHA256  : %s\n' "$CHECKSUM_PATH"
log "Profiles: brebes-waf, docker-php. Nginx discovery is endpoint-local."
log "No enrollment secret was copied or embedded."
