#!/usr/bin/env bash
#
# ============================================================================
# DefenseOps - Wazuh Agent Installer Generator
# ============================================================================
# Description : Generate a deployment bundle for enrolling Linux endpoints
#               into the DefenseOps Wazuh Manager.
#
# Version     : 1.2.2
# Release     : 2026-11-07
# Maintainer  : DefenseOps
#
# Execution   : Run this script ONLY on the DefenseOps Manager server.
# Output      : <repository>/agent/output/ (ignored by Git)
# Target      : Linux endpoints (Debian/Ubuntu and RHEL-compatible)
#
# Requirements:
#   - Bash 4+
#   - Root privileges
#   - iproute2 (ip command)
#   - iproute2/ss (ss command)
#   - Docker CLI (optional; used to validate Manager enrollment configuration)
#
# Network:
#   - Agent communication : TCP/1514
#   - Agent enrollment    : TCP/1515
#
# Security:
#   - Enrollment password is NOT embedded in the generated bundle.
#   - Password is entered interactively by install-agent.sh on the endpoint.
#
# Usage:
#   sudo ./generate-agent-installer.sh
#   sudo ./generate-agent-installer.sh --manager 15.0.90.3
#   sudo ./generate-agent-installer.sh --output /path/to/output
#
# ============================================================================
set -Eeuo pipefail

SCRIPT_VERSION="1.3.1"
SCRIPT_RELEASE="2026-11-07"
OUT_DIR=""
MANAGER_OVERRIDE=""
VERSION="4.14.10"
MANAGER_PORT="1514"
REG_PORT="1515"

log(){ printf '[INFO] %s\n' "$*"; }
warn(){ printf '[WARN] %s\n' "$*" >&2; }
die(){ printf '[ERROR] %s\n' "$*" >&2; exit 1; }

usage(){
  cat <<'EOF'
Usage: sudo ./generate-agent-installer.sh [options]
  -m, --manager IP/FQDN       Override detected Wazuh Manager address
  -o, --output DIR            Output directory (default: <repo>/agent/output)
  -V, --version               Show version
  -h, --help                  Show help

Generates focused profiles only:
  profiles/brebes-waf/agent.conf
  profiles/docker-php/agent.conf
Enrollment secrets are never embedded in the bundle.
EOF
}

while (($#)); do
  case "$1" in
    -m|--manager) [[ $# -ge 2 ]] || die "Missing manager address"; MANAGER_OVERRIDE="$2"; shift 2 ;;
    -o|--output) [[ $# -ge 2 ]] || die "Missing output directory"; OUT_DIR="$2"; shift 2 ;;
    -V|--version) echo "DefenseOps Wazuh Agent Installer Generator v${SCRIPT_VERSION} (${SCRIPT_RELEASE})"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Run as root: sudo $0"
command -v ip >/dev/null 2>&1 || die "iproute2 (ip command) is required."
command -v ss >/dev/null 2>&1 || die "ss command is required."
command -v awk >/dev/null 2>&1 || die "awk is required."
command -v find >/dev/null 2>&1 || die "find is required."

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
[[ -n "$OUT_DIR" ]] || OUT_DIR="${REPO_ROOT}/agent/output"
if [[ -n "$MANAGER_OVERRIDE" ]]; then
  MANAGER="$MANAGER_OVERRIDE"
else
  MANAGER="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
fi
[[ -n "$MANAGER" ]] || die "Could not detect Manager IP. Specify --manager."
[[ "$MANAGER" =~ ^[A-Za-z0-9._:-]+$ ]] || die "Invalid Manager address: $MANAGER"

echo
echo "DefenseOps Agent deployment settings"
echo "  Manager address : $MANAGER"
echo "  Agent port      : ${MANAGER_PORT}/TCP"
echo "  Enrollment port : ${REG_PORT}/TCP"
echo "  Wazuh version   : ${VERSION}"
echo
read -r -p "Is this the correct DefenseOps Manager IP/address? [Y/n] " confirm
case "${confirm,,}" in n|no) die "Cancelled. Re-run with --manager IP/FQDN." ;; esac

# Validate Manager enrollment prerequisites when the expected Manager container exists.
MANAGER_CONTAINER="${WAZUH_MANAGER_CONTAINER:-defenseops-manager-wazuh.manager-1}"
if command -v docker >/dev/null 2>&1 && docker inspect "$MANAGER_CONTAINER" >/dev/null 2>&1; then
  AUTHD_PASS="$(docker exec "$MANAGER_CONTAINER" sh -c 'test -s /var/ossec/etc/authd.pass && echo yes || echo no' 2>/dev/null || echo no)"
  USE_PASSWORD="$(docker exec "$MANAGER_CONTAINER" sh -c "grep -A12 '<auth>' /var/ossec/etc/ossec.conf | grep -m1 '<use_password>' | sed -E 's/.*>([^<]+).*/\1/'" 2>/dev/null || true)"
  [[ "$AUTHD_PASS" == yes ]] || die "Manager authd.pass not found/empty in ${MANAGER_CONTAINER}."
  [[ "$USE_PASSWORD" == yes ]] || die "Manager auth config does not show use_password=yes."
else
  warn "Manager container '${MANAGER_CONTAINER}' not detected; skipping local authd prerequisite check."
fi

# Collect only concrete log paths declared by the existing Brebes-WAF Nginx and
# ModSecurity configuration. Never invent a path or edit the live configuration.
declare -A NGINX_LOGS=() MODSEC_LOGS=()
trim_value(){
  local v="$1"
  v="${v%%#*}"
  v="${v%;}"
  v="${v%\"}"; v="${v#\"}"
  v="${v%\'}"; v="${v#\'}"
  printf '%s' "$v"
}
add_log_path(){
  local target="$1" value="$2"
  [[ -n "$value" ]] || return 0
  [[ "$value" == off || "$value" == syslog:* || "$value" == pipe:* ]] && return 0
  [[ "$value" == /* ]] || return 0
  [[ "$value" == *'$'* ]] && return 0
  [[ "$value" == *' '* ]] && return 0
  if [[ "$target" == nginx ]]; then NGINX_LOGS["$value"]=1; else MODSEC_LOGS["$value"]=1; fi
}

# Automatically inspect common Nginx site-configuration directories. No
# command-line directory override is exposed; active nginx -T output below is
# also inspected to catch included files outside these conventional locations.
NGINX_SITES_DIR=""
for candidate in /etc/nginx/site-enable /etc/nginx/sites-enabled /etc/nginx/conf.d; do
  if [[ -d "$candidate" ]]; then
    NGINX_SITES_DIR="$candidate"
    break
  fi
done

CONFIG_FILES=()
if [[ -n "$NGINX_SITES_DIR" ]]; then
  while IFS= read -r -d '' f; do CONFIG_FILES+=("$f"); done < <(find "$NGINX_SITES_DIR" -maxdepth 3 \( -type f -o -type l \) -print0 2>/dev/null | sort -z)
else
  warn "No conventional Nginx site directory found; will rely on nginx -T output if Nginx is installed."
fi

# Also inspect the active Nginx dump, if available, to capture included files
# that may be outside the site directory. Output is read-only.
NGINX_DUMP=""
if command -v nginx >/dev/null 2>&1; then
  NGINX_DUMP="$(nginx -T 2>/dev/null || true)"
fi

parse_nginx_text(){
  awk '
    /^[[:space:]]*#/ {next}
    {
      line=$0
      if (line ~ /^[[:space:]]*access_log[[:space:]]+/) {
        sub(/^[[:space:]]*access_log[[:space:]]+/, "", line); n=split(line,a,/[[:space:]]+/); print "ACCESS|" a[1]
      }
      if (line ~ /^[[:space:]]*error_log[[:space:]]+/) {
        sub(/^[[:space:]]*error_log[[:space:]]+/, "", line); n=split(line,a,/[[:space:]]+/); print "ERROR|" a[1]
      }
      if (line ~ /^[[:space:]]*modsecurity_rules_file[[:space:]]+/) {
        sub(/^[[:space:]]*modsecurity_rules_file[[:space:]]+/, "", line); n=split(line,a,/[[:space:]]+/); print "MODSECFILE|" a[1]
      }
    }
  '
}
MODSEC_FILES=()
for f in "${CONFIG_FILES[@]}"; do
  [[ -r "$f" ]] || continue
  while IFS='|' read -r kind val; do
    case "$kind" in
      ACCESS|ERROR) add_log_path nginx "$(trim_value "$val")" ;;
      MODSECFILE)
        val="$(trim_value "$val")"
        [[ "$val" == /* && -r "$val" ]] && MODSEC_FILES+=("$val")
        ;;
    esac
  done < <(parse_nginx_text < "$f")
done
if [[ -n "$NGINX_DUMP" ]]; then
  while IFS='|' read -r kind val; do
    case "$kind" in
      ACCESS|ERROR) add_log_path nginx "$(trim_value "$val")" ;;
      MODSECFILE)
        val="$(trim_value "$val")"
        [[ "$val" == /* && -r "$val" ]] && MODSEC_FILES+=("$val")
        ;;
    esac
  done < <(printf '%s\n' "$NGINX_DUMP" | parse_nginx_text)
fi

# Read ModSecurity config files referenced by Nginx. Follow Include directives
# for explicit absolute paths only; avoid broad filesystem crawling.
seen_modsec=()
while ((${#MODSEC_FILES[@]})); do
  f="${MODSEC_FILES[0]}"; MODSEC_FILES=("${MODSEC_FILES[@]:1}")
  [[ -r "$f" ]] || continue
  skip=0; for seen in "${seen_modsec[@]:-}"; do [[ "$seen" == "$f" ]] && skip=1; done
  (( skip )) && continue
  seen_modsec+=("$f")
  while IFS='|' read -r kind val; do
    val="$(trim_value "$val")"
    case "$kind" in
      AUDIT|DEBUG) add_log_path modsec "$val" ;;
      INCLUDE) [[ "$val" == /* && -r "$val" ]] && MODSEC_FILES+=("$val") ;;
    esac
  done < <(awk '
    /^[[:space:]]*#/ {next}
    /^[[:space:]]*SecAuditLog[[:space:]]+/ {v=$2; print "AUDIT|" v}
    /^[[:space:]]*SecDebugLog[[:space:]]+/ {v=$2; print "DEBUG|" v}
    /^[[:space:]]*Include[[:space:]]+/ {v=$2; print "INCLUDE|" v}
  ' "$f")
done

mkdir -p "$OUT_DIR"
chmod 0750 "$OUT_DIR"
mkdir -p "${OUT_DIR}/profiles/brebes-waf" "${OUT_DIR}/profiles/docker-php"
chmod 0750 "${OUT_DIR}/profiles" "${OUT_DIR}/profiles/brebes-waf" "${OUT_DIR}/profiles/docker-php"

TMP_CONF="$(mktemp)"; TMP_ARCHIVE=""
trap 'rm -f "$TMP_CONF" "${TMP_ARCHIVE:-}"' EXIT
cat > "$TMP_CONF" <<EOF
<ossec_config>
  <client>
    <server><address>${MANAGER}</address><port>${MANAGER_PORT}</port><protocol>tcp</protocol></server>
    <config-profile>linux</config-profile>
    <notify_time>10</notify_time><time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart><crypto_method>aes</crypto_method>
  </client>
  <client_buffer><disabled>no</disabled><queue_size>5000</queue_size><events_per_second>500</events_per_second></client_buffer>
</ossec_config>
EOF
install -o root -g root -m 0640 "$TMP_CONF" "${OUT_DIR}/ossec.conf"

# Endpoint installer. It preserves package-provided ossec.conf and asks before
# changing timezone or enabling the system's existing NTP synchronization.
cat > "${OUT_DIR}/install-agent.sh" <<'INSTALLER'
#!/usr/bin/env bash
set -Eeuo pipefail
VERSION="4.14.10"; MANAGER=""; REG_PORT="1515"; MANAGER_PORT="1514"; PROTOCOL="tcp"
CONFIG_FILE=""; AGENT_NAME=""; AGENT_GROUP=""
log(){ printf '[INFO] %s\n' "$*"; }; warn(){ printf '[WARN] %s\n' "$*" >&2; }; die(){ printf '[ERROR] %s\n' "$*" >&2; exit 1; }
usage(){ cat <<'EOF'
Usage: sudo ./install-agent.sh [options]
  -m, --manager IP/FQDN   Manager address (default: from ossec.conf)
  -n, --name NAME         Agent name (default: hostname)
  -g, --group GROUP       Existing Wazuh agent group (optional)
  -c, --config FILE       Generated ossec.conf (default: ./ossec.conf)
  -h, --help              Show help
EOF
}
while (($#)); do case "$1" in
  -m|--manager) [[ $# -ge 2 ]] || die "Missing manager"; MANAGER="$2"; shift 2;;
  -n|--name) [[ $# -ge 2 ]] || die "Missing agent name"; AGENT_NAME="$2"; shift 2;;
  -g|--group) [[ $# -ge 2 ]] || die "Missing agent group"; AGENT_GROUP="$2"; shift 2;;
  -c|--config) [[ $# -ge 2 ]] || die "Missing config"; CONFIG_FILE="$2"; shift 2;;
  -h|--help) usage; exit 0;; *) die "Unknown option: $1";; esac; done
[[ $EUID -eq 0 ]] || die "Run as root."
command -v systemctl >/dev/null 2>&1 || die "systemd is required."
command -v curl >/dev/null 2>&1 || die "curl is required."
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ -n "$CONFIG_FILE" ]] || CONFIG_FILE="${SCRIPT_DIR}/ossec.conf"
if [[ -z "$MANAGER" && -f "$CONFIG_FILE" ]]; then MANAGER="$(sed -n 's:.*<address>\(.*\)</address>.*:\1:p' "$CONFIG_FILE" | head -n1)"; fi
[[ -n "$MANAGER" ]] || die "Manager unavailable; use --manager or provide ossec.conf."
[[ "$MANAGER" =~ ^[A-Za-z0-9._:-]+$ ]] || die "Invalid Manager address."
[[ -n "$AGENT_NAME" ]] || AGENT_NAME="$(hostname -s)"
[[ "$AGENT_NAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "Invalid agent name."

# Refuse to overwrite an existing Agent installation.
if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null | grep -q 'install ok installed'; then die "wazuh-agent already installed; inspect it before proceeding."; fi
if command -v rpm >/dev/null 2>&1 && rpm -q wazuh-agent >/dev/null 2>&1; then die "wazuh-agent already installed; inspect it before proceeding."; fi

# Time settings are opt-in and independent. No chrony/timesyncd config files
# are overwritten; NTP simply enables the host's currently configured provider.
if command -v timedatectl >/dev/null 2>&1; then
  CURRENT_TZ="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
  echo "Current timezone: ${CURRENT_TZ:-unknown}"
  read -r -p "Change timezone to Asia/Jakarta? [y/N] " tz_answer
  case "${tz_answer,,}" in y|yes) timedatectl set-timezone Asia/Jakarta && log "Timezone set to Asia/Jakarta." || warn "Could not change timezone.";; *) log "Timezone unchanged.";; esac
  NTP_STATE="$(timedatectl show -p NTP --value 2>/dev/null || true)"
  echo "Current NTP synchronization state: ${NTP_STATE:-unknown}"
  read -r -p "Enable NTP synchronization using the host's existing time-sync configuration? [y/N] " ntp_answer
  case "${ntp_answer,,}" in
    y|yes) timedatectl set-ntp true && log "NTP synchronization enabled using the existing system provider/configuration." || warn "Could not enable NTP; inspect timedatectl and the installed time-sync service.";;
    *) log "NTP configuration unchanged.";;
  esac
else
  warn "timedatectl unavailable; timezone and NTP settings were not changed."
fi

read -r -s -p "Enrollment password for DefenseOps: " REG_PASSWORD; printf '\n'
[[ -n "$REG_PASSWORD" ]] || die "Enrollment password cannot be empty."
cleanup(){ unset REG_PASSWORD; }; trap cleanup EXIT
export WAZUH_MANAGER="$MANAGER" WAZUH_REGISTRATION_SERVER="$MANAGER"
export WAZUH_MANAGER_PORT="$MANAGER_PORT" WAZUH_REGISTRATION_PORT="$REG_PORT" WAZUH_PROTOCOL="$PROTOCOL"
export WAZUH_REGISTRATION_PASSWORD="$REG_PASSWORD" WAZUH_AGENT_NAME="$AGENT_NAME"
[[ -n "$AGENT_GROUP" ]] && export WAZUH_AGENT_GROUP="$AGENT_GROUP" || true
. /etc/os-release
case "${ID:-}" in
  ubuntu|debian|linuxmint|pop)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y curl gnupg apt-transport-https
    install -d -m 0755 /usr/share/keyrings
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg
    chmod 0644 /usr/share/keyrings/wazuh.gpg
    printf '%s\n' 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list
    apt-get update
    apt-get install -y "wazuh-agent=${VERSION}-1"
    ;;
  rhel|rocky|almalinux|centos|ol|fedora|amzn)
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
    if command -v dnf >/dev/null 2>&1; then dnf install -y "wazuh-agent-${VERSION}-1"; else yum install -y "wazuh-agent-${VERSION}-1"; fi
    ;;
  *) die "Unsupported distribution: ${ID:-unknown}.";;
esac
[[ -s /var/ossec/etc/ossec.conf ]] || die "Wazuh package did not create /var/ossec/etc/ossec.conf."
if command -v apt-mark >/dev/null 2>&1; then apt-mark hold wazuh-agent >/dev/null; elif command -v dnf >/dev/null 2>&1; then dnf versionlock add wazuh-agent >/dev/null 2>&1 || warn "Could not apply DNF versionlock."; fi
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent
unset WAZUH_REGISTRATION_PASSWORD REG_PASSWORD; trap - EXIT
sleep 3
systemctl is-active --quiet wazuh-agent || { systemctl --no-pager --full status wazuh-agent || true; die "Agent service failed; inspect /var/ossec/logs/ossec.log."; }
log "Wazuh Agent service is active."
log "Version: $(/var/ossec/bin/wazuh-agentd -V 2>&1 | head -n1 || true)"
log "Manager: ${MANAGER}:${MANAGER_PORT}/TCP; enrollment: ${MANAGER}:${REG_PORT}/TCP; agent: ${AGENT_NAME}"
log "Verify the endpoint appears Active in DefenseOps Dashboard."
INSTALLER
chown root:root "${OUT_DIR}/install-agent.sh"; chmod 0750 "${OUT_DIR}/install-agent.sh"

# Brebes-WAF group: emit only log paths actually discovered from existing site
# configs and ModSecurity rule files. Paths are XML-escaped before insertion.
xml_escape(){ local x="$1"; x="${x//&/\&amp;}"; x="${x//</\&lt;}"; x="${x//>/\&gt;}"; printf '%s' "$x"; }
WAF_PROFILE="${OUT_DIR}/profiles/brebes-waf/agent.conf"
{
  echo '<!-- DefenseOps profile: brebes-waf; generated from existing Nginx/ModSecurity configuration -->'
  echo '<agent_config os="^Linux">'
  echo '  <localfile><location>/var/log/auth.log</location><log_format>syslog</log_format></localfile>'
  echo '  <localfile><location>/var/log/syslog</location><log_format>syslog</log_format></localfile>'
  for path in "${!NGINX_LOGS[@]}"; do
    esc="$(xml_escape "$path")"
    echo "  <localfile><location>${esc}</location><log_format>syslog</log_format></localfile>"
  done
  for path in "${!MODSEC_LOGS[@]}"; do
    esc="$(xml_escape "$path")"
    echo "  <localfile><location>${esc}</location><log_format>syslog</log_format></localfile>"
  done
  echo '  <syscheck><disabled>no</disabled><frequency>43200</frequency><scan_on_start>yes</scan_on_start>'
  echo '    <directories realtime="yes">/etc/nginx</directories>'
  echo '    <ignore type="sregex">.log$|.tmp$|.swp$</ignore>'
  echo '  </syscheck>'
  echo '</agent_config>'
} > "$WAF_PROFILE"
chmod 0640 "$WAF_PROFILE"

if ((${#CONFIG_FILES[@]} == 0)) && [[ -z "$NGINX_DUMP" ]]; then
  warn "Nginx configuration was not discovered on the generator host; WAF profile contains only base host logs and /etc/nginx FIM."
else
  log "Brebes-WAF discovery on generator host: ${#CONFIG_FILES[@]} config file(s), ${#NGINX_LOGS[@]} Nginx log path(s), ${#MODSEC_LOGS[@]} ModSecurity log path(s)."
  ((${#NGINX_LOGS[@]})) || warn "No static access_log/error_log paths discovered. Check Nginx config directives."
  ((${#MODSEC_LOGS[@]})) || warn "No SecAuditLog/SecDebugLog paths discovered in referenced ModSecurity rule files."
fi

# Docker-PHP intentionally does NOT watch Docker's global container JSON logs.
# Per-application paths will be registered later by create-php-app.sh so only
# Docker-PHP-managed applications are in scope.
cat > "${OUT_DIR}/profiles/docker-php/agent.conf" <<'DOCKERPHP'
<!-- DefenseOps profile: docker-php; app-specific paths are registered by create-php-app.sh -->
<agent_config os="^Linux">
  <localfile><location>/var/log/auth.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/syslog</location><log_format>syslog</log_format></localfile>
  <syscheck>
    <disabled>no</disabled><frequency>43200</frequency><scan_on_start>yes</scan_on_start>
    <directories realtime="yes">/opt/docker/apps</directories>
    <ignore type="sregex">/vendor/|/node_modules/|/cache/|.log$|.tmp$|.swp$</ignore>
  </syscheck>
</agent_config>
DOCKERPHP
chmod 0640 "${OUT_DIR}/profiles/docker-php/agent.conf"

# Publish only these two focused groups; stage + validate before replacing.
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
docker exec "$CONTAINER" test -x /var/ossec/bin/verify-agent-conf || die "verify-agent-conf unavailable."
echo "This publishes the two DefenseOps profiles to ${CONTAINER}. Existing files are backed up."
read -r -p "Continue? [y/N] " answer
[[ "${answer,,}" == y || "${answer,,}" == yes ]] || { echo "Cancelled."; exit 0; }
STAMP="$(date +%Y%m%d%H%M%S)"
for group in "${GROUPS[@]}"; do
  src="${BUNDLE_DIR}/profiles/${group}/agent.conf"; [[ -s "$src" ]] || die "Missing $src"
  if ! docker exec "$CONTAINER" /var/ossec/bin/agent_groups -l 2>/dev/null | grep -Eq "^[[:space:]]*${group}([[:space:]]|$)"; then
    docker exec "$CONTAINER" /var/ossec/bin/agent_groups -a -g "$group" -q
  fi
  dir="/var/ossec/etc/shared/${group}"; tmp="${dir}/agent.conf.tmp.${STAMP}"
  docker exec "$CONTAINER" install -d -o wazuh -g wazuh -m 0750 "$dir"
  docker cp "$src" "${CONTAINER}:${tmp}"
  docker exec "$CONTAINER" chown wazuh:wazuh "$tmp"
  docker exec "$CONTAINER" chmod 0660 "$tmp"
  docker exec "$CONTAINER" /var/ossec/bin/verify-agent-conf -f "$tmp"
  if docker exec "$CONTAINER" test -f "${dir}/agent.conf"; then docker exec "$CONTAINER" cp -a "${dir}/agent.conf" "${dir}/agent.conf.bak.${STAMP}"; fi
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
Generator: v${SCRIPT_VERSION} (${SCRIPT_RELEASE})
Wazuh Agent: ${VERSION}
Manager: ${MANAGER}
Agent: TCP/${MANAGER_PORT}; enrollment: TCP/${REG_PORT}

Bundle:
  install-agent.sh
  ossec.conf
  profiles/brebes-waf/agent.conf
  profiles/docker-php/agent.conf
  deploy-agent-profiles.sh

Brebes-WAF discovery (on the generator host):
  Config directory inspected: ${NGINX_SITES_DIR:-not found; nginx -T only}
  Nginx log paths discovered: ${#NGINX_LOGS[@]}
  ModSecurity log paths discovered: ${#MODSEC_LOGS[@]}
  Only concrete absolute access_log/error_log and SecAuditLog/SecDebugLog paths
  found in existing config/rule files are included. No live config is modified.

Docker-PHP scope:
  Does NOT collect global /var/lib/docker/containers/* logs and does not monitor
  unrelated containers. Per-application monitoring registrations are intended
  to be added by create-php-app.sh / delete-php-app.sh integration.
  The base profile watches /opt/docker/apps if present; adjust after validating
  the actual Docker-PHP host directory layout.

Install on endpoint:
  sudo ./install-agent.sh [--name HOSTNAME]
  The installer asks independently whether to change timezone to Asia/Jakarta
  and whether to enable NTP using the host's existing time-sync configuration.
  It does not overwrite chrony/timesyncd configuration files.
  Enrollment password is prompted interactively and is not stored in the bundle.

Publish central profiles (explicit action only):
  sudo ./deploy-agent-profiles.sh
  Review each generated profile before publishing. Existing shared agent.conf
  files are backed up; group membership must be assigned separately.
EOF
chmod 0640 "${OUT_DIR}/README.txt"

command -v tar >/dev/null 2>&1 || die "tar required."
command -v sha256sum >/dev/null 2>&1 || die "sha256sum required."
ARCHIVE_STAMP="$(date +%Y%m%d-%H%M%S)"
ARCHIVE_NAME="defenseops-agent-bundle-wazuh-${VERSION}-${ARCHIVE_STAMP}.tar.gz"
ARCHIVE_PATH="${OUT_DIR}/${ARCHIVE_NAME}"
TMP_ARCHIVE="$(mktemp "${OUT_DIR}/.defenseops-agent-bundle.XXXXXX")"
tar -czf "$TMP_ARCHIVE" -C "$OUT_DIR" install-agent.sh ossec.conf README.txt profiles deploy-agent-profiles.sh
chmod 0640 "$TMP_ARCHIVE"; mv -f "$TMP_ARCHIVE" "$ARCHIVE_PATH"; TMP_ARCHIVE=""
(cd "$OUT_DIR" && sha256sum "$ARCHIVE_NAME" > "${ARCHIVE_NAME}.sha256")
chmod 0640 "${ARCHIVE_PATH}.sha256"
log "Focused deployment bundle generated:"
printf '  Output       : %s\n  Archive      : %s\n  SHA256       : %s\n' "$OUT_DIR" "$ARCHIVE_PATH" "${ARCHIVE_PATH}.sha256"
log "Profiles: brebes-waf, docker-php. No enrollment secret included."
