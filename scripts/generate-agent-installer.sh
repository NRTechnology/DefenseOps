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

SCRIPT_VERSION="1.2.3"
SCRIPT_RELEASE="2026-11-07"
OUT_DIR=""
MANAGER_OVERRIDE=""
VERSION="4.14.10"
MANAGER_PORT="1514"
REG_PORT="1515"

log(){ printf '[INFO] %s\n' "$*"; }
die(){ printf '[ERROR] %s\n' "$*" >&2; exit 1; }

usage(){
  cat <<'EOF'
Run this script ONLY on the DefenseOps Manager server.
It generates install-agent.sh for execution on Linux endpoints.

Usage:
  sudo ./generate-agent-installer.sh [options]

Options:
  -m, --manager IP/FQDN    Override auto-detected Manager address
  -o, --output DIR         Output directory (default: <repository>/agent/output)
  -V, --version            Show generator version
  -h, --help               Show help

The generated endpoint bundle contains:
  install-agent.sh (run this on the target Linux endpoint, NOT on DefenseOps)
  ossec.conf
  README.txt

Enrollment password is deliberately NOT copied into the bundle.
EOF
}

while (($#)); do
  case "$1" in
    -m|--manager) MANAGER_OVERRIDE="${2:?Missing manager address}"; shift 2 ;;
    -o|--output) OUT_DIR="${2:?Missing output directory}"; shift 2 ;;
    -V|--version) printf 'DefenseOps Wazuh Agent Installer Generator v%s (%s)\n' "$SCRIPT_VERSION" "$SCRIPT_RELEASE"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Run as root: sudo $0"
command -v ip >/dev/null 2>&1 || die "iproute2 (ip command) is required."
command -v ss >/dev/null 2>&1 || die "ss command is required."

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
# Keep generated deployment artifacts inside the checked-out repository.
# The directory is excluded from Git via the repository .gitignore.
if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="${REPO_ROOT}/agent/output"
fi

if [[ -n "$MANAGER_OVERRIDE" ]]; then
  MANAGER="$MANAGER_OVERRIDE"
else
  # Prefer the source address selected by the kernel for the default route.
  MANAGER="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
fi

[[ -n "$MANAGER" ]] || die "Could not detect Manager IP. Specify it with --manager."
[[ "$MANAGER" =~ ^[A-Za-z0-9._:-]+$ ]] || die "Invalid Manager address: $MANAGER"

echo
echo "DefenseOps Agent deployment settings"
echo "  Manager address : $MANAGER"
echo "  Agent port      : ${MANAGER_PORT}/TCP"
echo "  Enrollment port : ${REG_PORT}/TCP"
echo "  Wazuh version   : ${VERSION}"
echo
read -r -p "Use this Manager address? [Y/n] " confirm
case "${confirm,,}" in n|no) die "Cancelled. Re-run with --manager IP/FQDN." ;; esac

# Validate local Manager enrollment prerequisites before generating endpoint files.
MANAGER_CONTAINER="${WAZUH_MANAGER_CONTAINER:-defenseops-manager-wazuh.manager-1}"
if command -v docker >/dev/null 2>&1 && docker inspect "$MANAGER_CONTAINER" >/dev/null 2>&1; then
  AUTHD_PASS="$(docker exec "$MANAGER_CONTAINER" sh -c 'test -s /var/ossec/etc/authd.pass && echo yes || echo no' 2>/dev/null || echo no)"
  USE_PASSWORD="$(docker exec "$MANAGER_CONTAINER" sh -c "grep -A12 '<auth>' /var/ossec/etc/ossec.conf | grep -m1 '<use_password>' | sed -E 's/.*>([^<]+).*/\\1/'" 2>/dev/null || true)"
  [[ "$AUTHD_PASS" == "yes" ]] || die "Manager authd.pass not found/empty in container ${MANAGER_CONTAINER}."
  [[ "$USE_PASSWORD" == "yes" ]] || die "Manager auth config does not show use_password=yes."
fi

mkdir -p "$OUT_DIR"
chmod 0750 "$OUT_DIR"

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

# Generate the endpoint-side installer from the embedded payload below.
cat > "${OUT_DIR}/install-agent.sh" <<'DEFENSEOPS_AGENT_INSTALLER_EOF'
#!/usr/bin/env bash
# DefenseOps - Wazuh Linux Agent installer
set -Eeuo pipefail

VERSION="4.14.10"
MANAGER=""
REG_PORT="1515"
MANAGER_PORT="1514"
PROTOCOL="tcp"
CONFIG_FILE=""
AGENT_NAME=""
AGENT_GROUP=""

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
  -c, --config FILE        ossec.conf generated by DefenseOps (default: ./ossec.conf)
  -h, --help               Show help

Supported package families: Debian/Ubuntu (APT), RHEL-compatible (DNF/YUM).
Enrollment password is requested interactively and is not saved in this script.
EOF
}

while (($#)); do
  case "$1" in
    -m|--manager) MANAGER="${2:?Missing manager address}"; shift 2 ;;
    -n|--name) AGENT_NAME="${2:?Missing agent name}"; shift 2 ;;
    -g|--group) AGENT_GROUP="${2:?Missing agent group}"; shift 2 ;;
    -c|--config) CONFIG_FILE="${2:?Missing config file}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Run as root: sudo $0"
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

if [[ ! -f "$CONFIG_FILE" ]]; then
  warn "Config file not found; creating a minimal client config for ${MANAGER}."
  CONFIG_FILE="$(mktemp)"
  cat > "$CONFIG_FILE" <<EOF
<ossec_config>
  <client>
    <server>
      <address>${MANAGER}</address>
      <port>${MANAGER_PORT}</port>
      <protocol>${PROTOCOL}</protocol>
    </server>
    <config-profile>linux</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>
</ossec_config>
EOF
fi

# Do not overwrite an existing non-Wazuh installation or silently replace an installed agent.
if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null | grep -q 'install ok installed'; then
  die "wazuh-agent already installed. Review existing installation before proceeding."
fi
if command -v rpm >/dev/null 2>&1 && rpm -q wazuh-agent >/dev/null 2>&1; then
  die "wazuh-agent already installed. Review existing installation before proceeding."
fi

read -r -s -p "Enrollment password for DefenseOps: " REG_PASSWORD
printf '\n'
[[ -n "$REG_PASSWORD" ]] || die "Enrollment password cannot be empty."

cleanup(){ unset REG_PASSWORD; }
trap cleanup EXIT

export WAZUH_MANAGER="$MANAGER"
export WAZUH_REGISTRATION_SERVER="$MANAGER"
export WAZUH_MANAGER_PORT="$MANAGER_PORT"
export WAZUH_REGISTRATION_PORT="$REG_PORT"
export WAZUH_PROTOCOL="$PROTOCOL"
export WAZUH_REGISTRATION_PASSWORD="$REG_PASSWORD"
export WAZUH_AGENT_NAME="$AGENT_NAME"
[[ -n "$AGENT_GROUP" ]] && export WAZUH_AGENT_GROUP="$AGENT_GROUP"

if [[ -f /etc/os-release ]]; then . /etc/os-release; else die "Cannot identify Linux distribution."; fi

case "${ID:-}" in
  ubuntu|debian|linuxmint|pop)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y curl gnupg apt-transport-https
    install -d -m 0755 /usr/share/keyrings
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg
    chmod 0644 /usr/share/keyrings/wazuh.gpg
    printf '%s\n' 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' \
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

# Keep the vendor-provided ossec.conf intact: it contains the default
# syscheck, rootcheck, syscollector and logcollector modules. Wazuh package
# deployment variables above configure Manager/enrollment without replacing
# those useful defaults. The generated ossec.conf is the deployment profile
# and source of the Manager address, not a replacement for the vendor file.
if [[ ! -s /var/ossec/etc/ossec.conf ]]; then
  die "Wazuh package did not create /var/ossec/etc/ossec.conf."
fi

# Avoid unintended major/minor agent upgrades; keep this agent aligned with the Manager.
if command -v apt-mark >/dev/null 2>&1; then
  apt-mark hold wazuh-agent >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  dnf versionlock add wazuh-agent >/dev/null 2>&1 || warn "Could not apply DNF versionlock; manage agent updates manually."
fi

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

unset WAZUH_REGISTRATION_PASSWORD REG_PASSWORD
trap - EXIT

sleep 3
if systemctl is-active --quiet wazuh-agent; then
  log "Wazuh Agent service is active."
else
  systemctl --no-pager --full status wazuh-agent || true
  die "Wazuh Agent did not become active. Check /var/ossec/logs/ossec.log."
fi

log "Installed Wazuh Agent version: $(/var/ossec/bin/wazuh-agentd -V 2>&1 | head -n1 || true)"
log "Manager: ${MANAGER}:${MANAGER_PORT}/TCP; enrollment: ${MANAGER}:${REG_PORT}/TCP"
log "Agent name: ${AGENT_NAME}"
log "Next: verify this endpoint appears as Active in the DefenseOps Dashboard."
DEFENSEOPS_AGENT_INSTALLER_EOF
chown root:root "${OUT_DIR}/install-agent.sh"
chmod 0750 "${OUT_DIR}/install-agent.sh"

# Generate centralized monitoring profiles for Wazuh Agent Groups.
mkdir -p "${OUT_DIR}/profiles"/{linux-server,web-server,database-server,docker-host}
chmod 0750 "${OUT_DIR}/profiles" "${OUT_DIR}/profiles"/*

cat > "${OUT_DIR}/profiles/linux-server/agent.conf" <<'PROFILE_LINUX'
<!-- DefenseOps profile: linux-server -->
<agent_config os="^Linux">
  <agent_config os="^Ubuntu|^Debian">
    <localfile><location>/var/log/auth.log</location><log_format>syslog</log_format></localfile>
    <localfile><location>/var/log/syslog</location><log_format>syslog</log_format></localfile>
    <localfile><location>/var/log/kern.log</location><log_format>syslog</log_format></localfile>
  </agent_config>
  <agent_config os="^Rocky|^AlmaLinux|^CentOS|^Red Hat|^Oracle Linux|^Amazon Linux">
    <localfile><location>/var/log/secure</location><log_format>syslog</log_format></localfile>
    <localfile><location>/var/log/messages</location><log_format>syslog</log_format></localfile>
  </agent_config>
  <localfile><location>/var/log/audit/audit.log</location><log_format>audit</log_format></localfile>
  <syscheck>
    <disabled>no</disabled><frequency>43200</frequency><scan_on_start>yes</scan_on_start>
    <directories realtime="yes">/etc</directories>
    <directories realtime="yes">/boot</directories>
    <directories realtime="yes">/usr/local/bin</directories>
    <directories realtime="yes">/usr/local/sbin</directories>
    <ignore>/etc/mtab</ignore><ignore>/etc/hosts.deny</ignore><ignore>/etc/adjtime</ignore>
    <ignore type="sregex">.log$|.tmp$|.swp$</ignore>
    <skip_dev>yes</skip_dev><skip_proc>yes</skip_proc><skip_sys>yes</skip_sys><skip_nfs>yes</skip_nfs>
  </syscheck>
</agent_config>
PROFILE_LINUX

cat > "${OUT_DIR}/profiles/web-server/agent.conf" <<'PROFILE_WEB'
<!-- DefenseOps profile: web-server -->
<agent_config os="^Linux">
  <localfile><location>/var/log/nginx/access.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/nginx/error.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/apache2/access.log</location><log_format>apache</log_format></localfile>
  <localfile><location>/var/log/apache2/error.log</location><log_format>apache</log_format></localfile>
  <localfile><location>/var/log/httpd/access_log</location><log_format>apache</log_format></localfile>
  <localfile><location>/var/log/httpd/error_log</location><log_format>apache</log_format></localfile>
  <localfile><location>/var/log/php*-fpm.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/php-fpm/error.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/www/*/storage/logs/laravel.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/apps/*/storage/logs/laravel.log</location><log_format>syslog</log_format></localfile>
  <syscheck>
    <directories realtime="yes">/var/www/*/app</directories>
    <directories realtime="yes">/var/www/*/bootstrap</directories>
    <directories realtime="yes">/var/www/*/config</directories>
    <directories realtime="yes">/var/www/*/routes</directories>
    <directories realtime="yes">/var/www/*/resources</directories>
    <directories realtime="yes">/var/www/*/public</directories>
    <directories realtime="yes">/var/apps/*/app</directories>
    <directories realtime="yes">/var/apps/*/bootstrap</directories>
    <directories realtime="yes">/var/apps/*/config</directories>
    <directories realtime="yes">/var/apps/*/routes</directories>
    <directories realtime="yes">/var/apps/*/resources</directories>
    <directories realtime="yes">/var/apps/*/public</directories>
    <ignore>/var/www/*/public/storage</ignore><ignore>/var/www/*/public/uploads</ignore>
    <ignore>/var/apps/*/public/storage</ignore><ignore>/var/apps/*/public/uploads</ignore>
    <ignore type="sregex">/storage/|/cache/|/sessions/|.log$|.tmp$|.swp$</ignore>
  </syscheck>
</agent_config>
PROFILE_WEB

cat > "${OUT_DIR}/profiles/database-server/agent.conf" <<'PROFILE_DB'
<!-- DefenseOps profile: database-server -->
<agent_config os="^Linux">
  <localfile><location>/var/log/mysql/error.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/mariadb/mariadb.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/mysql/mariadb.log</location><log_format>syslog</log_format></localfile>
  <syscheck>
    <directories realtime="yes">/etc/mysql</directories>
    <directories>/etc/my.cnf</directories>
    <directories realtime="yes">/etc/my.cnf.d</directories>
    <ignore type="sregex">.log$|.tmp$|.swp$</ignore>
  </syscheck>
</agent_config>
PROFILE_DB

cat > "${OUT_DIR}/profiles/docker-host/agent.conf" <<'PROFILE_DOCKER'
<!-- DefenseOps profile: docker-host -->
<agent_config os="^Linux">
  <localfile>
    <location>/var/lib/docker/containers/*/*-json.log</location>
    <log_format>json</log_format>
  </localfile>
  <syscheck>
    <directories realtime="yes">/etc/docker</directories>
    <directories realtime="yes">/etc/containerd</directories>
    <directories realtime="yes">/opt/docker</directories>
    <directories realtime="yes">/opt/docker-apps</directories>
    <ignore type="sregex">.log$|.tmp$|.swp$|/vendor/|/node_modules/|/cache/</ignore>
  </syscheck>
</agent_config>
PROFILE_DOCKER

# Optional endpoint-side helper for Docker event monitoring.
cat > "${OUT_DIR}/enable-docker-listener.sh" <<'DOCKER_LISTENER'
#!/usr/bin/env bash
# Enable Wazuh Docker event listener on a Linux Docker host.
set -Eeuo pipefail
die(){ echo "[ERROR] $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "Run on the Docker endpoint as root."
command -v docker >/dev/null 2>&1 || die "Docker CLI not found."
docker info >/dev/null 2>&1 || die "Docker daemon is not reachable."
command -v python3 >/dev/null 2>&1 || die "Python 3 is required."
PYVER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
python3 -c 'import sys; raise SystemExit(0 if (3,8) <= sys.version_info[:2] <= (3,13) else 1)' \
  || die "Wazuh Docker listener dependency is documented for Python 3.8-3.13; found ${PYVER}."
AGENT_CONF="/var/ossec/etc/ossec.conf"
LISTENER="/var/ossec/wodles/docker/DockerListener"
VENV="/var/ossec/wodles/docker/venv"
[[ -s "$AGENT_CONF" ]] || die "Wazuh Agent config not found: $AGENT_CONF"
[[ -f "$LISTENER" ]] || die "Wazuh DockerListener script not found: $LISTENER"
command -v systemctl >/dev/null 2>&1 || die "systemd is required."

STAMP="$(date +%Y%m%d%H%M%S)"
cp -a "$AGENT_CONF" "${AGENT_CONF}.pre-docker-listener.${STAMP}"
cp -a "$LISTENER" "${LISTENER}.pre-docker-listener.${STAMP}"

python3 -m venv "$VENV"
"$VENV/bin/pip" install --disable-pip-version-check --no-cache-dir \
  "docker==7.1.0" "urllib3==1.26.20" "requests==2.32.2"

# Point the bundled DockerListener to the isolated virtual environment.
sed -i "1c\\#!${VENV}/bin/python3" "$LISTENER"

if ! grep -q 'wodle name="docker-listener"' "$AGENT_CONF"; then
  cat >> "$AGENT_CONF" <<'XML'

<ossec_config>
  <wodle name="docker-listener">
    <disabled>no</disabled>
    <attempts>5</attempts>
    <run_on_start>yes</run_on_start>
    <interval>1m</interval>
  </wodle>
</ossec_config>
XML
fi

if systemctl restart wazuh-agent && systemctl is-active --quiet wazuh-agent; then
  echo "[INFO] Wazuh Docker listener enabled."
  echo "[INFO] Check /var/ossec/logs/ossec.log for DockerListener startup status."
else
  cp -a "${AGENT_CONF}.pre-docker-listener.${STAMP}" "$AGENT_CONF"
  cp -a "${LISTENER}.pre-docker-listener.${STAMP}" "$LISTENER"
  systemctl restart wazuh-agent || true
  die "Agent restart failed. Original config and DockerListener were restored."
fi
DOCKER_LISTENER
chmod 0750 "${OUT_DIR}/enable-docker-listener.sh"

# Separate, explicitly-confirmed deployment helper. It does not run automatically.
cat > "${OUT_DIR}/deploy-agent-profiles.sh" <<'DEPLOY_PROFILES'
#!/usr/bin/env bash
set -Eeuo pipefail
CONTAINER="${WAZUH_MANAGER_CONTAINER:-defenseops-manager-wazuh.manager-1}"
BUNDLE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_GROUPS=(linux-server web-server database-server docker-host)
die(){ echo "[ERROR] $*" >&2; exit 1; }
log(){ echo "[INFO] $*"; }
[[ $EUID -eq 0 ]] || die "Run on DefenseOps host as root."
command -v docker >/dev/null 2>&1 || die "Docker CLI is required."
docker inspect "$CONTAINER" >/dev/null 2>&1 || die "Manager container not found: $CONTAINER"
docker exec "$CONTAINER" test -x /var/ossec/bin/verify-agent-conf || die "verify-agent-conf unavailable."

echo "Publish four centralized profiles to Manager container: $CONTAINER"
read -r -p "Continue? [y/N] " answer
[[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]] || { echo "Cancelled."; exit 0; }

STAMP="$(date +%Y%m%d%H%M%S)"
for group in "${PROFILE_GROUPS[@]}"; do
  src="${BUNDLE_DIR}/profiles/${group}/agent.conf"
  [[ -s "$src" ]] || die "Missing profile: $src"
  if ! docker exec "$CONTAINER" /var/ossec/bin/agent_groups -l 2>/dev/null | grep -Eq "^[[:space:]]*${group}[[:space:]]"; then
    docker exec "$CONTAINER" /var/ossec/bin/agent_groups -a -g "$group" -q
  fi
  remote_dir="/var/ossec/etc/shared/${group}"
  remote_tmp="${remote_dir}/agent.conf.tmp.${STAMP}"
  docker exec "$CONTAINER" install -d -o wazuh -g wazuh -m 0750 "$remote_dir"
  docker cp "$src" "${CONTAINER}:${remote_tmp}"
  docker exec "$CONTAINER" chown wazuh:wazuh "$remote_tmp"
  docker exec "$CONTAINER" chmod 0660 "$remote_tmp"
  docker exec "$CONTAINER" /var/ossec/bin/verify-agent-conf -f "$remote_tmp"
  if docker exec "$CONTAINER" test -f "${remote_dir}/agent.conf"; then
    docker exec "$CONTAINER" cp -a "${remote_dir}/agent.conf" "${remote_dir}/agent.conf.bak.${STAMP}"
  fi
  docker exec "$CONTAINER" mv -f "$remote_tmp" "${remote_dir}/agent.conf"
  docker exec "$CONTAINER" chown wazuh:wazuh "${remote_dir}/agent.conf"
  docker exec "$CONTAINER" chmod 0660 "${remote_dir}/agent.conf"
  log "Published and validated group: $group"
done
log "Profiles published. Wazuh distributes shared configuration automatically."
log "Assign Agent Group membership separately by Agent ID; avoid -f unless replacing all memberships."
DEPLOY_PROFILES
chmod 0750 "${OUT_DIR}/deploy-agent-profiles.sh"

cat > "${OUT_DIR}/README.txt" <<EOF
DefenseOps - Wazuh Linux Agent Deployment
=========================================
Generator    : v${SCRIPT_VERSION} (${SCRIPT_RELEASE})
Wazuh Agent  : ${VERSION}
Manager      : ${MANAGER}
Agent port   : ${MANAGER_PORT}/TCP
Enrollment   : ${REG_PORT}/TCP

Bundle:
  install-agent.sh
  enable-docker-listener.sh (optional; run only on Docker endpoints)
  ossec.conf
  profiles/linux-server/agent.conf
  profiles/web-server/agent.conf
  profiles/database-server/agent.conf
  profiles/docker-host/agent.conf
  deploy-agent-profiles.sh

Safe deployment:
1. Review the profile paths and remove log sources not present on the target distro.
2. Run deploy-agent-profiles.sh on DefenseOps as root. It asks confirmation,
   creates missing groups, stages files, validates each with verify-agent-conf,
   backs up existing agent.conf, then atomically activates the new file.
3. Install endpoint Agent with sudo ./install-agent.sh.
4. On Docker endpoints only, optionally enable Docker event collection:
     sudo ./enable-docker-listener.sh
   This installs pinned Python dependencies in an isolated virtualenv, backs up
   the local Agent config and DockerListener, then enables the local Docker wodle.
5. After the Agent appears in Dashboard, assign only applicable groups:
   docker exec ${MANAGER_CONTAINER} /var/ossec/bin/agent_groups -a -i AGENT_ID -g linux-server
   docker exec ${MANAGER_CONTAINER} /var/ossec/bin/agent_groups -a -i AGENT_ID -g web-server
   docker exec ${MANAGER_CONTAINER} /var/ossec/bin/agent_groups -a -i AGENT_ID -g database-server
   docker exec ${MANAGER_CONTAINER} /var/ossec/bin/agent_groups -a -i AGENT_ID -g docker-host
   Multiple groups are supported. Do not use -f unless replacing all memberships.
6. Verify membership and shared configuration on the endpoint.

Profile notes:
- linux-server: auth/system/kernel/audit logs; realtime FIM on critical OS paths.
- web-server: Nginx/Apache/PHP-FPM/Laravel logs; realtime FIM on application code.
- database-server: MariaDB/MySQL logs; realtime FIM on DB configuration only.
- docker-host: Docker json-file runtime logs; realtime FIM on Docker/Compose configuration.
- FIM realtime applies to directories. Public paths may include uploads; review excludes.
- Never enable report_changes for .env, private keys, credentials, or secrets.
- Do not FIM live database data (/var/lib/mysql, /var/lib/mariadb).
- Docker JSON log collection assumes the json-file logging driver.
- Docker event listener is a separate local Agent module. On Docker endpoints,
  run enable-docker-listener.sh explicitly. It uses an isolated Python virtualenv,
  pinned Docker Python dependencies, and backups before changing local ossec.conf.
- This bundle is not deployed until deploy-agent-profiles.sh is run and confirmed.
- Enrollment password is never included in the bundle.
EOF
chmod 0640 "${OUT_DIR}/README.txt"


# Build a portable archive from an explicit file list. The temporary archive
# is created inside OUT_DIR but is not included in itself; previous archives
# are not included in subsequent archives either.
command -v tar >/dev/null 2>&1 || die "tar is required to create the deployment archive."
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required to create the archive checksum."

ARCHIVE_STAMP="$(date +%Y%m%d-%H%M%S)"
ARCHIVE_NAME="defenseops-agent-bundle-wazuh-${VERSION}-${ARCHIVE_STAMP}.tar.gz"
ARCHIVE_PATH="${OUT_DIR}/${ARCHIVE_NAME}"
CHECKSUM_PATH="${ARCHIVE_PATH}.sha256"
TMP_ARCHIVE="$(mktemp "${OUT_DIR}/.defenseops-agent-bundle.XXXXXX")"

tar -czf "$TMP_ARCHIVE" -C "$OUT_DIR" \
  install-agent.sh \
  ossec.conf \
  README.txt \
  profiles \
  deploy-agent-profiles.sh \
  enable-docker-listener.sh

chmod 0640 "$TMP_ARCHIVE"
mv -f "$TMP_ARCHIVE" "$ARCHIVE_PATH"
TMP_ARCHIVE=""

(
  cd "$OUT_DIR"
  sha256sum "$ARCHIVE_NAME" > "${ARCHIVE_NAME}.sha256"
)
chmod 0640 "$CHECKSUM_PATH"

log "Deployment bundle generated:"
printf '  Files   : %s\n' "$OUT_DIR"
printf '  Archive : %s\n' "$ARCHIVE_PATH"
printf '  SHA256  : %s\n' "$CHECKSUM_PATH"
log "Copy the .tar.gz archive to the endpoint, verify its checksum, extract it, then run install-agent.sh."
log "No enrollment secret was copied or embedded."
