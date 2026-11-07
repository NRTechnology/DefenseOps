#!/usr/bin/env bash
#
# ============================================================================
# DefenseOps - Wazuh Agent Installer Generator
# ============================================================================
# Description : Generate a deployment bundle for enrolling Linux endpoints
#               into the DefenseOps Wazuh Manager.
#
# Version     : 1.0.0
# Release     : 2026-11-07
# Maintainer  : DefenseOps
#
# Execution   : Run this script ONLY on the DefenseOps Manager server.
# Output      : install-agent.sh, ossec.conf, and README.txt
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

SCRIPT_VERSION="1.0.0"
SCRIPT_RELEASE="2026-11-07"

OUT_DIR="/opt/defenseops/agent-deployment"
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
  -o, --output DIR         Output directory (default: /opt/defenseops/agent-deployment)
  -V, --version            Show script version
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
    -V|--version) printf 'DefenseOps Wazuh Agent Installer Generator v%s (%s)\\n' "$SCRIPT_VERSION" "$SCRIPT_RELEASE"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Run as root: sudo $0"
command -v ip >/dev/null 2>&1 || die "iproute2 (ip command) is required."
command -v ss >/dev/null 2>&1 || die "ss command is required."

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
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
trap 'rm -f "$TMP_CONF"' EXIT
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

cat > "${OUT_DIR}/README.txt" <<EOF
DefenseOps - Wazuh Linux Agent Deployment
=========================================
Generator    : v${SCRIPT_VERSION} (${SCRIPT_RELEASE})
Wazuh Agent  : ${VERSION}
Manager      : ${MANAGER}
Agent port   : ${MANAGER_PORT}/TCP
Enrollment   : ${REG_PORT}/TCP
Agent version: ${VERSION}

Requirements:
- Linux endpoint using Debian/Ubuntu or RHEL-compatible distribution
- Root/sudo access
- Outbound connectivity to the Manager on TCP ${MANAGER_PORT} and TCP ${REG_PORT}
- Internet access to packages.wazuh.com during installation

Install:
  chmod 750 install-agent.sh
  sudo ./install-agent.sh

The installer requests the enrollment password interactively.
Do not put the password in this directory or send it through chat/email.
The enrollment password is not included in this bundle.

The generated ossec.conf records the Manager connection profile. During
installation, Wazuh's deployment variables apply the same Manager and
enrollment settings while preserving the vendor ossec.conf defaults
(Syscheck, Rootcheck, Syscollector and log collection).

Optional:
  sudo ./install-agent.sh --name HOSTNAME --group EXISTING_GROUP
  sudo ./install-agent.sh --manager MANAGER_IP

After installation, verify the endpoint status is Active in the DefenseOps Dashboard.
EOF
chmod 0640 "${OUT_DIR}/README.txt"

log "Deployment bundle generated. Run install-agent.sh ONLY on target Linux endpoints:"
printf '  %s\n' "${OUT_DIR}/install-agent.sh" "${OUT_DIR}/ossec.conf" "${OUT_DIR}/README.txt"
log "No enrollment secret was copied or embedded."
