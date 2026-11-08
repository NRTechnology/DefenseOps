#!/usr/bin/env bash
#
# ============================================================================
# DefenseOps - Wazuh Agent Installer Generator
# ============================================================================
# Version     : 1.3.6
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

SCRIPT_VERSION="1.3.6"
SCRIPT_RELEASE="2026-11-08"
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

# Endpoint-side installer. First-time installation enrolls a new Agent.
# Existing installations are updated in place: active config is parsed and
# only missing profile settings are merged; unrelated content is preserved.
cat > "${OUT_DIR}/install-agent.sh" <<'INSTALLER'
#!/usr/bin/env bash
set -Eeuo pipefail

WAZUH_AGENT_VERSION="4.14.10"
INSTALLER_VERSION="1.3.6"
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
First-time installation requests an enrollment password. Existing Agents are
updated in place without re-enrollment or package reinstall.
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

command -v python3 >/dev/null 2>&1 || die "python3 is required for safe XML-aware configuration merging."

AGENT_ALREADY_INSTALLED=0
if command -v dpkg-query >/dev/null 2>&1 &&
   dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null | grep -q 'install ok installed'; then
  AGENT_ALREADY_INSTALLED=1
elif command -v rpm >/dev/null 2>&1 && rpm -q wazuh-agent >/dev/null 2>&1; then
  AGENT_ALREADY_INSTALLED=1
fi

ACTIVE_AGENT_CONF="/var/ossec/etc/ossec.conf"
ACTIVE_MANAGER=""
if (( AGENT_ALREADY_INSTALLED == 1 )) && [[ -s "$ACTIVE_AGENT_CONF" ]]; then
  ACTIVE_MANAGER="$(sed -n 's:.*<address>\\([^<]*\\)</address>.*:\\1:p' "$ACTIVE_AGENT_CONF" | head -n1)"
fi

if (( AGENT_ALREADY_INSTALLED == 1 )); then
  if [[ -n "$MANAGER" && -n "$ACTIVE_MANAGER" && "$MANAGER" != "$ACTIVE_MANAGER" ]]; then
    die "Existing Agent uses Manager '${ACTIVE_MANAGER}'. Refusing to change it to '${MANAGER}' during profile update."
  fi
  [[ -n "$ACTIVE_MANAGER" ]] && MANAGER="$ACTIVE_MANAGER"
fi

if [[ -z "$MANAGER" && -f "$CONFIG_FILE" ]]; then
  MANAGER="$(sed -n 's:.*<address>\\([^<]*\\)</address>.*:\\1:p' "$CONFIG_FILE" | head -n1)"
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
log "DefenseOps installer version: ${INSTALLER_VERSION}"

if (( AGENT_ALREADY_INSTALLED == 1 )); then
  log "Existing Wazuh Agent detected: update profile/configuration only."
  log "Package installation, enrollment, Manager address, and client identity will be preserved."
else
  log "No existing Wazuh Agent detected: performing first-time installation and enrollment."
fi

# ---------------------------------------------------------------------------
# Brebes-WAF endpoint-local discovery. nginx -T expands active include files,
# so discovery is performed on the WAF host, not on the DefenseOps generator.
# ---------------------------------------------------------------------------
declare -A NGINX_ACCESS_LOGS=()
declare -A NGINX_ERROR_LOGS=()
declare -A MODSEC_LOGS=()
declare -A SEEN_MODSEC=()
NGINX_DUMP=""
DISCOVERY_REPORT=""

trim_directive_value(){
  local value="$1"
  value="${value%%#*}"; value="${value%;}"
  value="${value%\"}"; value="${value#\"}"
  value="${value%\'}"; value="${value#\'}"
  printf '%s' "$value"
}
add_modsec_path(){
  local value="$1"
  [[ -n "$value" ]] || return 0
  [[ "$value" == /* && "$value" != *'$'* && "$value" != *' '* ]] || return 0
  MODSEC_LOGS["$value"]=1
}
discover_modsecurity_file(){
  local initial="$1"; local -a queue=()
  local current line directive value base expanded
  queue+=("$initial")
  while ((${#queue[@]})); do
    current="${queue[0]}"; queue=("${queue[@]:1}")
    [[ -r "$current" && -f "$current" ]] || continue
    [[ -n "${SEEN_MODSEC[$current]:-}" ]] && continue
    SEEN_MODSEC["$current"]=1; base="$(dirname -- "$current")"
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      read -r directive value _ <<< "$line"
      [[ -n "${directive:-}" && -n "${value:-}" ]] || continue
      value="$(trim_directive_value "$value")"
      case "$directive" in
        SecAuditLog|SecDebugLog) add_modsec_path "$value" ;;
        Include)
          [[ "$value" != /* ]] && value="${base}/${value}"
          if [[ "$value" == *'*'* || "$value" == *'?'* || "$value" == *'['* ]]; then
            while IFS= read -r expanded; do
              [[ -n "$expanded" && -f "$expanded" ]] && queue+=("$expanded")
            done < <(compgen -G "$value" || true)
          elif [[ -f "$value" ]]; then queue+=("$value")
          fi
          ;;
      esac
    done < "$current"
  done
}

discover_brebes_waf(){
  local dump_file report_file
  command -v nginx >/dev/null 2>&1 || die "Brebes-WAF profile selected, but nginx command was not found."
  command -v python3 >/dev/null 2>&1 || die "python3 is required for reliable Nginx virtual-host/log-format discovery."
  dump_file="$(mktemp)"; report_file="$(mktemp)"
  NGINX_DUMP="$dump_file"; DISCOVERY_REPORT="$report_file"
  if ! nginx -T >"$dump_file" 2>&1; then
    cat "$dump_file" >&2
    die "nginx -T failed. Fix/check Nginx configuration before installing the WAF profile."
  fi

  if ! python3 - "$dump_file" "$report_file" <<'PYNGINX'
import re, sys
from pathlib import Path
source, report = sys.argv[1:3]
text = Path(source).read_text(encoding="utf-8", errors="replace")
token_re = re.compile(r"""(?xs)\s+|\#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[;{}]|[^\s;{}#]+""")
tokens = []
for m in token_re.finditer(text):
    t = m.group(0)
    if not t or t.isspace() or t.startswith("#"): continue
    if t[0:1] in ("'", '"') and t[-1:] == t[0]: t = t[1:-1]
    tokens.append(t)

class Node:
    def __init__(self, name, args=None, parent=None):
        self.name, self.args, self.parent = name, args or [], parent
        self.directives, self.children = [], []

def parse_context(i=0, parent=None):
    node = parent or Node("root")
    while i < len(tokens):
        words = []
        while i < len(tokens) and tokens[i] not in (";", "{", "}"):
            words.append(tokens[i]); i += 1
        if i >= len(tokens):
            if words: raise ValueError("directive without ';' at end")
            break
        marker = tokens[i]; i += 1
        if marker == "}":
            if words: raise ValueError("unexpected '}'")
            return node, i
        if not words: raise ValueError("empty directive/context")
        if marker == ";": node.directives.append((words[0], words[1:]))
        else:
            child = Node(words[0], words[1:], node)
            child, i = parse_context(i, child)
            node.children.append(child)
    if parent is not None: raise ValueError("unclosed configuration context")
    return node, i

def walk(n):
    yield n
    for c in n.children: yield from walk(c)
def direct(n, name):
    return [args for key, args in n.directives if key == name]

try: root, _ = parse_context()
except Exception as e:
    print(f"[ERROR] Cannot parse expanded Nginx configuration: {e}", file=sys.stderr); sys.exit(2)

http_nodes = [n for n in walk(root) if n.name == "http"]
if not http_nodes:
    print("[ERROR] No http {} context found.", file=sys.stderr); sys.exit(2)
http = http_nodes[0]
formats = {}
for args in direct(http, "log_format"):
    if len(args) < 2: continue
    name, rest = args[0], args[1:]
    escaped = any(x.lower() == "escape=json" for x in rest)
    body = " ".join(x for x in rest if not x.lower().startswith("escape="))
    formats[name] = bool(escaped and "{" in body and "}" in body and re.search(r'"[^"]+"\s*:', body))

http_access = direct(http, "access_log")
servers = [n for n in walk(http) if n.name == "server"]
if not servers:
    print("[ERROR] No server {} virtual-host blocks found.", file=sys.stderr); sys.exit(2)

rows, failures = [], []
for idx, server in enumerate(servers, 1):
    names = [x for args in direct(server, "server_name") for x in args]
    vhost = ",".join(names) if names else f"<server-block-{idx}-without-server_name>"
    root_access = direct(server, "access_log")
    nested_access = [a for child in server.children for n in walk(child) for a in direct(n, "access_log")]
    effective = ([] if root_access else list(http_access)) + root_access + nested_access
    if not effective:
        failures.append((vhost, "<default Nginx access log>", "no explicit access_log; default format is not verified as JSON"))
        continue
    for args in effective:
        if not args:
            failures.append((vhost, "<unknown>", "empty access_log directive")); continue
        path = args[0]
        if path == "off":
            failures.append((vhost, "off", "access logging disabled for this context")); continue
        if not path.startswith("/") or "$" in path or " " in path:
            failures.append((vhost, path, "dynamic/non-file access_log path cannot be monitored safely")); continue
        fmt = args[1] if len(args) >= 2 else "combined"
        if fmt.startswith(("buffer=", "gzip=", "flush=", "if=")):
            fmt = "combined"
        if not formats.get(fmt, False):
            failures.append((vhost, path, f"format '{fmt}' is not verified JSON (requires escape=json and JSON object)"))
        else: rows.append((vhost, path, "json", fmt))

http_errors = direct(http, "error_log")
for idx, server in enumerate(servers, 1):
    names = [x for args in direct(server, "server_name") for x in args]
    vhost = ",".join(names) if names else f"<server-block-{idx}-without-server_name>"
    own_errors = [a for n in walk(server) for a in direct(n, "error_log")]
    if not own_errors: own_errors = http_errors
    for args in own_errors:
        if not args: continue
        path = args[0]
        if path in ("stderr", "syslog") or path.startswith("syslog:"): continue
        if path.startswith("/") and "$" not in path and " " not in path:
            rows.append((vhost, path, "syslog", "nginx-error"))

if failures:
    print("[ERROR] Brebes-WAF JSON access-log validation failed:", file=sys.stderr)
    for vhost, path, reason in failures:
        print(f"  VHOST: {vhost}\n  PATH : {path}\n  WHY  : {reason}", file=sys.stderr)
    print("[ERROR] Fix every listed virtual host and rerun install-agent.sh.", file=sys.stderr)
    sys.exit(3)

seen = set()
with open(report, "w", encoding="utf-8") as f:
    for row in rows:
        if row not in seen:
            seen.add(row); f.write("\t".join(row) + "\n")
print(f"[INFO] Nginx virtual hosts checked: {len(servers)}")
print(f"[INFO] Verified JSON access-log entries: {sum(1 for r in rows if r[2] == 'json')}")
print(f"[INFO] Nginx error-log entries: {sum(1 for r in rows if r[2] == 'syslog')}")
PYNGINX
  then
    rm -f "$dump_file" "$report_file"
    NGINX_DUMP=""; DISCOVERY_REPORT=""
    die "Brebes-WAF validation failed. No Agent installation or configuration changes were made."
  fi

  local vhost path format kind
  while IFS=$'\t' read -r vhost path format kind; do
    [[ -n "$path" ]] || continue
    if [[ "$kind" == "json" ]]; then NGINX_ACCESS_LOGS["$path"]=json
    else NGINX_ERROR_LOGS["$path"]=syslog
    fi
  done < "$report_file"

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    read -r directive value _ <<< "$line"
    [[ "${directive:-}" == "modsecurity_rules_file" && -n "${value:-}" ]] || continue
    value="$(trim_directive_value "$value")"
    [[ "$value" == /* && -r "$value" ]] && discover_modsecurity_file "$value"
  done < "$dump_file"

  ((${#NGINX_ACCESS_LOGS[@]} > 0)) || die "No verified JSON Nginx access logs found. Agent installation aborted."
  log "Nginx discovery: ${#NGINX_ACCESS_LOGS[@]} JSON access log(s), ${#NGINX_ERROR_LOGS[@]} text error log(s), ${#MODSEC_LOGS[@]} ModSecurity log(s)."
}
if [[ "$ENDPOINT_PROFILE" == "brebes-waf" ]]; then
  log "Inspecting every active Nginx virtual host and validating JSON access logs..."
  discover_brebes_waf
  log "Brebes-WAF JSON validation passed."
else
  log "Docker-PHP base profile selected."
  log "No global Docker container logs will be collected."
  log "Per-application monitoring will be registered later by create-php-app.sh."
fi

# Time settings are opt-in. Do not overwrite chrony/timesyncd configuration.
if (( AGENT_ALREADY_INSTALLED == 0 )) && command -v timedatectl >/dev/null 2>&1; then
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
elif (( AGENT_ALREADY_INSTALLED == 0 )); then
  warn "timedatectl unavailable; timezone and NTP settings were not changed."
fi

REG_PASSWORD=""
cleanup(){
  unset REG_PASSWORD WAZUH_REGISTRATION_PASSWORD 2>/dev/null || true
}
trap cleanup EXIT

if (( AGENT_ALREADY_INSTALLED == 0 )); then
  read -r -s -p "Enrollment password for DefenseOps: " REG_PASSWORD
  printf '\n'
  [[ -n "$REG_PASSWORD" ]] || die "Enrollment password cannot be empty."

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
      apt-get install -y "wazuh-agent=${WAZUH_AGENT_VERSION}-1"
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
        dnf install -y "wazuh-agent-${WAZUH_AGENT_VERSION}-1"
      else
        yum install -y "wazuh-agent-${WAZUH_AGENT_VERSION}-1"
      fi
      ;;
    *)
      die "Unsupported distribution: ${ID:-unknown}. Supported: Debian/Ubuntu and RHEL-compatible."
      ;;
  esac
else
  log "Skipping package installation and enrollment; existing Agent identity is preserved."
  unset REG_PASSWORD WAZUH_REGISTRATION_PASSWORD 2>/dev/null || true
fi

[[ -s /var/ossec/etc/ossec.conf ]] ||
  die "Wazuh package did not create /var/ossec/etc/ossec.conf."
[[ -x /var/ossec/bin/wazuh-agentd ]] ||
  die "Wazuh Agent daemon binary not found."

# Merge only DefenseOps-managed endpoint settings into the ACTIVE configuration.
# Existing XML is parsed before any write; unrelated elements/comments remain
# byte-for-byte in place. The merge is idempotent.
AGENT_CONF="/var/ossec/etc/ossec.conf"
[[ -s "$AGENT_CONF" ]] || die "Active Agent configuration is missing or empty."
[[ ! -L "$AGENT_CONF" ]] || die "Active ossec.conf is a symlink; refusing an unsafe replacement."
[[ -x /var/ossec/bin/wazuh-agentd ]] || die "Wazuh Agent daemon binary not found."

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="${AGENT_CONF}.pre-defenseops-${ENDPOINT_PROFILE}.${STAMP}.$$"
TMP_AGENT_CONF="$(mktemp "${AGENT_CONF}.tmp.XXXXXX")"
PATHS_FILE="$(mktemp)"
AGENT_CONFIG_REPLACED=0
AGENT_SERVICE_STOPPED=0
WAS_AGENT_ACTIVE=0
CONFIG_CHANGED=0

if [[ "$ENDPOINT_PROFILE" == "brebes-waf" ]]; then
  {
    for path in "${!NGINX_ACCESS_LOGS[@]}"; do printf '%s\\tjson\\n' "$path"; done
    for path in "${!NGINX_ERROR_LOGS[@]}"; do printf '%s\\tsyslog\\n' "$path"; done
    for path in "${!MODSEC_LOGS[@]}"; do printf '%s\\tsyslog\\n' "$path"; done
  } | sort -u > "$PATHS_FILE"
fi

cleanup_files(){
  local exit_code=$?
  trap - EXIT

  if (( exit_code != 0 && AGENT_CONFIG_REPLACED == 1 )); then
    warn "Configuration activation failed; restoring the original ossec.conf."
    local rollback_file="${AGENT_CONF}.rollback.$$"
    if [[ -s "$BACKUP" ]] && cp -a -- "$BACKUP" "$rollback_file" &&
       mv -f -- "$rollback_file" "$AGENT_CONF"; then
      command -v restorecon >/dev/null 2>&1 && restorecon "$AGENT_CONF" >/dev/null 2>&1 || true
      log "Original configuration restored from ${BACKUP}."
    else
      rm -f "$rollback_file"
      warn "Automatic rollback failed. Original backup: ${BACKUP}"
    fi
  fi

  if (( exit_code != 0 && AGENT_SERVICE_STOPPED == 1 )); then
    if systemctl start wazuh-agent; then
      log "Wazuh Agent service started after rollback."
    else
      warn "Could not start wazuh-agent after rollback; inspect systemctl status."
    fi
  fi

  rm -f "${TMP_AGENT_CONF:-}" "${PATHS_FILE:-}" "${NGINX_DUMP:-}" "${DISCOVERY_REPORT:-}"
  cleanup
  exit "$exit_code"
}
trap cleanup_files EXIT

# Copy metadata first; the merge writes only file contents to this same-directory
# staging file. The original remains untouched until all pre-activation checks pass.
cp -a -- "$AGENT_CONF" "$TMP_AGENT_CONF"

python3 - "$AGENT_CONF" "$TMP_AGENT_CONF" "$ENDPOINT_PROFILE" "$PATHS_FILE" <<'PYMERGE'
import html
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

source, destination, profile, paths_file = sys.argv[1:5]
original = Path(source).read_text(encoding="utf-8")
text = original

# Wazuh supports multiple top-level <ossec_config> sections. Wrap them only
# for validation; do not serialize through ElementTree, which would rewrite
# comments, whitespace, and formatting in the user's active configuration.
without_decl = re.sub(r"^\s*<\?xml[^?]*\?>", "", text, count=1)
try:
    parsed = ET.fromstring("<defenseops_validation_root>" + without_decl +
                           "</defenseops_validation_root>")
except ET.ParseError as exc:
    raise SystemExit(f"Existing ossec.conf is not parseable; refusing to modify it: {exc}")

blocks = list(re.finditer(r"<ossec_config\b[^>]*>.*?</ossec_config\s*>",
                          text, flags=re.DOTALL))
if not blocks:
    raise SystemExit("No <ossec_config> block found; refusing to modify the active file.")

if profile == "brebes-waf":
    paths = {}
    for raw in Path(paths_file).read_text(encoding="utf-8").splitlines():
        parts = raw.split("\\t", 1)
        if len(parts) != 2:
            raise SystemExit(f"Invalid discovered log entry: {raw!r}")
        path, fmt = parts[0].strip(), parts[1].strip()
        if path:
            if path in paths and paths[path] != fmt:
                raise SystemExit(f"Conflicting log formats discovered for {path}")
            paths[path] = fmt

    existing_locations = {}
    for node in parsed.iter("localfile"):
        location = node.find("location")
        log_format = node.find("log_format")
        if location is not None and location.text:
            existing_locations[location.text.strip()] = (
                (log_format.text or "default").strip() if log_format is not None else "default"
            )

    additions = []
    for path, fmt in paths.items():
        if path in existing_locations:
            current_fmt = existing_locations[path]
            if current_fmt != fmt:
                raise SystemExit(
                    f"Existing localfile for {path} uses log_format={current_fmt}; "
                    f"discovery requires {fmt}. Refusing to overwrite existing settings."
                )
            continue
        escaped = html.escape(path, quote=False)
        additions.append(
            "  <localfile>\\n"
            f"    <location>{escaped}</location>\\n"
            f"    <log_format>{fmt}</log_format>\\n"
            "  </localfile>\\n"
        )

    # Insert only missing localfile entries into the first ossec_config block.
    if additions:
        first = blocks[0]
        close = re.search(r"</ossec_config\s*>", first.group(0))
        insert_at = first.start() + close.start()
        text = text[:insert_at] + "".join(additions) + text[insert_at:]

    # Add /etc/nginx to an existing syscheck block without replacing any
    # existing frequency, directories, ignores, nodiff, or synchronization.
    nginx_already_watched = False
    for node in parsed.iter("syscheck"):
        for directory in node.findall("directories"):
            if (directory.text or "").strip() == "/etc/nginx":
                nginx_already_watched = True
                break
        if nginx_already_watched:
            break

    if not nginx_already_watched:
        syscheck_match = re.search(r"<syscheck\b[^>]*>.*?</syscheck\s*>",
                                   text, flags=re.DOTALL)
        if syscheck_match:
            closing = re.search(r"(?m)^([ \t]*)</syscheck\s*>", syscheck_match.group(0))
            if closing:
                indent = closing.group(1)
                insert_at = syscheck_match.start() + closing.start()
                text = (text[:insert_at] +
                        indent + '  <directories realtime="yes">/etc/nginx</directories>\n' +
                        text[insert_at:])
            else:
                raise SystemExit("Could not locate </syscheck>; refusing to modify configuration.")
        else:
            # No existing syscheck: create a minimal block; do not impose
            # frequency/ignore settings on an endpoint that has none.
            first = re.search(r"</ossec_config\s*>", text)
            text = (text[:first.start()] +
                    "  <syscheck>\n"
                    '    <directories realtime="yes">/etc/nginx</directories>\n'
                    "  </syscheck>\n" +
                    text[first.start():])

# Docker-PHP deliberately leaves the active local configuration unchanged.
# Its per-application paths are managed by create-php-app.sh integration.
try:
    ET.fromstring("<defenseops_validation_root>" +
                  re.sub(r"^\s*<\?xml[^?]*\?>", "", text, count=1) +
                  "</defenseops_validation_root>")
except ET.ParseError as exc:
    raise SystemExit(f"Merged ossec.conf failed XML validation; no file activated: {exc}")

Path(destination).write_text(text, encoding="utf-8")
PYMERGE

chown --reference="$AGENT_CONF" "$TMP_AGENT_CONF"
chmod --reference="$AGENT_CONF" "$TMP_AGENT_CONF"

if cmp -s -- "$AGENT_CONF" "$TMP_AGENT_CONF"; then
  CONFIG_CHANGED=0
  rm -f "$TMP_AGENT_CONF"
  log "Active ossec.conf already matches the selected profile; no file change required."
else
  CONFIG_CHANGED=1
  cp -a -- "$AGENT_CONF" "$BACKUP"
  WAS_AGENT_ACTIVE=0
  if systemctl is-active --quiet wazuh-agent; then
    WAS_AGENT_ACTIVE=1
    systemctl stop wazuh-agent
    AGENT_SERVICE_STOPPED=1
  fi

  # Same-directory rename is atomic. The backup exists before activation.
  mv -f -- "$TMP_AGENT_CONF" "$AGENT_CONF"
  AGENT_CONFIG_REPLACED=1
  command -v restorecon >/dev/null 2>&1 && restorecon "$AGENT_CONF" >/dev/null 2>&1 || true

  if ! /var/ossec/bin/wazuh-agentd -t; then
    die "Merged Agent configuration is invalid; original configuration will be restored."
  fi
  log "Merged Agent configuration passed wazuh-agentd validation."

  if (( WAS_AGENT_ACTIVE == 1 )); then
    systemctl start wazuh-agent
    AGENT_SERVICE_STOPPED=1
  elif (( AGENT_ALREADY_INSTALLED == 0 )); then
    systemctl enable wazuh-agent
    systemctl start wazuh-agent
    AGENT_SERVICE_STOPPED=1
  else
    log "Agent was inactive before update; preserving its inactive state."
  fi

  if (( WAS_AGENT_ACTIVE == 1 || AGENT_ALREADY_INSTALLED == 0 )); then
    sleep 3
    systemctl is-active --quiet wazuh-agent ||
      die "Wazuh Agent did not become active; original configuration will be restored."
    AGENT_SERVICE_STOPPED=0
  fi
  log "Original configuration backup: ${BACKUP}"
fi

# Do not alter package hold/service enablement on an already-managed endpoint.
if (( AGENT_ALREADY_INSTALLED == 0 )); then
  if command -v apt-mark >/dev/null 2>&1; then
    apt-mark hold wazuh-agent >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf versionlock add wazuh-agent >/dev/null 2>&1 ||
      warn "Could not apply DNF versionlock; manage Agent updates manually."
  fi
  systemctl enable wazuh-agent
  if ! systemctl is-active --quiet wazuh-agent; then
    systemctl start wazuh-agent
  fi
fi

unset WAZUH_REGISTRATION_PASSWORD REG_PASSWORD
if systemctl is-active --quiet wazuh-agent; then
  AGENT_SERVICE_STOPPED=0
  log "Wazuh Agent service is active."
elif (( AGENT_ALREADY_INSTALLED == 1 )); then
  log "Wazuh Agent was inactive before profile update; its service state was preserved."
else
  systemctl --no-pager --full status wazuh-agent || true
  die "Wazuh Agent did not become active. Check /var/ossec/logs/ossec.log."
fi

log "Installed Wazuh Agent version: $(/var/ossec/bin/wazuh-agentd -V 2>&1 | head -n1 || true)"
log "Endpoint profile: ${ENDPOINT_PROFILE}"
if (( AGENT_ALREADY_INSTALLED == 1 )); then
  log "Manager and enrolled Agent identity: preserved (no re-enrollment)."
else
  log "Manager: ${MANAGER}:${MANAGER_PORT}/TCP; enrollment: ${MANAGER}:${REG_PORT}/TCP"
  log "Agent name: ${AGENT_NAME}"
fi
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

Endpoint installation / profile update:
  sudo ./install-agent.sh [--name HOSTNAME]
  Select Brebes-WAF or Docker-PHP when prompted.

  If Wazuh Agent is absent: installs and enrolls the Agent.
  If Wazuh Agent is already installed: preserves package, Manager, client
  identity, and unrelated configuration; merges only missing profile settings.
  Existing installations are not re-enrolled or upgraded by package manager.

Brebes-WAF:
  Discovery runs on the Brebes-WAF endpoint using nginx -T, which expands active
  Nginx include files. Every server block must have an explicit access_log whose
  referenced log_format is verified as a JSON object using escape=json.
  Missing/default, disabled, dynamic, or non-JSON access logs abort installation
  before package installation, enrollment, or Agent configuration changes.
  Nginx error logs and discovered ModSecurity log paths are collected as syslog.
  Nginx and ModSecurity configurations are never modified.
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
  Enrollment password is requested only for first-time installation and is
  never stored in bundle. Existing Agent installations are not re-enrolled.
  Configuration updates are idempotent, backed up, validated, and rolled back
  on activation failure. Existing unrelated XML content is preserved.

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
log "Profiles: brebes-waf, docker-php. Existing Agents are updated in place; no re-enrollment."
log "No enrollment secret was copied or embedded."
