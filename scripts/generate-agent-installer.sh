#!/usr/bin/env bash
#
# ============================================================================
# DefenseOps - Wazuh Agent Installer Generator
# ============================================================================
# Version     : 1.8.24
# Release     : 2026-11-22
# Execution   : Run ONLY on the DefenseOps Manager server.
# Output      : <repository>/agent/output/ (excluded from Git)
# Target      : Debian/Ubuntu and RHEL-compatible Linux endpoints
#
# This generator does not inspect or modify Nginx/ModSecurity on DefenseOps.
# Brebes-WAF discovery is performed locally by install-agent.sh on the endpoint.
# Enrollment secrets are never embedded in the generated bundle.
# ============================================================================

set -Eeuo pipefail

SCRIPT_VERSION="1.8.24"
SCRIPT_RELEASE="2026-11-22"
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
  1. Brebes-WAF -> Wazuh group Brebes-WAF
  2. Docker-PHP -> Wazuh group docker-php

Brebes-WAF Nginx and ModSecurity discovery runs on the endpoint itself.
No Docker CLI or Docker Engine is required by this generator.
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

# Manager enrollment prerequisites are checked by the endpoint enrollment itself.

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

# Endpoint-side installer. Package installation and enrollment are separate.
# New and pre-installed unenrolled Agents use explicit agent-auth enrollment.
# Existing enrolled identities are preserved; only missing profile settings merge.
cat > "${OUT_DIR}/install-agent.sh" <<'INSTALLER'
#!/usr/bin/env bash
set -Eeuo pipefail

WAZUH_AGENT_VERSION="4.14.10"
INSTALLER_VERSION="1.8.24"
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
  -c, --config FILE        Generated ossec.conf (default: ./ossec.conf)
  -h, --help               Show help

At runtime, select Brebes-WAF or Docker-PHP.
A read-only pre-flight validation runs before package, Agent configuration,
collector, inotify, or service changes. First-time installation requests an enrollment password. Existing Agents
are never reinstalled or re-enrolled automatically. Their existing identity is
preserved and the selected profile configuration is repaired/merged in place.
EOF
}

while (($#)); do
  case "$1" in
    -m|--manager) [[ $# -ge 2 ]] || die "Missing Manager address."; MANAGER="$2"; shift 2 ;;
    -n|--name) [[ $# -ge 2 ]] || die "Missing agent name."; AGENT_NAME="$2"; shift 2 ;;
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

AGENT_PACKAGE_INSTALLED=0
if command -v dpkg-query >/dev/null 2>&1 &&
   dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null | grep -q 'install ok installed'; then
  AGENT_PACKAGE_INSTALLED=1
elif command -v rpm >/dev/null 2>&1 && rpm -q wazuh-agent >/dev/null 2>&1; then
  AGENT_PACKAGE_INSTALLED=1
fi

# A pre-existing/manual installation must never be mistaken for a fresh host
# merely because its package database is unavailable or incomplete.
if (( AGENT_PACKAGE_INSTALLED == 0 )) && [[ -x /var/ossec/bin/wazuh-agentd ]]; then
  AGENT_PACKAGE_INSTALLED=1
  log "Existing Wazuh Agent binary detected outside the package database; treating endpoint as an existing installation."
fi

ACTIVE_AGENT_CONF="/var/ossec/etc/ossec.conf"
ACTIVE_MANAGER=""
if (( AGENT_PACKAGE_INSTALLED == 1 )) && [[ -s "$ACTIVE_AGENT_CONF" ]]; then
  ACTIVE_MANAGER="$(sed -n 's:.*<address>\([^<]*\)</address>.*:\1:p' "$ACTIVE_AGENT_CONF" | head -n1)"
  # A literal template token is not a usable Manager address. Do not let it
  # override the trusted address embedded in this generated bundle.
  case "${ACTIVE_MANAGER,,}" in
    ""|manager_ip|"<manager_ip>"|changeme|"<manager>") ACTIVE_MANAGER="" ;;
  esac
fi

AGENT_ENROLLED=0
if (( AGENT_PACKAGE_INSTALLED == 1 )) &&
   [[ -s /var/ossec/etc/client.keys ]] &&
   awk 'NF >= 3 { found=1 } END { exit(found ? 0 : 1) }' /var/ossec/etc/client.keys; then
  AGENT_ENROLLED=1
fi
AGENT_WAS_ENROLLED="$AGENT_ENROLLED"
RESET_EXISTING=0

if [[ -z "$MANAGER" && -n "$ACTIVE_MANAGER" ]]; then
  MANAGER="$ACTIVE_MANAGER"
fi
if [[ -z "$MANAGER" && -f "$CONFIG_FILE" ]]; then
  MANAGER="$(sed -n 's:.*<address>\([^<]*\)</address>.*:\1:p' "$CONFIG_FILE" | head -n1)"
fi
case "${MANAGER,,}" in
  ""|manager_ip|"<manager_ip>"|changeme|"<manager>")
    die "Manager address is empty or a template placeholder. Check the generated bundle or use --manager IP/FQDN." ;;
esac
[[ "$MANAGER" =~ ^[A-Za-z0-9._:-]+$ ]] || die "Invalid Manager address: $MANAGER"

if (( AGENT_PACKAGE_INSTALLED == 1 )); then
  echo
  echo "Existing Wazuh Agent installation detected."
  echo "  Current Manager : ${ACTIVE_MANAGER:-not detected}"
  if (( AGENT_ENROLLED == 1 )); then
    echo "  Enrollment      : enrolled"
    log "Existing Agent identity will be preserved; no package reinstall or re-enrollment."
  else
    echo "  Enrollment      : not enrolled"
    log "Existing package detected without enrollment; package will be retained and enrollment completed."
  fi
  if [[ -n "$ACTIVE_MANAGER" ]]; then
    if [[ -n "$MANAGER" && "$MANAGER" != "$ACTIVE_MANAGER" ]]; then
      die "Installed Agent uses Manager '${ACTIVE_MANAGER}'. Refusing to redirect or re-enroll an existing Agent."
    fi
    MANAGER="$ACTIVE_MANAGER"
  fi
  log "Selected profile settings will be repaired/merged into the active ossec.conf."
fi
[[ "$MANAGER" =~ ^[A-Za-z0-9._:-]+$ ]] || die "Invalid Manager address."
[[ -n "$AGENT_NAME" ]] || AGENT_NAME="$(hostname -s)"
[[ "$AGENT_NAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "Invalid agent name."

echo
echo "Select endpoint profile:"
echo "  [1] Brebes-WAF (Nginx + ModSecurity)"
echo "  [2] Docker-PHP (only Docker-PHP-managed applications)"
read -r -p "Select profile [1/2]: " profile_answer
case "$profile_answer" in
  1)
    ENDPOINT_PROFILE="brebes-waf"
    AGENT_GROUP="Brebes-WAF"
    ;;
  2)
    ENDPOINT_PROFILE="docker-php"
    AGENT_GROUP="docker-php"
    ;;
  *)
    die "Invalid profile selection. Choose 1 or 2."
    ;;
esac
log "Selected endpoint profile: ${ENDPOINT_PROFILE}"
log "Wazuh agent group: ${AGENT_GROUP}"
log "DefenseOps installer version: ${INSTALLER_VERSION}"

if (( AGENT_PACKAGE_INSTALLED == 1 && AGENT_ENROLLED == 1 )); then
  log "Enrolled Wazuh Agent detected: profile/configuration update only."
  log "Package, enrollment identity, Manager address, and current group membership will be preserved."
  log "Selected target group '${AGENT_GROUP}' applies on first enrollment only; existing group membership is unchanged."
elif (( AGENT_PACKAGE_INSTALLED == 1 && AGENT_ENROLLED == 0 )); then
  log "Wazuh Agent package is installed but not enrolled: enrollment will be completed without reinstalling the package."
else
  log "Wazuh Agent package is not installed: performing package installation and first-time enrollment."
fi

# ---------------------------------------------------------------------------
# Brebes-WAF endpoint-local discovery. nginx -T expands active include files,
# so discovery is performed on the WAF host, not on the DefenseOps generator.
# ---------------------------------------------------------------------------
declare -A NGINX_ACCESS_LOGS=()
declare -A NGINX_ERROR_LOGS=()
declare -A MODSEC_AUDIT_FILES=()
declare -A MODSEC_DEBUG_FILES=()
declare -A MODSEC_STORAGE_DIRS=()
MODSEC_AUDIT_TYPE="Serial"
MODSEC_COLLECTOR_ENABLED=0
MODSEC_JSON_LOG="/var/log/defenseops/modsecurity-events.json"
declare -a MODSEC_PARSER_ROOTS=()
NGINX_DUMP=""
DISCOVERY_REPORT=""
MODSEC_REPORT=""

# Parse ModSecurity directives with shlex so quoted paths, comments, and
# whitespace are handled correctly. Includes are expanded recursively.
# This is discovery only: no Nginx/ModSecurity file is edited.
discover_modsecurity_files(){
  local dump_file="$1"
  local report_file="$2"

  python3 - "$dump_file" "$report_file" <<'PYMODSEC'
import glob
import os
import shlex
import sys
from pathlib import Path

nginx_dump = Path(sys.argv[1])
report_path = Path(sys.argv[2])

def parse_words(line):
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    return list(lexer)

def is_concrete_absolute_path(value):
    return (
        bool(value)
        and os.path.isabs(value)
        and "$" not in value
        and "\x00" not in value
        and "\t" not in value
    )

# nginx -T prints active configuration source lines. Only the exact Nginx
# directive is considered; source-marker and commented lines are ignored.
rules_files = []
for raw in nginx_dump.read_text(encoding="utf-8", errors="replace").splitlines():
    try:
        words = parse_words(raw)
    except ValueError:
        continue
    if len(words) >= 2 and words[0] == "modsecurity_rules_file":
        value = words[1].removesuffix(";")
        if is_concrete_absolute_path(value):
            rules_files.append(Path(value))

seen_files = set()
audit_files = set()
debug_files = set()
storage_dirs = set()
audit_types = set()
queue = list(rules_files)

while queue:
    current = queue.pop(0)
    try:
        resolved = current.resolve(strict=True)
    except OSError:
        continue
    if not resolved.is_file():
        continue
    key = str(resolved)
    if key in seen_files:
        continue
    seen_files.add(key)

    try:
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        continue

    for raw in lines:
        try:
            words = parse_words(raw)
        except ValueError:
            continue
        if len(words) < 2:
            continue

        directive = words[0].lower()
        value = words[1].removesuffix(";")

        if directive == "secauditlog":
            if is_concrete_absolute_path(value):
                audit_files.add(value)
            continue

        if directive == "secdebuglog":
            if is_concrete_absolute_path(value):
                debug_files.add(value)
            continue

        if directive == "secauditlogtype":
            if value.lower() in ("serial", "concurrent"):
                audit_types.add(value.capitalize())
            continue

        if directive == "secauditlogstoragedir":
            if is_concrete_absolute_path(value):
                storage_dirs.add(value)
            continue

        if directive in ("include", "includeoptional"):
            # Preserve the existing relative-include behavior: resolve from
            # the directory containing the file that declares the Include.
            pattern = value if os.path.isabs(value) else str(resolved.parent / value)
            for match in sorted(glob.glob(pattern)):
                candidate = Path(match)
                if candidate.is_file():
                    queue.append(candidate)

with report_path.open("w", encoding="utf-8") as out:
    for path in sorted(audit_files):
        out.write(f"AUDIT_FILE\t{path}\n")
    for path in sorted(debug_files):
        out.write(f"DEBUG_FILE\t{path}\n")
    for path in sorted(storage_dirs):
        out.write(f"DIR\t{path}\n")
    if not audit_types and storage_dirs:
        audit_types.add("Concurrent")
    if len(audit_types) > 1:
        raise SystemExit("Conflicting SecAuditLogType directives found: " + ", ".join(sorted(audit_types)))
    for audit_type in sorted(audit_types):
        out.write(f"TYPE\t{audit_type}\n")
PYMODSEC
}


discover_brebes_waf(){
  local dump_file report_file
  command -v nginx >/dev/null 2>&1 || die "Brebes-WAF profile selected, but nginx command was not found."
  command -v python3 >/dev/null 2>&1 || die "python3 is required for reliable Nginx virtual-host/log-format discovery."
  dump_file="$(mktemp)"; report_file="$(mktemp)"; modsec_report="$(mktemp)"
  NGINX_DUMP="$dump_file"; DISCOVERY_REPORT="$report_file"; MODSEC_REPORT="$modsec_report"
  if ! nginx -T >"$dump_file" 2>&1; then
    cat "$dump_file" >&2
    die "nginx -T failed. Fix/check Nginx configuration before installing the WAF profile."
  fi

  if ! python3 - "$report_file" <<'PYNGINX'
import glob
import os
import re
import subprocess
import sys
from pathlib import Path

report = sys.argv[1]

def fail(message, code=2):
    print(f"[ERROR] {message}", file=sys.stderr)
    raise SystemExit(code)

# Discover the exact main configuration path from the running Nginx build.
try:
    version_output = subprocess.run(
        ["nginx", "-V"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, check=True
    ).stdout
except Exception as exc:
    fail(f"Cannot determine Nginx build configuration: {exc}")

conf_match = re.search(r"(?:^|\s)--conf-path=([^\s]+)", version_output)
prefix_match = re.search(r"(?:^|\s)--prefix=([^\s]+)", version_output)
conf_path = Path(conf_match.group(1) if conf_match else "/etc/nginx/nginx.conf")
prefix_path = Path(prefix_match.group(1) if prefix_match else "/usr/share/nginx")
conf_dir = conf_path.parent

class Node:
    def __init__(self, name, args=None, parent=None, source=None):
        self.name = name
        self.args = args or []
        self.parent = parent
        self.source = source
        self.directives = []
        self.children = []

def tokenize(data, filename):
    # Quoted arguments remain one token. Braces, semicolons and # inside
    # quoted strings are data, never Nginx structural tokens.
    pattern = re.compile(
        r"""(?xs)\s+| \#[^\n]* | "(?:\\.|[^"\\])*" | '(?:\\.|[^'\\])*' | [;{}] | [^\s;{}#]+"""
    )
    result = []
    for match in pattern.finditer(data):
        token = match.group(0)
        if not token or token.isspace() or token.startswith("#"):
            continue
        if token[0] in ("'", '"') and token[-1] == token[0]:
            # Sentinel protects quoted braces/semicolons from parser syntax.
            token = "\\x01" + token[1:-1]
        result.append(token)
    return result

def include_matches(value, current_file):
    if not os.path.isabs(value):
        candidates = [
            current_file.parent / value,
            conf_dir / value,
            prefix_path / value,
        ]
    else:
        candidates = [Path(value)]
    matches = []
    for candidate in candidates:
        found = sorted(glob.glob(str(candidate)))
        if found:
            matches.extend(Path(item) for item in found if Path(item).is_file())
            break
    # Preserve order while removing duplicate resolved paths.
    unique = []
    seen = set()
    for item in matches:
        resolved = str(item.resolve())
        if resolved not in seen:
            seen.add(resolved)
            unique.append(Path(resolved))
    return unique

# Parse a file with a cursor-based recursive descent. Includes are expanded
# into the current context at the exact position of the include directive.
def parse_context(tokens, index, parent, current_file, stack, top_fragment=False):
    while index < len(tokens):
        words = []
        while index < len(tokens) and tokens[index] not in (";", "{", "}"):
            words.append(tokens[index])
            index += 1
        if index >= len(tokens):
            if words:
                fail(f"Directive without ';' at end of {current_file}: {' '.join(words)}")
            return index
        marker = tokens[index]
        index += 1
        if marker == "}":
            if words or top_fragment:
                fail(f"Unexpected '}}' in {current_file}")
            return index
        if not words:
            fail(f"Empty directive/context in {current_file}")
        def decode(value):
            return value[1:] if value.startswith("\\x01") else value
        words = [decode(value) for value in words]
        directive, args = words[0], words[1:]
        if marker == ";":
            if directive == "include":
                if len(args) != 1:
                    fail(f"Invalid include directive in {current_file}: {' '.join(words)}")
                for included in include_matches(args[0], current_file):
                    parse_file_into_context(included, parent, stack)
            else:
                parent.directives.append((directive, args, str(current_file)))
        else:
            child = Node(directive, args, parent, str(current_file))
            index = parse_context(tokens, index, child, current_file, stack)
            parent.children.append(child)
    if top_fragment:
        return index
    fail(f"Unclosed context in {current_file}")

def parse_file_into_context(path, parent, stack):
    path = path.resolve()
    key = str(path)
    if key in stack:
        fail("Nginx include cycle detected: " + " -> ".join(stack + [key]))
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        fail(f"Cannot read included Nginx configuration {path}: {exc}")
    tokens = tokenize(data, str(path))
    parse_context(tokens, 0, parent, path, stack + [key], top_fragment=True)

root = Node("root")
parse_file_into_context(conf_path, root, [])

def walk(node):
    yield node
    for child in node.children:
        yield from walk(child)

def direct(node, name):
    return [args for key, args, _source in node.directives if key == name]

http_nodes = [node for node in walk(root) if node.name == "http"]
if not http_nodes:
    fail(f"No http context found in {conf_path}")
if len(http_nodes) > 1:
    fail(f"Multiple http contexts found in {conf_path}; refusing ambiguous discovery")

http = http_nodes[0]
formats = {}
for args in direct(http, "log_format"):
    if len(args) < 2:
        continue
    name, rest = args[0], args[1:]
    escaped = any(item.lower() == "escape=json" for item in rest)
    body = "".join(item for item in rest if not item.lower().startswith("escape="))
    formats[name] = bool(
        escaped and "{" in body and "}" in body
        and re.search(r'"[^"]+"\s*:', body)
    )

servers = [node for node in walk(http) if node.name == "server"]
if not servers:
    fail(f"No server virtual-host blocks found inside http context in {conf_path}")

rows, failures = [], []
for index, server in enumerate(servers, 1):
    names = [item for args in direct(server, "server_name") for item in args]
    vhost = ",".join(names) if names else f"<server-block-{index}-without-server_name>"

    # Accept a dedicated verified JSON log at http scope (e.g. conf.d),
    # while excluding the conventional global text access.log.
    for args in direct(http, "access_log"):
        if not args:
            continue
        path = args[0]
        if path in ("off", "/var/log/nginx/access.log"):
            continue
        if not path.startswith("/") or "$" in path or "\\t" in path:
            continue
        fmt = "combined"
        for candidate in args[1:]:
            if candidate.startswith(("buffer=", "gzip=", "flush=", "if=")):
                continue
            fmt = candidate
            break
        if formats.get(fmt, False):
            rows.append(("<http-context>", path, fmt, "json"))
        else:
            print(f"[INFO] Ignoring non-JSON http-level access_log: {path} (format={fmt})")

    # Explicit virtual-host/nested access logs retain strict JSON validation.
    explicit_access = []
    for descendant in walk(server):
        explicit_access.extend(direct(descendant, "access_log"))

    for args in explicit_access:
        if not args:
            failures.append((vhost, "<unknown>", "empty access_log directive"))
            continue
        path = args[0]
        if path in ("off", "/var/log/nginx/access.log"):
            continue
        if not path.startswith("/") or "$" in path or "\\t" in path:
            failures.append((vhost, path, "dynamic/non-file access_log path cannot be monitored safely"))
            continue

        fmt = "combined"
        for candidate in args[1:]:
            if candidate.startswith(("buffer=", "gzip=", "flush=", "if=")):
                continue
            fmt = candidate
            break

        if not formats.get(fmt, False):
            failures.append((
                vhost, path,
                f"format '{fmt}' is not verified JSON (requires escape=json and a JSON object)"
            ))
        else:
            rows.append((vhost, path, fmt, "json"))

# Preserve existing error-log discovery behavior: use explicit server/tree
# error logs where present; otherwise inherit the http-level error_log.
http_errors = direct(http, "error_log")
for index, server in enumerate(servers, 1):
    names = [item for args in direct(server, "server_name") for item in args]
    vhost = ",".join(names) if names else f"<server-block-{index}-without-server_name>"
    own_errors = [args for node in walk(server) for args in direct(node, "error_log")]
    if not own_errors:
        own_errors = http_errors
    for args in own_errors:
        if not args:
            continue
        path = args[0]
        if path in ("stderr", "syslog") or path.startswith("syslog:"):
            continue
        if path.startswith("/") and "$" not in path and " " not in path:
            rows.append((vhost, path, "nginx-error", "syslog"))

if failures:
    print("[ERROR] Brebes-WAF JSON access-log validation failed:", file=sys.stderr)
    for vhost, path, reason in failures:
        print(f"  VHOST: {vhost}\n  PATH : {path}\n  WHY  : {reason}", file=sys.stderr)
    print("[ERROR] Fix every listed virtual host and rerun install-agent.sh.", file=sys.stderr)
    raise SystemExit(3)

seen = set()
with open(report, "w", encoding="utf-8") as output:
    for row in rows:
        if row not in seen:
            seen.add(row)
            output.write("\t".join(row) + "\n")

print(f"[INFO] Nginx virtual hosts checked: {len(servers)}")
print(f"[INFO] Verified JSON access-log entries: {sum(1 for row in rows if row[3] == 'json')}")
print(f"[INFO] Nginx error-log entries: {sum(1 for row in rows if row[3] == 'syslog')}")
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

  # Discover ModSecurity audit/debug files from every active
  # modsecurity_rules_file and its recursive Include tree.
  discover_modsecurity_files "$dump_file" "$modsec_report"
  while IFS=$'\t' read -r kind path; do
    [[ -n "${path:-}" ]] || continue
    case "$kind" in
      AUDIT_FILE) MODSEC_AUDIT_FILES["$path"]=1 ;;
      DEBUG_FILE) MODSEC_DEBUG_FILES["$path"]=1 ;;
      DIR)        MODSEC_STORAGE_DIRS["$path"]=1 ;;
      TYPE)       MODSEC_AUDIT_TYPE="$path" ;;
    esac
  done < "$modsec_report"

  ((${#NGINX_ACCESS_LOGS[@]} > 0)) || die "No verified JSON Nginx access logs found. Agent installation aborted."
  log "Nginx discovery: ${#NGINX_ACCESS_LOGS[@]} JSON access log(s), ${#NGINX_ERROR_LOGS[@]} text error log(s)."
  log "ModSecurity discovery: ${#MODSEC_AUDIT_FILES[@]} SecAuditLog file(s), ${#MODSEC_DEBUG_FILES[@]} SecDebugLog file(s), ${#MODSEC_STORAGE_DIRS[@]} SecAuditLogStorageDir director(ies); audit type=${MODSEC_AUDIT_TYPE}."
  if [[ "$MODSEC_AUDIT_TYPE" == "Concurrent" ]]; then
    for path in "${!MODSEC_STORAGE_DIRS[@]}"; do
      [[ -d "$path" ]] || { warn "SecAuditLogStorageDir does not exist yet: $path"; continue; }
      MODSEC_PARSER_ROOTS+=("$path")
      printf '  [MODSEC-AUDIT-ROOT] %s\n' "$path"
    done
    if ((${#MODSEC_PARSER_ROOTS[@]} == 0)) && ((${#MODSEC_AUDIT_FILES[@]} > 0)); then
      warn "SecAuditLogType Concurrent was found, but no existing SecAuditLogStorageDir was found. SecAuditLog index files are not transaction logs; collector will not guess a directory."
    fi
  else
    for path in "${!MODSEC_AUDIT_FILES[@]}"; do
      [[ -f "$path" ]] || { warn "SecAuditLog file does not exist yet: $path"; continue; }
      MODSEC_PARSER_ROOTS+=("$path")
      printf '  [MODSEC-AUDIT-FILE] %s\n' "$path"
    done
  fi
  for path in "${!MODSEC_DEBUG_FILES[@]}"; do
    if [[ -e "$path" ]]; then
      printf '  [MODSEC-DEBUG-LOG] %s (discovered; not used as audit event source)\n' "$path"
    else
      warn "SecDebugLog path does not exist yet: $path"
    fi
  done
  if ((${#MODSEC_PARSER_ROOTS[@]} > 0)); then
    MODSEC_COLLECTOR_ENABLED=1
    log "ModSecurity audit parser enabled with ${#MODSEC_PARSER_ROOTS[@]} root path(s)."
  else
    warn "No usable ModSecurity audit source was found. Wazuh Agent will still collect Nginx logs; ModSecurity JSON collection is skipped."
  fi
}

install_docker_php_monitoring(){
  local lib_dir="/usr/local/libexec"
  local config_dir="/etc/defenseops"
  local state_dir="/var/lib/defenseops/docker-php"
  local log_dir="/var/log/defenseops"
  local collector="${lib_dir}/defenseops-docker-php-collector.py"

  command -v docker >/dev/null 2>&1 || warn "Docker CLI not found; Docker-PHP collector will wait until Docker is installed/available."
  install -d -o root -g root -m 0755 "$lib_dir" "$config_dir"
  install -d -o root -g root -m 0750 "$state_dir"
  if getent group wazuh >/dev/null 2>&1; then
    install -d -o root -g wazuh -m 0750 "$log_dir"
  else
    install -d -o root -g root -m 0750 "$log_dir"
  fi

  cat > "${collector}.tmp.$$" <<'PYDOCKERPHP'
#!/usr/bin/env python3
"""DefenseOps Docker-PHP runtime collector v1.14.0 (Docker Events + snapshots)."""
from __future__ import annotations
import datetime as dt, grp, hashlib, json, os, subprocess, sys, time, threading, signal, select
from pathlib import Path

COLLECTOR_VERSION = "1.14.0"
REGISTRY=Path("/var/lib/docker-php/monitoring/applications")
STATE=Path("/var/lib/defenseops/docker-php/state.json")
OUTPUT=Path("/var/log/defenseops/docker-php-events.json")
EVENT_CURSOR=Path("/var/lib/defenseops/docker-php/docker-events.cursor")
MAX_FILE_SIZE=10*1024*1024
MAX_FILES_PER_APP=20000
CPU_ALERT_PERCENT=85.0
MEMORY_ALERT_PERCENT=85.0
WORKER_SURGE_THRESHOLD=50
# Source/htdocs is restricted to code and configuration extensions.
# Writable paths are monitored regardless of file extension, except volatile
# session/cache trees which would otherwise create excessive FIM noise.
EXCLUDED={".git","vendor","node_modules","storage","cache","sessions","tmp",".idea"}
WRITABLE_EXCLUDED={"session","sessions","cache"}
SOURCE_SUFFIXES={".php",".phtml",".inc",".js",".ts",".py",".sh",".conf",".ini",".env.example",".yaml",".yml",".json"}

def emit(app,container,source,event_type,severity,message,details=None):
    event={"integration":"docker-php","schema_version":"1.0","collector_version":COLLECTOR_VERSION,
           "timestamp":dt.datetime.now().astimezone().isoformat(),"hostname":os.uname().nodename,
           "application":app,"container":container,"event_source":source,"event_type":event_type,
           "severity":severity,"message":message,"details":details or {}}
    OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    with OUTPUT.open("a",encoding="utf-8") as f:
        f.write(json.dumps(event,ensure_ascii=False,separators=(",",":"))+"\n")
    os.chmod(OUTPUT,0o640)
    try: os.chown(OUTPUT,0,grp.getgrnam("wazuh").gr_gid)
    except KeyError: pass

def load_state():
    try:
        d=json.loads(STATE.read_text(encoding="utf-8"))
        return d if isinstance(d,dict) else {}
    except (OSError,json.JSONDecodeError): return {}

def save_state(state):
    STATE.parent.mkdir(parents=True,exist_ok=True)
    tmp=STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state,separators=(",",":")),encoding="utf-8")
    os.chmod(tmp,0o600); os.replace(tmp,STATE)

def docker_inspect(name):
    try:
        p=subprocess.run(["docker","inspect",name],capture_output=True,text=True,timeout=15,check=True)
        a=json.loads(p.stdout); return a[0] if a else None
    except (OSError,subprocess.SubprocessError,json.JSONDecodeError,IndexError): return None

def configured_fpm_socket(cfg):
    pool_file=cfg.get("fpm_pool")
    if not isinstance(pool_file,str) or not pool_file.startswith("/"):
        return None
    try:
        content=Path(pool_file).read_text(encoding="utf-8",errors="replace")
    except OSError:
        return None
    for line in content.splitlines():
        line=line.split(";",1)[0].strip()
        if line.lower().startswith("listen") and "=" in line:
            value=line.split("=",1)[1].strip().strip('"').strip("'")
            if value.startswith("/"):
                return value
    return None

def inspect_php_fpm(container,socket_path):
    # Inspect PHP-FPM pool workers, master process, and configured Unix socket.
    # The master process is deliberately not counted as a worker.
    cmd=r"""
workers=0
root_workers=0
fpm_processes=0
worker_uids=""
for p in /proc/[0-9]*; do
 [ -r "$p/cmdline" ] || continue
 c=$(tr '\000' ' ' < "$p/cmdline" 2>/dev/null) || continue
 case "$c" in
  "php-fpm: master process"*)
   fpm_processes=$((fpm_processes+1))
   ;;
  "php-fpm: pool "*)
   workers=$((workers+1))
   fpm_processes=$((fpm_processes+1))
   u=$(awk '/^Uid:/ {print $2; exit}' "$p/status" 2>/dev/null)
   if [ -n "$u" ]; then
    case ",$worker_uids," in
     *,"$u",*) ;;
     *) worker_uids="${worker_uids}${worker_uids:+,}$u" ;;
    esac
   fi
   [ "$u" = "0" ] && root_workers=$((root_workers+1))
   ;;
 esac
done
printf 'workers=%s\nroot_workers=%s\nfpm_processes=%s\nworker_uids=%s\n' \
 "$workers" "$root_workers" "$fpm_processes" "$worker_uids"
if [ -n "$1" ]; then
 if awk -v s="$1" '$8==s {found=1} END {exit(found?0:1)}' /proc/net/unix 2>/dev/null; then
  echo socket_listening=yes
 else
  echo socket_listening=no
 fi
else
 echo socket_listening=unknown
fi
"""
    try:
        p=subprocess.run(["docker","exec",container,"sh","-c",cmd,"sh",socket_path or ""],
                         capture_output=True,text=True,timeout=10)
    except (OSError,subprocess.SubprocessError):
        return {"status":"unknown","workers":None,"root_workers":None,
                "fpm_processes":None,"worker_uids":[],"root_worker_uids":[],
                "socket_path":socket_path,"socket_listening":"unknown"}
    values={}
    for line in p.stdout.splitlines():
        if "=" in line:
            k,v=line.split("=",1); values[k]=v
    def number(key):
        try: return int(values[key])
        except (KeyError,ValueError): return None
    workers=number("workers")
    processes=number("fpm_processes")
    worker_uids=[]
    for uid in values.get("worker_uids", "").split(","):
        try:
            if uid.strip():
                worker_uids.append(int(uid.strip()))
        except ValueError:
            continue
    worker_uids=sorted(set(worker_uids))
    root_worker_uids=[uid for uid in worker_uids if uid == 0]
    socket_state=values.get("socket_listening","unknown")
    if p.returncode != 0 or processes is None:
        status="unknown"
    elif processes == 0:
        status="stopped"
    elif workers == 0:
        status="no_workers"
    else:
        status="active"
    return {"status":status,"workers":workers,"root_workers":number("root_workers"),
            "fpm_processes":processes,"worker_uids":worker_uids,
            "root_worker_uids":root_worker_uids,"socket_path":socket_path,
            "socket_listening":socket_state}

def docker_resource_stats(container):
    try:
        p=subprocess.run(["docker","stats","--no-stream","--format","{{json .}}",container],
                         capture_output=True,text=True,timeout=15,check=True)
        row=json.loads(p.stdout.strip().splitlines()[0])
    except (OSError,subprocess.SubprocessError,json.JSONDecodeError,IndexError):
        return {"status":"unavailable"}
    def pct(value):
        try: return float(str(value).strip().rstrip("%"))
        except (TypeError,ValueError): return None
    def byte_value(value):
        import re
        m=re.match(r"^\s*([0-9.]+)\s*([KMGT]?i?B)\s*$",str(value),re.I)
        if not m: return None
        scale={"B":1,"KB":1000,"MB":1000**2,"GB":1000**3,"TB":1000**4,
               "KIB":1024,"MIB":1024**2,"GIB":1024**3,"TIB":1024**4}
        return int(float(m.group(1))*scale.get(m.group(2).upper(),1))
    mem_usage=row.get("MemUsage","")
    mem_parts=[x.strip() for x in str(mem_usage).split("/",1)]
    return {"status":"ok","cpu_percent":pct(row.get("CPUPerc")),
            "memory_percent":pct(row.get("MemPerc")),
            "memory_usage_bytes":byte_value(mem_parts[0]) if mem_parts else None,
            "memory_limit_bytes":byte_value(mem_parts[1]) if len(mem_parts)>1 else None,
            "block_io":row.get("BlockIO"),"network_io":row.get("NetIO")}

def file_manifest(root, source_only=False):
    """Return SHA256 fingerprints for one approved application directory.

    Source/htdocs uses SOURCE_SUFFIXES. Writable paths accept every regular
    file type but skip session/cache directories. Symlinks are never followed.
    """
    result={}
    if not root.is_dir(): return result
    excluded=EXCLUDED if source_only else WRITABLE_EXCLUDED
    if root.name.lower() in excluded: return result
    count=0
    for current,dirs,files in os.walk(root,followlinks=False):
        dirs[:]=[d for d in dirs if d.lower() not in excluded and not (Path(current)/d).is_symlink()]
        for name in files:
            p=Path(current)/name
            if p.is_symlink(): continue
            if source_only and not (p.suffix.lower() in SOURCE_SUFFIXES or p.name.lower().endswith(".env.example")):
                continue
            try:
                st=p.stat()
                if not p.is_file() or st.st_size>MAX_FILE_SIZE: continue
                h=hashlib.sha256()
                with p.open("rb") as f:
                    for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
                result[str(p)]=h.hexdigest(); count+=1
                if count>=MAX_FILES_PER_APP: return result
            except OSError: continue
    return result


def registered_writable_paths(cfg, app_root, apps_root, app):
    """Normalize and validate registry writable (string or list of strings)."""
    raw=cfg.get("writable")
    if raw is None or raw == "": return []
    if isinstance(raw,str):
        candidates=[raw]
    elif isinstance(raw,list):
        candidates=raw
    else:
        print(f"[WARN] {app}: registry writable must be a string or array; ignoring it.",file=sys.stderr)
        return []
    paths=[]
    seen=set()
    for item in candidates:
        if not isinstance(item,str) or not item or "\x00" in item:
            print(f"[WARN] {app}: invalid writable path entry ignored: {item!r}",file=sys.stderr)
            continue
        try:
            path=Path(item).resolve(strict=True)
            if not path.is_dir():
                raise ValueError("not a directory")
            if not path.is_relative_to(app_root) or not path.is_relative_to(apps_root):
                raise ValueError("outside this application's /var/apps directory")
        except (OSError,ValueError) as exc:
            print(f"[WARN] {app}: writable path rejected ({item}): {exc}",file=sys.stderr)
            continue
        value=str(path)
        if value not in seen:
            paths.append(path); seen.add(value)
    return paths

def old_fingerprints(previous,app):
    v=previous.get(app)
    return (v.get("health"),v.get("security")) if isinstance(v,dict) else (None,None)

def monitoring_enabled(cfg, key, default=True):
    flags=cfg.get("monitoring")
    if not isinstance(flags,dict):
        return default
    value=flags.get(key,default)
    return value is True

def collect_once():
    state=load_state(); previous=state.get("containers",{}); previous_files=state.get("files",{})
    previous_writable_roots=state.get("writable_roots",{})
    if not isinstance(previous,dict): previous={}
    if not isinstance(previous_files,dict): previous_files={}
    if not isinstance(previous_writable_roots,dict): previous_writable_roots={}
    current_containers={}; current_files={}; current_writable_roots={}
    if not REGISTRY.is_dir():
        print(f"[WARN] Registry directory unavailable: {REGISTRY}",file=sys.stderr); return 0
    try: registry_files=sorted(REGISTRY.glob("*.json"))
    except OSError as e:
        print(f"[WARN] Cannot enumerate registry: {e}",file=sys.stderr); return 0
    apps_root=Path("/var/apps").resolve()
    for rf in registry_files:
        try:
            cfg=json.loads(rf.read_text(encoding="utf-8"))
            if not isinstance(cfg,dict):
                raise ValueError("registry root must be a JSON object")
            app,container,source=cfg.get("application"),cfg.get("container"),cfg.get("source")
            if not all(isinstance(x,str) and x and "\x00" not in x for x in (app,container,source)):
                raise ValueError("application, container and source must be non-empty strings")
            source_path=Path(source).resolve(strict=True)
            if not source_path.is_dir() or not source_path.is_relative_to(apps_root):
                raise ValueError(f"source path outside /var/apps or unavailable: {source}")
            app_root=source_path.parent
            writable_paths=registered_writable_paths(cfg,app_root,apps_root,app)
        except (OSError,ValueError,json.JSONDecodeError,AttributeError) as e:
            print(f"[WARN] Invalid registry {rf}: {e}",file=sys.stderr); continue

        do_health=monitoring_enabled(cfg,"docker_health")
        do_security=monitoring_enabled(cfg,"security")
        do_fpm=monitoring_enabled(cfg,"php_fpm")
        health={"status":"disabled"} if not do_health else {"status":"unknown"}
        sec={"inspection":"disabled","security_findings":[]} if not do_security else {
            "inspection":"unavailable","security_findings":[]}
        fpm={"status":"disabled"} if not do_fpm else {"status":"unknown"}
        resources={"status":"disabled"} if not do_fpm else {"status":"unavailable"}
        # File integrity is owned exclusively by the dedicated inotify daemon.
        # Wazuh Syscheck does not watch application trees; it only ingests JSONL.
        do_fim=False
        if monitoring_enabled(cfg,"malware",False):
            print(f"[WARN] {app}: monitoring.malware=true is not implemented by this collector; no malware scan is performed.",file=sys.stderr)

        old_entry=previous.get(app,{})
        if not isinstance(old_entry,dict): old_entry={}
        entry=dict(old_entry)
        obj=docker_inspect(container)
        status="unknown"
        if do_health:
            if obj is None:
                status="not_found"; health={"status":status,"registry":str(rf)}
            else:
                st=obj.get("State") or {}; ho=st.get("Health") or {}
                status=ho.get("Status") or st.get("Status") or "unknown"
                health={"status":status,"restart_count":obj.get("RestartCount",0),
                        "health_failing_streak":ho.get("FailingStreak",0)}
            hfp=json.dumps(health,sort_keys=True)
            oldh=old_entry.get("health")
            entry["health"]=hfp
            if oldh!=hfp:
                emit(app,container,"docker_health","container_state_changed",
                     "high" if status in ("unhealthy","not_found","dead") else "info",
                     "Docker-PHP container health state changed",health)

        if do_security:
            if obj is None:
                sec={"inspection":"unavailable","security_findings":[]}
            else:
                host=obj.get("HostConfig") or {}; conf=obj.get("Config") or {}
                security={"privileged":bool(host.get("Privileged")),"read_only":bool(host.get("ReadonlyRootfs")),
                    "configured_user":conf.get("User") or "root(default)",
                    "no_new_privileges":bool(host.get("SecurityOpt") and any("no-new-privileges" in str(x).lower() for x in host.get("SecurityOpt",[]))),
                    "cap_add":host.get("CapAdd") or [],
                    "docker_socket_mounted":any("/var/run/docker.sock" in str(x) for x in (host.get("Binds") or []))}
                findings=[]
                if security["privileged"]: findings.append("privileged_container")
                if not security["read_only"]: findings.append("read_only_disabled")
                if not security["no_new_privileges"]: findings.append("no_new_privileges_disabled")
                if security["docker_socket_mounted"]: findings.append("docker_socket_mounted")
                if security["cap_add"]: findings.append("capabilities_added")
                if do_fpm:
                    fpm=inspect_php_fpm(container,configured_fpm_socket(cfg))
                    security["php_fpm_worker_check"]="checked" if fpm["status"]=="active" else fpm["status"]
                    security["php_fpm_worker_uids"]=fpm.get("worker_uids", [])
                    security["php_fpm_root_worker_uids"]=fpm.get("root_worker_uids", [])
                    if (fpm.get("root_workers") or 0)>0:
                        findings.append("root_user")
                    elif fpm.get("status")!="active":
                        findings.append("needs_review")
                sec={"security":security,"security_findings":sorted(set(findings))}
            sfp=json.dumps(sec,sort_keys=True)
            olds=old_entry.get("security")
            entry["security"]=sfp
            if olds!=sfp:
                findings=sec.get("security_findings",[])
                if findings:
                    emit(app,container,"docker_security","container_security_finding",
                         "high" if "root_user" in findings else "medium",
                         "Docker-PHP container security baseline finding",sec)
                elif olds is not None:
                    emit(app,container,"docker_security","container_security_recovered","info",
                         "Docker-PHP container security baseline recovered",sec)

        if do_fpm:
            fpm_socket=configured_fpm_socket(cfg)
            fpm=inspect_php_fpm(container,fpm_socket) if obj is not None else {
                "status":"container_unavailable","workers":None,"root_workers":None,
                "fpm_processes":None,"worker_uids":[],"root_worker_uids":[],
                "socket_path":fpm_socket,"socket_listening":"unknown"}
            resources=docker_resource_stats(container) if obj is not None else {"status":"unavailable"}
            state_obj=(obj.get("State") or {}) if obj is not None else {}
            restart_count=obj.get("RestartCount",0) if obj is not None else None
            anomalies=[]
            if fpm["status"] in ("stopped","no_workers"):
                anomalies.append("php_fpm_"+fpm["status"])
            if fpm.get("socket_listening")=="no": anomalies.append("php_fpm_socket_not_listening")
            if (fpm.get("root_workers") or 0)>0: anomalies.append("php_fpm_root_worker")
            if fpm.get("workers") is not None and fpm["workers"]>=WORKER_SURGE_THRESHOLD:
                anomalies.append("php_fpm_worker_surge")
            if resources.get("cpu_percent") is not None and resources["cpu_percent"]>=CPU_ALERT_PERCENT:
                anomalies.append("container_cpu_high")
            if resources.get("memory_percent") is not None and resources["memory_percent"]>=MEMORY_ALERT_PERCENT:
                anomalies.append("container_memory_high")
            if bool(state_obj.get("OOMKilled")): anomalies.append("container_oom_killed")
            snapshot={"php_fpm":fpm,"resources":resources,"oom_killed":bool(state_obj.get("OOMKilled")),
                      "restart_count":restart_count}
            runtime_fp=json.dumps(sorted(set(anomalies)),sort_keys=True)
            old_runtime_fp=old_entry.get("runtime_anomalies")
            entry["runtime_anomalies"]=runtime_fp
            entry["snapshot"]=snapshot
            if old_runtime_fp!=runtime_fp:
                if anomalies:
                    emit(app,container,"php_fpm_resource","runtime_anomaly","high",
                         "Docker-PHP PHP-FPM/resource monitoring detected an anomaly",
                         {"anomalies":sorted(set(anomalies)),"snapshot":snapshot,
                          "thresholds":{"cpu_percent":CPU_ALERT_PERCENT,
                                        "memory_percent":MEMORY_ALERT_PERCENT,
                                        "worker_surge":WORKER_SURGE_THRESHOLD}})
                elif old_runtime_fp not in (None,"[]"):
                    emit(app,container,"php_fpm_resource","runtime_recovered","info",
                         "Docker-PHP PHP-FPM/resource monitoring anomaly recovered",{"snapshot":snapshot})

        # Publish a complete point-in-time status for every registered app on
        # every successful 5-minute collection. This is informational telemetry:
        # it does not replace or alter the existing change-driven health/security
        # and anomaly events above.
        docker_state=(obj.get("State") or {}) if obj is not None else {}
        status_snapshot={
            "container_state":{
                "status":docker_state.get("Status","not_found" if obj is None else "unknown"),
                "running":bool(docker_state.get("Running",False)),
                "paused":bool(docker_state.get("Paused",False)),
                "restarting":bool(docker_state.get("Restarting",False)),
                "oom_killed":bool(docker_state.get("OOMKilled",False)),
                "exit_code":docker_state.get("ExitCode"),
                "started_at":docker_state.get("StartedAt"),
                "finished_at":docker_state.get("FinishedAt"),
                "restart_count":obj.get("RestartCount",0) if obj is not None else None
            },
            "health":health,
            "security":sec,
            "php_fpm":fpm,
            "resources":resources,
            "monitoring":{
                "docker_health":do_health,
                "security":do_security,
                "php_fpm":do_fpm
            }
        }
        if do_health or do_security or do_fpm:
            emit(app,container,"docker_status","container_status_snapshot","info",
                 "Docker-PHP container status snapshot",status_snapshot)

        if do_fim:
            # htdocs/source is extension-filtered; registry writable paths are
            # unrestricted by extension but exclude session/cache directories.
            manifest=file_manifest(source_path,source_only=True)
            current_roots=[str(root) for root in writable_paths]
            current_writable_roots[app]=current_roots
            prior_roots=previous_writable_roots.get(app,[])
            if not isinstance(prior_roots,list): prior_roots=[]
            for writable_root in writable_paths:
                manifest.update(file_manifest(writable_root,source_only=False))
            def in_roots(path,roots):
                return any(path==root or path.startswith(root+os.sep) for root in roots)
            old=previous_files.get(app)
            if isinstance(old,dict):
                for path,digest in manifest.items():
                    prior=old.get(path)
                    is_writable=in_roots(path,current_roots)
                    scope="writable" if is_writable else "source"
                    if prior is None:
                        # Newly enrolled writable roots are baselined silently;
                        # files created later inside an established root alert normally.
                        if is_writable and not in_roots(path,prior_roots):
                            continue
                        emit(app,container,"fim","file_added","warning","New application file detected",{"path":path,"scope":scope,"sha256":digest})
                    elif prior!=digest:
                        emit(app,container,"fim","file_modified","high","Application file modified",{"path":path,"scope":scope,"old_sha256":prior,"new_sha256":digest})
                for path,digest in old.items():
                    if path not in manifest:
                        # A writable root removed from the registry is a scope
                        # change, not evidence that its files were deleted.
                        if in_roots(path,prior_roots) and not in_roots(path,current_roots):
                            continue
                        emit(app,container,"fim","file_deleted","warning","Application file deleted",{"path":path,"old_sha256":digest})
            current_files[app]=manifest
        elif isinstance(previous_files.get(app),dict):
            current_files[app]=previous_files[app]

        current_containers[app]=entry

    # FIM ownership moved to the inotify daemon. Preserve the old manifest and
    # writable-root metadata for migration/recovery; never erase it here.
    current_writable_roots=previous_writable_roots
    save_state({"collector_version":COLLECTOR_VERSION,"containers":current_containers,
                "files":current_files,"writable_roots":current_writable_roots,
                "updated_at":time.time()})

    # Emit one heartbeat after a successful collection and state save.
    # Existing change-driven health/security/FIM/anomaly events are preserved;
    # container_status_snapshot is additional periodic informational telemetry.
    emit("system","defenseops-docker-php-collector","collector_status","heartbeat",
         "info","Docker-PHP collector is active",
         {"status":"active","applications_processed":len(current_containers),
          "collector_version":COLLECTOR_VERSION})
    return 0

def event_registry():
    """Build the event allow-list exclusively from valid Application Registry entries."""
    result={}
    if not REGISTRY.is_dir():
        return result
    for rf in sorted(REGISTRY.glob("*.json")):
        try:
            cfg=json.loads(rf.read_text(encoding="utf-8"))
            app=cfg.get("application"); container=cfg.get("container")
            if not isinstance(app,str) or not app or not isinstance(container,str) or not container:
                continue
            result[container]=(app,container)
        except (OSError,ValueError,AttributeError):
            continue
    return result

def docker_event_listener(stop_event):
    """Stream Docker container events, emitting only events for registered containers."""
    actions={"start","restart","die","stop","oom","destroy"}
    try:
        last_event_ns=int(EVENT_CURSOR.read_text(encoding="ascii").strip())
    except (OSError,ValueError):
        last_event_ns=0
    last_seen=set()
    while not stop_event.is_set():
        allow=event_registry()
        if not allow:
            stop_event.wait(15)
            continue
        since=(str(max(0,last_event_ns/1_000_000_000-2))
               if last_event_ns else str(max(0,int(time.time())-5)))
        cmd=["docker","events","--since",since,"--filter","type=container","--format","{{json .}}"]
        try:
            proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                  text=True,bufsize=1)
        except OSError as exc:
            print(f"[docker-php-collector] cannot start docker events: {exc}",file=sys.stderr,flush=True)
            stop_event.wait(10)
            continue
        try:
            while not stop_event.is_set():
                if not proc.stdout:
                    break
                ready,_,_=select.select([proc.stdout],[],[],1.0)
                if not ready:
                    if proc.poll() is not None:
                        break
                    continue
                line=proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    continue
                try:
                    event=json.loads(line)
                except ValueError:
                    continue
                actor=event.get("Actor") or {}
                attrs=actor.get("Attributes") or {}
                container_id=event.get("id") or actor.get("ID") or ""
                name=(attrs.get("name") or "").lstrip("/")
                match=allow.get(name)
                if match is None and container_id:
                    # Resolve ID only against currently registered container names.
                    for registered_name,(app,registered_container) in allow.items():
                        try:
                            inspected=docker_inspect(registered_container)
                            if inspected and (inspected.get("Id","").startswith(container_id) or
                                               container_id.startswith(inspected.get("Id","")[:12])):
                                match=(app,registered_container); break
                        except Exception:
                            pass
                action=str(event.get("Action") or event.get("status") or "").lower().split(":",1)[0]
                if match is None or action not in actions:
                    continue
                app,container=match
                stamp=event.get("timeNano") or event.get("time") or 0
                try:
                    stamp_ns=int(stamp) if int(stamp)>10**12 else int(stamp)*1_000_000_000
                except (TypeError,ValueError):
                    stamp_ns=0
                dedupe=(str(container_id),action,str(stamp))
                if dedupe in last_seen or (stamp_ns and stamp_ns<=last_event_ns):
                    continue
                last_seen.add(dedupe)
                if len(last_seen)>4096:
                    last_seen=set(list(last_seen)[-2048:])
                severity="high" if action in ("die","oom","destroy") else "info"
                emit(app,container,"docker_events",
                     "container_"+("oom_killed" if action=="oom" else action),
                     severity,"Docker container lifecycle event",
                     {"action":action,"container_id":container_id,"container_name":name,
                      "docker_time":event.get("time"),"docker_time_nano":event.get("timeNano"),
                      "actor_attributes":attrs})
                if stamp_ns:
                    last_event_ns=max(last_event_ns,stamp_ns)
                    EVENT_CURSOR.parent.mkdir(parents=True,exist_ok=True)
                    tmp=EVENT_CURSOR.with_suffix(".tmp")
                    tmp.write_text(str(last_event_ns),encoding="ascii")
                    os.chmod(tmp,0o600)
                    os.replace(tmp,EVENT_CURSOR)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait()
        if not stop_event.is_set():
            stop_event.wait(5)

def main():
    stop_event=threading.Event()
    def stop_handler(_signum,_frame):
        stop_event.set()
    signal.signal(signal.SIGTERM,stop_handler)
    signal.signal(signal.SIGINT,stop_handler)
    listener=threading.Thread(target=docker_event_listener,args=(stop_event,),daemon=True)
    listener.start()
    next_snapshot=0.0
    while not stop_event.is_set():
        now=time.monotonic()
        if now>=next_snapshot:
            try:
                collect_once()
            except Exception as exc:
                print(f"[docker-php-collector] snapshot failed: {exc}",file=sys.stderr,flush=True)
            next_snapshot=time.monotonic()+300
        stop_event.wait(1)
    return 0

if __name__=="__main__": raise SystemExit(main())
PYDOCKERPHP
  chown root:root "${collector}.tmp.$$"
  chmod 0750 "${collector}.tmp.$$"
  mv -f "${collector}.tmp.$$" "$collector"

  # Dedicated registry-scoped inotify FIM daemon. This is the sole component
  # that watches application source/writable directories and computes hashes.
  local fim_collector="${lib_dir}/defenseops-docker-php-inotify.py"
  cat > "${fim_collector}.tmp.$$" <<'PYINOTIFY'
#!/usr/bin/env python3
"""DefenseOps Docker-PHP registry-scoped inotify FIM daemon v1.0.0."""
import ctypes, ctypes.util, datetime as dt, grp, hashlib, json, os, select, signal, sqlite3, struct, sys, time
from pathlib import Path

REGISTRY=Path('/var/lib/docker-php/monitoring/applications')
DB=Path('/var/lib/defenseops/docker-php/inotify-fim.sqlite3')
OUTPUT=Path('/var/log/defenseops/docker-php-events.json')
APPS_ROOT=Path('/var/apps').resolve()
MAX_FILE_SIZE=10*1024*1024
MAX_FILES_PER_APP=20000
EXCLUDED={'.git','vendor','node_modules','storage','cache','sessions','tmp','.idea'}
WRITABLE_EXCLUDED={'session','sessions','cache'}
SOURCE_SUFFIXES={'.php','.phtml','.inc','.js','.ts','.py','.sh','.conf','.ini','.env.example','.yaml','.yml','.json'}
# Linux inotify masks
IN_MODIFY=0x00000002; IN_ATTRIB=0x00000004; IN_CLOSE_WRITE=0x00000008
IN_MOVED_FROM=0x00000040; IN_MOVED_TO=0x00000080; IN_CREATE=0x00000100
IN_DELETE=0x00000200; IN_DELETE_SELF=0x00000400; IN_MOVE_SELF=0x00000800
IN_IGNORED=0x00008000; IN_Q_OVERFLOW=0x00004000; IN_ISDIR=0x40000000
MASK=IN_CLOSE_WRITE|IN_ATTRIB|IN_MOVED_FROM|IN_MOVED_TO|IN_CREATE|IN_DELETE|IN_DELETE_SELF|IN_MOVE_SELF
libc=ctypes.CDLL(ctypes.util.find_library('c'),use_errno=True)
libc.inotify_init1.argtypes=[ctypes.c_int]; libc.inotify_init1.restype=ctypes.c_int
libc.inotify_add_watch.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_uint32]; libc.inotify_add_watch.restype=ctypes.c_int
libc.inotify_rm_watch.argtypes=[ctypes.c_int,ctypes.c_int]; libc.inotify_rm_watch.restype=ctypes.c_int

def log(msg): print('[docker-php-inotify] '+str(msg),file=sys.stderr,flush=True)
def emit(app,container,event_type,severity,message,details):
    event={'integration':'docker-php','schema_version':'1.0','collector_version':'1.11.0',
      'timestamp':dt.datetime.now().astimezone().isoformat(),'hostname':os.uname().nodename,
      'application':app,'container':container,'event_source':'fim','event_type':event_type,
      'severity':severity,'message':message,'details':details}
    OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    with OUTPUT.open('a',encoding='utf-8') as f: f.write(json.dumps(event,ensure_ascii=False,separators=(',',':'))+'\n')
    os.chmod(OUTPUT,0o640)
    try: os.chown(OUTPUT,0,grp.getgrnam('wazuh').gr_gid)
    except KeyError: pass

def db_open():
    DB.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(DB,timeout=30)
    db.execute('PRAGMA journal_mode=WAL'); db.execute('PRAGMA synchronous=FULL')
    db.execute('CREATE TABLE IF NOT EXISTS fingerprints (app TEXT NOT NULL,path TEXT NOT NULL,digest TEXT NOT NULL,scope TEXT NOT NULL,container TEXT NOT NULL,PRIMARY KEY(app,path))')
    db.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL)')
    db.commit(); os.chmod(DB,0o600)
    return db

def allowed(path,scope):
    if path.is_symlink() or not path.is_file(): return False
    parts={x.lower() for x in path.parts}
    if scope=='source':
        if parts & EXCLUDED: return False
        return path.suffix.lower() in SOURCE_SUFFIXES or path.name.lower().endswith('.env.example')
    return not bool(parts & WRITABLE_EXCLUDED)

def digest(path):
    try:
        st=path.stat()
        if st.st_size>MAX_FILE_SIZE or not path.is_file(): return None
        h=hashlib.sha256()
        with path.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
        return h.hexdigest()
    except OSError: return None

def load_registry():
    apps={}
    if not REGISTRY.is_dir(): return apps
    for rf in sorted(REGISTRY.glob('*.json')):
        try:
            c=json.loads(rf.read_text(encoding='utf-8'))
            app,container,source=c.get('application'),c.get('container'),c.get('source')
            if not all(isinstance(x,str) and x and '\x00' not in x for x in (app,container,source)): continue
            src=Path(source).resolve(strict=True)
            if not src.is_dir() or not src.is_relative_to(APPS_ROOT): continue
            roots=[(src,'source')]
            raw=c.get('writable',[])
            if isinstance(raw,str): raw=[raw]
            if not isinstance(raw,list): raw=[]
            for item in raw:
                if not isinstance(item,str) or not item or '\x00' in item: continue
                try:
                    w=Path(item).resolve(strict=True)
                    if w.is_dir() and w.is_relative_to(src.parent) and w.is_relative_to(APPS_ROOT): roots.append((w,'writable'))
                except OSError: pass
            # Deduplicate nested/equal roots; source remains distinct from writable.
            unique=[]; seen=set()
            for root,scope in roots:
                k=(str(root),scope)
                if k not in seen: unique.append((root,scope)); seen.add(k)
            flags=c.get('monitoring')
            if not isinstance(flags,dict): flags={}
            apps[app]={'container':container,'roots':unique,'fim':flags.get('fim',True) is True}
        except Exception as e: log(f'registry {rf} skipped: {e}')
    return apps

def walk_files(root,scope):
    count=0
    for current,dirs,files in os.walk(root,followlinks=False):
        dirs[:]=[d for d in dirs if d.lower() not in (EXCLUDED if scope=='source' else WRITABLE_EXCLUDED) and not (Path(current)/d).is_symlink()]
        for name in files:
            p=Path(current)/name
            if allowed(p,scope):
                yield p
                count+=1
                if count>=MAX_FILES_PER_APP: return

def in_scope(path,apps):
    try: resolved=path.resolve(strict=False)
    except OSError: return None
    for app,cfg in apps.items():
        if not cfg['fim']: continue
        for root,scope in cfg['roots']:
            try:
                if resolved.is_relative_to(root) and allowed(resolved,scope): return app,cfg['container'],scope
            except (OSError,ValueError): pass
    return None

def add_watch(fd,watches,path):
    try:
        if not path.is_dir() or path.is_symlink(): return
        wd=libc.inotify_add_watch(fd,os.fsencode(path),MASK)
        if wd<0:
            err=ctypes.get_errno()
            if err not in (2,20): log(f'cannot watch {path}: errno={err} (check fs.inotify.max_user_watches)')
            return
        watches[wd]=str(path)
    except OSError as e: log(f'watch error {path}: {e}')

def add_tree(fd,watches,root):
    if not root.is_dir(): return
    add_watch(fd,watches,root)
    for current,dirs,_files in os.walk(root,followlinks=False):
        dirs[:]=[d for d in dirs if d.lower() not in EXCLUDED|WRITABLE_EXCLUDED and not (Path(current)/d).is_symlink()]
        for d in dirs: add_watch(fd,watches,Path(current)/d)

def seed_legacy(db,apps):
    # One-time migration: preserve the previous collector's SHA256 baseline.
    if db.execute("SELECT value FROM metadata WHERE key='seeded'").fetchone(): return
    try: state=json.loads(Path('/var/lib/defenseops/docker-php/state.json').read_text())
    except Exception: state={}
    legacy=state.get('files',{}) if isinstance(state,dict) else {}
    for app,cfg in apps.items():
        old=legacy.get(app,{})
        if not isinstance(old,dict): old={}
        for raw,d in old.items():
            path=Path(raw)
            scope=in_scope(path,apps)
            if scope and scope[0]==app and isinstance(d,str):
                db.execute('INSERT OR IGNORE INTO fingerprints VALUES(?,?,?,?,?)',(app,str(path),d,scope[2],cfg['container']))
    db.execute("INSERT OR REPLACE INTO metadata VALUES('seeded','yes')"); db.commit()

def baseline_new_paths(db,apps,known_roots):
    # Baseline only newly registered roots; no alert storm for pre-existing data.
    roots={(app,str(root),scope) for app,cfg in apps.items() if cfg['fim'] for root,scope in cfg['roots']}
    for app,root,scope in roots-known_roots:
        cfg=apps[app]
        for path in walk_files(Path(root),scope):
            d=digest(path)
            if d: db.execute('INSERT OR IGNORE INTO fingerprints VALUES(?,?,?,?,?)',(app,str(path),d,scope,cfg['container']))
    db.commit(); return roots

def handle_file(db,apps,path):
    match=in_scope(path,apps)
    if match:
        app,container,scope=match; new=digest(path)
        if new is None: return
        row=db.execute('SELECT digest FROM fingerprints WHERE app=? AND path=?',(app,str(path))).fetchone()
        if row is None:
            db.execute('INSERT OR REPLACE INTO fingerprints VALUES(?,?,?,?,?)',(app,str(path),new,scope,container)); db.commit()
            emit(app,container,'file_added','warning','New application file detected',{'path':str(path),'scope':scope,'sha256':new})
        elif row[0]!=new:
            db.execute('UPDATE fingerprints SET digest=?,scope=?,container=? WHERE app=? AND path=?',(new,scope,container,app,str(path))); db.commit()
            emit(app,container,'file_modified','high','Application file modified',{'path':str(path),'scope':scope,'old_sha256':row[0],'new_sha256':new})
        return
    # A delete/move-out can no longer resolve inside current roots. Match stored paths.
    rows=db.execute('SELECT app,digest,scope,container FROM fingerprints WHERE path=?',(str(path),)).fetchall()
    for app,old,scope,container in rows:
        db.execute('DELETE FROM fingerprints WHERE app=? AND path=?',(app,str(path))); db.commit()
        emit(app,container,'file_deleted','warning','Application file deleted',{'path':str(path),'scope':scope,'old_sha256':old})

def main():
    fd=libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
    if fd<0: raise OSError(ctypes.get_errno(),'inotify_init1 failed')
    db=db_open(); apps={}; watches={}; known_roots=set(); last_sync=0
    try:
        while True:
            now=time.monotonic()
            if now-last_sync>=60:
                new_apps=load_registry()
                seed_legacy(db,new_apps)
                known_roots=baseline_new_paths(db,new_apps,known_roots)
                apps=new_apps; watches.clear()
                for cfg in apps.values():
                    if cfg['fim']:
                        for root,_scope in cfg['roots']: add_tree(fd,watches,root)
                last_sync=now
                log(f'registry reconciled: {len(apps)} applications, {len(watches)} directory watches')
            ready,_,_=select.select([fd],[],[],1.0)
            if not ready: continue
            try: data=os.read(fd,1024*1024)
            except BlockingIOError: continue
            offset=0
            while offset+16<=len(data):
                wd,mask,cookie,nlen=struct.unpack_from('iIII',data,offset); offset+=16
                name=data[offset:offset+nlen].split(b'\0',1)[0].decode(errors='surrogateescape'); offset+=nlen
                if mask & IN_Q_OVERFLOW:
                    log('inotify queue overflow; rebuilding watches from registry')
                    last_sync=0; break
                base=watches.get(wd)
                if not base: continue
                path=Path(base)/(name if name else '')
                if mask & IN_ISDIR:
                    if mask & (IN_CREATE|IN_MOVED_TO): add_tree(fd,watches,path)
                    continue
                if mask & (IN_CLOSE_WRITE|IN_ATTRIB|IN_MOVED_TO|IN_DELETE|IN_MOVED_FROM):
                    handle_file(db,apps,path)
    finally:
        os.close(fd); db.close()

if __name__=='__main__': main()
PYINOTIFY
  chown root:root "${fim_collector}.tmp.$$"
  chmod 0750 "${fim_collector}.tmp.$$"
  mv -f "${fim_collector}.tmp.$$" "$fim_collector"

  cat > /etc/systemd/system/defenseops-docker-php-inotify.service <<'EOF'
[Unit]
Description=DefenseOps Docker-PHP registry-scoped inotify FIM collector
After=local-fs.target wazuh-agent.service
Wants=wazuh-agent.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/python3 /usr/local/libexec/defenseops-docker-php-inotify.py
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=/var/lib/defenseops/docker-php /var/log/defenseops

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/defenseops-docker-php-collector.service <<'EOF'
[Unit]
Description=DefenseOps Docker-PHP registry-scoped runtime and Docker Events collector
After=docker.service wazuh-agent.service
Wants=docker.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/python3 -u /usr/local/libexec/defenseops-docker-php-collector.py
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=/var/lib/defenseops/docker-php /var/log/defenseops

[Install]
WantedBy=multi-user.target
EOF

  # The persistent collector now owns both Docker Events and five-minute
  # snapshots. Disable the former timer to prevent duplicate snapshot runs.
  systemctl disable --now defenseops-docker-php-collector.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/defenseops-docker-php-collector.timer

  systemctl daemon-reload
  systemctl enable --now defenseops-docker-php-collector.service
  systemctl enable --now defenseops-docker-php-inotify.service
  systemctl is-active --quiet defenseops-docker-php-inotify.service || die "Docker-PHP inotify FIM daemon failed to start."
  systemctl is-active --quiet defenseops-docker-php-collector.service || die "Docker-PHP runtime/Docker Events collector failed to start."
  log "Docker-PHP runtime collector v1.14.0 installed (Docker Events + five-minute snapshots + health/security/PHP-FPM/resource)."
  log "Docker-PHP FIM is handled only by the dedicated registry-scoped inotify daemon."
  log "Wazuh Agent only ingests the JSONL event file; it does not watch application directories."
  log "Runtime monitoring: PHP-FPM process/socket/workers and Docker CPU/memory/OOM/Block I/O/Network I/O."
}

stage_modsecurity_collector(){
  (( MODSEC_COLLECTOR_ENABLED == 1 )) || return 0

  local lib_dir="/usr/local/libexec"
  local config_dir="/etc/defenseops"
  local state_dir="/var/lib/defenseops"
  local log_dir="/var/log/defenseops"
  local parser="${lib_dir}/defenseops-modsecurity-collector.py"
  local parser_tmp="${lib_dir}/.defenseops-modsecurity-collector.py.tmp.$$"
  local config="${config_dir}/modsecurity-collector.json"

  install -d -o root -g root -m 0755 "$lib_dir" "$config_dir"
  install -d -o root -g root -m 0750 "$state_dir"
  if getent group wazuh >/dev/null 2>&1; then
    install -d -o root -g wazuh -m 0750 "$log_dir"
  else
    install -d -o root -g root -m 0750 "$log_dir"
  fi

  cat > "$parser_tmp" <<'PYCOLLECTOR'
#!/usr/bin/env python3
"""Normalize ModSecurity Concurrent/Serial audit transactions into DefenseOps JSONL."""
from __future__ import annotations

import argparse
import fcntl
import datetime as dt
import gzip
import json
import os
import re
import shutil
import socket
import sqlite3
import sys
import time
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MARKER_RE = re.compile(r'^---[A-Za-z0-9]+---([A-Z])--\s*$', re.M)
ATTR_RE = re.compile(r'\[(\w+) "((?:\\.|[^"\\])*)"\]')
REQUEST_RE = re.compile(r'^([A-Z]+)\s+(\S+)\s+HTTP/\d(?:\.\d)?$')
SENSITIVE_RE = re.compile(
    r'(?i)(password|passwd|token|secret|authorization|session(?:id)?|api[_-]?key|set-cookie|cookie)([=: ]+)([^&\s,;]+)'
)
COOKIE_VALUE_RE = re.compile(r'(?i)(cookie(?:s)?[^=]*=)[^;\s]+')
SENSITIVE_QUERY_KEYS = re.compile(
    r'(?i)(password|passwd|token|secret|authorization|session(?:id)?|api[_-]?key)'
)


def unquote(value: str) -> str:
    return value.replace(r'\"', '"').replace(r'\\', '\\')


def parse_sections(raw: str) -> dict[str, str]:
    parts = MARKER_RE.split(raw)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1, 2)}


def attrs(line: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for key, value in ATTR_RE.findall(line):
        result.setdefault(key, []).append(unquote(value))
    return result


def first(values: dict[str, list[str]], key: str, default=None):
    items = values.get(key) or []
    return items[0] if items else default


def sanitize(value: str | None) -> str | None:
    if value is None:
        return None
    value = SENSITIVE_RE.sub(
        lambda m: f'{m.group(1)}{m.group(2)}[REDACTED]', value
    )
    value = COOKIE_VALUE_RE.sub(r'\1[REDACTED]', value)
    return value[:2048]


def sanitize_uri(uri: str | None) -> str | None:
    if not uri:
        return uri
    try:
        parts = urlsplit(uri)
        query = urlencode([
            (key, '[REDACTED]' if SENSITIVE_QUERY_KEYS.search(key) else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ])
        return urlunsplit(('', '', parts.path, query, parts.fragment))[:4096]
    except Exception:
        return sanitize(uri)


def source_for(rule_file: str, tags: list[str]) -> str:
    normalized = rule_file.lower()
    lower_tags = {tag.lower() for tag in tags}
    if '/opt/brebes-waf/rules/' in normalized or 'brebes-waf' in lower_tags:
        return 'Brebes-WAF'
    if (
        '/modsecurity-crs/' in normalized
        or 'owasp_crs' in lower_tags
        or 'owasp-crs' in lower_tags
    ):
        return 'OWASP_CRS'
    return 'unknown'


class IncompleteAuditError(Exception):
    """Raised when a Concurrent audit file has not reached its terminal Z section."""


def parse_audit(path: Path, hostname: str) -> Iterator[dict]:
    try:
        raw = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        raise
    if not re.search(r'(?m)^---[A-Za-z0-9]+---Z--\s*$', raw):
        if re.search(r'(?m)^---[A-Za-z0-9]+---A--\s*$', raw):
            raise IncompleteAuditError(f'audit transaction is not complete yet: {path}')
        return

    sections = parse_sections(raw)
    a_lines = (sections.get('A') or '').strip().splitlines()
    if not a_lines:
        return []
    match = re.match(
        r'^\[(.+?)\]\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)',
        a_lines[0].strip()
    )
    if not match:
        return []

    date_text, txid, client_ip, _client_port, server_ip, server_port = match.groups()
    try:
        timestamp = dt.datetime.strptime(
            date_text, '%d/%b/%Y:%H:%M:%S %z'
        ).isoformat()
    except ValueError:
        timestamp = date_text

    b_lines = (sections.get('B') or '').splitlines()
    request_line = next(
        (line.strip() for line in b_lines if REQUEST_RE.match(line.strip())), ''
    )
    request_match = REQUEST_RE.match(request_line)
    method, uri = request_match.groups() if request_match else (None, None)

    headers: dict[str, str] = {}
    for line in b_lines:
        if ':' not in line or line.startswith((' ', '\t')):
            continue
        key, value = line.split(':', 1)
        if key.lower() in {'host', 'user-agent', 'referer'}:
            headers[key.lower()] = value.strip()

    status_match = re.search(
        r'(?m)^HTTP/\S+\s+(\d{3})', sections.get('F') or ''
    )
    status = int(status_match.group(1)) if status_match else None
    host = headers.get('host')
    scheme = (
        'https' if server_port == '443'
        else 'http' if server_port == '80'
        else None
    )

    h_lines = [
        line.strip()
        for line in (sections.get('H') or '').splitlines()
        if line.strip().startswith('ModSecurity:')
    ]
    for line in h_lines:
        meta = attrs(line)
        rule_id = first(meta, 'id')
        if not rule_id:
            continue

        denied = bool(re.match(r'^ModSecurity:\s*Access denied\b', line, re.I))
        warning = bool(re.match(r'^ModSecurity:\s*Warning\b', line, re.I))
        if denied:
            event_type, action, disruptive = 'waf_block', 'Access denied', True
        elif warning:
            event_type, action, disruptive = 'waf_detection', 'Warning', False
        else:
            event_type, action, disruptive = 'waf_detection', 'Detection', False

        tags = meta.get('tag', [])
        rule_file = first(meta, 'file', '')
        phase_match = re.search(r'\(phase\s+(\d+)\)', line, re.I)
        phase = int(phase_match.group(1)) if phase_match else None
        severity = first(meta, 'severity')
        try:
            severity = int(severity) if severity is not None else None
        except ValueError:
            pass

        waf = {
            'engine': 'ModSecurity',
            'rule_id': rule_id,
            'rule_message': sanitize(first(meta, 'msg', '')),
            'rule_source': source_for(rule_file, tags),
            'rule_file': rule_file or None,
            'action': action,
            'disruptive_action': disruptive,
            'severity': severity,
            'phase': phase,
            'tags': tags,
        }
        if first(meta, 'ver'):
            waf['rule_version'] = first(meta, 'ver')

        event = {
            'integration': 'brebes-waf',
            'event_type': event_type,
            'timestamp': timestamp,
            'hostname': hostname,
            'transaction_id': first(meta, 'unique_id', txid),
            'srcip': client_ip,
            'client': {'ip': client_ip},
            'request': {
                'method': method,
                'scheme': scheme,
                'domain': host,
                'uri': sanitize_uri(first(meta, 'uri', uri)),
                'http_status': status,
            },
            'waf': waf,
        }
        if headers.get('user-agent'):
            event['client']['user_agent'] = sanitize(headers['user-agent'])
        if headers.get('referer'):
            event['client']['referer'] = sanitize(headers['referer'])
        if server_ip:
            event['waf']['server_ip'] = server_ip

        matched_var = re.search(r"against variable [`']([^`']+)[`']", line, re.I)
        matched_data = first(meta, 'data')
        if matched_var or matched_data:
            context = {}
            if matched_var:
                context['matched_variable'] = matched_var.group(1)
            if matched_data:
                if matched_var and ('REQUEST_COOKIES' in matched_var.group(1).upper() or matched_var.group(1).upper().endswith(':COOKIE')):
                    context['matched_data'] = '[REDACTED_COOKIE_MATCH]'
                else:
                    context['matched_data'] = sanitize(matched_data)
            event['attack_context'] = context
        yield event


def load_config(path: Path) -> dict:
    try:
        config = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f'[ERROR] Cannot read collector config {path}: {exc}')
    roots = config.get('roots')
    if not isinstance(roots, list) or not roots:
        raise SystemExit('[ERROR] Collector config has no audit roots.')
    return config


def ensure_state_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        'CREATE TABLE IF NOT EXISTS processed '
        '(txid TEXT NOT NULL, rule_id TEXT NOT NULL, '
        'PRIMARY KEY(txid, rule_id))'
    )
    columns = {row[1] for row in conn.execute('PRAGMA table_info(processed)')}
    if 'processed_at' not in columns:
        # Existing v1.7.0 rows are retained for a full 180 days from migration.
        conn.execute('ALTER TABLE processed ADD COLUMN processed_at REAL')
        conn.execute(
            'UPDATE processed SET processed_at = ? WHERE processed_at IS NULL',
            (time.time(),)
        )
    conn.execute(
        'CREATE INDEX IF NOT EXISTS idx_processed_at ON processed(processed_at)'
    )
    conn.execute(
        '''CREATE TABLE IF NOT EXISTS file_checkpoint (
            path TEXT PRIMARY KEY,
            signature TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            event_cursor INTEGER NOT NULL DEFAULT 0,
            attempts INTEGER NOT NULL DEFAULT 0,
            retry_at REAL NOT NULL DEFAULT 0,
            last_error TEXT,
            updated_at REAL NOT NULL
        )'''
    )
    conn.execute(
        'CREATE INDEX IF NOT EXISTS idx_file_checkpoint_status '
        'ON file_checkpoint(status, retry_at)'
    )
    conn.commit()


def prune_state(conn: sqlite3.Connection, retention_days: int) -> int:
    cutoff = time.time() - retention_days * 86400
    cur = conn.execute(
        'DELETE FROM processed WHERE processed_at IS NOT NULL AND processed_at < ?',
        (cutoff,)
    )
    conn.commit()
    return cur.rowcount


def prune_file_checkpoints(conn: sqlite3.Connection, retention_days: int) -> int:
    cutoff = time.time() - retention_days * 86400
    cur = conn.execute('DELETE FROM file_checkpoint WHERE updated_at < ?', (cutoff,))
    conn.commit()
    return cur.rowcount


def rotate_output(output: Path) -> Path | None:
    if not output.exists() or output.stat().st_size == 0:
        return None
    st = output.stat()
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    sequence = 0
    while True:
        suffix = f'.{stamp}.{sequence:03d}.gz'
        archive = output.with_name(output.name + suffix)
        if not archive.exists():
            break
        sequence += 1
    staged = output.with_name('.' + output.name + '.rotating.' + str(os.getpid()))
    os.replace(output, staged)
    try:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, st.st_mode & 0o777)
        try:
            os.fchown(fd, st.st_uid, st.st_gid)
            os.fchmod(fd, st.st_mode & 0o777)
        finally:
            os.close(fd)
    except Exception:
        if output.exists() and output.stat().st_size == 0:
            output.unlink()
        os.replace(staged, output)
        raise
    try:
        with staged.open('rb') as source, gzip.open(archive, 'wb', compresslevel=6) as target:
            shutil.copyfileobj(source, target)
        os.chown(archive, st.st_uid, st.st_gid)
        os.chmod(archive, st.st_mode & 0o777)
        staged.unlink()
    except Exception:
        # Keep the uncompressed staged file if compression fails; never discard data.
        print(f'[WARN] Rotation compression failed; retained {staged}: {sys.exc_info()[1]}', file=sys.stderr)
        return staged
    return archive


def prune_archives(output: Path, retention_days: int) -> int:
    cutoff = time.time() - retention_days * 86400
    removed = 0
    pattern = output.name + '.*.gz'
    for archive in output.parent.glob(pattern):
        try:
            if archive.is_file() and archive.stat().st_mtime < cutoff:
                archive.unlink()
                removed += 1
        except OSError as exc:
            print(f'[WARN] Cannot remove expired archive {archive}: {exc}', file=sys.stderr)
    return removed


def append_events(output: Path, lines: list[str], max_bytes: int) -> int:
    written = 0
    current_size = output.stat().st_size if output.exists() else 0
    out = output.open('a', encoding='utf-8')
    try:
        for line in lines:
            encoded_size = len(line.encode('utf-8'))
            if max_bytes > 0 and current_size > 0 and current_size + encoded_size > max_bytes:
                out.flush()
                os.fsync(out.fileno())
                out.close()
                rotated = rotate_output(output)
                if rotated:
                    print(f'[INFO] Rotated ModSecurity output to {rotated}', file=sys.stderr)
                current_size = 0
                out = output.open('a', encoding='utf-8')
            out.write(line)
            current_size += encoded_size
            written += 1
        out.flush()
        os.fsync(out.fileno())
    finally:
        if not out.closed:
            out.close()
    return written


def file_signature(path: Path, st: os.stat_result) -> str:
    return f'{st.st_dev}:{st.st_ino}:{st.st_size}:{st.st_mtime_ns}'


def checkpoint_file(
    conn: sqlite3.Connection, path: str, signature: str, status: str,
    event_cursor: int = 0, attempts: int = 0, retry_at: float = 0,
    last_error: str | None = None
) -> None:
    conn.execute(
        '''INSERT INTO file_checkpoint
           (path, signature, status, event_cursor, attempts, retry_at, last_error, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(path) DO UPDATE SET
             signature=excluded.signature, status=excluded.status,
             event_cursor=excluded.event_cursor, attempts=excluded.attempts,
             retry_at=excluded.retry_at, last_error=excluded.last_error,
             updated_at=excluded.updated_at''',
        (path, signature, status, event_cursor, attempts, retry_at, last_error, time.time())
    )


def append_batch(
    conn: sqlite3.Connection, output: Path, batch: list[tuple[str, str, str]],
    max_output_bytes: int
) -> int:
    if not batch:
        return 0
    # Output is flushed before deduplication/checkpoint rows are committed.
    append_events(output, [item[2] for item in batch], max_output_bytes)
    now = time.time()
    conn.executemany(
        'INSERT OR IGNORE INTO processed(txid, rule_id, processed_at) VALUES (?, ?, ?)',
        [(item[0], item[1], now) for item in batch]
    )
    conn.commit()
    return len(batch)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', default='/etc/defenseops/modsecurity-collector.json')
    ap.add_argument('--once', action='store_true', help='run one reconciliation and processing pass (test mode)')
    args = ap.parse_args()
    config = load_config(Path(args.config))

    roots = [Path(item) for item in config['roots']]
    output = Path(config.get('output', '/var/log/defenseops/modsecurity-events.json'))
    state = Path(config.get('state', '/var/lib/defenseops/modsecurity-state.sqlite3'))
    baseline = config.get('baseline_epoch')
    try:
        baseline = float(baseline) if baseline is not None else None
    except (TypeError, ValueError):
        baseline = None

    max_output_bytes = int(config.get('max_output_bytes', 250000000))
    archive_retention_days = int(config.get('archive_retention_days', 90))
    state_retention_days = int(config.get('state_retention_days', 180))
    source_max_age_days = int(config.get('source_max_age_days', 180))
    max_files_per_run = int(config.get('max_files_per_run', 500))
    max_events_per_run = int(config.get('max_events_per_run', 1000))
    max_batch_bytes = int(config.get('max_batch_bytes', 1048576))
    retry_base_seconds = int(config.get('retry_base_seconds', 30))
    retry_max_seconds = int(config.get('retry_max_seconds', 1800))
    reconcile_seconds = int(config.get('reconcile_seconds', 600))
    idle_wait_seconds = float(config.get('idle_wait_seconds', 1.0))
    if min(archive_retention_days, state_retention_days, source_max_age_days,
           max_files_per_run, max_events_per_run, max_batch_bytes,
           retry_base_seconds, retry_max_seconds, reconcile_seconds) < 1:
        raise SystemExit('[ERROR] Collector limits and scheduler intervals must be positive.')
    if max_output_bytes < 1024 * 1024 or retry_max_seconds < retry_base_seconds:
        raise SystemExit('[ERROR] Invalid output or retry limits.')

    output.parent.mkdir(parents=True, exist_ok=True)
    state.parent.mkdir(parents=True, exist_ok=True)
    lock_path = state.with_name(state.name + '.collector.lock')
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o640)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('[ERROR] Another collector daemon owns the lock; exiting.', file=sys.stderr)
            return 1

        # Linux inotify via libc: no third-party Python package is required.
        import ctypes
        import select
        import struct
        libc = ctypes.CDLL(None, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_add_watch.restype = ctypes.c_int
        libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
        libc.inotify_rm_watch.restype = ctypes.c_int
        IN_NONBLOCK = os.O_NONBLOCK
        IN_CLOEXEC = getattr(os, 'O_CLOEXEC', 0)
        IN_CLOSE_WRITE = 0x00000008
        IN_MOVED_TO = 0x00000080
        IN_CREATE = 0x00000100
        IN_DELETE_SELF = 0x00000400
        IN_MOVE_SELF = 0x00000800
        IN_Q_OVERFLOW = 0x00004000
        IN_IGNORED = 0x00008000
        WATCH_MASK = IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE_SELF | IN_MOVE_SELF
        EVENT_HEADER = struct.Struct('iIII')
        inotify_fd = libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if inotify_fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))

        hostname = socket.gethostname()
        conn = sqlite3.connect(state, timeout=30)
        conn.execute('PRAGMA busy_timeout=30000')
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=FULL')
        watch_paths: dict[int, str] = {}

        def add_watch(directory: Path) -> None:
            try:
                wd = libc.inotify_add_watch(inotify_fd, os.fsencode(str(directory)), WATCH_MASK)
                if wd >= 0:
                    watch_paths[wd] = str(directory)
                else:
                    err = ctypes.get_errno()
                    print(f'[WARN] Cannot watch {directory}: {os.strerror(err)}', file=sys.stderr)
            except OSError as exc:
                print(f'[WARN] Cannot watch {directory}: {exc}', file=sys.stderr)

        def watch_tree() -> None:
            for root in roots:
                if root.is_file():
                    add_watch(root.parent)
                    continue
                if not root.is_dir():
                    print(f'[WARN] Audit root unavailable: {root}', file=sys.stderr)
                    continue
                for current, dirs, _files in os.walk(root):
                    dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
                    add_watch(Path(current))

        def enqueue_path(path: Path) -> None:
            try:
                if path.name == 'debug.log' or not path.is_file():
                    return
                st = path.stat()
                now = time.time()
                if st.st_size < 20 or st.st_mtime < now - source_max_age_days * 86400:
                    return
                if baseline is not None and st.st_mtime < baseline:
                    return
                resolved = str(path.resolve())
                signature = file_signature(path, st)
                row = conn.execute(
                    'SELECT signature,status FROM file_checkpoint WHERE path=?', (resolved,)
                ).fetchone()
                if row and row[0] == signature:
                    # done/pending/failed are already represented in the durable queue.
                    return
                checkpoint_file(conn, resolved, signature, 'pending', 0, 0, 0, None)
                conn.commit()
            except (OSError, sqlite3.Error) as exc:
                print(f'[WARN] Discovery cannot register {path}: {exc}', file=sys.stderr)

        def reconcile() -> None:
            print('[INFO] Periodic reconciliation started.', file=sys.stderr)
            for root in roots:
                if root.is_file():
                    enqueue_path(root)
                    continue
                if not root.is_dir():
                    continue
                # Streaming traversal: never materialize or sort the full path set.
                for current, dirs, files in os.walk(root):
                    dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
                    add_watch(Path(current))
                    for filename in files:
                        enqueue_path(Path(current) / filename)
            print('[INFO] Periodic reconciliation completed.', file=sys.stderr)

        def recover_interrupted() -> None:
            cur = conn.execute(
                "UPDATE file_checkpoint SET status='pending', retry_at=0, updated_at=? WHERE status='processing'",
                (time.time(),)
            )
            conn.commit()
            if cur.rowcount:
                print(f'[WARN] Recovered {cur.rowcount} interrupted file job(s).', file=sys.stderr)

        def process_queue() -> None:
            now = time.time()
            rows = conn.execute(
                """SELECT path,signature,event_cursor,attempts,status FROM file_checkpoint
                   WHERE status='pending' OR (status='failed' AND retry_at<=?)
                   ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, updated_at ASC
                   LIMIT ?""", (now, max_files_per_run)
            ).fetchall()
            if not rows:
                return
            batch: list[tuple[str, str, str]] = []
            batch_bytes = 0
            files_attempted = events_written = files_completed = 0

            def flush_batch() -> None:
                nonlocal batch, batch_bytes, events_written
                if batch:
                    events_written += append_batch(conn, output, batch, max_output_bytes)
                    batch = []
                    batch_bytes = 0

            for resolved, signature, saved_cursor, saved_attempts, old_status in rows:
                if events_written >= max_events_per_run:
                    break
                claimed = conn.execute(
                    "UPDATE file_checkpoint SET status='processing',updated_at=? WHERE path=? AND signature=? AND status=?",
                    (time.time(), resolved, signature, old_status)
                )
                conn.commit()
                if claimed.rowcount != 1:
                    continue
                files_attempted += 1
                path = Path(resolved)
                cursor = int(saved_cursor or 0)
                attempts = int(saved_attempts or 0)
                try:
                    st = path.stat()
                    current_signature = file_signature(path, st)
                    if current_signature != signature:
                        checkpoint_file(conn, resolved, current_signature, 'pending', 0, 0, 0, None)
                        conn.commit()
                        continue
                    event_index = 0
                    file_complete = True
                    for event in parse_audit(path, hostname):
                        if event_index < cursor:
                            event_index += 1
                            continue
                        txid = str(event.get('transaction_id', ''))
                        rule_id = str(event['waf']['rule_id'])
                        already = conn.execute(
                            'SELECT 1 FROM processed WHERE txid=? AND rule_id=?', (txid, rule_id)
                        ).fetchone()
                        if already:
                            event_index += 1
                            cursor = event_index
                            continue
                        line = json.dumps(event, ensure_ascii=False, separators=(',', ':')) + '\n'
                        encoded_size = len(line.encode('utf-8'))
                        if encoded_size > max_batch_bytes:
                            raise ValueError(f'event size {encoded_size} exceeds max_batch_bytes={max_batch_bytes}')
                        if events_written + len(batch) >= max_events_per_run:
                            file_complete = False
                            break
                        if batch and batch_bytes + encoded_size > max_batch_bytes:
                            flush_batch()
                        batch.append((txid, rule_id, line))
                        batch_bytes += encoded_size
                        event_index += 1
                        cursor = event_index
                        if batch_bytes >= max_batch_bytes or events_written + len(batch) >= max_events_per_run:
                            flush_batch()
                            checkpoint_file(conn, resolved, signature, 'pending', cursor, attempts, 0, None)
                            conn.commit()
                        if events_written >= max_events_per_run:
                            file_complete = False
                            break
                    # Do not mark a file done if it changed while being read.
                    latest_signature = file_signature(path, path.stat())
                    if latest_signature != signature:
                        flush_batch()
                        checkpoint_file(conn, resolved, latest_signature, 'pending', 0, 0, 0, None)
                        conn.commit()
                        continue
                    flush_batch()
                    if file_complete:
                        checkpoint_file(conn, resolved, signature, 'done', event_index, 0, 0, None)
                        files_completed += 1
                    else:
                        checkpoint_file(conn, resolved, signature, 'pending', cursor, attempts, 0, None)
                    conn.commit()
                except (OSError, UnicodeError, sqlite3.Error, ValueError, IncompleteAuditError) as exc:
                    flush_batch()
                    attempts += 1
                    delay = min(retry_max_seconds, retry_base_seconds * (2 ** min(attempts - 1, 10)))
                    checkpoint_file(conn, resolved, signature, 'failed', cursor, attempts,
                                    time.time() + delay, str(exc)[:1000])
                    conn.commit()
                    print(f'[WARN] Cannot complete {path}; retry in {delay}s: {exc}', file=sys.stderr)
            output.touch(exist_ok=True)
            if files_attempted:
                print(f'[INFO] Queue cycle: attempted={files_attempted}, completed={files_completed}, events={events_written}', file=sys.stderr)

        ensure_state_schema(conn)
        recover_interrupted()
        watch_tree()
        # Watch is installed before initial reconciliation to close the startup race.
        reconcile()
        next_reconcile = time.monotonic() + reconcile_seconds
        print(f'[INFO] Collector daemon started; reconciliation interval={reconcile_seconds}s.', file=sys.stderr)

        try:
            while True:
                # Drain filesystem notifications without retaining an unbounded in-memory queue.
                try:
                    readable, _, _ = select.select([inotify_fd], [], [], idle_wait_seconds)
                    if readable:
                        data = os.read(inotify_fd, 256 * 1024)
                        offset = 0
                        overflow = False
                        while offset + EVENT_HEADER.size <= len(data):
                            wd, mask, cookie, name_len = EVENT_HEADER.unpack_from(data, offset)
                            offset += EVENT_HEADER.size
                            raw_name = data[offset:offset + name_len].split(b'\0', 1)[0]
                            offset += name_len
                            if mask & IN_Q_OVERFLOW:
                                overflow = True
                                continue
                            parent = Path(watch_paths.get(wd, ''))
                            target = parent / os.fsdecode(raw_name) if raw_name else parent
                            if mask & (IN_CREATE | IN_MOVED_TO) and target.is_dir():
                                # Watch first, then reconcile the new subtree to close the
                                # mkdir->watch installation race for files created immediately.
                                for current, dirs, files in os.walk(target):
                                    dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
                                    add_watch(Path(current))
                                    for filename in files:
                                        enqueue_path(Path(current) / filename)
                            if mask & (IN_CLOSE_WRITE | IN_MOVED_TO) and target.is_file():
                                enqueue_path(target)
                            if mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED):
                                watch_paths.pop(wd, None)
                        if overflow:
                            print('[WARN] Inotify queue overflow; forcing reconciliation.', file=sys.stderr)
                            watch_tree()
                            reconcile()
                            next_reconcile = time.monotonic() + reconcile_seconds
                except BlockingIOError:
                    pass
                except OSError as exc:
                    print(f'[WARN] Inotify read failed; rebuilding watches and reconciling: {exc}', file=sys.stderr)
                    watch_tree()
                    reconcile()
                    next_reconcile = time.monotonic() + reconcile_seconds

                if time.monotonic() >= next_reconcile:
                    watch_tree()
                    reconcile()
                    next_reconcile = time.monotonic() + reconcile_seconds
                process_queue()
                if args.once:
                    break
        except KeyboardInterrupt:
            print('[INFO] Collector daemon stopping.', file=sys.stderr)
        finally:
            os.close(inotify_fd)
            conn.close()
    finally:
        os.close(lock_fd)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
PYCOLLECTOR
  chown root:root "$parser_tmp"
  chmod 0750 "$parser_tmp"
  python3 - "$parser_tmp" <<'PYCHECK'
import sys
from pathlib import Path
compile(Path(sys.argv[1]).read_text(encoding="utf-8"), sys.argv[1], "exec")
print("[INFO] ModSecurity collector Python syntax: OK")
PYCHECK
  mv -f "$parser_tmp" "$parser"

  # Preserve the original baseline and SQLite state on installer re-runs.
  python3 - "$config" "${MODSEC_PARSER_ROOTS[@]}" <<'PYCONFIG'
import json
import sys
import time
from pathlib import Path

config_path = Path(sys.argv[1])
roots = sorted(set(sys.argv[2:]))
baseline = time.time()
if config_path.is_file():
    try:
        old = json.loads(config_path.read_text(encoding="utf-8"))
        baseline = float(old.get("baseline_epoch", baseline))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
data = {}
if config_path.is_file():
    try:
        previous = json.loads(config_path.read_text(encoding="utf-8"))
        if isinstance(previous, dict):
            data.update(previous)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
# Preserve existing paths, baseline and operator-tuned limits where present.
data.update({
    "roots": roots,
    "output": data.get("output", "/var/log/defenseops/modsecurity-events.json"),
    "state": data.get("state", "/var/lib/defenseops/modsecurity-state.sqlite3"),
    "baseline_epoch": baseline,
    "max_output_bytes": int(data.get("max_output_bytes", 250000000)),
    "archive_retention_days": int(data.get("archive_retention_days", 90)),
    "state_retention_days": int(data.get("state_retention_days", 180)),
    "source_max_age_days": int(data.get("source_max_age_days", 180)),
    "max_files_per_run": int(data.get("max_files_per_run", 500)),
    "max_events_per_run": int(data.get("max_events_per_run", 1000)),
    "max_batch_bytes": int(data.get("max_batch_bytes", 1048576)),
    "retry_base_seconds": int(data.get("retry_base_seconds", 30)),
    "retry_max_seconds": int(data.get("retry_max_seconds", 1800)),
    "reconcile_seconds": int(data.get("reconcile_seconds", 600)),
    "idle_wait_seconds": float(data.get("idle_wait_seconds", 1.0))
})
tmp = config_path.with_suffix(".json.tmp")
tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
tmp.replace(config_path)
PYCONFIG
  chown root:root "$config"
  chmod 0640 "$config"

  cat > /etc/systemd/system/.defenseops-modsecurity-collector.service.tmp.$$ <<'UNIT'
[Unit]
Description=DefenseOps ModSecurity Audit Collector
After=local-fs.target

[Service]
Type=simple
User=root
Group=root
UMask=0027
ExecStart=/usr/bin/python3 -u /usr/local/libexec/defenseops-modsecurity-collector.py --config /etc/defenseops/modsecurity-collector.json
Restart=always
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT
  chown root:root /etc/systemd/system/.defenseops-modsecurity-collector.service.tmp.$$
  chmod 0644 /etc/systemd/system/.defenseops-modsecurity-collector.service.tmp.$$
  mv -f /etc/systemd/system/.defenseops-modsecurity-collector.service.tmp.$$ /etc/systemd/system/defenseops-modsecurity-collector.service

  # Stop the legacy periodic unit before removing it; collector is now a daemon.
  systemctl disable --now defenseops-modsecurity-collector.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/defenseops-modsecurity-collector.timer


  touch "${log_dir}/modsecurity-events.json"
  if getent group wazuh >/dev/null 2>&1; then
    chown root:wazuh "${log_dir}/modsecurity-events.json"
  else
    chown root:root "${log_dir}/modsecurity-events.json"
  fi
  chmod 0640 "${log_dir}/modsecurity-events.json"
  log "ModSecurity collector staged: ${parser}"
}

ensure_collector_unit_install_config(){
  local unit="/etc/systemd/system/defenseops-modsecurity-collector.service"
  [[ -f "$unit" ]] || die "Collector systemd unit not found: $unit"

  # Repair only the [Install] metadata. Preserve [Unit], [Service], and any
  # other existing directives so an installer update does not rewrite
  # unrelated service behavior.
  python3 - "$unit" <<'PYUNIT'
import os
import stat
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
try:
    original = path.read_text(encoding="utf-8")
except OSError as exc:
    raise SystemExit(f"[ERROR] Cannot read collector unit {path}: {exc}")

lines = original.splitlines()
install_start = None
install_end = len(lines)
for index, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        if stripped == "[Install]" and install_start is None:
            install_start = index
        elif install_start is not None:
            install_end = index
            break

if install_start is None:
    while lines and not lines[-1].strip():
        lines.pop()
    if lines:
        lines.append("")
    lines.extend(["[Install]", "WantedBy=multi-user.target"])
else:
    section = lines[install_start + 1:install_end]
    section = [
        line for line in section
        if not line.strip().startswith("WantedBy=")
    ]
    section.append("WantedBy=multi-user.target")
    lines = lines[:install_start + 1] + section + lines[install_end:]

updated = "\n".join(lines).rstrip() + "\n"
if updated != original:
    old_stat = path.stat()
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(updated)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, old_stat.st_uid, old_stat.st_gid)
        os.chmod(temporary, stat.S_IMODE(old_stat.st_mode))
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    print("[INFO] Repaired collector unit [Install] metadata.")
else:
    print("[INFO] Collector unit [Install] metadata is already correct.")
PYUNIT
}

activate_modsecurity_collector(){
  (( MODSEC_COLLECTOR_ENABLED == 1 )) || return 0
  if getent group wazuh >/dev/null 2>&1; then
    chown root:wazuh /var/log/defenseops /var/log/defenseops/modsecurity-events.json
    chmod 0750 /var/log/defenseops
    chmod 0640 /var/log/defenseops/modsecurity-events.json
  fi
  systemctl disable --now defenseops-modsecurity-collector.timer >/dev/null 2>&1 || true

  ensure_collector_unit_install_config
  systemctl daemon-reload
  systemctl enable defenseops-modsecurity-collector.service
  systemctl is-enabled --quiet defenseops-modsecurity-collector.service ||
    die "DefenseOps ModSecurity collector is not enabled for startup."

  systemctl start defenseops-modsecurity-collector.service
  systemctl is-active --quiet defenseops-modsecurity-collector.service ||
    die "DefenseOps ModSecurity collector daemon failed to start."
  log "DefenseOps ModSecurity collector daemon is active and enabled at boot (inotify + internal scheduler)."
}


# ---------------------------------------------------------------------------
# Read-only pre-flight validation. No package/config/service/file changes are
# permitted before this function completes successfully.
# ---------------------------------------------------------------------------
preflight_check(){
  local failures=0 warnings=0
  pf_pass(){ printf '[PASS] %s\n' "$*"; }
  pf_warn(){ printf '[WARN] %s\n' "$*"; warnings=$((warnings+1)); }
  pf_fail(){ printf '[FAIL] %s\n' "$*" >&2; failures=$((failures+1)); }

  echo
  echo "DefenseOps Agent Installer v${INSTALLER_VERSION}"
  echo "Pre-flight validation: ${ENDPOINT_PROFILE}"
  echo "------------------------------------------------------------"

  [[ $EUID -eq 0 ]] && pf_pass "Root privileges" || pf_fail "Root privileges required"
  [[ -r /etc/os-release ]] && pf_pass "OS identification file" || pf_fail "/etc/os-release unavailable"
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    case "${ID:-}" in
      ubuntu|debian|linuxmint|pop|rhel|rocky|almalinux|centos|ol|fedora|amzn)
        pf_pass "Supported distribution: ${PRETTY_NAME:-$ID}" ;;
      *)
        pf_fail "Unsupported distribution: ${ID:-unknown}" ;;
    esac
  fi
  command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1 &&
    pf_pass "systemd available" || pf_fail "systemd unavailable"
  command -v python3 >/dev/null 2>&1 && pf_pass "Python 3 available" || pf_fail "Python 3 unavailable"
  command -v curl >/dev/null 2>&1 && pf_pass "curl available" || pf_fail "curl unavailable"
  command -v getent >/dev/null 2>&1 && pf_pass "getent available" || pf_fail "getent unavailable"
  command -v timeout >/dev/null 2>&1 && pf_pass "timeout utility available" || pf_fail "timeout utility unavailable"
  command -v df >/dev/null 2>&1 && pf_pass "Disk inspection utility available" || pf_fail "df unavailable"

  if command -v df >/dev/null 2>&1; then
    local free_kb
    free_kb="$(df -Pk /var 2>/dev/null | awk 'NR==2 {print $4}')"
    if [[ "$free_kb" =~ ^[0-9]+$ ]] && (( free_kb >= 102400 )); then
      pf_pass "Free space on /var: ${free_kb} KiB"
    else
      pf_fail "At least 100 MiB free space is required on /var"
    fi
  fi

  [[ -r "$CONFIG_FILE" && -s "$CONFIG_FILE" ]] &&
    pf_pass "Generated ossec.conf is readable" || pf_fail "Generated ossec.conf missing/empty: $CONFIG_FILE"
  if [[ -r "$CONFIG_FILE" ]]; then
    if python3 - "$CONFIG_FILE" <<'PFPY'
import sys, xml.etree.ElementTree as ET
try:
    ET.parse(sys.argv[1])
except Exception as exc:
    print(f"[FAIL] Generated ossec.conf XML invalid: {exc}")
    raise SystemExit(1)
print("[PASS] Generated ossec.conf XML valid")
PFPY
    then :; else failures=$((failures+1)); fi
  fi

  if (( AGENT_PACKAGE_INSTALLED == 1 )); then
    [[ -x /var/ossec/bin/wazuh-agentd ]] &&
      pf_pass "Existing Wazuh Agent binary" || pf_fail "Wazuh Agent package detected but daemon binary missing"
    [[ -s /var/ossec/etc/ossec.conf ]] &&
      pf_pass "Existing Agent configuration present" || pf_fail "Existing Agent ossec.conf missing/empty"
    if [[ -e /var/ossec/etc/client.keys ]]; then
      if (( AGENT_ENROLLED == 1 )); then
        pf_pass "Existing enrollment identity detected (will be preserved)"
      elif [[ ! -s /var/ossec/etc/client.keys ]]; then
        pf_pass "Empty client.keys placeholder (not enrolled)"
      else
        pf_fail "client.keys is non-empty but contains no valid enrollment entry"
      fi
    else
      pf_pass "No existing client.keys (first enrollment path)"
    fi
  else
    pf_pass "Wazuh Agent package not installed; first-install path"
    if [[ -e /var/ossec/etc/client.keys && -s /var/ossec/etc/client.keys ]]; then
      pf_fail "Orphan non-empty client.keys exists without a detected Agent package"
    fi
  fi

  if [[ -n "$MANAGER" ]]; then
    if getent ahosts "$MANAGER" >/dev/null 2>&1; then
      pf_pass "Manager address resolves: $MANAGER"
    else
      pf_fail "Manager address cannot be resolved: $MANAGER"
    fi
    if timeout 4 bash -c ':</dev/tcp/$1/$2' _ "$MANAGER" "$MANAGER_PORT" >/dev/null 2>&1; then
      pf_pass "Manager TCP ${MANAGER_PORT} reachable"
    else
      pf_fail "Manager TCP ${MANAGER_PORT} is not reachable"
    fi
    if (( AGENT_ENROLLED == 0 )); then
      if timeout 4 bash -c ':</dev/tcp/$1/$2' _ "$MANAGER" "$REG_PORT" >/dev/null 2>&1; then
        pf_pass "Enrollment TCP ${REG_PORT} reachable"
      else
        pf_fail "Enrollment TCP ${REG_PORT} is not reachable"
      fi
    else
      pf_pass "Enrollment port check skipped for already-enrolled Agent"
    fi
  fi

  if [[ "$ENDPOINT_PROFILE" == "brebes-waf" ]]; then
    command -v nginx >/dev/null 2>&1 && pf_pass "Nginx command available" || pf_fail "Nginx command unavailable"
    [[ -s "$NGINX_DUMP" && -s "$DISCOVERY_REPORT" ]] &&
      pf_pass "Nginx configuration discovery completed" || pf_fail "Nginx discovery artifacts missing"
    ((${#NGINX_ACCESS_LOGS[@]} > 0)) &&
      pf_pass "Verified JSON access logs: ${#NGINX_ACCESS_LOGS[@]}" || pf_fail "No verified JSON access logs"
  elif [[ "$ENDPOINT_PROFILE" == "docker-php" ]]; then
    command -v docker >/dev/null 2>&1 && pf_pass "Docker CLI available" || pf_fail "Docker CLI required for Docker-PHP profile"
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
      pf_pass "Docker Engine accessible"
    else
      pf_fail "Docker Engine unavailable or current user cannot access it"
    fi
    local registry="/var/lib/docker-php/monitoring/applications"
    if [[ -d "$registry" && -r "$registry" && -x "$registry" ]]; then
      pf_pass "Application Registry directory available"
    else
      pf_fail "Application Registry directory missing or unreadable: $registry"
    fi
    if [[ -d "$registry" ]]; then
      if python3 - "$registry" <<'PFREG'
import json, os, sys
from pathlib import Path

registry=Path(sys.argv[1])
files=sorted(registry.glob("*.json"))
errors=[]
warnings=[]
seen_apps={}
seen_containers={}
apps_root=Path("/var/apps").resolve()

if not files:
    warnings.append("Registry contains no *.json application entries; collector will wait for registrations")

for rf in files:
    try:
        cfg=json.loads(rf.read_text(encoding="utf-8"))
        if not isinstance(cfg,dict):
            raise ValueError("root must be a JSON object")
        app=cfg.get("application")
        container=cfg.get("container")
        source=cfg.get("source")
        if not isinstance(app,str) or not app.strip() or not isinstance(container,str) or not container.strip():
            raise ValueError("application and container must be non-empty strings")
        if not isinstance(source,str) or not source.startswith("/"):
            raise ValueError("source must be an absolute path")
        if app in seen_apps:
            raise ValueError(f"duplicate application name also used by {seen_apps[app]}")
        if container in seen_containers:
            raise ValueError(f"container name already registered by {seen_containers[container]}")
        seen_apps[app]=rf.name; seen_containers[container]=rf.name

        src=Path(source).resolve(strict=True)
        if not src.is_dir() or not src.is_relative_to(apps_root):
            raise ValueError(f"source path unavailable or outside /var/apps: {source}")

        if "writable" not in cfg:
            raise ValueError("required field writable is missing")
        raw=cfg["writable"]
        if isinstance(raw,str):
            writable=[raw]
        elif isinstance(raw,list):
            writable=raw
        else:
            raise ValueError("writable must be an absolute path string or an array of absolute paths (null is invalid)")
        for item in writable:
            if not isinstance(item,str) or not item.startswith("/") or "\x00" in item:
                raise ValueError(f"invalid writable path entry: {item!r}")
            w=Path(item).resolve(strict=True)
            if not w.is_dir() or not w.is_relative_to(src.parent) or not w.is_relative_to(apps_root):
                raise ValueError(f"writable path unavailable or outside application root: {item}")

        flags=cfg.get("monitoring",{})
        if not isinstance(flags,dict):
            raise ValueError("monitoring must be a JSON object when specified")
        for key in ("fim","docker_health","security","php_fpm"):
            if key in flags and not isinstance(flags[key],bool):
                raise ValueError(f"monitoring.{key} must be boolean")
        if flags.get("malware") is True:
            warnings.append(f"{rf.name}: monitoring.malware=true is unsupported; no malware scan will run")

        compose=cfg.get("compose")
        if compose not in (None,""):
            if not isinstance(compose,str) or not compose.startswith("/"):
                raise ValueError("compose must be an absolute path when specified")
            if not Path(compose).is_file():
                raise ValueError(f"Compose file does not exist: {compose}")

        if not os.access(rf,os.R_OK):
            raise ValueError("registry file is not readable")
        print(f"[PASS] Registry {rf.name}: schema, source, writable, monitoring flags")
        # A registered container may legitimately be stopped at install time.
        import subprocess
        p=subprocess.run(["docker","inspect",container],stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        if p.returncode:
            warnings.append(f"{app}: registered container '{container}' is not currently inspectable")
    except Exception as exc:
        errors.append(f"{rf.name}: {exc}")

for item in warnings:
    print(f"[WARN] {item}")
for item in errors:
    print(f"[FAIL] {item}")
print(f"[INFO] Registry entries checked: {len(files)}")
raise SystemExit(1 if errors else 0)
PFREG
      then
        pf_pass "All registry entries passed validation"
      else
        pf_fail "One or more registry entries are invalid"
      fi
    fi
    if python3 - <<'PFMODULE'
import ctypes, ctypes.util, json, sqlite3
assert ctypes.util.find_library("c"), "libc not found"
sqlite3.connect(":memory:").close()
json.loads('{"preflight":true}')
print("[PASS] Python ctypes, SQLite and JSON modules available")
PFMODULE
    then :; else pf_fail "Required Python modules/libc are unavailable"; fi
  fi

  echo "------------------------------------------------------------"
  if (( failures > 0 )); then
    printf '[FAIL] Pre-flight result: %s failure(s), %s warning(s)\n' "$failures" "$warnings" >&2
    die "Installation cancelled. No package, Agent configuration, collector, inotify, or service changes have been made."
  fi
  printf '[PASS] Pre-flight result: READY (%s warning(s))\n' "$warnings"
  echo
  read -r -p "All required checks passed. Continue installation? [y/N] " proceed
  case "${proceed,,}" in
    y|yes) log "Pre-flight accepted; installation may proceed." ;;
    *) die "Installation cancelled by operator. No installation changes were made." ;;
  esac
}

# Docker-PHP application scope comes exclusively from the prepared Application Registry.
# No Compose discovery and no broad /var/apps paths are injected into native Syscheck.
DOCKER_PHP_APP_DIRS_FILE=""

if [[ "$ENDPOINT_PROFILE" == "brebes-waf" ]]; then
  log "Inspecting every active Nginx virtual host and validating JSON access logs..."
  discover_brebes_waf
  log "Brebes-WAF JSON validation passed."
else
  log "Docker-PHP endpoint profile selected."
  log "Application scope will be read exclusively from the Docker-PHP Application Registry."
fi

# All read-only checks must pass before staging collectors, changing time settings,
# installing packages, enrolling, or modifying the active Agent configuration.
preflight_check

# Stage the parser only after local ModSecurity discovery and pre-flight validation.
# Collector daemon activation is deferred until the Wazuh configuration has been validated.
if [[ "$ENDPOINT_PROFILE" == "brebes-waf" ]] && (( MODSEC_COLLECTOR_ENABLED == 1 )); then
  stage_modsecurity_collector
fi

# Time settings are opt-in. Do not overwrite chrony/timesyncd configuration.
if (( AGENT_PACKAGE_INSTALLED == 0 )) && command -v timedatectl >/dev/null 2>&1; then
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
elif (( AGENT_PACKAGE_INSTALLED == 0 )); then
  warn "timedatectl unavailable; timezone and NTP settings were not changed."
fi

REG_PASSWORD=""
TEMP_AUTHD_PASS=0
RESET_APPLIED=0
RESET_COMMITTED=0
RESET_CONF_BACKUP=""
RESET_KEYS_BACKUP=""
RESET_SERVICE_WAS_ACTIVE=0
cleanup(){
  local cleanup_rc=$?
  if (( TEMP_AUTHD_PASS == 1 )); then
    rm -f /var/ossec/etc/authd.pass
    TEMP_AUTHD_PASS=0
  fi
  if (( RESET_APPLIED == 1 && RESET_COMMITTED == 0 )); then
    warn "Reset/enrollment did not complete. Restoring the previous Agent configuration and identity."
    if [[ -s "$RESET_CONF_BACKUP" ]]; then
      cp -a -- "$RESET_CONF_BACKUP" /var/ossec/etc/ossec.conf || warn "Could not restore previous ossec.conf."
    fi
    if [[ -n "$RESET_KEYS_BACKUP" && -s "$RESET_KEYS_BACKUP" ]]; then
      cp -a -- "$RESET_KEYS_BACKUP" /var/ossec/etc/client.keys || warn "Could not restore previous client.keys."
    else
      rm -f /var/ossec/etc/client.keys
    fi
    if (( RESET_SERVICE_WAS_ACTIVE == 1 )); then
      systemctl start wazuh-agent || warn "Could not restart Agent after reset rollback."
    fi
  fi
  unset REG_PASSWORD WAZUH_REGISTRATION_PASSWORD 2>/dev/null || true
  return "$cleanup_rc"
}
trap cleanup EXIT

if (( RESET_EXISTING == 1 )); then
  [[ -s "$CONFIG_FILE" ]] || die "Generated baseline ossec.conf is missing; cannot reset safely."
  [[ -s "$ACTIVE_AGENT_CONF" && ! -L "$ACTIVE_AGENT_CONF" ]] ||
    die "Active ossec.conf is missing or is a symlink; refusing reset."
  RESET_STAMP="$(date +%Y%m%d-%H%M%S)"
  RESET_CONF_BACKUP="${ACTIVE_AGENT_CONF}.pre-defenseops-reset.${RESET_STAMP}.$$"
  RESET_KEYS_BACKUP="/var/ossec/etc/client.keys.pre-defenseops-reset.${RESET_STAMP}.$$"
  cp -a -- "$ACTIVE_AGENT_CONF" "$RESET_CONF_BACKUP"
  if [[ -e /var/ossec/etc/client.keys ]]; then
    cp -a -- /var/ossec/etc/client.keys "$RESET_KEYS_BACKUP"
  else
    RESET_KEYS_BACKUP=""
  fi
  RESET_APPLIED=1
  if systemctl is-active --quiet wazuh-agent; then
    RESET_SERVICE_WAS_ACTIVE=1
    systemctl stop wazuh-agent
  fi
  RESET_TMP="$(mktemp "${ACTIVE_AGENT_CONF}.reset.XXXXXX")"
  cp -- "$CONFIG_FILE" "$RESET_TMP"
  chown --reference="$ACTIVE_AGENT_CONF" "$RESET_TMP"
  chmod --reference="$ACTIVE_AGENT_CONF" "$RESET_TMP"
  mv -f -- "$RESET_TMP" "$ACTIVE_AGENT_CONF"
  rm -f /var/ossec/etc/client.keys
  log "Existing ossec.conf reset to the generated DefenseOps baseline; previous files backed up."
fi

if (( AGENT_ENROLLED == 0 )); then
  read -r -s -p "Enrollment password for DefenseOps: " REG_PASSWORD
  printf '\n'
  [[ -n "$REG_PASSWORD" ]] || die "Enrollment password cannot be empty."

  if (( AGENT_PACKAGE_INSTALLED == 0 )); then
    # Install package only. Enrollment is performed explicitly below.
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
    log "Wazuh Agent package already installed; package will not be reinstalled."
  fi

  [[ -x /var/ossec/bin/agent-auth ]] ||
    die "agent-auth binary not found; cannot enroll the Agent."

  # Preserve the package-created empty client.keys placeholder. Never overwrite
  # a non-empty invalid identity file.
  if [[ -e /var/ossec/etc/client.keys ]]; then
    if [[ -s /var/ossec/etc/client.keys ]]; then
      die "client.keys is non-empty but has no valid enrollment entry; refusing to overwrite it."
    fi
    EMPTY_KEYS_BACKUP="/var/ossec/etc/client.keys.empty.$(date +%Y%m%d-%H%M%S).$$"
    mv -- /var/ossec/etc/client.keys "$EMPTY_KEYS_BACKUP"
    log "Preserved empty client.keys placeholder: ${EMPTY_KEYS_BACKUP}"
  fi

  if systemctl is-active --quiet wazuh-agent; then
    systemctl stop wazuh-agent
  fi

  # agent-auth accepts the authorization password through -P. This argument is
  # short-lived; no credential file is created and no password enters the bundle.
  auth_args=(-m "$MANAGER" -p "$REG_PORT" -A "$AGENT_NAME" -P "$REG_PASSWORD" -G "$AGENT_GROUP")
  /var/ossec/bin/agent-auth "${auth_args[@]}" ||
    die "agent-auth failed. Check Manager connectivity, enrollment password, and authd configuration."

  [[ -s /var/ossec/etc/client.keys ]] ||
    die "Enrollment did not create /var/ossec/etc/client.keys; refusing to continue."
  if ! awk 'NF >= 3 { found=1 } END { exit(found ? 0 : 1) }' /var/ossec/etc/client.keys; then
    die "client.keys exists but contains no valid enrollment entry; refusing to continue."
  fi
  AGENT_ENROLLED=1

  unset WAZUH_REGISTRATION_PASSWORD 2>/dev/null || true
  [[ -s /var/ossec/etc/client.keys ]] ||
    die "Enrollment did not create /var/ossec/etc/client.keys; refusing to continue."
  if ! awk 'NF >= 3 { found=1 } END { exit(found ? 0 : 1) }' /var/ossec/etc/client.keys; then
    die "client.keys exists but contains no valid enrollment entry; refusing to continue."
  fi
  AGENT_ENROLLED=1
else
  log "Existing enrollment detected; preserving client.keys and skipping enrollment."
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
[[ -n "$DOCKER_PHP_APP_DIRS_FILE" ]] || DOCKER_PHP_APP_DIRS_FILE="$(mktemp)"
AGENT_CONFIG_REPLACED=0
AGENT_SERVICE_STOPPED=0
WAS_AGENT_ACTIVE=0
CONFIG_CHANGED=0

if [[ "$ENDPOINT_PROFILE" == "brebes-waf" ]]; then
  {
    for path in "${!NGINX_ACCESS_LOGS[@]}"; do printf '%s\tjson\n' "$path"; done
    for path in "${!NGINX_ERROR_LOGS[@]}"; do printf '%s\tsyslog\n' "$path"; done
    for path in "${!MODSEC_DEBUG_FILES[@]}"; do printf '%s\tsyslog\n' "$path"; done
    if (( MODSEC_COLLECTOR_ENABLED == 1 )); then
      printf '%s\tjson\n' "$MODSEC_JSON_LOG"
    fi
  } | sort -u > "$PATHS_FILE"

  if (( MODSEC_COLLECTOR_ENABLED == 1 )); then
    log "ModSecurity JSON event collection configured: ${MODSEC_JSON_LOG}"
  else
    warn "ModSecurity audit collector is not enabled because no usable audit source was discovered."
  fi
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

  rm -f "${TMP_AGENT_CONF:-}" "${PATHS_FILE:-}" "${DOCKER_PHP_APP_DIRS_FILE:-}" "${NGINX_DUMP:-}" "${DISCOVERY_REPORT:-}" "${MODSEC_REPORT:-}"
  cleanup
  exit "$exit_code"
}
trap cleanup_files EXIT

# Copy metadata first; the merge writes only file contents to this same-directory
# staging file. The original remains untouched until all pre-activation checks pass.
cp -a -- "$AGENT_CONF" "$TMP_AGENT_CONF"

python3 - "$AGENT_CONF" "$TMP_AGENT_CONF" "$ENDPOINT_PROFILE" "$PATHS_FILE" "$MANAGER" "$RESET_EXISTING" <<'PYMERGE'
import html
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

source, destination, profile, paths_file, expected_manager, reset_existing = sys.argv[1:7]
original = Path(source).read_text(encoding="utf-8")
text = original

# On the preserve path, validate the ACTIVE Agent's client/server address.
# Repair only a known template placeholder, using the Manager address from
# this generated bundle. A different but syntactically valid Manager is never
# silently replaced: abort and require an explicit reset/migration decision.
def manager_addresses(xml_text):
    root = ET.fromstring("<defenseops_validation_root>" +
                         re.sub(r"^\s*<\?xml[^?]*\?>", "", xml_text, count=1) +
                         "</defenseops_validation_root>")
    found = []
    for client in root.iter("client"):
        for server in client.findall("server"):
            for address in server.findall("address"):
                found.append((address.text or "").strip())
    return found

if reset_existing != "1":
    try:
        current_addresses = manager_addresses(text)
    except ET.ParseError as exc:
        raise SystemExit(f"Existing ossec.conf XML is invalid; refusing preserve-mode update: {exc}")
    if len(current_addresses) != 1:
        raise SystemExit(
            "Existing ossec.conf must contain exactly one <client><server><address>; "
            f"found {len(current_addresses)}. No configuration was changed."
        )
    current_manager = current_addresses[0]
    placeholder_values = {"", "manager_ip", "<manager_ip>", "changeme", "<manager>"}
    if current_manager.lower() in placeholder_values:
        # Replace only the address value inside the client/server section.
        pattern = re.compile(
            r"(<client\b[^>]*>.*?<server\b[^>]*>.*?<address\b[^>]*>)(.*?)(</address\s*>.*?</server\s*>.*?</client\s*>)",
            flags=re.DOTALL | re.IGNORECASE,
        )
        matches = list(pattern.finditer(text))
        if len(matches) != 1:
            raise SystemExit("Could not safely locate the single client/server address for placeholder repair.")
        match = matches[0]
        text = text[:match.start()] + match.group(1) + html.escape(expected_manager) + match.group(3) + text[match.end():]
        print(f"[INFO] Repaired placeholder Manager address in active ossec.conf: {expected_manager}")
    elif current_manager != expected_manager:
        raise SystemExit(
            f"Existing Agent Manager '{current_manager}' differs from generated bundle Manager "
            f"'{expected_manager}'. Refusing to overwrite an enrolled Agent's Manager address. "
            "Choose reset/re-enroll only if migration is intentional."
        )
    else:
        print(f"[INFO] Existing Agent Manager address verified: {current_manager}")

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
        parts = raw.split("\t", 1)
        if len(parts) != 2:
            raise SystemExit(f"Invalid discovered log entry: {raw!r}")
        path, fmt = parts[0].strip(), parts[1].strip()
        if path == "/var/log/nginx/access.log":
            continue
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

    # Remove only the obsolete global Nginx access.log input. All other
    # localfile entries (including error/debug/system logs) remain untouched.
    removed_counter = [0]
    localfile_pattern = re.compile(
        r"<localfile\b[^>]*>.*?</localfile\s*>",
        flags=re.DOTALL | re.IGNORECASE,
    )
    def remove_obsolete_access_log(match):
        block = match.group(0)
        location = re.search(
            r"<location\b[^>]*>\s*(.*?)\s*</location\s*>",
            block,
            flags=re.DOTALL | re.IGNORECASE,
        )
        if location and location.group(1).strip() == "/var/log/nginx/access.log":
            removed_counter[0] += 1
            return ""
        return block

    text = localfile_pattern.sub(remove_obsolete_access_log, text)
    if removed_counter[0]:
        print(
            f"[INFO] Removed {removed_counter[0]} obsolete localfile entry/entries "
            "for /var/log/nginx/access.log; unrelated inputs were preserved."
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
            "  <localfile>\n"
            f"    <location>{escaped}</location>\n"
            f"    <log_format>{fmt}</log_format>\n"
            "  </localfile>\n"
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

elif profile == "docker-php":
    # Docker-PHP application FIM is owned exclusively by the dedicated
    # registry-scoped inotify daemon. Remove legacy Syscheck entries under
    # /var/apps to prevent duplicate scanning, while preserving every
    # unrelated system directory and all other Syscheck settings.
    removed_fim_entries = [0]
    directories_pattern = re.compile(
        r"<directories\b[^>]*>.*?</directories\s*>",
        flags=re.DOTALL | re.IGNORECASE,
    )

    def remove_legacy_docker_php_fim(match):
        element = match.group(0)
        value = re.sub(
            r"^.*?>|</directories\s*>$",
            "",
            element,
            flags=re.DOTALL | re.IGNORECASE,
        ).strip()
        normalized = value.rstrip("/")
        if normalized == "/var/apps" or normalized.startswith("/var/apps/"):
            removed_fim_entries[0] += 1
            return ""
        return element

    text = directories_pattern.sub(remove_legacy_docker_php_fim, text)
    if removed_fim_entries[0]:
        print(
            f"[INFO] Removed {removed_fim_entries[0]} legacy Syscheck "
            "directory entr(y/ies) under /var/apps; unrelated Syscheck "
            "directories and settings were preserved."
        )
    else:
        print("[INFO] No legacy /var/apps Syscheck entries found.")

    docker_php_log = "/var/log/defenseops/docker-php-events.json"
    existing = set()
    for node in parsed.iter("localfile"):
        loc = node.find("location")
        fmt = node.find("log_format")
        if loc is not None and loc.text:
            existing.add((loc.text.strip(), (fmt.text or "default").strip() if fmt is not None else "default"))
    if (docker_php_log, "json") not in existing:
        first = blocks[0]
        close = re.search(r"</ossec_config\s*>", first.group(0))
        insert_at = first.start() + close.start()
        text = (text[:insert_at] +
                "  <localfile>\n"
                f"    <location>{docker_php_log}</location>\n"
                "    <log_format>json</log_format>\n"
                "  </localfile>\n" + text[insert_at:])

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
  elif (( AGENT_WAS_ENROLLED == 0 )); then
    systemctl enable wazuh-agent
    systemctl start wazuh-agent
    AGENT_SERVICE_STOPPED=1
  else
    log "Agent was inactive before update; preserving its inactive state."
  fi

  if (( WAS_AGENT_ACTIVE == 1 || AGENT_WAS_ENROLLED == 0 )); then
    sleep 3
    systemctl is-active --quiet wazuh-agent ||
      die "Wazuh Agent did not become active; original configuration will be restored."
    AGENT_SERVICE_STOPPED=0
  fi
  log "Original configuration backup: ${BACKUP}"
fi

# Apply package hold only when this run installed the package.
if (( AGENT_PACKAGE_INSTALLED == 0 )); then
  if command -v apt-mark >/dev/null 2>&1; then
    apt-mark hold wazuh-agent >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf versionlock add wazuh-agent >/dev/null 2>&1 ||
      warn "Could not apply DNF versionlock; manage Agent updates manually."
  fi
fi

# A previously installed but unenrolled Agent has just become managed:
# enable/start it. Preserve service state for Agents enrolled before this run.
if (( AGENT_WAS_ENROLLED == 0 )); then
  systemctl enable wazuh-agent
  if ! systemctl is-active --quiet wazuh-agent; then
    systemctl start wazuh-agent
  fi
fi

unset WAZUH_REGISTRATION_PASSWORD REG_PASSWORD
if systemctl is-active --quiet wazuh-agent; then
  AGENT_SERVICE_STOPPED=0
  log "Wazuh Agent service is active."
elif (( AGENT_WAS_ENROLLED == 1 )); then
  log "Wazuh Agent was inactive before profile update; its service state was preserved."
else
  systemctl --no-pager --full status wazuh-agent || true
  die "Wazuh Agent did not become active. Check /var/ossec/logs/ossec.log."
fi

if [[ "$ENDPOINT_PROFILE" == "brebes-waf" ]] && (( MODSEC_COLLECTOR_ENABLED == 1 )); then
  activate_modsecurity_collector
fi
if [[ "$ENDPOINT_PROFILE" == "docker-php" ]]; then
  install_docker_php_monitoring
fi

if (( RESET_APPLIED == 1 )); then
  RESET_COMMITTED=1
  log "Reset/re-enrollment completed. Previous ossec.conf backup: ${RESET_CONF_BACKUP}"
  [[ -n "$RESET_KEYS_BACKUP" ]] && log "Previous client.keys backup: ${RESET_KEYS_BACKUP}"
fi

log "Installed Wazuh Agent version: $(/var/ossec/bin/wazuh-agentd -V 2>&1 | head -n1 || true)"
log "Endpoint profile: ${ENDPOINT_PROFILE}"
if (( AGENT_WAS_ENROLLED == 1 )); then
  log "Manager and enrolled Agent identity: preserved (no re-enrollment)."
  log "Existing Manager-side group membership was not changed."
else
  log "Manager: ${MANAGER}:${MANAGER_PORT}/TCP; enrollment: ${MANAGER}:${REG_PORT}/TCP"
  log "Agent name: ${AGENT_NAME}"
  log "Assigned Wazuh group during enrollment: ${AGENT_GROUP}"
fi
log "Verify this endpoint appears as Active in the DefenseOps Dashboard."

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
     No native Syscheck directory monitoring is configured. The endpoint-local
     DefenseOps inotify daemon owns registry-scoped FIM; Wazuh only ingests JSONL. -->
<agent_config os="^Linux">
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
  </syscheck>
</agent_config>
PROFILE_DOCKERPHP
chmod 0640 "${OUT_DIR}/profiles/docker-php/agent.conf"

# Remove a stale artifact from older generator versions. This only affects
# the generated output directory; it does not touch the Manager or endpoints.
rm -f -- "${OUT_DIR}/deploy-agent-profiles.sh"

cat > "${OUT_DIR}/README.txt" <<EOF
DefenseOps Agent Deployment - Brebes-WAF & Docker-PHP
====================================================
Generator    : v${SCRIPT_VERSION} (${SCRIPT_RELEASE})
Docker-PHP collector : v1.14.0 + Docker Events + snapshots + inotify FIM
Wazuh Agent  : ${VERSION}
Manager      : ${MANAGER}
Agent port   : ${MANAGER_PORT}/TCP
Enrollment   : ${REG_PORT}/TCP

Bundle:
  install-agent.sh
  ossec.conf
  profiles/brebes-waf/agent.conf
  profiles/docker-php/agent.conf

Endpoint installation / profile update:
  sudo ./install-agent.sh [--name HOSTNAME]
  Select Brebes-WAF or Docker-PHP when prompted.

  If Wazuh Agent is absent: installs and enrolls the Agent.
  If Wazuh Agent is already installed and reset is declined: validates the
  active Manager address against this bundle, repairs only a known placeholder,
  preserves package/client identity/unrelated configuration, and merges only
  missing profile settings. A different valid Manager address causes a safe abort.
  Existing installations are not reinstalled, re-enrolled, or upgraded by package manager.

Brebes-WAF:
  Discovery runs on the Brebes-WAF endpoint by recursively parsing the active
  Nginx main configuration and its include files in their original contexts.
  The conventional global /var/log/nginx/access.log is intentionally excluded.
  A dedicated http-level Brebes-WAF access log is accepted when its log_format
  is verified as a JSON object using escape=json; this supports the dedicated
  access.json file defined from conf.d. Explicit virtual-host/server or nested
  access_log directives must also use verified JSON. Explicit access_log off
  directives are skipped. Non-JSON or unsafe vhost access logs abort installation
  before package installation, enrollment, or Agent configuration changes.
  SecAuditLogType, SecAuditLog, SecAuditLogStorageDir, and SecDebugLog are
  discovered separately. Concurrent mode reads completed transaction files
  from SecAuditLogStorageDir; Serial mode reads SecAuditLog. SecAuditLog index
  files are never mistaken for transaction files. SecDebugLog remains collected
  separately as plain-text syslog and is not treated as the audit-event source. A parser writes normalized JSONL
  events, which Wazuh collects with log_format=json. The endpoint installer
  installs the parser as a persistent systemd daemon automatically;
  no manual Python execution is required.
  The installer embeds defenseops-modsecurity-collector.py and installs it at
  /usr/local/libexec as one Type=simple daemon. Inotify detects completed/new
  audit files; an internal scheduler performs streaming reconciliation at the
  configured interval (default 600 seconds) and retries due queue entries.
  SQLite stores the persistent work queue and event deduplication state.
  The daemon installs recursive directory watches, performs reconciliation at
  startup and periodically, and forces reconciliation after inotify overflow.
  It does not create a 30-second systemd timer. Initial baseline prevents
  replaying pre-install audit transactions. Wazuh reads only
  /var/log/defenseops/modsecurity-events.json as JSON;
  rotates output at 250 MB, retains compressed archives for 90 days,
  and prunes SQLite deduplication state older than 180 days.
  Nginx and ModSecurity configurations are never modified.
  The installer backs up /var/ossec/etc/ossec.conf, stages the updated file,
  validates it with wazuh-agentd -t, and restores the backup if validation fails.
  Nginx and ModSecurity configuration files are never modified.

Docker-PHP:
  Enrollment assigns the endpoint to the docker-php Wazuh group. The endpoint
  installer installs a registry-scoped collector which reads only
  /var/lib/docker-php/monitoring/applications/*.json. It never enumerates all
  Docker containers as monitoring targets and does not collect Nginx logs.
  The bundled Docker-PHP runtime collector is v1.14.0; it streams Docker container lifecycle events and performs five-minute status snapshots. The dedicated inotify FIM daemon is v1.0.0. Health and security use separate
  fingerprints. PHP-FPM root detection counts only process command lines beginning with
  "php-fpm: pool ". The master process and inspection shell are excluded.
  A verified pool worker running as UID 0 is reported as root_user. If no
  worker can be verified or inspection fails, the collector reports
  needs_review instead of asserting the container is safe.
  The collector honors per-application monitoring flags (docker_health, security,
  php_fpm, fim). The malware flag is explicitly unsupported and produces a warning;
  no malware scan is performed. The collector checks registered container health/security
  and performs registry-scoped application FIM. Source/htdocs files are limited
  to SOURCE_SUFFIXES (PHP and selected source/config extensions). Every regular
  file type under each registered writable path is monitored, including images
  and documents; session, sessions, and cache directories are excluded. Writable
  paths may be a single string or an array in the Application Registry. Paths
  are resolved and must remain inside that application's /var/apps directory;
  symlinks are not followed. Existing files in newly added writable roots are
  baselined silently to avoid a burst of false file-added alerts. Subsequent
  changes generate JSONL events at /var/log/defenseops/docker-php-events.json.
  Wazuh Agent reads that dedicated file as JSON. The persistent runtime collector
  streams Docker Events for registered containers and performs health/security/
  PHP-FPM/resource snapshots every five minutes. A separate
  systemd inotify daemon recursively watches only validated registry source and
  writable roots, hashes changed files only, and persists fingerprints in SQLite.
  Registry reconciliation runs every 60 seconds; new roots are silently baselined.
  Native Wazuh Syscheck does not monitor application directories, avoiding duplicate
  FIM ownership. It requires Python 3, SQLite (standard library), Linux inotify,
  and Docker CLI access for runtime checks.
  Missing Docker or invalid registry entries are warnings; unrelated containers
  are not added to scope. This initial implementation reports findings only;
  it does not delete, quarantine, or modify application files.

Time settings:
  The installer asks independently whether to change timezone to Asia/Jakarta
  and whether to enable NTP using the host's existing time-sync configuration.
  It does not overwrite chrony/timesyncd configuration files.

Security:
  Enrollment password is requested only for first-time installation and is
  never stored in bundle. Existing enrolled Agent identities are preserved;
  existing packages are not reinstalled or upgraded.
  Configuration updates are idempotent, backed up, validated, and rolled back
  on activation failure. Existing unrelated XML content is preserved.

Wazuh group assignment:
  Brebes-WAF profile is enrolled into group Brebes-WAF.
  Docker-PHP profile is enrolled into group docker-php.
  Existing enrolled identities are preserved and are not re-enrolled;
  their existing Manager-side group membership is left unchanged.
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
  install-agent.sh ossec.conf README.txt profiles
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
log "Profiles: brebes-waf -> Brebes-WAF (unchanged); docker-php -> docker-php (collector v1.14.0 + Docker Events + five-minute snapshots + registry-scoped inotify FIM)."
log "Existing enrolled Agents are preserved; Manager-side group membership is not changed."
log "Brebes-WAF Concurrent/Serial ModSecurity audit normalization is integrated in the endpoint installer."
log "No enrollment secret was copied or embedded."
