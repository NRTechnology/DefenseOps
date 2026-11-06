#!/usr/bin/env bash
#
# DefenseOps - Full host preparation and Wazuh single-node deployment
# Supported OS: Ubuntu Server 24.04 LTS / 26.04 LTS
#
# Installs:
#   - Ubuntu base requirements
#   - Docker Engine + Docker Compose plugin
#   - Wazuh Manager, Indexer, Dashboard (three independent Compose projects)
#
# Wazuh containers are sourced from the official wazuh/wazuh-docker repository
# and pinned to WAZUH_VERSION below. The official single-node configuration is
# split into three Compose files while retaining the upstream service settings.
#
set -Eeuo pipefail
IFS=$'\n\t'
umask 027

readonly SCRIPT_NAME="$(basename "$0")"
readonly MIN_CPU_CORES=4
readonly MIN_RAM_GIB=8
readonly MIN_STORAGE_GIB=250
readonly WAZUH_VERSION="${WAZUH_VERSION:-4.14.10}"
readonly WAZUH_REPO_URL="https://github.com/wazuh/wazuh-docker.git"
readonly WAZUH_REPO_BRANCH="v${WAZUH_VERSION}"
readonly DEFENSEOPS_ROOT="${DEFENSEOPS_ROOT:-/opt/defenseops}"
readonly WAZUH_ROOT="${DEFENSEOPS_ROOT}/wazuh"
readonly WAZUH_SOURCE="${WAZUH_ROOT}/source"
readonly WAZUH_SHARED="${WAZUH_ROOT}/shared"
readonly WAZUH_CONFIG="${WAZUH_SHARED}/config"
readonly WAZUH_NETWORK="defenseops-wazuh"
readonly DOCKER_KEYRING="/etc/apt/keyrings/docker.asc"
readonly DOCKER_SOURCES_FILE="/etc/apt/sources.list.d/docker.sources"
readonly UBUNTU_SOURCES_FILE="/etc/apt/sources.list.d/ubuntu.sources"
readonly SYSCTL_FILE="/etc/sysctl.d/99-defenseops-wazuh.conf"
readonly CREDENTIALS_FILE="${DEFENSEOPS_ROOT}/secrets/wazuh-credentials.env"

LOG_FILE="${LOG_FILE:-/var/log/defenseops-install-requirements.log}"
DRY_RUN=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { printf "%b[INFO]%b %s\n" "$BLUE" "$NC" "$*"; }
ok()   { printf "%b[ OK ]%b %s\n" "$GREEN" "$NC" "$*"; }
warn() { printf "%b[WARN]%b %s\n" "$YELLOW" "$NC" "$*"; }
err()  { printf "%b[FAIL]%b %s\n" "$RED" "$NC" "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() {
    cat <<USAGE
Usage: sudo ./$SCRIPT_NAME [options]

Options:
  --dry-run       Check requirements and show the installation plan only.
  -h, --help      Show this help.

Environment:
  DEFENSEOPS_ROOT  Installation root (default: /opt/defenseops)
  WAZUH_VERSION    Wazuh Docker release (default: ${WAZUH_VERSION})
  LOG_FILE         Log file (default: /var/log/defenseops-install-requirements.log)

Example:
  sudo ./$SCRIPT_NAME --dry-run
  sudo ./$SCRIPT_NAME
USAGE
}

while (($#)); do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "Opsi tidak dikenal: $1 (gunakan --help)." ;;
    esac
    shift
done

[[ "${EUID}" -eq 0 ]] || die "Jalankan sebagai root: sudo ./$SCRIPT_NAME"
if (( ! DRY_RUN )); then
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 0600 "$LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

backup_file() {
    local file="$1"
    if [[ -e "$file" && ! -e "${file}.defenseops-backup" ]]; then
        cp -a "$file" "${file}.defenseops-backup"
        log "Backup dibuat: ${file}.defenseops-backup"
    fi
}

check_system_requirements() {
    log "Memeriksa system requirements DefenseOps..."
    [[ -r /etc/os-release ]] || die "/etc/os-release tidak ditemukan."
    # shellcheck disable=SC1091
    source /etc/os-release

    [[ "${ID:-}" == "ubuntu" ]] || die "OS tidak didukung. Gunakan Ubuntu Server 24.04 LTS atau 26.04 LTS."
    case "${VERSION_ID:-}" in
        24.04|26.04) ;;
        *) die "Ubuntu ${VERSION_ID:-unknown} belum didukung. Hanya Ubuntu 24.04 LTS dan 26.04 LTS." ;;
    esac

    local arch cores ram_kib storage_bytes ram_gib storage_gib
    arch="$(dpkg --print-architecture)"
    case "$arch" in amd64|arm64) ;; *) die "Arsitektur ${arch} belum didukung. Gunakan amd64 atau arm64." ;; esac
    cores="$(nproc)"
    ram_kib="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
    storage_bytes="$(df -B1 --output=size /opt 2>/dev/null | awk 'NR==2 {gsub(/[[:space:]]/, ""); print}')"
    [[ "$storage_bytes" =~ ^[0-9]+$ ]] || die "Tidak dapat membaca ukuran filesystem /opt."
    ram_gib=$((ram_kib / 1024 / 1024))
    storage_gib=$((storage_bytes / 1024 / 1024 / 1024))

    log "OS             : ${PRETTY_NAME}"
    log "Architecture   : ${arch}"
    log "CPU            : ${cores} core"
    log "RAM            : ${ram_gib} GiB (dibulatkan ke bawah)"
    log "Filesystem /opt: ${storage_gib} GiB (ukuran total filesystem)"

    (( cores >= MIN_CPU_CORES )) || die "CPU tidak memenuhi syarat: minimum ${MIN_CPU_CORES} core."
    (( ram_kib >= MIN_RAM_GIB * 1024 * 1024 )) || die "RAM tidak memenuhi syarat: minimum ${MIN_RAM_GIB} GiB."
    (( storage_bytes >= MIN_STORAGE_GIB * 1024 * 1024 * 1024 )) || die "Filesystem yang menampung /opt tidak memenuhi syarat: minimum ${MIN_STORAGE_GIB} GiB."

    ok "System requirements minimum terpenuhi."
}

configure_ubuntu_repositories() {
    log "Mengatur repository Ubuntu ke repository utama resmi..."
    local codename arch archive_uri tmp
    codename="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
    [[ -n "$codename" ]] || die "Codename Ubuntu tidak ditemukan."
    arch="$(dpkg --print-architecture)"

    # Ubuntu publishes ARM64 packages through ports.ubuntu.com.
    if [[ "$arch" == "arm64" ]]; then
        archive_uri="http://ports.ubuntu.com/ubuntu-ports/"
    else
        archive_uri="http://archive.ubuntu.com/ubuntu/"
    fi

    tmp="$(mktemp)"
    cat > "$tmp" <<SOURCES
Types: deb
URIs: ${archive_uri}
Suites: ${codename} ${codename}-updates ${codename}-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://security.ubuntu.com/ubuntu/
Suites: ${codename}-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
SOURCES

    install -d -m 0755 /etc/apt/sources.list.d
    backup_file "$UBUNTU_SOURCES_FILE"
    install -m 0644 "$tmp" "$UBUNTU_SOURCES_FILE"
    rm -f "$tmp"

    # Disable only legacy Ubuntu mirror lines in sources.list. Non-Ubuntu
    # third-party entries are preserved.
    if [[ -f /etc/apt/sources.list ]] && grep -Eq '^[[:space:]]*deb(-src)?[[:space:]]' /etc/apt/sources.list; then
        backup_file /etc/apt/sources.list
        local legacy_tmp
        legacy_tmp="$(mktemp)"
        awk '
          /^[[:space:]]*deb(-src)?[[:space:]]/ && /(ubuntu\.com|ubuntu-ports)/ {
            print "# Disabled by DefenseOps installer: " $0
            next
          }
          { print }
        ' /etc/apt/sources.list > "$legacy_tmp"
        install -m 0644 "$legacy_tmp" /etc/apt/sources.list
        rm -f "$legacy_tmp"
    fi

    ok "Repository Ubuntu dikonfigurasi: ${archive_uri} dan security.ubuntu.com."
}

install_base_packages() {
    log "Memasang paket kebutuhan dasar..."
    apt-get update
    env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        ca-certificates curl wget gnupg lsb-release jq git unzip zip tar gzip \
        openssl rsync logrotate chrony vim htop net-tools iproute2 dnsutils \
        iputils-ping procps util-linux findutils software-properties-common python3 \
        python3-yaml
    ok "Paket dasar terpasang."
}

check_docker_conflicts() {
    # Do not remove existing container runtimes automatically. A host with
    # docker.io / Podman compatibility packages needs an explicit migration.
    local pkg
    for pkg in docker.io docker-compose docker-compose-v2 docker-doc podman-docker; do
        if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
            die "Paket konflik ${pkg} terdeteksi. Installer tidak akan menghapus runtime yang mungkin sedang dipakai. Migrasikan secara manual lalu jalankan ulang."
        fi
    done
}

install_docker() {
    log "Memasang Docker Engine dan Docker Compose Plugin dari repository resmi Docker..."
    check_docker_conflicts

    local arch codename
    arch="$(dpkg --print-architecture)"
    codename="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"

    install -d -m 0755 /etc/apt/keyrings
    backup_file "$DOCKER_KEYRING"
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o "$DOCKER_KEYRING"
    chmod 0644 "$DOCKER_KEYRING"

    backup_file "$DOCKER_SOURCES_FILE"
    cat > "$DOCKER_SOURCES_FILE" <<DOCKERREPO
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${codename}
Components: stable
Architectures: ${arch}
Signed-By: ${DOCKER_KEYRING}
DOCKERREPO

    apt-get update
    env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    systemctl enable --now docker
    docker version >/dev/null
    docker compose version >/dev/null
    ok "Docker Engine dan Docker Compose Plugin terpasang."
}

configure_docker_defaults() {
    local daemon_json="/etc/docker/daemon.json"
    install -d -m 0755 /etc/docker

    if [[ -e "$daemon_json" ]]; then
        warn "${daemon_json} sudah ada; tidak ditimpa untuk menjaga konfigurasi administrator."
    else
        cat > "$daemon_json" <<'JSON'
{
  "log-driver": "local",
  "log-opts": {
    "max-size": "20m",
    "max-file": "5"
  },
  "live-restore": true
}
JSON
        chmod 0644 "$daemon_json"
        systemctl restart docker
        ok "Konfigurasi default Docker daemon dibuat."
    fi
}

configure_kernel() {
    log "Mengatur vm.max_map_count untuk Wazuh Indexer..."
    cat > "$SYSCTL_FILE" <<'SYSCTL'
# Required by Wazuh Indexer / OpenSearch
vm.max_map_count=262144
SYSCTL
    chmod 0644 "$SYSCTL_FILE"
    sysctl --system >/dev/null
    [[ "$(sysctl -n vm.max_map_count)" -ge 262144 ]] || die "vm.max_map_count gagal diatur."
    ok "vm.max_map_count=$(sysctl -n vm.max_map_count)."
}

create_directories() {
    log "Membuat direktori DefenseOps..."
    install -d -m 0750 \
        "${DEFENSEOPS_ROOT}/core/config" \
        "${DEFENSEOPS_ROOT}/core/logs" \
        "${DEFENSEOPS_ROOT}/core/services" \
        "${WAZUH_ROOT}/manager/config" \
        "${WAZUH_ROOT}/manager/data" \
        "${WAZUH_ROOT}/manager/logs" \
        "${WAZUH_ROOT}/manager/certs" \
        "${WAZUH_ROOT}/indexer/config" \
        "${WAZUH_ROOT}/indexer/data" \
        "${WAZUH_ROOT}/indexer/logs" \
        "${WAZUH_ROOT}/indexer/certs" \
        "${WAZUH_ROOT}/dashboard/config" \
        "${WAZUH_ROOT}/dashboard/data" \
        "${WAZUH_ROOT}/dashboard/logs" \
        "${WAZUH_SHARED}" \
        "${DEFENSEOPS_ROOT}/backup" \
        "${DEFENSEOPS_ROOT}/secrets"
    chmod 0700 "${DEFENSEOPS_ROOT}/secrets"
    ok "Direktori DefenseOps tersedia."
}

create_docker_network() {
    if docker network inspect "$WAZUH_NETWORK" >/dev/null 2>&1; then
        ok "Docker network ${WAZUH_NETWORK} sudah tersedia."
    else
        docker network create --driver bridge \
            --label purpose=defenseops \
            "$WAZUH_NETWORK" >/dev/null
        ok "Docker network ${WAZUH_NETWORK} dibuat."
    fi
}

prepare_wazuh_source() {
    log "Mengambil source deployment resmi Wazuh ${WAZUH_VERSION}..."
    if [[ -d "$WAZUH_SOURCE/.git" ]]; then
        local current_tag
        current_tag="$(git -C "$WAZUH_SOURCE" describe --tags --exact-match 2>/dev/null || true)"
        [[ "$current_tag" == "$WAZUH_REPO_BRANCH" ]] || die "Source Wazuh yang sudah ada bukan tag ${WAZUH_REPO_BRANCH}; tidak ditimpa."
    elif [[ -e "$WAZUH_SOURCE" ]]; then
        die "${WAZUH_SOURCE} sudah ada tetapi bukan Git repository. Pindahkan atau periksa secara manual."
    else
        git clone --depth 1 --branch "$WAZUH_REPO_BRANCH" "$WAZUH_REPO_URL" "$WAZUH_SOURCE"
    fi

    [[ -f "${WAZUH_SOURCE}/single-node/docker-compose.yml" ]] || die "Docker Compose resmi Wazuh tidak ditemukan."
    [[ -f "${WAZUH_SOURCE}/single-node/generate-indexer-certs.yml" ]] || die "Certificate generator resmi Wazuh tidak ditemukan."
    ok "Source Wazuh ${WAZUH_VERSION} tersedia."
}

build_certificate_generator_image() {
    local builder_dir="${WAZUH_ROOT}/certs-generator"
    local dockerfile="${builder_dir}/Dockerfile"

    install -d -m 0755 "$builder_dir"
    cat > "$dockerfile" <<'DOCKERFILE'
FROM wazuh/wazuh-certs-generator:0.0.5
USER root
RUN set -eux; \
    if command -v apt-get >/dev/null 2>&1; then \
        apt-get update && apt-get install -y --no-install-recommends findutils \
        && rm -rf /var/lib/apt/lists/*; \
    elif command -v apk >/dev/null 2>&1; then \
        apk add --no-cache findutils; \
    elif command -v dnf >/dev/null 2>&1; then \
        dnf install -y findutils && dnf clean all; \
    elif command -v microdnf >/dev/null 2>&1; then \
        microdnf install -y findutils && microdnf clean all; \
    elif command -v yum >/dev/null 2>&1; then \
        yum install -y findutils && yum clean all; \
    else \
        echo "No supported package manager found to install findutils" >&2; \
        exit 1; \
    fi
DOCKERFILE

    log "Membangun certificate-generator image dengan findutils..."
    docker build --pull=false \
        --tag wazuh/wazuh-certs-generator:0.0.5 \
        "$builder_dir"
    ok "Certificate-generator image siap (find tersedia)."
}

repair_wazuh_certificate_permissions() {
    local cert_dir="${WAZUH_CONFIG}/wazuh_indexer_ssl_certs"

    [[ -d "$cert_dir" ]] || die "Direktori sertifikat tidak ditemukan: ${cert_dir}"
    [[ -s "${cert_dir}/root-ca.pem" ]] || die "Root CA Wazuh tidak ditemukan atau kosong."

    # The upstream certificate tool uses find to set ownership and modes.
    # Repair these on the host as a safety net and validate required files.
    local cert
    for cert in \
        admin.pem admin-key.pem root-ca.pem root-ca.key \
        wazuh.indexer.pem wazuh.indexer-key.pem \
        wazuh.manager.pem wazuh.manager-key.pem \
        wazuh.dashboard.pem wazuh.dashboard-key.pem; do
        [[ -s "${cert_dir}/${cert}" ]] || die "Sertifikat wajib ${cert} tidak ditemukan atau kosong."
    done

    chown -R 1000:1000 "$cert_dir"
    find "$cert_dir" -type d -exec chmod 0500 {} +
    find "$cert_dir" -type f \( -name '*-key.pem' -o -name '*.key' \) -exec chmod 0400 {} +
    find "$cert_dir" -type f \( -name '*.pem' ! -name '*-key.pem' \) -exec chmod 0444 {} +

    ok "Sertifikat Wazuh tervalidasi; ownership dan permission diperbaiki."
}

seed_wazuh_configuration() {
    local upstream_config="${WAZUH_SOURCE}/single-node/config"
    local upstream_cert_dir="${upstream_config}/wazuh_indexer_ssl_certs"
    local target_cert_dir="${WAZUH_CONFIG}/wazuh_indexer_ssl_certs"

    [[ -d "$upstream_config" ]] || die "Direktori konfigurasi upstream tidak ditemukan."

    if [[ ! -f "${WAZUH_CONFIG}/wazuh_indexer/internal_users.yml" ]]; then
        log "Menyalin konfigurasi awal resmi Wazuh..."
        cp -a "$upstream_config/." "$WAZUH_CONFIG/"
    else
        log "Konfigurasi Wazuh yang sudah ada dipertahankan."
    fi

    if [[ ! -s "${target_cert_dir}/root-ca.pem" ]]; then
        log "Membuat sertifikat TLS self-signed menggunakan certificate generator resmi Wazuh..."
        build_certificate_generator_image
        (
            cd "${WAZUH_SOURCE}/single-node"
            docker compose -f generate-indexer-certs.yml run --rm --pull never generator
        )
        install -d -m 0750 "$target_cert_dir"
        if [[ -d "$upstream_cert_dir" ]]; then
            cp -a "${upstream_cert_dir}/." "${target_cert_dir}/"
        fi
    else
        log "Sertifikat Wazuh yang sudah ada dipertahankan; memeriksa permission dan ownership."
    fi

    repair_wazuh_certificate_permissions
    ok "Konfigurasi dan sertifikat Wazuh tersedia."
}


prepare_wazuh_config_permissions() {
    log "Menyiapkan permission konfigurasi agar dapat dibaca container Wazuh..."

    # Wazuh Indexer and Dashboard run as numeric UID/GID 1000 in the
    # official containers. The bind-mounted config tree must be traversable
    # by that identity. Keep access group-restricted rather than world-readable.
    local path
    for path in \
        "$DEFENSEOPS_ROOT" \
        "$WAZUH_ROOT" \
        "$WAZUH_SHARED" \
        "$WAZUH_CONFIG"; do
        [[ -d "$path" ]] || die "Direktori konfigurasi tidak ditemukan: ${path}"
        chgrp 1000 "$path"
        chmod 0750 "$path"
    done

    chown -R 1000:1000 "$WAZUH_CONFIG"
    find "$WAZUH_CONFIG" -type d -exec chmod 0750 {} +
    find "$WAZUH_CONFIG" -type f -exec chmod 0640 {} +

    # Certificate private keys remain restricted to the Wazuh service owner
    # and its group. The Indexer/Dashboard containers use this identity.
    if [[ -d "${WAZUH_CONFIG}/wazuh_indexer_ssl_certs" ]]; then
        chown -R 1000:1000 "${WAZUH_CONFIG}/wazuh_indexer_ssl_certs"
        find "${WAZUH_CONFIG}/wazuh_indexer_ssl_certs" -type d -exec chmod 0750 {} +
        find "${WAZUH_CONFIG}/wazuh_indexer_ssl_certs" -type f -exec chmod 0640 {} +
    fi

    local indexer_conf="${WAZUH_CONFIG}/wazuh_indexer/opensearch.yml"
    [[ -r "$indexer_conf" ]] || die "opensearch.yml tidak dapat dibaca oleh host: ${indexer_conf}"

    ok "Permission konfigurasi Wazuh disiapkan untuk UID/GID 1000."
}

generate_password() {
    # Hex characters plus Aa1- meet Wazuh's complexity requirements and avoid
    # Compose interpolation / YAML quoting problems.
    printf '%sAa1-' "$(openssl rand -hex 24)"
}

load_or_create_credentials() {
    if [[ ! -f "$CREDENTIALS_FILE" ]]; then
        log "Membuat kredensial acak untuk akun internal Wazuh..."
        cat > "$CREDENTIALS_FILE" <<CREDS
WAZUH_INDEXER_ADMIN_PASSWORD=$(generate_password)
WAZUH_INDEXER_KIBANASERVER_PASSWORD=$(generate_password)
WAZUH_INDEXER_KIBANARO_PASSWORD=$(generate_password)
WAZUH_INDEXER_LOGSTASH_PASSWORD=$(generate_password)
WAZUH_INDEXER_READALL_PASSWORD=$(generate_password)
WAZUH_INDEXER_SNAPSHOTRESTORE_PASSWORD=$(generate_password)
WAZUH_API_PASSWORD=$(generate_password)
WAZUH_API_ADMIN_PASSWORD=$(generate_password)
CREDS
        chmod 0600 "$CREDENTIALS_FILE"
    else
        chmod 0600 "$CREDENTIALS_FILE"
        log "Kredensial yang sudah ada dipertahankan."
    fi

    # Backward-compatible addition if an earlier credentials file predates this key.
    if ! grep -q '^WAZUH_API_ADMIN_PASSWORD=' "$CREDENTIALS_FILE"; then
        printf 'WAZUH_API_ADMIN_PASSWORD=%s\n' "$(generate_password)" >> "$CREDENTIALS_FILE"
        chmod 0600 "$CREDENTIALS_FILE"
    fi

    # Values are generated by this script and contain only safe shell characters.
    # shellcheck disable=SC1090
    source "$CREDENTIALS_FILE"

    for name in \
        WAZUH_INDEXER_ADMIN_PASSWORD \
        WAZUH_INDEXER_KIBANASERVER_PASSWORD \
        WAZUH_INDEXER_KIBANARO_PASSWORD \
        WAZUH_INDEXER_LOGSTASH_PASSWORD \
        WAZUH_INDEXER_READALL_PASSWORD \
        WAZUH_INDEXER_SNAPSHOTRESTORE_PASSWORD \
        WAZUH_API_PASSWORD \
        WAZUH_API_ADMIN_PASSWORD; do
        [[ -n "${!name:-}" ]] || die "Kredensial ${name} kosong."
    done
}

generate_indexer_hash() {
    local password="$1" output hash

    # OpenSearch hash.sh expects -p <password>; it does not read from stdin.
    # The password is passed through an environment variable to avoid exposing
    # it in the docker command-line arguments.
    output="$(docker run --rm \
        --entrypoint /bin/bash \
        -e "HASH_PASSWORD=${password}" \
        -e JAVA_HOME=/usr/share/wazuh-indexer/jdk \
        -e OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk \
        "wazuh/wazuh-indexer:${WAZUH_VERSION}" \
        -c '/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$HASH_PASSWORD"' 2>&1)" \
        || {
            err "Perintah hash.sh gagal. Output:"
            printf '%s\n' "$output" >&2
            die "Gagal membuat hash password Indexer."
        }

    hash="$(printf '%s\n' "$output" |
        grep -Eo '\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}' |
        tail -n 1 || true)"

    [[ -n "$hash" ]] || {
        err "Output hash.sh tidak berisi hash bcrypt yang valid:"
        printf '%s\n' "$output" >&2
        die "Hash bcrypt tidak ditemukan."
    }

    printf '%s' "$hash"
}

secure_indexer_internal_users() {
    local users_file="${WAZUH_CONFIG}/wazuh_indexer/internal_users.yml"
    [[ -f "$users_file" ]] || die "File internal_users.yml tidak ditemukan."
    log "Menyiapkan hash password unik untuk akun internal Indexer..."

    local admin_hash kibanaserver_hash kibanaro_hash logstash_hash readall_hash snapshotrestore_hash
    admin_hash="$(generate_indexer_hash "$WAZUH_INDEXER_ADMIN_PASSWORD")"
    kibanaserver_hash="$(generate_indexer_hash "$WAZUH_INDEXER_KIBANASERVER_PASSWORD")"
    kibanaro_hash="$(generate_indexer_hash "$WAZUH_INDEXER_KIBANARO_PASSWORD")"
    logstash_hash="$(generate_indexer_hash "$WAZUH_INDEXER_LOGSTASH_PASSWORD")"
    readall_hash="$(generate_indexer_hash "$WAZUH_INDEXER_READALL_PASSWORD")"
    snapshotrestore_hash="$(generate_indexer_hash "$WAZUH_INDEXER_SNAPSHOTRESTORE_PASSWORD")"

    ADMIN_HASH="$admin_hash" \
    KIBANASERVER_HASH="$kibanaserver_hash" \
    KIBANARO_HASH="$kibanaro_hash" \
    LOGSTASH_HASH="$logstash_hash" \
    READALL_HASH="$readall_hash" \
    SNAPSHOTRESTORE_HASH="$snapshotrestore_hash" \
    python3 - "$users_file" <<'PY'
import os, re, sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
hashes = {
    "admin": os.environ["ADMIN_HASH"],
    "kibanaserver": os.environ["KIBANASERVER_HASH"],
    "kibanaro": os.environ["KIBANARO_HASH"],
    "logstash": os.environ["LOGSTASH_HASH"],
    "readall": os.environ["READALL_HASH"],
    "snapshotrestore": os.environ["SNAPSHOTRESTORE_HASH"],
}
for username, value in hashes.items():
    pattern = re.compile(
        rf"(?ms)^({re.escape(username)}:\s*\n)(.*?)(?=^[A-Za-z0-9_-]+:\s*$|\Z)"
    )
    match = pattern.search(text)
    if not match:
        raise SystemExit(f"User {username} tidak ditemukan di {path}")
    block = match.group(2)
    block2, count = re.subn(
        r'(?m)^(\s*hash:\s*)["\']?[^"\']+["\']?\s*$',
        lambda m: m.group(1) + '"' + value + '"',
        block,
        count=1,
    )
    if count != 1:
        raise SystemExit(f"Field hash untuk {username} tidak ditemukan")
    text = text[:match.start(2)] + block2 + text[match.end(2):]

path.write_text(text, encoding="utf-8")
PY

    # The Wazuh Dashboard uses the wazuh-wui API account. Keep its password
    # synchronized with the Manager's API_PASSWORD environment variable.
    local dashboard_config="${WAZUH_CONFIG}/wazuh_dashboard/wazuh.yml"
    [[ -f "$dashboard_config" ]] || die "File konfigurasi dashboard wazuh.yml tidak ditemukan."
    API_PASSWORD_VALUE="$WAZUH_API_PASSWORD" python3 - "$dashboard_config" <<'PY'
import os, sys
from pathlib import Path
p = Path(sys.argv[1])
text = p.read_text(encoding="utf-8")
old = "MyS3cr37P450r.*-"
new = os.environ["API_PASSWORD_VALUE"]
if old in text:
    text = text.replace(old, new)
elif new not in text:
    # Preserve custom user configuration; the administrator must ensure that
    # the configured wazuh-wui password matches the Compose environment.
    raise SystemExit("Default API password marker not found; refusing to guess the custom wazuh-wui password.")
p.write_text(text, encoding="utf-8")
PY
    ok "Hash akun Indexer dan password integrasi Dashboard disiapkan."
}

generate_split_compose_files() {
    local source_compose="${WAZUH_SOURCE}/single-node/docker-compose.yml"
    log "Membuat tiga file Docker Compose dari konfigurasi upstream Wazuh..."

    WAZUH_CONFIG_DIR="$WAZUH_CONFIG" \
    MANAGER_DIR="${WAZUH_ROOT}/manager" \
    INDEXER_DIR="${WAZUH_ROOT}/indexer" \
    DASHBOARD_DIR="${WAZUH_ROOT}/dashboard" \
    python3 - "$source_compose" <<'PY'
import copy, os, sys
from pathlib import Path
import yaml

source = Path(sys.argv[1])
doc = yaml.safe_load(source.read_text(encoding="utf-8"))
services = doc.get("services", {})
config_dir = os.environ["WAZUH_CONFIG_DIR"]

targets = {
    "manager": ("wazuh.manager", Path(os.environ["MANAGER_DIR"]), "defenseops-manager"),
    "indexer": ("wazuh.indexer", Path(os.environ["INDEXER_DIR"]), "defenseops-indexer"),
    "dashboard": ("wazuh.dashboard", Path(os.environ["DASHBOARD_DIR"]), "defenseops-dashboard"),
}

for component, (service_name, out_dir, project) in targets.items():
    if service_name not in services:
        raise SystemExit(f"Service {service_name} tidak ditemukan dalam {source}")
    service = copy.deepcopy(services[service_name])
    service.pop("depends_on", None)
    service.pop("links", None)

    # All three Compose projects attach to the same external bridge network.
    # Service aliases preserve upstream DNS names for inter-component TLS URLs.
    service["networks"] = {
        "defenseops-wazuh": {"aliases": [service_name]}
    }
    service["labels"] = {
        **service.get("labels", {}),
        "com.defenseops.managed": "true",
        "com.defenseops.component": f"wazuh-{component}",
    }

    # Resolve upstream relative config bind mounts to one shared absolute path.
    transformed_volumes = []
    for item in service.get("volumes", []):
        if isinstance(item, str) and item.startswith("./config/"):
            item = "${WAZUH_CONFIG_DIR}/" + item[len("./config/"):]
        transformed_volumes.append(item)
    if "volumes" in service:
        service["volumes"] = transformed_volumes

    # Keep Indexer API and Manager API private to the host. Dashboard and
    # agent-facing ports remain published as defined upstream.
    if component in ("indexer", "manager", "dashboard"):
        new_ports = []
        for port in service.get("ports", []):
            value = str(port)
            if component == "indexer" and value == "9200:9200":
                value = "127.0.0.1:9200:9200"
            if component == "manager" and value == "55000:55000":
                value = "127.0.0.1:55000:55000"
            if component == "dashboard" and value == "443:5601":
                value = "${WAZUH_DASHBOARD_PORT:-8443}:5601"
            new_ports.append(value)
        if "ports" in service:
            service["ports"] = new_ports

    # Compose interpolation reads component-specific .env files.
    env_map = {
        "manager": {
            "INDEXER_PASSWORD": "${INDEXER_PASSWORD}",
            "API_PASSWORD": "${WAZUH_API_PASSWORD}",
        },
        "dashboard": {
            "INDEXER_PASSWORD": "${INDEXER_PASSWORD}",
            "DASHBOARD_PASSWORD": "${DASHBOARD_PASSWORD}",
            "API_PASSWORD": "${WAZUH_API_PASSWORD}",
        },
        "indexer": {},
    }[component]
    env = service.get("environment", [])
    if isinstance(env, list):
        rewritten = []
        for entry in env:
            if isinstance(entry, str) and "=" in entry:
                key, _ = entry.split("=", 1)
                if key in env_map:
                    entry = f"{key}={env_map[key]}"
            rewritten.append(entry)
        service["environment"] = rewritten
    elif isinstance(env, dict):
        for key, value in env_map.items():
            if key in env:
                env[key] = value
        service["environment"] = env

    # Include only the named volumes referenced by this service, with stable
    # names independent of the Compose project name.
    used_volumes = {}
    for item in service.get("volumes", []):
        if isinstance(item, str):
            src = item.split(":", 1)[0]
            if src in doc.get("volumes", {}):
                used_volumes[src] = {"name": f"defenseops-{component}-{src}"}
        elif isinstance(item, dict):
            src = item.get("source")
            if src in doc.get("volumes", {}):
                used_volumes[src] = {"name": f"defenseops-{component}-{src}"}

    compose = {
        "services": {service_name: service},
        "networks": {
            "defenseops-wazuh": {
                "external": True,
                "name": "defenseops-wazuh",
            }
        },
    }
    if used_volumes:
        compose["volumes"] = used_volumes

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "docker-compose.yml"
    if out_file.exists():
        print(f"Preserving existing Compose file: {out_file}")
    else:
        out_file.write_text(
            "# Generated by DefenseOps from the official Wazuh Docker release.\n"
            "# Review upstream license and changes before modifying.\n"
            + yaml.safe_dump(compose, sort_keys=False, default_flow_style=False),
            encoding="utf-8",
        )
        print(f"Created {out_file}")
PY

    # Per-project Compose interpolation files. Passwords contain only hex and
    # a short suffix, so no dotenv escaping is required.
    cat > "${WAZUH_ROOT}/manager/.env" <<ENV
WAZUH_CONFIG_DIR=${WAZUH_CONFIG}
INDEXER_PASSWORD=${WAZUH_INDEXER_ADMIN_PASSWORD}
WAZUH_API_PASSWORD=${WAZUH_API_PASSWORD}
ENV
    cat > "${WAZUH_ROOT}/indexer/.env" <<ENV
WAZUH_CONFIG_DIR=${WAZUH_CONFIG}
ENV
    cat > "${WAZUH_ROOT}/dashboard/.env" <<ENV
WAZUH_CONFIG_DIR=${WAZUH_CONFIG}
INDEXER_PASSWORD=${WAZUH_INDEXER_ADMIN_PASSWORD}
DASHBOARD_PASSWORD=${WAZUH_INDEXER_KIBANASERVER_PASSWORD}
WAZUH_API_PASSWORD=${WAZUH_API_PASSWORD}
WAZUH_DASHBOARD_PORT=8443
ENV
    chmod 0600 "${WAZUH_ROOT}/manager/.env" "${WAZUH_ROOT}/indexer/.env" "${WAZUH_ROOT}/dashboard/.env"

    ok "Compose Manager, Indexer, dan Dashboard dibuat terpisah."
}

validate_compose_files() {
    log "Memvalidasi konfigurasi Docker Compose..."
    docker compose --project-name defenseops-indexer \
        --env-file "${WAZUH_ROOT}/indexer/.env" \
        -f "${WAZUH_ROOT}/indexer/docker-compose.yml" config -q
    docker compose --project-name defenseops-manager \
        --env-file "${WAZUH_ROOT}/manager/.env" \
        -f "${WAZUH_ROOT}/manager/docker-compose.yml" config -q
    docker compose --project-name defenseops-dashboard \
        --env-file "${WAZUH_ROOT}/dashboard/.env" \
        -f "${WAZUH_ROOT}/dashboard/docker-compose.yml" config -q
    ok "Ketiga file Compose valid."
}

compose_up() {
    local component="$1" project="defenseops-${1}"
    docker compose --project-name "$project" \
        --env-file "${WAZUH_ROOT}/${component}/.env" \
        -f "${WAZUH_ROOT}/${component}/docker-compose.yml" up -d
}

wait_for_indexer() {
    log "Menunggu Wazuh Indexer siap (maksimal 5 menit)..."
    local attempt
    for attempt in $(seq 1 60); do
        if curl -kfsS --connect-timeout 3 --max-time 8 \
            -u "admin:${WAZUH_INDEXER_ADMIN_PASSWORD}" \
            https://127.0.0.1:9200/_cluster/health >/dev/null 2>&1; then
            ok "Wazuh Indexer merespons."
            return
        fi
        sleep 5
    done
    docker compose --project-name defenseops-indexer \
        --env-file "${WAZUH_ROOT}/indexer/.env" \
        -f "${WAZUH_ROOT}/indexer/docker-compose.yml" logs --tail=100 || true
    die "Wazuh Indexer belum siap. Periksa log di atas."
}

wait_for_manager() {
    log "Menunggu Wazuh Manager API siap (maksimal 5 menit)..."
    local attempt
    for attempt in $(seq 1 60); do
        local status
        status="$(curl -k -sS --connect-timeout 3 --max-time 8 \
            -o /dev/null -w '%{http_code}' \
            -u "wazuh-wui:${WAZUH_API_PASSWORD}" \
            -X POST https://127.0.0.1:55000/security/user/authenticate?raw=true 2>/dev/null || true)"
        if [[ "$status" == "200" ]]; then
            ok "Wazuh Manager API merespons."
            return
        fi
        sleep 5
    done
    docker compose --project-name defenseops-manager \
        --env-file "${WAZUH_ROOT}/manager/.env" \
        -f "${WAZUH_ROOT}/manager/docker-compose.yml" logs --tail=100 || true
    die "Wazuh Manager API belum siap. Periksa log di atas."
}

wait_for_dashboard() {
    log "Menunggu Wazuh Dashboard siap (maksimal 5 menit)..."
    local attempt
    for attempt in $(seq 1 60); do
        if curl -kfsS --connect-timeout 3 --max-time 8 \
            https://127.0.0.1:8443/app/login >/dev/null 2>&1; then
            ok "Wazuh Dashboard merespons."
            return
        fi
        sleep 5
    done
    docker compose --project-name defenseops-dashboard \
        --env-file "${WAZUH_ROOT}/dashboard/.env" \
        -f "${WAZUH_ROOT}/dashboard/docker-compose.yml" logs --tail=100 || true
    die "Wazuh Dashboard belum siap. Periksa log di atas."
}

rotate_wazuh_api_admin_password() {
    log "Mengamankan akun administrator Wazuh API..."
    local api_url="https://127.0.0.1:55000"
    local token="" users_json="" user_id="" payload="" status=""

    # First try the already-rotated password (idempotent reruns). If it fails,
    # try the upstream Docker default once, then replace it immediately.
    token="$(printf 'user = "wazuh:%s"\n' "$WAZUH_API_ADMIN_PASSWORD" | \
        curl -ksS --connect-timeout 5 --max-time 15 -K - \
        -X POST "${api_url}/security/user/authenticate?raw=true" 2>/dev/null || true)"

    if [[ -n "$token" ]]; then
        ok "Password administrator API sudah menggunakan kredensial DefenseOps."
        return
    fi

    token="$(printf 'user = "wazuh:wazuh"\n' | \
        curl -ksS --connect-timeout 5 --max-time 15 -K - \
        -X POST "${api_url}/security/user/authenticate?raw=true" 2>/dev/null || true)"
    [[ -n "$token" ]] || die "Tidak dapat mengautentikasi akun administrator API untuk rotasi password."

    users_json="$(curl -ksS --connect-timeout 5 --max-time 15 \
        -H "Authorization: Bearer ${token}" \
        "${api_url}/security/users?pretty=true")" || die "Gagal membaca daftar user Wazuh API."
    user_id="$(printf '%s' "$users_json" | jq -r '.data.affected_items[]? | select(.username == "wazuh") | .id' | head -n 1)"
    [[ "$user_id" =~ ^[0-9]+$ ]] || die "ID akun administrator API 'wazuh' tidak ditemukan."

    payload="$(jq -n --arg password "$WAZUH_API_ADMIN_PASSWORD" '{password: $password}')"
    status="$(printf '%s' "$payload" | curl -ksS --connect-timeout 5 --max-time 15 \
        -o /tmp/defenseops-wazuh-api-password-rotation.json \
        -w '%{http_code}' \
        -H "Authorization: Bearer ${token}" \
        -H 'Content-Type: application/json' \
        --data-binary @- \
        -X PUT "${api_url}/security/users/${user_id}")"
    [[ "$status" == "200" ]] || {
        cat /tmp/defenseops-wazuh-api-password-rotation.json >&2 || true
        rm -f /tmp/defenseops-wazuh-api-password-rotation.json
        die "Rotasi password administrator API gagal (HTTP ${status})."
    }
    rm -f /tmp/defenseops-wazuh-api-password-rotation.json

    token="$(printf 'user = "wazuh:%s"\n' "$WAZUH_API_ADMIN_PASSWORD" | \
        curl -ksS --connect-timeout 5 --max-time 15 -K - \
        -X POST "${api_url}/security/user/authenticate?raw=true" 2>/dev/null || true)"
    [[ -n "$token" ]] || die "Verifikasi password administrator API baru gagal."
    ok "Password default wazuh:wazuh berhasil dirotasi."
}

deploy_wazuh() {
    log "Menyiapkan deployment Wazuh ${WAZUH_VERSION}..."
    create_docker_network
    prepare_wazuh_source
    seed_wazuh_configuration

    log "Mengambil image Wazuh Indexer untuk membuat password hash..."
    docker pull "wazuh/wazuh-indexer:${WAZUH_VERSION}"

    load_or_create_credentials
    secure_indexer_internal_users
    prepare_wazuh_config_permissions
    generate_split_compose_files
    validate_compose_files

    log "Menjalankan Wazuh Indexer..."
    compose_up indexer
    wait_for_indexer

    log "Menjalankan Wazuh Manager..."
    compose_up manager
    wait_for_manager
    rotate_wazuh_api_admin_password

    log "Menjalankan Wazuh Dashboard..."
    compose_up dashboard
    wait_for_dashboard
}

verify_final_state() {
    log "Memverifikasi deployment akhir..."
    systemctl is-active --quiet docker || die "Docker service tidak aktif."
    docker compose --project-name defenseops-indexer \
        --env-file "${WAZUH_ROOT}/indexer/.env" \
        -f "${WAZUH_ROOT}/indexer/docker-compose.yml" ps
    docker compose --project-name defenseops-manager \
        --env-file "${WAZUH_ROOT}/manager/.env" \
        -f "${WAZUH_ROOT}/manager/docker-compose.yml" ps
    docker compose --project-name defenseops-dashboard \
        --env-file "${WAZUH_ROOT}/dashboard/.env" \
        -f "${WAZUH_ROOT}/dashboard/docker-compose.yml" ps
    ok "Deployment Wazuh selesai."
}

main() {
    log "===== DefenseOps Full Requirements & Wazuh Installer ====="
    check_system_requirements

    if (( DRY_RUN )); then
        echo
        log "DRY-RUN: tidak ada perubahan yang diterapkan."
        log "Rencana: repository Ubuntu -> dependencies -> Docker/Compose -> sysctl ->"
        log "direktori/network -> source Wazuh ${WAZUH_VERSION} -> TLS/passwords ->"
        log "3 Compose projects -> deploy Indexer, Manager, Dashboard -> health checks."
        exit 0
    fi

    configure_ubuntu_repositories
    install_base_packages
    install_docker
    configure_docker_defaults
    configure_kernel
    create_directories
    deploy_wazuh
    verify_final_state

    echo
    ok "DefenseOps host dan Wazuh single-node berhasil dipersiapkan."
    log "Dashboard URL : https://<IP-ADDRESS-SERVER>:8443/"
    log "Dashboard user: admin"
    log "Credentials   : ${CREDENTIALS_FILE}"
    log "Compose files :"
    log "  ${WAZUH_ROOT}/indexer/docker-compose.yml"
    log "  ${WAZUH_ROOT}/manager/docker-compose.yml"
    log "  ${WAZUH_ROOT}/dashboard/docker-compose.yml"
    log "Shared network: ${WAZUH_NETWORK}"
    warn "Sertifikat yang dibuat adalah self-signed. Browser akan menampilkan peringatan TLS."
    warn "Port 9200 (Indexer API) dan 55000 (Manager API) hanya dipublikasikan ke loopback."
    warn "Port 8443 (Dashboard), 1514/1515 TCP (Agent), dan 514 UDP (Syslog) perlu aturan firewall sesuai kebutuhan."
}

main "$@"
