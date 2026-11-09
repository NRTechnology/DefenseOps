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
readonly DEFENSEOPS_HOSTNAME="defenseops"
readonly MIN_CPU_CORES=4
readonly MIN_RAM_GIB=8
readonly MIN_STORAGE_GIB=250
readonly RAW_LOG_RETENTION_DAYS=30
readonly ALERT_RETENTION_DAYS=90
readonly MANAGER_ARCHIVE_RETENTION_DAYS=14
readonly WAZUH_ARCHIVE_INDEX_PATTERN="wazuh-archives-4.x-*"
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
REPAIR_ARCHIVES_ONLY=0

# Populated by finalize_manager_and_verify_archives() and displayed in summary.
SUMMARY_GROUP_BREBES_WAF="NOT VERIFIED"
SUMMARY_GROUP_DOCKER_PHP="NOT VERIFIED"
SUMMARY_FILEBEAT_ALERTS="NOT VERIFIED"
SUMMARY_FILEBEAT_ARCHIVES="NOT VERIFIED"
SUMMARY_ARCHIVES_HARVESTER="NOT VERIFIED"
SUMMARY_ARCHIVES_PIPELINE="NOT VERIFIED"
SUMMARY_ARCHIVES_INDEX="$WAZUH_ARCHIVE_INDEX_PATTERN"
SUMMARY_ARCHIVES_INDEX_HEALTH="NOT VERIFIED"

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
  --repair-archives-only  Repair persistent Filebeat archives config only; do not redeploy Wazuh.
  -h, --help      Show this help.

Environment:
  DEFENSEOPS_ROOT  Installation root (default: /opt/defenseops)
  WAZUH_VERSION    Wazuh Docker release (default: ${WAZUH_VERSION})
  LOG_FILE         Log file (default: /var/log/defenseops-install-requirements.log)

Example:
  sudo ./$SCRIPT_NAME --dry-run
  sudo ./$SCRIPT_NAME --repair-archives-only
  sudo ./$SCRIPT_NAME
USAGE
}

while (($#)); do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --repair-archives-only) REPAIR_ARCHIVES_ONLY=1 ;;
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


configure_host_hostname() {
    log "Mengatur hostname host menjadi ${DEFENSEOPS_HOSTNAME}..."

    if command -v hostnamectl >/dev/null 2>&1; then
        hostnamectl set-hostname "$DEFENSEOPS_HOSTNAME"
    else
        printf '%s\n' "$DEFENSEOPS_HOSTNAME" > /etc/hostname
        hostname "$DEFENSEOPS_HOSTNAME"
    fi

    # Preserve existing hosts entries; only normalize the 127.0.1.1 mapping.
    local hosts_tmp
    hosts_tmp="$(mktemp)"
    if [[ -f /etc/hosts ]]; then
        awk -v host="$DEFENSEOPS_HOSTNAME" '
            /^[[:space:]]*127\.0\.1\.1[[:space:]]/ {
                if (!done) {
                    print "127.0.1.1\t" host
                    done=1
                }
                next
            }
            { print }
            END {
                if (!done) print "127.0.1.1\t" host
            }
        ' /etc/hosts > "$hosts_tmp"
    else
        printf '127.0.0.1\tlocalhost\n127.0.1.1\t%s\n' "$DEFENSEOPS_HOSTNAME" > "$hosts_tmp"
    fi
    install -m 0644 "$hosts_tmp" /etc/hosts
    rm -f "$hosts_tmp"

    [[ "$(hostname)" == "$DEFENSEOPS_HOSTNAME" ]] || die "Gagal mengatur hostname menjadi ${DEFENSEOPS_HOSTNAME}."
    ok "Hostname host: $(hostname)."
}


configure_time_and_timezone() {
    log "Memastikan sinkronisasi waktu/NTP aktif..."
    if command -v timedatectl >/dev/null 2>&1; then
        timedatectl set-ntp true || warn "timedatectl tidak dapat mengaktifkan NTP; akan memeriksa chrony."
    fi

    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files chrony.service >/dev/null 2>&1; then
        systemctl enable --now chrony.service || warn "Layanan chrony gagal diaktifkan."
    elif command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files systemd-timesyncd.service >/dev/null 2>&1; then
        systemctl enable --now systemd-timesyncd.service || warn "systemd-timesyncd gagal diaktifkan."
    fi

    local ntp_state sync_state
    ntp_state="$(timedatectl show -p NTP --value 2>/dev/null || true)"
    sync_state="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
    if [[ "$ntp_state" == "yes" ]]; then
        ok "NTP aktif (timedatectl NTP=yes; synchronized=${sync_state:-unknown})."
    elif command -v chronyc >/dev/null 2>&1 && chronyc tracking >/dev/null 2>&1; then
        ok "Chrony aktif; status sinkronisasi dapat diperiksa dengan: chronyc tracking."
    else
        warn "Status NTP belum dapat dipastikan. Periksa timedatectl status dan chronyc tracking."
    fi

    local current_tz answer
    current_tz="$(timedatectl show -p Timezone --value 2>/dev/null || date +%Z)"
    printf '\\nZona waktu saat ini: %s\\n' "$current_tz"
    read -r -p "Pindahkan timezone ke Asia/Jakarta (WIB)? [y/N]: " answer </dev/tty || answer=""
    case "${answer,,}" in
        y|yes|ya)
            timedatectl set-timezone Asia/Jakarta
            [[ "$(timedatectl show -p Timezone --value)" == "Asia/Jakarta" ]] || die "Gagal mengatur timezone Asia/Jakarta."
            ok "Timezone diatur ke Asia/Jakarta."
            ;;
        *)
            ok "Timezone dipertahankan: ${current_tz}."
            ;;
    esac
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
    systemctl enable --now chrony.service || warn "Chrony belum berhasil diaktifkan; verifikasi NTP secara manual."
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
    local indexer_source_config="${WAZUH_SOURCE}/build-docker-images/wazuh-indexer/config"
    local indexer_opensearch_source="${indexer_source_config}/opensearch.yml"
    local target_opensearch="${WAZUH_CONFIG}/wazuh_indexer/opensearch.yml"

    [[ -d "$upstream_config" ]] || die "Direktori konfigurasi upstream tidak ditemukan: ${upstream_config}"

    # Seed missing files individually. Never overwrite an existing administrator
    # configuration just because one other file is missing.
    install -d -m 0750 "$WAZUH_CONFIG"
    log "Memastikan seluruh konfigurasi dasar Wazuh tersedia..."
    cp -a --update=none "${upstream_config}/." "${WAZUH_CONFIG}/"

    # In the official Wazuh Docker release, opensearch.yml is sourced from the
    # Indexer image build configuration, not necessarily from single-node/config.
    # The split Indexer Compose file bind-mounts it from shared/config/wazuh_indexer.
    if [[ ! -s "$target_opensearch" ]]; then
        if [[ -s "$indexer_opensearch_source" ]]; then
            install -d -m 0750 "${WAZUH_CONFIG}/wazuh_indexer"
            install -m 0640 "$indexer_opensearch_source" "$target_opensearch"
            log "opensearch.yml disalin dari konfigurasi Indexer resmi: ${indexer_opensearch_source}"
        else
            die "opensearch.yml tidak ditemukan di konfigurasi runtime maupun source resmi: ${indexer_opensearch_source}"
        fi
    else
        log "opensearch.yml yang sudah ada dipertahankan."
    fi

    # Validate the required Indexer configuration before changing permissions
    # or generating Compose files. This catches incomplete seeds early.
    local required_file
    for required_file in \
        "${WAZUH_CONFIG}/wazuh_indexer/opensearch.yml" \
        "${WAZUH_CONFIG}/wazuh_indexer/wazuh.indexer.yml" \
        "${WAZUH_CONFIG}/wazuh_indexer/internal_users.yml"; do
        [[ -s "$required_file" ]] || die "Konfigurasi wajib Wazuh tidak ditemukan atau kosong: ${required_file}"
    done

    if [[ ! -s "${target_cert_dir}/root-ca.pem" ]]; then
        log "Membuat sertifikat TLS self-signed menggunakan certificate generator resmi Wazuh..."
        build_certificate_generator_image
        (
            cd "${WAZUH_SOURCE}/single-node"
            docker compose -f generate-indexer-certs.yml run --rm --pull never generator
        )
        install -d -m 0750 "$target_cert_dir"
        if [[ -d "$upstream_cert_dir" ]]; then
            cp -a --update=none "${upstream_cert_dir}/." "${target_cert_dir}/"
        fi
    else
        log "Sertifikat Wazuh yang sudah ada dipertahankan; memeriksa permission dan ownership."
    fi

    repair_wazuh_certificate_permissions
    ok "Konfigurasi dasar, opensearch.yml, dan sertifikat Wazuh tersedia."
}

configure_raw_log_collection() {
    local manager_conf="${WAZUH_CONFIG}/wazuh_cluster/wazuh_manager.conf"
    [[ -s "$manager_conf" ]] || die "Konfigurasi Manager tidak ditemukan: ${manager_conf}"

    log "Mengaktifkan JSON raw event logging pada Wazuh Manager..."
    MANAGER_CONF="$manager_conf" python3 <<'PYCONF'
import os, re
from pathlib import Path
p = Path(os.environ["MANAGER_CONF"])
s = p.read_text(encoding="utf-8")
pattern = re.compile(r"(?ms)(<global>)(.*?)(</global>)")
m = pattern.search(s)
if not m:
    raise SystemExit(f"Blok <global> tidak ditemukan dalam {p}")
block = m.group(2)
for key, value in (("logall", "no"), ("logall_json", "yes")):
    rx = re.compile(rf"(?m)^(\s*<{key}>)[^<]*(</{key}>\s*)$")
    if rx.search(block):
        block = rx.sub(rf"\g<1>{value}\g<2>", block, count=1)
    else:
        block += f"\n    <{key}>{value}</{key}>"
s = s[:m.start(2)] + block + s[m.end(2):]
p.write_text(s, encoding="utf-8")
PYCONF
    ok "Raw event JSON logging aktif; plaintext logall tetap nonaktif."
}

configure_indexer_retention_policies() {
    log "Menerapkan Index State Management retention policies..."
    local base_url="https://127.0.0.1:9200" response status
    local raw_policy alert_policy

    raw_policy="$(jq -n --arg age "${RAW_LOG_RETENTION_DAYS}d" '{policy:{description:"DefenseOps raw event retention",default_state:"active",states:[{name:"active",actions:[],transitions:[{state_name:"delete",conditions:{min_index_age:$age}}]},{name:"delete",actions:[{retry:{count:3,backoff:"exponential",delay:"1m"},delete:{}}],transitions:[]}],ism_template:[{index_patterns:["wazuh-archives-4.x-*"],priority:100}]}}')"
    alert_policy="$(jq -n --arg age "${ALERT_RETENTION_DAYS}d" '{policy:{description:"DefenseOps security alert retention",default_state:"active",states:[{name:"active",actions:[],transitions:[{state_name:"delete",conditions:{min_index_age:$age}}]},{name:"delete",actions:[{retry:{count:3,backoff:"exponential",delay:"1m"},delete:{}}],transitions:[]}],ism_template:[{index_patterns:["wazuh-alerts-4.x-*"],priority:100}]}}')"

    local policy_id existing seq_no primary_term endpoint
    for policy_id in defenseops-raw-retention defenseops-alert-retention; do
        if [[ "$policy_id" == "defenseops-raw-retention" ]]; then
            endpoint="${base_url}/_plugins/_ism/policies/${policy_id}"
            response="$raw_policy"
        else
            endpoint="${base_url}/_plugins/_ism/policies/${policy_id}"
            response="$alert_policy"
        fi
        existing="$(curl -ksS --connect-timeout 5 --max-time 15 \
            -u "${WAZUH_DASHBOARD_USERNAME}:${WAZUH_DASHBOARD_PASSWORD}" -w '\n%{http_code}' "$endpoint" || true)"
        status="${existing##*$'\n'}"
        if [[ "$status" == "200" ]]; then
            existing="${existing%$'\n'*}"
            seq_no="$(printf '%s' "$existing" | jq -r '._seq_no // empty')"
            primary_term="$(printf '%s' "$existing" | jq -r '._primary_term // empty')"
            [[ "$seq_no" =~ ^[0-9]+$ && "$primary_term" =~ ^[0-9]+$ ]] || die "Metadata policy ${policy_id} tidak valid; menolak overwrite tanpa concurrency control."
            endpoint="${endpoint}?if_seq_no=${seq_no}&if_primary_term=${primary_term}"
        elif [[ "$status" != "404" ]]; then
            die "Gagal membaca policy ${policy_id} (HTTP ${status})."
        fi
        status="$(printf '%s' "$response" | curl -ksS --connect-timeout 5 --max-time 30 \
            -o "/tmp/${policy_id}.json" -w '%{http_code}' \
            -u "${WAZUH_DASHBOARD_USERNAME}:${WAZUH_DASHBOARD_PASSWORD}" -H 'Content-Type: application/json' \
            --data-binary @- -X PUT "$endpoint")" \
            || die "Gagal mengirim policy ${policy_id} ke Wazuh Indexer."
        [[ "$status" =~ ^(200|201)$ ]] || { cat "/tmp/${policy_id}.json" >&2 || true; die "Penerapan policy ${policy_id} gagal (HTTP ${status})."; }
        rm -f "/tmp/${policy_id}.json"
    done

    rm -f /tmp/defenseops-ism-raw.json /tmp/defenseops-ism-alerts.json
    ok "ISM policies aktif: raw ${RAW_LOG_RETENTION_DAYS} hari, alerts ${ALERT_RETENTION_DAYS} hari."
}

configure_filebeat_archives() {
    log "Memastikan Filebeat archives aktif pada volume persisten host..."
    local container_id mount_info volume_name volume_mount config_file changed
    container_id="$(docker ps -q --filter 'label=com.defenseops.component=wazuh-manager' | head -n 1)"
    [[ -n "$container_id" ]] || die "Container Wazuh Manager tidak ditemukan."

    # Resolve the actual host-side mount backing /etc/filebeat. Do not rely on
    # edits made only in the container writable layer.
    mount_info="$(docker inspect "$container_id" --format '{{range .Mounts}}{{if eq .Destination "/etc/filebeat"}}{{.Name}}|{{.Source}}{{end}}{{end}}')"
    [[ -n "$mount_info" && "$mount_info" == *'|'* ]] || die "Mount /etc/filebeat tidak ditemukan pada container Manager."
    volume_name="${mount_info%%|*}"
    if [[ -n "$volume_name" ]]; then
        volume_mount="$(docker volume inspect -f '{{.Mountpoint}}' "$volume_name")" \
            || die "Gagal mendapatkan mountpoint Docker volume ${volume_name}."
    else
        volume_mount="${mount_info#*|}"
    fi
    [[ -d "$volume_mount" ]] || die "Direktori volume Filebeat tidak ditemukan: ${volume_mount}"
    config_file="${volume_mount}/filebeat.yml"
    [[ -s "$config_file" && -f "$config_file" && ! -L "$config_file" ]] \
        || die "filebeat.yml persisten tidak ditemukan/valid: ${config_file}"

    log "Filebeat volume : ${volume_name:-bind-mount}"
    log "Host config     : ${config_file}"

    changed="$(FILEBEAT_CONFIG="$config_file" python3 - <<'PYFILEBEAT'
import os, re, shutil, tempfile
from datetime import datetime
from pathlib import Path

p = Path(os.environ["FILEBEAT_CONFIG"])
original = p.read_text(encoding="utf-8")
module = re.search(
    r"(?ms)^[ \t]*-[ \t]*module:[ \t]*wazuh[ \t]*\n.*?(?=^[ \t]*-[ \t]*module:|\Z)",
    original,
)
if not module:
    raise SystemExit("Wazuh Filebeat module tidak ditemukan; file tidak diubah.")
block = module.group(0)
archives = re.search(
    r"(?m)^([ \t]*archives:[ \t]*\n)([ \t]+enabled:[ \t]*)(true|false)([ \t]*)$",
    block,
)
if not archives:
    raise SystemExit("archives.enabled tidak ditemukan pada modul Wazuh; file tidak diubah.")
if archives.group(3) == "true":
    print("UNCHANGED")
    raise SystemExit(0)

updated_block = block[:archives.start(3)] + "true" + block[archives.end(3):]
updated = original[:module.start()] + updated_block + original[module.end():]
stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = p.with_name(p.name + ".defenseops-backup-" + stamp)
shutil.copy2(p, backup)
fd, tmp = tempfile.mkstemp(prefix=".filebeat.yml.", dir=str(p.parent))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(updated)
        f.flush()
        os.fsync(f.fileno())
    shutil.copystat(p, tmp)
    os.replace(tmp, p)
except Exception:
    try:
        Path(tmp).unlink()
    except FileNotFoundError:
        pass
    raise
print("CHANGED")
print(f"Backup: {backup}")
PYFILEBEAT
)" || die "Gagal memperbarui filebeat.yml pada volume persisten."

    # Confirm the container sees the persistent host-volume configuration.
    docker exec "$container_id" sh -c \
        'awk "/^[[:space:]]*archives:/ {in_archives=1; next} in_archives && /^[[:space:]]*enabled:[[:space:]]*true[[:space:]]*$/ {ok=1; exit} in_archives && /^[^[:space:]]/ {exit} END {exit !ok}" /etc/filebeat/filebeat.yml' \
        || die "Container tidak membaca archives.enabled=true dari volume persisten."

    # Validate configuration and output without signalling/restarting any
    # s6 service or restarting the Wazuh Manager container. In this Wazuh
    # image, s6-svc -r can initiate container shutdown rather than safely
    # restarting only Filebeat.
    docker exec "$container_id" filebeat test config -c /etc/filebeat/filebeat.yml -e \
        || die "Validasi konfigurasi Filebeat gagal."
    docker exec "$container_id" filebeat test output -c /etc/filebeat/filebeat.yml -e \
        || die "Filebeat tidak dapat terhubung ke Wazuh Indexer."

    if [[ "$changed" == CHANGED* ]]; then
        log "archives.enabled=true berhasil disimpan pada volume persisten."
        warn "Filebeat yang sedang berjalan belum dimuat ulang. Perubahan akan aktif setelah Manager container direstart pada maintenance window terencana."
    else
        log "archives.enabled sudah true; tidak ada perubahan konfigurasi atau restart dilakukan."
    fi

    ok "Filebeat archives.enabled=true tersimpan dan konfigurasi/output tervalidasi."
}
configure_effective_manager_archives() {
    log "Memastikan konfigurasi Archives pada ossec.conf aktif di volume Manager..."
    local container_id="" result=""
    container_id="$(docker ps -q --filter 'label=com.defenseops.component=wazuh-manager' | head -n 1)"
    [[ -n "$container_id" ]] || die "Container Wazuh Manager tidak ditemukan."

    result="$(docker exec "$container_id" python3 - <<'PYMANAGER'
import os, re, shutil, tempfile
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET
p = Path("/var/ossec/etc/ossec.conf")
if not p.is_file() or not p.stat().st_size: raise SystemExit("ossec.conf aktif tidak ditemukan/kosong.")
if p.is_symlink(): raise SystemExit("ossec.conf berupa symlink; menolak perubahan.")
original = p.read_text(encoding="utf-8")
gm = re.search(r"(?s)<global\b[^>]*>.*?</global\s*>", original)
if not gm: raise SystemExit("Blok global tidak ditemukan.")
block = gm.group(0)
for key, value in (("logall", "no"), ("logall_json", "yes")):
    rx = re.compile(rf"(?m)^([ \t]*<{key}>)[^<]*(</{key}>[ \t]*)$")
    matches = list(rx.finditer(block))
    if len(matches) > 1: raise SystemExit(f"Duplikasi <{key}> ditemukan.")
    if matches:
        block = rx.sub(lambda x: x.group(1) + value + x.group(2), block, count=1)
    else:
        block = block.replace("</global>", f"    <{key}>{value}</{key}>\n  </global>", 1)
updated = original[:gm.start()] + block + original[gm.end():]
try:
    ET.fromstring("<root>" + re.sub(r"^\s*<\?xml[^?]*\?>", "", updated, count=1) + "</root>")
except ET.ParseError as exc: raise SystemExit(f"XML hasil perubahan tidak valid: {exc}")
if updated == original:
    print("UNCHANGED")
    raise SystemExit(0)
stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = p.with_name(p.name + ".defenseops-backup-" + stamp)
shutil.copy2(p, backup)
fd, tmp = tempfile.mkstemp(prefix=".ossec.conf.", dir=str(p.parent))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(updated); f.flush(); os.fsync(f.fileno())
    shutil.copystat(p, tmp)
    os.replace(tmp, p)
except Exception:
    try: Path(tmp).unlink()
    except FileNotFoundError: pass
    raise
print("CHANGED")
print(f"Backup: {backup}")
PYMANAGER
)" || die "Gagal memperbarui ossec.conf aktif."

    if ! docker exec "$container_id" /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
        local backup_in_container=""
        backup_in_container="$(docker exec "$container_id" sh -c 'ls -1t /var/ossec/etc/ossec.conf.defenseops-backup-* 2>/dev/null | head -n 1' || true)"
        if [[ -n "$backup_in_container" ]]; then
            docker exec "$container_id" cp -a "$backup_in_container" /var/ossec/etc/ossec.conf
        fi
        die "Validasi konfigurasi Wazuh gagal; konfigurasi sebelumnya dipulihkan jika backup tersedia."
    fi

    if [[ "$result" == CHANGED* ]]; then
        log "Konfigurasi aktif berubah dan tervalidasi; restart Manager diperlukan."
        docker restart "$container_id" >/dev/null
        wait_for_manager
    else
        log "Konfigurasi aktif sudah sesuai; restart Manager tidak diperlukan."
    fi

    docker exec "$container_id" python3 - <<'PYVERIFY'
import re
from pathlib import Path
s = Path("/var/ossec/etc/ossec.conf").read_text(encoding="utf-8")
m = re.search(r"(?s)<global\b[^>]*>(.*?)</global\s*>", s)
if not m: raise SystemExit("Blok global tidak ditemukan.")
for key, expected in (("logall", "no"), ("logall_json", "yes")):
    vals = re.findall(rf"<{key}>\s*(.*?)\s*</{key}>", m.group(1))
    if vals != [expected]: raise SystemExit(f"{key}: expected exactly {expected}, found {vals}")
PYVERIFY
    ok "Manager aktif: logall=no dan logall_json=yes."
}


install_manager_archive_retention() {
    local script="/usr/local/sbin/defenseops-manager-archive-retention"
    local service="/etc/systemd/system/defenseops-manager-archive-retention.service"
    local timer="/etc/systemd/system/defenseops-manager-archive-retention.timer"

    log "Menyiapkan cleanup arsip lokal Manager (${MANAGER_ARCHIVE_RETENTION_DAYS} hari)..."
    cat > "$script" <<'RETENTION_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
RETENTION_DAYS=14
LOG_FILE=/var/log/defenseops-manager-archive-retention.log
exec >> "$LOG_FILE" 2>&1
printf '[%s] Starting Manager archives cleanup (older than %s days)\n' "$(date -Is)" "$RETENTION_DAYS"
container_id="$(docker ps -q --filter 'label=com.defenseops.component=wazuh-manager' | head -n 1)"
if [[ -z "$container_id" ]]; then
    echo 'Wazuh Manager container is not running; cleanup skipped.'
    exit 0
fi
# Delete only rotated/compressed archive files; never touch active JSON/log files.
docker exec "$container_id" find /var/ossec/logs/archives -type f -name '*.gz' -mtime "+${RETENTION_DAYS}" -print -delete
printf '[%s] Cleanup completed\n' "$(date -Is)"
RETENTION_SCRIPT
    sed -i "s/^RETENTION_DAYS=14$/RETENTION_DAYS=${MANAGER_ARCHIVE_RETENTION_DAYS}/" "$script"
    chmod 0750 "$script"

    cat > "$service" <<'SERVICE'
[Unit]
Description=DefenseOps Wazuh Manager local archives retention cleanup
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/defenseops-manager-archive-retention
SERVICE
    cat > "$timer" <<'TIMER'
[Unit]
Description=Daily DefenseOps Wazuh Manager archives retention cleanup

[Timer]
OnCalendar=daily
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
TIMER
    touch /var/log/defenseops-manager-archive-retention.log
    chmod 0600 /var/log/defenseops-manager-archive-retention.log
    systemctl daemon-reload
    systemctl enable --now defenseops-manager-archive-retention.timer
    ok "Systemd timer cleanup arsip lokal aktif (${MANAGER_ARCHIVE_RETENTION_DAYS} hari)."
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
    [[ -s "$indexer_conf" ]] || die "opensearch.yml tidak ditemukan atau kosong: ${indexer_conf}"
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
        log "Membuat kredensial acak untuk Wazuh..."
        cat > "$CREDENTIALS_FILE" <<CREDS
# Dashboard browser login (authenticated by Wazuh Indexer Security; default user: admin)
WAZUH_DASHBOARD_USERNAME=admin
WAZUH_DASHBOARD_PASSWORD=$(generate_password)

# Dashboard-to-Manager API integration account (Wazuh Manager API user)
WAZUH_MANAGER_API_USERNAME=wazuh-wui
WAZUH_MANAGER_API_PASSWORD=$(generate_password)

# Other Wazuh internal accounts
WAZUH_INDEXER_KIBANASERVER_PASSWORD=$(generate_password)
WAZUH_INDEXER_KIBANARO_PASSWORD=$(generate_password)
WAZUH_INDEXER_LOGSTASH_PASSWORD=$(generate_password)
WAZUH_INDEXER_READALL_PASSWORD=$(generate_password)
WAZUH_INDEXER_SNAPSHOTRESTORE_PASSWORD=$(generate_password)

# Wazuh API administrator account (used for API administration/rotation)
WAZUH_API_ADMIN_PASSWORD=$(generate_password)
CREDS
        chmod 0600 "$CREDENTIALS_FILE"
    else
        chmod 0600 "$CREDENTIALS_FILE"
        log "Kredensial yang sudah ada dipertahankan; migrasi nama variabel dilakukan tanpa mengganti password."
    fi

    # Load existing credentials first. The file is generated/managed by this
    # installer and must remain root-only (0600).
    # shellcheck disable=SC1090
    source "$CREDENTIALS_FILE"

    # Backward-compatible migration. Preserve existing secret values exactly;
    # prefer the new variable if both old and new names are present.
    WAZUH_DASHBOARD_USERNAME="${WAZUH_DASHBOARD_USERNAME:-admin}"
    WAZUH_DASHBOARD_PASSWORD="${WAZUH_DASHBOARD_PASSWORD:-${WAZUH_INDEXER_ADMIN_PASSWORD:-}}"
    WAZUH_MANAGER_API_USERNAME="${WAZUH_MANAGER_API_USERNAME:-wazuh-wui}"
    WAZUH_MANAGER_API_PASSWORD="${WAZUH_MANAGER_API_PASSWORD:-${WAZUH_API_PASSWORD:-}}"

    [[ -n "$WAZUH_DASHBOARD_PASSWORD" ]] || WAZUH_DASHBOARD_PASSWORD="$(generate_password)"
    [[ -n "$WAZUH_MANAGER_API_PASSWORD" ]] || WAZUH_MANAGER_API_PASSWORD="$(generate_password)"
    [[ -n "${WAZUH_INDEXER_KIBANASERVER_PASSWORD:-}" ]] || WAZUH_INDEXER_KIBANASERVER_PASSWORD="$(generate_password)"
    [[ -n "${WAZUH_INDEXER_KIBANARO_PASSWORD:-}" ]] || WAZUH_INDEXER_KIBANARO_PASSWORD="$(generate_password)"
    [[ -n "${WAZUH_INDEXER_LOGSTASH_PASSWORD:-}" ]] || WAZUH_INDEXER_LOGSTASH_PASSWORD="$(generate_password)"
    [[ -n "${WAZUH_INDEXER_READALL_PASSWORD:-}" ]] || WAZUH_INDEXER_READALL_PASSWORD="$(generate_password)"
    [[ -n "${WAZUH_INDEXER_SNAPSHOTRESTORE_PASSWORD:-}" ]] || WAZUH_INDEXER_SNAPSHOTRESTORE_PASSWORD="$(generate_password)"
    [[ -n "${WAZUH_API_ADMIN_PASSWORD:-}" ]] || WAZUH_API_ADMIN_PASSWORD="$(generate_password)"

    # Persist canonical names while retaining legacy entries for rollback
    # compatibility. No existing password is rotated by this migration.
    local tmp_credentials
    tmp_credentials="$(mktemp "${CREDENTIALS_FILE}.XXXXXX")"
    # Remove prior copies of canonical keys before appending one authoritative
    # block. Keep legacy keys untouched so older Compose files remain compatible.
    grep -Ev '^(WAZUH_DASHBOARD_USERNAME|WAZUH_DASHBOARD_PASSWORD|WAZUH_MANAGER_API_USERNAME|WAZUH_MANAGER_API_PASSWORD|WAZUH_INDEXER_KIBANASERVER_PASSWORD|WAZUH_INDEXER_KIBANARO_PASSWORD|WAZUH_INDEXER_LOGSTASH_PASSWORD|WAZUH_INDEXER_READALL_PASSWORD|WAZUH_INDEXER_SNAPSHOTRESTORE_PASSWORD|WAZUH_API_ADMIN_PASSWORD)=' \
        "$CREDENTIALS_FILE" > "$tmp_credentials" || true
    {
        printf '\n# Canonical DefenseOps credential names\n'
        printf 'WAZUH_DASHBOARD_USERNAME=%s\n' "$WAZUH_DASHBOARD_USERNAME"
        printf 'WAZUH_DASHBOARD_PASSWORD=%s\n' "$WAZUH_DASHBOARD_PASSWORD"
        printf 'WAZUH_MANAGER_API_USERNAME=%s\n' "$WAZUH_MANAGER_API_USERNAME"
        printf 'WAZUH_MANAGER_API_PASSWORD=%s\n' "$WAZUH_MANAGER_API_PASSWORD"
        printf 'WAZUH_INDEXER_KIBANASERVER_PASSWORD=%s\n' "$WAZUH_INDEXER_KIBANASERVER_PASSWORD"
        printf 'WAZUH_INDEXER_KIBANARO_PASSWORD=%s\n' "$WAZUH_INDEXER_KIBANARO_PASSWORD"
        printf 'WAZUH_INDEXER_LOGSTASH_PASSWORD=%s\n' "$WAZUH_INDEXER_LOGSTASH_PASSWORD"
        printf 'WAZUH_INDEXER_READALL_PASSWORD=%s\n' "$WAZUH_INDEXER_READALL_PASSWORD"
        printf 'WAZUH_INDEXER_SNAPSHOTRESTORE_PASSWORD=%s\n' "$WAZUH_INDEXER_SNAPSHOTRESTORE_PASSWORD"
        printf 'WAZUH_API_ADMIN_PASSWORD=%s\n' "$WAZUH_API_ADMIN_PASSWORD"
    } >> "$tmp_credentials"
    chmod 0600 "$tmp_credentials"
    mv -f "$tmp_credentials" "$CREDENTIALS_FILE"

    for name in \
        WAZUH_DASHBOARD_USERNAME \
        WAZUH_DASHBOARD_PASSWORD \
        WAZUH_MANAGER_API_USERNAME \
        WAZUH_MANAGER_API_PASSWORD \
        WAZUH_INDEXER_KIBANASERVER_PASSWORD \
        WAZUH_INDEXER_KIBANARO_PASSWORD \
        WAZUH_INDEXER_LOGSTASH_PASSWORD \
        WAZUH_INDEXER_READALL_PASSWORD \
        WAZUH_INDEXER_SNAPSHOTRESTORE_PASSWORD \
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
    admin_hash="$(generate_indexer_hash "$WAZUH_DASHBOARD_PASSWORD")"
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
API_PASSWORD_VALUE="$WAZUH_MANAGER_API_PASSWORD" \
API_USERNAME_VALUE="$WAZUH_MANAGER_API_USERNAME" \
python3 - "$dashboard_config" <<'PY'
import os, re, sys
from pathlib import Path

p = Path(sys.argv[1])
text = p.read_text(encoding="utf-8")
old_password = "MyS3cr37P450r.*-"
new_password = os.environ["API_PASSWORD_VALUE"]
new_username = os.environ["API_USERNAME_VALUE"]

# Update the upstream default username. If a custom username is already
# present, preserve it unless it matches the configured canonical username.
if re.search(r"(?m)^\s*username:\s*wazuh-wui\s*$", text):
    text = re.sub(
        r"(?m)^(\s*username:)\s*wazuh-wui\s*$",
        lambda m: m.group(1) + " " + new_username,
        text,
        count=1,
    )
elif not re.search(
    r"(?m)^\s*username:\s*" + re.escape(new_username) + r"\s*$",
    text,
):
    raise SystemExit("Dashboard API username is custom and differs from WAZUH_MANAGER_API_USERNAME; refusing to overwrite it.")

if old_password in text:
    text = text.replace(old_password, new_password)
elif new_password not in text:
    raise SystemExit("Dashboard API password is custom and differs from WAZUH_MANAGER_API_PASSWORD; refusing to overwrite it.")

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
            "API_PASSWORD": "${WAZUH_MANAGER_API_PASSWORD}",
            "API_USERNAME": "${WAZUH_MANAGER_API_USERNAME}",
        },
        "dashboard": {
            "INDEXER_PASSWORD": "${INDEXER_PASSWORD}",
            "DASHBOARD_PASSWORD": "${DASHBOARD_PASSWORD}",
            "API_PASSWORD": "${WAZUH_MANAGER_API_PASSWORD}",
            "API_USERNAME": "${WAZUH_MANAGER_API_USERNAME}",
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
INDEXER_PASSWORD=${WAZUH_DASHBOARD_PASSWORD}
WAZUH_MANAGER_API_PASSWORD=${WAZUH_MANAGER_API_PASSWORD}
WAZUH_MANAGER_API_USERNAME=${WAZUH_MANAGER_API_USERNAME}
# Legacy interpolation alias for Compose files generated by older installer versions
WAZUH_API_PASSWORD=${WAZUH_MANAGER_API_PASSWORD}
ENV
    cat > "${WAZUH_ROOT}/indexer/.env" <<ENV
WAZUH_CONFIG_DIR=${WAZUH_CONFIG}
ENV
    cat > "${WAZUH_ROOT}/dashboard/.env" <<ENV
WAZUH_CONFIG_DIR=${WAZUH_CONFIG}
INDEXER_PASSWORD=${WAZUH_DASHBOARD_PASSWORD}
DASHBOARD_PASSWORD=${WAZUH_INDEXER_KIBANASERVER_PASSWORD}
WAZUH_MANAGER_API_PASSWORD=${WAZUH_MANAGER_API_PASSWORD}
WAZUH_MANAGER_API_USERNAME=${WAZUH_MANAGER_API_USERNAME}
# Legacy interpolation alias for Compose files generated by older installer versions
WAZUH_API_PASSWORD=${WAZUH_MANAGER_API_PASSWORD}
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
            -u "${WAZUH_DASHBOARD_USERNAME}:${WAZUH_DASHBOARD_PASSWORD}" \
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
            -u "${WAZUH_MANAGER_API_USERNAME}:${WAZUH_MANAGER_API_PASSWORD}" \
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

configure_manager_api_tls() {
    log "Mengonfigurasi Wazuh Manager API menggunakan sertifikat TLS resmi DefenseOps..."

    local container_id
    container_id="$(docker ps -q --filter 'label=com.defenseops.component=wazuh-manager' | head -n 1)"
    [[ -n "$container_id" ]] || die "Container Wazuh Manager tidak ditemukan untuk konfigurasi TLS API."

    # The official Manager certificate already has SAN DNS:wazuh.manager.
    # Copy it into the API's persistent configuration volume. Wazuh API 4.14
    # accepts certificate/key basenames here, not absolute paths.
    docker exec "$container_id" sh -c '
        set -eu
        ssl_dir=/var/ossec/api/configuration/ssl
        install -d -o wazuh -g wazuh -m 0750 "$ssl_dir"
        install -o wazuh -g wazuh -m 0640 /etc/ssl/filebeat.pem "$ssl_dir/manager-api.crt"
        install -o wazuh -g wazuh -m 0640 /etc/ssl/filebeat.key "$ssl_dir/manager-api.key"
    '

    docker exec -i "$container_id" python3 - <<'PYAPI'
from pathlib import Path

path = Path("/var/ossec/api/configuration/api.yaml")
text = path.read_text(encoding="utf-8")

old = """# https:
#  enabled: yes
#  key: "server.key"
#  cert: "server.crt"
#  use_ca: False
#  ca: "ca.crt"
#  ssl_protocol: "auto"
#  ssl_ciphers: ""
"""
new = """https:
  enabled: yes
  key: "manager-api.key"
  cert: "manager-api.crt"
  use_ca: false
  ssl_protocol: "auto"
  ssl_ciphers: ""
"""

if new in text:
    print("Manager API TLS configuration already applied.")
elif old in text:
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print("Manager API TLS configuration applied.")
else:
    raise SystemExit(
        "Unexpected api.yaml HTTPS configuration; refusing to overwrite custom settings."
    )
PYAPI

    # Validate the installed certificate identity and private-key pairing
    # before restarting the Manager container.
    docker exec "$container_id" sh -c '
        set -eu
        cert=/var/ossec/api/configuration/ssl/manager-api.crt
        key=/var/ossec/api/configuration/ssl/manager-api.key
        cert_pub="$(openssl x509 -in "$cert" -pubkey -noout | openssl sha256)"
        key_pub="$(openssl pkey -in "$key" -pubout | openssl sha256)"
        [ "$cert_pub" = "$key_pub" ] || {
            echo "Manager API certificate and private key do not match." >&2
            exit 1
        }
        openssl x509 -in "$cert" -noout -checkhost wazuh.manager
    ' || die "Validasi sertifikat Manager API gagal."

    log "Restart Wazuh Manager untuk menerapkan TLS API..."
    docker restart "$container_id" >/dev/null
    wait_for_manager_tls
    ok "Wazuh Manager API menggunakan sertifikat TLS dengan SAN wazuh.manager."
}

wait_for_manager_tls() {
    log "Memverifikasi HTTPS dan hostname sertifikat Manager API..."
    local attempt status
    local ca_file="${WAZUH_CONFIG}/wazuh_indexer_ssl_certs/root-ca-manager.pem"

    [[ -s "$ca_file" ]] || die "Root CA Wazuh tidak ditemukan: ${ca_file}"

    for attempt in $(seq 1 60); do
        status="$(curl --silent --show-error --connect-timeout 3 --max-time 8 \
            --cacert "$ca_file" \
            --resolve wazuh.manager:55000:127.0.0.1 \
            -o /dev/null -w '%{http_code}' \
            -u "${WAZUH_MANAGER_API_USERNAME}:${WAZUH_MANAGER_API_PASSWORD}" \
            -X POST https://wazuh.manager:55000/security/user/authenticate?raw=true \
            2>/dev/null || true)"
        if [[ "$status" == "200" ]]; then
            ok "Manager API TLS certificate verification and authentication succeeded."
            return
        fi
        sleep 5
    done

    docker logs --tail=120 defenseops-manager-wazuh.manager-1 2>&1 || true
    die "Manager API belum lolos verifikasi TLS setelah restart."
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


ensure_manager_agent_enrollment() {
    log "Mengaktifkan enrollment password dan memastikan konfigurasi Manager persisten..."

    local manager_conf="${WAZUH_CONFIG}/wazuh_cluster/wazuh_manager.conf"
    local secret_file="${DEFENSEOPS_ROOT}/secrets/wazuh-agent-enrollment.pass"
    [[ -s "$manager_conf" ]] || die "Konfigurasi Manager tidak ditemukan: ${manager_conf}"

    install -d -o root -g root -m 0700 "${DEFENSEOPS_ROOT}/secrets"
    if [[ ! -s "$secret_file" ]]; then
        umask 077
        openssl rand -hex 32 > "$secret_file"
        log "Enrollment password baru dibuat."
    else
        log "Enrollment password yang sudah ada dipertahankan."
    fi
    chown root:root "$secret_file"
    chmod 0600 "$secret_file"

    # Ensure the bind-mounted source config requests password-protected enrollment.
    MANAGER_CONF="$manager_conf" python3 <<'PYAUTH'
import os, re
from pathlib import Path

p = Path(os.environ["MANAGER_CONF"])
s = p.read_text(encoding="utf-8")
auth = re.search(r"(?ms)(<auth>)(.*?)(</auth>)", s)
if not auth:
    raise SystemExit(f"Blok <auth> tidak ditemukan dalam {p}")
block = auth.group(2)
rx = re.compile(r"(?m)^([ \t]*<use_password>)[^<]*(</use_password>[ \t]*)$")
if rx.search(block):
    block = rx.sub(r"\g<1>yes\g<2>", block, count=1)
else:
    block += "\n    <use_password>yes</use_password>\n  "
s = s[:auth.start(2)] + block + s[auth.end(2):]
p.write_text(s, encoding="utf-8")
PYAUTH

    # The effective ossec.conf is stored in the named Docker volume, not in
    # /wazuh-config-mount. Update that persistent volume after Compose creates it.
    local volume_name="defenseops-manager-wazuh_etc"
    local volume_mount=""
    volume_mount="$(docker volume inspect -f '{{.Mountpoint}}' "$volume_name" 2>/dev/null || true)"
    if [[ -z "$volume_mount" || ! -d "$volume_mount" ]]; then
        die "Docker volume ${volume_name} belum tersedia; Manager harus dibuat terlebih dahulu."
    fi

    local effective_conf="${volume_mount}/ossec.conf"
    [[ -s "$effective_conf" ]] || die "ossec.conf persisten tidak ditemukan: ${effective_conf}"
    cp -a "$effective_conf" "${effective_conf}.defenseops-backup-$(date +%Y%m%d-%H%M%S)"

    EFFECTIVE_CONF="$effective_conf" python3 <<'PYVOL'
import os, re
from pathlib import Path

p = Path(os.environ["EFFECTIVE_CONF"])
s = p.read_text(encoding="utf-8")
auth = re.search(r"(?ms)(<auth>)(.*?)(</auth>)", s)
if not auth:
    raise SystemExit(f"Blok <auth> tidak ditemukan dalam {p}")
block = auth.group(2)
rx = re.compile(r"(?m)^([ \t]*<use_password>)[^<]*(</use_password>[ \t]*)$")
if rx.search(block):
    block = rx.sub(r"\g<1>yes\g<2>", block, count=1)
else:
    block += "\n    <use_password>yes</use_password>\n  "
s = s[:auth.start(2)] + block + s[auth.end(2):]
p.write_text(s, encoding="utf-8")
PYVOL

    # Wazuh authd reads this file from the same persistent /var/ossec/etc volume.
    local restart_needed=0
    if [[ ! -s "${volume_mount}/authd.pass" ]] || ! cmp -s "$secret_file" "${volume_mount}/authd.pass"; then
        restart_needed=1
    fi
    local container_id wazuh_gid
    container_id="$(docker ps -q --filter 'label=com.defenseops.component=wazuh-manager' | head -n 1)"
    [[ -n "$container_id" ]] || die "Container Manager tidak ditemukan setelah volume dibuat."
    wazuh_gid="$(docker exec "$container_id" getent group wazuh | cut -d: -f3)"
    [[ "$wazuh_gid" =~ ^[0-9]+$ ]] || die "GID grup wazuh tidak dapat dideteksi dari container."
    install -o root -g "$wazuh_gid" -m 0640 "$secret_file" "${volume_mount}/authd.pass"

    local active_value
    active_value="$(docker exec "$container_id" python3 -c '
import re
from pathlib import Path
s=Path("/var/ossec/etc/ossec.conf").read_text()
m=re.search(r"(?ms)<auth>(.*?)</auth>",s)
v=re.search(r"<use_password>\s*(.*?)\s*</use_password>",m.group(1)) if m else None
print(v.group(1) if v else "missing")
' 2>/dev/null || true)"

    if [[ "$active_value" != "yes" ]]; then
        restart_needed=1
    fi
    if (( restart_needed )); then
        log "Menerapkan konfigurasi enrollment/password ke Manager; container akan direstart satu kali."
        docker restart "$container_id" >/dev/null
        wait_for_manager
    fi

    # Re-read the active config after any restart and validate the authd listener.
    active_value="$(docker exec "$container_id" python3 -c '
import re
from pathlib import Path
s=Path("/var/ossec/etc/ossec.conf").read_text()
m=re.search(r"(?ms)<auth>(.*?)</auth>",s)
v=re.search(r"<use_password>\s*(.*?)\s*</use_password>",m.group(1)) if m else None
print(v.group(1) if v else "missing")
' 2>/dev/null || true)"
    [[ "$active_value" == "yes" ]] || die "Konfigurasi aktif Manager belum menunjukkan use_password=yes."

    docker exec "$container_id" test -s /var/ossec/etc/authd.pass \
        || die "authd.pass tidak ditemukan di volume aktif Manager."
    docker exec "$container_id" sh -c 'test "$(stat -c "%a" /var/ossec/etc/authd.pass)" = 640' \
        || die "Permission authd.pass bukan 0640."
    docker exec "$container_id" pgrep -x wazuh-authd >/dev/null \
        || die "Proses wazuh-authd tidak berjalan."
    if ! ss -lnt 2>/dev/null | awk '$4 ~ /:1515$/ {found=1} END {exit !found}'; then
        die "Port enrollment TCP 1515 tidak listening pada host."
    fi

    ok "Enrollment password aktif; use_password=yes persisten, authd.pass tersimpan aman, dan TCP 1515 listening."
}

ensure_manager_agent_groups() {
    log "Memastikan group agent DefenseOps tersedia..."

    local container_id groups_output group
    container_id="$(docker ps -q --filter 'label=com.defenseops.component=wazuh-manager' | head -n 1)"
    [[ -n "$container_id" ]] || die "Container Wazuh Manager tidak ditemukan untuk pembuatan agent groups."

    docker exec "$container_id" test -x /var/ossec/bin/agent_groups \
        || die "Tool /var/ossec/bin/agent_groups tidak ditemukan di container Manager."

    groups_output="$(docker exec "$container_id" /var/ossec/bin/agent_groups -l 2>&1)" \
        || die "Gagal membaca daftar agent groups dari Wazuh Manager."

    for group in Brebes-WAF docker-php; do
        if printf '%s\n' "$groups_output" |
            awk -v wanted="$group" '$1 == wanted && $2 ~ /^\([0-9]+\)$/ { found=1 } END { exit !found }'; then
            ok "Agent group '${group}' sudah tersedia; dipertahankan."
            continue
        fi

        log "Membuat agent group '${group}'..."
        docker exec "$container_id" /var/ossec/bin/agent_groups -a -g "$group" -q \
            || die "Gagal membuat agent group '${group}'."

        groups_output="$(docker exec "$container_id" /var/ossec/bin/agent_groups -l 2>&1)" \
            || die "Gagal memverifikasi agent group '${group}'."
        printf '%s\n' "$groups_output" |
            awk -v wanted="$group" '$1 == wanted && $2 ~ /^\([0-9]+\)$/ { found=1 } END { exit !found }' \
            || die "Agent group '${group}' belum terdaftar setelah pembuatan."
        ok "Agent group '${group}' berhasil dibuat."
    done

    log "Daftar agent groups yang ditargetkan:"
    docker exec "$container_id" /var/ossec/bin/agent_groups -l |
        awk '$1 == "Brebes-WAF" || $1 == "docker-php"'
}

deploy_wazuh() {
    log "Menyiapkan deployment Wazuh ${WAZUH_VERSION}..."
    create_docker_network
    prepare_wazuh_source
    seed_wazuh_configuration
    configure_raw_log_collection

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
    configure_indexer_retention_policies

    log "Menjalankan Wazuh Manager..."
    compose_up manager
    ensure_manager_agent_enrollment
    ensure_manager_agent_groups
    configure_effective_manager_archives
    wait_for_manager
    configure_manager_api_tls
    rotate_wazuh_api_admin_password
    configure_filebeat_archives
    wait_for_manager
    install_manager_archive_retention

    log "Menjalankan Wazuh Dashboard..."
    compose_up dashboard
    wait_for_dashboard
}



finalize_manager_and_verify_archives() {
    log "Menjalankan finalisasi Manager setelah seluruh konfigurasi dan deployment selesai..."

    local manager_id restart_time attempt logs groups_output group
    manager_id="$(docker ps -q --filter 'label=com.defenseops.component=wazuh-manager' | head -n 1)"
    [[ -n "$manager_id" ]] || die "Container Wazuh Manager tidak ditemukan untuk final restart."

    # Filebeat archives config is stored on the persistent /etc/filebeat volume.
    # Restart the Manager container once, after all Manager configuration steps,
    # so Filebeat loads the final configuration. Do not use s6-svc -r here.
    restart_time="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    log "Restart final Wazuh Manager untuk memuat konfigurasi Filebeat archives..."
    docker restart "$manager_id" >/dev/null \
        || die "Gagal melakukan final restart Wazuh Manager."

    wait_for_manager

    manager_id="$(docker ps -q --filter 'label=com.defenseops.component=wazuh-manager' | head -n 1)"
    [[ -n "$manager_id" ]] || die "Container Wazuh Manager tidak kembali berjalan setelah restart."

    # Verify both required agent groups still exist; do not recreate or alter them.
    groups_output="$(docker exec "$manager_id" /var/ossec/bin/agent_groups -l 2>&1)" \
        || die "Gagal membaca agent groups setelah final restart."
    for group in Brebes-WAF docker-php; do
        printf '%s\n' "$groups_output" |
            awk -v wanted="$group" '$1 == wanted && $2 ~ /^\([0-9]+\)$/ { found=1 } END { exit !found }' \
            || die "Agent group '${group}' tidak ditemukan setelah final restart."
        case "$group" in
            Brebes-WAF) SUMMARY_GROUP_BREBES_WAF="OK" ;;
            docker-php) SUMMARY_GROUP_DOCKER_PHP="OK" ;;
        esac
        ok "Agent group '${group}' terverifikasi."
    done

    # Wait until the Filebeat process started by this restart reports alerts
    # and archives enabled, starts the archives harvester, and loads its pipeline.
    log "Memverifikasi Filebeat alerts, archives, harvester, dan pipeline (maksimal 5 menit)..."
    local filebeat_ready=0 pipeline_ready=0
    for attempt in $(seq 1 60); do
        logs="$(docker logs --since "$restart_time" "$manager_id" 2>&1 || true)"

        if printf '%s\n' "$logs" |
            grep -E 'Enabled modules/filesets: wazuh \(archives, alerts\)|Enabled modules/filesets: wazuh \(alerts, archives\)' >/dev/null; then
            filebeat_ready=1
        fi

        if printf '%s\n' "$logs" |
            grep -F 'Harvester started for file: /var/ossec/logs/archives/archives.json' >/dev/null; then
            SUMMARY_ARCHIVES_HARVESTER="running"
        fi

        if printf '%s\n' "$logs" |
            grep -F 'filebeat-7.10.2-wazuh-archives-pipeline' >/dev/null; then
            pipeline_ready=1
        fi

        if (( filebeat_ready == 1 )) &&
           [[ "$SUMMARY_ARCHIVES_HARVESTER" == "running" ]] &&
           (( pipeline_ready == 1 )); then
            break
        fi
        sleep 5
    done

    (( filebeat_ready == 1 )) || {
        docker logs --since "$restart_time" "$manager_id" 2>&1 | tail -n 120 >&2 || true
        die "Filebeat belum mengaktifkan alerts dan archives setelah restart."
    }
    SUMMARY_FILEBEAT_ALERTS="enabled"
    SUMMARY_FILEBEAT_ARCHIVES="enabled"
    [[ "$SUMMARY_ARCHIVES_HARVESTER" == "running" ]] \
        || die "Filebeat archives aktif tetapi harvester archives.json belum berjalan."
    (( pipeline_ready == 1 )) \
        || die "Filebeat archives aktif tetapi archives pipeline belum terdeteksi pada log."
    SUMMARY_ARCHIVES_PIPELINE="loaded"
    ok "Filebeat alerts dan archives aktif; harvester berjalan; pipeline loaded."

    # Verify the archive index is actually created in the Indexer.
    log "Menunggu index ${WAZUH_ARCHIVE_INDEX_PATTERN} terbentuk (maksimal 5 menit)..."
    local index_response index_count index_health
    for attempt in $(seq 1 60); do
        index_response="$(curl -ksS --connect-timeout 5 --max-time 15 \
            -u "${WAZUH_DASHBOARD_USERNAME}:${WAZUH_DASHBOARD_PASSWORD}" \
            'https://127.0.0.1:9200/_cat/indices/wazuh-archives-4.x-*?format=json' 2>/dev/null || true)"
        index_count="$(printf '%s' "$index_response" | jq -r 'if type == "array" then length else 0 end' 2>/dev/null || printf '0')"

        if [[ "$index_count" =~ ^[0-9]+$ ]] && (( index_count > 0 )); then
            printf '%s\n' "$index_response" |
                jq -r '.[] | "  \(.health) \(.status) \(.index) docs=\(.["docs.count"])"'

            index_health="$(printf '%s' "$index_response" |
                jq -r 'if length == 0 then "NOT FOUND"
                       elif any(.[]; .health == "red") then "red"
                       elif any(.[]; .health == "yellow") then "yellow"
                       elif all(.[]; .health == "green") then "green"
                       else "unknown" end')"

            case "$index_health" in
                green|yellow)
                    SUMMARY_ARCHIVES_INDEX_HEALTH="$index_health"
                    SUMMARY_ARCHIVES_INDEX="$WAZUH_ARCHIVE_INDEX_PATTERN"
                    ok "Wazuh archives aktif; index health ${index_health}."
                    return
                    ;;
                *)
                    die "Archives index ditemukan tetapi health=${index_health}."
                    ;;
            esac
        fi
        sleep 5
    done

    die "Filebeat archives harvester aktif, tetapi index ${WAZUH_ARCHIVE_INDEX_PATTERN} belum terbentuk dalam 5 menit. Periksa Filebeat dan Indexer."
}


check_component_communications() {
    log "Memeriksa komunikasi antar-komponen Wazuh..."
    local dashboard_id manager_id indexer_id
    dashboard_id="$(docker ps -q --filter 'label=com.defenseops.component=wazuh-dashboard' | head -n 1)"
    manager_id="$(docker ps -q --filter 'label=com.defenseops.component=wazuh-manager' | head -n 1)"
    indexer_id="$(docker ps -q --filter 'label=com.defenseops.component=wazuh-indexer' | head -n 1)"
    [[ -n "$dashboard_id" && -n "$manager_id" && -n "$indexer_id" ]] || die "Salah satu container Wazuh tidak berjalan."

    local result
    result="$(curl -kfsS --connect-timeout 5 --max-time 15 \
        -u "${WAZUH_DASHBOARD_USERNAME}:${WAZUH_DASHBOARD_PASSWORD}" \
        https://127.0.0.1:9200/_cluster/health 2>/dev/null)" \
        || die "Host -> Indexer API gagal."
    printf '%s' "$result" | jq -e '.status == "green" or .status == "yellow"' >/dev/null \
        || die "Indexer cluster health bukan green/yellow."
    ok "Host -> Indexer API: OK (cluster $(printf '%s' "$result" | jq -r '.status'))."

    local dashboard_http
    dashboard_http="$(curl -k -sS --connect-timeout 5 --max-time 15 \
        -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/app/login 2>/dev/null || true)"
    [[ "$dashboard_http" =~ ^(200|302)$ ]] || die "Dashboard UI gagal (HTTP ${dashboard_http})."
    ok "Host -> Dashboard UI: OK (HTTP ${dashboard_http})."

    # Dashboard container -> Indexer (TLS + authentication).
    docker exec -e CHECK_USER="$WAZUH_DASHBOARD_USERNAME" \
        -e CHECK_PASS="$WAZUH_DASHBOARD_PASSWORD" "$dashboard_id" sh -c '
        curl -kfsS --connect-timeout 5 --max-time 15 \
          -u "$CHECK_USER:$CHECK_PASS" https://wazuh.indexer:9200/_cluster/health >/dev/null
    ' || die "Dashboard -> Indexer gagal."
    ok "Dashboard -> Indexer: OK (HTTPS + authentication)."

    # Dashboard container -> Manager API (TLS + API authentication).
    docker exec -e CHECK_USER="$WAZUH_MANAGER_API_USERNAME" \
        -e CHECK_PASS="$WAZUH_MANAGER_API_PASSWORD" "$dashboard_id" sh -c '
        code=$(curl -k -sS --connect-timeout 5 --max-time 15 -o /dev/null -w "%{http_code}" \
          -u "$CHECK_USER:$CHECK_PASS" \
          -X POST "https://wazuh.manager:55000/security/user/authenticate?raw=true")
        [ "$code" = 200 ]
    ' || die "Dashboard -> Manager API gagal."
    ok "Dashboard -> Manager API: OK (HTTPS + authentication)."

    # Manager container -> Indexer (TLS + authentication).
    docker exec -e CHECK_USER="$WAZUH_DASHBOARD_USERNAME" \
        -e CHECK_PASS="$WAZUH_DASHBOARD_PASSWORD" "$manager_id" sh -c '
        curl -kfsS --connect-timeout 5 --max-time 15 \
          -u "$CHECK_USER:$CHECK_PASS" https://wazuh.indexer:9200/_cluster/health >/dev/null
    ' || die "Manager -> Indexer gagal."
    ok "Manager -> Indexer: OK (HTTPS + authentication)."

    ok "Seluruh pemeriksaan komunikasi komponen berhasil."
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


print_installation_summary() {
    local primary_ip="" dashboard_url="" credentials_mode="" docker_version="" compose_version=""
    local host_name="" os_name="" container_status="" ntp_state="" sync_state="" timezone="" enrollment_state=""

    # Prefer the source address selected by the host's default route.
    primary_ip="$(ip -4 route get 1.1.1.1 2>/dev/null |
        awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}' || true)"

    # Fallback for hosts without a usable default route.
    if [[ -z "$primary_ip" ]]; then
        primary_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    fi

    if [[ -n "$primary_ip" ]]; then
        dashboard_url="https://${primary_ip}:8443/"
    else
        dashboard_url="https://<IP-ADDRESS-SERVER>:8443/"
    fi

    host_name="$(hostname -f 2>/dev/null || hostname)"
    # shellcheck disable=SC1091
    source /etc/os-release
    os_name="${PRETTY_NAME:-Ubuntu}"

    docker_version="$(docker --version 2>/dev/null || true)"
    compose_version="$(docker compose version --short 2>/dev/null || docker compose version 2>/dev/null || true)"
    ntp_state="$(timedatectl show -p NTP --value 2>/dev/null || printf 'unknown')"
    sync_state="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || printf 'unknown')"
    timezone="$(timedatectl show -p Timezone --value 2>/dev/null || date +%Z)"
    enrollment_state="$(docker exec defenseops-manager-wazuh.manager-1 python3 -c 'import re; s=open("/var/ossec/etc/ossec.conf").read(); m=re.search(r"(?ms)<auth>(.*?)</auth>",s); v=re.search(r"<use_password>\s*(.*?)\s*</use_password>",m.group(1)) if m else None; print(v.group(1) if v else "missing")' 2>/dev/null || printf 'check-failed')"
    if [[ "$enrollment_state" == "yes" ]]; then
        enrollment_state="enabled (yes)"
    else
        enrollment_state="NOT ENABLED (${enrollment_state})"
    fi

    if [[ -f "$CREDENTIALS_FILE" ]]; then
        credentials_mode="$(stat -c '%a (%A)' "$CREDENTIALS_FILE" 2>/dev/null || printf 'unknown')"
    else
        credentials_mode="MISSING"
    fi

    echo
    printf '%b============================================================%b\n' "$GREEN" "$NC"
    printf '%b             DEFENSEOPS INSTALLATION SUMMARY%b\n' "$GREEN" "$NC"
    printf '%b============================================================%b\n' "$GREEN" "$NC"

    printf '\n%b[ HOST ]%b\n' "$BLUE" "$NC"
    printf 'Hostname              : %s\n' "$host_name"
    printf 'Operating System      : %s\n' "$os_name"
    printf 'Docker Engine         : %s\n' "${docker_version:-not detected}"
    printf 'Docker Compose        : %s\n' "${compose_version:-not detected}"
    printf 'Wazuh Version         : %s\n' "$WAZUH_VERSION"
    printf 'Timezone              : %s\n' "$timezone"
    printf 'NTP                   : enabled=%s, synchronized=%s\n' "$ntp_state" "$sync_state"

    printf '\n%b[ WAZUH DASHBOARD ]%b\n' "$BLUE" "$NC"
    printf 'Dashboard URL         : %s\n' "$dashboard_url"
    printf 'Dashboard Port        : 8443/TCP'
    printf '\n'
    printf "Dashboard Username    : %s\n" "${WAZUH_DASHBOARD_USERNAME:-admin}"
    printf 'Dashboard Password    : WAZUH_DASHBOARD_PASSWORD in credentials file\n'

    printf '\n%b[ AGENT ENROLLMENT ]%b\n' "$BLUE" "$NC"
    printf 'Enrollment Password   : %s\n' "${DEFENSEOPS_ROOT}/secrets/wazuh-agent-enrollment.pass"
    printf 'Secret Permission     : %s\n' "$(stat -c '%a (%A)' "${DEFENSEOPS_ROOT}/secrets/wazuh-agent-enrollment.pass" 2>/dev/null || printf MISSING)"
    printf 'Manager use_password  : %s\n' "$enrollment_state"
    printf 'Persistent authd.pass : %s\n' "$(docker exec defenseops-manager-wazuh.manager-1 test -s /var/ossec/etc/authd.pass && printf OK || printf MISSING)"
    printf 'Enrollment Listener   : %s\n' "$(ss -lnt 2>/dev/null | awk '$4 ~ /:1515$/ {found=1} END {print found ? "1515/TCP LISTENING" : "NOT LISTENING"}')"

    printf '\n%b[ AGENT GROUPS ]%b\n' "$BLUE" "$NC"
    printf 'Brebes-WAF            : %s\n' "$SUMMARY_GROUP_BREBES_WAF"
    printf 'docker-php            : %s\n' "$SUMMARY_GROUP_DOCKER_PHP"

    printf '\n%b[ FILEBEAT ARCHIVES ]%b\n' "$BLUE" "$NC"
    printf 'Filebeat Alerts       : %s\n' "$SUMMARY_FILEBEAT_ALERTS"
    printf 'Filebeat Archives     : %s\n' "$SUMMARY_FILEBEAT_ARCHIVES"
    printf 'Archives Harvester    : %s\n' "$SUMMARY_ARCHIVES_HARVESTER"
    printf 'Archives Pipeline     : %s\n' "$SUMMARY_ARCHIVES_PIPELINE"
    printf 'Archives Index        : %s\n' "$SUMMARY_ARCHIVES_INDEX"
    printf 'Archives Index Health : %s\n' "$SUMMARY_ARCHIVES_INDEX_HEALTH"

    printf '\n%b[ LOG COLLECTION & RETENTION ]%b\n' "$BLUE" "$NC"
    printf 'Raw JSON Events       : enabled (Manager logall_json=yes)\n'
    printf 'Archives Index        : %s\n' "$WAZUH_ARCHIVE_INDEX_PATTERN"
    printf 'Dashboard Time Field  : timestamp\n'
    printf 'Raw Logs Indexer      : %s days\n' "$RAW_LOG_RETENTION_DAYS"
    printf 'Security Alerts       : %s days\n' "$ALERT_RETENTION_DAYS"
    printf 'Manager Local Archives: %s days (compressed files)\n' "$MANAGER_ARCHIVE_RETENTION_DAYS"

    printf '\n%b[ CREDENTIALS ]%b\n' "$BLUE" "$NC"
    printf 'Password File         : %s\n' "$CREDENTIALS_FILE"
    printf 'File Permission       : %s\n' "$credentials_mode"
    printf 'Read credentials      : sudo cat %q\n' "$CREDENTIALS_FILE"
    printf 'Recommended handling : keep private; do not share or commit this file.\n'

    printf '\n%b[ COMPOSE FILES ]%b\n' "$BLUE" "$NC"
    printf 'Indexer               : %s\n' "${WAZUH_ROOT}/indexer/docker-compose.yml"
    printf 'Manager               : %s\n' "${WAZUH_ROOT}/manager/docker-compose.yml"
    printf 'Dashboard             : %s\n' "${WAZUH_ROOT}/dashboard/docker-compose.yml"
    printf 'Shared Docker Network : %s\n' "$WAZUH_NETWORK"

    printf '\n%b[ API ENDPOINTS ]%b\n' "$BLUE" "$NC"
    printf 'Indexer API           : https://127.0.0.1:9200 (loopback only)\n'
    printf 'Manager API           : https://127.0.0.1:55000 (loopback only)\n'

    printf '\n%b[ AGENT / SYSLOG PORTS ]%b\n' "$BLUE" "$NC"
    printf 'Wazuh Agent           : 1514/TCP\n'
    printf 'Agent Enrollment      : 1515/TCP\n'
    printf 'Syslog                : 514/UDP\n'

    printf '\n%b[ COMPONENT COMMUNICATION ]%b\n' "$BLUE" "$NC"
    printf 'Dashboard -> Indexer   : OK (HTTPS + authentication)\n'
    printf 'Dashboard -> Manager   : OK (HTTPS + authentication)\n'
    printf 'Manager -> Indexer      : OK (HTTPS + authentication)\n'
    printf 'Host -> Dashboard       : OK (HTTP 200/302)\n'
    printf 'Host -> Indexer         : OK (cluster health checked)\n'

    printf '\n%b[ SERVICE STATUS ]%b\n' "$BLUE" "$NC"
    docker ps --filter "label=com.defenseops.managed=true" \
        --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || true

    printf '\n%b[ LOG FILE ]%b\n' "$BLUE" "$NC"
    printf 'Installer Log         : %s\n' "$LOG_FILE"

    printf '\n%b[ SECURITY NOTES ]%b\n' "$YELLOW" "$NC"
    printf '%s\n' \
        '- Dashboard TLS certificate is self-signed.' \
        '- Indexer API (9200) and Manager API (55000) are bound to loopback.' \
        '- Restrict Dashboard, Agent, Enrollment, and Syslog ports with the host/network firewall.' \
        '- Credentials file is sensitive; retain its 0600 permissions and secure backups.'

    if [[ -z "$primary_ip" ]]; then
        warn "IP utama server tidak dapat dideteksi otomatis. Ganti placeholder pada Dashboard URL dengan IP server."
    fi

    printf '%b============================================================%b\n' "$GREEN" "$NC"
    printf '%b Deployment Wazuh selesai dan ringkasan instalasi ditampilkan.%b\n' "$GREEN" "$NC"
    printf '%b============================================================%b\n' "$GREEN" "$NC"
}

main() {
    if (( REPAIR_ARCHIVES_ONLY )); then
        log "===== DefenseOps Filebeat Archives Repair Only ====="
        command -v docker >/dev/null 2>&1 || die "Docker tidak ditemukan."
        docker info >/dev/null 2>&1 || die "Docker daemon tidak dapat diakses."
        configure_filebeat_archives
        log "Perbaikan archives selesai. Komponen selain Filebeat tidak disentuh."
        exit 0
    fi

    log "===== DefenseOps Full Requirements & Wazuh Installer ====="
    check_system_requirements

    if (( DRY_RUN )); then
        echo
        log "DRY-RUN: tidak ada perubahan yang diterapkan."
        log "Rencana: hostname defenseops -> repository Ubuntu -> dependencies -> Docker/Compose -> sysctl ->"
        log "direktori/network -> source Wazuh ${WAZUH_VERSION} -> TLS/passwords ->"
        log "3 Compose projects -> deploy Indexer, Manager, Dashboard -> Manager API TLS -> health checks."
        log "Raw JSON events (logall_json=yes) + Filebeat archives.enabled=true -> ${WAZUH_ARCHIVE_INDEX_PATTERN} ->"
        log "Archive retention: raw 30d, alerts 90d -> ${WAZUH_ARCHIVE_INDEX_PATTERN};"
        log "Manager local compressed archives cleanup (14d)."
        log "NTP/chrony -> optional timezone Asia/Jakarta -> enrollment password use_password=yes in persistent wazuh_etc volume."
        log "Agent enrollment secret -> component communication checks (Dashboard/Indexer/Manager)."
        log "Agent groups dibuat idempotent: Brebes-WAF dan docker-php (tanpa assignment agent otomatis)."
        exit 0
    fi

    configure_host_hostname
    configure_ubuntu_repositories
    install_base_packages
    configure_time_and_timezone
    install_docker
    configure_docker_defaults
    configure_kernel
    create_directories
    deploy_wazuh
    # Final Manager restart happens only after Manager, Filebeat, and Dashboard
    # configuration is complete. Then verify groups and end-to-end archives.
    finalize_manager_and_verify_archives
    verify_final_state
    check_component_communications

    print_installation_summary
}

main "$@"
