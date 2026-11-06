#requires -Version 5.1
<#
.SYNOPSIS
    Merapikan struktur repository DefenseOps.
.DESCRIPTION
    Membuat direktori yang belum ada, menormalkan nama COMMERCIAL-LICENSE.md,
    memindahkan dokumentasi lama ke struktur baru, menambahkan .gitignore,
    dan menyelaraskan bagian struktur repository serta lisensi pada README.md.
    File non-empty tidak ditimpa. File yang diubah/diganti akan dibackup.
.PARAMETER RootPath
    Lokasi root repository DefenseOps. Default: direktori script ini.
.EXAMPLE
    .\repair-defenseops-structure.ps1 -RootPath C:\Projects\DefenseOps
.EXAMPLE
    .\repair-defenseops-structure.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$RootPath = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RootPath = [System.IO.Path]::GetFullPath($RootPath)
if (-not (Test-Path -LiteralPath $RootPath -PathType Container)) { throw "Root repository tidak ditemukan: $RootPath" }
if (-not (Test-Path -LiteralPath (Join-Path $RootPath 'README.md') -PathType Leaf)) { throw 'README.md tidak ditemukan. RootPath harus menunjuk ke root DefenseOps.' }

$script:BackupRoot = Join-Path $RootPath ('.structure-backup\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$script:BackupCreated = $false
$script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Write-TextFileNoBom {
    param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, $script:Utf8NoBom)
}
function Backup-ExistingFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $relative = $Path.Substring($RootPath.Length).TrimStart('\','/')
    $target = Join-Path $script:BackupRoot $relative
    $parent = Split-Path -Parent $target
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    Copy-Item -LiteralPath $Path -Destination $target -Force
    $script:BackupCreated = $true
}
function Ensure-Directory {
    param([string]$RelativePath)
    $path = Join-Path $RootPath $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        if ($script:PSCmdlet.ShouldProcess($path, 'Buat direktori')) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            Write-Host "[OK] Directory: $RelativePath" -ForegroundColor Green
        }
    }
}
function Ensure-File {
    param([string]$RelativePath, [string]$Content, [switch]$InitializeIfEmpty)
    $path = Join-Path $RootPath $RelativePath
    $exists = Test-Path -LiteralPath $path -PathType Leaf
    $write = -not $exists
    if ($exists -and $InitializeIfEmpty) { $write = ((Get-Item -LiteralPath $path).Length -eq 0) }
    if ($write -and $script:PSCmdlet.ShouldProcess($path, 'Buat/inisialisasi file')) {
        if ($exists) { Backup-ExistingFile -Path $path }
        $parent = Split-Path -Parent $path
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Write-TextFileNoBom -Path $path -Content $Content
        Write-Host "[OK] File: $RelativePath" -ForegroundColor Green
    }
    elseif ($exists -and -not $write) { Write-Host "[KEEP] $RelativePath" -ForegroundColor DarkGray }
}

Write-Host "DefenseOps repository: $RootPath" -ForegroundColor Cyan

# 1. Directory layout: core, integrations, agent package generator, benchmark/capacity planner.
$directories = @(
'docs','docs\architecture','docs\deployment','docs\operations','docs\security',
'scripts','config','config\manager','config\indexer','config\dashboard','config\agent',
'deployment','deployment\docker','deployment\native',
'detection','detection\rules','detection\rules\authentication','detection\rules\web','detection\rules\waf','detection\rules\malware','detection\rules\filesystem','detection\rules\application',
'detection\decoders','detection\decoders\nginx','detection\decoders\modsecurity','detection\decoders\clamav','detection\decoders\lmd','detection\decoders\yara','detection\decoders\application','detection\threat-intelligence',
'response','response\active','response\active\firewall','response\active\authentication','response\active\endpoint','response\playbooks',
'integrations','integrations\brebes-waf','integrations\docker-php','integrations\nginx','integrations\clamav','integrations\lmd','integrations\yara','integrations\pfsense','integrations\zabbix',
'monitoring','monitoring\health','monitoring\dashboards','monitoring\alerts',
'agent','agent\generator','agent\templates','agent\templates\linux','agent\templates\windows','agent\profiles','agent\output',
'tests','tests\detection','tests\decoders','tests\response','tests\integration',
'examples','examples\nginx','examples\modsecurity','examples\clamav','examples\yara','examples\application',
'benchmark','benchmark\engine','benchmark\workload','benchmark\workload\central-server','benchmark\workload\central-server\wazuh-manager','benchmark\workload\central-server\wazuh-indexer','benchmark\workload\central-server\wazuh-dashboard','benchmark\workload\docker-host','benchmark\workload\docker-host\php','benchmark\workload\docker-host\aspnet','benchmark\workload\docker-host\python','benchmark\workload\docker-host\generic','benchmark\analyzer','benchmark\profiles','benchmark\reports'
)
foreach ($dir in $directories) { Ensure-Directory -RelativePath $dir }

# 2. Rename commercial license without overwriting a destination file.
$oldLicense = Join-Path $RootPath 'COMMERCIAL-LICENSE'
$newLicense = Join-Path $RootPath 'COMMERCIAL-LICENSE.md'
if ((Test-Path -LiteralPath $oldLicense -PathType Leaf) -and -not (Test-Path -LiteralPath $newLicense)) {
    if ($script:PSCmdlet.ShouldProcess($oldLicense, 'Rename menjadi COMMERCIAL-LICENSE.md')) {
        Rename-Item -LiteralPath $oldLicense -NewName 'COMMERCIAL-LICENSE.md'
        Write-Host '[OK] COMMERCIAL-LICENSE.md' -ForegroundColor Green
    }
}
elseif ((Test-Path -LiteralPath $oldLicense) -and (Test-Path -LiteralPath $newLicense)) {
    Write-Warning 'COMMERCIAL-LICENSE dan COMMERCIAL-LICENSE.md sama-sama ada. Tidak ada yang ditimpa; periksa manual.'
}

# 3. Move legacy docs into the nested documentation structure.
$docMoves = @(
    @{ Old = 'docs\architecture.md'; New = 'docs\architecture\overview.md' },
    @{ Old = 'docs\installation.md'; New = 'docs\deployment\installation.md' }
)
foreach ($move in $docMoves) {
    $src = Join-Path $RootPath $move.Old
    $dst = Join-Path $RootPath $move.New
    if ((Test-Path -LiteralPath $src -PathType Leaf) -and -not (Test-Path -LiteralPath $dst)) {
        if ($script:PSCmdlet.ShouldProcess($src, "Pindahkan ke $($move.New)")) {
            Move-Item -LiteralPath $src -Destination $dst
            Write-Host "[OK] $($move.Old) -> $($move.New)" -ForegroundColor Green
        }
    }
    elseif ((Test-Path -LiteralPath $src) -and (Test-Path -LiteralPath $dst)) {
        Write-Warning "Kedua file ada: $($move.Old) dan $($move.New). Tidak ditimpa."
    }
}
Ensure-File -RelativePath 'docs\architecture\overview.md' -InitializeIfEmpty -Content @'
# DefenseOps Architecture

Dokumentasikan arsitektur konseptual dan implementasi DefenseOps di bagian ini.

Status: Draft.
'@
Ensure-File -RelativePath 'docs\deployment\installation.md' -InitializeIfEmpty -Content @'
# DefenseOps Installation

Dokumentasikan prasyarat, deployment mode, instalasi, konfigurasi, dan validasi DefenseOps di bagian ini.

Status: Draft.
'@

# 4. Add .gitignore only if it does not exist. Public CA certificates (*.pem) are not blanket-ignored.
Ensure-File -RelativePath '.gitignore' -Content @'
# Environment files and secrets
.env
.env.*
!.env.example
*.key
*.p12
*.pfx
secrets/

# Generated agent packages (do not commit deployment secrets)
agent/output/*
!agent/output/.gitkeep
*.tar
*.tar.gz
*.tgz
*.zip

# Benchmark results and temporary test data
benchmark/results/
benchmark/reports/generated/
benchmark/tmp/
*.fio

# Runtime and temporary files
*.log
*.tmp
*.pid
__pycache__/
*.py[cod]

# Editors and operating systems
.vscode/
.idea/
.DS_Store
Thumbs.db

# Backups created by this repair script
.structure-backup/
'@

# 5. Initialize empty metadata/scripts only. Non-empty scripts are preserved.
Ensure-File -RelativePath 'install.sh' -InitializeIfEmpty -Content @'
#!/usr/bin/env bash
set -Eeuo pipefail

# TODO: Main DefenseOps installation entry point. It will orchestrate
# prerequisite checks, deployment selection, configuration, and validation.
echo "[INFO] DefenseOps installer: implementation pending."
exit 2
'@
Ensure-File -RelativePath 'CHANGELOG.md' -InitializeIfEmpty -Content @'
# Changelog

All notable changes to DefenseOps will be documented here.

## [Unreleased]

- Repository structure aligned for deployment, integrations, agent packaging, and benchmark/capacity planning.
'@

$scriptFiles = @{
'scripts\install-requirements.sh' = @'
#!/usr/bin/env bash
set -Eeuo pipefail

# TODO: Detect supported OS, validate prerequisites, install missing packages,
# and apply approved host configuration. Do not make production changes yet.
echo "[INFO] DefenseOps requirements installer: implementation pending."
exit 2
'@
'scripts\check-server.sh' = @'
#!/usr/bin/env bash
set -Eeuo pipefail

# TODO: Collect OS, architecture, CPU, RAM, storage, network and virtualization
# inventory. This check must not run stress tests.
echo "[INFO] DefenseOps server inventory: implementation pending."
exit 2
'@
'scripts\install-dependencies.sh' = @'
#!/usr/bin/env bash
set -Eeuo pipefail

# TODO: Install only missing, supported dependencies. Preserve existing services.
echo "[INFO] DefenseOps dependency installation: implementation pending."
exit 2
'@
'scripts\configure.sh' = @'
#!/usr/bin/env bash
set -Eeuo pipefail

# TODO: Implement idempotent configuration for the selected deployment mode.
echo "[INFO] DefenseOps configuration: implementation pending."
exit 2
'@
'scripts\healthcheck.sh' = @'
#!/usr/bin/env bash
set -Eeuo pipefail

# TODO: Implement component-aware health checks for the selected deployment.
echo "[INFO] DefenseOps health check: implementation pending."
exit 2
'@
}
foreach ($file in $scriptFiles.GetEnumerator()) {
    Ensure-File -RelativePath $file.Key -InitializeIfEmpty -Content $file.Value
}

# 6. Add .gitkeep to selected directories so Git tracks intentionally empty folders.
$keepDirs = @('config','deployment\docker','deployment\native','docs\operations','docs\security','agent\output','benchmark\reports')
foreach ($dir in $keepDirs) { Ensure-File -RelativePath (Join-Path $dir '.gitkeep') -Content "Placeholder to keep this directory in Git.`n" }

# 7. Update only the README sections that are stale; all other prose is preserved.
$readmePath = Join-Path $RootPath 'README.md'
$readme = Get-Content -LiteralPath $readmePath -Raw -Encoding UTF8
$structureSection = @'
## Repository Structure

```text
DefenseOps/
├── README.md
├── LICENSE
├── COMMERCIAL-LICENSE.md
├── CHANGELOG.md
├── .gitignore
├── install.sh
├── docs/
│   ├── architecture/
│   ├── deployment/
│   ├── operations/
│   └── security/
├── scripts/
│   ├── install-requirements.sh
│   ├── check-server.sh
│   ├── install-dependencies.sh
│   ├── configure.sh
│   └── healthcheck.sh
├── config/
│   ├── manager/
│   ├── indexer/
│   ├── dashboard/
│   └── agent/
├── deployment/
│   ├── docker/
│   └── native/
├── detection/
│   ├── rules/
│   ├── decoders/
│   └── threat-intelligence/
├── response/
│   ├── active/
│   └── playbooks/
├── integrations/
├── monitoring/
├── agent/
│   ├── generator/
│   ├── templates/
│   ├── profiles/
│   └── output/          # Generated packages; ignored by Git
├── benchmark/
│   ├── engine/
│   ├── workload/
│   ├── analyzer/
│   ├── profiles/
│   └── reports/
├── examples/
└── tests/
```

`agent/` contains the Wazuh Agent installer-package generator. `benchmark/`
contains infrastructure benchmarking, workload simulation, and capacity
planning for DefenseOps Central Server and managed Docker Hosts.

'@
$licenseSection = @'
## License

DefenseOps is distributed under its **DefenseOps Source-Available License**
(see `LICENSE`). Use, study, modification, and source-based development are
governed by that license. Creating or distributing proprietary/closed-source
products derived from DefenseOps requires a separate written commercial
license from the copyright holder; see `COMMERCIAL-LICENSE.md`.

Copyright (c) 2026 Hendrawan Aprillia Ashari, S.T., M.Kom.

'@
$updated = $readme
$structureRegex = '(?ms)^## Repository Structure\s*.*?(?=^##\s|\z)'
$licenseRegex = '(?ms)^## License\s*.*?(?=^##\s|\z)'
if ($updated -match $structureRegex) { $updated = [regex]::Replace($updated, $structureRegex, $structureSection, 1) }
else { $updated = $updated.TrimEnd() + "`r`n`r`n" + $structureSection }
if ($updated -match $licenseRegex) { $updated = [regex]::Replace($updated, $licenseRegex, $licenseSection, 1) }
else { $updated = $updated.TrimEnd() + "`r`n`r`n" + $licenseSection }
if ($updated -ne $readme -and $script:PSCmdlet.ShouldProcess($readmePath, 'Perbarui bagian Repository Structure dan License')) {
    Backup-ExistingFile -Path $readmePath
    Write-TextFileNoBom -Path $readmePath -Content $updated
    Write-Host '[OK] README.md diperbarui.' -ForegroundColor Green
}

Write-Host ''
Write-Host 'Perapian struktur DefenseOps selesai.' -ForegroundColor Green
Write-Host "Root: $RootPath"
if ($script:BackupCreated) { Write-Host "Backup file yang diubah: $script:BackupRoot" -ForegroundColor Yellow }
Write-Host 'Catatan: script ini hanya merapikan struktur dan metadata; tidak menginstal Wazuh atau menjalankan benchmark.' -ForegroundColor Yellow
