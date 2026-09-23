#!/usr/bin/env pwsh
# Issuerd Federation Stack startup script (PowerShell)
# Requires Docker Desktop and Git for Windows (bash) or WSL for the .sh version.

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Resolve-Path (Join-Path $scriptDir "..")
Push-Location $projectRoot

Write-Host "==> Starting Issuerd Federation Stack <==" -ForegroundColor Cyan
Write-Host ""

# Start infrastructure services
docker compose -f docker-compose.integration.yml up -d issuerd-postgres samba-dc openldap redis

# Wait for PostgreSQL
Write-Host -NoNewline "Waiting for PostgreSQL..."
while ($true) {
    $ready = docker exec issuerd-postgres pg_isready -U issuerd -d issuerd 2>$null
    if ($LASTEXITCODE -eq 0) { break }
    Write-Host -NoNewline "."
    Start-Sleep -Seconds 1
}
Write-Host " ready" -ForegroundColor Green

# Wait for Samba DC
Write-Host -NoNewline "Waiting for Samba DC..."
while ($true) {
    $ready = docker exec issuerd-samba-dc ldapsearch -x -H ldap://localhost -D 'CN=Administrator,CN=Users,DC=test,DC=issuerd,DC=local' -w 'AdminPass123!' -b 'DC=test,DC=issuerd,DC=local' '(sAMAccountName=testuser)' 2>$null
    if ($LASTEXITCODE -eq 0) { break }
    Write-Host -NoNewline "."
    Start-Sleep -Seconds 2
}
Write-Host " ready" -ForegroundColor Green

# Wait for OpenLDAP (probe server readiness; no seed users exist by default)
Write-Host -NoNewline "Waiting for OpenLDAP..."
$attempts = 0
while ($true) {
    $ready = docker exec issuerd-openldap ldapsearch -x -H ldap://localhost -D 'cn=admin,dc=test,dc=issuerd,dc=local' -w 'admin' -b 'dc=test,dc=issuerd,dc=local' '(objectClass=*)' 2>$null
    if ($LASTEXITCODE -eq 0) { break }
    Write-Host -NoNewline "."
    Start-Sleep -Seconds 2
    $attempts++
    if ($attempts -ge 60) {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Error "OpenLDAP did not become ready in time"
    }
}
Write-Host " ready" -ForegroundColor Green

# Check for keytab
$keytab = "tests/fixtures/samba-dc/shared/issuerd.keytab"
if (Test-Path $keytab) {
    Write-Host "Kerberos keytab found" -ForegroundColor Green
} else {
    Write-Host "WARNING: Kerberos keytab not found yet. It may still be generating." -ForegroundColor Yellow
    Write-Host "  If using the kerberos realm, ensure $keytab exists before starting Issuerd."
}

Write-Host ""
Write-Host "Infrastructure is up. Start Issuerd with:" -ForegroundColor Cyan
Write-Host "  Copy-Item examples/issuerd.example.toml issuerd.toml   # first run only; set provision = `"examples/provision.federation.yaml`""
Write-Host "  cargo run --release --bin issuerd -- daemon -c issuerd.toml"
Write-Host ""
Write-Host "Admin UI:     https://issuerd.test.internal"
Write-Host "Admin user:   admin / admin"
Write-Host "Realms:       master, ad, samba, openldap, kerberos"
Write-Host ""
Write-Host "To wipe PostgreSQL data and re-provision from scratch:" -ForegroundColor Cyan
Write-Host "  docker compose -f docker-compose.integration.yml down; docker volume rm issuerd_issuerd_postgres_data"
Write-Host "  .\scripts\federation-up.ps1"
Write-Host "  cargo run --release --bin issuerd -- daemon -c issuerd.toml"

Pop-Location
