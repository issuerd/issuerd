<#
.SYNOPSIS
    Start the Issuerd daemon in a visible console window on the user's desktop.

.DESCRIPTION
    When an agent runs the Issuerd executable directly, the process usually
    inherits the agent's hidden console and the developer cannot see it on the
    desktop.  This script explicitly launches the daemon inside Windows Terminal
    (wt.exe) so logs are visible in a real window.

.PARAMETER Binary
    Path to the issuerd.exe binary.  Defaults to target/debug/issuerd.exe.

.PARAMETER Config
    Path to the TOML/YAML/JSON config file.  Defaults to examples/issuerd.agent-test.toml
    (suitable for dev with InMemory storage).

.EXAMPLE
    .\scripts\start-issuerd-dev.ps1
    .\scripts\start-issuerd-dev.ps1 -Binary target\release\issuerd.exe -Config issuerd.toml
#>
param(
    [string]$Binary = "target\debug\issuerd.exe",
    [string]$Config = "examples\issuerd.agent-test.toml"
)

$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
Push-Location $root

try {
    $absBinary = Resolve-Path $Binary
    $absConfig = Resolve-Path $Config

    # Prefer Windows Terminal because it always creates a visible desktop window
    # even when the agent is running in a non-interactive / hidden console.
    $wt = Get-Command "wt.exe" -ErrorAction SilentlyContinue
    if ($wt) {
        $wtPath = $wt.Source
    } else {
        # Fallback to the packaged Windows Terminal executable.
        $wtPath = "C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.24.11321.0_x64__8wekyb3d8bbwe\wt.exe"
    }

    if (Test-Path $wtPath) {
        # wt.exe syntax: wt.exe cmd /k "<command>"
        # The command string is passed as the last argument to cmd /k.
        $command = "cd /d `"$root`" && `"$absBinary`" daemon -c `"$absConfig`""
        Write-Host "Launching Issuerd in Windows Terminal: $wtPath"
        Start-Process -FilePath $wtPath -ArgumentList "cmd", "/k", $command
    } else {
        # Best-effort fallback: open a normal cmd window.  On Windows 11 this
        # usually opens in Windows Terminal and is visible; on older systems it
        # may still be hidden if the agent has no interactive desktop.
        Write-Warning "wt.exe not found; falling back to cmd.exe."
        $command = "cd /d `"$root`" && `"$absBinary`" daemon -c `"$absConfig`""
        Start-Process -FilePath "cmd.exe" -ArgumentList "/k", $command -WindowStyle Normal
    }

    Start-Sleep -Seconds 2
    $issuerd = Get-Process -Name "issuerd" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($issuerd) {
        Write-Host "Issuerd started. PID: $($issuerd.Id)" -ForegroundColor Green
    } else {
        Write-Warning "Issuerd process not detected; the window may show an error."
    }
} finally {
    Pop-Location
}
