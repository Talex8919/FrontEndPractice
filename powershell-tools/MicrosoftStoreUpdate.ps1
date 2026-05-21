# ================================================
# Microsoft Store Update Detection & Remediation
# Run as Administrator
# ================================================

# Auto-elevate to Administrator if not already
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Restarting as Administrator..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -File `"$PSCommandPath`""
    exit
}

# ------------------------------------------------
# DETECTION: Check which apps have pending updates
# ------------------------------------------------
Write-Host "`n=== DETECTION: Scanning for pending Store app updates ===" -ForegroundColor Cyan

$updatesFound = @()

try {
    # Check via winget for available upgrades
    $wingetOutput = winget upgrade --source msstore 2>&1
    $lines = $wingetOutput | Where-Object { $_ -match '\S' }

    foreach ($line in $lines) {
        if ($line -notmatch 'Name|---|----|winget|No applicable' -and $line -match '\w') {
            $updatesFound += $line.Trim()
        }
    }

    if ($updatesFound.Count -gt 0) {
        Write-Host "Pending updates detected via winget:" -ForegroundColor Yellow
        $updatesFound | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
    } else {
        Write-Host "No pending updates found via winget." -ForegroundColor Green
    }
} catch {
    Write-Host "winget detection skipped: $_" -ForegroundColor Yellow
}

# Check AppX packages for known update-pending state
Write-Host "`nChecking AppX package states..." -ForegroundColor Cyan
$pendingApps = Get-AppxPackage -AllUsers | Where-Object {
    $_.Status -ne 'Ok' -or $_.PackageUserInformation.InstallState -eq 'Staged'
} 2>$null

if ($pendingApps) {
    Write-Host "Apps with non-OK or staged state:" -ForegroundColor Yellow
    $pendingApps | Select-Object Name, Status | Format-Table -AutoSize
} else {
    Write-Host "All AppX packages report OK state." -ForegroundColor Green
}

# ------------------------------------------------
# REMEDIATION
# ------------------------------------------------
Write-Host "`n=== REMEDIATION: Starting update process ===" -ForegroundColor Cyan

# Step 1: winget upgrade all
Write-Host "`n--- Step 1: winget upgrade ---" -ForegroundColor Cyan
try {
    winget upgrade --all --accept-source-agreements --accept-package-agreements
    Write-Host "winget upgrade complete." -ForegroundColor Green
} catch {
    Write-Host "winget failed: $_" -ForegroundColor Yellow
}

# Step 2: Trigger Microsoft Store internal update scan via MDM
Write-Host "`n--- Step 2: Triggering Store internal update scan ---" -ForegroundColor Cyan
try {
    $wmiObj = Get-WmiObject -Namespace "root\cimv2\mdm\dmmap" `
              -Class "MDM_EnterpriseModernAppManagement_AppManagement01"
    $wmiObj.UpdateScanMethod()
    Write-Host "Store update scan triggered successfully." -ForegroundColor Green
} catch {
    Write-Host "MDM scan not supported on this edition: $_" -ForegroundColor Yellow
}

# Step 3: Re-register stuck Store apps
Write-Host "`n--- Step 3: Re-registering stuck Store apps ---" -ForegroundColor Cyan
$failed  = 0
$success = 0
Get-AppxPackage -AllUsers | ForEach-Object {
    try {
        Add-AppxPackage -DisableDevelopmentMode `
            -Register "$($_.InstallLocation)\AppXManifest.xml" `
            -ErrorAction SilentlyContinue
        $success++
    } catch {
        $failed++
    }
}
Write-Host "Re-registered: $success apps. Skipped/failed: $failed" -ForegroundColor Green

# Step 4: Reset Microsoft Store cache
Write-Host "`n--- Step 4: Resetting Microsoft Store cache ---" -ForegroundColor Cyan
try {
    Stop-Process -Name "WinStore.App" -Force -ErrorAction SilentlyContinue
    & wsreset.exe
    Write-Host "Store cache reset triggered." -ForegroundColor Green
} catch {
    Write-Host "wsreset failed: $_" -ForegroundColor Yellow
}

# ------------------------------------------------
# SUMMARY
# ------------------------------------------------
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "All steps complete." -ForegroundColor Green
Write-Host "Open Microsoft Store > Library and verify remaining updates." -ForegroundColor White
Write-Host "================================================`n" -ForegroundColor Cyan
