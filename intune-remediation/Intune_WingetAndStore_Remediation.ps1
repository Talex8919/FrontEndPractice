#Requires -Version 5.1
<#
.SYNOPSIS
    Intune Proactive Remediation - Remediation Script
    Runs winget upgrades, triggers Microsoft Store scan, re-registers
    stuck Store apps, and resets the Store cache.

.NOTES
    Run As: SYSTEM
    Architecture: 64-bit
    Exit 0 = Success
    Exit 1 = Failure
#>

$LogFile       = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\Intune_WingetAndStore_Remediation.log"
$TimestampFile = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\Intune_WingetAndStore_LastRun.txt"

# Packages excluded from winget --all (managed elsewhere or self-updating)
$ExcludeList = @(
    'Microsoft.Teams'               # Self-updating; MSI installs handled by M365
    'Microsoft.EdgeWebView2Runtime' # Edge-managed component
    'Microsoft.PowerBI'             # Managed via separate Intune app deployment
)

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts  $Message" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

function Find-Winget {
    $resolvers = @(
        { Get-Command winget -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source },
        {
            $base = 'C:\Program Files\WindowsApps'
            if (Test-Path $base) {
                Get-ChildItem $base -Filter 'Microsoft.DesktopAppInstaller_*' -Directory |
                    Sort-Object Name -Descending |
                    ForEach-Object { Join-Path $_.FullName 'winget.exe' } |
                    Where-Object { Test-Path $_ } |
                    Select-Object -First 1
            }
        }
    )
    foreach ($r in $resolvers) {
        $path = & $r
        if ($path -and (Test-Path $path)) { return $path }
    }
    return $null
}

# ---------------------------------------------------------------------------
try {
    Write-Log '=== Remediation start ==='

    # --------------------------------------------------------
    # Step 1: Winget upgrade --all
    # --------------------------------------------------------
    Write-Log '--- Step 1: winget upgrade --all ---'
    $winget = Find-Winget

    if ($winget) {
        Write-Log "winget path: $winget"
        Write-Log "Excluded packages: $($ExcludeList -join ', ')"

        foreach ($id in $ExcludeList) {
            Write-Log "Pinning: $id"
            & $winget pin add --id $id --accept-source-agreements 2>&1 | Out-Null
        }

        $wingetArgs = @(
            'upgrade'
            '--all'
            '--include-unknown'
            '--accept-source-agreements'
            '--accept-package-agreements'
            '--silent'
            '--disable-interactivity'
        )

        Write-Log "Running: $winget $($wingetArgs -join ' ')"
        $output = & $winget @wingetArgs 2>&1
        foreach ($line in $output) { Write-Log "  $line" }

        foreach ($id in $ExcludeList) {
            & $winget pin remove --id $id 2>&1 | Out-Null
        }

        Write-Log 'winget upgrade complete.'

        # --- Step 1b: Force-update Store apps via winget msstore source ---
        Write-Log '--- Step 1b: winget upgrade --source msstore ---'
        $msStoreArgs = @(
            'upgrade'
            '--all'
            '--source', 'msstore'
            '--accept-source-agreements'
            '--accept-package-agreements'
            '--silent'
            '--disable-interactivity'
        )
        Write-Log "Running: $winget $($msStoreArgs -join ' ')"
        $msStoreOutput = & $winget @msStoreArgs 2>&1
        foreach ($line in $msStoreOutput) { Write-Log "  $line" }
        Write-Log 'msstore upgrade complete.'
    }
    else {
        Write-Log 'winget not found - skipping winget step.'
    }

    # --------------------------------------------------------
    # Step 2: Trigger Microsoft Store MDM update scan
    # --------------------------------------------------------
    Write-Log '--- Step 2: Microsoft Store MDM update scan ---'
    try {
        $wmiObj = Get-WmiObject -Namespace 'root\cimv2\mdm\dmmap' `
                  -Class 'MDM_EnterpriseModernAppManagement_AppManagement01' `
                  -ErrorAction Stop
        $wmiObj.UpdateScanMethod() | Out-Null
        Write-Log 'Store MDM scan triggered successfully.'
    }
    catch {
        Write-Log "Store MDM scan failed (may not be supported on this edition): $_"
    }

    # --------------------------------------------------------
    # Step 3: Re-register stuck Store / AppX packages
    # --------------------------------------------------------
    Write-Log '--- Step 3: Re-registering AppX packages ---'
    $success = 0
    $failed  = 0
    Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
        $manifest = Join-Path $_.InstallLocation 'AppXManifest.xml'
        if (Test-Path $manifest) {
            try {
                Add-AppxPackage -DisableDevelopmentMode -Register $manifest -ErrorAction SilentlyContinue
                $success++
            }
            catch {
                $failed++
            }
        }
    }
    Write-Log "AppX re-registration - succeeded: $success, skipped/failed: $failed"

    # --------------------------------------------------------
    # Step 4: Reset Microsoft Store cache (wsreset)
    # --------------------------------------------------------
    Write-Log '--- Step 4: Resetting Store cache ---'
    try {
        Stop-Process -Name 'WinStore.App' -Force -ErrorAction SilentlyContinue
        $wsreset = "$env:SystemRoot\System32\wsreset.exe"
        if (Test-Path $wsreset) {
            Start-Process -FilePath $wsreset -WindowStyle Hidden -Wait
            Write-Log 'Store cache reset complete.'
        }
        else {
            Write-Log 'wsreset.exe not found - skipping.'
        }
    }
    catch {
        Write-Log "Store cache reset failed: $_"
    }

    # --------------------------------------------------------
    # Write timestamp so detection knows remediation ran
    # --------------------------------------------------------
    (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') | Out-File -FilePath $TimestampFile -Encoding utf8 -Force
    Write-Log "Timestamp written to: $TimestampFile"

    Write-Log '=== Remediation complete ==='
    exit 0
}
catch {
    Write-Log "FATAL: $_"
    exit 1
}
