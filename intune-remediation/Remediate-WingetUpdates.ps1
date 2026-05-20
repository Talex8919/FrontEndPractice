#Requires -Version 5.1
<#
.SYNOPSIS
    Intune Proactive Remediation - Remediation Script
    Silently upgrades all winget packages running as SYSTEM.

.NOTES
    Run As: SYSTEM
    Architecture: 64-bit
    Exit 0 = Success
    Exit 1 = Failure
#>

$LogFile = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\WingetUpgrade-Remediation.log"

# --- Packages to skip (add IDs as needed) ---
# These are typically self-updating, cause reboots, or are managed elsewhere.
$ExcludeList = @(
    'Microsoft.Teams'               # Self-updating; MSI installs handled by M365
    'Microsoft.Edge'                # Managed via Intune/ADMX policy
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

function Invoke-WingetUpgrade {
    param(
        [string]$WingetPath,
        [string[]]$Exclude
    )

    # Build the exclusion filter string for the log
    $excludeStr = $Exclude -join ', '
    Write-Log "Excluded packages: $excludeStr"

    $wingetArgs = @(
        'upgrade'
        '--all'
        '--include-unknown'
        '--accept-source-agreements'
        '--accept-package-agreements'
        '--silent'
        '--scope', 'machine'    # Prefer machine-scope installs; falls back gracefully
        '--force'               # Overwrite a running version where the installer allows it
        '--disable-interactivity'
    )

    # Exclude individual packages before running --all
    foreach ($id in $Exclude) {
        Write-Log "Pinning/excluding: $id"
        # winget pin add prevents --all from touching the package this session
        & $WingetPath pin add --id $id --accept-source-agreements 2>&1 | Out-Null
    }

    Write-Log "Running: $WingetPath $($wingetArgs -join ' ')"
    $output = & $WingetPath @wingetArgs 2>&1

    foreach ($line in $output) { Write-Log "  $line" }

    # Remove temporary pins so normal user-initiated upgrades still work
    foreach ($id in $Exclude) {
        & $WingetPath pin remove --id $id 2>&1 | Out-Null
    }

    return $output
}

# ---------------------------------------------------------------------------
try {
    Write-Log '=== Remediation start ==='

    $winget = Find-Winget
    if (-not $winget) {
        Write-Log 'winget not found — cannot remediate.'
        exit 1
    }
    Write-Log "winget path: $winget"

    $result = Invoke-WingetUpgrade -WingetPath $winget -Exclude $ExcludeList

    # Detect hard failures (installer crashes, source errors, etc.)
    $failures = $result | Where-Object {
        $_ -match 'failed|error|0x[0-9A-Fa-f]{8}' -and
        $_ -notmatch 'No applicable|already installed'
    }

    if ($failures) {
        Write-Log "Completed with warnings/failures:"
        $failures | ForEach-Object { Write-Log "  WARN: $_" }
        # Still exit 0 — partial upgrades are better than a reported failure loop.
        # Change to exit 1 if you want Intune to keep retrying on any error.
        exit 0
    }

    Write-Log '=== Remediation complete ==='
    exit 0
}
catch {
    Write-Log "FATAL: $_"
    exit 1
}
