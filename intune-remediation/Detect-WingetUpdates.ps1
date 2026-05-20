#Requires -Version 5.1
<#
.SYNOPSIS
    Intune Proactive Remediation - Detection Script
    Checks whether winget has pending upgrades.

.NOTES
    Run As: SYSTEM
    Architecture: 64-bit
    Exit 0  = Compliant   (no updates or winget unavailable — nothing to do)
    Exit 1  = Non-Compliant (updates found — trigger remediation)
#>

$LogFile = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\WingetUpgrade-Detection.log"

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts  $Message" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

function Find-Winget {
    # Prefer the stable AppInstaller path available to SYSTEM
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

try {
    Write-Log '=== Detection start ==='

    $winget = Find-Winget
    if (-not $winget) {
        Write-Log 'winget not found — marking compliant (nothing to remediate).'
        exit 0
    }
    Write-Log "winget path: $winget"

    # --include-unknown surfaces packages whose version cannot be determined
    $output = & $winget upgrade --include-unknown --accept-source-agreements 2>&1
    Write-Log "winget output: $($output -join ' | ')"

    # Winget always prints "X upgrades available." when updates exist.
    # Everything else (spinners, "No installed package found", "No applicable update") means compliant.
    $summaryLine = $output | Where-Object { $_ -match '\d+\s+upgrade' }

    if ($summaryLine) {
        Write-Log "Updates found — non-compliant. ($summaryLine)"
        exit 1
    }

    Write-Log 'No updates — compliant.'
    exit 0
}
catch {
    Write-Log "ERROR: $_"
    exit 0   # Don't trigger remediation on unexpected errors
}
