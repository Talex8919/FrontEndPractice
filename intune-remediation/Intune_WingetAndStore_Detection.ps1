#Requires -Version 5.1
<#
.SYNOPSIS
    Intune Proactive Remediation - Detection Script
    Checks for pending winget upgrades OR if Store remediation is overdue.

.NOTES
    Run As: SYSTEM
    Architecture: 64-bit
    Exit 0 = Compliant   (no winget updates and Store remediation is current)
    Exit 1 = Non-Compliant (trigger remediation)
#>

$LogFile       = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\Intune_WingetAndStore_Detection.log"
$TimestampFile = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\Intune_WingetAndStore_LastRun.txt"
$MaxDaysSinceStoreRemediation = 7   # Re-run Store steps even if no winget updates

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

try {
    Write-Log '=== Detection start ==='

    # --- Check 1: Winget updates available ---
    $winget = Find-Winget
    if ($winget) {
        Write-Log "winget path: $winget"
        $output = & $winget upgrade --include-unknown --accept-source-agreements 2>&1

        # Strip progress bars, spinner chars and blank lines before logging
        $cleanOutput = $output | Where-Object {
            $_ -and
            $_ -notmatch '^\s*[-\\|/]\s*$' -and
            $_ -notmatch '%\s*\|' -and
            $_ -notmatch 'KB\s*/\s*\d' -and
            $_ -notmatch '^\s+$'
        }
        Write-Log "winget output: $($cleanOutput -join ' | ')"

        $summaryLine = $output | Where-Object { $_ -match '\d+\s+upgrade' }
        if ($summaryLine) {
            Write-Log "Winget updates found - non-compliant. ($summaryLine)"
            exit 1
        }
        Write-Log 'No winget updates found.'
    }
    else {
        Write-Log 'winget not found - skipping winget check.'
    }

    # --- Check 2: Store remediation overdue ---
    if (Test-Path $TimestampFile) {
        $raw      = Get-Content $TimestampFile -Raw
        $lastRun  = [datetime]::Parse($raw.Trim())
        $daysSince = ((Get-Date) - $lastRun).TotalDays
        Write-Log "Last Store remediation: $($lastRun.ToString('yyyy-MM-dd HH:mm:ss')) ($([math]::Round($daysSince,1)) days ago)"

        if ($daysSince -gt $MaxDaysSinceStoreRemediation) {
            Write-Log "Store remediation overdue - non-compliant."
            exit 1
        }
    }
    else {
        Write-Log 'No Store remediation timestamp found - non-compliant.'
        exit 1
    }

    Write-Log 'No updates and Store remediation current - compliant.'
    exit 0
}
catch {
    Write-Log "ERROR: $_"
    exit 0
}
