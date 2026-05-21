#Requires -Version 5.1
<#
.SYNOPSIS
    Intune Proactive Remediation - Detection Script
    Checks for pending winget, Microsoft Store, or Microsoft 365 updates,
    and whether scheduled maintenance (AppX re-registration, Store cache
    reset) is overdue.

.NOTES
    Run As: SYSTEM
    Architecture: 64-bit
    Exit 0 = Compliant   (nothing to update, maintenance is current)
    Exit 1 = Non-Compliant (trigger remediation)

    Checks performed:
      1. winget updates available (all sources incl. msstore)
      2. Microsoft Store app updates (msstore source explicitly)
      3. Microsoft 365 pending update (registry AvailableVersion vs VersionToReport)
      4. Scheduled maintenance overdue (timestamp > MaxDaysSinceLastRun days)
#>

$LogFile       = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\Intune_WingetAndStore_Detection.log"
$TimestampFile = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\Intune_WingetAndStore_LastRun.txt"
$MaxDaysSinceLastRun = 7   # Force full maintenance cycle every 7 days

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

function Get-CleanWingetOutput {
    param([string[]]$Output)
    $Output | Where-Object {
        $_ -and
        $_ -notmatch '^\s*[-\\|/]\s*$' -and
        $_ -notmatch '%\s*\|' -and
        $_ -notmatch '[KMGT]B\s*/\s*[\d.]' -and
        $_ -notmatch '^\s+$'
    }
}

try {
    Write-Log '=== Detection start ==='

    # ----------------------------------------------------------
    # Check 1: winget updates (all sources including msstore)
    # ----------------------------------------------------------
    $winget = Find-Winget
    if ($winget) {
        Write-Log "winget path: $winget"
        $output      = & $winget upgrade --include-unknown --accept-source-agreements 2>&1
        $cleanOutput = Get-CleanWingetOutput $output
        Write-Log "winget output: $($cleanOutput -join ' | ')"

        $summaryLine = $output | Where-Object { $_ -match '\d+\s+upgrade' }
        if ($summaryLine) {
            Write-Log "winget updates found - non-compliant. ($($summaryLine.Trim()))"
            exit 1
        }
        Write-Log 'No winget updates found.'

        # ----------------------------------------------------------
        # Check 2: Microsoft Store app updates (msstore source)
        # ----------------------------------------------------------
        $msOutput      = & $winget upgrade --source msstore --include-unknown --accept-source-agreements 2>&1
        $msCleanOutput = Get-CleanWingetOutput $msOutput
        Write-Log "msstore output: $($msCleanOutput -join ' | ')"

        $msSummary = $msOutput | Where-Object { $_ -match '\d+\s+upgrade' }
        if ($msSummary) {
            $pendingApps = $msOutput | Where-Object { $_ -match 'msstore\s*$' } |
                ForEach-Object { ($_ -split '\s{2,}')[0].Trim() }
            Write-Log "Store app updates found - non-compliant. Apps: $($pendingApps -join ', ')"
            exit 1
        }
        Write-Log 'No Microsoft Store app updates found.'
    }
    else {
        Write-Log 'winget not found - skipping winget and Store checks.'
    }

    # ----------------------------------------------------------
    # Check 3: Microsoft 365 pending update (Click-to-Run)
    # ----------------------------------------------------------
    $c2rConfig  = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    $c2rUpdates = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Updates'

    if (Test-Path $c2rConfig) {
        $currentVer   = (Get-ItemProperty $c2rConfig  -ErrorAction SilentlyContinue).VersionToReport
        $availableVer = (Get-ItemProperty $c2rUpdates -ErrorAction SilentlyContinue).AvailableVersion

        if ($availableVer -and $availableVer -ne $currentVer) {
            Write-Log "Microsoft 365 update available - non-compliant. Current: $currentVer -> Available: $availableVer"
            exit 1
        }
        Write-Log "Microsoft 365 is current (version: $currentVer)"
    }
    else {
        Write-Log 'Microsoft 365 (Click-to-Run) not detected on this device.'
    }

    # ----------------------------------------------------------
    # Check 4: Scheduled maintenance overdue (AppX, Store cache, M365)
    # ----------------------------------------------------------
    if (Test-Path $TimestampFile) {
        $lastRun   = [datetime]::Parse((Get-Content $TimestampFile -Raw).Trim())
        $daysSince = [math]::Round(((Get-Date) - $lastRun).TotalDays, 1)
        Write-Log "Last full remediation: $($lastRun.ToString('yyyy-MM-dd HH:mm:ss')) ($daysSince days ago)"

        if ($daysSince -gt $MaxDaysSinceLastRun) {
            Write-Log "Maintenance overdue ($daysSince days) - non-compliant."
            exit 1
        }
    }
    else {
        Write-Log 'No remediation timestamp found - non-compliant.'
        exit 1
    }

    Write-Log 'All checks passed - compliant.'
    exit 0
}
catch {
    Write-Log "ERROR: $_"
    exit 0
}
