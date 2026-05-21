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
        $output | Where-Object {
            $_ -and
            $_ -notmatch '^\s*[-\\|/]\s*$' -and
            $_ -notmatch '[KMGT]B\s*/\s*[\d.]' -and
            $_ -notmatch '%\s*\|' -and
            $_ -notmatch '^\s+$'
        } | ForEach-Object { Write-Log "  $_" }

        foreach ($id in $ExcludeList) {
            & $winget pin remove --id $id 2>&1 | Out-Null
        }

        Write-Log 'winget upgrade complete.'

        # --- Step 1b: Force-update Store apps via winget msstore source ---
        Write-Log '--- Step 1b: winget upgrade --source msstore ---'

        # Get ALL pending Store updates dynamically
        $msCheckOutput = & $winget upgrade --source msstore --include-unknown --accept-source-agreements 2>&1

        # Parse display name + Store ID from every table row ending with 'msstore'
        $pendingStoreUpdates = $msCheckOutput | Where-Object { $_ -match 'msstore\s*$' } | ForEach-Object {
            $cols = $_ -split '\s{2,}'
            if ($cols.Count -ge 2) {
                [PSCustomObject]@{ Name = $cols[0].Trim(); Id = $cols[1].Trim() }
            }
        } | Where-Object { $_ -and $_.Name }

        if ($pendingStoreUpdates) {
            Write-Log "Store apps needing update: $($pendingStoreUpdates.Name -join ', ')"

            # Load all AppX packages once to avoid repeated slow calls
            $allAppx = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue

            foreach ($update in $pendingStoreUpdates) {
                $displayName = $update.Name
                $appxPkg     = $null

                # Strategy 1: remove spaces from display name and match package name
                # e.g. "Windows Notepad" -> *WindowsNotepad*
                $noSpaces = $displayName -replace '\s+', ''
                $appxPkg  = $allAppx | Where-Object { $_.Name -like "*$noSpaces*" } | Select-Object -First 1

                # Strategy 2: every significant word (>3 chars) must appear in the package name
                # e.g. "Python Install Manager" -> Name contains "Python" AND "Install" AND "Manager"
                if (-not $appxPkg) {
                    $words   = $displayName -split '\s+' | Where-Object { $_.Length -gt 3 }
                    if ($words) {
                        $appxPkg = $allAppx | Where-Object {
                            $pkg = $_
                            ($words | Where-Object { $pkg.Name -notlike "*$_*" }).Count -eq 0
                        } | Select-Object -First 1
                    }
                }

                # Strategy 3: first significant word only (broadest fallback)
                if (-not $appxPkg) {
                    $firstWord = $displayName -split '\s+' | Where-Object { $_.Length -gt 4 } | Select-Object -First 1
                    if ($firstWord) {
                        $appxPkg = $allAppx | Where-Object { $_.Name -like "*$firstWord*" } | Select-Object -First 1
                    }
                }

                if ($appxPkg -and $appxPkg.InstallLocation -and
                    (Test-Path $appxPkg.InstallLocation -ErrorAction SilentlyContinue)) {

                    $installPath  = $appxPkg.InstallLocation.TrimEnd('\')
                    $runningProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
                        try {
                            $_.Path -and $_.Path.StartsWith($installPath, [System.StringComparison]::OrdinalIgnoreCase)
                        } catch { $false }
                    }

                    if ($runningProcs) {
                        foreach ($proc in $runningProcs) {
                            Write-Log "Force-closing '$($proc.Name)' (PID $($proc.Id)) for update: $displayName"
                            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                        }
                        Start-Sleep -Seconds 2
                    } else {
                        Write-Log "Not running: $displayName (matched package: $($appxPkg.Name))"
                    }
                } else {
                    Write-Log "Could not match AppX package for: $displayName (Store ID: $($update.Id))"
                }
            }
        } else {
            Write-Log 'No pending Store app updates found.'
        }

        # Run the Store upgrade - all blocking processes are now closed
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
        if (-not $_.InstallLocation) { return }   # skip packages with no install path
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
            $wsProc      = Start-Process -FilePath $wsreset -WindowStyle Hidden -PassThru -ErrorAction Stop
            $wsCompleted = $wsProc.WaitForExit(60000)   # 60-second timeout - wsreset hangs as SYSTEM
            if ($wsCompleted) {
                Write-Log 'Store cache reset complete.'
            }
            else {
                $wsProc.Kill() | Out-Null
                Write-Log 'Store cache reset timed out (60s) - killed and continuing.'
            }
        }
        else {
            Write-Log 'wsreset.exe not found - skipping.'
        }
    }
    catch {
        Write-Log "Store cache reset failed: $_"
    }

    # --------------------------------------------------------
    # Step 5: Update Microsoft 365 (Click-to-Run)
    # --------------------------------------------------------
    Write-Log '--- Step 5: Microsoft 365 update ---'
    $c2rPaths = @(
        'C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe'
        'C:\Program Files (x86)\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe'
    )
    $c2rClient = $c2rPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($c2rClient) {
        Write-Log "OfficeC2RClient path: $c2rClient"
        try {
            # forceappshutdown=true closes Word, Excel, Outlook etc. before updating
            $c2rArgs = '/update user displaylevel=false forceappshutdown=true updatepromptuser=false'
            Write-Log "Running: $c2rClient $c2rArgs"
            $c2rProc = Start-Process -FilePath $c2rClient -ArgumentList $c2rArgs -PassThru -NoNewWindow

            # Wait up to 30 minutes for the update handoff to complete
            $finished = $c2rProc.WaitForExit(1800000)
            if ($finished) {
                $exitCode = if ($null -ne $c2rProc.ExitCode) { $c2rProc.ExitCode } else { '0 (success)' }
                Write-Log "Microsoft 365 update completed. Exit code: $exitCode"
            }
            else {
                Write-Log 'Microsoft 365 update still running after 30 min - continuing (update proceeds in background).'
            }
        }
        catch {
            Write-Log "Microsoft 365 update failed: $_"
        }
    }
    else {
        Write-Log 'OfficeC2RClient.exe not found - Microsoft 365 (Click-to-Run) is not installed on this device.'
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
