<#
Intune Proactive Remediation remediation script.

Targets:
  - Microsoft Paint
  - Microsoft Photos
  - Microsoft OfficeHub / Microsoft 365 Hub Store app
  - Lenovo Store apps such as Lenovo Vantage / Commercial Vantage / Companion / Settings
  - Zoom installed via Microsoft Store (Appx)
  - Zoom installed manually via MSI or per-user EXE installer (Win32)

Actions:
  - Stop running target app processes.
  - Remove installed Appx packages for all users where supported.
  - Remove provisioned Appx packages so they do not return for new users.
  - Uninstall Win32 Zoom installs found in machine and per-user uninstall registry keys.
  - Trigger Defender signature update and quick scan after cleanup.

Safety:
  - Does not manually delete files from C:\Program Files\WindowsApps.
  - Does not remove Lenovo drivers or core Lenovo services.
  - Does not remove Lenovo Fn/function key service.
  - Only removes Win32 entries whose DisplayName starts with "Zoom" and whose
    Publisher (when present) contains "Zoom Video Communications".
#>

$ErrorActionPreference = "Continue"

$TargetPackagePatterns = @(
    "Microsoft.Paint",
    "Microsoft.Windows.Photos",
    "Microsoft.MicrosoftOfficeHub",
    "E046963F.LenovoCompanion",
    "E046963F.LenovoSettings",
    "E046963F.LenovoVantage",
    "E046963F.LenovoCommercialVantage",
    "LenovoCorporation.LenovoVantage",
    "LenovoCorporation.LenovoCommercialVantage",
    "ZoomVideoCommunications.*"
)

$TargetProcessPatterns = @(
    "mspaint",
    "PaintStudio.View",
    "Photos",
    "Microsoft.Photos",
    "OfficeHub",
    "LenovoVantage",
    "CommercialVantage",
    "LenovoCommercialVantage",
    "LenovoCompanion",
    "LenovoSettings",
    "Zoom",
    "CptHost",
    "airhost",
    "aomhost64",
    "ZoomOutlookIMPlugin"
)

function New-LogRoot {
    $Candidates = @(
        "C:\ProgramData\AppCleanup-Paint-Photos-Lenovo",
        "C:\Users\Public\Desktop\AppCleanup-Paint-Photos-Lenovo-Logs",
        $env:TEMP
    )

    foreach ($Candidate in $Candidates) {
        try {
            New-Item -ItemType Directory -Force -Path $Candidate -ErrorAction Stop | Out-Null
            return $Candidate
        }
        catch {
            continue
        }
    }

    return $env:TEMP
}

$LogRoot = New-LogRoot
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogPath = Join-Path $LogRoot "Remediation-$Stamp.log"
$BeforeCsv = Join-Path $LogRoot "Remediation-Before-$Stamp.csv"
$AfterCsv = Join-Path $LogRoot "Remediation-After-$Stamp.csv"

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)
    $Line = "$(Get-Date -Format s) $Message"
    Write-Output $Line
    Add-Content -Path $LogPath -Value $Line -Encoding UTF8
}

function Test-TargetName {
    param([Parameter(Mandatory)][string]$Name)

    foreach ($Pattern in $TargetPackagePatterns) {
        if ($Name -like $Pattern) {
            return $true
        }
    }

    return $false
}

function Get-Win32ZoomTargets {
    $Result = New-Object System.Collections.Generic.List[object]

    $UninstallRoots = New-Object System.Collections.Generic.List[object]
    $UninstallRoots.Add([pscustomobject]@{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"; Scope = "Machine-x64" })
    $UninstallRoots.Add([pscustomobject]@{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"; Scope = "Machine-x86" })

    try {
        $UserHives = @(Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction Stop |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notlike '*_Classes' })
        foreach ($Hive in $UserHives) {
            $UninstallRoots.Add([pscustomobject]@{
                Path  = "Registry::$($Hive.Name)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
                Scope = "User-$($Hive.PSChildName)"
            })
        }
    }
    catch {
        Write-Log "Enumerating HKEY_USERS failed: $($_.Exception.Message)"
    }

    foreach ($Root in $UninstallRoots) {
        if (-not (Test-Path -Path $Root.Path)) { continue }

        try {
            $Keys = @(Get-ChildItem -Path $Root.Path -ErrorAction Stop)
        }
        catch {
            Write-Log "Reading $($Root.Path) failed: $($_.Exception.Message)"
            continue
        }

        foreach ($Key in $Keys) {
            try {
                $Props = Get-ItemProperty -Path $Key.PSPath -ErrorAction Stop
            }
            catch { continue }

            $DisplayName = $Props.DisplayName
            if (-not $DisplayName) { continue }
            if ($DisplayName -notlike "Zoom*") { continue }

            $Publisher = $Props.Publisher
            if ($Publisher -and $Publisher -notlike "*Zoom Video Communications*") { continue }

            $IsMsi = ($Props.WindowsInstaller -eq 1)

            $Result.Add([pscustomobject]@{
                Type                 = "Win32ZoomInstall"
                Name                 = $DisplayName
                Version              = $Props.DisplayVersion
                Publisher            = $Publisher
                UninstallString      = $Props.UninstallString
                QuietUninstallString = $Props.QuietUninstallString
                WindowsInstaller     = $IsMsi
                ProductCode          = $Key.PSChildName
                Scope                = $Root.Scope
                RegistryPath         = $Key.PSPath
            })
        }
    }

    return $Result
}

function Invoke-Win32ZoomUninstall {
    param([Parameter(Mandatory)][object]$Install)

    $Label = "$($Install.Name) [$($Install.Scope)\$($Install.ProductCode)]"

    if ($Install.WindowsInstaller -and $Install.ProductCode -match '^\{[0-9A-Fa-f-]+\}$') {
        $MsiArgs = @("/x", $Install.ProductCode, "/qn", "/norestart")
        Write-Log "Uninstalling MSI: $Label -> msiexec.exe $($MsiArgs -join ' ')"
        try {
            $Proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $MsiArgs -Wait -PassThru -ErrorAction Stop
            Write-Log "msiexec exit code for $Label : $($Proc.ExitCode)"
            return ($Proc.ExitCode -in @(0, 1605, 1614, 1641, 3010))
        }
        catch {
            Write-Log "msiexec failed for $Label : $($_.Exception.Message)"
            return $false
        }
    }

    $Cmd = $Install.QuietUninstallString
    if (-not $Cmd) { $Cmd = $Install.UninstallString }
    if (-not $Cmd) {
        Write-Log "No uninstall string for $Label"
        return $false
    }

    $FilePath = $null
    $ArgString = ""

    if ($Cmd -match '^\s*"([^"]+)"\s*(.*)$') {
        $FilePath = $Matches[1]
        $ArgString = $Matches[2]
    }
    elseif ($Cmd -match '^\s*(\S+)\s*(.*)$') {
        $FilePath = $Matches[1]
        $ArgString = $Matches[2]
    }
    else {
        $FilePath = $Cmd
    }

    if ($ArgString -notmatch '(?i)(/silent|/quiet|/qn|/S\b)') {
        if ($ArgString) {
            $ArgString = "$ArgString /silent"
        }
        else {
            $ArgString = "/silent"
        }
    }

    if (-not (Test-Path -Path $FilePath)) {
        Write-Log "Uninstaller path not found for $Label : $FilePath"
        return $false
    }

    Write-Log "Uninstalling EXE: $Label -> `"$FilePath`" $ArgString"
    try {
        $Proc = Start-Process -FilePath $FilePath -ArgumentList $ArgString -Wait -PassThru -ErrorAction Stop
        Write-Log "Uninstaller exit code for $Label : $($Proc.ExitCode)"
        return ($Proc.ExitCode -in @(0, 3010))
    }
    catch {
        Write-Log "Uninstaller failed for $Label : $($_.Exception.Message)"
        return $false
    }
}

function Get-TargetPackages {
    $Findings = New-Object System.Collections.Generic.List[object]

    try {
        $InstalledPackages = @(Get-AppxPackage -AllUsers -ErrorAction Stop)
        foreach ($Package in $InstalledPackages) {
            if (Test-TargetName -Name $Package.Name) {
                $Findings.Add([pscustomobject]@{
                    Type = "InstalledAppxPackage"
                    Name = $Package.Name
                    Version = $Package.Version
                    PackageFullName = $Package.PackageFullName
                    InstallLocation = $Package.InstallLocation
                })
            }
        }
    }
    catch {
        Write-Log "Get-AppxPackage -AllUsers failed: $($_.Exception.Message)"
    }

    try {
        $ProvisionedPackages = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)
        foreach ($Package in $ProvisionedPackages) {
            if ((Test-TargetName -Name $Package.DisplayName) -or (Test-TargetName -Name $Package.PackageName)) {
                $Findings.Add([pscustomobject]@{
                    Type = "ProvisionedAppxPackage"
                    Name = $Package.DisplayName
                    Version = $Package.Version
                    PackageFullName = $Package.PackageName
                    InstallLocation = ""
                })
            }
        }
    }
    catch {
        Write-Log "Get-AppxProvisionedPackage failed: $($_.Exception.Message)"
    }

    try {
        $Win32ZoomTargets = @(Get-Win32ZoomTargets)
        foreach ($ZoomTarget in $Win32ZoomTargets) {
            $Findings.Add([pscustomobject]@{
                Type = "Win32ZoomInstall"
                Name = $ZoomTarget.Name
                Version = $ZoomTarget.Version
                PackageFullName = "$($ZoomTarget.Scope)\$($ZoomTarget.ProductCode)"
                InstallLocation = $ZoomTarget.RegistryPath
            })
        }
    }
    catch {
        Write-Log "Win32 Zoom scan failed: $($_.Exception.Message)"
    }

    return $Findings
}

function Stop-TargetProcesses {
    Write-Log "Checking for running target app processes."

    $Processes = @(Get-Process -ErrorAction SilentlyContinue)

    foreach ($Process in $Processes) {
        $ProcessName = $Process.ProcessName
        $ProcessPath = ""

        try {
            $ProcessPath = $Process.Path
        }
        catch {
            $ProcessPath = ""
        }

        $ShouldStop = $false
        foreach ($Pattern in $TargetProcessPatterns) {
            if ($ProcessName -like $Pattern) {
                $ShouldStop = $true
                break
            }
        }

        if (-not $ShouldStop -and $ProcessPath -like "*\WindowsApps\*") {
            foreach ($PackagePattern in $TargetPackagePatterns) {
                if ($ProcessPath -like "*$PackagePattern*") {
                    $ShouldStop = $true
                    break
                }
            }
        }

        if ($ShouldStop) {
            Write-Log "Stopping process: Name=$($Process.ProcessName), Id=$($Process.Id), Path=$ProcessPath"
            try {
                Stop-Process -Id $Process.Id -Force -ErrorAction Stop
                Write-Log "Stopped process Id=$($Process.Id)"
            }
            catch {
                Write-Log "Failed to stop process Id=$($Process.Id): $($_.Exception.Message)"
            }
        }
    }
}

Write-Log "App cleanup remediation started."

$Before = @(Get-TargetPackages)
$Before | Sort-Object Type, Name, PackageFullName | Export-Csv -Path $BeforeCsv -NoTypeInformation -Encoding UTF8
Write-Log "Targets before remediation: $($Before.Count)"
Write-Log "Before CSV: $BeforeCsv"

if ($Before.Count -gt 0) {
    Stop-TargetProcesses
}
else {
    Write-Log "No targets to remove; skipping process termination."
}

foreach ($Package in ($Before | Where-Object { $_.Type -eq "InstalledAppxPackage" } | Sort-Object PackageFullName -Unique)) {
    Write-Log "Removing installed Appx package: $($Package.PackageFullName)"

    try {
        Remove-AppxPackage -Package $Package.PackageFullName -AllUsers -ErrorAction Stop
        Write-Log "Removed installed Appx package with -AllUsers: $($Package.PackageFullName)"
    }
    catch {
        Write-Log "Remove-AppxPackage -AllUsers failed for $($Package.PackageFullName): $($_.Exception.Message)"
        try {
            Remove-AppxPackage -Package $Package.PackageFullName -ErrorAction Stop
            Write-Log "Removed installed Appx package for current context: $($Package.PackageFullName)"
        }
        catch {
            Write-Log "Remove-AppxPackage failed for $($Package.PackageFullName): $($_.Exception.Message)"
        }
    }
}

foreach ($Package in ($Before | Where-Object { $_.Type -eq "ProvisionedAppxPackage" } | Sort-Object PackageFullName -Unique)) {
    Write-Log "Removing provisioned Appx package: $($Package.PackageFullName)"

    $ProvisionedRemoved = $false

    try {
        Remove-AppxProvisionedPackage -Online -PackageName $Package.PackageFullName -ErrorAction Stop | Out-Null
        Write-Log "Removed provisioned Appx package: $($Package.PackageFullName)"
        $ProvisionedRemoved = $true
    }
    catch {
        Write-Log "Remove-AppxProvisionedPackage failed for $($Package.PackageFullName): $($_.Exception.Message)"
    }

    if (-not $ProvisionedRemoved) {
        Write-Log "Running DISM fallback for provisioned package: $($Package.PackageFullName)"
        try {
            $DismOutput = @(dism.exe /Online /Remove-ProvisionedAppxPackage /PackageName:$($Package.PackageFullName) /NoRestart 2>&1)
            foreach ($Line in $DismOutput) {
                Write-Log "DISM: $Line"
            }
            Write-Log "DISM fallback exit code for $($Package.PackageFullName): $LASTEXITCODE"
        }
        catch {
            Write-Log "DISM fallback failed for $($Package.PackageFullName): $($_.Exception.Message)"
        }
    }
}

Write-Log "Skipping wsreset.exe -i during app removal to avoid Store app rehydration during remediation."

Write-Log "Scanning for Win32 Zoom installs."
$Win32ZoomBefore = @(Get-Win32ZoomTargets)
Write-Log "Win32 Zoom targets found: $($Win32ZoomBefore.Count)"

if ($Win32ZoomBefore.Count -gt 0) {
    Stop-TargetProcesses

    foreach ($ZoomInstall in $Win32ZoomBefore) {
        Invoke-Win32ZoomUninstall -Install $ZoomInstall | Out-Null
    }
}

Write-Log "Running command: Update-MpSignature"
try {
    Update-MpSignature
    Write-Log "Update-MpSignature completed."
}
catch {
    Write-Log "Update-MpSignature failed: $($_.Exception.Message)"
}

Write-Log "Running command: Start-MpScan -ScanType QuickScan -AsJob"
try {
    Start-MpScan -ScanType QuickScan -AsJob -ErrorAction Stop | Out-Null
    Write-Log "Start-MpScan -ScanType QuickScan triggered asynchronously."
}
catch {
    Write-Log "Start-MpScan -ScanType QuickScan failed: $($_.Exception.Message)"
}

$After = @(Get-TargetPackages)

if ($After.Count -gt 0) {
    Write-Log "Targets still present after first pass. Running second installed-package removal pass."

    Stop-TargetProcesses

    foreach ($Package in ($After | Where-Object { $_.Type -like "InstalledAppxPackage*" } | Sort-Object PackageFullName -Unique)) {
        Write-Log "Second pass removing installed Appx package: $($Package.PackageFullName)"

        try {
            Remove-AppxPackage -Package $Package.PackageFullName -AllUsers -ErrorAction Stop
            Write-Log "Second pass removed installed Appx package with -AllUsers: $($Package.PackageFullName)"
        }
        catch {
            Write-Log "Second pass Remove-AppxPackage -AllUsers failed for $($Package.PackageFullName): $($_.Exception.Message)"
            try {
                Remove-AppxPackage -Package $Package.PackageFullName -ErrorAction Stop
                Write-Log "Second pass removed installed Appx package for current context: $($Package.PackageFullName)"
            }
            catch {
                Write-Log "Second pass Remove-AppxPackage failed for $($Package.PackageFullName): $($_.Exception.Message)"
            }
        }
    }

    Start-Sleep -Seconds 5
    $After = @(Get-TargetPackages)
}

$After | Sort-Object Type, Name, PackageFullName | Export-Csv -Path $AfterCsv -NoTypeInformation -Encoding UTF8
Write-Log "Targets after remediation: $($After.Count)"
Write-Log "After CSV: $AfterCsv"

foreach ($Remaining in ($After | Sort-Object Type, Name, PackageFullName)) {
    Write-Log "Remaining target: Type=$($Remaining.Type) Name=$($Remaining.Name) Version=$($Remaining.Version) Package=$($Remaining.PackageFullName)"
}

if ($After.Count -gt 0) {
    Write-Log "Remediation completed, but some targets remain. Review logs."
    exit 1
}

Write-Log "Remediation completed successfully. No target packages remain."
exit 0
