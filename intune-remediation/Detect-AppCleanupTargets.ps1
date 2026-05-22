<#
Intune Proactive Remediation detection script.

Targets:
  - Microsoft Paint
  - Microsoft Photos
  - Microsoft OfficeHub / Microsoft 365 Hub Store app
  - Lenovo Store apps such as Lenovo Vantage / Commercial Vantage / Companion / Settings
  - Zoom installed via Microsoft Store (Appx)
  - Zoom installed manually via MSI or per-user EXE installer (Win32)

Exit codes:
  0 = No cleanup targets found.
  1 = One or more cleanup targets found; run remediation.

Notes:
  This script detects app packages and registry uninstall entries. It does not
  manually inspect/delete files from C:\Program Files\WindowsApps.
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
$LogPath = Join-Path $LogRoot "Detection-$Stamp.log"
$FindingCsv = Join-Path $LogRoot "Detection-Findings-$Stamp.csv"

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

            $Result.Add([pscustomobject]@{
                Type            = "Win32ZoomInstall"
                Name            = $DisplayName
                Version         = $Props.DisplayVersion
                PackageFullName = "$($Root.Scope)\$($Key.PSChildName)"
                InstallLocation = $Props.InstallLocation
            })
        }
    }

    return $Result
}

Write-Log "App cleanup detection started."

$Findings = New-Object System.Collections.Generic.List[object]
$QueryFailed = $false

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
    $QueryFailed = $true

    try {
        $InstalledPackages = @(Get-AppxPackage -ErrorAction Stop)
        foreach ($Package in $InstalledPackages) {
            if (Test-TargetName -Name $Package.Name) {
                $Findings.Add([pscustomobject]@{
                    Type = "InstalledAppxPackageCurrentUser"
                    Name = $Package.Name
                    Version = $Package.Version
                    PackageFullName = $Package.PackageFullName
                    InstallLocation = $Package.InstallLocation
                })
            }
        }
    }
    catch {
        Write-Log "Get-AppxPackage current-user fallback failed: $($_.Exception.Message)"
    }
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
    $QueryFailed = $true
}

try {
    $Win32ZoomFindings = @(Get-Win32ZoomTargets)
    foreach ($Item in $Win32ZoomFindings) {
        $Findings.Add($Item)
    }
}
catch {
    Write-Log "Win32 Zoom scan failed: $($_.Exception.Message)"
    $QueryFailed = $true
}

$Findings | Sort-Object Type, Name, PackageFullName | Export-Csv -Path $FindingCsv -NoTypeInformation -Encoding UTF8

Write-Log "Findings: $($Findings.Count)"
Write-Log "Findings CSV: $FindingCsv"

if ($Findings.Count -gt 0) {
    Write-Log "Detection result: cleanup targets found."
    exit 1
}

if ($QueryFailed) {
    Write-Log "Detection result: package query failed. Returning remediation required to avoid a false clean result."
    exit 1
}

Write-Log "Detection result: no cleanup targets found."
exit 0
