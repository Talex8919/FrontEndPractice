<#
Intune Proactive Remediation detection script.

Purpose:
  Detect stale DriverStore packages that contain OpenSSL DLLs.

Scope:
  C:\Windows\System32\DriverStore\FileRepository\*\libssl*.dll
  C:\Windows\System32\DriverStore\FileRepository\*\libcrypto*.dll

Exit codes:
  0 = No unused/stale OpenSSL driver package found.
  1 = One or more unused/stale OpenSSL driver packages found; remediation should run.

Safety:
  This script does not delete files and does not remove drivers.
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"

function New-LogRoot {
    $Candidates = @(
        "C:\ProgramData\DriverStore-StaleOpenSSL-Cleanup",
        "C:\Users\Public\Desktop\DriverStore-StaleOpenSSL-Cleanup-Logs",
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
$DecisionCsv = Join-Path $LogRoot "Detection-Decisions-$Stamp.csv"

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)
    $Line = "$(Get-Date -Format s) $Message"
    Write-Host $Line
    Add-Content -Path $LogPath -Value $Line -Encoding UTF8
}

function Get-DriverPackages {
    $Output = @(pnputil /enum-drivers)
    $Packages = New-Object System.Collections.Generic.List[object]
    $Current = [ordered]@{}

    foreach ($Line in $Output) {
        if ($Line -match "^\s*Published Name:\s*(.+)$") {
            if ($Current.Count -gt 0) {
                $Packages.Add([pscustomobject]$Current)
                $Current = [ordered]@{}
            }
            $Current.PublishedName = $Matches[1].Trim()
            continue
        }

        if ($Line -match "^\s*Original Name:\s*(.+)$") { $Current.OriginalName = $Matches[1].Trim(); continue }
        if ($Line -match "^\s*Provider Name:\s*(.+)$") { $Current.ProviderName = $Matches[1].Trim(); continue }
        if ($Line -match "^\s*Class Name:\s*(.+)$") { $Current.ClassName = $Matches[1].Trim(); continue }
        if ($Line -match "^\s*Driver Version:\s*(.+)$") { $Current.DriverVersion = $Matches[1].Trim(); continue }
        if ($Line -match "^\s*Signer Name:\s*(.+)$") { $Current.SignerName = $Matches[1].Trim(); continue }
    }

    if ($Current.Count -gt 0) {
        $Packages.Add([pscustomobject]$Current)
    }

    return $Packages
}

function Test-DriverPackageInUse {
    param(
        [Parameter(Mandatory)][string]$PublishedName,
        [Parameter(Mandatory)][string[]]$DeviceOutput
    )

    $Pattern = "^\s*Driver Name:\s*$([regex]::Escape($PublishedName))\s*$"
    return [bool]($DeviceOutput | Select-String -Pattern $Pattern)
}

function Get-OriginalInfFromFileRepositoryPath {
    param([Parameter(Mandatory)][string]$Path)

    $Match = [regex]::Match($Path, "\\FileRepository\\(?<folder>[^\\]+)")
    if (-not $Match.Success) {
        return ""
    }

    $Folder = $Match.Groups["folder"].Value
    $InfPart = $Folder -replace "\.inf_(amd64|x86|arm64|arm)_[0-9a-f]+$",".inf"
    return $InfPart
}

Write-Log "Stale DriverStore OpenSSL detection started."
Write-Log "Scanning path: C:\Windows\System32\DriverStore\FileRepository"
Write-Log "Searching for files: libssl*.dll and libcrypto*.dll"

try {
    $DriverPackages = @(Get-DriverPackages)
    $DeviceDriverOutput = @(pnputil /enum-devices /drivers)
}
catch {
    Write-Log "Driver enumeration failed: $($_.Exception.Message)"
    exit 1
}

$DriverStoreFiles = @(Get-ChildItem "C:\Windows\System32\DriverStore\FileRepository" -Recurse -Force -Include "libssl*.dll","libcrypto*.dll" -ErrorAction SilentlyContinue)

$Findings = New-Object System.Collections.Generic.List[object]
$Decisions = New-Object System.Collections.Generic.List[object]

Write-Log "Published driver packages enumerated: $($DriverPackages.Count)"
Write-Log "OpenSSL files found in FileRepository: $($DriverStoreFiles.Count)"

if ($DriverPackages.Count -eq 0 -and $DriverStoreFiles.Count -gt 0) {
    Write-Log "WARNING: pnputil enumerated zero driver packages while OpenSSL files exist. Parser may be incompatible with this pnputil locale/version. Skipping decisions."
}

foreach ($File in $DriverStoreFiles) {
    $OriginalInf = Get-OriginalInfFromFileRepositoryPath -Path $File.FullName
    $Packages = @($DriverPackages | Where-Object { $_.OriginalName -ieq $OriginalInf })
    $RepositoryFolder = ""
    $FolderMatch = [regex]::Match($File.FullName, "\\FileRepository\\(?<folder>[^\\]+)")
    if ($FolderMatch.Success) {
        $RepositoryFolder = $FolderMatch.Groups["folder"].Value
    }

    Write-Log "Found OpenSSL file: $($File.FullName)"
    Write-Log "Repository folder: $RepositoryFolder"
    Write-Log "Mapped original INF: $OriginalInf"
    Write-Log "Matching published packages for '$OriginalInf': $($Packages.Count)"

    if ($Packages.Count -eq 0) {
        Write-Log "Decision: ManualReview-NoPublishedPackageFound"
        $Findings.Add([pscustomobject]@{
            Status = "NoPublishedPackageFound"
            OriginalName = $OriginalInf
            PublishedName = ""
            ProviderName = ""
            ClassName = ""
            DriverVersion = ""
            SameOriginalInfPackageCount = 0
            HasReplacementCandidate = $false
            InUseByDevice = $false
            FileName = $File.Name
            FileVersion = $File.VersionInfo.FileVersion
            FullName = $File.FullName
            LastWriteTime = $File.LastWriteTime
        })
        $Decisions.Add([pscustomobject]@{
            FullName = $File.FullName
            RepositoryFolder = $RepositoryFolder
            OriginalName = $OriginalInf
            PublishedName = ""
            MatchingPackageCount = 0
            InUseByDevice = $false
            HasReplacementCandidate = $false
            Decision = "ManualReview-NoPublishedPackageFound"
        })
        continue
    }

    $SiblingCount = $Packages.Count

    foreach ($Package in $Packages) {
        $InUse = Test-DriverPackageInUse -PublishedName $Package.PublishedName -DeviceOutput $DeviceDriverOutput
        $HasReplacementCandidate = ($SiblingCount -gt 1)
        $Status = if ($InUse) {
            "InUseManualReview"
        }
        elseif (-not $HasReplacementCandidate) {
            "OnlyPackageManualReview"
        }
        else {
            "UnusedRemovableCandidate"
        }

        Write-Log "Package check: Published=$($Package.PublishedName), Provider=$($Package.ProviderName), Version=$($Package.DriverVersion), InUse=$InUse, SameOriginalInfPackageCount=$SiblingCount, HasReplacementCandidate=$HasReplacementCandidate, Decision=$Status"

        $Findings.Add([pscustomobject]@{
            Status = $Status
            OriginalName = $OriginalInf
            PublishedName = $Package.PublishedName
            ProviderName = $Package.ProviderName
            ClassName = $Package.ClassName
            DriverVersion = $Package.DriverVersion
            SameOriginalInfPackageCount = $SiblingCount
            HasReplacementCandidate = $HasReplacementCandidate
            InUseByDevice = $InUse
            FileName = $File.Name
            FileVersion = $File.VersionInfo.FileVersion
            FullName = $File.FullName
            LastWriteTime = $File.LastWriteTime
        })
        $Decisions.Add([pscustomobject]@{
            FullName = $File.FullName
            RepositoryFolder = $RepositoryFolder
            OriginalName = $OriginalInf
            PublishedName = $Package.PublishedName
            MatchingPackageCount = $SiblingCount
            InUseByDevice = $InUse
            HasReplacementCandidate = $HasReplacementCandidate
            Decision = $Status
        })
    }
}

$Findings | Export-Csv -Path $FindingCsv -NoTypeInformation -Encoding UTF8
$Decisions | Export-Csv -Path $DecisionCsv -NoTypeInformation -Encoding UTF8

$Removable = @($Findings | Where-Object { $_.Status -eq "UnusedRemovableCandidate" -and $_.PublishedName })
$Manual = @($Findings | Where-Object { $_.Status -ne "UnusedRemovableCandidate" })

Write-Log "OpenSSL DriverStore files found: $($DriverStoreFiles.Count)"
Write-Log "Removable candidate findings: $($Removable.Count)"
Write-Log "Manual/review findings: $($Manual.Count)"
Write-Log "Findings CSV: $FindingCsv"
Write-Log "Decision CSV: $DecisionCsv"

if ($Removable.Count -gt 0) {
    Write-Log "Detection result: unused/stale OpenSSL DriverStore packages found."
    exit 1
}

Write-Log "Detection result: no unused/stale OpenSSL DriverStore packages found."
exit 0
