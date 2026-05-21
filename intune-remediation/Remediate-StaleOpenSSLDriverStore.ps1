<#
Intune Proactive Remediation remediation script.

Purpose:
  Remove unused/stale DriverStore packages that contain OpenSSL DLLs.

Safety:
  - Uses pnputil only.
  - Does not manually delete DriverStore files or folders.
  - Does not use /force.
  - Skips packages that appear in use by a device.
  - Skips packages when they are the only package with that original INF name.
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
$LogPath = Join-Path $LogRoot "Remediation-$Stamp.log"
$BeforeCsv = Join-Path $LogRoot "Remediation-Before-$Stamp.csv"
$AfterCsv = Join-Path $LogRoot "Remediation-After-$Stamp.csv"
$DecisionCsv = Join-Path $LogRoot "Remediation-Decisions-$Stamp.csv"

function Write-Log {
    param([Parameter(Mandatory = $true)][string]$Message)

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

        if ($Line -match "^\s*Original Name:\s*(.+)$") {
            $Current.OriginalName = $Matches[1].Trim()
            continue
        }

        if ($Line -match "^\s*Provider Name:\s*(.+)$") {
            $Current.ProviderName = $Matches[1].Trim()
            continue
        }

        if ($Line -match "^\s*Class Name:\s*(.+)$") {
            $Current.ClassName = $Matches[1].Trim()
            continue
        }

        if ($Line -match "^\s*Driver Version:\s*(.+)$") {
            $Current.DriverVersion = $Matches[1].Trim()
            continue
        }

        if ($Line -match "^\s*Signer Name:\s*(.+)$") {
            $Current.SignerName = $Matches[1].Trim()
            continue
        }
    }

    if ($Current.Count -gt 0) {
        $Packages.Add([pscustomobject]$Current)
    }

    return $Packages
}

function Test-DriverPackageInUse {
    param(
        [Parameter(Mandatory = $true)][string]$PublishedName,
        [Parameter(Mandatory = $true)][string[]]$DeviceOutput
    )

    $Pattern = "^\s*Driver Name:\s*$([regex]::Escape($PublishedName))\s*$"
    return [bool]($DeviceOutput | Select-String -Pattern $Pattern)
}

function Get-OriginalInfFromFileRepositoryPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $Match = [regex]::Match($Path, "\\FileRepository\\(?<folder>[^\\]+)")
    if (-not $Match.Success) {
        return ""
    }

    $Folder = $Match.Groups["folder"].Value
    $InfPart = $Folder -replace "\.inf_(amd64|x86|arm64|arm)_[0-9a-f]+$", ".inf"
    return $InfPart
}

function Get-OpenSSLDriverStoreFindings {
    $DriverPackages = @(Get-DriverPackages)
    $DeviceDriverOutput = @(pnputil /enum-devices /drivers)
    $DriverStoreFiles = @(Get-ChildItem "C:\Windows\System32\DriverStore\FileRepository" -Recurse -Force -Include "libssl*.dll", "libcrypto*.dll" -ErrorAction SilentlyContinue)
    $Findings = New-Object System.Collections.Generic.List[object]

    Write-Log "Published driver packages enumerated: $($DriverPackages.Count)"
    Write-Log "OpenSSL files found in FileRepository: $($DriverStoreFiles.Count)"

    if ($DriverPackages.Count -eq 0 -and $DriverStoreFiles.Count -gt 0) {
        Write-Log "WARNING: pnputil enumerated zero driver packages while OpenSSL files exist. Parser may be incompatible with this pnputil locale/version."
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
            continue
        }

        $SiblingCount = $Packages.Count

        foreach ($Package in $Packages) {
            $InUse = Test-DriverPackageInUse -PublishedName $Package.PublishedName -DeviceOutput $DeviceDriverOutput
            $HasReplacementCandidate = ($SiblingCount -gt 1)

            if ($InUse) {
                $Status = "InUseManualReview"
            }
            elseif (-not $HasReplacementCandidate) {
                $Status = "OnlyPackageManualReview"
            }
            else {
                $Status = "UnusedRemovableCandidate"
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
        }
    }

    return $Findings
}

Write-Log "Stale DriverStore OpenSSL remediation started."

$Before = @(Get-OpenSSLDriverStoreFindings)
$Before | Export-Csv -Path $BeforeCsv -NoTypeInformation -Encoding UTF8
$Before | Select-Object FullName, OriginalName, PublishedName, ProviderName, DriverVersion, SameOriginalInfPackageCount, HasReplacementCandidate, InUseByDevice, Status | Export-Csv -Path $DecisionCsv -NoTypeInformation -Encoding UTF8
Write-Log "Before findings: $($Before.Count)"
Write-Log "Before CSV: $BeforeCsv"
Write-Log "Decision CSV: $DecisionCsv"

$CandidatePackages = @(
    $Before |
        Where-Object { $_.Status -eq "UnusedRemovableCandidate" -and $_.PublishedName } |
        Select-Object PublishedName, OriginalName, ProviderName, ClassName, DriverVersion -Unique
)

if ($CandidatePackages.Count -eq 0) {
    Write-Log "No unused/removable DriverStore OpenSSL packages found. Nothing to remove."
    exit 0
}

$AnyFailure = $false

foreach ($Package in $CandidatePackages) {
    Write-Log "Candidate package: Published=$($Package.PublishedName) Original=$($Package.OriginalName) Provider=$($Package.ProviderName) Class=$($Package.ClassName) Version=$($Package.DriverVersion)"

    $FreshDeviceOutput = @(pnputil /enum-devices /drivers)
    if (Test-DriverPackageInUse -PublishedName $Package.PublishedName -DeviceOutput $FreshDeviceOutput) {
        Write-Log "Skipping package because it appears in use: $($Package.PublishedName)"
        continue
    }

    Write-Log "Running command: pnputil /delete-driver $($Package.PublishedName) /uninstall"
    $Output = @(pnputil /delete-driver $Package.PublishedName /uninstall 2>&1)
    foreach ($Line in $Output) {
        Write-Log "pnputil: $Line"
    }

    $ExitCode = $LASTEXITCODE
    Write-Log "pnputil exit code for $($Package.PublishedName): $ExitCode"

    if ($ExitCode -ne 0) {
        $AnyFailure = $true
    }
}

# Defender hygiene pass: refresh signatures and trigger a quick scan after removal.
# Rationale: the OpenSSL DLLs cleaned up here are tied to known CVEs; the scan
# helps catch residual copies outside DriverStore. Cmdlets are absent on servers
# without Defender and on EDR-managed endpoints - failures are non-fatal.
Write-Log "Running command: Update-MpSignature"
try {
    Update-MpSignature
    Write-Log "Update-MpSignature completed."
}
catch {
    Write-Log "Update-MpSignature failed: $($_.Exception.Message)"
}

Write-Log "Running command: Start-MpScan -ScanType QuickScan"
try {
    Start-MpScan -ScanType QuickScan
    Write-Log "Start-MpScan -ScanType QuickScan completed or was triggered."
}
catch {
    Write-Log "Start-MpScan -ScanType QuickScan failed: $($_.Exception.Message)"
}

$After = @(Get-OpenSSLDriverStoreFindings)
$After | Export-Csv -Path $AfterCsv -NoTypeInformation -Encoding UTF8
Write-Log "After findings: $($After.Count)"
Write-Log "After CSV: $AfterCsv"

if ($AnyFailure) {
    Write-Log "Remediation completed with one or more pnputil failures."
    exit 1
}

$RemainingCandidates = @($After | Where-Object { $_.Status -eq "UnusedRemovableCandidate" -and $_.PublishedName })
if ($RemainingCandidates.Count -gt 0) {
    Write-Log "Remediation completed, but unused/removable OpenSSL DriverStore packages remain."
    exit 1
}

Write-Log "Remediation completed successfully or only manual-review/in-use findings remain."
exit 0
