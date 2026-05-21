# Intune Proactive Remediation detection script - Webex Full Cleanup
# Exit 0 = no Webex evidence anywhere. Device is clean.
# Exit 1 = any Webex evidence found. Remediation should run.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

if ($env:PROCESSOR_ARCHITEW6432 -and (Test-Path "$env:WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe")) {
    & "$env:WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -NoProfile -File $PSCommandPath
    exit $LASTEXITCODE
}

# Broad match: every Webex/Cisco Spark/Webex Teams variant.
$WebexNamePattern = '(?i)(webex|cisco spark|cisco webex|webex teams|webex meetings|webex productivity|webex recording|webex outlook|webex events|webex training|webex support|webex access anywhere|webex remote)'

function Get-PropertyValue {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($property -and $null -ne $property.Value) {
        return [string]$property.Value
    }

    return ''
}

function New-Evidence {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Detail
    )

    [pscustomobject]@{
        Source = $Source
        Detail = $Detail
    }
}

function Get-RegistryEvidence {
    $machinePaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($path in $machinePaths) {
        foreach ($item in @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)) {
            $displayName = Get-PropertyValue -Object $item -Name 'DisplayName'
            if ($displayName -and $displayName -match $WebexNamePattern) {
                $version = Get-PropertyValue -Object $item -Name 'DisplayVersion'
                $regPath = ([string]$item.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::','')
                New-Evidence -Source 'Registry' -Detail "Name='$displayName' Version='$version' Key='$regPath'"
            }
        }
    }

    foreach ($hive in @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -notlike '*_Classes' -and $_.PSChildName -ne '.DEFAULT' })) {
        $userUninstall = "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        foreach ($item in @(Get-ItemProperty -Path $userUninstall -ErrorAction SilentlyContinue)) {
            $displayName = Get-PropertyValue -Object $item -Name 'DisplayName'
            if ($displayName -and $displayName -match $WebexNamePattern) {
                $version = Get-PropertyValue -Object $item -Name 'DisplayVersion'
                $regPath = ([string]$item.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::','')
                New-Evidence -Source 'UserRegistry' -Detail "Name='$displayName' Version='$version' Key='$regPath'"
                continue
            }

            $childName = [string]$item.PSChildName
            if ($childName -match '(?i)(ActiveTouchMeetingClient|WebEx|CiscoSpark|CiscoWebex)') {
                $regPath = ([string]$item.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::','')
                New-Evidence -Source 'UserRegistry' -Detail "Key='$regPath'"
            }
        }
    }

    $componentRoots = @(
        'HKLM:\SOFTWARE\Cisco Spark',
        'HKLM:\SOFTWARE\WebEx',
        'HKLM:\SOFTWARE\Cisco Systems, Inc.\Webex',
        'HKLM:\SOFTWARE\WOW6432Node\Cisco Spark',
        'HKLM:\SOFTWARE\WOW6432Node\WebEx',
        'HKLM:\SOFTWARE\WOW6432Node\Cisco Systems, Inc.\Webex'
    )

    foreach ($root in $componentRoots) {
        if (Test-Path -LiteralPath $root) {
            New-Evidence -Source 'ComponentRegistry' -Detail "Key='$root'"
        }
    }

    $outlookAddins = @(
        'HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins\Cisco.WebEx.Outlook.AddIn',
        'HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins\WebEx Productivity Tools',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins\Cisco.WebEx.Outlook.AddIn',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins\WebEx Productivity Tools'
    )

    foreach ($root in $outlookAddins) {
        if (Test-Path -LiteralPath $root) {
            New-Evidence -Source 'OutlookAddin' -Detail "Key='$root'"
        }
    }
}

function Get-FileSystemEvidence {
    $machineFolders = @(
        "$env:ProgramFiles\Webex",
        "$env:ProgramFiles\Cisco Spark",
        "${env:ProgramFiles(x86)}\Webex",
        "${env:ProgramFiles(x86)}\Cisco Spark",
        "$env:ProgramData\Webex",
        "$env:ProgramData\Cisco Spark",
        "$env:ProgramData\Cisco\Webex"
    )

    foreach ($folder in $machineFolders) {
        if ($folder -and (Test-Path -LiteralPath $folder)) {
            New-Evidence -Source 'MachineFolder' -Detail $folder
        }
    }

    $profilesRoot = Join-Path $env:SystemDrive 'Users'
    $excludedProfiles = @('Public', 'Default', 'Default User', 'All Users')

    foreach ($profile in @(Get-ChildItem -Path $profilesRoot -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin $excludedProfiles })) {
        $userFolders = @(
            'AppData\Local\Programs\Cisco Spark',
            'AppData\Local\Programs\Webex',
            'AppData\Local\CiscoSparkLauncher',
            'AppData\Local\CiscoSpark',
            'AppData\Local\Webex',
            'AppData\Local\WebEx',
            'AppData\Roaming\Webex',
            'AppData\Roaming\WebEx',
            'AppData\Roaming\Cisco Spark',
            'AppData\Roaming\Cisco Webex Meetings'
        )

        foreach ($relativePath in $userFolders) {
            $target = Join-Path $profile.FullName $relativePath
            if (Test-Path -LiteralPath $target) {
                New-Evidence -Source 'UserFolder' -Detail $target
            }
        }
    }
}

function Get-ServiceEvidence {
    foreach ($service in @(Get-Service -ErrorAction SilentlyContinue)) {
        if ($service.Name -match '(?i)(webex|ciscospark|ciscowebex)' -or $service.DisplayName -match $WebexNamePattern) {
            New-Evidence -Source 'Service' -Detail "Name='$($service.Name)' Display='$($service.DisplayName)' Status='$($service.Status)'"
        }
    }
}

function Get-ScheduledTaskEvidence {
    try {
        foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            if ($task.TaskName -match $WebexNamePattern -or $task.TaskPath -match $WebexNamePattern) {
                New-Evidence -Source 'ScheduledTask' -Detail "Path='$($task.TaskPath)' Name='$($task.TaskName)'"
            }
        }
    } catch {
        # Get-ScheduledTask is unavailable on some SKUs - ignore.
    }
}

$evidence = @()
$evidence += @(Get-RegistryEvidence)
$evidence += @(Get-FileSystemEvidence)
$evidence += @(Get-ServiceEvidence)
$evidence += @(Get-ScheduledTaskEvidence)

if ($evidence.Count -eq 0) {
    Write-Output 'No Webex evidence detected. Device is clean.'
    exit 0
}

Write-Output "Webex evidence found ($($evidence.Count) item(s)). Remediation required."
foreach ($item in ($evidence | Sort-Object Source, Detail -Unique)) {
    Write-Output "Evidence: Source=$($item.Source) $($item.Detail)"
}

exit 1
