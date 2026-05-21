# Intune Proactive Remediation - Webex Full Cleanup
# Pairs with Detect-WebexFullCleanup.ps1.
# Removes every Webex/Cisco Spark/Webex Teams variant: App, Meetings, Productivity Tools,
# Recording Player, Outlook Add-In, legacy Cisco Spark. Also deletes per-user app data.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\WebexFullCleanup.log"

if ($env:PROCESSOR_ARCHITEW6432 -and (Test-Path "$env:WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe")) {
    & "$env:WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -NoProfile -File $PSCommandPath
    exit $LASTEXITCODE
}

$logDirectory = Split-Path -Parent $LogPath
if (-not (Test-Path -LiteralPath $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
}

$WebexNamePattern = '(?i)(webex|cisco spark|cisco webex|webex teams|webex meetings|webex productivity|webex recording|webex outlook|webex events|webex training|webex support|webex access anywhere|webex remote)'

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)

    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Output $line
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
}

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

function New-UninstallEntry {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$DisplayName,
        [string]$DisplayVersion = '',
        [string]$Publisher = '',
        [string]$InstallLocation = '',
        [string]$RegistryPsPath = '',
        [string]$ProductCode = '',
        [string]$UninstallString = '',
        [string]$QuietUninstallString = ''
    )

    [pscustomobject]@{
        Source               = $Source
        DisplayName          = $DisplayName
        DisplayVersion       = $DisplayVersion
        Publisher            = $Publisher
        InstallLocation      = $InstallLocation
        RegistryPsPath       = $RegistryPsPath
        ProductCode          = $ProductCode
        UninstallString      = $UninstallString
        QuietUninstallString = $QuietUninstallString
    }
}

function Get-WebexUninstallEntries {
    $machinePaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($path in $machinePaths) {
        foreach ($item in @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)) {
            $displayName = Get-PropertyValue -Object $item -Name 'DisplayName'
            if ($displayName -and $displayName -match $WebexNamePattern) {
                New-UninstallEntry `
                    -Source 'Machine' `
                    -DisplayName $displayName `
                    -DisplayVersion (Get-PropertyValue -Object $item -Name 'DisplayVersion') `
                    -Publisher (Get-PropertyValue -Object $item -Name 'Publisher') `
                    -InstallLocation (Get-PropertyValue -Object $item -Name 'InstallLocation') `
                    -RegistryPsPath ([string]$item.PSPath) `
                    -ProductCode ([string]$item.PSChildName) `
                    -UninstallString (Get-PropertyValue -Object $item -Name 'UninstallString') `
                    -QuietUninstallString (Get-PropertyValue -Object $item -Name 'QuietUninstallString')
            }
        }
    }

    foreach ($hive in @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -notlike '*_Classes' -and $_.PSChildName -ne '.DEFAULT' })) {
        $userUninstall = "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        foreach ($item in @(Get-ItemProperty -Path $userUninstall -ErrorAction SilentlyContinue)) {
            $displayName = Get-PropertyValue -Object $item -Name 'DisplayName'
            $childName = [string]$item.PSChildName
            $isWebex = $false
            if ($displayName -and $displayName -match $WebexNamePattern) { $isWebex = $true }
            if ($childName -match '(?i)(ActiveTouchMeetingClient|WebEx|CiscoSpark|CiscoWebex)') { $isWebex = $true }

            if ($isWebex) {
                $effectiveName = $displayName
                if (-not $effectiveName) { $effectiveName = $childName }
                New-UninstallEntry `
                    -Source 'UserHive' `
                    -DisplayName $effectiveName `
                    -DisplayVersion (Get-PropertyValue -Object $item -Name 'DisplayVersion') `
                    -Publisher (Get-PropertyValue -Object $item -Name 'Publisher') `
                    -InstallLocation (Get-PropertyValue -Object $item -Name 'InstallLocation') `
                    -RegistryPsPath ([string]$item.PSPath) `
                    -ProductCode ([string]$item.PSChildName) `
                    -UninstallString (Get-PropertyValue -Object $item -Name 'UninstallString') `
                    -QuietUninstallString (Get-PropertyValue -Object $item -Name 'QuietUninstallString')
            }
        }
    }
}

function Get-MsiProductCode {
    param(
        [string]$ProductCode,
        [string]$UninstallString
    )

    if ($ProductCode -match '^\{[0-9A-Fa-f-]{36}\}$') {
        return $ProductCode
    }

    $match = [regex]::Match($UninstallString, '\{[0-9A-Fa-f-]{36}\}')
    if ($match.Success) {
        return $match.Value
    }

    return ''
}

function Invoke-Process {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string]$Arguments,
        [int[]]$SuccessExitCodes = @(0, 3010, 1605, 1614, 1641)
    )

    Write-Log "Running: $FilePath $Arguments"
    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
        Write-Log "Exit code: $($process.ExitCode)"
        return ($process.ExitCode -in $SuccessExitCodes)
    } catch {
        Write-Log "WARN: Failed to run '$FilePath'. $($_.Exception.Message)"
        return $false
    }
}

function Invoke-WebexUninstall {
    param([Parameter(Mandatory)]$Entry)

    Write-Log "Uninstalling: Source=$($Entry.Source) Name='$($Entry.DisplayName)' Version='$($Entry.DisplayVersion)'"

    $productCode = Get-MsiProductCode -ProductCode $Entry.ProductCode -UninstallString $Entry.UninstallString
    if ($productCode) {
        $safeName = ($Entry.DisplayName -replace '[^A-Za-z0-9._-]', '_')
        if (-not $safeName) { $safeName = $productCode }
        $msiLog = Join-Path $logDirectory "WebexFullCleanup-MSI-$safeName.log"
        $arguments = "/x $productCode /qn /norestart /L*v `"$msiLog`""
        return Invoke-Process -FilePath "$env:WINDIR\System32\msiexec.exe" -Arguments $arguments
    }

    $command = $Entry.QuietUninstallString
    if (-not $command) {
        $command = $Entry.UninstallString
    }

    if (-not $command) {
        Write-Log "WARN: No uninstall command for '$($Entry.DisplayName)'. Registry-only removal will follow."
        return $false
    }

    if ($command -notmatch '(?i)(/quiet|/qn|/silent|/s\b|--silent)') {
        $command = "$command /S /silent /quiet /norestart"
    }

    return Invoke-Process -FilePath "$env:ComSpec" -Arguments "/c `"$command`""
}

function Stop-WebexProcesses {
    $processNames = @(
        'Webex', 'WebexHost', 'WebexLauncher', 'WebexTeams',
        'CiscoCollabHost', 'CiscoCollabHostCef',
        'CiscoWebexStart', 'CiscoWebexLauncher', 'CiscoWebexHelper',
        'CiscoWebexVideoService', 'CiscoWebexConverter',
        'CiscoSparkLauncher', 'CiscoSpark',
        'atmgr', 'atrelay', 'atmccli', 'atcliun', 'aticleanup',
        'ptoneclk', 'ptUserSetting',
        'wbxtrace', 'wbxcheck'
    )

    foreach ($name in $processNames) {
        foreach ($process in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            Write-Log "Stopping process: $($process.ProcessName) PID=$($process.Id)"
            try {
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
            } catch {
                Write-Log "WARN: Could not stop process '$($process.ProcessName)'. $($_.Exception.Message)"
            }
        }
    }
}

function Stop-WebexServices {
    foreach ($service in @(Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '(?i)(webex|ciscospark|ciscowebex)' -or
        $_.DisplayName -match $WebexNamePattern
    })) {
        Write-Log "Stopping and removing service: Name='$($service.Name)' Display='$($service.DisplayName)'"
        try {
            Stop-Service -Name $service.Name -Force -ErrorAction Stop
        } catch {
            Write-Log "WARN: Could not stop service '$($service.Name)'. $($_.Exception.Message)"
        }

        $null = Invoke-Process -FilePath "$env:WINDIR\System32\sc.exe" -Arguments "delete `"$($service.Name)`"" -SuccessExitCodes @(0, 1060, 1072)
    }
}

function Remove-WebexScheduledTasks {
    try {
        foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskName -match $WebexNamePattern -or $_.TaskPath -match $WebexNamePattern
        })) {
            Write-Log "Removing scheduled task: Path='$($task.TaskPath)' Name='$($task.TaskName)'"
            try {
                Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
            } catch {
                Write-Log "WARN: Could not remove scheduled task '$($task.TaskName)'. $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Log "WARN: Get-ScheduledTask unavailable. $($_.Exception.Message)"
    }
}

function Remove-FolderIfPresent {
    param([Parameter(Mandatory)][string]$Path)

    if ($Path -and (Test-Path -LiteralPath $Path)) {
        Write-Log "Removing folder: $Path"
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        } catch {
            Write-Log "WARN: Could not remove '$Path'. $($_.Exception.Message)"
        }
    }
}

function Remove-FileIfPresent {
    param([Parameter(Mandatory)][string]$Path)

    if ($Path -and (Test-Path -LiteralPath $Path)) {
        Write-Log "Removing file: $Path"
        try {
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        } catch {
            Write-Log "WARN: Could not remove '$Path'. $($_.Exception.Message)"
        }
    }
}

function Remove-RegistryKeyIfPresent {
    param([Parameter(Mandatory)][string]$Path)

    if ($Path -and (Test-Path -LiteralPath $Path)) {
        Write-Log "Removing registry key: $Path"
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        } catch {
            Write-Log "WARN: Could not remove registry key '$Path'. $($_.Exception.Message)"
        }
    }
}

Write-Log '=== Webex Full Cleanup started ==='
Write-Log "Host: $env:COMPUTERNAME  User context: $env:USERNAME"

Stop-WebexProcesses
Stop-WebexServices
Remove-WebexScheduledTasks

# Pass 1: invoke each native uninstaller.
$entries = @(Get-WebexUninstallEntries | Sort-Object RegistryPsPath -Unique)
Write-Log "Uninstall entries discovered: $($entries.Count)"
foreach ($entry in $entries) {
    $null = Invoke-WebexUninstall -Entry $entry
}

# Pass 2: stop anything that respawned during uninstall.
Stop-WebexProcesses

# Pass 3: scrub leftover machine folders.
$machineFolders = @(
    "$env:ProgramFiles\Webex",
    "$env:ProgramFiles\Cisco Spark",
    "$env:ProgramFiles\Webex\Meetings",
    "$env:ProgramFiles\Webex\Productivity Tools",
    "${env:ProgramFiles(x86)}\Webex",
    "${env:ProgramFiles(x86)}\Cisco Spark",
    "${env:ProgramFiles(x86)}\Webex\Meetings",
    "${env:ProgramFiles(x86)}\Webex\Productivity Tools",
    "$env:ProgramData\Webex",
    "$env:ProgramData\Cisco Spark",
    "$env:ProgramData\Cisco\Webex"
)

foreach ($folder in $machineFolders) {
    Remove-FolderIfPresent -Path $folder
}

# Pass 4: scrub per-user program and data folders (DeleteUserData = true).
$profilesRoot = Join-Path $env:SystemDrive 'Users'
$excludedProfiles = @('Public', 'Default', 'Default User', 'All Users')

foreach ($profile in @(Get-ChildItem -Path $profilesRoot -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin $excludedProfiles })) {
    $userRelativePaths = @(
        'AppData\Local\Programs\Cisco Spark',
        'AppData\Local\Programs\Webex',
        'AppData\Local\CiscoSparkLauncher',
        'AppData\Local\CiscoSpark',
        'AppData\Local\Webex',
        'AppData\Local\WebEx',
        'AppData\Local\Cisco\Webex',
        'AppData\Roaming\Webex',
        'AppData\Roaming\WebEx',
        'AppData\Roaming\Cisco Spark',
        'AppData\Roaming\Cisco Webex Meetings',
        'AppData\Roaming\Cisco\Webex'
    )

    foreach ($relativePath in $userRelativePaths) {
        Remove-FolderIfPresent -Path (Join-Path $profile.FullName $relativePath)
    }

    $userShortcuts = @(
        'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Cisco Webex Meetings.lnk',
        'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Webex.lnk',
        'Desktop\Webex.lnk',
        'Desktop\Cisco Webex Meetings.lnk'
    )

    foreach ($relativePath in $userShortcuts) {
        Remove-FileIfPresent -Path (Join-Path $profile.FullName $relativePath)
    }
}

# Pass 5: shortcut sweep, machine-wide.
$shortcutPatterns = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Webex*.lnk",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Cisco Webex*.lnk",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Cisco Spark*.lnk",
    "$env:Public\Desktop\Webex*.lnk",
    "$env:Public\Desktop\Cisco Webex*.lnk",
    "$env:Public\Desktop\Cisco Spark*.lnk"
)

foreach ($pattern in $shortcutPatterns) {
    foreach ($file in @(Get-ChildItem -Path $pattern -Force -ErrorAction SilentlyContinue)) {
        Remove-FileIfPresent -Path $file.FullName
    }
}

# Pass 6: registry leftovers (component roots + Outlook add-in registrations).
$registryRoots = @(
    'HKLM:\SOFTWARE\Cisco Spark',
    'HKLM:\SOFTWARE\WebEx',
    'HKLM:\SOFTWARE\Cisco Systems, Inc.\Webex',
    'HKLM:\SOFTWARE\WOW6432Node\Cisco Spark',
    'HKLM:\SOFTWARE\WOW6432Node\WebEx',
    'HKLM:\SOFTWARE\WOW6432Node\Cisco Systems, Inc.\Webex',
    'HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins\Cisco.WebEx.Outlook.AddIn',
    'HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins\WebEx Productivity Tools',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins\Cisco.WebEx.Outlook.AddIn',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins\WebEx Productivity Tools'
)

foreach ($root in $registryRoots) {
    Remove-RegistryKeyIfPresent -Path $root
}

# Pass 7: per-user registry trees.
foreach ($hive in @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -notlike '*_Classes' -and $_.PSChildName -ne '.DEFAULT' })) {
    $userRoots = @(
        "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Cisco Spark",
        "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Cisco Spark Native",
        "Registry::HKEY_USERS\$($hive.PSChildName)\Software\WebEx",
        "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Webex",
        "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Cisco Systems, Inc.\Webex",
        "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Office\Outlook\Addins\Cisco.WebEx.Outlook.AddIn",
        "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Office\Outlook\Addins\WebEx Productivity Tools"
    )

    foreach ($root in $userRoots) {
        Remove-RegistryKeyIfPresent -Path $root
    }

    $userUninstall = "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    foreach ($item in @(Get-ChildItem -Path $userUninstall -ErrorAction SilentlyContinue)) {
        $childName = [string]$item.PSChildName
        $displayName = Get-PropertyValue -Object (Get-ItemProperty -LiteralPath $item.PSPath -ErrorAction SilentlyContinue) -Name 'DisplayName'
        $matchesName = $displayName -and $displayName -match $WebexNamePattern
        $matchesKey = $childName -match '(?i)(ActiveTouchMeetingClient|WebEx|CiscoSpark|CiscoWebex)'
        if ($matchesName -or $matchesKey) {
            Remove-RegistryKeyIfPresent -Path $item.PSPath
        }
    }
}

# Final verification: re-run discovery and report what (if anything) survived.
Stop-WebexProcesses

$remaining = @()
$remaining += @(Get-WebexUninstallEntries)

foreach ($folder in $machineFolders) {
    if ($folder -and (Test-Path -LiteralPath $folder)) {
        $remaining += [pscustomobject]@{ Source = 'Folder'; DisplayName = $folder; RegistryPsPath = '' }
    }
}

if ($remaining.Count -eq 0) {
    Write-Log '=== Webex Full Cleanup completed: device is clean ==='
    exit 0
}

Write-Log "=== Webex Full Cleanup finished with $($remaining.Count) remnant(s) ==="
foreach ($item in $remaining) {
    Write-Log "Remnant: Source=$($item.Source) Name='$($item.DisplayName)' Key='$($item.RegistryPsPath)'"
}
exit 1
