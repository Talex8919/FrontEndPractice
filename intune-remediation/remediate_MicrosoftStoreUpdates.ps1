# ================================================
# Intune Remediation Script - Microsoft Store Updates
# Runs only when detection exits 1 (non-compliant)
# ================================================

$errors = @()

# Step 1: winget upgrade all Store apps
try {
    $result = & winget upgrade --all --source msstore --accept-source-agreements --accept-package-agreements 2>&1
    Write-Output "[winget] $result"
} catch {
    $errors += "winget: $_"
}

# Step 2: Trigger Microsoft Store's internal update scan via MDM bridge
try {
    $wmiObj = Get-WmiObject -Namespace "root\cimv2\mdm\dmmap" `
              -Class "MDM_EnterpriseModernAppManagement_AppManagement01" `
              -ErrorAction Stop
    $wmiObj.UpdateScanMethod()
    Write-Output "[MDM] Store update scan triggered successfully."
} catch {
    $errors += "MDM scan: $_"
}

# Step 3: Re-register stuck AppX packages
try {
    $reregistered = 0
    Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Add-AppxPackage -DisableDevelopmentMode `
                -Register "$($_.InstallLocation)\AppXManifest.xml" `
                -ErrorAction SilentlyContinue
            $reregistered++
        } catch {}
    }
    Write-Output "[AppX] Re-registered $reregistered packages."
} catch {
    $errors += "AppX re-register: $_"
}

# Step 4: Reset Microsoft Store cache
try {
    Stop-Process -Name "WinStore.App" -Force -ErrorAction SilentlyContinue
    Start-Process -FilePath "wsreset.exe" -Wait -ErrorAction Stop
    Write-Output "[wsreset] Store cache cleared."
} catch {
    $errors += "wsreset: $_"
}

# Report outcome
if ($errors.Count -gt 0) {
    Write-Output "Remediation completed with warnings:"
    $errors | ForEach-Object { Write-Output "  - $_" }
    exit 1
} else {
    Write-Output "Remediation completed successfully."
    exit 0
}
