# ================================================
# Intune Detection Script - Microsoft Store Updates
# Exit 0 = Compliant (no updates pending)
# Exit 1 = Non-compliant (updates found, trigger remediation)
# ================================================

$pendingUpdates = @()

# Check 1: winget pending updates from Microsoft Store
try {
    $wingetOutput = & winget upgrade --source msstore 2>&1
    foreach ($line in $wingetOutput) {
        if ($line -notmatch 'Name|---|winget|No applicable|^$' -and $line -match '\w{3,}') {
            $pendingUpdates += $line.Trim()
        }
    }
} catch {
    # winget unavailable - not blocking
}

# Check 2: AppX packages in non-OK or staged state
try {
    $stagedApps = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -ne 'Ok'
    }
    if ($stagedApps) {
        $pendingUpdates += $stagedApps | ForEach-Object { $_.Name }
    }
} catch {
    # Non-fatal
}

if ($pendingUpdates.Count -gt 0) {
    Write-Output "Non-compliant: $($pendingUpdates.Count) pending Microsoft Store update(s) detected."
    exit 1
} else {
    Write-Output "Compliant: No pending Microsoft Store updates detected."
    exit 0
}
