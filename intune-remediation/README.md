# Intune Remediation - Microsoft Store Updates

Two-script Intune remediation package to detect and fix pending Microsoft Store app updates.

## Files

| File | Purpose |
|------|---------|
| `detect_MicrosoftStoreUpdates.ps1` | Detection — exits `0` (compliant) or `1` (non-compliant) |
| `remediate_MicrosoftStoreUpdates.ps1` | Remediation — runs when detection exits `1` |

## How to deploy in Intune

1. Go to **Intune > Devices > Scripts and remediations**
2. Click **+ Create** > **Remediation**
3. Upload `detect_MicrosoftStoreUpdates.ps1` as the **Detection script**
4. Upload `remediate_MicrosoftStoreUpdates.ps1` as the **Remediation script**
5. Set **Run this script using the logged-on credentials**: No (run as SYSTEM)
6. Set **Enforce script signature check**: No
7. Set **Run script in 64-bit PowerShell**: Yes
8. Assign to a device group and set a schedule

## What the remediation does

1. Runs `winget upgrade` for Store-registered apps
2. Triggers the Store's internal MDM update scan
3. Re-registers stuck AppX packages
4. Resets the Microsoft Store cache via `wsreset`

## Related

See also [`../powershell-tools/MicrosoftStoreUpdate.ps1`](../powershell-tools/MicrosoftStoreUpdate.ps1) for the standalone (non-Intune) combined script.
