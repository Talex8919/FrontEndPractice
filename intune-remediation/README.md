# Intune Proactive Remediation — Winget Upgrade All

Silently upgrades all installed packages via winget running under the **SYSTEM** account.

---

## Files

| File | Purpose |
|------|---------|
| `Detect-WingetUpdates.ps1` | Detection — exits 1 when updates are available |
| `Remediate-WingetUpdates.ps1` | Remediation — runs `winget upgrade --all` silently |

---

## Intune Configuration

| Setting | Value |
|---------|-------|
| Run this script using the logged-on credentials | **No** (runs as SYSTEM) |
| Enforce script signature check | No (or Yes if you sign the scripts) |
| Run script in 64-bit PowerShell | **Yes** |
| Schedule | Daily or every 8 hours |

---

## Key flags used

```
winget upgrade --all
             --include-unknown          # Upgrades packages where version can't be determined
             --accept-source-agreements # Auto-accepts source EULAs (msstore, winget)
             --accept-package-agreements# Auto-accepts per-package EULAs
             --silent                   # No UI, no prompts
             --scope machine            # Installs machine-wide (SYSTEM context)
             --force                    # Overwrite running instances where supported
             --disable-interactivity    # Suppresses any remaining interactive prompts
```

---

## Excluded packages (edit `$ExcludeList` in the remediation script)

These are pinned out of `--all` to avoid conflicts with other management channels:

- `Microsoft.Teams` — self-updating / M365 managed
- `Microsoft.Edge` — managed via Intune/ADMX policy
- `Microsoft.EdgeWebView2Runtime` — Edge-managed component
- `Microsoft.PowerBI` — managed via separate Intune app deployment

Add any MSI/EXE that requires a reboot or is deployed via another Intune app policy.

---

## Logs

Both scripts write to:

```
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\WingetUpgrade-Detection.log
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\WingetUpgrade-Remediation.log
```

These are automatically collected by the IME log collector.

---

## Notes on SYSTEM + winget

winget is a per-user AppX package but its binary is accessible to SYSTEM via
`C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*\winget.exe`.
The scripts resolve this path automatically; no extra configuration is needed
as long as App Installer ≥ 1.4 is deployed to devices.
