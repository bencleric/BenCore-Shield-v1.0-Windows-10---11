# BenCore Shield — Windows 11 installation guide

1. Download the ZIP from GitHub, then extract it completely to a trusted local folder such as `C:\Tools\BenCoreShield`. **Do not double-click scripts inside a compressed ZIP viewer.**
2. Review `BenCoreShield.ps1`, `BenCoreShield.Engine.psm1`, `BenCoreShield.Worker.ps1` and `.cmd` launchers. Scripts are not digitally signed in this preview.
3. Run `Run-Diagnostics.cmd` first. It checks file locations, the PowerShell parser, XAML loading, and basic Defender availability without running a scan or changing security settings.
4. Run `Start-BenCoreShield.cmd` for a standard user dashboard. You can use `Start-BenCoreShield-Admin.cmd` when you explicitly want to approve a UAC prompt for more complete audit coverage. Administrator rights do not make a heuristic flag proof of malware.
5. Select **Audit processes & services**. After it finishes, review each section. Paths and statuses may be incomplete on protected processes.
6. Run **Defender quick scan** if desired. Full scan can be time-consuming and may increase disk/CPU use; save work first if needed.
7. If you suspect an entrenched or rootkit infection, use the separate **Offline / rootkit scan guidance** button, then start an offline scan in Windows Security after saving your work.
8. Export JSON reports only when appropriate, and check them for usernames, hostnames, and file paths before sending anywhere.

## Optional manual command

From inside the unzipped folder, run:

```powershell
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File .\BenCoreShield.ps1
```

The `Bypass` flag is process-scoped; it does not change computer-wide execution policies. If your organization blocks unsigned scripts, get approval instead of bypassing the policy.

## Report location

`%LOCALAPPDATA%\BenCoreShield\Jobs\<session-id>\status.json` — status updates  
`%LOCALAPPDATA%\BenCoreShield\Jobs\<session-id>\result.json` — read-only inspection/scanner records

## Diagnosing errors

- **Defender unavailable or inactive:** Windows Security → Virus & threat protection → Manage providers. Use your installed antivirus if Defender is passive.
- **Access denied:** you may choose explicit elevated launch; managed device policy still applies.
- **Missing module/XAML:** reinstall the entire ZIP in the same folder, not individual scripts.
- **Unexpected scan behavior:** examine Windows Security → Protection history and local `result.json` rather than assuming a screen label indicates a clean result.
- **Window blank/doesn't load:** check diagnostics then report Windows build and full error message (remove personal details).

No network port, website, scheduled task, service, login, driver or persistent installer is created by this application.
