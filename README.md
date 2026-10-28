# BenCore Shield

**Protect the Core. Secure the System.**  
**Windows 11 Security Inspector — v1.0 (preview)**  
**Developed by Benie Mansueto Vison**

BenCore Shield is a locally running **Windows PowerShell 5.1 + WPF desktop application** for reviewing Windows 11 security. Its dashboard brings together Microsoft Defender scans, a Task Manager-style process inventory, running service inspection, startup and scheduled-task inspection, and recent Defender detection history.

> **Important:** BenCore Shield is **not an independent antivirus engine or kernel rootkit detector**. Actual malware scans are performed by Microsoft's installed Defender antivirus. The process/service audit uses **simple investigation heuristics, not malware classification**. An unsigned or unusual application may be legitimate, and signed malware is possible. A clean result does not prove a PC is uninfected.
>
> **Release status: Windows beta / test before deployment.** The code and XAML are packaged and checked statically, but **the WPF UI and Defender actions have not been executed on a Windows 11 machine** in the build environment. Test on a VM or noncritical PC before release or enterprise use.


## BenCore Sheild Dashboard

<p align="center">
  <img src="https://i.ibb.co/gYCGwdm/Screenshot-2026-10-28-080655.png" alt="Screenshot 2026 10 28 080655" border="0">
</p>

<h3 align="center">
  Protect your core. Unleash the Performance.
</h3>

<p align="center">
  Developed by Benie Mansueto Vison
</p>

## Capabilities

| Section | What it does |
|---|---|
| **Security overview** | Shows Defender activation, signature version, audited process/service counts and items needing review. |
| **Quick scan / Full scan** | Starts Microsoft Defender's genuine `Start-MpScan -ScanType QuickScan` / `FullScan`. |
| **Defender update** | Requests the latest security intelligence using `Update-MpSignature`. |
| **Running processes** | Audits `Win32_Process`, executable paths and Authenticode signatures. |
| **Running services** | Audits `Win32_Service` entries in the Running state, executable paths and signatures. |
| **Startup and tasks** | Audits common Run/RunOnce registry entries and enabled non-Microsoft scheduled tasks. |
| **Defender history** | Displays the 60 most recent entries returned by `Get-MpThreatDetection`, including reported status. |
| **File investigation** | Opens the executable's containing folder or copies its SHA-256 hash, without launching the executable. |
| **Deep-scan guidance** | Explains how to start a Microsoft Defender **Offline** scan using Windows Security. |
| **Reports** | Exports JSON containing the last inspection/scan results. Local records live in `%LOCALAPPDATA%\BenCoreShield\Jobs`. |

## Requirements

- Windows 11 (Windows 10 not yet formally supported or tested).
- Windows PowerShell **5.1** and .NET Framework with WPF (normally included in Windows 11).
- Microsoft Defender Antivirus **enabled** for Quick/Full scan and signature-update functionality. If a third-party AV is active, use that vendor's scanner instead.
- Interactive local desktop session; no Python, Node.js, additional PowerShell modules, internet APIs or installer needed.
- An **administrator session can improve inventory coverage and may be required for Defender scan operations**. Standard user mode may return incomplete paths or denied access.

## Quick start

1. Select **Code → Download ZIP** on GitHub (or download the release package).
2. Extract the project files to `C:\Tools\BenCoreShield` or another trusted local location. Keep all files together.
3. Review the source before executing downloaded scripts. Do not bypass organization security policies.
4. Double-click **`Run-Diagnostics.cmd`**. Fix any reported missing dependency.
5. Double-click **`Start-BenCoreShield.cmd`**. For a deeper inventory, you can explicitly choose **`Start-BenCoreShield-Admin.cmd`** and approve the UAC prompt.
6. Click **Audit processes & services**. This is read-only. Inspect **Running processes**, **Windows services**, **Startup & tasks**, and **Defender history**.
7. Optionally click **Defender quick scan** or **Defender full scan** to ask Microsoft's antivirus engine to scan for malicious files and programs.
8. Review results with **Windows Security → Virus & threat protection → Protection history**. The dashboard never auto-removes flagged processes or files.
9. Click **Export last report** to save JSON for your own investigation. **Review private file paths before sharing**.

### Manual PowerShell launch (from the extracted directory)

```powershell
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File .\Test-BenCoreShield.ps1
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File .\BenCoreShield.ps1
```

The launchers' `-ExecutionPolicy Bypass` applies only to their spawned PowerShell processes and **does not** persistently change your device's execution policy. Only run code you have reviewed and trust.

## Threat assessment: what flags mean

- **Review**: a *heuristic investigation lead*, such as an unsigned executable in a temporary/public/download location or a Windows-component-looking name outside the Windows folder. **Not proof of malware.**
- **Informational**: no simple high-signal rule matched. **Not an assurance of safety.**
- **Unknown**: executable path or signature could not be checked (permissions, protected processes, command-line parsing, etc.).
- **Defender attention**: Defender history reported a detected, allowed or failed-remediation state; open Windows Security and verify current status.
- **History**: Defender previously detected something and reports another outcome such as removed or quarantined. This is **not an active-infection indicator** by itself.

**Signature status:** a valid Authenticode signature only indicates signing information passed Windows verification; it is not an antivirus reputation result. Many legitimate projects distribute unsigned executables.

**Coverage limitations:** this version does not enumerate every startup technique, drivers, kernel modules, hidden files, malicious network flows or EDR telemetry. A rootkit can tamper with process/service views. It does not implement process memory inspection, sandbox detonation, YARA, VirusTotal queries, behavior engines, manual malware removal or real-time monitoring.

## Rootkit and persistent infection investigation

Use **Offline / rootkit scan guidance** in the app. It directs you to:

**Windows Security → Virus & threat protection → Scan options → Microsoft Defender Antivirus (offline scan)**

Save all work **before proceeding**: Offline Scan restarts your computer and checks for threats from outside the normal Windows session. BenCore Shield **never silently initiates the restart**. Defender Offline does not guarantee detection of every rootkit. When compromise is serious, disconnect the PC from the network and consult an incident-response professional.

## Safe by design

- No process termination, quarantine, deletion, service disabling, registry modification, Defender exclusions, firewall changes or tampering with operating-system security controls.
- Scan and definition update actions are explicitly initiated by the user and performed using existing Microsoft Defender commands.
- Defender **itself** may remediate threats according to its current policies while scanning. BenCore Shield doesn't override those policies.
- No uploads, API keys, external threat database, account registration, advertisements or data collection implemented.
- Reports contain local paths, hostnames, and perhaps usernames; handle as potentially confidential. Data is stored under your Windows user profile.
- GUI launches long tasks in child PowerShell processes so the interface remains responsive. Closing the dashboard does **not** reliably cancel an active Defender scan.

## Project structure

```text
BenCoreShield.ps1            # WPF application controller
BenCoreShield.UI.xaml        # Modern dark dashboard
BenCoreShield.Engine.psm1    # Read-only audit functions
BenCoreShield.Worker.ps1     # Scan/inventory background worker
Start-BenCoreShield.cmd      # Normal launcher
Start-BenCoreShield-Admin.cmd# Explicit UAC launcher
Run-Diagnostics.cmd          # Read-only diagnostic launcher
Test-BenCoreShield.ps1       # Dependency and basic compatibility checks
README.md                    # Main documentation
SECURITY.md                  # Responsible issue reporting and safety limits
CHANGELOG.md                 # Version changes
docs/INSTALLATION.md         # Detailed setup and troubleshooting
docs/USER_GUIDE.md           # How to interpret each section
docs/GITHUB_PUBLISHING.md    # How to upload the files to GitHub
.github/workflows/check.yml # Windows script/XAML parse checks
```

## Troubleshooting

- **Window will not open:** unzip **all** files, run `Run-Diagnostics.cmd`, and verify Windows PowerShell 5.1 and a desktop user session.
- **Cannot scan with Defender:** check **Windows Security** and whether Defender AV is active. Some operations may require admin rights or be blocked by company policy. A third-party antivirus may place Defender in passive mode.
- **Protected process path blank:** some process paths are protected or access is restricted. Run as administrator if appropriate; this still will not expose all kernel activity.
- **No findings:** that means the heuristics did not raise investigation leads, **not** that the machine is proven clean.
- **A scan takes a long time:** full scans vary widely with disk size and hardware. Check Windows Security for results and ongoing activity.
- **Scan status is Failed or Partial:** open local `Jobs` reports and read `Warnings`. Do not interpret partial results as clean.

## Author & license

Developed by **Benie Mansueto Vison**.  
**BenCore Shield** is a separate security-inspection utility inspired by the dashboard style of BenCore.

**License:** none selected. Public viewing of source on GitHub does not automatically authorize reuse, modification or redistribution. The repository owner may later add a suitable `LICENSE` file.

For security issues, see [SECURITY.md](SECURITY.md). Official Defender references: [Microsoft Defender PowerShell cmdlets](https://learn.microsoft.com/en-us/powershell/module/defender/), [Microsoft Defender Offline](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-offline).
