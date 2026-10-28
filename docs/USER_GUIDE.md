# BenCore Shield — user guide

## Security overview

Shows Microsoft Defender status and signature version. Displayed counts only update after **Audit processes & services**; there is no always-on background monitoring. The audit is read-only and may be partial.

## Quick scan and Full scan

Quick and Full delegate to `Start-MpScan`. They are **not** independent scanners built into BenCore Shield. Defender's own security policy decides how threats are handled. Use Windows Security's **Protection history** to see and manage Defender results. A completed PowerShell scan does not certify the device as clean.

## Process inspection

Lists operating-system process records including name, PID, path, Authenticode status and simple flags. Select one record to inspect the executable's folder or copy a SHA-256 file hash. A **Review** label means inspect further. Do not kill services or remove binaries just because they're unsigned.

## Services

Shows **running** service entries from Windows management, with their executable paths and signatures. Some services share `svchost.exe` and a signature on this host executable cannot establish whether all service-loaded components are safe.

## Startup and scheduled tasks

Shows Run/RunOnce registry values and selected enabled non-Microsoft scheduled tasks. This is an **incomplete view** of Windows persistence and it cannot detect all malicious autoruns or drivers. BenCore Shield does not change these settings.

## Defender history

Shows records returned by `Get-MpThreatDetection`. Some are from previous days or represent already removed/quarantined threats. Treat records as historical until corroborated by Windows Security.

## Offline / rootkit investigation

The Offline Scan guidance **does not restart your PC**. It shows the Windows Security path for running Microsoft Defender Offline. This scan can help with persistent malware but cannot guarantee rootkit discovery. Save work before launching offline scan within Windows Security.

## Export reports and privacy

The Export button lets you save `result.json`. It may include executable paths with usernames, host details and previous Defender detections. Do not post unredacted reports on public GitHub issues.

## Limitations

No real-time protection, network reputation score, public malware hash lookups, automatic quarantine, scheduled scanning, kernel driver analysis, sandbox execution, YARA signatures, behavior engine or guaranteed rootkit discovery. Running an audit as administrator improves some data access, not completeness or certainty.
