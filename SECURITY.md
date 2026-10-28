# Security & responsible reporting

BenCore Shield is a **preview** of a defensive inspection interface. It is not certified antivirus software. Do not make incident-response decisions based only on its heuristic flags.

Do not post log files, Windows computer names, usernames, full local paths, private keys, or Defender reports publicly. To report a possible vulnerability, contact the repository owner through a suitable private channel before public disclosure. Do not publish weaponized proof-of-concept code against real systems in project issues.

The project never intentionally sends telemetry, executes suspicious files, disables Defender, turns off logging, deletes binaries, quarantines files, or modifies Windows security settings. Microsoft Defender, if invoked for scans, may remediate malware based on its existing policy.

Always validate releases in a Windows 11 VM before using on managed or production systems. Keep Windows and Defender security intelligence current.
