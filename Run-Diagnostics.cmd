@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Test-BenCoreShield.ps1"
pause
