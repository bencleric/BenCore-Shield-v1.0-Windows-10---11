@echo off
setlocal
cd /d "%~dp0"
echo This starts BenCore Shield with administrator privileges after a UAC prompt.
echo Review the source before approving elevation.
powershell.exe -NoLogo -NoProfile -Command "Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoLogo','-NoProfile','-STA','-ExecutionPolicy','Bypass','-File','""%~dp0BenCoreShield.ps1""') -Verb RunAs"
if errorlevel 1 pause
