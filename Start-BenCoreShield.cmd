@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0BenCoreShield.ps1"
if errorlevel 1 (
  echo.
  echo BenCore Shield could not start. Run Run-Diagnostics.cmd for details.
  pause
)
