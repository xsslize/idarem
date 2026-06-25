@echo off
REM Double-click to remove the idarem loader from IDA's plugins folder.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"
pause
