@echo off
REM Double-click to remove the idarem loader from IDA's plugins folder.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"
set "IDAREM_EXIT_CODE=%ERRORLEVEL%"
pause
exit /b %IDAREM_EXIT_CODE%
