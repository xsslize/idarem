@echo off
REM Double-click this, or run it from a terminal. It launches the PowerShell
REM installer with an execution-policy bypass scoped to this one process, so
REM Windows' script-blocking policy doesn't get in the way.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set "IDAREM_EXIT_CODE=%ERRORLEVEL%"
pause
exit /b %IDAREM_EXIT_CODE%
