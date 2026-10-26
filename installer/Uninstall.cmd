@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Uninstall.ps1"
set "result=%ERRORLEVEL%"
if not "%result%"=="0" (
    echo CTF Agent removal was incomplete. Check the error above.
)
pause
exit /b %result%
