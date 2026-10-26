@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start.ps1"
set "result=%ERRORLEVEL%"
if not "%result%"=="0" (
    echo CTF Agent could not start. Check the error above.
    pause
)
exit /b %result%
