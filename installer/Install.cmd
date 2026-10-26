@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install.ps1"
set "result=%ERRORLEVEL%"
if "%result%"=="20" echo Restart Windows or finish WSL setup, then run Install.cmd again.
if not "%result%"=="0" if not "%result%"=="20" echo Installation failed. Read the error above and retry.
pause
exit /b %result%
