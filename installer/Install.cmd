@echo off
setlocal
rem Verify that PowerShell actually entered the script before trusting exit 0.
set "CTF_AGENT_LAUNCH_MARKER=%TEMP%\ctf-agent-install-%RANDOM%%RANDOM%"
set "attempt=0"
:launch
set /a attempt+=1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install.ps1" %*
set "result=%ERRORLEVEL%"
if exist "%CTF_AGENT_LAUNCH_MARKER%" goto finished
if %attempt% geq 3 goto notrun
echo PowerShell ended before Install.ps1 ran. Retrying...
goto launch
:notrun
echo Install.ps1 did not run. Check whether security software is blocking PowerShell.
set "result=1"
:finished
del "%CTF_AGENT_LAUNCH_MARKER%" 2>nul
if "%result%"=="20" echo Restart Windows or finish WSL setup, then run Install.cmd again.
if not "%result%"=="0" if not "%result%"=="20" echo Installation failed. Read the error above and retry.
if not "%result%"=="0" if not "%result%"=="20" pause
exit /b %result%
