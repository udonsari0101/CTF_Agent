@echo off
setlocal
rem PowerShell can end with exit code 0 and no output before it runs the script,
rem which was seen with real-time security software active. Start.ps1 creates
rem this marker on its first line, so a missing marker means it never ran.
set "CTF_AGENT_START_MARKER=%TEMP%\ctf-agent-start-%RANDOM%%RANDOM%"
set "attempt=0"
:launch
set /a attempt+=1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start.ps1"
set "result=%ERRORLEVEL%"
if exist "%CTF_AGENT_START_MARKER%" goto finished
if %attempt% geq 3 goto notrun
echo PowerShell ended before Start.ps1 ran. Retrying...
goto launch
:notrun
echo Start.ps1 did not run. Check whether security software is blocking PowerShell.
set "result=1"
:finished
del "%CTF_AGENT_START_MARKER%" 2>nul
if not "%result%"=="0" (
    echo CTF Agent could not start. Check the error above.
    pause
)
exit /b %result%
