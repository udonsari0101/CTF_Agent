@echo off
setlocal
set "CTF_AGENT_LAUNCH_MARKER=%TEMP%\ctf-agent-link-%RANDOM%%RANDOM%"
set "attempt=0"
:launch
set /a attempt+=1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0RemoteLink.ps1" %*
set "result=%ERRORLEVEL%"
if exist "%CTF_AGENT_LAUNCH_MARKER%" goto finished
if %attempt% geq 3 goto notrun
echo PowerShell ended before RemoteLink.ps1 ran. Retrying...
goto launch
:notrun
echo RemoteLink.ps1 did not run. Check whether security software is blocking PowerShell.
set "result=1"
:finished
del "%CTF_AGENT_LAUNCH_MARKER%" 2>nul
pause
exit /b %result%
