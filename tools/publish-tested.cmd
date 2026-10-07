@echo off
setlocal
set "WINUP_GH=gh"
if exist "%~dp0github\gh.exe" set "WINUP_GH=%~dp0github\gh.exe"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0publish-tested.ps1" -Gh "%WINUP_GH%" -Refresh
set "WINUP_RESULT=%ERRORLEVEL%"
if not "%WINUP_RESULT%"=="0" echo Release stopped. No failed candidate is signed.
pause
exit /b %WINUP_RESULT%
