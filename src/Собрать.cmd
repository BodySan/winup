@echo off
rem Build WinUp using the .NET Framework compiler included in Windows.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1"
if errorlevel 1 (echo Build failed. & pause & exit /b 1)
pause
