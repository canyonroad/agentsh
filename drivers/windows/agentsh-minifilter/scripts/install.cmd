@echo off
REM install.cmd - Install the AgentSH driver (requires admin)

setlocal

set DRIVER_PATH=%1
if "%DRIVER_PATH%"=="" set DRIVER_PATH=%~dp0..\bin\x64\Debug\agentsh.sys

if not exist "%DRIVER_PATH%" (
    echo ERROR: Driver not found at %DRIVER_PATH%
    echo Build the driver first with: scripts\build.cmd
    exit /b 1
)

echo ========================================
echo Installing AgentSH Driver
echo ========================================

REM Check admin privileges
net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: This script requires administrator privileges.
    echo Right-click and select "Run as administrator".
    exit /b 1
)

REM Copy driver to System32\drivers
copy /y "%DRIVER_PATH%" "%SystemRoot%\System32\drivers\agentsh.sys"
if errorlevel 1 (
    echo ERROR: Failed to copy driver
    exit /b 1
)

REM Install using INF
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 %~dp0..\agentsh.inf
if errorlevel 1 (
    echo ERROR: INF installation failed
    exit /b 1
)

REM Load the driver
fltmc load agentsh
if errorlevel 1 (
    echo WARNING: Driver load failed (may already be loaded or need reboot)
)

echo ========================================
echo Driver installed successfully
echo Use 'fltmc' to verify filter is loaded
echo ========================================

exit /b 0
