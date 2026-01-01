@echo off
REM uninstall.cmd - Uninstall the AgentSH driver (requires admin)

setlocal

echo ========================================
echo Uninstalling AgentSH Driver
echo ========================================

REM Check admin privileges
net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: This script requires administrator privileges.
    echo Right-click and select "Run as administrator".
    exit /b 1
)

REM Unload the driver
fltmc unload agentsh 2>nul

REM Uninstall using INF
rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 %~dp0..\agentsh.inf

REM Delete driver file
del /f "%SystemRoot%\System32\drivers\agentsh.sys" 2>nul

echo ========================================
echo Driver uninstalled successfully
echo ========================================

exit /b 0
