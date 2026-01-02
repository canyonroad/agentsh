@echo off
REM build.cmd - Build the AgentSH mini filter driver

setlocal

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Debug

set PLATFORM=%2
if "%PLATFORM%"=="" set PLATFORM=x64

echo ========================================
echo Building AgentSH Driver (%CONFIG%/%PLATFORM%)
echo ========================================

pushd %~dp0..

REM Find MSBuild
set MSBUILD=
for %%i in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
) do (
    if exist %%i (
        set MSBUILD=%%i
        goto :found
    )
)

echo ERROR: MSBuild not found. Install Visual Studio with C++ and WDK.
exit /b 1

:found
echo Using MSBuild: %MSBUILD%

%MSBUILD% agentsh.sln /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /t:Build /v:minimal

if errorlevel 1 (
    echo Build FAILED
    popd
    exit /b 1
)

echo ========================================
echo Build successful: bin\%PLATFORM%\%CONFIG%\agentsh.sys
echo ========================================

popd
exit /b 0
