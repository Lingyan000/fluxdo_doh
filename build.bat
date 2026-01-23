@echo off
REM ECH Proxy Build Script for Windows
REM This script sets up the MSVC environment and builds the project

echo Setting up Visual Studio environment...

REM Try VS 2022 Community first
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    goto :build
)

REM Try VS 2022 Professional
if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    goto :build
)

REM Try VS 2022 Enterprise
if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    goto :build
)

REM Try VS 2019
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    goto :build
)

echo ERROR: Visual Studio not found!
echo Please install Visual Studio with C++ build tools.
exit /b 1

:build
echo.
echo Building ECH Proxy...
echo.

cd /d "%~dp0"
cargo build --release

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build successful!
    echo Binary: target\release\ech_proxy_bin.exe
) else (
    echo.
    echo Build failed!
    exit /b 1
)
