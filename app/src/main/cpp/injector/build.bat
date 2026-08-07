@echo off
setlocal EnableDelayedExpansion

:: 尝试从注册表读取 NDK_HOME（如果环境变量未生效）
if not defined NDK_HOME (
    for /f "tokens=2*" %%a in ('reg query "HKCU\Environment" /v NDK_HOME 2^>nul') do set "NDK_HOME=%%b"
)
if not defined NDK_HOME (
    for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v NDK_HOME 2^>nul') do set "NDK_HOME=%%b"
)

if not defined NDK_HOME (
    echo Error: NDK_HOME is not set
    echo Please set NDK_HOME environment variable or restart your terminal
    exit /b 1
)

echo Using NDK_HOME: %NDK_HOME%

set BUILD_DIR=build
set ABI=arm64-v8a
set API=21

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

cd %BUILD_DIR%

cmake .. ^
    -DCMAKE_TOOLCHAIN_FILE=%NDK_HOME%/build/cmake/android.toolchain.cmake ^
    -DANDROID_ABI=%ABI% ^
    -DANDROID_PLATFORM=android-%API% ^
    -DCMAKE_BUILD_TYPE=Release ^
    -G "Ninja"

if errorlevel 1 (
    echo CMake configuration failed
    exit /b 1
)

ninja

if errorlevel 1 (
    echo Build failed
    exit /b 1
)

echo.
echo Build successful!
echo Output: %BUILD_DIR%/injector

cd ..
