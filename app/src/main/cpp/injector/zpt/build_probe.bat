@echo off
setlocal
set NDK=C:\Users\Alive\AppData\Local\Android\Sdk\ndk\27.0.12077973
set CC=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe
set SRC=%~dp0execmem_probe.c
if not exist "%~dp0out" mkdir "%~dp0out"
"%CC%" --target=aarch64-linux-android24 -O1 -fPIE -pie -o "%~dp0out\execmem_probe" "%SRC%"
if errorlevel 1 (echo BUILD FAILED & exit /b 1)
echo BUILD_OK
