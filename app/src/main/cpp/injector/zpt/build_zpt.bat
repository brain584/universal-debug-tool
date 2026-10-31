@echo off
setlocal
set NDK=C:\Users\Alive\AppData\Local\Android\Sdk\ndk\27.0.12077973
set CC=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\clang++.exe
set SRC=%~dp0..\src\zeroptrace_injector.cpp
set OUT=%~dp0zeroptrace_injector
"%CC%" --target=aarch64-linux-android24 -Wall -Wextra -O2 -fPIE -pie -o "%OUT%" "%SRC%" -llog
if errorlevel 1 (echo BUILD_FAILED & exit /b 1)
echo BUILD_OK
