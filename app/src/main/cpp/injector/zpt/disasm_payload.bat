@echo off
setlocal
set NDK=C:\Users\Alive\AppData\Local\Android\Sdk\ndk\27.0.12077973
set ADB=C:\Users\Alive\AppData\Local\Android\Sdk\platform-tools\adb.exe
set D=%~dp0
set CC=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe
set CXX=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\clang++.exe
set OD=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-objdump.exe
set PY=C:\Users\Alive\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe
set SRC=%D%..\src\zeroptrace_injector.cpp

echo === 1) build ===
"%CXX%" --target=aarch64-linux-android24 -Wall -Wextra -O2 -fPIE -pie -o "%D%zeroptrace_injector" "%SRC%" -llog
if errorlevel 1 (echo BUILD_FAILED & exit /b 1)

echo === 2) push ===
"%ADB%" push "%D%zeroptrace_injector" /data/local/tmp/zpt >nul
if errorlevel 1 (echo PUSH_FAILED & exit /b 1)
"%ADB%" shell chmod 755 /data/local/tmp/zpt

echo === 3) dump payload from device ===
del /q "%D%payload.bin" "%D%payload.s" "%D%payload.o" 2>nul
"%ADB%" shell "/data/local/tmp/zpt --dump-payload 0x1122334455 > /dev/null 2>&1"
if errorlevel 1 (echo DUMP_FAILED & exit /b 1)
"%ADB%" pull /data/local/tmp/payload.bin "%D%payload.bin" >nul
if errorlevel 1 (echo PULL_FAILED & exit /b 1)

echo === 4) disassemble ===
"%PY%" "C:\Users\Alive\Documents\deepseek-harness\default-workspace\dump2asm.py" "%D%payload.bin" "%D%payload.s"
"%CC%" --target=aarch64-linux-android24 -c -x assembler -o "%D%payload.o" "%D%payload.s"
if errorlevel 1 (echo ASM_FAILED & exit /b 1)
"%OD%" -d "%D%payload.o"
