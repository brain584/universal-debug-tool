@echo off
REM ===========================================================================
REM  atrace_lua.bat -- PC-side Lua editor for ATrace (via USB debugging).
REM
REM  Usage:
REM    double-click                      -> interactive mode
REM    drag a .lua file onto this .bat   -> push and run it immediately
REM    atrace_lua.bat file.lua --edit    -> edit in IDE then run
REM
REM  Requirements: USB debugging authorized, ATrace running, "adb script mode"
REM                enabled in ATrace options page, target injected+agent connected.
REM
REM  NOTE: keep this file ASCII + CRLF. cmd.exe reads .bat in the system ANSI
REM        codepage and requires CRLF; UTF-8/LF breaks the parser.
REM ===========================================================================
setlocal enabledelayedexpansion
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set "HERE=%~dp0"
set "CFG=%HERE%pc_config.ini"
set "PY="
set "PORT="

REM ---- read cached settings (written by atrace_lua.py) ----
if exist "%CFG%" (
    for /f "usebackq tokens=1,* delims==" %%A in ("%CFG%") do (
        if /i "%%A"=="python" set "PY=%%B"
        if /i "%%A"=="port"   set "PORT=%%B"
    )
)
if not defined PORT set "PORT=28471"
if defined PY if not exist "%PY%" set "PY="

REM ---- auto-detect python ----
if not defined PY (
    where py >nul 2>nul
    if !errorlevel!==0 (
        for /f "delims=" %%P in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do set "PY=%%P"
    )
)
if not defined PY (
    where python >nul 2>nul
    if !errorlevel!==0 (
        for /f "delims=" %%P in ('python -c "import sys;print(sys.executable)" 2^>nul') do set "PY=%%P"
    )
)
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python" (
    for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
        if exist "%%~fD\python.exe" set "PY=%%~fD\python.exe"
    )
)
if not defined PY if exist "C:\Python313\python.exe" set "PY=C:\Python313\python.exe"
if not defined PY if exist "C:\Python312\python.exe" set "PY=C:\Python312\python.exe"
if not defined PY if exist "C:\Python311\python.exe" set "PY=C:\Python311\python.exe"
if not defined PY if exist "C:\Python310\python.exe" set "PY=C:\Python310\python.exe"

REM ---- still nothing: ask the user (drag-and-drop supported) ----
if not defined PY (
    echo [!] Python 3 not found automatically.
    echo     Drag python.exe into this window, or paste its full path, then press Enter.
    echo     Or install Python 3 and tick "Add python.exe to PATH".
    set /p "PYRAW=python path> "
    set "PY=!PYRAW:"=!"
    if defined PY if not exist "!PY!" (
        echo [!] not a file: !PY!
        set "PY="
    )
)
if not defined PY (
    echo [!] Cannot continue without Python 3.
    pause
    exit /b 1
)

echo [*] python: %PY%
"%PY%" "%HERE%atrace_lua.py" --port %PORT% %*
set "RC=%errorlevel%"
if not "%RC%"=="0" echo [!] exit code %RC%
pause
exit /b %RC%
