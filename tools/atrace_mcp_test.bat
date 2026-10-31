@echo off
REM ===========================================================================
REM  atrace_mcp_test.bat -- Quick self-test of the PC-side MCP service.
REM  Prints MCP handshake / tool list / a real tool call, then exits.
REM  NOTE: keep this file ASCII + CRLF (cmd.exe requires it).
REM ===========================================================================
setlocal enabledelayedexpansion
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set "HERE=%~dp0"
set "CFG=%HERE%pc_config.ini"
set "PY="
set "PORT="

if exist "%CFG%" (
    for /f "usebackq tokens=1,* delims==" %%A in ("%CFG%") do (
        if /i "%%A"=="python" set "PY=%%B"
        if /i "%%A"=="port"   set "PORT=%%B"
    )
)
if not defined PORT set "PORT=28471"
if defined PY if not exist "%PY%" set "PY="

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
if not defined PY (
    echo [!] Python 3 not found. Run atrace_lua.bat once to configure it.
    pause
    exit /b 1
)

echo [*] python: %PY%
"%PY%" "%HERE%atrace_mcp.py" --selftest --mode auto --port %PORT% %*
set "RC=%errorlevel%"
if not "%RC%"=="0" echo [!] exit code %RC%
pause
exit /b %RC%
