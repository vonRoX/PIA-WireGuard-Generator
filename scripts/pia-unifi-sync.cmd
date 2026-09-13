@echo off
rem ---------------------------------------------------------------------------
rem  Refresh the UniFi WireGuard tunnels from Windows, by double-click.
rem
rem  Reads credentials from pia-unifi-sync.env in the repository root and hands
rem  them to scripts/pia-unifi-sync.mjs through the environment, which is where
rem  that script already looks for them. Nothing is passed on the command line,
rem  so no password or API key lands in the console title, the window's scroll
rem  buffer, or another user's `wmic process` output.
rem
rem  With no arguments this performs a DRY RUN: it signs in, registers keys with
rem  PIA and prints what it would change, but writes nothing to the console.
rem  Pass --apply to actually write. Any other arguments are passed through, so
rem  --list-networks and --list-regions work as documented.
rem
rem  Deliberately not `setlocal enabledelayedexpansion`: delayed expansion eats
rem  an exclamation mark, and passwords contain exclamation marks.
rem ---------------------------------------------------------------------------

setlocal
set "SCRIPT_DIR=%~dp0"
set "REPO_ROOT=%SCRIPT_DIR%.."
set "ENV_FILE=%REPO_ROOT%\pia-unifi-sync.env"
set "CONFIG_FILE=%REPO_ROOT%\pia-unifi-sync.json"
set "ENTRY=%REPO_ROOT%\scripts\pia-unifi-sync.mjs"

rem --- Node -------------------------------------------------------------------
where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo   Node.js was not found on this computer.
  echo.
  echo   This launcher runs the sync script, which needs Node 20 or newer.
  echo   Install it from https://nodejs.org/ ^(the LTS build is fine^), then
  echo   close this window and double-click this file again.
  echo.
  goto :finish_error
)

rem --- Configuration ----------------------------------------------------------
if not exist "%CONFIG_FILE%" (
  echo.
  echo   No configuration file found at:
  echo     %CONFIG_FILE%
  echo.
  echo   Copy examples\pia-unifi-sync.example.json there and edit it so each
  echo   tunnel names a UniFi VPN Client and a PIA region. Run this launcher
  echo   with --list-networks to see the names your console actually uses.
  echo.
  goto :finish_error
)

if not exist "%ENV_FILE%" (
  echo.
  echo   No credentials file found at:
  echo     %ENV_FILE%
  echo.
  echo   Copy examples\pia-unifi-sync.env.example there and fill it in.
  echo   That file is already in .gitignore, so it will not be committed.
  echo.
  goto :finish_error
)

rem Load KEY=value pairs. `eol=#` skips comment lines; blank lines are skipped
rem by for /f. A value containing a double quote is not supported and will fail
rem loudly below rather than being silently truncated.
for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%ENV_FILE%") do (
  if not "%%~A"=="" set "%%A=%%B"
)

if not defined PIA_USERNAME goto :missing_credentials
if not defined PIA_PASSWORD goto :missing_credentials
if defined UNIFI_API_KEY goto :credentials_ok
if not defined UNIFI_USERNAME goto :missing_credentials
if not defined UNIFI_PASSWORD goto :missing_credentials
:credentials_ok

rem --- Arguments --------------------------------------------------------------
rem No arguments at all means a dry run. `--apply` means "no extra flag".
rem Anything else is passed through untouched.
set "ARGS=--dry-run"
if not "%~1"=="" (
  if /i "%~1"=="--apply" (
    set "ARGS="
  ) else (
    set "ARGS=%*"
  )
)

echo.
if defined ARGS (
  echo   Running: pia-unifi-sync %ARGS%
) else (
  echo   Running: pia-unifi-sync ^(applying changes to the console^)
)
echo.

node "%ENTRY%" --config "%CONFIG_FILE%" %ARGS%
set "EXIT_CODE=%errorlevel%"

echo.
if "%EXIT_CODE%"=="0" (
  echo   Finished.
) else (
  echo   Finished with errors ^(exit code %EXIT_CODE%^).
)
goto :finish

:missing_credentials
echo.
echo   %ENV_FILE%
echo   is missing something. It needs PIA_USERNAME and PIA_PASSWORD, plus
echo   either UNIFI_API_KEY on its own, or both UNIFI_USERNAME and
echo   UNIFI_PASSWORD.
echo.

:finish_error
set "EXIT_CODE=1"

:finish
rem Pause only when double-clicked, so running this from an open terminal does
rem not wait for a keypress. cmd.exe launches a double-clicked file with /c.
echo %cmdcmdline% | find /i "/c" >nul
if not errorlevel 1 pause
exit /b %EXIT_CODE%
