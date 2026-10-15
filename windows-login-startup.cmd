@echo off
REM HITL Connect - explicitly enabled current-user login startup.
set "HITL_STARTUP_DIR=%LOCALAPPDATA%\HITLConnectStartup"
if not exist "%HITL_STARTUP_DIR%" exit /b 1
echo %DATE% %TIME% entry_started>>"%HITL_STARTUP_DIR%\bootstrap.log"
set "HITL_PYTHONW=%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\pythonw.exe"
if exist "%HITL_PYTHONW%" goto runtime_ready
set "HITL_PYTHONW=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\pythonw.exe"
if exist "%HITL_PYTHONW%" goto runtime_ready
echo %DATE% %TIME% pythonw_missing>>"%HITL_STARTUP_DIR%\bootstrap.log"
exit /b 1
:runtime_ready
if exist "%HITL_STARTUP_DIR%\launch_hitl.pyw" goto launch_ready
echo %DATE% %TIME% launcher_missing>>"%HITL_STARTUP_DIR%\bootstrap.log"
exit /b 1
:launch_ready
echo %DATE% %TIME% launching_pythonw>>"%HITL_STARTUP_DIR%\bootstrap.log"
start "" "%HITL_PYTHONW%" "%HITL_STARTUP_DIR%\launch_hitl.pyw"
if errorlevel 1 echo %DATE% %TIME% launch_failed>>"%HITL_STARTUP_DIR%\bootstrap.log"
exit /b 0
