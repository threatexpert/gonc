title p2p-S
@echo off
cd %~dp0

:check_file
if "%~1"=="" (
    echo Please drag and drop a PSK file onto this batch file
    echo You can run `gonc -psk .` to automatically generate a strong password.
    pause
    exit /b
)

:loop
echo ________________________________
echo Running command at %TIME%

gonc.exe -p2p "@%~1" -P -linkagent

timeout /t 2 >nul
goto loop
