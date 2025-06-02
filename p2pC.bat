title p2p-C
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

gonc.exe -mqtt-push hello -p2p "@%~1" -exec "-app-mux -l 9998"

timeout /t 10 >nul
goto loop