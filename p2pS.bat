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

gonc.exe -mqtt-wait hello -p2p "@%~1" -exec "-app-mux 127.0.0.1 3389" -keep-open

timeout /t 2 >nul
goto loop
