title p2p-S
@echo off

:: Note: For actual use, replace 12345678 with a private and secure key.
:: You can run `gonc -p2p .` to automatically generate a strong password.

:loop
echo ________________________________
echo Running command at %TIME%

gonc.exe -mqtt-wait hello -p2p-kcp 12345678 -exec ". -app-mux 127.0.0.1 3389" -keep-open

timeout /t 2 >nul
goto loop
