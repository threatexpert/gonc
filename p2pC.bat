title p2p-C
@echo off

:: Note: For actual use, replace 12345678 with a private and secure key.
:: You can run `gonc -p2p .` to automatically generate a strong password.

:loop
echo ________________________________
echo Running command at %TIME%

gonc.exe -mqtt-push hello -p2p-kcp 12345678 -exec "-app-mux -l 9999" -tls

timeout /t 10 >nul
goto loop
