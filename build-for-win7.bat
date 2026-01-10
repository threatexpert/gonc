@echo off
setlocal

REM === Use Win7-compatible Go toolchain ===
REM https://github.com/XTLS/go-win7/releases/download/patched-1.24.4/go-for-win7-windows-amd64.zip
set "GOROOT=C:\go\go-1.24.4-win7"
set "PATH=%GOROOT%\bin;%PATH%"

REM === Validate GOROOT ===
if not exist "%GOROOT%\bin\go.exe" (
    echo ERROR: Go toolchain not found at "%GOROOT%"
    exit /b 1
)

REM Verify Go toolchain
go version
go env GOROOT

REM === Application name ===
set app=gonc

REM === Initialize module and dependencies ===
go mod init %app% 2>nul
go mod tidy

REM === Build flags ===
set "LDFLAGS=-s -w -buildid= -checklinkname=0"
set "BUILD_FLAGS=-buildvcs=false -trimpath"

set GOOS=windows
set GOARCH=386
set CGO_ENABLED=0

echo Building binary for %GOOS%_%GOARCH% (Win7)...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin\%app%_%GOARCH%.exe

@REM set GOOS=windows
@REM set GOARCH=amd64
@REM set CGO_ENABLED=0

@REM echo Building binary for %GOOS%_%GOARCH% (Win7)...
@REM go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin\%app%.exe

@REM SET GOOS=windows
@REM SET GOARCH=arm64
@REM SET CGO_ENABLED=0
@REM echo Building binary for %GOOS%_%GOARCH% (Win7)...
@REM go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOARCH%.exe

build.bat

endlocal
