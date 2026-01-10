@echo off
setlocal

REM === Use Win7-compatible Go toolchain ===
set "GOROOT=C:\go\go-1.24.3-win7"
set "PATH=%GOROOT%\bin;%PATH%"

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

echo Building windows/amd64 binary...
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0

go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin\%app%.exe

echo Building windows/386 binary...
set GOOS=windows
set GOARCH=386
set CGO_ENABLED=0

go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin\%app%_%GOARCH%.exe

echo Building windows/arm64 binary...
SET GOOS=windows
SET GOARCH=arm64
SET CGO_ENABLED=0
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOARCH%.exe

endlocal
