@echo off

set app=gonc

go mod init %app%
go mod tidy

set "LDFLAGS=-s -w -buildid= -checklinkname=0"
set "BUILD_FLAGS=-buildvcs=false -trimpath"

SET GOOS=windows
SET GOARCH=amd64
SET CGO_ENABLED=0
echo Building binary for %GOOS%_%GOARCH% ...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%.exe

SET GOOS=linux
SET GOARCH=amd64
SET CGO_ENABLED=0
echo Building binary for %GOOS%_%GOARCH% ...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%

@REM SET GOOS=linux
@REM SET GOARCH=mips
@REM SET CGO_ENABLED=0
@REM SET GOMIPS=softfloat
@REM echo Building binary for %GOOS%_%GOARCH% ...
@REM go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%
@REM SET GOMIPS=

SET GOOS=android
SET GOARCH=arm64
SET CGO_ENABLED=0
echo Building binary for %GOOS%_%GOARCH% ...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%

SET GOOS=windows
SET GOARCH=arm64
SET CGO_ENABLED=0
echo Building binary for %GOOS%_%GOARCH% ...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOARCH%.exe

@REM SET GOOS=linux
@REM SET GOARCH=386
@REM SET CGO_ENABLED=0
@REM echo Building binary for %GOOS%_%GOARCH% ...
@REM go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%

@REM SET GOOS=linux
@REM SET GOARCH=mips64
@REM SET CGO_ENABLED=0
@REM echo Building binary for %GOOS%_%GOARCH% ...
@REM go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%

@REM SET GOOS=linux
@REM SET GOARCH=mipsle
@REM SET CGO_ENABLED=0
@REM SET GOMIPS=softfloat
@REM echo Building binary for %GOOS%_%GOARCH% ...
@REM go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%
@REM SET GOMIPS=

@REM SET GOOS=linux
@REM SET GOARCH=arm
@REM SET CGO_ENABLED=0
@REM echo Building binary for %GOOS%_%GOARCH% ...
@REM go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%

SET GOOS=linux
SET GOARCH=arm64
SET CGO_ENABLED=0
echo Building binary for %GOOS%_%GOARCH% ...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%

SET GOOS=darwin
SET GOARCH=amd64
SET CGO_ENABLED=0
echo Building binary for %GOOS%_%GOARCH% ...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%

SET GOOS=darwin
SET GOARCH=arm64
SET CGO_ENABLED=0
echo Building binary for %GOOS%_%GOARCH% ...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%
