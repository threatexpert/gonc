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

SET GOOS=linux
SET GOARCH=mips
SET CGO_ENABLED=0
SET GOMIPS=softfloat
echo Building binary for %GOOS%_%GOARCH% ...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%
SET GOMIPS=

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

SET GOOS=linux
SET GOARCH=386
SET CGO_ENABLED=0
echo Building binary for %GOOS%_%GOARCH% ...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%

SET GOOS=linux
SET GOARCH=mips64
SET CGO_ENABLED=0
echo Building binary for %GOOS%_%GOARCH% ...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%

SET GOOS=linux
SET GOARCH=mipsle
SET CGO_ENABLED=0
SET GOMIPS=softfloat
echo Building binary for %GOOS%_%GOARCH% ...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%
SET GOMIPS=

SET GOOS=linux
SET GOARCH=arm
SET CGO_ENABLED=0
echo Building binary for %GOOS%_%GOARCH% ...
go build %BUILD_FLAGS% -ldflags="%LDFLAGS%" -o bin/%app%_%GOOS%_%GOARCH%

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
