go mod init gonc
go mod tidy

set app=gonc

set PY=
python --version > nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    set PY=python > nul
)
py --version > nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    set PY=py > nul
)
if "%PY%"=="" (
    echo no python
)


SET GOOS=windows
SET GOARCH=386
SET CGO_ENABLED=0
go build -buildvcs=false -ldflags="-s -w -buildid=" -trimpath -o bin/gonc.exe

SET GOOS=linux
SET GOARCH=amd64
SET CGO_ENABLED=0
go build -buildvcs=false -ldflags="-s -w -buildid=" -trimpath -o bin/%app%_%GOOS%_%GOARCH%

SET GOOS=linux
SET GOARCH=386
SET CGO_ENABLED=0
go build -buildvcs=false -ldflags="-s -w -buildid=" -trimpath -o bin/%app%_%GOOS%_%GOARCH%

SET GOOS=linux
SET GOARCH=mips64
SET CGO_ENABLED=0
go build -buildvcs=false -ldflags="-s -w -buildid=" -trimpath -o bin/%app%_%GOOS%_%GOARCH%

SET GOOS=linux
SET GOARCH=mips
SET CGO_ENABLED=0
SET GOMIPS=softfloat
go build -buildvcs=false -ldflags="-s -w -buildid=" -trimpath -o bin/%app%_%GOOS%_%GOARCH%
SET GOMIPS=

SET GOOS=linux
SET GOARCH=mipsle
SET CGO_ENABLED=0
SET GOMIPS=softfloat
go build -buildvcs=false -ldflags="-s -w -buildid=" -trimpath -o bin/%app%_%GOOS%_%GOARCH%
SET GOMIPS=

SET GOOS=linux
SET GOARCH=arm
SET CGO_ENABLED=0
go build -buildvcs=false -ldflags="-s -w -buildid=" -trimpath -o bin/%app%_%GOOS%_%GOARCH%

SET GOOS=linux
SET GOARCH=arm64
SET CGO_ENABLED=0
go build -buildvcs=false -ldflags="-s -w -buildid=" -trimpath -o bin/%app%_%GOOS%_%GOARCH%

SET GOOS=darwin
SET GOARCH=amd64
SET CGO_ENABLED=0
go build -buildvcs=false -ldflags="-s -w -buildid=" -trimpath -o bin/%app%_%GOOS%_%GOARCH%

SET GOOS=darwin
SET GOARCH=arm64
SET CGO_ENABLED=0
go build -buildvcs=false -ldflags="-s -w -buildid=" -trimpath -o bin/%app%_%GOOS%_%GOARCH%

