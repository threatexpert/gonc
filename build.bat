set app=gonc

go mod init %app%
go mod tidy


SET GOOS=windows
SET GOARCH=amd64
SET CGO_ENABLED=0
go build -buildvcs=false -ldflags="-s -w -buildid=" -trimpath -o bin/%app%.exe

SET GOOS=windows
SET GOARCH=386
SET CGO_ENABLED=0
go build -buildvcs=false -ldflags="-s -w -buildid=" -trimpath -o bin/%app%_%GOARCH%.exe

SET GOOS=windows
SET GOARCH=arm64
SET CGO_ENABLED=0
go build -buildvcs=false -ldflags="-s -w -buildid=" -trimpath -o bin/%app%_%GOARCH%.exe

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

SET GOOS=android
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

