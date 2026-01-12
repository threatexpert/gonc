#!/usr/bin/env sh

app=gonc

go mod init "$app"
go mod tidy

LDFLAGS="-s -w -buildid= -checklinkname=0"
BUILD_FLAGS="-buildvcs=false -trimpath"

go build $BUILD_FLAGS -ldflags="$LDFLAGS" -o "$app"
