package main

import (
	"os"

	"github.com/threatexpert/gonc/v2/apps"
	"github.com/threatexpert/gonc/v2/misc"
)

func main() {
	console := &misc.ConsoleIO{}
	apps.App_Netcat_main(console, os.Args[1:])
}
