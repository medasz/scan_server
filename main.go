package main

import "scan_server/cmd"

var (
	version = "1.0.1"
)

func main() {
	cmd.Run(version)
}
