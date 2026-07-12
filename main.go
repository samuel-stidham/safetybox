package main

import "github.com/samuel-stidham/safetybox/cmd"

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cmd.Execute(version)
}
