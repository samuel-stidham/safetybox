package main

import (
	"runtime/debug"

	"github.com/samuel-stidham/safetybox/cmd"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cmd.Execute(resolveVersion())
}

// resolveVersion falls back to the module version recorded in the
// build info when the ldflags injection did not run, which is the
// case for a plain `go install module@version`. That path previously
// reported "dev" for real tagged installs.
func resolveVersion() string {
	if version != "dev" {
		return version
	}

	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return version
	}

	return info.Main.Version
}
