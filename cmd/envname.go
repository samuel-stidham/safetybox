package cmd

import "strings"

// isReservedEnvName reports whether injecting name would hand over
// control of the child rather than pass it data.
//
// Every name here is a syntactically valid identifier, so
// isShellIdentifier accepts them all and this is the only thing standing
// between a vault row and code execution. The stakes are concrete. exec
// starts from os.Environ and appends, and os/exec keeps the later value
// on a duplicate, so an injected PATH replaces the real one for the
// child. reveal --format sh emits assignments that a shell sourcing them
// from an .envrc or a secrets.fish applies to the whole session.
//
// The comparison is case-sensitive, because environment variables are: a
// lowercase "path" is a different variable and carries none of this
// meaning.
func isReservedEnvName(name string) bool {
	switch name {
	case
		// The shell finds commands through PATH and splits words on IFS.
		"PATH", "IFS",
		// sh and bash execute these files at startup.
		"ENV", "BASH_ENV",
		// bash executes these as commands.
		"PROMPT_COMMAND", "PS4",
		// These change how the shell itself behaves.
		"SHELL", "SHELLOPTS", "BASHOPTS", "CDPATH", "GLOBIGNORE":
		return true
	}

	// The dynamic loader reads these before a program's own code runs.
	// LD_PRELOAD and DYLD_INSERT_LIBRARIES load an arbitrary shared
	// object into every child.
	return strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_")
}
