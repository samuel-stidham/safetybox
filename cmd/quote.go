package cmd

import "strings"

// quoteSh single-quotes value for POSIX shells. An embedded single
// quote closes the string, escapes itself, and reopens.
func quoteSh(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// quoteFish single-quotes value for fish, where backslash and single
// quote are the only characters interpreted inside single quotes.
func quoteFish(value string) string {
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `'`, `\'`)

	return "'" + escaped + "'"
}
