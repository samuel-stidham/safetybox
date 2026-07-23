//go:build darwin

package cmd

import "golang.org/x/sys/unix"

// The termios ioctl request codes on darwin, matching x/term.
const (
	ioctlReadTermios  = unix.TIOCGETA
	ioctlWriteTermios = unix.TIOCSETA
)
