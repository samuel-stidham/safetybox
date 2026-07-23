//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package cmd

import "golang.org/x/sys/unix"

// The termios ioctl request codes on the BSD family, darwin included,
// matching x/term.
const (
	ioctlReadTermios  = unix.TIOCGETA
	ioctlWriteTermios = unix.TIOCSETA
)
