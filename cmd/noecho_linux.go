//go:build linux

package cmd

import "golang.org/x/sys/unix"

// The termios ioctl request codes on linux, matching x/term.
const (
	ioctlReadTermios  = unix.TCGETS
	ioctlWriteTermios = unix.TCSETS
)
