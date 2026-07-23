//go:build linux || darwin

package cmd

import (
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestReadLineNoEchoOnPTY drives the no-echo prompt against a real
// pseudo-terminal. The pipe-based tests cover the reading loop, but only
// a terminal exercises the termios handling. This checks the three
// properties the roadmap named: echo is off while the line is read, the
// returned line is exact, and the terminal state is restored on return.
func TestReadLineNoEchoOnPTY(t *testing.T) {
	master, slave, err := pty.Open()
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
	})

	slaveFd := int(slave.Fd())

	before, err := unix.IoctlGetTermios(slaveFd, ioctlReadTermios)
	require.NoError(t, err)
	require.NotZero(t, before.Lflag&unix.ECHO, "a fresh pty starts with echo enabled")

	const typed = "fake-typed-passphrase-not-real"

	type outcome struct {
		line []byte
		err  error
	}

	done := make(chan outcome, 1)

	go func() {
		line, readErr := readLineNoEcho(slaveFd)
		done <- outcome{line: line, err: readErr}
	}()

	// Poll until the prompt has disabled echo and is blocked on its read,
	// so the write below arrives with echo already off. A fixed sleep
	// could be flaky under load.
	require.Eventually(t, func() bool {
		during, getErr := unix.IoctlGetTermios(slaveFd, ioctlReadTermios)

		return getErr == nil && during.Lflag&unix.ECHO == 0
	}, 2*time.Second, 10*time.Millisecond, "echo must go off while the prompt reads")

	_, err = master.WriteString(typed + "\n")
	require.NoError(t, err)

	got := <-done
	require.NoError(t, got.err)
	assert.Equal(t, []byte(typed), got.line, "the prompt must read back the exact line")

	after, err := unix.IoctlGetTermios(slaveFd, ioctlReadTermios)
	require.NoError(t, err)
	assert.Equal(t, before.Lflag, after.Lflag, "the terminal state must be restored on return")
}
