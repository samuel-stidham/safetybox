//go:build linux || darwin

package cmd

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// stubExit returns a fake process exit and a channel closed when it is
// called. The real exit calls memguard.SafeExit, which would take the
// test binary down with it.
func stubExit() (func(), <-chan struct{}) {
	exited := make(chan struct{})

	var once atomic.Bool

	return func() {
		if once.CompareAndSwap(false, true) {
			close(exited)
		}
	}, exited
}

// TestPromptSignalRestoresEchoAndExits pins the fix for the disclosure
// where a SIGTERM at a prompt put echo back and left the read running,
// so the rest of the passphrase was echoed to the terminal.
//
// signal.Notify overrides the default termination for every signal it
// registers, and memguard.CatchInterrupt in main covers SIGINT alone.
// So the handler itself has to exit. This asserts both halves: the
// terminal goes back to its original state, and the exit is requested.
func TestPromptSignalRestoresEchoAndExits(t *testing.T) {
	for _, signalUnderTest := range []struct {
		name   string
		signal unix.Signal
	}{
		{name: "SIGTERM", signal: unix.SIGTERM},
		{name: "SIGHUP", signal: unix.SIGHUP},
		{name: "SIGQUIT", signal: unix.SIGQUIT},
	} {
		t.Run(signalUnderTest.name, func(t *testing.T) {
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

			exitProcess, exited := stubExit()

			finished := make(chan struct{})

			go func() {
				defer close(finished)

				line, _ := readLineNoEchoExiting(slaveFd, exitProcess)

				zeroBytes(line)
			}()

			require.Eventually(t, func() bool {
				during, getErr := unix.IoctlGetTermios(slaveFd, ioctlReadTermios)

				return getErr == nil && during.Lflag&unix.ECHO == 0
			}, 2*time.Second, 10*time.Millisecond, "echo must go off while the prompt reads")

			// The handler is registered now, so this signal cannot fall
			// through to the default action and kill the test binary.
			require.NoError(t, unix.Kill(unix.Getpid(), signalUnderTest.signal))

			select {
			case <-exited:
			case <-time.After(2 * time.Second):
				require.Fail(t, "the signal handler must terminate the process, not resume the read")
			}

			after, err := unix.IoctlGetTermios(slaveFd, ioctlReadTermios)
			require.NoError(t, err)
			assert.Equal(t, before.Lflag, after.Lflag,
				"the terminal must be restored before the process exits")
			assert.NotZero(t, after.Lflag&unix.ECHO,
				"echo must be back on, so a broken shell is not left behind")

			// The stubbed exit returned instead of terminating, so the
			// read is still blocked. Finish the line to unblock it, or
			// the handler stays registered and bleeds into later tests.
			_, err = master.WriteString("\n")
			require.NoError(t, err)

			select {
			case <-finished:
			case <-time.After(2 * time.Second):
				require.Fail(t, "the prompt must return once the line completes")
			}
		})
	}
}

// The EINTR backstop in readLineWiping has no test. Go installs signal
// handlers with SA_RESTART, so a blocked read resumes without ever
// reporting EINTR, and there is no portable way to force it. The
// disclosure itself is pinned by the exit assertion above, which is the
// defence that actually stops the echo.

// TestSignalRestoreTeardownStopsTheHandler checks that the teardown
// returned by onSignalRestore actually detaches, so a later signal in
// the same process is not swallowed by a stale handler.
func TestSignalRestoreTeardownStopsTheHandler(t *testing.T) {
	exitProcess, exited := stubExit()

	var (
		restored  atomic.Bool
		signalled atomic.Bool
	)

	stop := onSignalRestore(func() { restored.Store(true) }, &signalled, exitProcess)
	stop()

	// Give the goroutine a moment to observe the closed done channel.
	assert.Never(t, func() bool {
		return restored.Load() || signalled.Load()
	}, 200*time.Millisecond, 20*time.Millisecond,
		"a torn-down handler must not restore or flag anything")

	select {
	case <-exited:
		require.Fail(t, "a torn-down handler must not exit the process")
	default:
	}
}
