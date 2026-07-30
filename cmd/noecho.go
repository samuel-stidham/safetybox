package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"

	"github.com/awnumar/memguard"
	"golang.org/x/sys/unix"
)

// lineChunk is the initial capacity of the prompt line buffer and the
// extra headroom added on each growth.
const lineChunk = 64

// ErrPromptSignal reports that a terminating signal arrived while the
// prompt was reading. The handler exits the process, so a caller only
// observes this if the exit itself was replaced, which tests do.
var ErrPromptSignal = errors.New("prompt interrupted by a signal")

// readLineNoEcho reads one line from the terminal with echo disabled,
// growing through a wiping buffer. term.ReadPassword grows its line
// buffer by plain append, which abandons unzeroed prefixes of the
// passphrase inside the library. This mirrors its terminal state, echo
// off with canonical line assembly and signals kept on, and CR mapped
// to NL, then reads through the wiping loop instead.
func readLineNoEcho(stdinFd int) ([]byte, error) {
	return readLineNoEchoExiting(stdinFd, func() { memguard.SafeExit(1) })
}

// readLineNoEchoExiting is readLineNoEcho with the process exit injected.
// A test needs to observe that a signal terminates the process without
// taking the test binary down with it, and the exit is the whole point of
// the signal handler, so it cannot simply be left out.
func readLineNoEchoExiting(stdinFd int, exitProcess func()) ([]byte, error) {
	previous, err := unix.IoctlGetTermios(stdinFd, ioctlReadTermios)
	if err != nil {
		return nil, fmt.Errorf("read terminal state: %w", err)
	}

	restore := func() { _ = unix.IoctlSetTermios(stdinFd, ioctlWriteTermios, previous) }

	// Install the handler before echo goes off, never after. A signal
	// arriving in the gap between the two would find no handler, take the
	// default termination, and leave the shell with echo disabled, which
	// is the exact state this exists to prevent. Restoring a terminal that
	// was never changed is a harmless no-op, so registering early costs
	// nothing.
	var signalled atomic.Bool

	stopSignalRestore := onSignalRestore(restore, &signalled, exitProcess)
	defer stopSignalRestore()

	state := *previous
	state.Lflag &^= unix.ECHO
	state.Lflag |= unix.ICANON | unix.ISIG
	state.Iflag |= unix.ICRNL

	if err := unix.IoctlSetTermios(stdinFd, ioctlWriteTermios, &state); err != nil {
		return nil, fmt.Errorf("disable terminal echo: %w", err)
	}

	// Deferred after the handler, so it runs before it. The terminal goes
	// back first, then the handler comes down.
	defer restore()

	return readLineWiping(stdinFd, &signalled)
}

// onSignalRestore restores the terminal and then exits when a
// terminating signal arrives, and returns a function that tears the
// handler down.
//
// The exit is the load-bearing part. signal.Notify overrides the
// default termination for every signal it registers, so a handler that
// only restores the terminal leaves the process running with echo back
// on while the prompt is still reading, and the rest of the line is
// echoed. main installs memguard.CatchInterrupt, but that covers SIGINT
// alone, so it cannot be relied on to terminate the others.
//
// It also sets signalled before restoring, so the read loop refuses to
// resume during the wipe that SafeExit performs on the way out.
func onSignalRestore(restore func(), signalled *atomic.Bool, exitProcess func()) func() {
	signals := make(chan os.Signal, 1)

	// SIGINT and SIGQUIT arrive from the keyboard at the prompt, SIGTERM
	// from a supervisor or a timeout wrapper, and SIGHUP when the terminal
	// goes away. Each would otherwise leave echo disabled.
	signal.Notify(signals, os.Interrupt, unix.SIGTERM, unix.SIGHUP, unix.SIGQUIT)

	done := make(chan struct{})

	go func() {
		select {
		case <-signals:
			signalled.Store(true)
			restore()
			exitProcess()
		case <-done:
		}
	}()

	return func() {
		signal.Stop(signals)
		close(done)
	}
}

// readLineWiping reads until a newline or end of input, zeroing each
// buffer it outgrows, so no unzeroed prefix of the line survives on
// the heap. It reads one byte at a time, the way term.ReadPassword
// does, so it never consumes input past the newline. The newline is
// not included in the result. End of input before any newline returns
// what was read, matching term.ReadPassword.
//
// A read interrupted by a signal normally resumes, because a benign
// signal such as a window resize must not break the prompt. When
// signalled reports a terminating signal, the loop gives up instead:
// that signal has already put echo back, so resuming would echo the
// rest of the line.
//
// This is a backstop, not the defence. Go installs signal handlers with
// SA_RESTART, so a blocked read usually resumes without ever reporting
// EINTR. What actually stops the echo is the exit in onSignalRestore.
// This only narrows the window while SafeExit wipes the enclave.
func readLineWiping(stdinFd int, signalled *atomic.Bool) ([]byte, error) {
	line := make([]byte, 0, lineChunk)

	var one [1]byte

	defer zeroBytes(one[:])

	for {
		count, err := unix.Read(stdinFd, one[:])

		if errors.Is(err, unix.EINTR) {
			if signalled.Load() {
				zeroBytes(line)

				return nil, ErrPromptSignal
			}

			continue
		}

		if err != nil {
			zeroBytes(line)

			return nil, fmt.Errorf("read line: %w", err)
		}

		next := one[0]

		if count == 0 || next == '\n' {
			return line, nil
		}

		line = appendWiping(line, next)
	}
}

// appendWiping appends one byte to line, zeroing the outgrown buffer
// whenever the append must grow it.
func appendWiping(line []byte, next byte) []byte {
	if len(line) == cap(line) {
		grown := make([]byte, len(line), cap(line)+cap(line)+lineChunk)
		copy(grown, line)
		zeroBytes(line)
		line = grown
	}

	return append(line, next)
}
