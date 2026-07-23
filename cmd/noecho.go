package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

// lineChunk is the initial capacity of the prompt line buffer and the
// extra headroom added on each growth.
const lineChunk = 64

// readLineNoEcho reads one line from the terminal with echo disabled,
// growing through a wiping buffer. term.ReadPassword grows its line
// buffer by plain append, which abandons unzeroed prefixes of the
// passphrase inside the library. This mirrors its terminal state, echo
// off with canonical line assembly and signals kept on, and CR mapped
// to NL, then reads through the wiping loop instead.
func readLineNoEcho(stdinFd int) ([]byte, error) {
	previous, err := unix.IoctlGetTermios(stdinFd, ioctlReadTermios)
	if err != nil {
		return nil, fmt.Errorf("read terminal state: %w", err)
	}

	state := *previous
	state.Lflag &^= unix.ECHO
	state.Lflag |= unix.ICANON | unix.ISIG
	state.Iflag |= unix.ICRNL

	if err := unix.IoctlSetTermios(stdinFd, ioctlWriteTermios, &state); err != nil {
		return nil, fmt.Errorf("disable terminal echo: %w", err)
	}

	restore := func() { _ = unix.IoctlSetTermios(stdinFd, ioctlWriteTermios, previous) }

	defer restore()

	// Echo is off now. A Ctrl-C at the prompt raises SIGINT, and the
	// memguard interrupt handler in main wipes the enclave and exits
	// the process without unwinding the defer above, which would leave
	// the shell with echo disabled. Restore the terminal from a signal
	// handler too, so an interrupted prompt does not leave a broken
	// shell. Both restores run the same idempotent ioctl. This is best
	// effort: it races the memguard handler's exit, and it usually wins
	// because the restore is one syscall.
	stopSignalRestore := onSignalRestore(restore)
	defer stopSignalRestore()

	return readLineWiping(stdinFd)
}

// onSignalRestore runs restore when the process receives an interrupt
// or terminate signal, and returns a function that tears the handler
// down. Registering with signal.Notify overrides the default exit for
// these signals. So the process relies on the memguard interrupt
// handler installed in main to actually exit. This handler only
// restores the terminal, it does not exit.
func onSignalRestore(restore func()) func() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, unix.SIGTERM)

	done := make(chan struct{})

	go func() {
		select {
		case <-signals:
			restore()
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
func readLineWiping(stdinFd int) ([]byte, error) {
	line := make([]byte, 0, lineChunk)

	var one [1]byte

	defer zeroBytes(one[:])

	for {
		count, err := unix.Read(stdinFd, one[:])

		if errors.Is(err, unix.EINTR) {
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
