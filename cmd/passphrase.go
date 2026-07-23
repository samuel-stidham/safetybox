package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/samuel-stidham/safetybox/v2/internal/secret"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// readPassphrase returns the passphrase from --passphrase-file, or
// from a single no-echo prompt. Passphrases never come from argv or
// environment variables.
func readPassphrase(cobraCmd *cobra.Command, passphraseFile, label string) ([]byte, error) {
	if passphraseFile != "" {
		return passphraseFromFile(passphraseFile)
	}

	return promptOnce(cobraCmd, label, "passphrase")
}

// readNewPassphrase returns a passphrase for new key material, from a
// file or from a prompt-and-confirm pair.
func readNewPassphrase(cobraCmd *cobra.Command, passphraseFile, label string) ([]byte, error) {
	if passphraseFile != "" {
		return passphraseFromFile(passphraseFile)
	}

	passphrase, err := promptOnce(cobraCmd, label, "passphrase")
	if err != nil {
		return nil, err
	}

	confirmation, err := promptOnce(cobraCmd, "Confirm passphrase: ", "passphrase")
	if err != nil {
		zeroBytes(passphrase)

		return nil, err
	}

	defer zeroBytes(confirmation)

	if !bytes.Equal(passphrase, confirmation) {
		zeroBytes(passphrase)

		return nil, errors.New("passphrases do not match")
	}

	return passphrase, nil
}

// passphraseUnsafeBits are the group and world permission bits a
// regular passphrase file must not carry, mirroring the identity
// file's ssh-style check (invariant 3).
const passphraseUnsafeBits = 0o077

func passphraseFromFile(passphraseFile string) ([]byte, error) {
	// Open once and stat the descriptor so the check and the read see
	// the same object.
	file, err := os.Open(filepath.Clean(passphraseFile))
	if err != nil {
		return nil, fmt.Errorf("open passphrase file: %w", err)
	}

	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat passphrase file: %w", err)
	}

	// Only a regular on-disk file is held to the permission check. A
	// fifo or pipe from process substitution (secret-get | psub) is a
	// transient stream, not an at-rest secret, so it is allowed.
	if info.Mode().IsRegular() && info.Mode().Perm()&passphraseUnsafeBits != 0 {
		return nil, fmt.Errorf("passphrase file %s has mode %04o: run chmod 600 on it",
			passphraseFile, info.Mode().Perm())
	}

	content, err := secret.ReadAllWiping(file)
	if err != nil {
		return nil, fmt.Errorf("read passphrase file: %w", err)
	}

	// Trim trailing newlines left by editors and echo.
	passphrase := bytes.TrimRight(content, "\r\n")
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase file is empty")
	}

	return passphrase, nil
}

// promptOnce reads one no-echo line. noun names what is being read,
// so the set value prompt does not error about a passphrase.
func promptOnce(cobraCmd *cobra.Command, label, noun string) ([]byte, error) {
	stdinFd := int(os.Stdin.Fd())
	if !term.IsTerminal(stdinFd) {
		return nil, errors.New("stdin is not a terminal: use --passphrase-file")
	}

	printStderr(cobraCmd, label)

	entered, err := readLineNoEcho(stdinFd)

	printStderr(cobraCmd, "\n")

	if err != nil {
		return nil, fmt.Errorf("read %s: %w", noun, err)
	}

	if len(entered) == 0 {
		return nil, fmt.Errorf("%s must not be empty", noun)
	}

	return entered, nil
}

func zeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

// printStderr writes user-facing text, ignoring write errors the way
// terminal prompts always do.
func printStderr(cobraCmd *cobra.Command, text string) {
	_, _ = fmt.Fprint(cobraCmd.ErrOrStderr(), text)
}
