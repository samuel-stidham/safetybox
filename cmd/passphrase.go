package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

	return promptOnce(cobraCmd, label)
}

// readNewPassphrase returns a passphrase for new key material, from a
// file or from a prompt-and-confirm pair.
func readNewPassphrase(cobraCmd *cobra.Command, passphraseFile, label string) ([]byte, error) {
	if passphraseFile != "" {
		return passphraseFromFile(passphraseFile)
	}

	passphrase, err := promptOnce(cobraCmd, label)
	if err != nil {
		return nil, err
	}

	confirmation, err := promptOnce(cobraCmd, "Confirm passphrase: ")
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

func passphraseFromFile(passphraseFile string) ([]byte, error) {
	content, err := os.ReadFile(filepath.Clean(passphraseFile))
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

func promptOnce(cobraCmd *cobra.Command, label string) ([]byte, error) {
	stdinFd := int(os.Stdin.Fd())
	if !term.IsTerminal(stdinFd) {
		return nil, errors.New("stdin is not a terminal: use --passphrase-file")
	}

	printStderr(cobraCmd, label)

	passphrase, err := term.ReadPassword(stdinFd)

	printStderr(cobraCmd, "\n")

	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}

	if len(passphrase) == 0 {
		return nil, errors.New("passphrase must not be empty")
	}

	return passphrase, nil
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
