// Package identity reads and writes the passphrase-encrypted age
// identity file.
//
// The file is age-encrypted with an scrypt passphrase. On disk it is
// 0600 inside a 0700 directory, and Load refuses group- or
// world-readable files the way ssh does. The decrypted key material
// is held in a memguard LockedBuffer for the duration of one
// invocation and destroyed by the returned cleanup function.
package identity

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/awnumar/memguard"
)

const (
	fileMode = 0o600
	dirMode  = 0o700

	// unsafeBits are the group and world permission bits.
	unsafeBits = 0o077
)

// Load decrypts the identity file with the passphrase. The cleanup
// function wipes the decrypted key material and must be deferred by
// the caller.
func Load(path string, passphrase []byte) (*age.X25519Identity, func(), error) {
	cleaned := filepath.Clean(path)

	info, err := os.Stat(cleaned)
	if os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("%s: %w", cleaned, ErrNotFound)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("stat identity %s: %w", cleaned, err)
	}

	if info.Mode().Perm()&unsafeBits != 0 {
		return nil, nil, fmt.Errorf("%s has mode %04o: %w", cleaned, info.Mode().Perm(), ErrUnsafePermissions)
	}

	sealed, err := os.ReadFile(cleaned)
	if err != nil {
		return nil, nil, fmt.Errorf("read identity %s: %w", cleaned, err)
	}

	return decrypt(sealed, passphrase)
}

func decrypt(sealed, passphrase []byte) (*age.X25519Identity, func(), error) {
	scryptIdentity, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, nil, fmt.Errorf("prepare passphrase decryption: %w", err)
	}

	reader, err := age.Decrypt(bytes.NewReader(sealed), scryptIdentity)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrDecryptFailed, err)
	}

	plaintext, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrDecryptFailed, err)
	}

	// Move the key material into locked memory. NewBufferFromBytes
	// wipes the source slice.
	locked := memguard.NewBufferFromBytes(plaintext)
	cleanup := locked.Destroy

	key := string(bytes.TrimSpace(locked.Bytes()))

	parsed, err := age.ParseX25519Identity(key)
	if err != nil {
		cleanup()

		return nil, nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	return parsed, cleanup, nil
}

// Write encrypts the identity with the passphrase and creates the
// file at path with 0600 permissions inside a 0700 directory. It
// refuses to overwrite an existing file.
func Write(path string, key *age.X25519Identity, passphrase []byte) error {
	sealed, err := encrypt(key, passphrase)
	if err != nil {
		return err
	}

	cleaned := filepath.Clean(path)

	if err := os.MkdirAll(filepath.Dir(cleaned), dirMode); err != nil {
		return fmt.Errorf("create identity directory: %w", err)
	}

	file, err := os.OpenFile(cleaned, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if os.IsExist(err) {
		return fmt.Errorf("%s: %w", cleaned, ErrExists)
	}

	if err != nil {
		return fmt.Errorf("create identity file: %w", err)
	}

	if _, err := file.Write(sealed); err != nil {
		_ = file.Close()

		return fmt.Errorf("write identity file: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("write identity file: %w", err)
	}

	return nil
}

// Replace atomically swaps the identity file with one encrypted to a
// new passphrase or key. It writes a sibling temp file first and
// renames it over the original, so a crash never leaves a corrupt or
// missing identity.
func Replace(path string, key *age.X25519Identity, passphrase []byte) error {
	cleaned := filepath.Clean(path)
	temp := cleaned + ".tmp"

	if err := Write(temp, key, passphrase); err != nil {
		return err
	}

	if err := os.Rename(temp, cleaned); err != nil {
		_ = os.Remove(temp)

		return fmt.Errorf("replace identity file: %w", err)
	}

	return nil
}

func encrypt(key *age.X25519Identity, passphrase []byte) ([]byte, error) {
	scryptRecipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return nil, fmt.Errorf("prepare passphrase encryption: %w", err)
	}

	var sealed bytes.Buffer

	writer, err := age.Encrypt(&sealed, scryptRecipient)
	if err != nil {
		return nil, fmt.Errorf("encrypt identity: %w", err)
	}

	if _, err := fmt.Fprintln(writer, key.String()); err != nil {
		return nil, fmt.Errorf("encrypt identity: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("encrypt identity: %w", err)
	}

	return sealed.Bytes(), nil
}
