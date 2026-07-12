// Package identity reads and writes the passphrase-encrypted age
// identity file.
//
// The file is age-encrypted with an scrypt passphrase. On disk it is
// 0600 inside a 0700 directory, and Load refuses group- or
// world-readable files, and a loose containing directory, the way ssh
// does. The decrypted file bytes pass through a memguard LockedBuffer
// that is wiped by the returned cleanup function. The parsed key
// itself is an *age.X25519Identity, which age holds in an ordinary Go
// slice on the heap for the duration of one invocation. That heap
// copy is the practical limit of the in-memory protection here.
package identity

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

	if err := checkDirPerms(filepath.Dir(cleaned)); err != nil {
		return nil, nil, err
	}

	// Open once and stat the descriptor, so the permission check and
	// the read provably see the same file even if the path is swapped.
	file, err := os.Open(cleaned)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("%s: %w", cleaned, ErrNotFound)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("open identity %s: %w", cleaned, err)
	}

	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat identity %s: %w", cleaned, err)
	}

	if info.Mode().Perm()&unsafeBits != 0 {
		return nil, nil, fmt.Errorf("%s has mode %04o: %w", cleaned, info.Mode().Perm(), ErrUnsafePermissions)
	}

	sealed, err := io.ReadAll(file)
	if err != nil {
		return nil, nil, fmt.Errorf("read identity %s: %w", cleaned, err)
	}

	return decrypt(sealed, passphrase)
}

// checkDirPerms refuses an identity directory readable or writable by
// group or world, the ssh-style check invariant 3 extends to the
// containing directory, whether the directory is fresh or pre-existing.
func checkDirPerms(dir string) error {
	info, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s: %w", dir, ErrNotFound)
	}

	if err != nil {
		return fmt.Errorf("stat identity directory %s: %w", dir, err)
	}

	if info.Mode().Perm()&unsafeBits != 0 {
		return fmt.Errorf("directory %s has mode %04o: %w", dir, info.Mode().Perm(), ErrUnsafeDirPermissions)
	}

	return nil
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

		// The age parse error can embed fragments of the decrypted
		// file (the bech32 HRP and byte values), so it is dropped
		// here rather than wrapped. Invariant 1: never in errors.
		return nil, nil, fmt.Errorf("parse identity: %w", ErrMalformed)
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

	dir := filepath.Dir(cleaned)

	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("create identity directory: %w", err)
	}

	// MkdirAll leaves a pre-existing directory's mode untouched, so
	// enforce 0700 explicitly rather than trusting the create path.
	if err := checkDirPerms(dir); err != nil {
		return err
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

	// fsync before close so a crash cannot leave a zero-length or
	// partial identity, which for the sole private key is data loss.
	if err := file.Sync(); err != nil {
		_ = file.Close()

		return fmt.Errorf("sync identity file: %w", err)
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

	// fsync the directory so the rename itself is durable. Without it,
	// a crash can commit the rename's data but not the directory entry,
	// leaving the sole private key missing.
	if err := syncDir(filepath.Dir(cleaned)); err != nil {
		return err
	}

	return nil
}

// syncDir flushes a directory's metadata so a rename inside it
// survives a crash.
func syncDir(dir string) error {
	// dir is the identity file's own directory, derived from the
	// resolved identity path, not external input. Opened only to fsync.
	handle, err := os.Open(dir) //nolint:gosec // trusted internal directory path, opened for fsync only
	if err != nil {
		return fmt.Errorf("open identity directory %s: %w", dir, err)
	}

	defer func() { _ = handle.Close() }()

	if err := handle.Sync(); err != nil {
		return fmt.Errorf("sync identity directory %s: %w", dir, err)
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
