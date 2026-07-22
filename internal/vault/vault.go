// Package vault implements the SQLite-backed secret store.
//
// It stores metadata and sealed envelopes only. Plaintext never
// enters this package. The vault stores the recipient public key so
// write verbs never need the private identity.
package vault

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	// The pure-Go SQLite driver, registered as "sqlite".
	_ "modernc.org/sqlite"
)

const (
	// formatVersion is the vault format this build reads and writes.
	formatVersion = 1

	vaultFileMode = 0o600
	vaultDirMode  = 0o700

	metaKeyFormatVersion = "format_version"
	metaKeyRecipient     = "recipient"

	// unsafeBits are the group and world permission bits.
	unsafeBits = 0o077
)

// Vault is an open handle to a vault database.
type Vault struct {
	handle *sql.DB
	path   string
}

// Create makes a new vault at path with the given recipient. The
// file is created 0600 with WAL journaling and schema v1. It fails
// if path already exists.
func Create(path, recipient string) error {
	path = filepath.Clean(path)

	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("create %s: %w", path, ErrVaultExists)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("create %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), vaultDirMode); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}

	// Pre-create the file so its permissions are 0600 from the first
	// byte. SQLite gives the -wal and -shm siblings the same mode.
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, vaultFileMode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}

	handle, err := openHandle(path)
	if err != nil {
		RemoveFiles(path)

		return err
	}

	if err := initSchema(handle, recipient); err != nil {
		_ = handle.Close()

		RemoveFiles(path)

		return err
	}

	if err := handle.Close(); err != nil {
		return fmt.Errorf("close new vault: %w", err)
	}

	return nil
}

// Open opens an existing vault and verifies its format version.
func Open(path string) (*Vault, error) {
	path = filepath.Clean(path)

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("open %s: %w", path, ErrVaultNotFound)
		}

		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	handle, err := openHandle(path)
	if err != nil {
		return nil, err
	}

	vault := &Vault{handle: handle, path: path}

	version, err := vault.metaValue(metaKeyFormatVersion)
	if err != nil {
		_ = handle.Close()

		// A file that opens as SQLite but has no vault_meta row or table
		// is not a readable vault. The commonest cause is a half-created
		// vault from a crashed init. Report a sentinel the cmd layer can
		// turn into recovery guidance, instead of a raw driver error.
		return nil, fmt.Errorf("open %s: %w: %w", path, ErrVaultCorrupt, err)
	}

	if version != strconv.Itoa(formatVersion) {
		_ = handle.Close()

		return nil, fmt.Errorf("open %s: found version %s, want %d: %w", path, version, formatVersion, ErrFormatVersion)
	}

	return vault, nil
}

// Close releases the underlying database handle.
func (v *Vault) Close() error {
	if err := v.handle.Close(); err != nil {
		return fmt.Errorf("close vault: %w", err)
	}

	return nil
}

// Path returns the filesystem path of the open vault.
func (v *Vault) Path() string {
	return v.path
}

// Recipient returns the stored recipient public key.
func (v *Vault) Recipient() (string, error) {
	recipient, err := v.metaValue(metaKeyRecipient)
	if err != nil {
		return "", fmt.Errorf("read recipient: %w", err)
	}

	return recipient, nil
}

func (v *Vault) metaValue(key string) (string, error) {
	var value string

	row := v.handle.QueryRowContext(context.Background(), "SELECT value FROM vault_meta WHERE key = ?", key)
	if err := row.Scan(&value); err != nil {
		return "", fmt.Errorf("vault_meta[%s]: %w", key, err)
	}

	return value, nil
}

func openHandle(path string) (*sql.DB, error) {
	// secure_delete(1) makes SQLite overwrite freed content with zeros
	// instead of leaving it in freelist pages, so purge and rekey
	// actually destroy old envelope bytes. _txlock=immediate starts
	// write transactions with a write lock up front, avoiding the
	// SQLITE_BUSY_SNAPSHOT a deferred read-then-write hits under
	// concurrency.
	dsn := "file:" + path +
		"?_txlock=immediate" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=secure_delete(1)" +
		"&_pragma=busy_timeout(5000)"

	handle, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// One connection per vault. This is a single-user CLI, so nothing
	// is lost to serialization, and it guarantees the post-purge and
	// post-rekey wal_checkpoint(TRUNCATE) runs on the only connection
	// in THIS process, with no pooled sibling pinning a WAL frame. A
	// concurrent safetybox process can still hold a read snapshot that
	// blocks the truncate. Checkpoint reports that as
	// ErrCheckpointBlocked so the purge and rekey verbs can warn.
	handle.SetMaxOpenConns(1)

	if err := handle.PingContext(context.Background()); err != nil {
		_ = handle.Close()

		return nil, fmt.Errorf("open database: %w", err)
	}

	return handle, nil
}

// initSchema applies every migration and writes vault_meta inside a
// single transaction.
func initSchema(handle *sql.DB, recipient string) error {
	ctx := context.Background()

	txn, err := handle.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema transaction: %w", err)
	}

	defer func() { _ = txn.Rollback() }()

	for i, migration := range migrations() {
		if _, err := txn.ExecContext(ctx, migration); err != nil {
			return fmt.Errorf("apply migration %d: %w", i+1, err)
		}
	}

	const insertMeta = "INSERT INTO vault_meta (key, value) VALUES (?, ?)"

	if _, err := txn.ExecContext(ctx, insertMeta, metaKeyFormatVersion, strconv.Itoa(formatVersion)); err != nil {
		return fmt.Errorf("write format version: %w", err)
	}

	if _, err := txn.ExecContext(ctx, insertMeta, metaKeyRecipient, recipient); err != nil {
		return fmt.Errorf("write recipient: %w", err)
	}

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("commit schema: %w", err)
	}

	return nil
}

// LoosePermission names one vault-related file whose mode grants group
// or world access, for the cmd layer to warn about. Path is the file
// or directory, and Recommend is the mode it should carry.
type LoosePermission struct {
	Label     string
	Path      string
	Mode      os.FileMode
	Recommend os.FileMode
}

// LoosePermissions returns a [LoosePermission] for each vault-related
// path that grants group or world access: the database file, its
// containing directory, and the -wal and -shm siblings. It never
// prints, so the cmd layer owns the warning, and it skips a path that
// does not exist. Unlike the identity file, which gates key material
// and is refused when loose, the vault holds ciphertext and public
// metadata, so a loose vault is reported rather than blocked.
func LoosePermissions(path string) []LoosePermission {
	path = filepath.Clean(path)

	targets := []struct {
		label     string
		path      string
		recommend os.FileMode
	}{
		{"vault file", path, vaultFileMode},
		{"vault directory", filepath.Dir(path), vaultDirMode},
		{"vault write-ahead log", path + "-wal", vaultFileMode},
		{"vault shared-memory file", path + "-shm", vaultFileMode},
	}

	var loose []LoosePermission

	for _, target := range targets {
		info, err := os.Stat(target.path)
		if err != nil {
			continue
		}

		perm := info.Mode().Perm()
		if perm&unsafeBits == 0 {
			continue
		}

		loose = append(loose, LoosePermission{
			Label:     target.label,
			Path:      target.path,
			Mode:      perm,
			Recommend: target.recommend,
		})
	}

	return loose
}

// RemoveFiles deletes a vault database and its WAL siblings, best
// effort. It is for unwinding a vault created earlier in the same
// invocation, such as after a failed self-test, so a retry does not
// hit ErrVaultExists. It does not distinguish a live vault from a
// half-created one. The caller owns that judgement.
func RemoveFiles(path string) {
	_ = os.Remove(path)
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")
}
