package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// MigrationResealer re-seals one version's envelope during a format
// migration. It decrypts the old frame and re-seals the value into the
// current frame with the given env name and expiry bound into it. It
// returns the re-sealed envelope and the env name it actually sealed,
// which differs from the input when a legacy env name held a character
// the new frame cannot store, such as a newline. The migration then
// reconciles the shared column with the sealed value, so a later read
// does not refuse the secret.
type MigrationResealer func(
	name string, number int64, envName, expiresAt string, oldEnvelope []byte,
) (resealed []byte, sealedEnvName string, err error)

// migrateVersion identifies one row the migration must re-seal, with the
// bound metadata to seal into its new frame.
type migrateVersion struct {
	id        int64
	name      string
	number    int64
	envName   string
	expiresAt string
}

// Migrate upgrades a format 1 vault at path to the current format in
// place. It re-seals every non-destroyed envelope through reseal, which
// decrypts the old address-only frame and re-seals the value into the
// current frame with the secret's env name and expiry bound in. It then
// sets the format version. Everything runs in one transaction, so a
// failure leaves the format 1 vault intact. It returns the number of
// envelopes re-sealed. It returns [ErrAlreadyCurrentFormat] when the
// vault is already current, so a re-run after a crash is safe. It
// refuses with [ErrRecipientMismatch] when expectedRecipient does not
// match the stored recipient, so migrate does not re-seal every
// envelope on a vault whose recipient was swapped.
func Migrate(ctx context.Context, path, expectedRecipient string, reseal MigrationResealer) (int64, error) {
	path = filepath.Clean(path)

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("open %s: %w", path, ErrVaultNotFound)
		}

		return 0, fmt.Errorf("open %s: %w", path, err)
	}

	handle, err := openHandle(ctx, path)
	if err != nil {
		return 0, err
	}

	defer func() { _ = handle.Close() }()

	migrated := &Vault{handle: handle, path: path}

	if err := checkMigratable(ctx, migrated, expectedRecipient); err != nil {
		return 0, err
	}

	count, err := resealForMigration(ctx, migrated, reseal)
	if err != nil {
		return 0, err
	}

	// Flush the WAL so the old frames do not survive in write-ahead
	// frames after the upgrade. Best effort, as after purge and rekey.
	_ = migrated.Checkpoint(ctx)

	return count, nil
}

// checkMigratable confirms the vault is a real vault at format version
// 1 encrypted to expectedRecipient. A vault already at the current
// format returns [ErrAlreadyCurrentFormat], and any other version is
// unsupported. A stored recipient that does not match returns
// [ErrRecipientMismatch].
func checkMigratable(ctx context.Context, migrated *Vault, expectedRecipient string) error {
	hasMeta, err := migrated.tableExists(ctx, metaTableName)
	if err != nil {
		return fmt.Errorf("open %s: %w", migrated.path, err)
	}

	if !hasMeta {
		return fmt.Errorf("open %s: %w", migrated.path, ErrVaultCorrupt)
	}

	version, err := migrated.metaValue(ctx, metaKeyFormatVersion)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("open %s: %w", migrated.path, ErrVaultCorrupt)
		}

		return err
	}

	switch version {
	case strconv.Itoa(formatVersion):
		return ErrAlreadyCurrentFormat
	case "1":
		return checkMigrateRecipient(ctx, migrated, expectedRecipient)
	default:
		return fmt.Errorf("open %s: found version %s, only version 1 migrates: %w", migrated.path, version, ErrFormatVersion)
	}
}

// checkMigrateRecipient refuses a vault whose stored recipient does not
// match the identity presented to migrate. Every other identity-holding
// verb makes this check, so migrate makes it too rather than re-sealing
// every envelope on a recipient-swapped vault.
func checkMigrateRecipient(ctx context.Context, migrated *Vault, expectedRecipient string) error {
	stored, err := migrated.metaValue(ctx, metaKeyRecipient)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("open %s: %w", migrated.path, ErrVaultCorrupt)
		}

		return err
	}

	if stored != expectedRecipient {
		return fmt.Errorf("open %s: %w", migrated.path, ErrRecipientMismatch)
	}

	return nil
}

// resealForMigration re-seals every non-destroyed envelope and sets the
// format version, all in one transaction.
func resealForMigration(ctx context.Context, migrated *Vault, reseal MigrationResealer) (int64, error) {
	txn, err := migrated.handle.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin migrate transaction: %w", err)
	}

	defer func() { _ = txn.Rollback() }()

	// Re-read the format inside the write transaction. The pre-check in
	// checkMigratable runs before this lock is held, so a second migrate
	// can pass it, then serialize here behind the first. Without this
	// re-read the loser would re-seal the winner's version 2 frames and
	// fail with a confusing address mismatch. _txlock=immediate takes the
	// write lock at BeginTx, so this read sees the winner's commit.
	if err := ensureFormatOne(ctx, txn, migrated.path); err != nil {
		return 0, err
	}

	versions, err := collectMigrateVersions(ctx, txn)
	if err != nil {
		return 0, err
	}

	fetch, err := txn.PrepareContext(ctx, "SELECT envelope FROM secret_version WHERE id = ?")
	if err != nil {
		return 0, fmt.Errorf("prepare envelope fetch: %w", err)
	}

	defer func() { _ = fetch.Close() }()

	for _, version := range versions {
		if err := resealOneVersion(ctx, txn, fetch, reseal, version); err != nil {
			return 0, err
		}
	}

	if _, err := txn.ExecContext(ctx,
		"UPDATE vault_meta SET value = ? WHERE key = ?", strconv.Itoa(formatVersion), metaKeyFormatVersion); err != nil {
		return 0, fmt.Errorf("set format version: %w", err)
	}

	if err := txn.Commit(); err != nil {
		return 0, fmt.Errorf("commit migrate: %w", err)
	}

	return int64(len(versions)), nil
}

// resealOneVersion re-seals one version's envelope through reseal and
// stores it, reconciling the shared env name column when the resealer
// had to sanitize a legacy env name the new frame could not carry.
func resealOneVersion(
	ctx context.Context, txn *sql.Tx, fetch *sql.Stmt, reseal MigrationResealer, version migrateVersion,
) error {
	var oldEnvelope []byte

	if err := fetch.QueryRowContext(ctx, version.id).Scan(&oldEnvelope); err != nil {
		return fmt.Errorf("read %s version %d: %w", version.name, version.number, err)
	}

	resealed, sealedEnvName, err := reseal(
		version.name, version.number, version.envName, version.expiresAt, oldEnvelope,
	)
	if err != nil {
		return fmt.Errorf("reseal %s version %d: %w", version.name, version.number, err)
	}

	if sealedEnvName != version.envName {
		// The legacy env name held a character the new frame cannot store,
		// so the resealer sanitized it. Reconcile the shared column with
		// the sealed value, or verifyBound would refuse every later read.
		// An empty result becomes NULL, since the store never holds a
		// non-NULL empty env name.
		if err := reconcileEnvName(ctx, txn, version.name, sealedEnvName); err != nil {
			return err
		}
	}

	if _, err := txn.ExecContext(ctx,
		"UPDATE secret_version SET envelope = ? WHERE id = ?", resealed, version.id); err != nil {
		return fmt.Errorf("store resealed %s version %d: %w", version.name, version.number, err)
	}

	return nil
}

// ensureFormatOne re-checks the format version inside the migration
// transaction. It returns [ErrAlreadyCurrentFormat] when a concurrent
// migrate already upgraded the vault, so the loser reports a clean
// no-op instead of failing to re-seal the new frames.
func ensureFormatOne(ctx context.Context, txn *sql.Tx, path string) error {
	var version string

	err := txn.QueryRowContext(ctx,
		"SELECT value FROM vault_meta WHERE key = ?", metaKeyFormatVersion).Scan(&version)
	if err != nil {
		return fmt.Errorf("read format version in transaction: %w", err)
	}

	switch version {
	case strconv.Itoa(formatVersion):
		return ErrAlreadyCurrentFormat
	case "1":
		return nil
	default:
		return fmt.Errorf("open %s: found version %s, only version 1 migrates: %w", path, version, ErrFormatVersion)
	}
}

// reconcileEnvName rewrites a secret's env name column to the value the
// migration actually sealed, after the resealer stripped a character the
// new frame could not carry. An empty result is stored as NULL, matching
// how the store maps an empty env name, so no row holds a non-NULL empty
// string.
func reconcileEnvName(ctx context.Context, txn *sql.Tx, name, sealedEnvName string) error {
	var column sql.NullString
	if sealedEnvName != "" {
		column = sql.NullString{String: sealedEnvName, Valid: true}
	}

	if _, err := txn.ExecContext(ctx,
		"UPDATE secret SET env_name = ? WHERE name = ?", column, name); err != nil {
		return fmt.Errorf("reconcile env name for %s: %w", name, err)
	}

	return nil
}

func collectMigrateVersions(ctx context.Context, txn *sql.Tx) ([]migrateVersion, error) {
	rows, err := txn.QueryContext(ctx,
		`SELECT sv.id, s.name, sv.version_number, s.env_name, s.expires_at
		 FROM secret_version sv JOIN secret s ON s.id = sv.secret_id
		 WHERE sv.state != ? AND sv.envelope IS NOT NULL
		 ORDER BY s.name, sv.version_number`,
		string(StateDestroyed))
	if err != nil {
		return nil, fmt.Errorf("collect versions to migrate: %w", err)
	}

	defer func() { _ = rows.Close() }()

	var versions []migrateVersion

	for rows.Next() {
		var (
			version   migrateVersion
			envName   sql.NullString
			expiresAt sql.NullString
		)

		if err := rows.Scan(&version.id, &version.name, &version.number, &envName, &expiresAt); err != nil {
			return nil, fmt.Errorf("scan version to migrate: %w", err)
		}

		version.envName = envName.String
		version.expiresAt = expiresAt.String

		versions = append(versions, version)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("collect versions to migrate: %w", err)
	}

	return versions, nil
}
