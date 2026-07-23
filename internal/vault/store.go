package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// timeFormat is how timestamps are stored in TEXT columns.
const timeFormat = time.RFC3339

func formatTime(t time.Time) string {
	return t.UTC().Format(timeFormat)
}

func parseTime(raw string) (time.Time, error) {
	parsed, err := time.Parse(timeFormat, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse stored time: %w", err)
	}

	return parsed, nil
}

// parseNullableTime reports ok=false when the column is NULL.
func parseNullableTime(raw sql.NullString) (time.Time, bool, error) {
	if !raw.Valid {
		return time.Time{}, false, nil
	}

	parsed, err := parseTime(raw.String)
	if err != nil {
		return time.Time{}, false, err
	}

	return parsed, true, nil
}

// secretRow mirrors the secret table for scanning.
type secretRow struct {
	id        int64
	name      string
	envName   sql.NullString
	createdAt string
	updatedAt string
	deletedAt sql.NullString
	expiresAt sql.NullString
}

func (r secretRow) meta() (SecretMeta, error) {
	createdAt, err := parseTime(r.createdAt)
	if err != nil {
		return SecretMeta{}, err
	}

	updatedAt, err := parseTime(r.updatedAt)
	if err != nil {
		return SecretMeta{}, err
	}

	meta := SecretMeta{
		Name:      r.name,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}

	if deletedAt, ok, err := parseNullableTime(r.deletedAt); err != nil {
		return SecretMeta{}, err
	} else if ok {
		meta.DeletedAt = &deletedAt
	}

	if expiresAt, ok, err := parseNullableTime(r.expiresAt); err != nil {
		return SecretMeta{}, err
	} else if ok {
		meta.ExpiresAt = &expiresAt
	}

	if r.envName.Valid {
		envName := r.envName.String
		meta.EnvName = &envName
	}

	return meta, nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

const sqlSelectByName = `SELECT id, name, env_name, created_at, updated_at, deleted_at, expires_at
	FROM secret WHERE name = ?`

// findSecret returns the secret row or ErrSecretNotFound.
func findSecret(ctx context.Context, q querier, name string) (secretRow, error) {
	var row secretRow

	err := q.QueryRowContext(ctx, sqlSelectByName, name).Scan(
		&row.id, &row.name, &row.envName,
		&row.createdAt, &row.updatedAt, &row.deletedAt, &row.expiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return secretRow{}, fmt.Errorf("secret %s: %w", name, ErrSecretNotFound)
	}

	if err != nil {
		return secretRow{}, fmt.Errorf("look up secret %s: %w", name, err)
	}

	return row, nil
}

// AppendVersion stores a new sealed version of name inside one
// transaction. It creates the secret row on first use and revives a
// soft-deleted secret. The seal callback receives the canonical
// address of the new version so the envelope binds to its row.
func (v *Vault) AppendVersion(
	ctx context.Context, name string, opts SetOptions, seal Sealer,
) (*AppendResult, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}

	txn, err := v.handle.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin set transaction: %w", err)
	}

	defer func() { _ = txn.Rollback() }()

	now := time.Now().UTC().Truncate(time.Second)

	secretID, err := upsertSecret(ctx, txn, name, opts, now)
	if err != nil {
		return nil, err
	}

	// Read the row as upsert left it, so the seal binds the effective
	// env name and expiry into the new version's envelope. Empty strings
	// mean the secret carries none.
	row, err := findSecret(ctx, txn, name)
	if err != nil {
		return nil, err
	}

	nextVersion, err := sealAndInsertVersion(
		ctx, txn, secretID, name, row.envName.String, row.expiresAt.String, now, seal,
	)
	if err != nil {
		return nil, err
	}

	var revoked int64

	if opts.RevokePrevious {
		revoked, err = revokeOlderVersions(ctx, txn, secretID, nextVersion)
		if err != nil {
			return nil, fmt.Errorf("revoke previous versions of %s: %w", name, err)
		}
	}

	meta, err := row.meta()
	if err != nil {
		return nil, err
	}

	if err := txn.Commit(); err != nil {
		return nil, fmt.Errorf("commit set of %s: %w", name, err)
	}

	result := &AppendResult{
		Secret:  meta,
		Version: VersionMeta{Number: nextVersion, State: StateEnabled, CreatedAt: now},
		Revoked: revoked,
	}

	return result, nil
}

// sealAndInsertVersion computes the next monotonic version number,
// seals the envelope to that address with the bound metadata, and
// inserts the row.
func sealAndInsertVersion(
	ctx context.Context, txn *sql.Tx, secretID int64, name, envName, expiresAt string, now time.Time, seal Sealer,
) (int64, error) {
	var nextVersion int64

	err := txn.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(version_number), 0) + 1 FROM secret_version WHERE secret_id = ?",
		secretID).Scan(&nextVersion)
	if err != nil {
		return 0, fmt.Errorf("next version for %s: %w", name, err)
	}

	envelope, err := seal(CanonicalAddress(name, nextVersion), envName, expiresAt)
	if err != nil {
		return 0, fmt.Errorf("seal %s: %w", name, err)
	}

	_, err = txn.ExecContext(ctx,
		"INSERT INTO secret_version (secret_id, version_number, state, envelope, created_at) VALUES (?, ?, ?, ?, ?)",
		secretID, nextVersion, string(StateEnabled), envelope, formatTime(now))
	if err != nil {
		return 0, fmt.Errorf("insert version %d of %s: %w", nextVersion, name, err)
	}

	return nextVersion, nil
}

func upsertSecret(ctx context.Context, txn *sql.Tx, name string, opts SetOptions, now time.Time) (int64, error) {
	row, err := findSecret(ctx, txn, name)

	switch {
	case errors.Is(err, ErrSecretNotFound):
		return insertSecret(ctx, txn, name, opts, now)
	case err != nil:
		return 0, err
	}

	// Existing secret, possibly soft-deleted. A set revives it and
	// applies only the attributes that were passed.
	envName := row.envName

	if opts.EnvName != nil {
		envName = sql.NullString{String: *opts.EnvName, Valid: *opts.EnvName != ""}
	}

	expiresAt := row.expiresAt

	switch {
	case opts.ClearExpiry:
		expiresAt = sql.NullString{}
	case opts.ExpiresAt != nil:
		expiresAt = sql.NullString{String: formatTime(*opts.ExpiresAt), Valid: true}
	}

	_, err = txn.ExecContext(ctx,
		"UPDATE secret SET env_name = ?, expires_at = ?, deleted_at = NULL, updated_at = ? WHERE id = ?",
		envName, expiresAt, formatTime(now), row.id)
	if err != nil {
		return 0, fmt.Errorf("update secret %s: %w", name, err)
	}

	return row.id, nil
}

func insertSecret(ctx context.Context, txn *sql.Tx, name string, opts SetOptions, now time.Time) (int64, error) {
	var envName, expiresAt sql.NullString

	if opts.EnvName != nil && *opts.EnvName != "" {
		envName = sql.NullString{String: *opts.EnvName, Valid: true}
	}

	if opts.ExpiresAt != nil {
		expiresAt = sql.NullString{String: formatTime(*opts.ExpiresAt), Valid: true}
	}

	inserted, err := txn.ExecContext(ctx,
		"INSERT INTO secret (name, env_name, created_at, updated_at, expires_at) VALUES (?, ?, ?, ?, ?)",
		name, envName, formatTime(now), formatTime(now), expiresAt)
	if err != nil {
		return 0, fmt.Errorf("insert secret %s: %w", name, err)
	}

	secretID, err := inserted.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("insert secret %s: %w", name, err)
	}

	return secretID, nil
}

func revokeOlderVersions(ctx context.Context, txn *sql.Tx, secretID, keepVersion int64) (int64, error) {
	outcome, err := txn.ExecContext(ctx,
		"UPDATE secret_version SET state = ? WHERE secret_id = ? AND state = ? AND version_number < ?",
		string(StateDisabled), secretID, string(StateEnabled), keepVersion)
	if err != nil {
		return 0, fmt.Errorf("disable older versions: %w", err)
	}

	revoked, err := outcome.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count revoked versions: %w", err)
	}

	return revoked, nil
}

// NewestEnabled returns the newest enabled version of name with its
// envelope. Deleted secrets do not resolve.
func (v *Vault) NewestEnabled(ctx context.Context, name string) (*Resolved, error) {
	row, err := findSecret(ctx, v.handle, name)
	if err != nil {
		return nil, err
	}

	if row.deletedAt.Valid {
		return nil, fmt.Errorf("secret %s: %w", name, ErrSecretDeleted)
	}

	meta, err := row.meta()
	if err != nil {
		return nil, err
	}

	var (
		number    int64
		createdAt string
		envelope  []byte
	)

	err = v.handle.QueryRowContext(ctx,
		`SELECT version_number, created_at, envelope FROM secret_version
		 WHERE secret_id = ? AND state = ? ORDER BY version_number DESC LIMIT 1`,
		row.id, string(StateEnabled)).Scan(&number, &createdAt, &envelope)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("secret %s has no enabled version: %w", name, ErrVersionNotFound)
	}

	if err != nil {
		return nil, fmt.Errorf("newest version of %s: %w", name, err)
	}

	created, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}

	return &Resolved{
		Secret:   meta,
		Version:  VersionMeta{Number: number, State: StateEnabled, CreatedAt: created},
		Envelope: envelope,
	}, nil
}

// Meta returns the secret row and all its versions, including
// soft-deleted secrets and destroyed versions. It never touches
// envelopes.
func (v *Vault) Meta(ctx context.Context, name string) (SecretMeta, []VersionMeta, error) {
	row, err := findSecret(ctx, v.handle, name)
	if err != nil {
		return SecretMeta{}, nil, err
	}

	meta, err := row.meta()
	if err != nil {
		return SecretMeta{}, nil, err
	}

	rows, err := v.handle.QueryContext(ctx,
		"SELECT version_number, state, created_at FROM secret_version WHERE secret_id = ? ORDER BY version_number",
		row.id)
	if err != nil {
		return SecretMeta{}, nil, fmt.Errorf("versions of %s: %w", name, err)
	}

	defer func() { _ = rows.Close() }()

	var versions []VersionMeta

	for rows.Next() {
		var (
			number    int64
			state     string
			createdAt string
		)

		if err := rows.Scan(&number, &state, &createdAt); err != nil {
			return SecretMeta{}, nil, fmt.Errorf("scan version of %s: %w", name, err)
		}

		created, err := parseTime(createdAt)
		if err != nil {
			return SecretMeta{}, nil, err
		}

		versions = append(versions, VersionMeta{Number: number, State: State(state), CreatedAt: created})
	}

	if err := rows.Err(); err != nil {
		return SecretMeta{}, nil, fmt.Errorf("versions of %s: %w", name, err)
	}

	return meta, versions, nil
}

const summaryQuery = `SELECT s.id, s.name, s.env_name, s.created_at, s.updated_at, s.deleted_at, s.expires_at,
	COALESCE(MAX(sv.version_number), 0)
	FROM secret s LEFT JOIN secret_version sv ON sv.secret_id = s.id
	WHERE s.deleted_at IS NULL`

// prefixClause matches a name that IS the prefix or lives under it as
// a whole segment, so "projects/app" never selects the sibling
// "projects/app-legacy". The comparison is exact and case-sensitive.
// LIKE is not used because it treats `_` and `%` in a name as
// wildcards and folds ASCII case, which would over-match and, through
// reveal --prefix, disclose secrets the caller did not select.
const prefixClause = ` AND (s.name = ? OR substr(s.name, 1, length(?) + 1) = ? || '/')`

// prefixArgs binds the prefix for prefixClause's three placeholders.
// A trailing slash is dropped so "db/" and "db" select the same set.
func prefixArgs(prefix string) []any {
	trimmed := strings.TrimSuffix(prefix, "/")

	return []any{trimmed, trimmed, trimmed}
}

// List returns non-deleted secrets whose name equals prefix or sits
// under it as a whole segment. An empty prefix lists everything.
func (v *Vault) List(ctx context.Context, prefix string) ([]Summary, error) {
	query := summaryQuery

	var args []any

	if prefix != "" {
		query += prefixClause
		args = prefixArgs(prefix)
	}

	return v.summaries(ctx, query+" GROUP BY s.id ORDER BY s.name", args...)
}

// Stale returns non-deleted secrets whose expiry has passed.
func (v *Vault) Stale(ctx context.Context, now time.Time) ([]Summary, error) {
	query := summaryQuery + " AND s.expires_at IS NOT NULL AND s.expires_at <= ? GROUP BY s.id ORDER BY s.name"

	return v.summaries(ctx, query, formatTime(now))
}

func (v *Vault) summaries(ctx context.Context, query string, args ...any) ([]Summary, error) {
	rows, err := v.handle.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	defer func() { _ = rows.Close() }()

	var result []Summary

	for rows.Next() {
		var (
			row    secretRow
			latest int64
		)

		err := rows.Scan(&row.id, &row.name, &row.envName,
			&row.createdAt, &row.updatedAt, &row.deletedAt, &row.expiresAt, &latest)
		if err != nil {
			return nil, fmt.Errorf("scan secret list: %w", err)
		}

		meta, err := row.meta()
		if err != nil {
			return nil, err
		}

		result = append(result, Summary{SecretMeta: meta, LatestVersion: latest})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	return result, nil
}

// Disable marks one version disabled. Destroyed versions stay
// destroyed and disabling twice is a no-op.
func (v *Vault) Disable(ctx context.Context, name string, number int64) error {
	row, err := findSecret(ctx, v.handle, name)
	if err != nil {
		return err
	}

	var state string

	err = v.handle.QueryRowContext(ctx,
		"SELECT state FROM secret_version WHERE secret_id = ? AND version_number = ?",
		row.id, number).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("version %d of %s: %w", number, name, ErrVersionNotFound)
	}

	if err != nil {
		return fmt.Errorf("look up version %d of %s: %w", number, name, err)
	}

	if State(state) == StateDestroyed {
		return fmt.Errorf("version %d of %s: %w", number, name, ErrVersionDestroyed)
	}

	// The guard on state != destroyed makes the update self-checking,
	// so a Purge that destroys the row between the SELECT above and
	// this statement cannot be undone: the update simply affects zero
	// rows, which is reported as ErrVersionDestroyed.
	outcome, err := v.handle.ExecContext(ctx,
		"UPDATE secret_version SET state = ? WHERE secret_id = ? AND version_number = ? AND state != ?",
		string(StateDisabled), row.id, number, string(StateDestroyed))
	if err != nil {
		return fmt.Errorf("disable version %d of %s: %w", number, name, err)
	}

	changed, err := outcome.RowsAffected()
	if err != nil {
		return fmt.Errorf("disable version %d of %s: %w", number, name, err)
	}

	if changed == 0 {
		return fmt.Errorf("version %d of %s: %w", number, name, ErrVersionDestroyed)
	}

	return nil
}

// SoftDelete marks the secret deleted. Its versions and envelopes
// stay intact until purge.
func (v *Vault) SoftDelete(ctx context.Context, name string) error {
	row, err := findSecret(ctx, v.handle, name)
	if err != nil {
		return err
	}

	if row.deletedAt.Valid {
		return fmt.Errorf("secret %s: %w", name, ErrSecretDeleted)
	}

	now := formatTime(time.Now().UTC())

	// The deleted_at IS NULL guard makes the update self-checking, the
	// same pattern Disable uses. A second racing delete or a purge that
	// lands between the read above and this statement affects zero rows
	// rather than overwriting the first tombstone's timestamp.
	outcome, err := v.handle.ExecContext(ctx,
		"UPDATE secret SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL", now, now, row.id)
	if err != nil {
		return fmt.Errorf("delete secret %s: %w", name, err)
	}

	changed, err := outcome.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete secret %s: %w", name, err)
	}

	if changed == 0 {
		return fmt.Errorf("secret %s: %w", name, ErrSecretDeleted)
	}

	return nil
}

// Purge erases every envelope of the secret and marks all versions
// destroyed, inside one transaction. Rows and history remain.
func (v *Vault) Purge(ctx context.Context, name string) (int64, error) {
	txn, err := v.handle.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin purge transaction: %w", err)
	}

	defer func() { _ = txn.Rollback() }()

	row, err := findSecret(ctx, txn, name)
	if err != nil {
		return 0, err
	}

	outcome, err := txn.ExecContext(ctx,
		"UPDATE secret_version SET state = ?, envelope = NULL WHERE secret_id = ? AND state != ?",
		string(StateDestroyed), row.id, string(StateDestroyed))
	if err != nil {
		return 0, fmt.Errorf("destroy envelopes of %s: %w", name, err)
	}

	destroyed, err := outcome.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count destroyed versions: %w", err)
	}

	now := formatTime(time.Now().UTC())

	_, err = txn.ExecContext(ctx,
		"UPDATE secret SET deleted_at = COALESCE(deleted_at, ?), updated_at = ? WHERE id = ?",
		now, now, row.id)
	if err != nil {
		return 0, fmt.Errorf("mark %s deleted: %w", name, err)
	}

	if err := txn.Commit(); err != nil {
		return 0, fmt.Errorf("commit purge of %s: %w", name, err)
	}

	// Flush the WAL so the erased envelope bytes do not linger in
	// write-ahead frames. secure_delete zeroed the freed pages. This
	// truncates the log that still holds their pre-images. It is best
	// effort for the same reason as rekey. The purge is already
	// committed, so a checkpoint error must not report the committed
	// purge as a failure. The next checkpoint reclaims the frames.
	_ = v.Checkpoint(ctx)

	return destroyed, nil
}

// Checkpoint flushes and truncates the WAL so that content freed by a
// destructive operation cannot be recovered from write-ahead frames.
// The single connection (SetMaxOpenConns) rules out same-process
// contention, but a reader in ANOTHER process can still block the
// truncate. The pragma reports that as busy=1 with no SQL error, so
// the result row is read rather than discarded and a blocked
// checkpoint surfaces as [ErrCheckpointBlocked]. [Vault.Purge] and
// [Vault.Rekey] treat any failure as best effort because the
// destructive operation is already committed. Callers that must know
// the scrub happened, such as the purge and rekey verbs warning the
// user, call this again and check the error.
func (v *Vault) Checkpoint(ctx context.Context) error {
	var busy, logFrames, checkpointed int64

	err := v.handle.QueryRowContext(ctx,
		"PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointed)
	if err != nil {
		return fmt.Errorf("checkpoint wal: %w", err)
	}

	if busy != 0 {
		return fmt.Errorf("checkpoint wal: %w", ErrCheckpointBlocked)
	}

	return nil
}

// entriesQuery builds the batch selection for filter. Every clause
// keeps to the newest enabled version of non-deleted secrets.
func entriesQuery(filter EntryFilter) (string, []any) {
	query := `SELECT s.name, s.env_name, s.expires_at, sv.version_number, sv.envelope
	 FROM secret s JOIN secret_version sv ON sv.secret_id = s.id AND sv.state = ?
	 WHERE s.deleted_at IS NULL
	 AND sv.version_number = (
		SELECT MAX(v2.version_number) FROM secret_version v2
		WHERE v2.secret_id = s.id AND v2.state = ?)`
	args := []any{string(StateEnabled), string(StateEnabled)}

	if filter.EnvNamed {
		query += " AND s.env_name IS NOT NULL"
	}

	if filter.Prefix != "" {
		query += prefixClause

		args = append(args, prefixArgs(filter.Prefix)...)
	}

	return query + " ORDER BY s.name", args
}

// Entries returns the newest enabled version of every non-deleted
// secret matching filter, ordered by name.
func (v *Vault) Entries(ctx context.Context, filter EntryFilter) ([]Entry, error) {
	query, args := entriesQuery(filter)

	rows, err := v.handle.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("batch entries: %w", err)
	}

	defer func() { _ = rows.Close() }()

	var entries []Entry

	for rows.Next() {
		var (
			entry     Entry
			envName   sql.NullString
			expiresAt sql.NullString
		)

		if err := rows.Scan(&entry.Name, &envName, &expiresAt, &entry.Version, &entry.Envelope); err != nil {
			return nil, fmt.Errorf("scan batch entry: %w", err)
		}

		entry.EnvName = envName.String
		entry.EnvNameValid = envName.Valid

		if expiry, ok, err := parseNullableTime(expiresAt); err != nil {
			return nil, err
		} else if ok {
			entry.ExpiresAt = &expiry
		}

		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("batch entries: %w", err)
	}

	return entries, nil
}

// liveVersion identifies one row rekey must re-encrypt. It carries no
// envelope, because rekey fetches each envelope in turn so the whole
// vault's ciphertext is never resident at once.
type liveVersion struct {
	id     int64
	name   string
	number int64
}

// Rekey re-encrypts every non-destroyed version through reseal and
// stores the new recipient, all inside ONE transaction. The recipient
// update happens last. Any failure before the commit rolls the whole
// vault back. The commit itself can error after its record became
// durable, and that ambiguity is marked with [ErrCommitAmbiguous].
func (v *Vault) Rekey(ctx context.Context, newRecipient string, reseal Resealer) (int64, error) {
	txn, err := v.handle.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin rekey transaction: %w", err)
	}

	defer func() { _ = txn.Rollback() }()

	live, err := collectLiveVersions(ctx, txn)
	if err != nil {
		return 0, err
	}

	// Prepare the per-row fetch once. Issuing the raw SQL inside the
	// loop would re-parse and re-plan it for every version, which on a
	// large vault is pure overhead on top of the reseal's crypto work.
	fetch, err := txn.PrepareContext(ctx, "SELECT envelope FROM secret_version WHERE id = ?")
	if err != nil {
		return 0, fmt.Errorf("prepare envelope fetch: %w", err)
	}

	defer func() { _ = fetch.Close() }()

	for _, version := range live {
		var envelope []byte

		err := fetch.QueryRowContext(ctx, version.id).Scan(&envelope)
		if err != nil {
			return 0, fmt.Errorf("read %s version %d: %w", version.name, version.number, err)
		}

		resealed, err := reseal(version.name, version.number, envelope)
		if err != nil {
			return 0, fmt.Errorf("reseal %s version %d: %w", version.name, version.number, err)
		}

		if _, err := txn.ExecContext(ctx,
			"UPDATE secret_version SET envelope = ? WHERE id = ?", resealed, version.id); err != nil {
			return 0, fmt.Errorf("store resealed %s version %d: %w", version.name, version.number, err)
		}
	}

	if _, err := txn.ExecContext(ctx,
		"UPDATE vault_meta SET value = ? WHERE key = ?", newRecipient, metaKeyRecipient); err != nil {
		return 0, fmt.Errorf("store new recipient: %w", err)
	}

	if err := txn.Commit(); err != nil {
		// The commit record can be durable in the WAL even when the
		// commit call reports an error, a failed fsync being the
		// canonical case. Mark the ambiguity so the rekey verb knows
		// not to delete the staged key the vault may now depend on.
		return 0, fmt.Errorf("commit rekey: %w: %w", ErrCommitAmbiguous, err)
	}

	// Flush the WAL so envelopes sealed to the old recipient do not
	// survive in write-ahead frames after rotation. This is best
	// effort on purpose: the rekey is already committed, and the
	// caller treats any error from Rekey as "the vault is unchanged"
	// and discards the freshly staged new identity. Returning a
	// checkpoint error here would destroy the only key that can read
	// the re-encrypted vault. An unscrubbed WAL frame, cleaned up by
	// the next checkpoint, is the lesser evil than a locked vault.
	_ = v.Checkpoint(ctx)

	return int64(len(live)), nil
}

func collectLiveVersions(ctx context.Context, txn *sql.Tx) ([]liveVersion, error) {
	// Select only the row identity, not the envelope. Loading every
	// envelope here would hold the whole vault's ciphertext at once. The
	// rekey loop fetches each envelope in turn instead.
	rows, err := txn.QueryContext(ctx,
		`SELECT sv.id, s.name, sv.version_number
		 FROM secret_version sv JOIN secret s ON s.id = sv.secret_id
		 WHERE sv.state != ? AND sv.envelope IS NOT NULL
		 ORDER BY s.name, sv.version_number`,
		string(StateDestroyed))
	if err != nil {
		return nil, fmt.Errorf("collect live versions: %w", err)
	}

	defer func() { _ = rows.Close() }()

	var live []liveVersion

	for rows.Next() {
		var version liveVersion

		if err := rows.Scan(&version.id, &version.name, &version.number); err != nil {
			return nil, fmt.Errorf("scan live version: %w", err)
		}

		live = append(live, version)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("collect live versions: %w", err)
	}

	return live, nil
}
