package vault

// schemaV1 is the initial schema.
//
// Name visibility: secret.name is a plaintext column so list, stale,
// and prefix queries stay cheap. This is a recorded design decision,
// documented in docs/security.md. Moving names inside the encryption
// boundary would change the on-disk format, so it can arrive only with
// a major release.
const schemaV1 = `
CREATE TABLE vault_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE secret (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    env_name   TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    expires_at TEXT
) STRICT;

CREATE TABLE secret_version (
    id             INTEGER PRIMARY KEY,
    secret_id      INTEGER NOT NULL REFERENCES secret (id),
    version_number INTEGER NOT NULL,
    state          TEXT NOT NULL CHECK (state IN ('enabled', 'disabled', 'destroyed')),
    envelope       BLOB,
    created_at     TEXT NOT NULL,
    UNIQUE (secret_id, version_number)
) STRICT;

CREATE INDEX secret_version_lookup
    ON secret_version (secret_id, state, version_number);
`

// migrations returns the ordered SQL schema migrations, applied in
// order when a vault is created. Format version 2 changed the envelope
// frame, not the SQL schema, so it added no migration here. So
// formatVersion can exceed len(migrations()), and a version 1 to 2
// upgrade is a re-seal at the cmd layer, not a SQL migration.
func migrations() []string {
	return []string{schemaV1}
}
