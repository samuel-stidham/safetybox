package vault

// schemaV1 is the initial schema.
//
// Name visibility: secret.name is a plaintext column so list, stale,
// and prefix queries stay cheap. This is the open decision recorded
// in CLAUDE.md. Names may move inside the encryption boundary before
// 1.0.
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

// migrations returns the ordered schema migrations. Migration i
// upgrades a vault at format version i to i+1, so formatVersion
// always equals len(migrations()).
func migrations() []string {
	return []string{schemaV1}
}
