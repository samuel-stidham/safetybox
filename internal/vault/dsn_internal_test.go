package vault

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSQLiteDSNEscapesURISpecialCharacters pins the escaping that keeps
// a vault path from being reinterpreted as URI syntax. SQLite opens the
// DSN with SQLITE_OPEN_URI, so an unescaped '#' would truncate the
// filename and an unescaped '?' would start the query early, dropping
// _txlock=immediate with it.
func TestSQLiteDSNEscapesURISpecialCharacters(t *testing.T) {
	for _, testCase := range []struct {
		name string
		path string
		want string
	}{
		{
			name: "absolute path gets an empty authority",
			path: "/data/safetybox/vault.db",
			want: "file:///data/safetybox/vault.db",
		},
		{
			name: "relative path gets no authority",
			path: "vault.db",
			want: "file:vault.db",
		},
		{
			name: "hash is escaped so the filename is not truncated",
			path: "/data/my#box/vault.db",
			want: "file:///data/my%23box/vault.db",
		},
		{
			name: "question mark is escaped so the query is not started early",
			path: "/data/why?/vault.db",
			want: "file:///data/why%3F/vault.db",
		},
		{
			name: "percent is escaped so SQLite does not decode it",
			path: "/data/100%/vault.db",
			want: "file:///data/100%25/vault.db",
		},
		{
			name: "percent is escaped before the others, never doubly",
			path: "/data/%23/vault.db",
			want: "file:///data/%2523/vault.db",
		},
		{
			name: "a leading double slash stays inside the path",
			path: "//data/vault.db",
			want: "file:////data/vault.db",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			dsn := sqliteDSN(testCase.path)

			assert.Equal(t, testCase.want+dsnQuery, dsn)

			// The first '?' must be the one that begins our query, since
			// that is where the driver and SQLite both split the DSN.
			assert.True(t, strings.HasPrefix(dsn, testCase.want+"?"),
				"the query must start at the first question mark, got %q", dsn)
			assert.Contains(t, dsn, "?_txlock=immediate",
				"_txlock=immediate must survive the path")
		})
	}
}

// TestSQLiteDSNKeepsConnectionSettings guards the settings the storage
// layer depends on elsewhere: secure_delete for purge and rekey, and
// the immediate write lock for cross-process serialization.
func TestSQLiteDSNKeepsConnectionSettings(t *testing.T) {
	dsn := sqliteDSN("/data/vault.db")

	for _, required := range []string{
		"_txlock=immediate",
		"_pragma=journal_mode(WAL)",
		"_pragma=foreign_keys(1)",
		"_pragma=secure_delete(1)",
		"_pragma=busy_timeout(5000)",
	} {
		require.Contains(t, dsn, required)
	}
}
