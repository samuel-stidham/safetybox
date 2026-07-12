package vault

import (
	"fmt"
	"regexp"
	"time"
)

// State is the lifecycle state of a secret version.
type State string

// The three version states. Destroyed versions keep their row but
// their envelope is erased forever.
const (
	StateEnabled   State = "enabled"
	StateDisabled  State = "disabled"
	StateDestroyed State = "destroyed"
)

// SecretMeta is a secret row without any envelope material.
type SecretMeta struct {
	Name      string     `json:"name"`
	EnvName   *string    `json:"envName,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
	DeletedAt *time.Time `json:"deletedAt,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// Expired reports whether the secret is past its expiry at now.
// Expiry marks a secret stale. It never blocks resolution.
func (m SecretMeta) Expired(now time.Time) bool {
	return m.ExpiresAt != nil && !now.Before(*m.ExpiresAt)
}

// VersionMeta is a secret_version row without its envelope.
type VersionMeta struct {
	Number    int64     `json:"version"`
	State     State     `json:"state"`
	CreatedAt time.Time `json:"createdAt"`
}

// Summary is one row of list and stale output.
type Summary struct {
	SecretMeta
	LatestVersion int64 `json:"latestVersion"`
}

// SetOptions carry the optional attributes of a set operation. Nil
// pointer fields keep whatever the secret already stores.
type SetOptions struct {
	EnvName        *string
	ExpiresAt      *time.Time
	RevokePrevious bool
}

// AppendResult reports what a set operation did.
type AppendResult struct {
	Secret  SecretMeta
	Version VersionMeta
	Revoked int64
}

// Resolved is a secret's newest enabled version with its envelope.
type Resolved struct {
	Secret   SecretMeta
	Version  VersionMeta
	Envelope []byte
}

// Entry is one secret selected for batch resolution, carrying the
// envelope of its newest enabled version. EnvName is empty when the
// secret has none.
type Entry struct {
	Name      string
	EnvName   string
	Version   int64
	ExpiresAt *time.Time
	Envelope  []byte
}

// Expired reports whether the entry is past its expiry at now, the
// same rule SecretMeta.Expired applies. Expiry marks a secret stale.
// It never blocks resolution.
func (e Entry) Expired(now time.Time) bool {
	return e.ExpiresAt != nil && !now.Before(*e.ExpiresAt)
}

// EntryFilter selects which secrets Entries returns. The zero value
// selects every non-deleted secret with an enabled version.
type EntryFilter struct {
	// Prefix keeps only names that start with it. Empty keeps all.
	Prefix string
	// EnvNamed keeps only secrets that carry an env name.
	EnvNamed bool
}

// Sealer produces a sealed envelope for a canonical address. The
// vault never sees plaintext, so sealing is injected by the caller.
type Sealer func(address string) ([]byte, error)

// Resealer re-encrypts an existing envelope during rekey.
type Resealer func(name string, number int64, envelope []byte) ([]byte, error)

// CanonicalAddress is the address baked into every envelope. It
// binds ciphertext to its exact row.
func CanonicalAddress(name string, number int64) string {
	return fmt.Sprintf("api/v1/%s/%d", name, number)
}

// ValidateName enforces the hierarchical name grammar: segments of
// letters, digits, dots, underscores, and dashes, joined by single
// slashes.
func ValidateName(name string) error {
	grammar := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$`)
	if !grammar.MatchString(name) {
		return fmt.Errorf("%q: %w", name, ErrInvalidName)
	}

	return nil
}
