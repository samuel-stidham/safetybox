# Roadmap

Work planned for after 2.0.0. Each item traces to a finding from the
security review that shipped in 2.0.0. The review fixed the rest. These
are the pieces left open, with why each was deferred and a rough
approach.

## Authenticated vault metadata

Priority: high. Touches the on-disk format.

The 2.0.0 release added a recipient check. Every read verb compares the
vault's stored recipient to the loaded identity and refuses on a
mismatch. A swapped recipient is caught on the next read. The check does
not reach the rest of the metadata. An attacker with write access to the
vault can still alter `env_name`, `expires_at`, or a version's state,
and nothing detects it.

The fix is an authenticated structure over the metadata, so any
tampering fails a check on read. That changes the on-disk format, so it
needs a format bump and a migration. This is the one deferred item with
real security weight. It belongs in its own release.

## Stream rekey to bound its memory

Priority: low.

`rekey` collects every live envelope into one slice before the reseal
loop, so all of a vault's ciphertext is resident at once. This is a
memory and scalability concern for a very large vault, not a secrecy
one, because the loaded envelopes are ciphertext.

Each decrypted plaintext is already wiped the moment its version is
resealed, through the per-version `Destroy` call in the reseal callback.
So the plaintext window is one secret at a time, not the whole vault.
The remaining work is to stream the ciphertext rows rather than load
them all, which matters only at scale.

## Bound the secret and passphrase reads

Priority: low.

`set` and `--passphrase-file` read their input with `io.ReadAll`, which
grows its buffer by reallocation. Each abandoned buffer holds a prefix
of the secret and is never zeroed. The final buffer is wiped, but the
intermediates are not.

The fix is a bounded read into a pre-sized buffer instead of
`io.ReadAll`, so no intermediate copy escapes. This is the same
hardening scope as the rekey item.

## Thread a caller context through the vault

Priority: low. No security impact.

Every exported vault method builds its own `context.Background()`.
Cancellation relies on process death, which SQLite tolerates. This is a
design smell, not a bug. The internal query plumbing already takes a
context, so threading it through the exported methods is cheap.

The fix is to accept a `context.Context` on the exported vault methods
and pass the caller's down.

## Minor cleanups

Priority: low. No security or correctness impact.

- The `nameGrammar` package variable in `internal/vault/types.go` repeats
  the grammar that `ValidateName`'s comment already gives. Trim one, or
  point the variable comment at the function.
- `warnLooseVaultPerms` runs from `PersistentPreRun`, so it checks vault
  permissions for every verb that runs, including ones that never open
  the vault, like `passwd`. It is correct but warns where no vault read
  happens. The `--version` flag short-circuits before the check, so it
  is exempt.
