# Architecture

safetybox is a thin CLI over three internal packages. The package
boundaries are load-bearing. They are what make the security
guarantees checkable by the compiler instead of by review.

## Package layout

```text
main.go              thin, calls cmd.Execute()
cmd/                 one file per verb, flags, JSON output, user-facing errors
internal/secret/     secret.Value, the only type holding plaintext bytes
internal/envelope/   age seal and open, address binding
internal/identity/   identity file load, write, and atomic replace
internal/vault/      SQLite store, schema, versions, metadata
internal/logging/    slog setup on stderr
```

Secrets flow `secret → envelope → vault` and never backward. The
vault stores sealed bytes it cannot read. The envelope package seals
and opens but never persists. The secret package holds plaintext and
nothing else.

Where the vault needs an envelope created, it takes a callback. set
hands `AppendVersion` a sealer that closes over the recipient, and
rekey hands `Rekey` a resealer that closes over both keys. The vault
picks the canonical address and stays free of crypto imports.

## The redaction type

`secret.Value` keeps its bytes unexported. `String`, `GoString`,
`MarshalJSON`, and `LogValue` all return `[REDACTED]`, so fmt, JSON
encoding, and slog cannot leak by accident. Plaintext exits only
through `Expose`, and the call sites are the reveal output, the exec
environment, and the envelope seal path. Never add another exit and
never move the type into a shared package. `Destroy` zeroes the held
bytes, and the decrypt paths call it as soon as the value is copied
out, so a plaintext copy does not sit on the heap for the whole run.

## Data model

Three tables, strict mode, WAL journaling.

`vault_meta` is a key value table holding the recipient and the
format version.

`secret` holds one row per name: id, name, env_name, created_at,
updated_at, deleted_at, and expires_at. deleted_at implements soft
delete. expires_at is a staleness flag and never triggers deletion.
The name column is plaintext by recorded decision, see the
[security model](security.md).

`secret_version` is append-only: secret_id, version_number, state,
envelope, and created_at. version_number is monotonic per secret and
never reused. state is one of enabled, disabled, or destroyed,
enforced by a CHECK constraint. destroyed rows keep their metadata
but their envelope column is NULL forever.

Derived facts like expired are computed at read time, never stored.

## Address binding

The canonical address of a version is `api/v1/<name>/<version>`.
Seal prefixes the plaintext with it. Open verifies it against the
row being read. The binding travels inside the ciphertext, so moving
or swapping envelopes in the database breaks decryption.

## Resolution rules

get, reveal, and exec resolve the newest enabled version of a
non-deleted secret. Updates append rather than replace, so two
versions being enabled at once is the designed overlap window for
rotation. disable removes a version from resolution without
destroying anything. Only purge destroys.

Before decrypting, every read verb compares the vault's stored
recipient to the loaded identity and refuses on a mismatch. The write
path holds no identity, so it cannot make this check. That is why the
recipient guard lives on the read side, and why it detects a tampered
recipient rather than preventing the write that follows one.

## Format version and migrations

`vault_meta` records format_version, currently 1. Open refuses a
vault written by a different format. Migrations are an ordered list
where entry i upgrades format i to i+1, applied inside one
transaction at create time. The scaffold is in place before any
second format exists on purpose.

## Error convention

Packages under `internal/` declare sentinel errors in an `errors.go`
and never print. Context is added by wrapping at call sites with
`%w`. Callers branch with `errors.Is`. The cmd package is the single
boundary that turns sentinels into user-facing messages that say
what to do next.
