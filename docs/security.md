# Security model

This page explains what safetybox protects, how, and what it leaves
to you. The invariants here are enforced by code and tests.
Violations are bugs, not style.

## The asymmetric model

The vault stores your public key, the recipient. Anything that
writes a secret encrypts to that public key and never touches
private key material. Anything that reads a secret needs the
identity file and its passphrase. A machine that only produces
secrets never needs the ability to read them back.

## Layers of protection

A secret at rest sits behind two locks. The value itself is sealed
in an age envelope encrypted to your X25519 key. The private key is
in turn encrypted with an scrypt passphrase. Stealing the vault file
alone yields ciphertext. Stealing the vault and the identity file
still requires the passphrase.

## Plaintext handling

Plaintext secret bytes live in one Go type, `secret.Value`, in one
package, and leave it through one method, `Expose`. Formatting, JSON
encoding, and logging of that type all render `[REDACTED]`. The
compiler enforces the boundary because the bytes are unexported.

Plaintext is never written to disk, logs, or command arguments. Not
in errors, not in debug output, not in test fixtures. Values enter
through stdin or a no-echo prompt. Passphrases enter the same way or
through `--passphrase-file`, never through argv or environment
variables. reveal is the single verb that prints plaintext, and exec
places it only in the child process environment.

## Address binding

Every envelope's plaintext is prefixed with its canonical address,
`api/v1/<name>/<version>`. Decryption verifies the embedded address
matches the row the ciphertext came from. An attacker with write
access to the database cannot swap envelopes between rows without
detection.

The stored recipient is that attacker's other target. A write to
`vault_meta` could point new secrets at a key the attacker controls.
Every decrypting verb now compares the stored recipient to your loaded
identity and refuses on a mismatch, so tampering surfaces on the next
read, even for old versions that still decrypt. The write path holds no
identity by design, so it cannot prevent the bad write. Detection on
read is the guard, not prevention at write time.

## Files and permissions

The vault file is created 0600 with WAL journaling, and SQLite gives
the `-wal` and `-shm` siblings the same mode. The identity file is
0600 inside a 0700 directory. Loading refuses an identity file, or a
containing directory, with group or world permission bits, the way
ssh refuses a loose private key. A regular file passed to
`--passphrase-file` is held to the same check. A pipe or process
substitution is a transient stream and is allowed.

The vault gets a warning rather than a refusal. On every run safetybox
checks the vault file, its directory, and the `-wal` and `-shm`
siblings, and warns on stderr when any of them grant group or world
access. A refusal fits the identity file, which gates key material. The
vault holds ciphertext plus public metadata, so a hard refusal would
lock you out of your own data after a backup reset the mode.

## Key material in memory

The decrypted identity is held in a memguard locked buffer for the
duration of one invocation and wiped afterward. Passphrase buffers
are zeroed after use. Go strings copied during parsing are outside
that control, so this is hardening, not a guarantee against a
debugger on your own machine.

## Rotation and destruction

rekey re-encrypts every non-destroyed version inside one SQLite
transaction, and the stored recipient updates last in that same
transaction. There is no window where half the vault is on the new
key. The new identity is staged on disk, with a directory fsync,
before that transaction starts, so a crash can never leave
re-encrypted envelopes without their key. Before staging anything,
rekey verifies the vault is really encrypted to the loaded identity,
so a rerun after an interrupted rotation can never discard the live
staged key. Read verbs heal an interrupted swap on the next
invocation.

purge erases envelopes but keeps rows, so history shows a version
existed without any way to recover its value. The vault runs with
SQLite secure_delete, and purge and rekey truncate the write-ahead
log after committing, so freed pages and WAL frames do not keep old
ciphertext. A reader in another process can block that truncate. The
verbs warn when it happens and the next checkpoint reclaims the
frames.

## What safetybox does not defend against

An attacker with your identity file, your passphrase, and the vault
has everything. Malware running as your user while you type the
passphrase can capture it. A root user or a debugger can read
process memory. safetybox is a careful single-user store, not an
HSM. At-rest disk protection like FileVault remains worth having
underneath it.

Metadata integrity is only partial. An attacker with vault write
access can alter any metadata column, not only the recipient. The
recipient swap is caught on the next read, but changes to `env_name`,
`expires_at`, or version state carry no integrity check in the current
format. Treat write access to the vault file as a serious compromise.

## Secret names are plaintext

Names, timestamps, version counts, and env variable names are
readable without the identity in the current format. That keeps
list, stale, and prefix queries cheap. Treat names as
non-confidential. This is a recorded open decision and may change
before 1.0.

Purge is subject to the same rule. It erases the values but keeps
the secret row, so the name stays readable in the vault forever. A
name like `customers/acme-corp/api-key` remains after purge. If a
name itself is sensitive, purge does not remove it.
