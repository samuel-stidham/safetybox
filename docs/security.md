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

## Address and metadata binding

Every envelope's plaintext starts with a header. It holds a version
tag, the canonical address `api/v1/<name>/<version>`, and the secret's
env name and expiry as of when the version was written. A read verifies
the address against the row and returns the bound env name and expiry.

The address binding stops an attacker moving an envelope between rows.
The metadata binding, added in 3.0.0, catches an edit to the `env_name`
or `expires_at` column. A read compares the column to the value sealed
into the envelope and refuses on a mismatch. Re-sealing the envelope
needs the plaintext value, which a vault-write attacker does not have.
So they cannot make the column and the sealed value agree while keeping
your value.

The limit is inherent to keyless writes. The recipient is a public key,
so an attacker can seal a chosen plaintext with a matching env name and
expiry, then overwrite a row. That forged envelope passes every check.
But it holds the attacker's value, not yours, so it is a substitution
you would notice, not a stealthy metadata edit. Version state and
soft-deletion are not bound, because the operations that change them,
disable, delete, and purge, hold no plaintext to re-seal.

Deleting version rows is the cheaper version of that gap. An attacker
with vault write access can remove the newest `secret_version` rows so
an older version becomes newest enabled. The env name and expiry are
shared columns. When they did not change between the two versions, the
older envelope's sealed metadata still matches them. The read then
passes every check and returns the older value. That hands back a real
prior secret, such as a rotated-away credential, with no error and no
forged ciphertext. Neither which version is newest nor the set of rows
is authenticated, so the rollback is not detectable in this format.

One consequence to know. If you change a secret's env name or expiry,
which writes a new version, and then disable that exact version, the
active older version was sealed with the old value while the column
holds the new one. A read refuses that state until you re-set the
secret to reconcile it. It is rare and fails safe.

The stored recipient is the attacker's other target. A write to
`vault_meta` could point new secrets at a key the attacker controls.
Every decrypting verb compares the stored recipient to your loaded
identity and refuses on a mismatch, so tampering surfaces on the next
read, even for old versions that still decrypt. The write path holds no
identity by design, so this is detection on read, not prevention.

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
are zeroed after use. Every reader that touches secret material wipes
each buffer it outgrows. That covers the no-echo prompt, the stdin
and file readers, the identity loader, and the envelope decrypt path.
A failed read wipes its partial buffer and returns nothing. A
successful read also wipes the unused tail of its buffer. Go strings
copied during parsing are outside that control, so this is hardening,
not a guarantee against a debugger on your own machine.

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

rekey and passwd hold an exclusive lock beside the identity for
their whole run, so two rotations can never interleave and delete
each other's staged key. A commit that errors after its record became
durable is treated as ambiguous. rekey then keeps both key files and
says to test which one opens the vault before deleting either.

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

Vault write integrity is only partial. A recipient swap, an `env_name`
edit, and an `expires_at` edit are all caught on the next read, through
the recipient check and the metadata binding. Version state and
soft-deletion are not, because the operations that change them hold no
plaintext to re-seal. Deleting newer version rows to roll a read back to
a prior value is unbound for the same reason. And a full envelope
re-forge with a chosen value passes every check, since the recipient is
public. The address and metadata binding section covers the details. Treat write access to the
vault file as a serious compromise.

## Secret names are plaintext

Names, timestamps, version counts, and env variable names are
readable without the identity in the current format. That keeps
list, stale, and prefix queries cheap. Treat names as
non-confidential. This is a recorded design decision. Changing it
needs a format bump, so it would arrive only with a major release.

Purge is subject to the same rule. It erases the values but keeps
the secret row, so the name stays readable in the vault forever. A
name like `customers/acme-corp/api-key` remains after purge. If a
name itself is sensitive, purge does not remove it.
