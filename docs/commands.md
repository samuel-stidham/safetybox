# Command reference

Every verb, its flags, and its output. Global flags are covered in
the [configuration guide](configuration.md). Output is JSON on
stdout, pretty by default and compact with `--json`. Warnings and
prompts go to stderr.

Verbs that decrypt need your identity passphrase: get, reveal, exec,
passwd, rekey, and migrate. Verbs that only write or read metadata never
ask for it: set, show, list, stale, disable, delete, and purge. That
asymmetry is the point of storing the public recipient in the vault.

Two guards apply. safetybox warns on stderr when the vault file, its
directory, or its write-ahead siblings grant group or world access,
since names and timestamps are plaintext columns. And every verb that
reads the vault, get, reveal, exec, rekey, and migrate, refuses when the
stored recipient does not match your identity, which flags a tampered
vault or the wrong identity before a confusing decryption error. passwd
touches only the identity file, so it makes no such check.

## init

```sh
safetybox init
```

Generates an X25519 identity, encrypts it with a passphrase, writes
it 0600 inside a 0700 directory, and creates the vault with the
recipient stored in it. Finishes with a seal and open self-test.
Refuses to overwrite an existing identity or vault. Prints the
recipient and a backup warning to stderr.

## set

```sh
printf 'value' | safetybox set <name> [--env-name NAME] [--expires WHEN] [--revoke-previous]
```

Appends a new enabled version. The value comes from stdin, or from a
no-echo prompt when stdin is a terminal. One trailing newline is
trimmed so `echo value | safetybox set` stores what was typed.
Values never come from arguments.

Names are hierarchical. Segments of letters, digits, dots,
underscores, and dashes, joined by single slashes. `api/stripe/live`
is valid. Leading slashes, trailing slashes, and spaces are not.

`--env-name` records the environment variable exec will use. It must
be a valid shell identifier, letters, digits, and underscores, not
starting with a digit, so exec and `reveal --format` can emit it as a
variable name. `--expires` takes RFC3339 or YYYY-MM-DD, where a bare
date means midnight UTC. Both attributes stick until a later set
changes them. Pass an empty value to either flag to clear it, so
`--expires ''` removes an expiry and `--env-name ''` removes the env
name. `--revoke-previous` disables all older enabled versions in the
same transaction. Without it, prior versions stay enabled so rotation
has an overlap window.

Setting a soft-deleted secret revives it. Version numbers are
monotonic and never reused, even across delete and revive.

```json
{"name":"api/stripe/live","version":2,"state":"enabled","envName":"STRIPE_KEY","revokedPrevious":0}
```

## get

```sh
safetybox get <name>
```

Decrypts the newest enabled version, verifies its address and metadata
binding, and prints metadata. The value field always reads `[REDACTED]`.
Use get in scripts that need to know a secret resolves without ever
printing it. A metadata edit or a sealed value that no longer matches the
env name or expiry columns fails the read. Expired secrets warn on stderr
and still resolve.

```json
{"name":"api/stripe/live","version":2,"state":"enabled","envName":"STRIPE_KEY","createdAt":"2026-07-12T17:35:17Z","updatedAt":"2026-07-12T17:36:46Z","expired":false,"value":"[REDACTED]"}
```

## reveal

```sh
safetybox reveal <name>
safetybox reveal <name> --json | jq -r .value
safetybox reveal <name> <name>...
safetybox reveal --env --format fish | source
safetybox reveal --prefix projects/myapp --format sh
```

The single verb that prints plaintext. Everything else redacts. It
verifies the address and metadata binding before printing. A value whose
sealed env name or expiry no longer matches the columns is refused for
an explicit name. A filter selection skips it instead.

One name prints one JSON object, unchanged from earlier releases.
`--json` compacts the JSON output and cannot be combined with
`--format sh` or `--format fish`. A value that is not valid UTF-8
cannot ride inside JSON byte for byte, so safetybox base64-encodes it,
adds an `encoding` field set to `base64`, and warns on stderr. A plain
UTF-8 value has no encoding field and reads as itself. Use exec when
you want the raw bytes without decoding.

```json
{"name":"api/stripe/live","envName":"STRIPE_KEY","version":2,"expired":false,"value":"sk_live_example"}
```

Several names, `--env`, or `--prefix` select a batch. The whole batch
decrypts with one passphrase read and one identity unlock, which is
the point. `--env` selects every secret that has an env name.
`--prefix` selects the named secret itself and everything under it as
whole segments. `projects/myapp` selects `projects/myapp` and
`projects/myapp/token` but never the sibling `projects/myapp-legacy`.
The match is exact and case-sensitive, never a pattern, so `_` and
`%` in a name are ordinary characters. A trailing slash on the prefix
is allowed and means the same thing. The two filters compose, and
filters cannot be mixed with explicit names. Batch JSON output is an
array. An explicit name that does not resolve, or whose metadata no
longer matches its sealed value, fails the whole batch. A
filter-selected secret with that same mismatch is skipped with a warning
on stderr, so one stale secret never denies the rest. A filter that
matches nothing prints an empty array.

`--format sh` and `--format fish` emit assignment lines ready to
source into a shell session, using the env name recorded by set.

```sh
export STRIPE_KEY='sk_live_example'
```

```fish
set -gx STRIPE_KEY 'sk_live_example'
```

Values are single-quoted for the target shell, so embedded quotes,
command substitutions, and newlines stay inert text. A
filter-selected secret with no usable env name is skipped with a
warning on stderr and never silently dropped. An explicitly named
secret with no usable env name fails the whole batch before anything
is emitted, the same way a missing name fails it. When two secrets
share an env name the later assignment wins in the sourcing shell,
and reveal warns about the override. Load your global secrets in one
line:

```fish
safetybox reveal --env --format fish --passphrase-file FILE | source
```

And a project's secrets in a `.envrc`:

```sh
eval "$(safetybox reveal --prefix projects/myapp --format sh --passphrase-file FILE)"
```

## show

```sh
safetybox show <name>
```

Metadata only. Existence, timestamps, expiry state, and the full
version history with states. It never prints the value or its
length, and it needs no identity. show includes soft-deleted secrets
so you can see tombstones.

```json
{"name":"api/stripe/live","envName":"STRIPE_KEY","createdAt":"2026-07-12T17:35:17Z","updatedAt":"2026-07-12T17:36:46Z","expired":false,"versions":[{"version":1,"state":"disabled","createdAt":"2026-07-12T17:35:17Z"},{"version":2,"state":"enabled","createdAt":"2026-07-12T17:36:46Z"}]}
```

## list

```sh
safetybox list [prefix]
```

Lists every non-deleted secret, or only those under a name prefix.
The prefix selects whole segments, exactly and case-sensitively, the
same rule reveal uses. Names are plaintext columns in the current
format, so list needs no identity. Output is a JSON array of metadata
summaries with the latest version number.

## stale

```sh
safetybox stale
```

Lists non-deleted secrets whose expiry has passed. Expiry is a
staleness flag, never a deletion trigger. Stale secrets keep
resolving, with a warning, until you rotate or delete them.

## disable

```sh
safetybox disable <name> <version>
```

Takes one version out of resolution without touching its envelope.
get and reveal fall back to the newest remaining enabled version.
Disabling a destroyed version fails. Disabling twice is a no-op.

## delete

```sh
safetybox delete <name>
```

Soft delete. The secret leaves list, get, and exec, but every
version and envelope stays intact. show still displays it with a
deletedAt timestamp. set revives it. purge destroys it.

## purge

```sh
safetybox purge <name> --yes
```

Erases every envelope of the secret and marks all versions
destroyed, inside one transaction. Rows and history remain, so the
secret name stays readable in the vault forever, even after purge. If
a name itself is sensitive, purge does not remove it. The values are
gone forever. Refuses to run without `--yes`. purge implies delete.

After the commit, purge scrubs the write-ahead log so the erased
bytes do not linger in its frames. A reader in another safetybox
process can block that scrub. purge warns on stderr when it happens
and the next checkpoint reclaims the frames.

```json
{"name":"legacy/token","destroyedVersions":1,"result":"purged"}
```

## exec

```sh
safetybox exec -- <command> [args...]
```

Resolves every non-deleted secret that has an env name, decrypts its
newest enabled version, and runs the command with those variables
added to the environment. Everything after `--` belongs to the
child. stdin, stdout, and stderr pass through. The child's exit code
is propagated, and a child killed by a signal exits 128 plus the
signal number, the way a shell reports it. Expired secrets warn on
stderr and still resolve.

An env name stored before set validated them may not be a legal
variable name. exec skips such a secret with a warning instead of
injecting a malformed entry. A value that holds a NUL byte cannot
become an environment variable either, so exec skips it with a warning
that names it and runs the command with the rest. A secret whose sealed
env name or expiry no longer matches its columns is skipped the same
way. One such mismatch never denies every variable to the child. When
two secrets share an env name the later one wins in the child
environment, and exec warns about the override.

## passwd

```sh
safetybox passwd [--new-passphrase-file FILE]
```

Changes the identity passphrase. It decrypts the identity with the
current passphrase and re-encrypts it with the new one, swapped into
place atomically. The key itself does not change, so the vault needs
nothing. The current passphrase comes from the prompt or the global
`--passphrase-file`. passwd shares the identity lock with rekey, so
it never interleaves with a rotation.

## rekey

```sh
safetybox rekey
```

Full key rotation. rekey generates a new identity, re-encrypts every
non-destroyed version to it, and stores the new recipient. All vault
writes happen inside one transaction and the recipient updates last,
so a failure before the commit leaves the old vault fully intact.
The commit itself can error while its record is already durable. In
that one case rekey keeps both key files, and the error says to test
which key opens the vault before deleting either.

The new identity is staged beside the old one before the vault
transaction starts. After the transaction commits, the old identity
moves to a `.bak` sibling and the new one takes its place. Keep the
`.bak` until you have verified a reveal, then back up the new file
and delete the old one. The passphrase stays the same. Use passwd to
change it.

rekey and passwd hold an exclusive lock on an `identity.age.lock`
sibling for their whole run, so two rotations can never interleave
and delete each other's staged key. A second run refuses up front
while one is active. The empty lock file is a permanent, harmless
sibling of the identity.

Before touching anything, rekey verifies the vault is really
encrypted to the loaded identity. If a previous rekey crashed after
re-encrypting the vault, the staged `.new` sibling is the live key,
and rekey refuses with recovery steps instead of discarding it. Like
purge, rekey scrubs the write-ahead log after the commit and warns
when another process blocks the scrub.

```json
{"recipient":"age1...","rekeyedVersions":4,"backupIdentity":"~/.config/safetybox/identity.age.bak"}
```

## migrate

```sh
safetybox migrate
```

Upgrades a vault from an older safetybox to the current on-disk format.
The current format seals each secret's env name and expiry into its
envelope, so a later edit to those columns is caught on read. migrate
re-seals every secret into that format and bumps the format version.

It needs the passphrase, because re-sealing decrypts each value. The
passphrase comes from the prompt or the global `--passphrase-file`,
which accepts a process substitution such as
`(secret-get name | psub)`. The identity and the recipient do not
change, only the envelopes are re-framed. Like the read verbs, migrate
refuses when the vault's stored recipient does not match your identity,
before it re-seals anything.

Everything runs in one transaction. A crash mid-migration rolls back
and leaves the old vault intact. Back up the vault file first. A vault
already at the current format reports that and does nothing.

migrate holds an exclusive lock on a `vault.db.lock` sibling for its
whole run, so two migrates on one vault can never interleave. A second
run refuses up front while one is active, rather than blocking on the
database write lock and failing with a raw busy error. The empty lock
file is a permanent, harmless sibling of the vault, the same design the
identity lock uses for rekey and passwd.

The lock only guards against other migrates. Stop any older safetybox
binary, such as a script still on 2.x, before you run migrate. The old
binary checks the format only when it opens the vault. A 2.x `set`
racing the migration can therefore append a legacy envelope just after
the upgrade commits. The write succeeds silently, and the next read of
that secret fails with a tamper-shaped error. Re-running migrate
reports the vault as already current, so it cannot repair the row.
Re-set the secret instead.

An env name stored by a very old safetybox could contain a newline,
which the new format cannot carry. migrate strips the newline, warns
naming the secret, and stores the cleaned name, so such a vault still
upgrades. A trailing newline, the usual cause, leaves the intended name.

```json
{"migratedVersions":12,"result":"migrated"}
```

## version

```sh
safetybox --version
```

Prints the running version. Builds made through the Makefile or a
release stamp it at build time. A plain `go install` gets no stamp,
so the binary falls back to the module version recorded in the build
info. Every path reports the same v-prefixed form, such as v2.0.0.
Running `safetybox` with no arguments also shows the version under
the banner.
